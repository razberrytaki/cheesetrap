"""Bounded request evidence for OpenCanary 0.9.10 / Twisted 26.4.0.

All transport bytes are hashed incrementally; only bounded, redacted fields are
retained. No URL fetch, subprocess, reverse proxy, or independent HTTP parser.
"""
import hashlib
import io
import json
import re
from datetime import datetime, timezone
from urllib.parse import unquote_to_bytes

BODY, URI, HEADERS, RECORD = 16384, 8192, 16384, 262144
SENSITIVE = re.compile(r'auth|cookie|password|passwd|token|secret|api[-_]?key', re.I)
OUTPUT = '/var/tmp/events.jsonl'
FIELDS = ('timestamp', 'peer_ip', 'peer_port', 'destination', 'method', 'uri', 'headers', 'body', 'parse_error', 'truncation')


def safe_uri(raw):
    if any(c < 33 or c > 126 for c in raw) or re.search(rb'%(?![0-9a-fA-F]{2})', raw):
        return None
    path, sep, query = raw.partition(b'?')
    if sep:
        parts = []
        for part in query.split(b'&'):
            key, eq, value = part.partition(b'=')
            if SENSITIVE.search(unquote_to_bytes(key).decode('ascii', 'replace')):
                part = key + b'=[REDACTED]'
            parts.append(part)
        raw = path + b'?' + b'&'.join(parts)
    return raw.decode('ascii')


def bound(limit, observed, retained):
    return {'limit': limit, 'observed': observed, 'retained': retained, 'truncated': observed > retained}


class Evidence:
    def __init__(self):
        self.method = self.uri = None
        self.uri_seen = self.uri_retained = 0
        self.headers = []
        self.headers_seen = self.headers_retained = 0
        self.body_bytes = bytearray()
        self.body_seen = 0
        self.content_type = ''
        self.error = ''
        self.complete = self.headers_complete = False
        self.flags = []
        self.unavailable = {}
        self.wire = hashlib.sha256()
        self.wire_bytes = 0

    def uri_line(self, line):
        parts = line.split(b' ')
        if len(parts) != 3:
            self.unavailable.update(method='malformed request line', uri='malformed request line')
            return
        method, raw, _ = parts
        self.method = method.decode('ascii') if re.fullmatch(rb'[A-Z]{1,32}', method) else None
        self.uri_seen = len(raw)
        self.uri_retained = min(len(raw), URI)
        if len(raw) > URI:
            self.flags.append('uri_truncated')
        self.uri = safe_uri(raw[:URI])
        if self.uri is None or len(self.uri.encode('ascii')) > URI or (len(raw) > URI and b'?' in raw):
            self.uri = None
            self.uri_retained = 0
            self.unavailable['uri'] = 'malformed or truncated query cannot be safely redacted'

    def header_line(self, line):
        self.headers_seen += len(line) + 2
        if self.headers is None:
            return
        if self.headers_seen > HEADERS:
            self.headers = None
            self.headers_retained = 0
            self.unavailable['headers'] = 'header byte limit exceeded; partial fields withheld'
            self.flags.append('headers_truncated')
            return
        name, sep, value = line.partition(b':')
        if not sep or not re.fullmatch(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+", name) or any(c < 32 and c != 9 or c > 126 for c in value):
            self.headers = None
            self.headers_retained = 0
            self.unavailable['headers'] = 'malformed headers withheld to avoid secret leakage'
            return
        name = name.decode('ascii').lower()
        value = value.strip().decode('ascii')
        if name == 'content-type':
            self.content_type = value.lower()
        if SENSITIVE.search(name):
            value = '[REDACTED]'
            self.flags.append('headers_redacted')
        self.headers.append({'name': name, 'value': value})
        self.headers_retained += len(line) + 2
        if sum(len(h['name']) + len(h['value']) + 4 for h in self.headers) > HEADERS:
            self.headers = None
            self.headers_retained = 0
            self.unavailable['headers'] = 'redacted headers exceed retained byte limit'
            self.flags.append('headers_truncated')

    def body_chunk(self, data):
        self.body_seen += len(data)
        available = BODY - len(self.body_bytes)
        if available:
            self.body_bytes.extend(data[:available])

    def record(self):
        flags = set(self.flags)
        body = bytes(self.body_bytes)
        if self.body_seen > len(body):
            flags.add('body_truncated')
        if any(t in self.content_type for t in ('json', 'form', 'multipart')) or SENSITIVE.search(body.decode('utf-8', 'replace')):
            text = '[REDACTED structured or sensitive body]' if body else ''
            if body:
                flags.add('body_redacted')
        else:
            try:
                text = body.decode('utf-8')
            except UnicodeDecodeError:
                text = None
                self.unavailable['body'] = 'invalid or truncated UTF-8 body withheld'
        if not self.headers_complete:
            self.headers = None
            self.headers_retained = 0
            self.unavailable.setdefault('headers', 'headers did not complete')
            text = None
            self.unavailable['body'] = 'body framing unavailable because headers did not complete'
        if self.error:
            flags.add(self.error)
        fields = {k: {'status': 'present', 'source': k} for k in FIELDS}
        for k, reason in self.unavailable.items():
            fields[k] = {'status': 'unavailable', 'reason': reason}
            flags.add('required_field_unavailable')
        if self.method is None:
            fields['method'] = {'status': 'unavailable', 'reason': 'request method was not parsed'}
            flags.add('required_field_unavailable')
        if self.uri is None:
            fields['uri'] = {'status': 'unavailable', 'reason': self.unavailable.get('uri', 'request target was not parsed')}
            flags.add('required_field_unavailable')
        return {'event_type': 'web.request', 'timestamp': datetime.now(timezone.utc).isoformat(),
                'method': self.method, 'uri': self.uri, 'headers': self.headers, 'body': text,
                'parse_error': self.error, 'field_completeness': fields,
                'truncation': {'uri': bound(URI, self.uri_seen, self.uri_retained),
                               'headers': bound(HEADERS, self.headers_seen, self.headers_retained),
                               'body': bound(BODY, self.body_seen, len(body)),
                               'record': bound(RECORD, 0, 0)},
                'quality_flags': sorted(flags), 'auto_report_eligible': False,
                'wire_sha256': self.wire.hexdigest(), 'wire_bytes': self.wire_bytes}


def serialize(event):
    """Check escaped UTF-8 JSON bytes, including the final limit metadata."""
    def encoded():
        return json.dumps(event, ensure_ascii=True, separators=(',', ':')).encode('ascii')
    data = encoded()
    observed = len(data)
    if observed > RECORD:
        for field in ('uri', 'headers', 'body'):
            event[field] = None
            event['field_completeness'][field] = {'status': 'unavailable', 'reason': 'serialized record limit exceeded'}
        event['quality_flags'] = sorted(set(event['quality_flags']) | {'record_truncated', 'required_field_unavailable'})
        event['auto_report_eligible'] = False
    for _ in range(8):
        data = encoded()
        event['truncation']['record'] = bound(RECORD, max(observed, len(data)), len(data))
        updated = encoded()
        if len(updated) == len(data):
            if len(updated) > RECORD:
                raise ValueError('bounded evidence metadata exceeded record cap')
            return updated
    raise ValueError('record length did not stabilize')


def evidence_site(resource, service, request_base):
    # Imports are local so pure redaction/boundary tests do not require Twisted.
    from twisted.web.http import HTTPChannel
    from twisted.web.server import Site

    class BoundedRequest(request_base):
        def __init__(self, *args, **kwargs):
            kwargs['parsePOSTFormSubmission'] = False
            super().__init__(*args, **kwargs)

        def gotLength(self, length):
            self.content = io.BytesIO()

        def handleContentChunk(self, data):
            state = self.channel.evidence
            state.body_chunk(data)
            # OpenCanary resources do not need a copy of untrusted POST bodies.
            # Twisted still validates framing incrementally and counts all bytes.

        def requestReceived(self, command, path, version):
            self.channel.evidence.complete = True
            super().requestReceived(command, path, version)

    class BoundedChannel(HTTPChannel):
        MAX_LENGTH = HEADERS
        totalHeadersSize = URI + HEADERS + 256
        maxHeaders = 100
        timeOut = 5
        abortTimeout = 1

        def connectionMade(self):
            self.evidence = Evidence()
            self.first = True
            self.header_wire_bytes = 0
            self.failed = False
            self.peer, self.destination = self.transport.getPeer(), self.transport.getHost()
            super().connectionMade()

        def dataReceived(self, data):
            # Split deliveries before the inherited parser can buffer them.
            # TCP/TLS transport owns its own bounded network read buffer.
            for offset in range(0, len(data), 4096):
                piece = data[offset:offset + 4096]
                self.evidence.wire.update(piece)
                self.evidence.wire_bytes += len(piece)
                if not self.failed and not self.evidence.complete:
                    super().dataReceived(piece)

        def lineReceived(self, line):
            if self.failed:
                return
            if self.first:
                self.first = False
                self.evidence.uri_line(line)
                if self.evidence.uri_seen > URI:
                    self.evidence.error = 'uri_limit'
                    self._respondToBadRequestAndDisconnect()
                    return
                if self.evidence.method is None or self.evidence.uri is None:
                    self._respondToBadRequestAndDisconnect()
                    return
            else:
                self.header_wire_bytes += len(line) + 2
                if self.header_wire_bytes > HEADERS:
                    self.evidence.headers_seen = self.header_wire_bytes
                    self.evidence.headers_retained = 0
                    self.evidence.headers = None
                    self.evidence.unavailable['headers'] = 'header byte limit exceeded'
                    self.evidence.flags.append('headers_truncated')
                    self.evidence.error = 'headers_limit'
                    self._respondToBadRequestAndDisconnect()
                    return
            super().lineReceived(line)

        def headerReceived(self, line):
            self.evidence.header_line(line)
            if self.evidence.headers is None:
                self._respondToBadRequestAndDisconnect()
                return False
            try:
                return super().headerReceived(line)
            except ValueError:
                # Numeric/framing parse errors must not escape into a traceback
                # that may quote untrusted input or bypass the evidence event.
                self._respondToBadRequestAndDisconnect()
                return False

        def allHeadersReceived(self):
            self.evidence.headers_complete = True
            super().allHeadersReceived()
            self.persistent = False  # one evidence record per transport connection

        def lineLengthExceeded(self, line):
            self.evidence.error = 'line_limit'
            if self.first:
                self.evidence.uri_seen = len(line)
                self.evidence.unavailable['uri'] = 'request line exceeded parser limit'
            else:
                self.evidence.headers_seen = self.header_wire_bytes + len(line)
                self.evidence.headers = None
                self.evidence.headers_retained = 0
                self.evidence.unavailable['headers'] = 'header line exceeded parser limit'
            self._respondToBadRequestAndDisconnect()

        def _respondToBadRequestAndDisconnect(self):
            if not self.failed:
                self.failed = True
                if not self.evidence.error:
                    self.evidence.error = 'malformed_http'
                super()._respondToBadRequestAndDisconnect()

        def connectionLost(self, reason):
            e = self.evidence
            if e.wire_bytes:
                if not e.complete and not e.error:
                    e.error = 'client_disconnect'
                event = e.record()
                event.update(protocol=service.NAME, peer_ip=self.peer.host, peer_port=self.peer.port,
                             destination_ip=self.destination.host, destination_port=self.destination.port)
                with open(OUTPUT, 'ab', buffering=0) as output:
                    output.write(serialize(event) + b'\n')
            super().connectionLost(reason)

    class EvidenceSite(Site):
        protocol = BoundedChannel
        requestFactory = BoundedRequest

        def log(self, request):
            # Twisted's combined access log writes the original URI.
            # The sanitized request event is the only web request log.
            pass

    # Old resource logs contain raw passwords/query fields and duplicate a subset
    # of evidence. Suppress only these two web service instances after patching.
    service.log = lambda *args, **kwargs: None
    return EvidenceSite(resource, timeout=5)
