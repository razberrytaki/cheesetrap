import importlib.util
import json
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('request_evidence', Path(__file__).with_name('request_evidence.py'))
evidence = importlib.util.module_from_spec(spec)
spec.loader.exec_module(evidence)

class EvidenceTests(unittest.TestCase):
    def test_incremental_body_has_fixed_storage(self):
        e = evidence.Evidence()
        for _ in range(1000):
            e.body_chunk(b'A' * 4096)
        self.assertEqual(len(e.body_bytes), 16384)
        self.assertEqual(e.body_seen, 4096000)

    def test_secrets_never_survive_fragments(self):
        for content_type, payload in [('application/json', b'{"password":"synthetic-secret-' + b'S' * 20000), ('application/x-www-form-urlencoded', b'password=synthetic-secret-' + b'S' * 20000)]:
            e = evidence.Evidence()
            e.uri_line(b'POST /?token=synthetic-secret-query&safe=ok HTTP/1.1')
            e.header_line(b'Content-Type: ' + content_type.encode())
            e.header_line(b'Authorization: Bearer synthetic-secret-auth')
            e.header_line(b'Cookie: session=synthetic-secret-cookie')
            e.body_chunk(payload)
            b = evidence.serialize(e.record())
            self.assertNotIn(b'synthetic-secret', b)
            self.assertIn(b'REDACTED', b)

    def test_malformed_header_and_uri_are_not_retained(self):
        e = evidence.Evidence()
        e.uri_line(b'GET /?token=synthetic-secret% HTTP/1.1')
        e.header_line(b'Broken-synthetic-secret-header')
        e.error = 'malformed_http'
        b = evidence.serialize(e.record())
        self.assertNotIn(b'synthetic-secret', b)
        self.assertFalse(json.loads(b)['auto_report_eligible'])

    def test_redaction_expansion_cannot_exceed_field_storage_limits(self):
        e = evidence.Evidence()
        e.uri_line(b'GET /?' + b'&'.join([b'token=x'] * 1000) + b' HTTP/1.1')
        for _ in range(1000):
            e.header_line(b'Token: x')
        r = e.record()
        self.assertTrue(r['uri'] is None or len(r['uri'].encode()) <= 8192)
        self.assertTrue(r['headers'] is None or sum(len(h['name']) + len(h['value']) + 4 for h in r['headers']) <= 16384)

    def test_record_escape_expansion_enforces_real_serialized_limit(self):
        e = evidence.Evidence()
        event = e.record()
        event['body'] = '\x00' * 65536
        b = evidence.serialize(event)
        self.assertLessEqual(len(b), 262144)
        r = json.loads(b)
        self.assertTrue(r['truncation']['record']['truncated'])
        self.assertIn('record_truncated', r['quality_flags'])
        self.assertEqual(r['truncation']['record']['retained'], len(b))

class TwistedBoundaryTests(unittest.TestCase):
    def setUp(self):
        try:
            from twisted.internet.testing import StringTransport
            from twisted.web.resource import Resource
            from twisted.web.server import Request
            from twisted.internet.address import IPv4Address
        except ImportError:
            import os
            if os.environ.get('CHEESETRAP_REQUIRE_TWISTED_TESTS'):
                self.fail('exact pinned Twisted runtime is required')
            self.skipTest('run integration in pinned engine image')
        import tempfile
        from types import SimpleNamespace
        self.tmp = tempfile.TemporaryDirectory()
        evidence.OUTPUT = self.tmp.name + '/events.jsonl'
        class Page(Resource):
            isLeaf = True
            def render(self, request):
                return b'ok'
        service = SimpleNamespace(NAME='http', log=lambda *a, **kw: None)
        site = evidence.evidence_site(Page(), service, Request)
        self.channel = site.buildProtocol(IPv4Address('TCP', '198.51.100.20', 50000))
        self.transport = StringTransport(peerAddress=IPv4Address('TCP', '198.51.100.20', 50000), hostAddress=IPv4Address('TCP', '172.30.0.2', 8080))
        self.channel.makeConnection(self.transport)

    def tearDown(self):
        if hasattr(self, 'tmp'):
            self.tmp.cleanup()

    def result(self):
        from twisted.python.failure import Failure
        from twisted.internet.error import ConnectionDone
        self.channel.connectionLost(Failure(ConnectionDone()))
        return json.loads(Path(evidence.OUTPUT).read_bytes())

    def test_site_timeout_is_five_seconds(self):
        self.assertEqual(self.channel.timeOut, 5)

    def test_actual_parser_unknown_path_chunked_body_and_peer(self):
        raw = b'POST /unknown?q=one&q=two HTTP/1.1\r\nHost: example.invalid\r\nX-Forwarded-For: 203.0.113.99\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n'
        for b in raw:
            self.channel.dataReceived(bytes([b]))
        r = self.result()
        self.assertEqual(r['body'], 'test')
        self.assertEqual(r['uri'], '/unknown?q=one&q=two')
        self.assertEqual(r['peer_ip'], '198.51.100.20')
        self.assertEqual(r['parse_error'], '')
        self.assertEqual(r['wire_sha256'], __import__('hashlib').sha256(raw).hexdigest())

    def test_twisted_access_log_does_not_duplicate_raw_secret(self):
        from twisted.logger import globalLogPublisher
        observed = []
        observer = lambda event: observed.append(str(event))
        globalLogPublisher.addObserver(observer)
        try:
            self.channel.dataReceived(b'GET /?token=synthetic-secret-query HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
            self.result()
        finally:
            globalLogPublisher.removeObserver(observer)
        self.assertNotIn('synthetic-secret', ''.join(observed))

    def test_actual_parser_body_storage_is_bounded_before_application(self):
        self.channel.dataReceived(b'POST /unknown HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 1048576\r\n\r\n')
        for _ in range(256):
            self.channel.dataReceived(b'A' * 4096)
        r = self.result()
        self.assertEqual(len(r['body']), 16384)
        self.assertEqual(r['truncation']['body']['observed'], 1048576)
        self.assertTrue(r['truncation']['body']['truncated'])

    def test_incomplete_body_on_connection_lost_retains_partial_evidence(self):
        self.channel.dataReceived(b'POST /partial HTTP/1.1\r\nContent-Length: 100\r\n\r\npartial')
        r = self.result()
        self.assertEqual(r['parse_error'], 'client_disconnect')
        self.assertEqual(r['body'], 'partial')
        self.assertFalse(r['auto_report_eligible'])

    def test_malformed_uri_is_rejected_before_resource_processing(self):
        self.channel.dataReceived(b'GET /?token=synthetic-secret% HTTP/1.1\r\nHost: example.invalid\r\n\r\n')
        r = self.result()
        self.assertEqual(r['parse_error'], 'malformed_http')
        self.assertIsNone(r['uri'])
        self.assertNotIn('synthetic-secret', json.dumps(r))

    def test_unparseable_content_length_is_a_safe_parser_failure(self):
        self.channel.dataReceived(b'POST / HTTP/1.1\r\nContent-Length: ' + b'9' * 5000 + b'\r\n\r\n')
        r = self.result()
        self.assertEqual(r['parse_error'], 'malformed_http')
        self.assertFalse(r['auto_report_eligible'])

    def test_actual_parser_limits_unterminated_headers(self):
        self.channel.dataReceived(b'GET / HTTP/1.1\r\nX-Large: ')
        for _ in range(100):
            self.channel.dataReceived(b'H' * 4096)
        r = self.result()
        self.assertIsNone(r['headers'])
        self.assertTrue(r['parse_error'])
        self.assertLessEqual(len(self.channel._buffer), 20480)
        self.assertFalse(r['auto_report_eligible'])

if __name__ == '__main__':
    unittest.main()
