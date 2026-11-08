#!/usr/bin/env python3
"""Sensor engine-local rename/reopen probes and an offline evidence verifier.

Run `python rotation_probe.py cowrie|web` inside the corresponding pinned image.
Run `python rotation_probe.py verify report.json` anywhere with Python's stdlib.
Only owned /tmp files and process-local configuration are changed. Engine imports
are deferred, so offline verification does not require either engine installed.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import sys
import tempfile
from types import SimpleNamespace

SCHEMA = 'cheesetrap.rotation.v1'
SCOPE = 'engine logging component; synthetic input; no public listener or TLS handshake'
PINNED = {
    'cowrie.output.jsonlog': '3bb8d59a4e34334507b5f06f2c7339c4ee2fa67d52a4f1a146bc24275b247d33',
    'cowrie.python.logfile': 'b4b82b443b06a75c8c4352e53e750781b291a3b724e64acf4aafedf92fde8975',
    'opencanary.modules.request_evidence': '391edc59f724236729325e242aa72ccfe4fbd78664ed015b8183be8683551c3a',
}
BUNDLED_CONFIG_SHA256 = '6a428d2af29b6b154e379ded8258144f5f5c4b0967a5990a97b15d1b670179db'
MAX_REPORT_BYTES = 131072


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def snapshot(path):
    path = Path(path)
    if not path.exists():
        return {'exists': False}
    with path.open('rb') as stream:
        info = os.fstat(stream.fileno())
        data = stream.read(MAX_REPORT_BYTES + 1)
    require(len(data) <= MAX_REPORT_BYTES, 'probe file exceeded retained evidence bound')
    return {'exists': True, 'device': info.st_dev, 'inode': info.st_ino,
            'size': info.st_size, 'sha256': digest(data),
            'content_utf8': data.decode('utf-8')}


def wire(case, phase):
    return ('GET /sensor-rotation-' + case + '-' + phase +
            ' HTTP/1.1\r\nHost: rotation.test.invalid\r\nConnection: close\r\n\r\n').encode('ascii')


def expected(engine, case, phase):
    identifier = 'sensor-rotation-' + case + '-' + phase
    if engine == 'cowrie':
        return {'eventid': 'sensor.rotation', 'probe_event': identifier}
    raw = wire(case, phase)
    return {'event_type': 'web.request', 'protocol': case, 'uri': '/' + identifier,
            'method': 'GET', 'parse_error': '', 'wire_bytes': len(raw), 'wire_sha256': digest(raw)}


def check_snapshot(value, expected_rows):
    require(value['exists'] is True, 'required log path is absent')
    require(isinstance(value['inode'], int) and value['inode'] > 0, 'invalid inode')
    require(isinstance(value['device'], int) and value['device'] >= 0, 'invalid device')
    data = value['content_utf8'].encode('utf-8')
    require(len(data) <= MAX_REPORT_BYTES, 'retained file too large')
    require(value['size'] == len(data), 'retained byte length mismatch')
    require(value['sha256'] == digest(data), 'retained SHA-256 mismatch')
    require(data.endswith(b'\n'), 'JSONL record missing final LF')
    rows = [json.loads(line) for line in data.splitlines()]
    require(len(rows) == len(expected_rows), 'event count mismatch (missing or duplicate event)')
    for actual, wanted in zip(rows, expected_rows):
        require(isinstance(actual, dict), 'JSONL event is not an object')
        require(all(actual.get(key) == value for key, value in wanted.items()),
                'synthetic event identity or required fields mismatch')
    return rows


def verify_report(report):
    """Raise ValueError on missing/inconsistent evidence; never trust PASS flags."""
    try:
        require(report['schema'] == SCHEMA, 'unexpected report schema')
        require(report['scope'] == SCOPE, 'unexpected validation scope')
        require(report.get('status', 'PASS') == 'PASS', 'report records a failed probe')
        engine = report['engine']
        require(engine in ('cowrie', 'web'), 'unexpected engine')
        require(isinstance(report['pid_before'], int) and report['pid_before'] > 0,
                'invalid process ID')
        require(report['pid_after'] == report['pid_before'], 'process changed during probe')
        start = datetime.fromisoformat(report['started_utc'])
        end = datetime.fromisoformat(report['finished_utc'])
        require(start.utcoffset() == end.utcoffset() == timedelta(0), 'timestamps must be UTC')
        require(end >= start, 'finish predates start')
        package = 'cowrie' if engine == 'cowrie' else 'opencanary'
        require(report['versions'][package] == ('3.1.2' if engine == 'cowrie' else '0.9.10'),
                'engine package version mismatch')
        require(report['versions']['twisted'] == '26.4.0', 'Twisted version mismatch')
        modules = ['cowrie.output.jsonlog', 'cowrie.python.logfile'] if engine == 'cowrie' else ['opencanary.modules.request_evidence']
        for name in modules:
            require(report['sources'][name]['sha256'] == PINNED[name], 'pinned source hash mismatch: ' + name)
            require(bool(report['sources'][name]['path']), 'missing imported module path')
        names = ['native', 'external'] if engine == 'cowrie' else ['http', 'https']
        require([case['name'] for case in report['cases']] == names, 'missing, reordered or duplicate case')
        if engine == 'cowrie':
            require(report['effective_logtype'] == 'rotating', 'Cowrie effective logtype is not rotating')
            require(report['bundled_config']['logtype'] == 'rotating', 'Cowrie bundled default is not rotating')
            require(report['bundled_config']['sha256'] == BUNDLED_CONFIG_SHA256, 'Cowrie bundled default hash mismatch')
        for case in report['cases']:
            name = case['name']
            require(case['pid_before'] == case['pid_after'] == report['pid_before'],
                    'case did not use the same process')
            before, after = expected(engine, name, 'before'), expected(engine, name, 'after')
            check_snapshot(case['before'], [before])
            if name != 'native':
                check_snapshot(case['archive_after_rename'], [before])
                require(case['before'] == case['archive_after_rename'], 'rename changed original inode or bytes')
            archive = case['archive_after_write']
            check_snapshot(archive, [before, after] if name == 'external' else [before])
            require((archive['device'], archive['inode']) ==
                    (case['before']['device'], case['before']['inode']), 'archive inode changed')
            if name == 'external':
                require(case['current_after_write'] == {'exists': False}, 'negative control unexpectedly reopened path')
                require(archive['content_utf8'].startswith(case['before']['content_utf8']),
                        'negative control did not preserve previous bytes')
                require(archive['size'] > case['before']['size'], 'negative control did not append old inode')
            else:
                require(archive == case['before'], 'archive grew or changed after reopening')
                current = case['current_after_write']
                check_snapshot(current, [after])
                require(current['device'] == archive['device'], 'new log changed filesystem')
                require(current['inode'] != archive['inode'], 'new log reused archive inode')
                if name == 'native':
                    stimulus = case['date_stimulus']
                    today = datetime(*stimulus['current_date'])
                    previous = datetime(*stimulus['forced_last_date'])
                    require(today - previous == timedelta(days=1), 'date stimulus is not the previous day')
                    require(stimulus['should_rotate'] is True, 'date stimulus did not make rotation due')
                    require(stimulus['action'] == 'real Output.write triggers inherited daily rotation',
                            'native case did not trigger rotation through Output.write')
                    require(case['archive_after_followup'] == archive, 'archive changed after followup write')
                    followup = case['current_after_followup']
                    check_snapshot(followup, [after, expected(engine, name, 'followup')])
                    require((followup['device'], followup['inode']) == (current['device'], current['inode']),
                            'followup changed reopened inode')
                    require(followup['content_utf8'].startswith(current['content_utf8']),
                            'followup did not preserve first reopened event bytes')
    except (KeyError, TypeError, AttributeError, UnicodeError, json.JSONDecodeError) as error:
        raise ValueError('missing or malformed rotation evidence: ' + str(error)) from error


def source(module):
    path = Path(module.__file__).resolve()
    data = path.read_bytes()
    return {'path': str(path), 'size': len(data), 'sha256': digest(data)}


def cowrie_version_info():
    # Cowrie's image copies the source tree onto PYTHONPATH without dist-info.
    # This is the same generated version module used by its Twisted plugin.
    from cowrie import __version__ as version_module

    version = getattr(version_module, '__version__', None)
    require(isinstance(version, str) and bool(version), 'Cowrie runtime version is absent or malformed')
    return {'version': version, 'source': source(version_module)}


def cowrie_probe(report, directory):
    import configparser
    import cowrie.output.jsonlog as jsonlog
    import cowrie.python.logfile as cowrie_logfile
    from cowrie.core.config import CowrieConfig
    from cowrie.core.resources import read_data_bytes
    from twisted.python import logfile as twisted_logfile

    version_info = cowrie_version_info()
    report['versions'].update(cowrie=version_info['version'],
                              twisted=importlib.metadata.version('twisted'))
    report['sources'] = {m.__name__: source(m) for m in (jsonlog, cowrie_logfile, twisted_logfile)}
    report['sources']['cowrie._version'] = version_info['source']
    report['version_origin'] = 'cowrie._version.__version__ (generated runtime source)'
    bundled = read_data_bytes('etc', 'cowrie.cfg.dist')
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(bundled.decode('utf-8'))
    report['bundled_config'] = {'sha256': digest(bundled), 'logtype': parser.get('honeypot', 'logtype')}
    report['effective_logtype'] = CowrieConfig.get('honeypot', 'logtype', fallback='plain')
    require(report['effective_logtype'] == 'rotating', 'effective Cowrie logtype must already be rotating')
    report['mechanism'] = 'real jsonlog.Output and CowrieDailyLogFile; inherited Twisted DailyLogFile.rotate closes, renames, reopens'
    original = CowrieConfig.get('output_jsonlog', 'logfile', raw=True)
    require('COWRIE_OUTPUT_JSONLOG_LOGFILE' not in os.environ, 'environment logfile override would bypass temporary path')
    try:
        for name in ('native', 'external'):
            current = Path(directory) / (name + '.jsonl')
            CowrieConfig.set('output_jsonlog', 'logfile', str(current))
            output = jsonlog.Output()
            try:
                writer = output.outfile
                require(isinstance(writer, cowrie_logfile.CowrieDailyLogFile), 'unexpected Cowrie writer')
                require(type(writer).rotate is twisted_logfile.DailyLogFile.rotate, 'rotation method is not inherited Twisted implementation')
                case = {'name': name, 'pid_before': os.getpid(), 'writer_class': type(writer).__module__ + '.' + type(writer).__name__,
                        'stimulus_before': expected('cowrie', name, 'before'),
                        'stimulus_after': expected('cowrie', name, 'after')}
                output.write(dict(case['stimulus_before']))
                case['before'] = snapshot(current)
                if name == 'native':
                    # Change only this writer's stored date; host clock is untouched.
                    today = tuple(writer.toDate())
                    yesterday = (datetime(*today) - timedelta(days=1)).timetuple()[:3]
                    writer.lastDate = yesterday
                    case['date_stimulus'] = {'current_date': list(today), 'forced_last_date': list(yesterday),
                                             'should_rotate': writer.shouldRotate(),
                                             'action': 'real Output.write triggers inherited daily rotation'}
                    require(case['date_stimulus']['should_rotate'], 'date stimulus did not make rotation due')
                    archive = Path(str(current) + '.' + writer.suffix(yesterday))
                else:
                    case['negative_control'] = 'external rename alone must keep writing old inode; no automatic reopen or SIGHUP claim'
                    archive = Path(str(current) + '.external')
                    current.rename(archive)
                    case['archive_after_rename'] = snapshot(archive)
                output.write(dict(case['stimulus_after']))
                case['archive_after_write'] = snapshot(archive)
                case['current_after_write'] = snapshot(current)
                if name == 'native':
                    case['stimulus_followup'] = expected('cowrie', name, 'followup')
                    output.write(dict(case['stimulus_followup']))
                    case['archive_after_followup'] = snapshot(archive)
                    case['current_after_followup'] = snapshot(current)
                case['pid_after'] = os.getpid()
                report['cases'].append(case)
            finally:
                output.stop()
                output.outfile.close()
    finally:
        CowrieConfig.set('output_jsonlog', 'logfile', original)


def web_probe(report, directory):
    from opencanary.modules import request_evidence
    from opencanary.modules.http import CanaryRequest
    from twisted.internet.address import IPv4Address
    from twisted.internet.error import ConnectionDone
    from twisted.internet.testing import StringTransport
    from twisted.python.failure import Failure
    from twisted.web.resource import Resource
    from twisted.web.server import Request
    from twisted.web import http

    report['versions'].update(opencanary=importlib.metadata.version('opencanary'),
                              twisted=importlib.metadata.version('twisted'))
    report['sources'] = {m.__name__: source(m) for m in (request_evidence, http)}
    require(report['sources'][request_evidence.__name__]['sha256'] == PINNED[request_evidence.__name__],
            'installed request_evidence module differs from pinned patch')
    report['mechanism'] = 'installed evidence_site real HTTPChannel; StringTransport; connectionLost opens log pathname for each record'

    class Page(Resource):
        isLeaf = True

        def render(self, request):
            return b'ok'

    original = request_evidence.OUTPUT
    try:
        for name, base in (('http', CanaryRequest), ('https', Request)):
            current = Path(directory) / (name + '.jsonl')
            archive = Path(str(current) + '.archive')
            request_evidence.OUTPUT = str(current)
            site = request_evidence.evidence_site(Page(), SimpleNamespace(NAME=name, log=lambda *a, **kw: None), base)
            case = {'name': name, 'pid_before': os.getpid(), 'request_base': base.__module__ + '.' + base.__name__,
                    'transport': 'twisted.internet.testing.StringTransport',
                    'stimulus_before_ascii': wire(name, 'before').decode('ascii'),
                    'stimulus_after_ascii': wire(name, 'after').decode('ascii')}
            for phase in ('before', 'after'):
                peer = IPv4Address('TCP', '198.51.100.20', 50000)
                destination = IPv4Address('TCP', '192.0.2.10', 443 if name == 'https' else 80)
                channel = site.buildProtocol(peer)
                require(isinstance(channel, http.HTTPChannel), 'not an actual Twisted HTTPChannel')
                transport = StringTransport(peerAddress=peer, hostAddress=destination)
                channel.makeConnection(transport)
                channel.dataReceived(wire(name, phase))
                channel.connectionLost(Failure(ConnectionDone()))
                require(transport.value().startswith(b'HTTP/1.1 200 '), 'synthetic request did not complete successfully')
                if phase == 'before':
                    case['before'] = snapshot(current)
                    current.rename(archive)
                    case['archive_after_rename'] = snapshot(archive)
            case['archive_after_write'] = snapshot(archive)
            case['current_after_write'] = snapshot(current)
            case['pid_after'] = os.getpid()
            report['cases'].append(case)
    finally:
        request_evidence.OUTPUT = original


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('mode', choices=('cowrie', 'web', 'verify'))
    parser.add_argument('report', nargs='?', help='saved JSON report for verify mode')
    args = parser.parse_args(argv)
    result = {}
    try:
        if args.mode == 'verify':
            require(args.report is not None, 'verify requires a report path')
            data = Path(args.report).read_bytes()
            require(len(data) <= MAX_REPORT_BYTES, 'report exceeds evidence bound')
            report = json.loads(data)
            verify_report(report)
            result = {'status': 'PASS', 'schema': SCHEMA, 'engine': report['engine'],
                      'scope': SCOPE, 'verified_report_sha256': digest(data)}
        else:
            require(args.report is None, 'engine mode takes no report path')
            result = {'schema': SCHEMA, 'engine': args.mode, 'scope': SCOPE,
                      'started_utc': datetime.now(timezone.utc).isoformat(), 'pid_before': os.getpid(),
                      'versions': {'python': platform.python_version()}, 'sources': {}, 'cases': []}
            with tempfile.TemporaryDirectory(prefix='sensor-rotation-', dir='/tmp') as directory:
                (cowrie_probe if args.mode == 'cowrie' else web_probe)(result, directory)
            result['pid_after'] = os.getpid()
            result['finished_utc'] = datetime.now(timezone.utc).isoformat()
            verify_report(result)
            result['status'] = 'PASS'
        encoded = json.dumps(result, sort_keys=True)
        require(len(encoded.encode('utf-8')) <= MAX_REPORT_BYTES, 'output report exceeds evidence bound')
        print(encoded)
        return 0
    except Exception as error:
        result.update(status='FAIL', error=type(error).__name__ + ': ' + str(error),
                      finished_utc=datetime.now(timezone.utc).isoformat())
        print(json.dumps(result, sort_keys=True))
        return 1


if __name__ == '__main__':
    sys.exit(main())
