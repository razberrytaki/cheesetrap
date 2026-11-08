"""Offline contract tests; runtime engine imports are exercised in pinned images."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

PROBE = Path(__file__).with_name('rotation_probe.py')
PINNED = {
    'cowrie.output.jsonlog': '3bb8d59a4e34334507b5f06f2c7339c4ee2fa67d52a4f1a146bc24275b247d33',
    'cowrie.python.logfile': 'b4b82b443b06a75c8c4352e53e750781b291a3b724e64acf4aafedf92fde8975',
    'opencanary.modules.request_evidence': '391edc59f724236729325e242aa72ccfe4fbd78664ed015b8183be8683551c3a',
}


def snapshot(records, inode=100):
    data = ''.join(json.dumps(row, separators=(',', ':')) + '\n' for row in records)
    return {'exists': True, 'device': 1, 'inode': inode, 'size': len(data.encode()),
            'sha256': hashlib.sha256(data.encode()).hexdigest(), 'content_utf8': data}


def row(engine, case, phase):
    identifier = 'sensor-rotation-' + case + '-' + phase
    if engine == 'cowrie':
        return {'eventid': 'sensor.rotation', 'probe_event': identifier}
    raw = ('GET /' + identifier + ' HTTP/1.1\r\nHost: rotation.test.invalid\r\nConnection: close\r\n\r\n').encode()
    return {'event_type': 'web.request', 'protocol': case, 'uri': '/' + identifier,
            'method': 'GET', 'parse_error': '', 'wire_bytes': len(raw),
            'wire_sha256': hashlib.sha256(raw).hexdigest()}


def valid_report(engine='cowrie'):
    names = ['native', 'external'] if engine == 'cowrie' else ['http', 'https']
    modules = ['cowrie.output.jsonlog', 'cowrie.python.logfile'] if engine == 'cowrie' else ['opencanary.modules.request_evidence']
    report = {'schema': 'cheesetrap.rotation.v1', 'engine': engine,
              'scope': 'engine logging component; synthetic input; no public listener or TLS handshake',
              'started_utc': '2026-10-18T00:00:00+00:00', 'finished_utc': '2026-10-18T00:00:01+00:00',
              'pid_before': 123, 'pid_after': 123,
              'versions': {'cowrie': '3.1.2', 'opencanary': '0.9.10', 'twisted': '26.4.0'},
              'sources': {name: {'path': '/installed/' + name + '.py', 'sha256': PINNED[name]} for name in modules},
              'cases': []}
    if engine == 'cowrie':
        report['effective_logtype'] = 'rotating'
        report['bundled_config'] = {'logtype': 'rotating', 'sha256': '6a428d2af29b6b154e379ded8258144f5f5c4b0967a5990a97b15d1b670179db'}
    for name in names:
        before, after = row(engine, name, 'before'), row(engine, name, 'after')
        case = {'name': name, 'pid_before': 123, 'pid_after': 123,
                'before': snapshot([before]), 'archive_after_rename': snapshot([before]),
                'archive_after_write': snapshot([before]), 'current_after_write': snapshot([after], 101)}
        if name == 'native':
            del case['archive_after_rename']
            case['date_stimulus'] = {'current_date': [2026, 10, 18], 'forced_last_date': [2026, 10, 17],
                                     'should_rotate': True, 'action': 'real Output.write triggers inherited daily rotation'}
            case['archive_after_followup'] = snapshot([before])
            case['current_after_followup'] = snapshot([after, row(engine, name, 'followup')], 101)
        if name == 'external':
            case['archive_after_write'] = snapshot([before, after])
            case['current_after_write'] = {'exists': False}
        report['cases'].append(case)
    return report


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(PROBE.exists(), 'rotation probe/verifier not implemented')
        spec = importlib.util.spec_from_file_location('rotation_probe', PROBE)
        self.probe = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.probe)
        self.report = valid_report()

    def rejected(self, report=None):
        with self.assertRaises(ValueError):
            self.probe.verify_report(self.report if report is None else report)

    def test_valid_native_and_external_control(self):
        self.probe.verify_report(self.report)

    def test_valid_http_and_https_cases(self):
        self.probe.verify_report(valid_report('web'))

    def test_missing_event_rejected_even_with_consistent_hash(self):
        self.report['cases'][0]['current_after_write'] = snapshot([], 101)
        self.rejected()

    def test_duplicate_event_rejected_with_consistent_hash(self):
        event = row('cowrie', 'native', 'after')
        self.report['cases'][0]['current_after_write'] = snapshot([event, event], 101)
        self.rejected()

    def test_unexpected_event_rejected(self):
        self.report['cases'][0]['current_after_write'] = snapshot([{'probe_event': 'unexpected'}], 101)
        self.rejected()

    def test_wrong_hash_rejected(self):
        self.report['cases'][0]['current_after_write']['sha256'] = '0' * 64
        self.rejected()

    def test_wrong_length_rejected(self):
        self.report['cases'][0]['current_after_write']['size'] += 1
        self.rejected()

    def test_archive_growth_rejected(self):
        self.report['cases'][0]['archive_after_write'] = snapshot([row('cowrie', 'native', 'before'), row('cowrie', 'native', 'after')])
        self.rejected()

    def test_changed_archive_inode_rejected(self):
        self.report['cases'][0]['archive_after_write']['inode'] = 999
        self.rejected()

    def test_reused_inode_rejected(self):
        self.report['cases'][0]['current_after_write']['inode'] = 100
        self.rejected()

    def test_missing_path_rejected(self):
        self.report['cases'][0]['current_after_write'] = {'exists': False}
        self.rejected()

    def test_truncated_json_rejected_with_consistent_hash(self):
        part = '{"probe_event":'
        current = self.report['cases'][0]['current_after_write']
        current.update(content_utf8=part, size=len(part), sha256=hashlib.sha256(part.encode()).hexdigest())
        self.rejected()

    def test_valid_json_without_final_lf_rejected(self):
        current = self.report['cases'][0]['current_after_write']
        part = current['content_utf8'].rstrip('\n')
        current.update(content_utf8=part, size=len(part), sha256=hashlib.sha256(part.encode()).hexdigest())
        self.rejected()

    def test_changed_process_rejected(self):
        self.report['cases'][0]['pid_after'] = 456
        self.rejected()

    def test_changed_report_process_rejected(self):
        self.report['pid_after'] = 456
        self.rejected()

    def test_wrong_module_hash_rejected(self):
        self.report['sources']['cowrie.output.jsonlog']['sha256'] = '0' * 64
        self.rejected()

    def test_missing_module_provenance_rejected(self):
        del self.report['sources']['cowrie.python.logfile']
        self.rejected()

    def test_wrong_package_version_rejected(self):
        self.report['versions']['cowrie'] = 'unexpected'
        self.rejected()

    def test_wrong_web_twisted_version_rejected(self):
        report = valid_report('web')
        report['versions']['twisted'] = 'unexpected'
        self.rejected(report)

    def test_wrong_cowrie_mode_rejected(self):
        self.report['effective_logtype'] = 'plain'
        self.rejected()

    def test_missing_required_case_rejected(self):
        self.report['cases'].pop()
        self.rejected()

    def test_duplicate_case_rejected(self):
        self.report['cases'].append(copy.deepcopy(self.report['cases'][0]))
        self.rejected()

    def test_external_control_must_keep_path_absent(self):
        self.report['cases'][1]['current_after_write'] = snapshot([row('cowrie', 'external', 'after')], 101)
        self.rejected()

    def test_external_control_must_show_old_inode_growth(self):
        self.report['cases'][1]['archive_after_write'] = snapshot([row('cowrie', 'external', 'before')])
        self.rejected()

    def test_web_protocol_label_rejected_if_incorrect(self):
        report = valid_report('web')
        event = row('web', 'https', 'after')
        event['protocol'] = 'http'
        report['cases'][1]['current_after_write'] = snapshot([event], 101)
        self.rejected(report)

    def test_web_wire_hash_rejected_if_incorrect(self):
        report = valid_report('web')
        event = row('web', 'http', 'after')
        event['wire_sha256'] = '0' * 64
        report['cases'][0]['current_after_write'] = snapshot([event], 101)
        self.rejected(report)

    def test_reversed_times_rejected(self):
        self.report['finished_utc'] = '2026-10-17T00:00:01+00:00'
        self.rejected()

    def test_empty_report_rejected(self):
        self.rejected({})

    def test_native_followup_event_is_required(self):
        self.report['cases'][0]['current_after_followup'] = snapshot([row('cowrie', 'native', 'after')], 101)
        self.rejected()

    def test_native_followup_cannot_grow_archive(self):
        self.report['cases'][0]['archive_after_followup'] = snapshot([row('cowrie', 'native', 'before'), row('cowrie', 'native', 'followup')])
        self.rejected()

    def test_native_followup_uses_same_reopened_inode(self):
        self.report['cases'][0]['current_after_followup']['inode'] = 999
        self.rejected()

    def test_native_date_stimulus_is_required(self):
        del self.report['cases'][0]['date_stimulus']
        self.rejected()

    def test_native_date_stimulus_must_be_previous_day(self):
        self.report['cases'][0]['date_stimulus']['forced_last_date'] = [2026, 10, 18]
        self.rejected()

    def test_unexpected_scope_is_rejected(self):
        self.report['scope'] = 'full public SSH/HTTP/HTTPS validation'
        self.rejected()

    def test_bundled_default_must_be_rotating(self):
        self.report['bundled_config']['logtype'] = 'plain'
        self.rejected()

    def test_bundled_default_hash_must_match(self):
        self.report['bundled_config']['sha256'] = '0' * 64
        self.rejected()

    def test_missing_engine_dependencies_fail_without_skip(self):
        for mode in ('cowrie', 'web'):
            with self.subTest(mode=mode):
                result = subprocess.run([sys.executable, '-I', '-S', str(PROBE), mode], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0)
                report = json.loads(result.stdout)
                self.assertEqual(report['status'], 'FAIL')
                self.assertIn('ModuleNotFoundError', report['error'])

    def test_source_tree_cowrie_version_needs_no_distribution_metadata(self):
        for observed_version in ('3.1.2', '7.9.3'):
            with self.subTest(version=observed_version), tempfile.TemporaryDirectory() as directory:
                package = Path(directory) / 'cowrie'
                package.mkdir()
                (package / '__init__.py').write_text('from . import _version\n__version__ = _version\n')
                version_file = package / '_version.py'
                version_bytes = ('__version__ = ' + repr(observed_version) + '\n').encode()
                version_file.write_bytes(version_bytes)
                code = (
                    'import importlib.metadata, importlib.util, json, sys\n'
                    'sys.path.insert(0, sys.argv[1])\n'
                    'try:\n importlib.metadata.version("cowrie")\n'
                    'except importlib.metadata.PackageNotFoundError:\n pass\n'
                    'else:\n raise AssertionError("fixture unexpectedly has distribution metadata")\n'
                    'spec = importlib.util.spec_from_file_location("rotation_probe", sys.argv[2])\n'
                    'probe = importlib.util.module_from_spec(spec)\n'
                    'spec.loader.exec_module(probe)\n'
                    'print(json.dumps(probe.cowrie_version_info()))\n'
                )
                result = subprocess.run([sys.executable, '-I', '-S', '-c', code, directory, str(PROBE)], capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                info = json.loads(result.stdout)
                self.assertEqual(info['version'], observed_version)
                self.assertEqual(info['source']['path'], str(version_file.resolve()))
                self.assertEqual(info['source']['sha256'], hashlib.sha256(version_bytes).hexdigest())

    def test_source_tree_cowrie_version_must_be_present_string(self):
        with tempfile.TemporaryDirectory() as directory:
            package = Path(directory) / 'cowrie'
            package.mkdir()
            (package / '__init__.py').write_text('from . import _version\n__version__ = _version\n')
            (package / '_version.py').write_text('__version__ = None\n')
            code = (
                'import importlib.util, sys\n'
                'sys.path.insert(0, sys.argv[1])\n'
                'spec = importlib.util.spec_from_file_location("rotation_probe", sys.argv[2])\n'
                'probe = importlib.util.module_from_spec(spec)\n'
                'spec.loader.exec_module(probe)\n'
                'try:\n probe.cowrie_version_info()\n'
                'except ValueError:\n pass\n'
                'else:\n raise AssertionError("missing runtime version was accepted")\n'
            )
            result = subprocess.run([sys.executable, '-I', '-S', '-c', code, directory, str(PROBE)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_reads_real_bytes_inode_and_missing_path(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'log.jsonl'
            self.assertEqual(self.probe.snapshot(path), {'exists': False})
            data = b'{"test":"complete"}\n'
            path.write_bytes(data)
            result = self.probe.snapshot(path)
            self.assertEqual(result['content_utf8'].encode(), data)
            self.assertEqual(result['inode'], path.stat().st_ino)
            self.assertEqual(result['sha256'], hashlib.sha256(data).hexdigest())

    def test_verification_cli_returns_nonzero_on_bad_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text('{}')
            result = subprocess.run([sys.executable, str(PROBE), 'verify', str(path)], capture_output=True, text=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(json.loads(result.stdout)['status'], 'FAIL')

    def test_verification_cli_accepts_retained_report(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'report.json'
            path.write_text(json.dumps(self.report))
            result = subprocess.run([sys.executable, str(PROBE), 'verify', str(path)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
            self.assertEqual(json.loads(result.stdout)['status'], 'PASS')


if __name__ == '__main__':
    unittest.main()
