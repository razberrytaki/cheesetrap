import copy
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
import tempfile
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location('acceptance_runner', Path(__file__).with_name('test-acceptance.py'))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)

class AcceptanceGateTests(unittest.TestCase):
    def test_generated_snapshot_detects_model_changes_additions_and_deletions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / 'web/src/api/generated/models.ts'
            model.parent.mkdir(parents=True)
            model.write_text('export type Model = string;')
            with mock.patch.object(runner, 'ROOT', root):
                before = runner.generated_snapshot()
                model.write_text('export type Model = number;')
                self.assertNotEqual(before, runner.generated_snapshot())
                model.write_text('export type Model = string;')
                self.assertEqual(before, runner.generated_snapshot())
                extra = model.with_name('extra.ts')
                extra.write_text('export type Extra = string;')
                self.assertNotEqual(before, runner.generated_snapshot())
                extra.unlink()
                model.unlink()
                self.assertNotEqual(before, runner.generated_snapshot())

    def test_summary_retains_runner_failures_after_successful_batch_evidence(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.local').mkdir()
            (root / '.local/passed.jsonl').write_text(json.dumps({
                'Action': 'pass', 'Package': 'cheesetrap/example', 'Test': 'TestPassed',
            }) + '\n')
            (root / '.local/integration.log').write_text(
                'PASS: 1 tests; evidence .local/passed.jsonl\n'
                'Testcontainers PostgreSQL startup failed\n'
                'owned integration project cleanup failed\n'
                'private-runtime-canary\n')
            captured = io.StringIO()
            with mock.patch.object(runner, 'ROOT', root), \
                 mock.patch.object(runner.subprocess, 'check_output', return_value=b''), \
                 contextlib.redirect_stdout(captured):
                runner.print_public_summary([{
                    'name': 'integration', 'status': 'FAIL', 'log': '.local/integration.log',
                }])
            row = json.loads(captured.getvalue().removeprefix('CI_CHECK '))
            self.assertEqual(row, {'command': 'integration', 'status': 'FAIL',
                                  'categories': ['cleanup_failed', 'postgres_startup_failed'],
                                  'tests': [], 'locations': []})
            self.assertNotIn('private-runtime-canary', captured.getvalue())

    def test_harness_merges_three_isolated_batches_and_single_e2e(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / '.local').mkdir()
            logs, expected = [], set()
            for n in range(3):
                identity = ('cheesetrap/example', f'TestBatch{n}')
                expected.add(identity)
                relative = f'.local/batch{n}.jsonl'
                (root / relative).write_text(json.dumps(dict(Action='pass', Package=identity[0], Test=identity[1])))
                logs.append(relative)
            output = '\n'.join('PASS: 1 tests; evidence ' + path for path in logs)
            self.assertEqual(runner.harness_results(output, 0, 3, root), (expected, logs))
            self.assertEqual(runner.harness_results('evidence ' + logs[0], 0, 1, root),
                             ({('cheesetrap/example', 'TestBatch0')}, logs[:1]))
            for case in ('failed-exit', 'missing-batch', 'duplicate', 'missing-file', 'empty', 'fail', 'skip', 'escape'):
                with self.subTest(case=case):
                    changed, code = output, 0
                    path = root / logs[-1]
                    original = path.read_text()
                    if case == 'failed-exit': code = 1
                    if case == 'missing-batch': changed = '\n'.join(output.splitlines()[:-1])
                    if case == 'duplicate': changed = output.replace(logs[-1], logs[0])
                    if case == 'missing-file': path.unlink()
                    if case == 'empty': path.write_text('')
                    if case in ('fail', 'skip'):
                        path.write_text(original + '\n' + json.dumps(dict(Action=case, Package='cheesetrap/example', Test='TestBad')))
                    if case == 'escape':
                        (root / 'outside.jsonl').write_text(original)
                        changed = output.replace(logs[-1], '.local/../outside.jsonl')
                    with self.assertRaises(ValueError):
                        runner.harness_results(changed, code, 3, root)
                    path.write_text(original)

    def test_public_diagnostics_never_echo_runtime_values(self):
        sources = {'internal/example/check_test.go': 'package example\nfunc TestCheck(t *testing.T) {\n}\n',
                   'scripts/test_fixture.py': 'def test_fixture(self):\n    pass\n',
                   'internal/unrelated/check_test.go': 'package unrelated\nfunc TestOther(t *testing.T) {\n}\n'}
        secret = 'runtime-secret-value'
        output = '\n'.join([
            json.dumps({'Action': 'fail', 'Package': 'cheesetrap/internal/example',
                        'Test': 'TestCheck/' + secret, 'Output': secret}),
            '    check_test.go:3: password=' + secret,
            '    FAIL: test_fixture (fixture.Tests.test_fixture)',
            'context deadline exceeded: https://user:' + secret + '@private.invalid',
            '--- FAIL: TestInvented' + secret,
            'File "/private/' + secret + '/test_fixture.py", line 2',
        ])
        summary = runner.public_diagnostics(output, sources)
        self.assertNotIn(secret, json.dumps(summary))
        self.assertNotIn('private.invalid', json.dumps(summary))
        self.assertEqual(summary['tests'], ['internal/example/check_test.go::TestCheck',
                                            'scripts/test_fixture.py::test_fixture'])
        self.assertEqual(summary['locations'], ['internal/example/check_test.go:3',
                                                'scripts/test_fixture.py:2'])
        self.assertIn('deadline_exceeded', summary['categories'])

    def test_public_diagnostics_reject_unknown_names_and_out_of_range_lines(self):
        sources = {'internal/check_test.go': 'func TestKnown(t *testing.T) {}\n'}
        summary = runner.public_diagnostics('--- FAIL: TestUnknown\ncheck_test.go:999: token\n', sources)
        self.assertEqual(summary['tests'], [])
        self.assertEqual(summary['locations'], [])
        self.assertNotIn('token', json.dumps(summary))

    def test_public_timeout_identifies_unfinished_source_tests_without_test_fail_event(self):
        sources = {'internal/example/check_test.go':
                   'func TestPassed(t *testing.T) {}\nfunc TestPending(t *testing.T) {}\n'}
        package = 'cheesetrap/internal/example'
        events = [
            dict(Action='start', Package=package),
            dict(Action='run', Package=package, Test='TestPassed'),
            dict(Action='pass', Package=package, Test='TestPassed'),
            dict(Action='run', Package=package, Test='TestPending/runtime-secret'),
            dict(Action='run', Package=package, Test='TestUnknown/runtime-secret'),
            dict(Action='output', Package=package, Test='TestPending/runtime-secret',
                 Output='panic: test timed out after 3m0s\n'),
            dict(Action='fail', Package=package),
        ]
        summary = runner.public_diagnostics('\n'.join(map(json.dumps, events)), sources)
        self.assertEqual(summary['tests'], ['internal/example/check_test.go::TestPending'])
        self.assertEqual(summary['categories'], ['test_timeout'])
        self.assertNotIn('runtime-secret', json.dumps(summary))
        # A timeout-like log from a completed test is not evidence of a crash.
        events[-1:] = [dict(Action='pass', Package=package, Test='TestPending/runtime-secret'),
                       dict(Action='pass', Package=package)]
        self.assertEqual(runner.public_diagnostics('\n'.join(map(json.dumps, events)), sources)['tests'], [])

    def manifest(self):
        return {'schema': 1, 'requirements': [{'id': f'T{i:02}', 'tests': [{'suite': 'go', 'package': 'cheesetrap/example', 'name': f'Test{i}'}], 'linux': []} for i in range(1, 14)]}

    def test_checkout_provenance_observes_untracked_and_modified_inputs(self):
        self.assertTrue(callable(getattr(runner, 'checkout_is_clean', None)), 'checkout provenance recorder missing')
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(['git', 'init', '-q', str(root)], check=True)
            (root / '.gitignore').write_text('.local/\n')
            (root / 'test.py').write_text('original')
            subprocess.run(['git', 'add', '.'], cwd=root, check=True)
            subprocess.run(['git', '-c', 'user.name=Test', '-c', 'user.email=test@example.invalid', 'commit', '-qm', 'fixture'], cwd=root, check=True)
            self.assertTrue(runner.checkout_is_clean(root))
            (root / '.local').mkdir()
            (root / '.local/result.json').write_text('private result')
            self.assertTrue(runner.checkout_is_clean(root))
            (root / 'extra_test.py').write_text('untracked test')
            self.assertFalse(runner.checkout_is_clean(root))
            (root / 'extra_test.py').unlink()
            (root / 'test.py').write_text('modified test')
            self.assertFalse(runner.checkout_is_clean(root))
            (root / 'test.py').write_text('original')
            self.assertTrue(runner.checkout_is_clean(root))

    def test_manifest_requires_exact_traceability(self):
        runner.validate_manifest(self.manifest())
        for change in ('missing', 'duplicate', 'empty', 'unknown-suite'):
            manifest = self.manifest()
            if change == 'missing': manifest['requirements'].pop()
            if change == 'duplicate': manifest['requirements'][-1]['id'] = 'T01'
            if change == 'empty': manifest['requirements'][0]['tests'] = []
            if change == 'unknown-suite': manifest['requirements'][0]['tests'][0]['suite'] = 'mock-linux'
            with self.subTest(change=change), self.assertRaises(ValueError):
                runner.validate_manifest(manifest)

    def test_go_skip_fail_and_missing_never_pass(self):
        event = {'Package': 'cheesetrap/example', 'Test': 'Test1', 'Action': 'pass'}
        passed, errors = runner.go_results(json.dumps(event))
        self.assertIn(('cheesetrap/example', 'Test1'), passed)
        self.assertFalse(errors)
        for action in ('skip', 'fail'):
            event['Action'] = action
            passed, errors = runner.go_results(json.dumps(event))
            self.assertTrue(errors)
            self.assertNotIn(('cheesetrap/example', 'Test1'), passed)
        self.assertTrue(runner.go_results('no tests')[1])
        self.assertTrue(runner.go_results(json.dumps({'Action': 'fail', 'Package': 'broken'}))[1])

    def test_missing_test_fails_requirement(self):
        result = runner.evaluate(self.manifest(), {'go': set()}, {})
        self.assertTrue(all(row['status'] == 'FAIL' for row in result))

    def test_linux_cannot_be_replaced_by_unit_pass(self):
        manifest = self.manifest()
        manifest['requirements'][0]['linux'] = ['linux-public-boundary']
        passed = {'go': {('cheesetrap/example', f'Test{i}') for i in range(1, 14)}}
        result = runner.evaluate(manifest, passed, {})
        self.assertEqual(result[0]['status'], 'BLOCKED')
        self.assertEqual(result[1]['status'], 'PASS')

    def test_linux_evidence_requires_live_provenance_and_bound_logs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'probe.json').write_text('{"observed":true}')
            sha = hashlib.sha256((root / 'probe.json').read_bytes()).hexdigest()
            document = {'schema': 1, 'revision': 'abc', 'source_sha256': runner.production_sources(), 'environment': {'os': 'Linux', 'host': 'isolated-test', 'kernel': '6.8', 'docker': '29', 'actual_host': True}, 'checks': [{'id': 'linux-public-boundary', 'status': 'PASS', 'method': 'live-linux', 'command': 'paired probes', 'log': 'probe.json', 'sha256': sha, 'observed_at': '2026-10-21T00:00:00Z'}]}
            self.assertEqual(runner.linux_results(document, root, 'abc')['linux-public-boundary']['status'], 'PASS')
            for change in ('mock', 'desktop', 'missing-log', 'wrong-hash', 'old', 'invalid-status', 'unsupported-wrong-check', 'changed-source'):
                bad = copy.deepcopy(document)
                if change == 'changed-source': bad['source_sha256'] = {}
                if change == 'mock': bad['checks'][0]['method'] = 'mock'
                if change == 'desktop': bad['environment']['actual_host'] = False
                if change == 'missing-log': bad['checks'][0]['log'] = 'missing'
                if change == 'wrong-hash': bad['checks'][0]['sha256'] = '0'*64
                if change == 'old': bad['revision'] = 'old'
                if change == 'invalid-status': bad['checks'][0]['status'] = 'SKIP'
                if change == 'unsupported-wrong-check': bad['checks'][0]['status'] = 'UNSUPPORTED_ADDRESS_FAMILY'
                with self.subTest(change=change), self.assertRaises(ValueError):
                    runner.linux_results(bad, root, 'abc')
            unsupported = copy.deepcopy(document)
            unsupported['checks'][0].update(id='linux-ipv6', status='UNSUPPORTED_ADDRESS_FAMILY', reason='Public IPv6 unsupported; live disable state checked')
            self.assertEqual(runner.linux_results(unsupported, root, 'abc')['linux-ipv6']['status'], 'UNSUPPORTED_ADDRESS_FAMILY')

    def cleanup_harness(self, directory):
        harness = directory / 'harness.py'
        harness.write_text("""import os, signal, subprocess, sys, time
from pathlib import Path
root = Path(sys.argv[1])
child = None
def cleanup(signum, frame):
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    if child is not None:
        os.killpg(child.pid, signal.SIGTERM)
        child.wait(timeout=2)
    (root / 'cleaned').write_text('yes')
    sys.exit(0)
signal.signal(signal.SIGTERM, cleanup)
child = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)'], start_new_session=True)
(root / 'child.pid').write_text(str(child.pid))
(root / 'ready').write_text('yes')
time.sleep(30)
""")
        return [sys.executable, str(harness), str(directory)]

    def assert_child_cleaned(self, directory):
        self.assertTrue((directory / 'cleaned').is_file(), 'harness cleanup was bypassed')
        pid = int((directory / 'child.pid').read_text())
        with self.assertRaises(ProcessLookupError): os.kill(pid, 0)

    def test_timeout_allows_harness_to_clean_separate_child_group(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            command = self.cleanup_harness(directory)
            with self.assertRaises(runner.AcceptanceTimeout):
                runner.run_command(command, cwd=directory, env=os.environ.copy(), log=directory / 'run.log', timeout=1, cleanup_timeout=3)
            self.assert_child_cleaned(directory)

    def test_sigterm_forwards_then_stops_orchestration(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            command = self.cleanup_harness(directory)
            code = f"""import importlib.util, pathlib, os, sys
spec = importlib.util.spec_from_file_location('runner', {str(Path(runner.__file__).resolve())!r})
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)
r.install_signal_handlers()
try:
    r.run_command({command!r}, cwd=pathlib.Path({temp!r}), env=os.environ.copy(), log=pathlib.Path({str(directory / 'run.log')!r}), timeout=30, cleanup_timeout=3)
    pathlib.Path({str(directory / 'continued')!r}).write_text('wrong')
except r.AcceptanceInterrupted:
    sys.exit(143)
"""
            outer = subprocess.Popen([sys.executable, '-c', code], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            try:
                deadline = time.monotonic() + 5
                while not (directory / 'ready').exists() and outer.poll() is None and time.monotonic() < deadline: time.sleep(0.02)
                self.assertTrue((directory / 'ready').exists(), outer.communicate(timeout=1) if outer.poll() is not None else 'harness never ready')
                outer.send_signal(signal.SIGTERM)
                stdout, stderr = outer.communicate(timeout=6)
                self.assertEqual(outer.returncode, 143, stderr)
                self.assertFalse((directory / 'continued').exists())
                self.assert_child_cleaned(directory)
            finally:
                if outer.poll() is None: outer.kill(); outer.wait()

    def test_uncooperative_harness_is_killed_after_grace(self):
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            pidfile = directory / 'pid'
            command = [sys.executable, '-c', f"import os,signal,time; from pathlib import Path; signal.signal(signal.SIGTERM,signal.SIG_IGN); Path({str(pidfile)!r}).write_text(str(os.getpid())); time.sleep(30)"]
            start = time.monotonic()
            with self.assertRaises(runner.AcceptanceTimeout):
                runner.run_command(command, cwd=directory, env=os.environ.copy(), log=directory / 'run.log', timeout=1, cleanup_timeout=0.2)
            self.assertLess(time.monotonic() - start, 4)
            with self.assertRaises(ProcessLookupError): os.kill(int(pidfile.read_text()), 0)

    def test_browser_names_and_skips(self):
        doc = {'suites': [{'suites': [{'specs': [{'file': 'review.spec.ts', 'title': 'review', 'tests': [{'expectedStatus': 'passed', 'status': 'expected', 'results': [{'status': 'passed'}]}]}]}]}]}
        self.assertEqual(runner.browser_results(doc), {('review.spec.ts', 'review')})
        doc['suites'][0]['suites'][0]['specs'][0]['tests'][0]['results'][0]['status'] = 'skipped'
        self.assertRaises(ValueError, runner.browser_results, doc)
        self.assertRaises(ValueError, runner.browser_results, {'suites': []})

    def test_automated_mode_never_claims_full_acceptance(self):
        rows = [{'status': 'BLOCKED'}]
        self.assertEqual(runner.run_status(rows, [], False), 'BLOCKED')
        self.assertEqual(runner.run_status(rows, [], True), 'PASS_AUTOMATED')
        self.assertEqual(runner.run_status(rows, [{'status': 'FAIL'}], True), 'FAIL')
        self.assertEqual(runner.run_status([{'status': 'FAIL'}], [], True), 'FAIL')

    def test_ui_skips_and_empty_are_failures(self):
        self.assertRaises(ValueError, runner.ui_results, {'success': True, 'testResults': []})
        result = {'success': True, 'testResults': [{'name': 'ui', 'status': 'passed', 'assertionResults': [{'title': 'escape HTML', 'fullName': 'escape HTML', 'status': 'passed'}]}]}
        self.assertEqual(runner.ui_results(result), {('ui', 'escape HTML')})
        result['testResults'][0]['assertionResults'][0]['status'] = 'pending'
        self.assertRaises(ValueError, runner.ui_results, result)

if __name__ == '__main__': unittest.main()
