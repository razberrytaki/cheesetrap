"""Process-level regression tests for Python CI collection and failure gates."""
import importlib.util
import json
import os
import signal
import time
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test-python.py'


class PythonRunnerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'shared Python test runner is missing')
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def invoke(self, *args, env=None):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), *args],
                              env=env, text=True, capture_output=True, timeout=10)

    def test_empty_skip_failure_and_import_error_fail_closed(self):
        bodies = ['pass', 'import unittest\n@unittest.skip("missing runtime")\nclass T(unittest.TestCase):\n def test_it(self): pass',
                  'import unittest\nclass T(unittest.TestCase):\n def test_it(self): self.fail("injected")',
                  'raise RuntimeError("import failed")']
        for body in bodies:
            with self.subTest(body=body):
                fixture = self.root / 'test_fixture.py'
                fixture.write_text(body)
                result = self.invoke('unit', str(fixture))
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_passing_test_executes(self):
        marker = self.root / 'executed'
        fixture = self.root / 'test_fixture.py'
        fixture.write_text('import unittest\nfrom pathlib import Path\nclass T(unittest.TestCase):\n def test_it(self): Path(' + repr(str(marker)) + ').touch()\n')
        result = self.invoke('unit', str(fixture))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(marker.exists())

    def test_regression_collection_contains_missing_files_without_install_duplicate(self):
        result = self.invoke('regression', '--list')
        self.assertEqual(result.returncode, 0, result.stderr)
        collected = result.stdout.splitlines()
        expected = ['scripts/test_backup_restore.py', 'scripts/test_raw_retention.py',
                    'scripts/test_storage_capacity.py', 'scripts/test_performance_metrics.py',
                    'scripts/test_operations_docs.py', 'scripts/validation/test_network_fixture.py',
                    'scripts/validation/test_rotation_probe.py', 'scripts/test_python_runner.py']
        self.assertTrue(set(expected) <= set(collected), collected)
        self.assertEqual(len(collected), len(set(collected)))
        self.assertNotIn('scripts/test_install.py', collected)
        self.assertNotIn('sensors/web/test_reactor_evidence.py', collected)

    def fake_docker(self, mode):
        docker = self.root / 'docker'
        docker.write_text('#!' + sys.executable + '\n' + '''import json, os, sys, time
from pathlib import Path
with Path(os.environ['DOCKER_TEST_LOG']).open('a') as stream:
 stream.write(json.dumps(sys.argv[1:]) + '\\n')
if sys.argv[1:3] == ['image', 'inspect']:
 print('sha256:' + 'a'*64)
elif sys.argv[1] == 'create':
 print(sys.argv[sys.argv.index('--name')+1])
elif sys.argv[1] == 'start':
 if os.environ['DOCKER_TEST_MODE'] == 'failure': sys.exit(17)
 if os.environ['DOCKER_TEST_MODE'] == 'timeout': time.sleep(30)
''')
        docker.chmod(0o755)
        env = os.environ.copy()
        env.update(PATH=str(self.root) + os.pathsep + env['PATH'],
                   DOCKER_TEST_LOG=str(self.root / 'docker.jsonl'), DOCKER_TEST_MODE=mode)
        return env

    def test_image_failure_and_timeout_propagate_and_remove_owned_container(self):
        for mode, code in [('failure', 17), ('timeout', 124)]:
            with self.subTest(mode=mode):
                env = self.fake_docker(mode)
                result = self.invoke('image', '--image', 'test:local', '--timeout', '0.2', env=env)
                self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                calls = [json.loads(s) for s in (self.root / 'docker.jsonl').read_text().splitlines()]
                created = [c[c.index('--name')+1] for c in calls if c[0] == 'create']
                self.assertTrue(created)
                self.assertEqual(calls[-1], ['rm', '-f', created[-1]])
                (self.root / 'docker.jsonl').unlink()

    def test_image_runs_both_suites_with_pinned_id_and_isolation(self):
        result = self.invoke('image', '--image', 'test:local', env=self.fake_docker('pass'))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        calls = [json.loads(s) for s in (self.root / 'docker.jsonl').read_text().splitlines()]
        creates = [c for c in calls if c[0] == 'create']
        self.assertEqual(len(creates), 2)
        for c in creates:
            self.assertIn('sha256:' + 'a'*64, c)
            self.assertEqual(c[c.index('--network')+1], 'none')
            self.assertIn('--read-only', c)
            self.assertIn('CHEESETRAP_REQUIRE_TWISTED_TESTS=1', c)
            self.assertEqual(c[c.index('--entrypoint')+1], '/opencanary/.venv/bin/python')
            self.assertTrue(all('readonly' in c[i+1] for i, x in enumerate(c) if x == '--mount'))
        self.assertIn('unit', creates[0])
        self.assertEqual(creates[1][-1], '/checks/test_reactor_evidence.py')
        self.assertEqual(len([c for c in calls if c[0] == 'rm']), 2)

    def test_image_interruption_removes_owned_container(self):
        env = self.fake_docker('timeout')
        process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), 'image', '--image', 'test:local'],
                                   env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            log = self.root / 'docker.jsonl'
            deadline = time.monotonic() + 5
            calls = []
            while time.monotonic() < deadline and process.poll() is None:
                calls = [json.loads(s) for s in log.read_text().splitlines()] if log.exists() else []
                if any(c[0] == 'start' for c in calls):
                    break
                time.sleep(0.02)
            self.assertTrue(any(c[0] == 'start' for c in calls), 'container never started')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=6)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            calls = [json.loads(s) for s in log.read_text().splitlines()]
            name = next(c[c.index('--name')+1] for c in calls if c[0] == 'create')
            self.assertEqual(calls[-1], ['rm', '-f', name])
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()

    def test_regression_failure_and_timeout_stop_before_later_files(self):
        import shutil
        local = self.root / 'scripts/test-python.py'
        local.parent.mkdir()
        shutil.copyfile(SCRIPT, local)
        fixture = local.with_name('test_injected_runner.py')
        for body, expected in [('import unittest\nclass T(unittest.TestCase):\n def test_it(self): self.fail("injected")', 1),
                               ('import time; time.sleep(30)', 124)]:
            with self.subTest(expected=expected):
                fixture.write_text(body)
                result = subprocess.run([sys.executable, '-B', str(local), 'regression', '--timeout', '0.3'],
                                        text=True, capture_output=True, timeout=6)
                self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                self.assertNotIn('PASS_PYTHON_REGRESSION', result.stdout)
                self.assertNotIn('Running Python regression: scripts/test_backup_restore.py', result.stdout)

    def test_failed_python_command_cannot_produce_pass_automated(self):
        fixture = self.root / 'test_fixture.py'
        fixture.write_text('import unittest\nclass T(unittest.TestCase):\n def test_it(self): self.fail("injected")\n')
        spec = importlib.util.spec_from_file_location('acceptance', ROOT / 'scripts/test-acceptance.py')
        acceptance = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(acceptance)
        code = acceptance.run_command([sys.executable, '-B', str(SCRIPT), 'unit', str(fixture)],
                                      cwd=ROOT, env=os.environ.copy(), log=self.root / 'acceptance.log', timeout=5)
        self.assertNotEqual(code, 0)
        status = acceptance.run_status([{'status': 'BLOCKED'}],
                                       [{'name': 'runner-tests', 'status': 'PASS' if code == 0 else 'FAIL'}], True)
        self.assertEqual(status, 'FAIL')


if __name__ == '__main__':
    unittest.main()
