"""CLI-level failure and cleanup checks; fake Docker is not image evidence."""
import json
import os
from pathlib import Path
import platform
import re
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
import contextlib
import importlib.util
import io
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / 'scripts/test-main-image.py'
IMAGE = 'sha256:' + 'a' * 64
ARCH = {'x86_64': 'amd64', 'aarch64': 'arm64'}[platform.machine()]


class MainImageRunnerTests(unittest.TestCase):
    def setUp(self):
        self.assertTrue(SCRIPT.is_file(), 'main image smoke runner is missing')
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        docker = self.root / 'docker'
        docker.write_text('#!' + sys.executable + '\n' + '''
import json, os, sys, time
from pathlib import Path
a = sys.argv[2:]  # explicit local --host is always the first argument
root = Path(os.environ['SMOKE_FAKE_ROOT'])
mode = os.environ['SMOKE_FAKE_MODE']
with (root / 'calls').open('a') as f: f.write(json.dumps(a) + '\\n')
image = 'sha256:' + 'a' * 64
if a[:2] == ['info', '--format']:
 print('linux/' + os.environ.get('SMOKE_FAKE_DAEMON', os.environ['SMOKE_FAKE_ARCH']))
elif a[:2] == ['image', 'inspect']:
 print(json.dumps([{'Id': image, 'Os': 'linux',
  'Architecture': 'wrong' if mode == 'architecture' else os.environ['SMOKE_FAKE_ARCH'],
  'Config': {'User': '10001:10001', 'Entrypoint': ['/usr/local/bin/cheesetrap'],
             'Cmd': ['help'], 'Env': ['PATH=/usr/local/bin:/usr/bin:/bin']}}]))
elif a[0] == 'create':
 (root / 'args').write_text(json.dumps(a[a.index(image)+1:]))
 print('fake-container')
elif a[0] == 'start':
 if mode == 'timeout': time.sleep(20)
 if mode == 'stdout_flood': os.write(1, b'x' * (2 * 1024 * 1024))
 if mode == 'stderr_flood': os.write(2, b'x' * (2 * 1024 * 1024))
 if mode == 'combined_flood':
  os.write(1, b'x' * (600 * 1024))
  os.write(2, b'x' * (600 * 1024))
 args = json.loads((root / 'args').read_text())
 code = 0
 if not args:
  print('Usage: cheesetrap api | collector | worker | migrate | admin create', file=sys.stderr)
 elif args == ['api-schema', '--out', '/dev/stdout']:
  print('{}' if mode in ('schema', 'schema_cleanup', 'cleanup_signal_error') else Path(os.environ['SMOKE_FAKE_SCHEMA']).read_text(), end='')
 else:
  code = 1 if args[0] == 'api-schema' else 2
  error = 'runtime_failure' if code == 1 else ('database_url_required' if args == ['api'] else 'invalid_command')
  print(json.dumps({'msg': 'role_failed' if code == 1 else 'configuration_rejected', 'error_code': error}), file=sys.stderr)
 if mode == 'exit':
  print('PRIVATE_RAW_STDERR', file=sys.stderr)
  code = 17
 (root / 'exit').write_text(str(code))
 sys.exit(code)
elif a[:2] == ['container', 'inspect']:
 print(json.dumps([{'Image': image, 'HostConfig': {'ReadonlyRootfs': mode != 'writable_rootfs'}, 'State': {'Running': False,
  'ExitCode': int((root / 'exit').read_text()), 'OOMKilled': mode == 'oom', 'Error': 'PRIVATE_STATE_ERROR' if mode == 'state_error' else ''}}]))
elif a[0] == 'rm':
 if mode == 'cleanup': sys.exit(1)
 counter = root / 'cleanup_count'
 count = int(counter.read_text()) + 1 if counter.exists() else 1
 counter.write_text(str(count))
 if mode == 'schema_cleanup' and count == 2: sys.exit(1)
 if (mode == 'cleanup_signal_first' and count == 1) or (mode == 'cleanup_signal_last' and count == 5) or (mode == 'cleanup_signal_error' and count == 2):
  (root / 'cleanup_ready').touch()
  while not (root / 'cleanup_release').exists(): time.sleep(0.01)
''')
        docker.chmod(0o755)
        self.env = dict(os.environ, PATH=str(self.root) + os.pathsep + os.environ['PATH'],
                        SMOKE_FAKE_ROOT=str(self.root), SMOKE_FAKE_ARCH=ARCH,
                        SMOKE_FAKE_SCHEMA=str(ROOT / 'api/openapi.json'))

    def invoke(self, mode='pass', *extra):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--image', IMAGE,
                               '--architecture', ARCH, *extra],
                              env=dict(self.env, SMOKE_FAKE_MODE=mode), capture_output=True,
                              text=True, timeout=10)

    def calls(self):
        return [json.loads(line) for line in (self.root / 'calls').read_text().splitlines()]

    def test_success_preserves_entrypoint_by_id_with_no_source_mount(self):
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('PASS_MAIN_IMAGE_SMOKE', result.stdout)
        calls = self.calls()
        creates = [c for c in calls if c[0] == 'create']
        self.assertEqual(len(creates), 5)
        self.assertIn('execution=native emulated=false', result.stdout)
        for c in creates:
            self.assertEqual(c[c.index('--network') + 1], 'none')
            self.assertEqual(c[c.index('--platform') + 1], 'linux/' + ARCH)
            self.assertEqual(c[c.index('--pull') + 1], 'never')
            self.assertIn('--read-only', c)
            self.assertNotIn('--mount', c)
            self.assertNotIn('--entrypoint', c)
            self.assertIn(IMAGE, c)
        self.assertEqual(len([c for c in calls if c[0] == 'rm']), 5)

    def test_wrong_architecture_fails_before_container_creation(self):
        result = self.invoke('architecture')
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(any(c[0] == 'create' for c in self.calls()))

    def test_failure_modes_never_claim_pass_and_cleanup(self):
        for mode in ['exit', 'schema', 'oom', 'cleanup', 'timeout', 'writable_rootfs']:
            with self.subTest(mode=mode):
                (self.root / 'calls').unlink(missing_ok=True)
                result = self.invoke(mode, '--timeout', '0.2')
                self.assertNotEqual(result.returncode, 0)
                self.assertNotIn('PASS_MAIN_IMAGE_SMOKE', result.stdout)
                calls = self.calls()
                created = [c[c.index('--name') + 1] for c in calls if c[0] == 'create']
                removed = [c[-1] for c in calls if c[0] == 'rm']
                self.assertTrue(created)
                self.assertEqual(created, removed)
                self.assertEqual(calls[-1][0], 'rm')

    def test_output_limit_fails_without_echo_and_removes_container(self):
        for mode in ['stdout_flood', 'stderr_flood', 'combined_flood']:
            with self.subTest(mode=mode):
                (self.root / 'calls').unlink(missing_ok=True)
                result = self.invoke(mode)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn('FAIL_MAIN_IMAGE_SMOKE output_limit', result.stderr)
                self.assertNotIn('PASS_MAIN_IMAGE_SMOKE', result.stdout)
                self.assertLess(len(result.stdout + result.stderr), 1024)
                calls = self.calls()
                created = [c[c.index('--name') + 1] for c in calls if c[0] == 'create']
                self.assertEqual(len(created), 1)
                self.assertEqual([c[-1] for c in calls if c[0] == 'rm'], created)

    def test_signal_during_first_or_last_cleanup_never_passes(self):
        for mode, count in [('cleanup_signal_first', 1), ('cleanup_signal_last', 5), ('cleanup_signal_error', 2)]:
            for sig in (signal.SIGTERM, signal.SIGINT):
                with self.subTest(mode=mode, signal=sig):
                    for name in ('calls', 'cleanup_count', 'cleanup_ready', 'cleanup_release'):
                        (self.root / name).unlink(missing_ok=True)
                    process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--image', IMAGE,
                                                '--architecture', ARCH],
                                               env=dict(self.env, SMOKE_FAKE_MODE=mode),
                                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        deadline = time.monotonic() + 5
                        while not (self.root / 'cleanup_ready').exists():
                            self.assertIsNone(process.poll(), 'runner exited before cleanup')
                            self.assertLess(time.monotonic(), deadline, 'cleanup was not reached')
                            time.sleep(0.01)
                        process.send_signal(sig)
                        (self.root / 'cleanup_release').touch()
                        stdout, stderr = process.communicate(timeout=5)
                        if mode == 'cleanup_signal_error':
                            self.assertEqual(process.returncode, 1, stdout + stderr)
                            self.assertIn('schema_mismatch', stderr)
                            self.assertIn('interrupted_during_cleanup', stderr)
                        else:
                            self.assertEqual(process.returncode, 128 + sig, stdout + stderr)
                        self.assertNotIn('PASS_MAIN_IMAGE_SMOKE', stdout)
                        self.assertEqual(int((self.root / 'cleanup_count').read_text()), count)
                        calls = self.calls()
                        created = [c[c.index('--name') + 1] for c in calls if c[0] == 'create']
                        self.assertEqual([c[-1] for c in calls if c[0] == 'rm'], created)
                    finally:
                        (self.root / 'cleanup_release').touch()
                        if process.poll() is None:
                            process.kill()
                            process.communicate()

    def test_cleanup_failure_preserves_original_failure(self):
        result = self.invoke('schema_cleanup')
        self.assertEqual(result.returncode, 1)
        self.assertIn('FAIL_MAIN_IMAGE_SMOKE schema_mismatch', result.stderr)
        self.assertIn('FAIL_MAIN_IMAGE_SMOKE cleanup_failed', result.stderr)
        self.assertNotIn('PASS_MAIN_IMAGE_SMOKE', result.stdout)
        self.assertEqual(len([c for c in self.calls() if c[0] == 'rm']), 2)

    def test_production_environment_is_rejected_without_echo(self):
        self.env['CHEESETRAP_DATABASE_URL'] = 'synthetic-forbidden-value'
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn('synthetic-forbidden-value', result.stdout + result.stderr)
        self.assertFalse((self.root / 'calls').exists())

    def test_signal_removes_owned_container(self):
        process = subprocess.Popen([sys.executable, '-B', str(SCRIPT), '--image', IMAGE,
                                    '--architecture', ARCH],
                                   env=dict(self.env, SMOKE_FAKE_MODE='timeout'),
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                if (self.root / 'calls').exists() and any(c[0] == 'start' for c in self.calls()):
                    break
                time.sleep(0.02)
            else:
                self.fail('container start was not reached')
            process.send_signal(signal.SIGTERM)
            stdout, stderr = process.communicate(timeout=5)
            self.assertEqual(process.returncode, 143, stdout + stderr)
            self.assertNotIn('PASS_MAIN_IMAGE_SMOKE', stdout)
            self.assertEqual(self.calls()[-1][0], 'rm')
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


class QemuWorkflowTests(unittest.TestCase):
    def test_fixed_ci_policy_keeps_identity_pins_and_disposable_guard(self):
        workflow = (ROOT/'.github/workflows/arm64-image.yml').read_text()
        guard = workflow.index('Require GitHub-hosted Linux x86_64')
        action = workflow.index('uses: docker/setup-qemu-action@')
        buildkit = workflow.index('Start an owned local BuildKit')
        self.assertLess(guard, action)
        self.assertLess(action, buildkit)
        preflight = workflow[guard:action]
        for check in ('test "$GITHUB_ACTIONS" = true',
                      'test "$RUNNER_ENVIRONMENT" = github-hosted',
                      'test "$RUNNER_OS" = Linux', 'test "$RUNNER_ARCH" = X64',
                      'test "$(uname -s)" = Linux',
                      'test "$(uname -m)" = x86_64', 'linux/amd64|linux/x86_64'):
            self.assertIn(check, preflight)
        qemu = workflow[action:buildkit]
        self.assertRegex(qemu, r'docker/setup-qemu-action@[0-9a-f]{40}\n')
        self.assertRegex(qemu, r'image: tonistiigi/binfmt@sha256:[0-9a-f]{64}\n')
        self.assertIn('platforms: arm64', qemu)
        self.assertIn('cache-image: false', qemu)
        for path in (ROOT/'.github/workflows').glob('*.yml'):
            self.assertTrue(all(value == 'ubuntu-24.04' for value in
                                re.findall(r'runs-on: (.+)', path.read_text())))

    def test_privileged_image_build_is_manual_only(self):
        workflow = (ROOT/'.github/workflows/arm64-image.yml').read_text()
        triggers = workflow.split('\non:\n', 1)[1].split('\nconcurrency:', 1)[0]
        self.assertEqual(triggers.strip(), 'workflow_dispatch:')
        automatic = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertEqual(re.findall(r'^  ([a-z-]+):$', automatic.split('\njobs:\n', 1)[1], re.M),
                         ['secrets', 'dependencies', 'automated'])
        self.assertNotIn('--privileged', automatic)
        self.assertNotIn('setup-qemu-action', automatic)
        self.assertIn('--execution qemu --timeout 60', workflow)
        self.assertIn('--platform linux/arm64', workflow)
        self.assertIn('--oci-worker-net=bridge --cdi-disabled', workflow)
        self.assertIn('for entitlement in network.host security.insecure device', workflow)
        self.assertIn("if: ${{ always() && steps.runner.outcome == 'success' }}", workflow)
        self.assertIn('--force --volumes "$owned"', workflow)

    def test_hosted_checks_keep_read_only_permissions_and_no_secrets_or_artifacts(self):
        for name in ('ci.yml', 'arm64-image.yml'):
            workflow = (ROOT/'.github/workflows'/name).read_text()
            self.assertIn('permissions:\n  contents: read\n', workflow)
            self.assertEqual(re.findall(r'^\s+([a-z-]+): (read|write|none)$', workflow, re.M),
                             [('contents', 'read')])
            actions = re.findall(r'uses: (\S+)', workflow)
            self.assertTrue(actions)
            for action in actions:
                self.assertRegex(action, r'^[\w./-]+@[0-9a-f]{40}$')
            self.assertEqual(workflow.count('uses: actions/checkout@'),
                             workflow.count('persist-credentials: false'))
            self.assertNotRegex(workflow, r'\$\{\{\s*(secrets|vars)\.')
            self.assertNotIn('upload-artifact', workflow)
        automatic = (ROOT/'.github/workflows/ci.yml').read_text()
        self.assertIn('  pull_request:\n', automatic)
        self.assertIn('fetch-depth: 0', automatic)
        self.assertIn('--redact=100', automatic)
        self.assertIn('Verify Testcontainers loopback ports and locked Ryuk image', automatic)
        self.assertIn('scripts/test-acceptance.sh --automated-only', automatic)
        self.assertIn('scripts/release-check.sh --acceptance-results "$result"', automatic)

    def test_privileged_guard_rejects_non_hosted_or_non_x64_runners(self):
        workflow = (ROOT/'.github/workflows/arm64-image.yml').read_text()
        preflight = workflow.split('Require GitHub-hosted Linux x86_64', 1)[1]
        script = textwrap.dedent(preflight.split('run: |\n', 1)[1].split('      - name:', 1)[0])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root/'uname').write_text('#!/bin/sh\ncase "$1" in -s) echo Linux;; -m) echo "${FAKE_HOST_ARCH:-x86_64}";; esac\n')
            (root/'docker').write_text('#!/bin/sh\necho "${FAKE_DAEMON:-linux/amd64}"\nexit "${FAKE_DOCKER_EXIT:-0}"\n')
            for name in ('uname', 'docker'):
                (root/name).chmod(0o755)
            environment = dict(PATH=str(root) + os.pathsep + os.environ['PATH'],
                               GITHUB_ACTIONS='true', RUNNER_ENVIRONMENT='github-hosted',
                               RUNNER_OS='Linux', RUNNER_ARCH='X64')
            for override in ({}, {'GITHUB_ACTIONS': 'false'}, {'RUNNER_ENVIRONMENT': 'self-hosted'},
                             {'RUNNER_OS': 'Windows'}, {'RUNNER_ARCH': 'ARM64'},
                             {'FAKE_HOST_ARCH': 'aarch64'}, {'FAKE_DAEMON': 'linux/arm64'},
                             {'FAKE_DOCKER_EXIT': '1'}):
                with self.subTest(override=override):
                    result = subprocess.run(['bash', '-c', script], env=dict(environment, **override),
                                            capture_output=True, text=True, timeout=5)
                    self.assertEqual(result.returncode == 0, not override, result.stderr)

    def test_builds_run_on_build_platform_and_cross_compile_target(self):
        dockerfile = (ROOT/'deploy/Dockerfile').read_text()
        self.assertRegex(dockerfile, r'FROM --platform=\$BUILDPLATFORM node:[^\n]+ AS ui')
        self.assertRegex(dockerfile, r'FROM --platform=\$BUILDPLATFORM golang:[^\n]+ AS go')
        self.assertIn('ARG TARGETOS\nARG TARGETARCH', dockerfile)
        self.assertIn('CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build', dockerfile)
        self.assertRegex(dockerfile, r'FROM debian:[^\n]+ AS runtime')


class QemuRunnerTests(unittest.TestCase):
    setUp = MainImageRunnerTests.setUp
    calls = MainImageRunnerTests.calls

    def runner(self, mode='pass', *, host='x86_64', system='Linux', binfmt=None,
               architecture='arm64', timeout=0.2):
        spec = importlib.util.spec_from_file_location('qemu_smoke_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        if binfmt is None:
            binfmt = 'enabled\ninterpreter /usr/bin/qemu-aarch64\nflags: POCF\n'
        original_read = Path.read_text
        def read(path, *args, **kwargs):
            if str(path) == '/proc/sys/fs/binfmt_misc/qemu-aarch64':
                if isinstance(binfmt, Exception):
                    raise binfmt
                return binfmt
            return original_read(path, *args, **kwargs)
        stdout, stderr = io.StringIO(), io.StringIO()
        with patch.dict(os.environ, dict(self.env, SMOKE_FAKE_MODE=mode,
                        SMOKE_FAKE_ARCH='arm64', SMOKE_FAKE_DAEMON=self.env.get('SMOKE_FAKE_DAEMON', 'amd64')), clear=True), \
                patch.object(module.platform, 'machine', return_value=host), \
                patch.object(module.platform, 'system', return_value=system), \
                patch.object(Path, 'read_text', read), \
                contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            try:
                result = module.smoke(IMAGE, architecture, timeout, execution='qemu')
            except Exception as error:
                return module, error, stdout.getvalue(), stderr.getvalue()
        return module, result, stdout.getvalue(), stderr.getvalue()

    def test_qemu_success_is_explicit_and_uses_arm64_platform_for_every_case(self):
        _, result, stdout, stderr = self.runner()
        self.assertIsInstance(result, str, stderr)
        self.assertIn('execution=qemu emulated=true', result)
        self.assertIn('checks=5', result)
        self.assertNotIn('PASS', stdout)
        self.assertIn('host=amd64 daemon=amd64 target=arm64 binfmt=F', stdout)
        creates = [c for c in self.calls() if c[0] == 'create']
        self.assertEqual(len(creates), 5)
        self.assertEqual(len([c for c in self.calls() if c[0] == 'rm']), 5)
        for create in creates:
            self.assertEqual(create[create.index('--platform')+1], 'linux/arm64')

    def test_qemu_guard_failures_never_create_containers(self):
        for options in ({'host': 'aarch64'}, {'system': 'Darwin'}, {'architecture': 'amd64'},
                        {'binfmt': FileNotFoundError('PRIVATE_PATH')}, {'binfmt': 'disabled\nflags: F\n'},
                        {'binfmt': 'enabled\nflags: OC\n'}, {'binfmt': 'enabled\ninterpreter F\n'},
                        {'timeout': 61}, {'timeout': float('nan')}, {'timeout': 0}):
            with self.subTest(options=options):
                (self.root/'calls').unlink(missing_ok=True)
                module, error, stdout, stderr = self.runner(**options)
                self.assertIsInstance(error, module.Failure)
                self.assertNotIn('PASS', stdout)
                self.assertNotIn('PRIVATE', stdout+stderr+str(error))
                self.assertFalse((self.root/'calls').exists())

    def test_qemu_daemon_and_image_must_match_contract(self):
        for daemon, mode in [('arm64', 'pass'), ('amd64', 'architecture')]:
            with self.subTest(daemon=daemon, mode=mode):
                (self.root/'calls').unlink(missing_ok=True)
                self.env['SMOKE_FAKE_DAEMON'] = daemon
                module, error, stdout, _ = self.runner(mode)
                self.assertIsInstance(error, module.Failure)
                self.assertNotIn('PASS', stdout)
                self.assertFalse(any(c[0] == 'create' for c in self.calls()))

    def test_qemu_failures_cleanup_and_only_allow_safe_diagnostics(self):
        for mode in ('exit', 'schema', 'oom', 'state_error', 'cleanup', 'timeout', 'writable_rootfs'):
            with self.subTest(mode=mode):
                (self.root/'calls').unlink(missing_ok=True)
                _, error, stdout, stderr = self.runner(mode)
                self.assertIsInstance(error, Exception)
                self.assertNotIn('PASS', stdout)
                self.assertNotIn('PRIVATE', stdout+stderr)
                self.assertIn('execution=qemu', stderr)
                calls = self.calls()
                self.assertEqual([c[c.index('--name')+1] for c in calls if c[0] == 'create'],
                                 [c[-1] for c in calls if c[0] == 'rm'])

    def test_failure_diagnostics_allow_only_fixed_reasons_and_typed_state(self):
        spec = importlib.util.spec_from_file_location('diagnostic_test', SCRIPT)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        state = {'ExitCode': 'PRIVATE_EXIT', 'OOMKilled': 'PRIVATE_OOM',
                 'Running': 'PRIVATE_RUNNING', 'Error': 'PRIVATE_ERROR', 'Logs': 'PRIVATE_LOGS'}
        with patch.object(module, 'inspect', return_value={'State': state}), \
                contextlib.redirect_stderr(io.StringIO()) as stderr:
            module.failure_diagnostic('qemu', 'schema', module.Failure('PRIVATE_REASON'), 'owned')
        self.assertEqual(stderr.getvalue(), 'IMAGE_FAILURE execution=qemu case=schema reason=runner_error\n')

    def test_cli_rejects_native_31_seconds_and_qemu_61_seconds(self):
        for execution, timeout in [('native', '31'), ('qemu', '61')]:
            result = MainImageRunnerTests.invoke(self, 'pass', '--execution', execution, '--timeout', timeout)
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn('invalid_timeout', result.stderr)
            self.assertFalse((self.root/'calls').exists())


if __name__ == '__main__':
    unittest.main()
