#!/usr/bin/env python3
"""Shared Python CI gates; no empty suites or skipped required tests pass."""
import argparse
import importlib.util
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
REGRESSIONS = (
    'scripts/test_backup_restore.py', 'scripts/test_raw_retention.py',
    'scripts/test_storage_capacity.py', 'scripts/test_performance_metrics.py',
    'scripts/test_backup_budget.py',
    'scripts/test_operations_docs.py', 'scripts/validation/test_network_fixture.py',
    'scripts/validation/test_rotation_probe.py',
    'scripts/test_validation_bundle_path.py',
)


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupt(signum, _frame):
    raise Interrupted(signum)


def run_process(command, timeout, *, capture=False):
    """Bound a process group, including children, on timeout or interruption."""
    process = subprocess.Popen(command, stdin=subprocess.DEVNULL, start_new_session=True,
                               stdout=subprocess.PIPE if capture else None, text=True)
    try:
        output, _ = process.communicate(timeout=timeout)
        if process.returncode:
            raise subprocess.CalledProcessError(process.returncode, command)
        return (output or '').strip()
    finally:
        # Descendants may outlive their group leader, including after a failure.
        for sig in (signal.SIGTERM, signal.SIGKILL):
            try:
                os.killpg(process.pid, sig)
            except ProcessLookupError:
                break
            if sig == signal.SIGTERM:
                try:
                    process.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
        process.wait(timeout=5)


def run_unit(path):
    path = Path(path).resolve(strict=True)
    sys.path.insert(0, str(path.parent))
    spec = importlib.util.spec_from_file_location(path.stem, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    suite = unittest.defaultTestLoader.loadTestsFromModule(module)
    if not suite.countTestCases():
        raise ValueError('no tests collected: ' + str(path))
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    if not result.wasSuccessful() or result.skipped or not result.testsRun:
        raise ValueError('required Python tests failed, skipped, or did not execute: ' + str(path))


def regression_files():
    runners = sorted(str(p.relative_to(ROOT)) for p in (ROOT / 'scripts').glob('test_*runner.py'))
    if not runners:
        raise ValueError('no runner regression files found')
    return runners + list(REGRESSIONS)


def run_regressions(timeout):
    for name in regression_files():
        print('Running Python regression: ' + name, flush=True)
        run_process([sys.executable, '-B', str(Path(__file__).resolve()), 'unit', str(ROOT / name)], timeout)
    print('PASS_PYTHON_REGRESSION', flush=True)


def run_images(image, timeout):
    image_id = run_process(['docker', 'image', 'inspect', '--format', '{{.Id}}', image], 30, capture=True)
    if not re.fullmatch(r'sha256:[0-9a-f]{64}', image_id):
        raise ValueError('invalid local image ID; build the pinned patched image first')
    print('Python engine test image: ' + image_id, flush=True)
    files = [Path(__file__).resolve()] + [ROOT / 'sensors/web' / name for name in
             ('request_evidence.py', 'test_request_evidence.py', 'test_reactor_evidence.py')]
    commands = [('/checks/test-python.py', 'unit', '/checks/test_request_evidence.py'),
                ('/checks/test_reactor_evidence.py',)]
    for command in commands:
        name = 'cheesetrap-python-' + uuid.uuid4().hex
        create = ['docker', 'create', '--name', name, '--network', 'none', '--read-only',
                  '--tmpfs', '/tmp:rw,nosuid,nodev,size=64m', '--memory', '512m', '--cpus', '1',
                  '--pids-limit', '128', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--workdir', '/checks', '--entrypoint', '/opencanary/.venv/bin/python',
                  '-e', 'CHEESETRAP_REQUIRE_TWISTED_TESTS=1', '-e', 'PYTHONDONTWRITEBYTECODE=1']
        for file in files:
            if not file.is_file():
                raise ValueError('missing image test input: ' + str(file))
            create += ['--mount', f'type=bind,source={file},target=/checks/{file.name},readonly']
        try:
            run_process(create + [image_id, '-B', *command], 30, capture=True)
            run_process(['docker', 'start', '-a', name], timeout)
        finally:
            # Cleanup uses only our random container name, never shared resources.
            previous = {sig: signal.signal(sig, signal.SIG_IGN) for sig in (signal.SIGINT, signal.SIGTERM)}
            try:
                cleanup = subprocess.run(['docker', 'rm', '-f', name], capture_output=True, text=True, timeout=30)
                if cleanup.returncode and 'No such container' not in cleanup.stderr:
                    raise RuntimeError('failed to remove owned test container: ' + name)
            finally:
                for sig, handler in previous.items():
                    signal.signal(sig, handler)
    print('PASS_PYTHON_IMAGE ' + image_id, flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest='mode', required=True)
    unit = modes.add_parser('unit', help='run one unittest file; reject skips and empty collection')
    unit.add_argument('path')
    regression = modes.add_parser('regression', help='run all general Python regressions')
    regression.add_argument('--list', action='store_true', help='list files without importing tests')
    regression.add_argument('--timeout', type=float, default=180, help='seconds per file')
    image = modes.add_parser('image', help='test the locally built pinned patched engine image')
    image.add_argument('--image', required=True)
    image.add_argument('--timeout', type=float, default=120, help='seconds per container')
    args = parser.parse_args()
    if hasattr(args, 'timeout') and args.timeout <= 0:
        parser.error('--timeout must be positive')
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupt)
    if args.mode == 'unit':
        run_unit(args.path)
    elif args.mode == 'regression':
        if args.list:
            print('\n'.join(regression_files()))
        else:
            run_regressions(args.timeout)
    else:
        run_images(args.image, args.timeout)


if __name__ == '__main__':
    try:
        main()
    except Interrupted as error:
        print('FAIL: interrupted', file=sys.stderr)
        sys.exit(128 + error.signum)
    except subprocess.TimeoutExpired:
        print('FAIL: Python test command timed out', file=sys.stderr)
        sys.exit(124)
    except subprocess.CalledProcessError as error:
        print('FAIL: Python test command exited ' + str(error.returncode), file=sys.stderr)
        sys.exit(error.returncode if error.returncode > 0 else 128 - error.returncode)
    except (OSError, ValueError, RuntimeError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)
