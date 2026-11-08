#!/usr/bin/env python3
"""Bounded, offline CLI smoke of the actual local runtime image (no DB/E2E claim)."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import selectors
import signal
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
DOCKER = ['docker', '--host=unix:///var/run/docker.sock']
OUTPUT_LIMIT = 1024 * 1024  # Combined stdout/stderr per Docker command, including attach.


class Failure(Exception):
    pass


class Interrupted(Exception):
    def __init__(self, signum):
        self.signum = signum


def interrupt(signum, _frame):
    raise Interrupted(signum)


def require(condition, code):
    if not condition:
        raise Failure(code)


def command(args, timeout=10, *, expected=0):
    # Never pass the host environment as container environment. Preserve Docker's
    # registry configuration but force the local Unix socket, not a remote context.
    env = {k: v for k, v in os.environ.items() if k not in
           ('DOCKER_HOST', 'DOCKER_CONTEXT', 'DOCKER_TLS', 'DOCKER_TLS_VERIFY', 'DOCKER_CERT_PATH')}
    process = subprocess.Popen(DOCKER + args, env=env, stdin=subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               start_new_session=True)
    try:
        deadline = time.monotonic() + timeout
        output = [bytearray(), bytearray()]
        size = 0
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise subprocess.TimeoutExpired(DOCKER + args, timeout)
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), 65536)
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    size += len(chunk)
                    require(size <= OUTPUT_LIMIT, 'output_limit')
                    output[key.data].extend(chunk)
        process.wait(timeout=max(0, deadline - time.monotonic()))
        require(process.returncode == expected, 'command_exit')
        return bytes(output[0]), bytes(output[1])
    finally:
        # The container has a separate lifetime; the caller removes it in finally.
        # Never drain unbounded pipes during error cleanup. Kill descendants even
        # if the group leader has exited with a child still holding a pipe open.
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.stdout.close()
        process.stderr.close()
        process.wait(timeout=5)


def remove_owned_container(name, primary_error):
    pending_signal = None

    def remember_interrupt(signum, _frame):
        nonlocal pending_signal
        if pending_signal is None:
            pending_signal = signum

    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    cleanup_error = None
    try:
        for sig in previous:
            signal.signal(sig, remember_interrupt)
        command(['rm', '--force', '--volumes', name])
    except Exception as error:
        cleanup_error = error
    finally:
        for sig, handler in previous.items():
            signal.signal(sig, handler)
    # Preserve an already propagating failure, with only fixed supplementary
    # diagnostics. A newly received interrupt must never turn into a PASS.
    if primary_error is not None:
        if cleanup_error is not None:
            print('FAIL_MAIN_IMAGE_SMOKE cleanup_failed', file=sys.stderr)
        if pending_signal is not None:
            print('FAIL_MAIN_IMAGE_SMOKE interrupted_during_cleanup', file=sys.stderr)
        return
    if cleanup_error is not None:
        if pending_signal is not None:
            print('FAIL_MAIN_IMAGE_SMOKE interrupted_during_cleanup', file=sys.stderr)
        raise cleanup_error
    if pending_signal is not None:
        raise Interrupted(pending_signal)


def inspect(kind, target):
    stdout, _ = command([kind, 'inspect', target])
    return json.loads(stdout)[0]


def check_error(stderr, code):
    records = [json.loads(line) for line in stderr.splitlines() if line]
    require(any(record.get('error_code') == code for record in records), 'error_contract')


def failure_diagnostic(execution, label, error, name):
    safe_reasons = {'command_exit', 'output_limit', 'container_state', 'readonly_rootfs',
                    'help_contract', 'schema_mismatch', 'error_contract'}
    reason = ('timeout' if isinstance(error, subprocess.TimeoutExpired) else
              'interrupted' if isinstance(error, Interrupted) else
              str(error) if isinstance(error, Failure) and str(error) in safe_reasons else 'runner_error')
    fields = [f'execution={execution}', f'case={label}', f'reason={reason}']
    try:
        state = inspect('container', name)['State']
        if type(state.get('ExitCode')) is int:
            fields.append(f'exit={state["ExitCode"]}')
        for key, label in (('OOMKilled', 'oom'), ('Running', 'running')):
            if type(state.get(key)) is bool:
                fields.append(f'{label}={str(state[key]).lower()}')
    except Exception:
        fields.append('state=unavailable')
    print('IMAGE_FAILURE ' + ' '.join(fields), file=sys.stderr, flush=True)


def smoke(image, architecture, timeout, *, execution):
    require(execution in ('native', 'qemu'), 'invalid_execution')
    require(0 < timeout <= (60 if execution == 'qemu' else 30), 'invalid_timeout')
    require(not any(value and (key.startswith('CHEESETRAP_') or 'DATABASE_URL' in key)
                    for key, value in os.environ.items()), 'external_configuration')
    host_arch = {'x86_64': 'amd64', 'aarch64': 'arm64'}.get(platform.machine())
    if execution == 'qemu':
        require(platform.system() == 'Linux' and platform.machine() == 'x86_64' and
                architecture == 'arm64', 'qemu_host_target_required')
        try:
            registration = Path('/proc/sys/fs/binfmt_misc/qemu-aarch64').read_text().splitlines()
        except OSError:
            raise Failure('qemu_binfmt_required') from None
        require(bool(registration) and registration[0] == 'enabled' and
                any(re.fullmatch(r'flags: [A-Z]*F[A-Z]*', line) for line in registration),
                'qemu_binfmt_required')
    else:
        require(platform.system() == 'Linux' and host_arch == architecture, 'native_host_required')
    require(re.fullmatch(r'sha256:[0-9a-f]{64}', image), 'immutable_image_id_required')
    daemon, _ = command(['info', '--format', '{{.OSType}}/{{.Architecture}}'])
    daemon_arch = 'amd64' if execution == 'qemu' else architecture
    aliases = ('amd64', 'x86_64') if daemon_arch == 'amd64' else ('arm64', 'aarch64')
    require(daemon.strip().decode() in {'linux/' + alias for alias in aliases},
            'qemu_daemon_required' if execution == 'qemu' else 'native_daemon_required')
    emulated = str(execution == 'qemu').lower()
    print(f'IMAGE_EXECUTION execution={execution} emulated={emulated} host={host_arch} '
          f'daemon={daemon_arch} target={architecture} binfmt={"F" if execution == "qemu" else "none"}',
          flush=True)
    metadata = inspect('image', image)
    require(metadata['Id'] == image and metadata['Os'] == 'linux' and
            metadata['Architecture'] == architecture, 'image_architecture')
    config = metadata['Config']
    require(config.get('User') == '10001:10001' and
            config.get('Entrypoint') == ['/usr/local/bin/cheesetrap'] and
            config.get('Cmd') == ['help'] and not config.get('Volumes'), 'runtime_configuration')
    require(not any(value.partition('=')[0].startswith('CHEESETRAP_') or
                    'DATABASE_URL' in value.partition('=')[0]
                    for value in config.get('Env', [])), 'image_configuration')
    expected_schema = (ROOT / 'api/openapi.json').read_bytes()
    require(bool(json.loads(expected_schema).get('paths')), 'empty_schema')
    cases = [
        ('default_help', [], 0, None),
        ('schema', ['api-schema', '--out', '/dev/stdout'], 0, None),
        ('invalid_command', ['synthetic-invalid-command'], 2, 'invalid_command'),
        ('missing_database', ['api'], 2, 'database_url_required'),
        ('readonly_output', ['api-schema', '--out', '/synthetic-openapi.json'], 1, 'runtime_failure'),
    ]
    for label, args, expected_exit, error_code in cases:
        name = 'cheesetrap-main-smoke-' + uuid.uuid4().hex
        create = ['create', '--platform', 'linux/' + architecture, '--name', name, '--pull', 'never', '--network', 'none',
                  '--read-only', '--tmpfs', '/tmp:rw,noexec,nosuid,nodev,size=16m',
                  '--memory', '256m', '--memory-swap', '256m', '--cpus', '1',
                  '--pids-limit', '64', '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges',
                  '--log-driver', 'json-file', '--log-opt', 'max-size=1m', '--log-opt', 'max-file=1']
        # Docker client proxy defaults must not enter the offline test container.
        for key in ('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY',
                    'http_proxy', 'https_proxy', 'all_proxy', 'no_proxy'):
            create += ['--env', key + '=']
        try:
            command(create + [image, *args])
            stdout, stderr = command(['start', '-a', name], timeout, expected=expected_exit)
            actual = inspect('container', name)
            state = actual['State']
            require(actual['Image'] == image and not state['Running'] and
                    state['ExitCode'] == expected_exit and not state['OOMKilled'] and
                    not state.get('Error'), 'container_state')
            require(actual['HostConfig']['ReadonlyRootfs'] is True, 'readonly_rootfs')
            if label == 'default_help':
                require(b'Usage: cheesetrap api | collector | worker | migrate | admin create' in stderr,
                        'help_contract')
            elif label == 'schema':
                require(stdout == expected_schema, 'schema_mismatch')
            else:
                check_error(stderr, error_code)
        except Exception as error:
            failure_diagnostic(execution, label, error, name)
            raise
        finally:
            # Cleanup is bounded and only touches our unique name. Failure is not PASS.
            try:
                remove_owned_container(name, sys.exc_info()[1])
            except Exception:
                print(f'IMAGE_FAILURE execution={execution} case={label} reason=cleanup_failed',
                      file=sys.stderr, flush=True)
                raise
        print(f'IMAGE_CHECK {label} execution={execution} emulated={emulated} exit={expected_exit} image_id={image}', flush=True)
    digest = hashlib.sha256(expected_schema).hexdigest()
    return (f'PASS_MAIN_IMAGE_SMOKE execution={execution} emulated={emulated} architecture={architecture} '
            f'image_id={image} checks={len(cases)} schema_sha256={digest}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image', required=True, help='local sha256 image ID from build --iidfile')
    parser.add_argument('--architecture', choices=('arm64', 'amd64'), default='arm64',
                        help='target image architecture; QEMU requires arm64, amd64 is native rehearsal only')
    parser.add_argument('--execution', choices=('native', 'qemu'), default='native')
    parser.add_argument('--timeout', type=float, default=20,
                        help='per-container seconds, at most 30 native or 60 QEMU')
    args = parser.parse_args()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupt)
    print(smoke(args.image, args.architecture, args.timeout, execution=args.execution), flush=True)


if __name__ == '__main__':
    try:
        main()
    except Interrupted as error:
        print('FAIL_MAIN_IMAGE_SMOKE interrupted', file=sys.stderr)
        sys.exit(128 + error.signum)
    except subprocess.TimeoutExpired:
        print('FAIL_MAIN_IMAGE_SMOKE timeout', file=sys.stderr)
        sys.exit(124)
    except Failure as error:
        print('FAIL_MAIN_IMAGE_SMOKE ' + str(error), file=sys.stderr)
        sys.exit(1)
    except (OSError, ValueError, KeyError, IndexError, TypeError):
        # Do not expose raw container output, environment, or subprocess arguments.
        print('FAIL_MAIN_IMAGE_SMOKE runner_error', file=sys.stderr)
        sys.exit(1)
