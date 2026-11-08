#!/usr/bin/env python3
"""Fail-closed T01–T13 acceptance. No operational targets or SMTP credentials.

Linux evidence is operator-supplied, never synthesized from Compose/unit tests.
The JSON and all referenced logs remain private in .local, outside Git.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import signal
import shutil
import stat
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
LINUX_CHECKS = {'linux-install', 'linux-public-boundary', 'linux-sensor-egress', 'linux-ipv6'}


class AcceptanceInterrupted(Exception):
    def __init__(self, signum):
        self.signum = signum
        super().__init__('acceptance interrupted; active harness cleanup requested')


class AcceptanceTimeout(Exception):
    pass


def interrupted(signum, _frame):
    # A second signal must not cut short the harness's owned Compose cleanup.
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, signal.SIG_IGN)
    raise AcceptanceInterrupted(signum)


def install_signal_handlers():
    for sig in (signal.SIGINT, signal.SIGTERM): signal.signal(sig, interrupted)


def stop_command(active, cleanup_timeout):
    previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    for sig in previous: signal.signal(sig, signal.SIG_IGN)
    try:
        # The integration harness catches TERM, stops its separately-owned
        # command groups, and tears down only its random Compose project.
        try: os.killpg(active.pid, signal.SIGTERM)
        except ProcessLookupError: pass
        try: active.wait(timeout=cleanup_timeout)
        except subprocess.TimeoutExpired: pass
        # Kill uncooperative descendants in our group even if their leader exited.
        try: os.killpg(active.pid, signal.SIGKILL)
        except ProcessLookupError: pass
        active.wait(timeout=5)
    finally:
        for sig, handler in previous.items(): signal.signal(sig, handler)


def run_command(command, *, cwd, env, log, timeout, cleanup_timeout=90):
    with log.open('w') as stream:
        active = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                  stdout=stream, stderr=subprocess.STDOUT, start_new_session=True)
        try:
            return active.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            stop_command(active, cleanup_timeout)
            raise AcceptanceTimeout('acceptance command timed out; active harness cleanup requested') from None
        except BaseException:
            stop_command(active, cleanup_timeout)
            raise


def validate_manifest(manifest):
    rows = manifest.get('requirements', [])
    if manifest.get('schema') != 1 or len(rows) != 13 or {r.get('id') for r in rows} != {f'T{i:02}' for i in range(1, 14)}:
        raise ValueError('coverage must contain exactly T01–T13 once')
    for row in rows:
        if not row.get('tests') or not isinstance(row.get('linux'), list):
            raise ValueError('each requirement needs named tests and explicit Linux dependencies')
        if not set(row['linux']) <= LINUX_CHECKS:
            raise ValueError('unknown Linux requirement')
        for test in row['tests']:
            if test.get('suite') not in ('go', 'integration', 'e2e') or not test.get('package', '').startswith('cheesetrap/') or not re.fullmatch(r'Test[A-Za-z0-9_]+', test.get('name', '')):
                raise ValueError('invalid concrete test identity')


def go_results(output):
    passed, errors = set(), []
    for line in output.splitlines():
        try: event = json.loads(line)
        except json.JSONDecodeError: continue
        if not isinstance(event, dict): continue
        identity = (event.get('Package'), event.get('Test'))
        action = event.get('Action')
        if action == 'pass' and identity[1]: passed.add(identity)
        if action == 'fail' or (action == 'skip' and identity[1]): errors.append(identity)
    if not passed: errors.append(('runner', 'no tests executed'))
    return passed, errors


def harness_results(output, code, expected_logs, root=ROOT):
    """Validate every owned batch before merging its concrete test results."""
    logs = re.findall(r'evidence (\.local/[A-Za-z0-9_./-]+\.jsonl)', output)
    if code != 0 or len(logs) != expected_logs or len(set(logs)) != expected_logs:
        raise ValueError('invalid integration evidence count or exit status')
    passed = set()
    for relative in logs:
        path = (root / relative).resolve()
        if not path.is_relative_to((root / '.local').resolve()) or not path.is_file():
            raise ValueError('missing or invalid integration evidence path')
        batch, errors = go_results(path.read_text())
        if errors:
            raise ValueError('integration evidence contains failed, skipped or empty tests')
        passed.update(batch)
    return passed, logs


def ui_document(document):
    """Validate the reporter envelope; never classify failure message contents."""
    if not isinstance(document, dict) or type(document.get('success')) is not bool or not isinstance(document.get('testResults'), list):
        raise ValueError('invalid UI report schema')
    passed, categories, failures, seen = set(), set(), [], set()
    if not document['success']: categories.add('ui_reported_failure')
    for file in document['testResults']:
        if not isinstance(file, dict) or not isinstance(file.get('name'), str) or not file['name'] or file.get('status') not in ('passed', 'failed') or not isinstance(file.get('assertionResults'), list):
            raise ValueError('invalid UI report schema')
        name = file['name']
        if file['status'] == 'failed':
            categories.add('ui_suite_failed')
            failures.append((name, None))
        if not file['assertionResults']: categories.add('ui_empty_results')
        for test in file['assertionResults']:
            if not isinstance(test, dict) or not all(isinstance(test.get(key), str) and test[key] for key in ('title', 'fullName')) or test.get('status') not in ('passed', 'failed', 'pending', 'skipped', 'todo', 'disabled'):
                raise ValueError('invalid UI report schema')
            path = Path(name)
            relative = str(path.relative_to(ROOT / 'web')) if path.is_absolute() and path.is_relative_to(ROOT / 'web') else name
            identity = (relative, test['fullName'])
            if identity in seen: raise ValueError('duplicate UI test identity')
            seen.add(identity)
            if test['status'] == 'passed':
                passed.add(identity)
            else:
                categories.add('ui_test_failed' if test['status'] == 'failed' else 'ui_test_skipped')
                failures.append((name, test))
    if not seen: categories.add('ui_empty_results')
    return passed, categories, failures


def ui_results(document):
    passed, categories, _ = ui_document(document)
    if categories: raise ValueError('UI report did not pass')
    return passed


def ui_declarations(sources):
    """Best-effort AST inventory; parser failure must never print raw output."""
    sources = {path: source for path, source in sources.items()
               if re.fullmatch(r'web/src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.test\.tsx?', path)}
    if not sources: return {}
    try:
        result = subprocess.run(['node', str(ROOT / 'scripts/ui-test-identities.mjs')],
                                input=json.dumps(sources), text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=10, check=True,
                                env={key: os.environ[key] for key in ('PATH', 'LANG') if key in os.environ})
        parsed = json.loads(result.stdout)
        if isinstance(parsed, dict): return parsed
    except (OSError, ValueError, subprocess.SubprocessError):
        pass
    return {}


def ui_source_identity(name, test, sources, declarations):
    """Match source AST, exact reporter location AND literal title; emit no text."""
    for path, source in sources.items():
        if not re.fullmatch(r'web/src/(?:[A-Za-z0-9_-]+/)*[A-Za-z0-9_.-]+\.test\.tsx?', path): continue
        if name not in (path, path.removeprefix('web/'), str(ROOT / path)): continue
        location = test.get('location') if isinstance(test, dict) else None
        if not isinstance(location, dict) or any(type(location.get(key)) is not int or location[key] < 1 for key in ('line', 'column')):
            return path, None
        candidates = declarations.get(path, [])
        if not isinstance(candidates, list): return path, None
        matches = [item for item in candidates if isinstance(item, dict)
                   and item.get('title') == test['title']
                   and item.get('line') == location['line'] and item.get('column') == location['column']
                   and location['line'] <= len(source.splitlines())]
        return path, location['line'] if len(matches) == 1 else None
    return None, None


def ui_check(report, code, sources, process_status='exited'):
    """Fail closed with a bounded, allowlisted public diagnostic projection."""
    process_status = process_status if process_status in ('exited', 'start_failed', 'timed_out', 'interrupted') else 'unknown'
    code = code if type(code) is int and -255 <= code <= 255 else None
    row = {'returncode': code, 'process_status': process_status,
           'report_present': None, 'report_status': 'unreadable',
           'categories': [], 'tests': [], 'locations': [], 'files': []}
    categories = set()
    if process_status != 'exited': categories.add('process_' + process_status)
    elif code is None: categories.add('process_unknown')
    elif code != 0: categories.add('process_failed')
    passed, failures = set(), []
    try:
        # Refuse symlinks/FIFOs/devices and bound private report memory. Never
        # echo OS/JSON exception messages, absolute paths or the report itself.
        mode = report.lstat().st_mode
        row['report_present'] = True
        if not stat.S_ISREG(mode): raise OSError('invalid report type')
        fd = os.open(report, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode): raise OSError('invalid report type')
            raw = stream.read(8 * 1024 * 1024 + 1)
        if len(raw) > 8 * 1024 * 1024:
            row['report_status'] = 'too_large'
        else:
            try:
                document = json.loads(raw)
            except (ValueError, UnicodeError, RecursionError):
                row['report_status'] = 'malformed'
            else:
                try:
                    passed, found, failures = ui_document(document)
                except (ValueError, TypeError, RecursionError):
                    row['report_status'] = 'invalid_schema'
                else:
                    row['report_status'] = 'valid'
                    categories.update(found)
    except FileNotFoundError:
        row.update(report_present=False, report_status='missing')
    except OSError:
        pass
    if row['report_status'] != 'valid': categories.add('ui_report_' + row['report_status'])
    tests, locations, files = set(), set(), set()
    declarations = ui_declarations(sources) if failures else {}
    for name, test in failures:
        path, line = ui_source_identity(name, test, sources, declarations)
        if path:
            files.add(path)
            if line:
                tests.add(path + '::test@' + str(line))
                locations.add(path + ':' + str(line))
    row.update(categories=sorted(categories), tests=sorted(tests)[:40],
               locations=sorted(locations)[:40], files=sorted(files)[:40])
    return (set() if categories else passed), row


def browser_results(document):
    passed = set()
    def walk(suite):
        for spec in suite.get('specs', []):
            tests = spec.get('tests', [])
            if not tests: raise ValueError('empty browser spec')
            for test in tests:
                results = test.get('results', [])
                if test.get('expectedStatus') != 'passed' or test.get('status') != 'expected' or len(results) != 1 or results[0].get('status') != 'passed':
                    raise ValueError('browser test failed, skipped or retried')
                identity = (spec['file'], spec['title'])
                if identity in passed: raise ValueError('duplicate browser test')
                passed.add(identity)
        for child in suite.get('suites', []): walk(child)
    walk(document)
    if not passed: raise ValueError('no browser tests executed')
    return passed


def public_diagnostics(output, sources):
    """Emit source-owned identifiers and fixed categories, never runtime text."""
    tests, locations = set(), set()
    events, plain = [], []
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            plain.append(line)
            continue
        if isinstance(event, dict) and 'Action' in event:
            events.append(event)
    failed = {(e.get('Package'), e.get('Test')) for e in events
              if e.get('Action') in ('fail', 'skip')}
    # Go's timeout panic ends the package without a per-test fail event.
    # Retain unfinished identities only when that package actually fails;
    # the source allowlist below removes unknown names and dynamic suffixes.
    active, timed_out = set(), set()
    for event in events:
        package, test = event.get('Package'), event.get('Test')
        action = event.get('Action')
        if action == 'start':
            active = {identity for identity in active if identity[0] != package}
            timed_out.discard(package)
        elif action == 'run' and isinstance(test, str):
            active.add((package, test))
        elif action in ('pass', 'fail', 'skip') and isinstance(test, str):
            active.discard((package, test))
        elif action == 'output' and isinstance(event.get('Output'), str) and event['Output'].startswith('panic: test timed out after '):
            timed_out.add(package)
        elif action == 'fail' and test is None and package in timed_out:
            failed.update(identity for identity in active if identity[0] == package)
    for event in events:
        if (event.get('Package'), event.get('Test')) in failed:
            if isinstance(event.get('Output'), str): plain.append(event['Output'])
    text = '\n'.join(plain)
    for path, source in sorted(sources.items()):
        # Paths come from tracked source, not from the logs or environment.
        if not re.fullmatch(r'[A-Za-z0-9_./-]+', path): continue
        package = 'cheesetrap/' + str(Path(path).parent)
        for name in re.findall(r'^func (Test[A-Za-z0-9_]+)\(', source, re.M):
            if any(p == package and isinstance(n, str) and n.split('/')[0] == name for p, n in failed) or re.search(r'--- FAIL: ' + re.escape(name) + r'(?:[/\s]|$)', text):
                tests.add(path + '::' + name)
        for name in re.findall(r'^\s*def (test_[A-Za-z0-9_]+)\(', source, re.M):
            if re.search(r'^\s*(?:FAIL|ERROR): ' + re.escape(name) + r'\s', text, re.M):
                tests.add(path + '::' + name)
        if events and path.endswith('.go') and package not in {p for p, _ in failed}:
            continue
        filename = re.escape(Path(path).name)
        numbers = re.findall(r'\b' + filename + r':(\d+):', text)
        numbers += re.findall(r'/' + filename + r'", line (\d+)', text)
        for line in numbers:
            if 1 <= int(line) <= len(source.splitlines()): locations.add(path + ':' + str(int(line)))
    categories = {name for name, marker in (
        ('deadline_exceeded', 'context deadline exceeded'),
        ('test_timeout', 'test timed out'), ('permission_denied', 'permission denied'),
        ('disk_full', 'no space left on device'), ('storage_pressure', 'storage_pressure'),
        ('insufficient_free_disk', 'insufficient_free_disk'),
        ('integration_subprocess_failed', 'integration subprocess failed'),
        ('postgres_startup_failed', 'Testcontainers PostgreSQL startup failed'),
        ('cleanup_failed', 'owned integration project cleanup failed'),
        ('e2e_infrastructure_failed', 'E2E infrastructure failure'),
        ('missing_dependency', 'ModuleNotFoundError'), ('assertion_failed', 'AssertionError'),
    ) if marker in output}
    return {'tests': sorted(tests)[:40], 'locations': sorted(locations)[:40],
            'categories': sorted(categories)}


def print_public_summary(commands):
    tracked = subprocess.check_output(['git', 'ls-files', '-z'], cwd=ROOT).decode().split('\0')
    sources = {name: (ROOT / name).read_text() for name in tracked
               if name.endswith(('.go', '.py', '.ts', '.tsx')) and (ROOT / name).is_file()
               and not (ROOT / name).is_symlink()}
    allowed = {'runner-tests', 'go', 'vet', 'integration', 'e2e', 'ui', 'ui-build',
               'api-schema', 'api-types', 'api-contract', 'sql-schema', 'generated-clean'}
    for command in commands:
        name = command['name']
        if name not in allowed: continue
        row = {'command': name, 'status': 'PASS' if command['status'] == 'PASS' else 'FAIL'}
        if name == 'ui':
            _, diagnostics = ui_check(ROOT / command['report'], command.get('returncode'), sources,
                                      command.get('process_status', 'exited'))
            row.update(diagnostics)
            if diagnostics['categories']: row['status'] = 'FAIL'
        elif command['status'] != 'PASS':
            output = ''
            if command.get('log'):
                output = (ROOT / command['log']).read_text(errors='replace')
                # Failure runners also name their private JSONL. Read it locally;
                # never upload it or echo any of its runtime output fields.
                logs = re.findall(r'(\.local/[A-Za-z0-9_./-]+\.jsonl)', output)
                evidence = []
                for relative in sorted(set(logs)):
                    path = (ROOT / relative).resolve()
                    if path.is_relative_to((ROOT / '.local').resolve()) and path.is_file():
                        evidence.append(path.read_text(errors='replace'))
                # A later batch can fail outside Go after earlier tests passed.
                # Retain runner failures alongside the concrete test evidence.
                if evidence: output = '\n'.join([output, *evidence])
            row.update(public_diagnostics(output, sources))
        print('CI_CHECK ' + json.dumps(row, sort_keys=True), flush=True)


def production_sources():
    """Bind live evidence to tracked runtime inputs, including uncommitted edits.

    Tests, docs and acceptance harnesses are excluded; runtime Go, SQL, sensor,
    deployment, installer, UI and API schema inputs are included.
    """
    tracked = subprocess.check_output(['git', 'ls-files', '--cached', '--others', '--exclude-standard', '-z'], cwd=ROOT).decode().split('\0')
    result = {}
    for name in tracked:
        if not name or not (name in ('go.mod', 'go.sum', 'sqlc.yaml', 'tokens.css', '.dockerignore', 'web/package.json', 'web/package-lock.json', 'web/vite.config.ts', 'web/tsconfig.json', 'web/tsconfig.node.json', 'web/index.html') or name.startswith(('cmd/', 'internal/', 'migrations/', 'deploy/', 'sensors/', 'web/src/', 'api/')) or name.startswith(('scripts/install', 'scripts/backup', 'scripts/restore', 'scripts/raw_retention', 'scripts/retain-raw', 'scripts/validation/'))): continue
        path = Path(name)
        if path.name.startswith('test_') or path.name.endswith('_test.go') or '.test.' in path.name or 'testdata' in path.parts: continue
        full = ROOT / name
        result[name] = hashlib.sha256(full.read_bytes()).hexdigest() if full.is_file() else 'MISSING'
    return result


def linux_results(document, directory, revision):
    env = document.get('environment', {})
    if document.get('source_sha256') != production_sources():
        raise ValueError('Linux evidence production source hashes differ from current working tree')
    if document.get('schema') != 1 or document.get('revision') != revision:
        raise ValueError('Linux evidence missing or from a different revision')
    if env.get('os') != 'Linux' or env.get('actual_host') is not True or not all(env.get(k) for k in ('host', 'kernel', 'docker')):
        raise ValueError('actual Linux host provenance required; Desktop/mocks are insufficient')
    results = {}
    for check in document.get('checks', []):
        identity, status = check.get('id'), check.get('status')
        if identity not in LINUX_CHECKS or identity in results or check.get('method') != 'live-linux':
            raise ValueError('unknown, duplicate or mocked Linux check')
        if status not in ('PASS', 'FAIL', 'BLOCKED', 'UNSUPPORTED_ADDRESS_FAMILY'):
            raise ValueError('invalid Linux status; skip is not acceptance')
        if status == 'UNSUPPORTED_ADDRESS_FAMILY' and (identity != 'linux-ipv6' or not check.get('reason')):
            raise ValueError('only explicit IPv6 unsupported evidence is permitted')
        if not check.get('command') or not check.get('observed_at'):
            raise ValueError('Linux command and observation time required')
        relative = Path(check.get('log', ''))
        path = (directory / relative).resolve()
        if relative.is_absolute() or not path.is_relative_to(directory.resolve()) or not path.is_file():
            raise ValueError('Linux log missing or outside evidence directory')
        if hashlib.sha256(path.read_bytes()).hexdigest() != check.get('sha256'):
            raise ValueError('Linux evidence digest mismatch')
        results[identity] = check
    return results


def evaluate(manifest, suites, linux):
    result = []
    for row in manifest['requirements']:
        missing = [test for test in row['tests'] if (test['package'], test['name']) not in suites.get(test['suite'], set())]
        missing += [dict(suite='browser', package=test['file'], name=test['name']) for test in row.get('browser_tests', []) if (test['file'], test['name']) not in suites.get('browser', set())]
        missing += [dict(suite='ui', package=test['file'], name=test['name']) for test in row.get('ui_tests', []) if (test['file'], test['name']) not in suites.get('ui', set())]
        live = {name: linux.get(name, {'status': 'BLOCKED', 'reason': 'current actual Linux evidence missing'}) for name in row['linux']}
        status = 'FAIL' if missing or any(c['status'] == 'FAIL' for c in live.values()) else 'BLOCKED' if any(c['status'] == 'BLOCKED' for c in live.values()) else 'PASS'
        result.append({'id': row['id'], 'status': status, 'missing_tests': missing, 'linux': live})
    return result


def run_status(rows, commands, automated=False):
    if any(c['status'] == 'FAIL' for c in commands) or any(r['status'] == 'FAIL' for r in rows): return 'FAIL'
    if automated: return 'PASS_AUTOMATED'
    return 'BLOCKED' if any(r['status'] == 'BLOCKED' for r in rows) else 'PASS'


def checkout_is_clean(root):
    """Snapshot tracked and untracked inputs before running acceptance commands."""
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, text=True)
    return not status.strip()


def generated_snapshot():
    generated = [ROOT / 'api/openapi.json', ROOT / 'web/src/api/schema.d.ts'] + sorted((ROOT / 'internal/store/db').glob('*.go'))
    generated += sorted(path for path in (ROOT / 'web/src/api/generated').rglob('*') if path.is_file())
    return {str(path): path.read_bytes() for path in generated if path.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument('--linux-evidence', type=Path)
    mode.add_argument('--automated-only', action='store_true', help='CI checks only; never asserts full Linux acceptance')
    args = parser.parse_args()
    install_signal_handlers()
    os.umask(0o077)
    # Match the owned DB harness policy and reject production/test targets.
    if any(v and ('DATABASE_URL' in k or k.startswith(('CHEESETRAP_', 'PLAYWRIGHT_'))) for k, v in os.environ.items()):
        raise ValueError('unset operational/test configuration before acceptance')
    if os.environ.get('DOCKER_HOST') or os.environ.get('DOCKER_CONTEXT'):
        raise ValueError('Docker target overrides must be unset')
    manifest = json.loads((ROOT / 'tests/acceptance/coverage.json').read_text())
    validate_manifest(manifest)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    checkout_clean = checkout_is_clean(ROOT)
    source_hashes = production_sources()
    diff = subprocess.check_output(['git', 'diff', 'HEAD', '--binary'], cwd=ROOT)
    stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S.%fZ')
    out = ROOT / '.local/acceptance' / stamp
    out.mkdir(parents=True)
    env = {k: os.environ[k] for k in ('PATH', 'HOME', 'TMPDIR', 'USER', 'LANG') if k in os.environ}
    env.update(GOENV='off', GOWORK='off', GOFLAGS='', GOTOOLCHAIN='local')
    suites, commands = {}, []
    def run(name, command, cwd=ROOT, timeout=1200, report=None):
        print('Running ' + name, flush=True)
        log = out / (name + '.log')
        record = {'name': name, 'command': command, 'status': 'FAIL', 'log': str(log.relative_to(ROOT)),
                  'returncode': None, 'process_status': 'exited'}
        if report is not None: record['report'] = str(report.relative_to(ROOT))
        commands.append(record)
        try:
            code = run_command(command, cwd=cwd, env=env, log=log, timeout=timeout)
        except (AcceptanceInterrupted, AcceptanceTimeout) as error:
            record.update(reason=str(error), process_status='interrupted' if isinstance(error, AcceptanceInterrupted) else 'timed_out')
            (out / 'results.json').write_text(json.dumps({'schema': 1, 'revision': revision, 'checkout_clean': checkout_clean, 'tracked_diff_sha256': hashlib.sha256(diff).hexdigest(), 'started_at': stamp, 'status': 'FAIL', 'aborted': True, 'reason': str(error), 'commands': commands}, indent=2) + '\n')
            print_public_summary(commands)
            raise
        except OSError:
            code = None
            record['process_status'] = 'start_failed'
        record.update(status='PASS' if code == 0 else 'FAIL', returncode=code)
        return code, log.read_text(errors='replace') if name != 'ui' and log.exists() else ''
    # Keep the result key for release-gate compatibility; include every general
    # Python regression, with required skips and empty collection failing closed.
    run('runner-tests', ['python3', '-B', 'scripts/test-python.py', 'regression'])
    code, output = run('go', ['go', 'test', './...', '-count=1', '-json'])
    suites['go'], errors = go_results(output)
    if errors: commands[-1]['status'] = 'FAIL'
    run('vet', ['go', 'vet', './...'])
    browser_json = ROOT / '.local/e2e/browser-results.json'
    for name, command in [('integration', ['./scripts/test-integration.sh', './...']), ('e2e', ['./scripts/test-e2e.sh'])]:
        if name == 'e2e': browser_json.unlink(missing_ok=True)
        code, output = run(name, command)
        try:
            # Full integration owns three isolated batches; E2E owns one.
            suites[name], logs = harness_results(output, code, 3 if name == 'integration' else 1)
            commands[-1]['test_logs'] = logs
            if len(logs) == 1: commands[-1]['test_log'] = logs[0]
        except (ValueError, OSError):
            commands[-1]['status'] = 'FAIL'
        if name == 'e2e':
            try:
                suites['browser'] = browser_results(json.loads(browser_json.read_text()))
                preserved = out / 'browser.json'
                shutil.copyfile(browser_json, preserved)
                commands[-1]['browser_log'] = str(preserved.relative_to(ROOT))
            except (ValueError, OSError, KeyError): commands[-1]['status'] = 'FAIL'
    ui_json = out / 'ui.json'
    code, _ = run('ui', ['npm', 'run', 'test', '--', '--run', '--includeTaskLocation', '--reporter=json', '--outputFile=' + str(ui_json)], ROOT / 'web', report=ui_json)
    suites['ui'], diagnostics = ui_check(ui_json, code, {}, commands[-1]['process_status'])
    if diagnostics['categories']: commands[-1]['status'] = 'FAIL'
    run('ui-build', ['npm', 'run', 'build'], ROOT / 'web')
    before = generated_snapshot()
    run('api-schema', ['go', 'run', './cmd/cheesetrap', 'api-schema', '--out', 'api/openapi.json'])
    run('api-types', ['npm', 'run', 'generate:api'], ROOT / 'web')
    run('api-contract', ['npm', 'run', 'test:api'], ROOT / 'web')
    run('sql-schema', ['./scripts/generate-sql.sh'])
    after = generated_snapshot()
    changed = sorted(path for path in before.keys() | after.keys() if before.get(path) != after.get(path))
    commands.append({'name': 'generated-clean', 'status': 'FAIL' if changed else 'PASS', 'changed': changed})
    linux, linux_error = {}, None
    if args.linux_evidence:
        try: linux = linux_results(json.loads(args.linux_evidence.read_text()), args.linux_evidence.resolve().parent, revision)
        except (ValueError, OSError, KeyError) as error: linux_error = str(error)
    rows = evaluate(manifest, suites, linux)
    status = 'FAIL' if linux_error else run_status(rows, commands, args.automated_only)
    report = {'schema': 1, 'revision': revision, 'source_sha256': source_hashes, 'tracked_diff_sha256': hashlib.sha256(diff).hexdigest(), 'checkout_clean': checkout_clean, 'started_at': stamp, 'status': status,
              'environment': {'os': platform.system(), 'release': platform.release(), 'machine': platform.machine(), 'python': platform.python_version()},
              'commands': commands, 'tests': {suite: [dict(package=p, name=n) for p, n in sorted(tests)] for suite, tests in suites.items()},
              'requirements': rows, 'linux_error': linux_error}
    (out / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print_public_summary(commands)
    print(f'{status}: {out.relative_to(ROOT)}/results.json')
    return 0 if status in ('PASS', 'PASS_AUTOMATED') else 2 if status == 'BLOCKED' else 1

if __name__ == '__main__':
    try: sys.exit(main())
    except AcceptanceInterrupted as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(128 + error.signum)
    except AcceptanceTimeout as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(124)
    except (ValueError, OSError) as error:
        print('FAIL: ' + str(error), file=sys.stderr)
        sys.exit(1)
