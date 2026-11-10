#!/usr/bin/env python3
"""Read-only release metadata gate; never runs a deployment or asserts live tests."""
import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = (
    'README.md', 'CONTRIBUTING.md', 'SECURITY.md', 'THIRD_PARTY_NOTICES.md', 'LICENSE',
    'docs/operations/release.md', 'docs/operations/install.md', 'docs/operations/upgrade.md',
    'docs/operations/backup-restore.md', 'docs/operations/retention.md',
    'deploy/toolchain.lock.json', 'deploy/images.lock.json',
    'third_party/notices.json', '.nvmrc', '.github/workflows/ci.yml',
    'go.mod', 'go.sum', 'web/package.json', 'web/package-lock.json',
    'scripts/generate-sql.sh', 'scripts/release-check.sh', 'scripts/test-testcontainers.py', 'tests/acceptance/coverage.json',
    'sensors/images.lock', 'sensors/cowrie/commands.py',
    'sensors/cowrie/LICENSE-BSD-3-Clause.txt',
    'sensors/web/request_evidence.py', 'sensors/web/patches/request-evidence.patch',
)
IMAGE_FILES = ('deploy/Dockerfile', 'deploy/compose.yaml', 'deploy/compose.external-db.yaml', 'deploy/test.compose.yaml', 'sensors/web/Dockerfile')
ACCEPTANCE_COMMANDS = ('runner-tests', 'go', 'vet', 'integration', 'e2e', 'ui', 'ui-build',
                       'api-schema', 'api-types', 'api-contract', 'sql-schema', 'generated-clean')


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def read_json(root, name):
    try:
        data = json.loads((root / name).read_text())
    except (OSError, ValueError) as error:
        raise ValueError(f'{name}: missing or invalid JSON') from error
    require(isinstance(data, dict), f'{name}: JSON object required')
    return data


def sha(root, name):
    path = Path(name)
    require(not path.is_absolute() and '..' not in path.parts, f'unsafe metadata path: {name}')
    try:
        return hashlib.sha256((root / path).read_bytes()).hexdigest()
    except OSError as error:
        raise ValueError(f'missing license/record/input: {name}') from error


def metadata_inputs(root):
    """Explicit fixture/export inputs; private evidence is never included."""
    notices = read_json(root, 'third_party/notices.json')
    return sorted(set(REQUIRED + IMAGE_FILES) |
                  {entry['path'] for entry in notices['notices']})


def images(root, name):
    content = (root / name).read_text()
    if name.endswith('Dockerfile'):
        found, stages = [], set()
        for line in content.splitlines():
            line = line.strip()
            match = re.fullmatch(r'FROM\s+(?:(?-i:--platform=\$BUILDPLATFORM)\s+)?(\S+)(?:\s+AS\s+(\S+))?', line, re.I)
            if not match:
                require(not re.match(r'FROM\b', line, re.I), f'unsupported image FROM: {name}')
                continue
            image, stage = match.groups()
            if image not in stages:
                found.append(image)
            if stage: stages.add(stage)
    else:
        found = []
        for raw_line in content.splitlines():
            # Operational Compose uses block image scalars. Comments are allowed;
            # flow mappings/quoted keys/other image-bearing forms require review.
            # Reject unsupported syntax instead of silently dropping an override.
            line = raw_line.split('#', 1)[0]
            if not re.search(r"(?:^|[\s,{])[\"']?image[\"']?\s*:", line):
                continue
            match = re.fullmatch(r'\s*image:\s+(\S+)\s*', line)
            require(match is not None, f'unsupported Compose image syntax: {name}')
            found.append(match.group(1))
        local = {'${COMPOSE_PROJECT_NAME:-cheesetrap}:local', '${COMPOSE_PROJECT_NAME:-cheesetrap}-web:local'}
        found = [image for image in found if image not in local]
    for image in found:
        require(':latest' not in image and re.fullmatch(r'[^@\s]+@sha256:[a-f0-9]{64}', image),
                f'image is not immutable: {name}: {image}')
    return found


def validate_metadata(root):
    for name in REQUIRED + IMAGE_FILES:
        require((root / name).is_file() and (root / name).stat().st_size > 0, f'missing required file: {name}')
    license = (root / 'LICENSE').read_text()
    require(license.startswith('MIT License\n') and 'Copyright (c) 2026 cheesetrap contributors' in license
            and 'Permission is hereby granted' in license and 'THE SOFTWARE IS PROVIDED "AS IS"' in license,
            'LICENSE must preserve the selected MIT grant and disclaimer')
    discovered = {str(p.relative_to(root)) for p in (root / 'deploy').rglob('*') if p.is_file()
                  and (p.name.startswith('Dockerfile') or ('compose' in p.name and p.suffix in ('.yaml', '.yml')))}
    require(discovered == {name for name in IMAGE_FILES if name.startswith('deploy/')}, 'image lock missing or unexpected deployment file')
    lock = read_json(root, 'deploy/images.lock.json')
    ryuk = lock.get('testcontainers', {})
    require(isinstance(ryuk, dict) and set(ryuk) == {'ryuk'}
            and isinstance(ryuk['ryuk'], str)
            and re.fullmatch(r'testcontainers/ryuk:\d+\.\d+\.\d+@sha256:[a-f0-9]{64}', ryuk['ryuk']),
            'Ryuk image must be digest locked')
    require(lock.get('schema') == 1 and isinstance(lock.get('files'), dict)
            and set(lock['files']) == set(IMAGE_FILES), 'image lock file set differs')
    for name in IMAGE_FILES:
        require(images(root, name) == lock['files'][name], f'image lock differs: {name}')
    engines = read_json(root, 'sensors/images.lock')
    require(engines['cowrie']['image'] in lock['files']['deploy/compose.yaml'], 'cowrie image lock differs')
    require(engines['opencanary']['image'] in lock['files']['sensors/web/Dockerfile'], 'opencanary image lock differs')
    require(sha(root, 'sensors/web/request_evidence.py') == engines['opencanary']['request_evidence_sha256'], 'engine patch lock differs')
    tool = read_json(root, 'deploy/toolchain.lock.json')
    require(tool.get('schema') == 1, 'invalid toolchain lock')
    for name in ('go', 'node', 'npm', 'sqlc', 'orval'):
        require(isinstance(tool.get(name), str) and re.fullmatch(r'\d+\.\d+\.\d+', tool[name]), f'invalid {name} version')
    require(re.search(r'^go ' + re.escape(tool['go']) + r'$', (root / 'go.mod').read_text(), re.M), 'Go version differs')
    require((root / '.nvmrc').read_text().strip() == tool['node'], 'Node version differs')
    require(f'golang:{tool["go"]}-bookworm@' in lock['files']['deploy/Dockerfile'][1], 'Go image/tool version differs')
    require(f'node:{tool["node"]}-bookworm-slim@' in lock['files']['deploy/Dockerfile'][0], 'Node image/tool version differs')
    require(f'cmd/sqlc@v{tool["sqlc"]} generate' in (root / 'scripts/generate-sql.sh').read_text(), 'sqlc version differs')
    package = read_json(root, 'web/package.json')
    npm = read_json(root, 'web/package-lock.json')
    require(package['devDependencies']['orval'] == tool['orval']
            == npm['packages']['node_modules/orval']['version'], 'OpenAPI generator version differs')
    ci = (root / '.github/workflows/ci.yml').read_text()
    action_lines = re.findall(r'^\s*(?:-\s+)?uses:\s*(.+)$', ci, re.M)
    require(len(action_lines) >= 3, 'CI actions missing')
    for line in action_lines:
        require(re.match(r'[^@]+@[a-f0-9]{40}(?:\s|$)', line), 'CI action must use commit SHA')
    require(f"go-version: '{tool['go']}'" in ci and f"node-version: '{tool['node']}'" in ci
            and f'= {tool["npm"]}' in ci, 'CI tool versions differ')
    notices = read_json(root, 'third_party/notices.json')
    require(notices.get('schema') == 1 and isinstance(notices.get('notices'), list) and notices['notices'], 'empty license notices')
    require(set(notices.get('inputs', {})) == {'go.mod', 'go.sum', 'web/package-lock.json', 'sensors/images.lock'}, 'license inputs incomplete')
    for name, expected in notices['inputs'].items():
        require(sha(root, name) == expected, f'license inventory stale for {name}')
    paths = set()
    for entry in notices['notices']:
        require(set(entry) == {'component', 'version', 'source', 'path', 'sha256'} and entry['source'].startswith('https://'), 'invalid license notice')
        require(entry['path'].startswith('third_party/licenses/') and entry['path'] not in paths, 'invalid/duplicate license path')
        paths.add(entry['path'])
        require(sha(root, entry['path']) == entry['sha256'], f'license notice changed: {entry["path"]}')
    components = {(entry['component'], entry['version']) for entry in notices['notices']}
    required_modules = re.findall(r'^\s*([a-zA-Z0-9][^\s]+) (v[^\s]+)', (root / 'go.mod').read_text(), re.M)
    for identity in required_modules:
        require(identity in components, f'missing Go module license: {identity}')
    for name, info in npm['packages'].items():
        if name and not info.get('dev', False):
            identity = (name.removeprefix('node_modules/'), info['version'])
            require(identity in components, f'missing browser runtime license: {identity}')
    vite_version = npm['packages']['node_modules/vite']['version']
    require(package['devDependencies']['vite'] == vite_version and ('vite', vite_version) in components, 'missing vite injected runtime helper license')
    required_engines = {('Cowrie', engines['cowrie']['version']), ('Cowrie vendored JA4+', engines['cowrie']['version']), ('OpenCanary', engines['opencanary']['version']), ('Go', tool['go'])}
    require(required_engines <= components, 'missing engine/toolchain license notices')
    coverage = read_json(root, 'tests/acceptance/coverage.json')
    require(len(coverage.get('requirements', [])) == 13 and {row['id'] for row in coverage['requirements']} == {f'T{i:02}' for i in range(1, 14)}, 'acceptance coverage missing T01–T13')


def validate_acceptance(result, revision, sources):
    require(result.get('schema') == 1 and result.get('status') in ('PASS', 'PASS_AUTOMATED'), 'acceptance result did not pass')
    require(result.get('revision') == revision, 'acceptance revision is stale')
    require(result.get('tracked_diff_sha256') == hashlib.sha256(b'').hexdigest(), 'acceptance began with a nonempty or unknown tracked diff')
    require(result.get('checkout_clean') is True, 'acceptance did not begin from a clean checkout')
    require(bool(sources) and result.get('source_sha256') == sources, 'acceptance production sources are stale')
    commands = result.get('commands', [])
    require(len(commands) == len(ACCEPTANCE_COMMANDS) and {c.get('name') for c in commands} == set(ACCEPTANCE_COMMANDS)
            and all(c.get('status') == 'PASS' for c in commands), 'acceptance commands incomplete or failed')
    rows = result.get('requirements', [])
    require(len(rows) == 13 and {r.get('id') for r in rows} == {f'T{i:02}' for i in range(1, 14)}
            and all(r.get('status') in ('PASS', 'BLOCKED') and r.get('missing_tests') == [] for r in rows),
            'acceptance requirements incomplete or failed')


def validate_clean_checkout(root):
    status = subprocess.check_output(['git', 'status', '--porcelain', '--untracked-files=all'], cwd=root, text=True)
    require(not status.strip(), 'current automated release gate requires a clean checkout (including tests and harnesses)')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument('--metadata-only', action='store_true', help='static checks only; not release readiness')
    mode.add_argument('--acceptance-results', type=Path, help='current private test-acceptance results.json')
    args = parser.parse_args()
    validate_metadata(ROOT)
    if args.metadata_only:
        print('PASS_METADATA: documents, licenses, locks and acceptance coverage; no build/live-test claim')
        return
    validate_clean_checkout(ROOT)
    result = json.loads(args.acceptance_results.read_text())
    spec = importlib.util.spec_from_file_location('acceptance', ROOT / 'scripts/test-acceptance.py')
    acceptance = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(acceptance)
    revision = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
    validate_acceptance(result, revision, acceptance.production_sources())
    print('PASS_AUTOMATED_GATE: current automated result + metadata; historical Linux/load scopes remain separate; image build requires release record')


if __name__ == '__main__':
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError, subprocess.CalledProcessError) as error:
        print(f'FAIL: {error}', file=sys.stderr)
        sys.exit(1)
