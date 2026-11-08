#!/usr/bin/env python3
"""Exercise Git ignore policy and the real pinned scanner in disposable repositories."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class SecretScanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='cheesetrap-secret-check-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        self.env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull,
                        GIT_CONFIG_NOSYSTEM='1', GIT_TERMINAL_PROMPT='0')
        # Never inherit alternate Git indexes, worktrees, or scanner configuration.
        for key in list(self.env):
            if key.startswith(('GITLEAKS_', 'GIT_CONFIG_')) or key in (
                    'GIT_DIR', 'GIT_WORK_TREE', 'GIT_INDEX_FILE', 'GIT_COMMON_DIR',
                    'GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES'):
                self.env.pop(key)
        self.env.update(GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_NOSYSTEM='1')
        self.git('init', '-q')
        self.git('config', 'user.name', 'Synthetic fixture')
        self.git('config', 'user.email', 'fixture@example.invalid')
        self.git('config', 'core.hooksPath', os.devnull)
        self.git('config', 'commit.gpgsign', 'false')
        for name in ('.gitignore', '.gitleaks.toml', '.gitleaksignore'):
            shutil.copyfile(ROOT / name, self.root / name)

    def git(self, *args):
        return subprocess.run(['git', *args], cwd=self.root, env=self.env,
                              capture_output=True, text=True, timeout=20, check=True)

    def test_sensitive_paths_ignored_and_public_fixtures_trackable(self):
        ignored = ['.env', 'web/.env', 'web/.env.production', 'deploy/credentials.json',
                   'deploy/credentials.yaml', 'private.key', 'nested/server.pem',
                   'nested/client.p12', 'nested/client.pfx', 'nested/id_ed25519',
                   'nested/id_rsa', 'nested/secrets/token', '.local/evidence.json',
                   'nested/.aws/credentials', 'nested/.ssh/config', 'nested/.oci/config']
        public = ['.env.example', 'web/.env.example', 'web/.env.production.example',
                  'testdata/engines/cowrie/events.jsonl', 'testdata/synthetic.log',
                  'deploy/config.example.yaml', 'third_party/licenses/npm/react-LICENSE.txt']
        for path in ignored + public:
            with self.subTest(path=path):
                result = subprocess.run(['git', 'check-ignore', '--no-index', '-q', path],
                                        cwd=self.root, env=self.env, timeout=10)
                self.assertEqual(result.returncode, 0 if path in ignored else 1)

    def test_new_secrets_fail_in_staging_and_deleted_history_even_in_exception_paths(self):
        scanner = shutil.which('gitleaks')
        self.assertIsNotNone(scanner, 'Gitleaks 8.30.1 is required; do not skip this gate')
        version = subprocess.check_output([scanner, 'version'], text=True, env=self.env, timeout=10)
        self.assertEqual(version.strip(), '8.30.1')
        report = Path(self.tmp.name) / 'redacted.json'
        # Deliberately fake, generated at runtime so the test source is not an allowlist.
        # Ordered example alphabets are intentionally ignored by upstream rules.
        token = 'gh' + 'p_' + hashlib.sha256(b'cheesetrap-synthetic-detection-fixture').hexdigest()[:36]

        def scan(*mode):
            report.unlink(missing_ok=True)
            result = subprocess.run([
                scanner, 'git', '--config', '.gitleaks.toml',
                '--gitleaks-ignore-path', '.gitleaksignore', '--ignore-gitleaks-allow',
                '--redact=100', '--no-banner', '--no-color', '--timeout', '20',
                '--report-format', 'json', '--report-path', str(report), *mode, '.',
            ], cwd=self.root, env=self.env, capture_output=True, text=True, timeout=30)
            output = result.stdout + result.stderr + (report.read_text() if report.exists() else '')
            self.assertNotIn(token, output, 'scanner output must redact credentials')
            return result, json.loads(report.read_text()) if report.exists() else []

        self.git('add', '.')
        self.git('commit', '-qm', 'clean fixture')
        result, _ = scan('--log-opts=--all')
        self.assertEqual(result.returncode, 0, result.stderr)
        paths = ['docs/validation/m1-auth-api.md', 'internal/ingestion/adapter_test.go',
                 '.local/forced-secret.env']
        for name in paths:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('api_token = "' + token + '" # gitleaks:allow\n')
        self.git('add', '-f', '--', *paths)
        result, findings = scan('--pre-commit', '--staged')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual({row['File'] for row in findings}, set(paths))
        self.git('commit', '-qm', 'synthetic detection fixture')
        self.git('rm', '-q', '--', *paths)
        self.git('commit', '-qm', 'remove synthetic fixture')
        result, findings = scan('--log-opts=--all')
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual({row['File'] for row in findings}, set(paths))


if __name__ == '__main__':
    unittest.main(verbosity=2)
