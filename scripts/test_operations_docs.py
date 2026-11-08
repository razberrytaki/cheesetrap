"""Check executable runbook syntax without running operational commands."""
from pathlib import Path
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class OperationsDocsTest(unittest.TestCase):
    def test_project_instruction_checks_without_claude(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'internal').mkdir()
            (root / 'web').mkdir()
            (root / 'AGENTS.md').write_text('[Backend](internal/AGENTS.md)\n')
            (root / 'internal/AGENTS.md').write_text('Backend instructions\n')
            (root / 'web/AGENTS.md').write_text('Frontend instructions\n')
            for script in ('validate_agents_surface.py', 'validate_instruction_surface.py'):
                with self.subTest(script=script):
                    result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts' / script),
                                             '--root', str(root)], capture_output=True, text=True)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    legacy = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts' / script),
                                             '--design-kit', '--root', str(root)], capture_output=True, text=True)
                    self.assertNotEqual(legacy.returncode, 0)

    def test_project_instruction_checks_reject_broken_references(self):
        for defect in ('missing_scope', 'missing_link', 'missing_script', 'empty_scope'):
            with self.subTest(defect=defect), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / 'internal').mkdir()
                (root / 'web').mkdir()
                (root / 'AGENTS.md').write_text('Project instructions\n')
                (root / 'internal/AGENTS.md').write_text('Backend instructions\n')
                if defect != 'missing_scope':
                    (root / 'web/AGENTS.md').write_text('' if defect == 'empty_scope' else 'Frontend\n')
                if defect == 'missing_link':
                    (root / 'AGENTS.md').write_text('[Missing](docs/missing.md)\n')
                if defect == 'missing_script':
                    (root / 'AGENTS.md').write_text('Run `python3 scripts/missing.py`.\n')
                result = subprocess.run([sys.executable, '-B', str(ROOT / 'scripts/validate_agents_surface.py'),
                                         '--root', str(root)], capture_output=True, text=True)
                self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('ERROR:', result.stdout)

    def test_shell_blocks_parse(self):
        required = {"install.md", "upgrade.md", "backup-restore.md", "retention.md", "release.md"}
        checked = set()
        for path in sorted((ROOT / "docs/operations").glob("*.md")):
            for index, block in enumerate(re.findall(r"```(?:sh|bash)\n(.*?)\n```", path.read_text(), re.S)):
                with self.subTest(document=path.name, block=index):
                    result = subprocess.run(["bash", "-n"], input=block, text=True, capture_output=True)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    checked.add(path.name)
        self.assertFalse(required - checked, f"missing shell blocks: {sorted(required - checked)}")

    def test_compose_helpers_use_base_without_smtp(self):
        # Execute only the documented functions with sudo replaced by a recorder.
        # This cannot start Docker or invoke privileged commands.
        for filename, name in [("upgrade.md", "ops_compose"), ("install.md", "rdc")]:
            text = (ROOT / "docs/operations" / filename).read_text()
            match = re.search(r"^" + name + r"\(\) \{\n.*?^\}", text, re.M | re.S)
            self.assertIsNotNone(match)
            script = """set -eu
sudo() { printf '%s\n' "$@"; }
INSTALL_ROOT=/fixture/install
OPS_DOCKER_CONFIG=/fixture/context
COMPOSE_PROJECT_NAME=fixture-project
""" + match.group(0) + "\n" + name + " --profile worker config --quiet\n"
            result = subprocess.run(["bash"], input=script, text=True, capture_output=True)
            with self.subTest(helper=name):
                self.assertEqual(result.returncode, 0, result.stderr)
                args = result.stdout.splitlines()
                self.assertFalse(any("SMTP" in arg for arg in args))
                self.assertIn("deploy/compose.yaml", args)
                self.assertIn("/fixture/install/compose.env", args)
                self.assertEqual(args[-4:], ["--profile", "worker", "config", "--quiet"])

    def run_upgrade_identity(self, *, errexit=False, conditional=False, compare_volume_created=None, **overrides):
        text = (ROOT / "docs/operations/upgrade.md").read_text()
        helper = re.search(r"^upgrade_identity\(\) \{\n.*?^\}", text, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "compose.env").write_text("COMPOSE_PROJECT_NAME=" + overrides.pop("env_project", "fixture-project") + "\n")
            config = {
                "name": "fixture-project",
                "volumes": {"postgres-data": {"name": "fixture-project_postgres-data"}},
                "services": {"postgres": {"volumes": [
                    {"type": "volume", "source": "postgres-data", "target": "/var/lib/postgresql/data"},
                    {"type": "bind", "source": str(root / "secrets/bootstrap-password")},
                ]}},
                "networks": {"sensor": {"external": True, "name": "fixture-sensor"}},
            }
            if overrides.pop("wrong_root", False):
                config["services"]["postgres"]["volumes"][1]["source"] = "/other/secrets/bootstrap-password"
            if overrides.pop("wrong_compose_project", False):
                config["name"] = "other"
            if overrides.pop("wrong_compose_volume", False):
                config["volumes"]["postgres-data"]["name"] = "other_postgres-data"
            env = {"PATH": os.environ["PATH"], "INSTALL_ROOT": directory,
                   "COMPOSE_PROJECT_NAME": "fixture-project", "POSTGRES_CONTAINER": "fixture-postgres",
                   "COMPOSE_JSON": json.dumps(config), **overrides}
            script = ("set -euo pipefail\n" if errexit else "set +e\n") + r'''
sudo() { "$@"; }
ops_compose() { printf '%s\n' "$COMPOSE_JSON"; return "${COMPOSE_STATUS:-0}"; }
ops_docker() {
    case "$*" in
        "inspect"*"com.docker.compose.project"*) printf '%s\n' "${PG_PROJECT-fixture-project}" ;;
        "inspect"*"com.docker.compose.service"*) printf '%s\n' "${PG_SERVICE-postgres}" ;;
        "inspect"*"Mounts"*) printf '%s\n' "${PG_VOLUME-fixture-project_postgres-data}" ;;
        "volume inspect"*"com.docker.compose.project"*) printf '%s\n' "${VOLUME_PROJECT-fixture-project}" ;;
        "volume inspect"*"com.docker.compose.volume"*) printf '%s\n' "${VOLUME_KEY-postgres-data}" ;;
        "volume inspect"*"CreatedAt"*) printf '%s\n' "${VOLUME_CREATED-2026-01-01T00:00:00Z}" ;;
        "network inspect"*) printf '%s\n' "${NETWORK_ID-network-original}" ;;
        *) return 9 ;;
    esac
    return "${DOCKER_STATUS:-0}"
}
''' + helper
            if compare_volume_created is not None:
                env["AFTER_VOLUME_CREATED"] = compare_volume_created
                script += '''
upgrade_identity > "$INSTALL_ROOT/before" || exit 1
VOLUME_CREATED=$AFTER_VOLUME_CREATED
upgrade_identity > "$INSTALL_ROOT/after" || exit 1
cmp "$INSTALL_ROOT/before" "$INSTALL_ROOT/after"
'''
            else:
                script += ("\nif upgrade_identity; then exit 0; else exit 1; fi\n" if conditional
                       else "\nupgrade_identity\n")
            return subprocess.run(["bash"], input=script, text=True, capture_output=True, env=env)

    def test_upgrade_identity_rejects_mismatches_without_caller_errexit(self):
        scenarios = [
            {}, {"PG_PROJECT": "other"}, {"PG_SERVICE": "api"}, {"PG_VOLUME": ""},
            {"VOLUME_PROJECT": "other"}, {"VOLUME_KEY": "other"},
            {"wrong_root": True}, {"wrong_compose_project": True}, {"wrong_compose_volume": True},
            {"DOCKER_STATUS": "9"}, {"COMPOSE_STATUS": "9"}, {"env_project": "other"},
        ]
        for errexit in (False, True):
            for conditional in (False, True):
                for overrides in scenarios:
                    with self.subTest(errexit=errexit, conditional=conditional, overrides=overrides):
                        result = self.run_upgrade_identity(errexit=errexit, conditional=conditional, **overrides)
                        if overrides:
                            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
                        else:
                            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                            self.assertIn("fixture-project_postgres-data", result.stdout)
                            self.assertIn("network-original", result.stdout)

    def test_upgrade_identity_detects_recreated_volume_with_same_name(self):
        for errexit in (False, True):
            for created, expected in [("2026-01-01T00:00:00Z", 0), ("2026-02-01T00:00:00Z", 1)]:
                with self.subTest(errexit=errexit, created=created):
                    result = self.run_upgrade_identity(errexit=errexit, compare_volume_created=created)
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)

    def test_upgrade_sources_preserves_identity_across_archive_refresh(self):
        text = (ROOT / "docs/operations/upgrade.md").read_text()
        helper = re.search(r"^upgrade_sources\(\) \{\n.*?^\}", text, re.M | re.S).group(0)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config/collector/sources.json"
            path.parent.mkdir(parents=True)
            source = {"sensor_id": "fixture-id", "engine": "web", "archive_paths": [],
                      "endpoints": [{"service": "http", "public_port": 18080}]}
            script = 'sudo() { "$@"; }\n' + helper + "\nupgrade_sources\n"
            env = {"PATH": os.environ["PATH"], "INSTALL_ROOT": directory}
            path.write_text(json.dumps([source]))
            before = subprocess.run(["bash"], input=script, text=True, capture_output=True, env=env)
            self.assertEqual(before.returncode, 0, before.stderr)
            for change, expected_equal in [({"archive_paths": ["web/events.jsonl.1"]}, True),
                                           ({"sensor_id": "different-id"}, False),
                                           ({"endpoints": [{"service": "http", "public_port": 28080}]}, False)]:
                with self.subTest(change=change):
                    path.write_text(json.dumps([{**source, **change}]))
                    after = subprocess.run(["bash"], input=script, text=True, capture_output=True, env=env)
                    self.assertEqual(after.returncode, 0, after.stderr)
                    self.assertEqual(before.stdout == after.stdout, expected_equal)

    def test_relative_links_exist(self):
        for path in sorted((ROOT / "docs/operations").glob("*.md")):
            for target in re.findall(r"\]\(([^)]+)\)", path.read_text()):
                if "://" in target or target.startswith("#"):
                    continue
                with self.subTest(document=path.name, target=target):
                    self.assertTrue((path.parent / target.split("#", 1)[0]).is_file())

if __name__ == "__main__":
    unittest.main()
