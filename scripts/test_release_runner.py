import importlib.util
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

class ReleaseGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = ROOT / "scripts/release-check.py"

    def setUp(self):
        self.assertTrue(self.path.is_file(), "release metadata checker has not been implemented")
        spec = importlib.util.spec_from_file_location("release_checker", self.path)
        self.checker = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(self.checker)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        for name in self.checker.metadata_inputs(ROOT):
            target = self.root / name
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, target)

    def test_current_metadata_passes(self):
        self.checker.validate_metadata(self.root)

    def test_unreviewed_from_platform_options_fail(self):
        path = self.root / "deploy/Dockerfile"
        original = path.read_text()
        for option in ("--platform=$TARGETPLATFORM", "--platform=linux/amd64",
                       "--platform=$buildplatform", "--platform=$BUILDPLATFORM --network=host"):
            path.write_text(original.replace("--platform=$BUILDPLATFORM", option, 1))
            with self.subTest(option=option), self.assertRaisesRegex(ValueError, "unsupported image FROM"):
                self.checker.images(self.root, "deploy/Dockerfile")

    def test_orval_version_mismatch_fails(self):
        path = self.root / "web/package.json"
        package = json.loads(path.read_text())
        package["devDependencies"]["orval"] = "8.45.0"
        path.write_text(json.dumps(package))
        with self.assertRaisesRegex(ValueError, "OpenAPI generator version differs"):
            self.checker.validate_metadata(self.root)

    def test_missing_license_fails(self):
        (self.root / "LICENSE").unlink()
        with self.assertRaisesRegex(ValueError, "LICENSE"):
            self.checker.validate_metadata(self.root)

    def test_latest_image_fails(self):
        file = self.root / "deploy/Dockerfile"
        file.write_text(file.read_text().replace("node:22.23.1-bookworm-slim@sha256:", "node:latest@sha256:"))
        with self.assertRaisesRegex(ValueError, "image|latest"):
            self.checker.validate_metadata(self.root)

    def test_indented_docker_from_cannot_bypass_image_lock(self):
        file = self.root / "deploy/Dockerfile"
        file.write_text(file.read_text() + "\n FROM alpine:latest AS surprise\n")
        with self.assertRaisesRegex(ValueError, "image"):
            self.checker.validate_metadata(self.root)

    def test_stale_image_lock_fails(self):
        file = self.root / "deploy/images.lock.json"
        lock = json.loads(file.read_text())
        lock["files"]["deploy/Dockerfile"][0] = "node:22.23.1-bookworm-slim@sha256:" + "0" * 64
        file.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "image.*lock"):
            self.checker.validate_metadata(self.root)

    def test_mutable_ryuk_image_fails(self):
        file = self.root / "deploy/images.lock.json"
        lock = json.loads(file.read_text())
        lock["testcontainers"] = {"ryuk": "testcontainers/ryuk:0.14.0"}
        file.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "Ryuk|ryuk"):
            self.checker.validate_metadata(self.root)

    def test_missing_ryuk_lock_fails(self):
        file = self.root / "deploy/images.lock.json"
        lock = json.loads(file.read_text())
        lock.pop("testcontainers", None)
        file.write_text(json.dumps(lock))
        with self.assertRaisesRegex(ValueError, "Ryuk|ryuk"):
            self.checker.validate_metadata(self.root)

    def test_unpinned_new_runtime_image_fails(self):
        file = self.root / "deploy/compose.yaml"
        file.write_text(file.read_text() + "\n  unexpected:\n    image: example/service:1.0\n")
        with self.assertRaisesRegex(ValueError, "image"):
            self.checker.validate_metadata(self.root)

    def test_optional_overlay_image_override_fails(self):
        file = self.root / "deploy/test.compose.yaml"
        file.write_text("services:\n  worker:\n    image: example/service:latest\n")
        with self.assertRaisesRegex(ValueError, "image"):
            self.checker.validate_metadata(self.root)

    def test_commented_and_flow_mapping_image_overrides_fail(self):
        file = self.root / "deploy/test.compose.yaml"
        overrides = [
            "services:\n  worker:\n    image: example/service:latest # temporary override\n",
            "services:\n  worker: {image: example/service:latest}\n",
            'services:\n  worker: {"image": "example/service:latest"}\n',
        ]
        for content in overrides:
            file.write_text(content)
            with self.subTest(content=content), self.assertRaisesRegex(ValueError, "image"):
                self.checker.validate_metadata(self.root)

    def test_new_deploy_compose_file_requires_image_lock(self):
        (self.root / "deploy/extra.compose.yaml").write_text("services:\n  worker:\n    image: example/service:latest\n")
        with self.assertRaisesRegex(ValueError, "image"):
            self.checker.validate_metadata(self.root)

    def test_named_ci_step_requires_pinned_action(self):
        file = self.root / ".github/workflows/ci.yml"
        file.write_text(file.read_text() + "\n      - name: Unpinned action\n        uses: actions/example@v1\n")
        with self.assertRaisesRegex(ValueError, "CI action"):
            self.checker.validate_metadata(self.root)

    def test_stale_tool_lock_fails(self):
        file = self.root / "scripts/generate-sql.sh"
        file.write_text(file.read_text().replace("v1.31.1", "v1.30.0"))
        with self.assertRaisesRegex(ValueError, "sqlc"):
            self.checker.validate_metadata(self.root)

    def test_missing_notice_fails(self):
        (self.root / "third_party/licenses/npm/react-LICENSE.txt").unlink()
        with self.assertRaisesRegex(ValueError, "notice|license"):
            self.checker.validate_metadata(self.root)

    def test_vite_injected_runtime_helper_requires_license(self):
        path = self.root / "third_party/notices.json"
        document = json.loads(path.read_text())
        document["notices"] = [entry for entry in document["notices"] if entry["component"] != "vite"]
        path.write_text(json.dumps(document))
        with self.assertRaisesRegex(ValueError, "vite.*license|license.*vite"):
            self.checker.validate_metadata(self.root)

    def test_checkout_rejects_untracked_or_modified_release_inputs(self):
        repo = self.root / "clean-repo"
        repo.mkdir()
        subprocess.run(["git", "init", "-q", str(repo)], check=True)
        (repo / "tracked").write_text("original")
        subprocess.run(["git", "add", "tracked"], cwd=repo, check=True)
        subprocess.run(["git", "-c", "user.name=Test", "-c", "user.email=test@example.invalid", "commit", "-qm", "fixture"], cwd=repo, check=True)
        self.checker.validate_clean_checkout(repo)
        (repo / "untracked").write_text("new harness")
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            self.checker.validate_clean_checkout(repo)
        (repo / "untracked").unlink()
        (repo / "tracked").write_text("changed test")
        with self.assertRaisesRegex(ValueError, "clean checkout"):
            self.checker.validate_clean_checkout(repo)

    def evidence(self):
        return {"schema": 1, "revision": "a" * 40, "source_sha256": {"go.mod": "b" * 64},
                "tracked_diff_sha256": hashlib.sha256(b"").hexdigest(), "checkout_clean": True,
                "status": "PASS_AUTOMATED", "commands": [{"name": name, "status": "PASS"} for name in self.checker.ACCEPTANCE_COMMANDS],
                "requirements": [{"id": f"T{i:02}", "status": "BLOCKED" if i == 1 else "PASS", "missing_tests": []} for i in range(1, 14)]}

    def test_current_automated_result_keeps_linux_scope_separate(self):
        self.checker.validate_acceptance(self.evidence(), "a" * 40, {"go.mod": "b" * 64})

    def test_results_from_dirty_checkout_cannot_pass_after_restoring_files(self):
        for field, value in [("tracked_diff_sha256", hashlib.sha256(b"modified tests").hexdigest()),
                             ("tracked_diff_sha256", None), ("checkout_clean", False), ("checkout_clean", None)]:
            result = self.evidence()
            result[field] = value
            with self.subTest(field=field, value=value), self.assertRaisesRegex(ValueError, "checkout|diff"):
                self.checker.validate_acceptance(result, "a" * 40, {"go.mod": "b" * 64})

    def test_stale_failed_or_incomplete_automated_results_fail(self):
        for field, value in [("revision", "c" * 40), ("source_sha256", {}), ("status", "FAIL"), ("commands", []), ("requirements", [])]:
            evidence = self.evidence()
            evidence[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.checker.validate_acceptance(evidence, "a" * 40, {"go.mod": "b" * 64})
        evidence = self.evidence()
        evidence["requirements"][0]["missing_tests"] = ["missing-test"]
        with self.assertRaises(ValueError):
            self.checker.validate_acceptance(evidence, "a" * 40, {"go.mod": "b" * 64})

if __name__ == "__main__":
    unittest.main()
