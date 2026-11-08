#!/usr/bin/env python3
"""Live Docker regression for the owned PostgreSQL and Ryuk boundary."""
import importlib.util
import json
import os
from pathlib import Path
import secrets
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("runner", ROOT / "scripts/test-integration.py")
RUNNER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(RUNNER)


class LiveTestcontainersTests(unittest.TestCase):
    def setUp(self):
        RUNNER.validate_environment(os.environ)
        env = {k: os.environ[k] for k in ("PATH", "HOME", "TMPDIR", "USER", "LANG") if k in os.environ}
        env.update(GOENV="off", GOWORK="off", GOFLAGS="", GOTOOLCHAIN="local")
        _, selected = RUNNER.run_command(["docker", "context", "show"], childenv=env)
        docker = ["docker", "--context", selected.strip()]
        _, description = RUNNER.run_command(docker + ["context", "inspect"], childenv=env)
        endpoint = json.loads(description)[0]["Endpoints"]["docker"]["Host"]
        self.assertTrue(endpoint.startswith("unix://"), "a local Docker context is required")
        self.env, self.docker, self.endpoint = env, docker, endpoint

    def test_sequential_owned_databases_use_distinct_reapers_and_clean_up(self):
        sessions, reapers, owned = set(), set(), []
        for _ in range(3):
            project = "cheesetrap-test-" + secrets.token_hex(8)
            owner = RUNNER.OwnedPostgres(self.env, self.endpoint, project, secrets.token_hex(32))
            try:
                database, _ = owner.start()
                owned.append(database)
                _, info = RUNNER.run_command(self.docker + ["inspect", database], childenv=self.env)
                session = json.loads(info)[0]["Config"]["Labels"]["org.testcontainers.sessionId"]
                self.assertEqual(session, project, "the reaper session must belong to this owned database")
                self.assertNotIn(session, sessions, "sequential batches must not share a reaper session")
                sessions.add(session)
                _, ids = RUNNER.run_command(self.docker + ["ps", "-q", "--filter", "label=org.testcontainers.ryuk=true",
                                                         "--filter", "label=org.testcontainers.sessionId=" + session], childenv=self.env)
                self.assertEqual(len(ids.split()), 1, "exactly one owned Ryuk is required")
                reaper = ids.strip()
                self.assertNotIn(reaper, reapers, "sequential batches must not reuse a retiring Ryuk")
                reapers.add(reaper)
                owned.append(reaper)
            finally:
                owner.close()
            # Start the next batch immediately, while the previous Ryuk can
            # still be retiring. Waiting here would hide the reuse regression.
        deadline = time.monotonic() + 30
        for identifier in owned:
            while RUNNER.run_command(self.docker + ["inspect", identifier], childenv=self.env, check=False)[0] == 0:
                self.assertLess(time.monotonic(), deadline, "owned container survived lease cleanup")
                time.sleep(0.1)

    def test_unavailable_selected_socket_never_falls_back(self):
        project = "cheesetrap-test-" + secrets.token_hex(8)
        with tempfile.TemporaryDirectory(prefix="cheesetrap-missing-socket-") as directory:
            endpoint = "unix://" + str(Path(directory) / "unavailable.sock")
            owner = RUNNER.OwnedPostgres(self.env, endpoint, project, secrets.token_hex(32))
            try:
                with self.assertRaisesRegex(RuntimeError, "startup failed"):
                    owner.start()
            finally:
                try:
                    owner.close()
                except RuntimeError as error:
                    # A rejected helper exits nonzero; close must report that.
                    self.assertEqual(str(error), "owned integration project cleanup failed")
        _, remaining = RUNNER.run_command(self.docker + ["ps", "-aq", "--filter", "name=^/" + project + "$"], childenv=self.env)
        self.assertEqual(remaining.strip(), "", "an unavailable target must not create resources elsewhere")

    def test_owned_containers_use_loopback_and_locked_images(self):
        env, docker, endpoint = self.env, self.docker, self.endpoint
        owner = RUNNER.OwnedPostgres(env, endpoint, "cheesetrap-test-" + secrets.token_hex(8), secrets.token_hex(32))
        owned = []
        try:
            database, _ = owner.start()
            owned.append(database)
            _, info = RUNNER.run_command(docker + ["inspect", database], childenv=env)
            db = json.loads(info)[0]
            session = db["Config"]["Labels"]["org.testcontainers.sessionId"]
            _, ids = RUNNER.run_command(docker + ["ps", "-q", "--filter", "label=org.testcontainers.ryuk=true",
                                                     "--filter", "label=org.testcontainers.sessionId=" + session], childenv=env)
            self.assertEqual(len(ids.split()), 1, "exactly one owned Ryuk is required")
            reaper = ids.strip()
            owned.append(reaper)
            _, info = RUNNER.run_command(docker + ["inspect", reaper], childenv=env)
            ryuk = json.loads(info)[0]
            for info in (db, ryuk):
                bindings = [binding for values in info["NetworkSettings"]["Ports"].values() for binding in (values or [])]
                self.assertTrue(bindings, "the owned service must have a reachable test port")
                self.assertEqual({b["HostIp"] for b in bindings}, {"127.0.0.1"}, "all published ports must be IPv4 loopback")
                self.assertTrue(all(0 < int(b["HostPort"]) < 65536 for b in bindings))
                configured = [binding for values in info["HostConfig"]["PortBindings"].values() for binding in values]
                self.assertEqual({b["HostIp"] for b in configured}, {"127.0.0.1"})
            lock = json.loads((ROOT / "deploy/images.lock.json").read_text())
            self.assertEqual(ryuk["Config"]["Image"], lock["testcontainers"]["ryuk"])
            self.assertRegex(ryuk["Config"]["Image"], r"@sha256:[a-f0-9]{64}$")
            self.assertEqual(db["Config"]["Image"], lock["files"]["deploy/test.compose.yaml"][0])
            RUNNER.run_command(docker + ["exec", database, "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "cheesetrap_test"], childenv=env)
        finally:
            owner.close()
        # The actual Ryuk lease must finish cleanup as well as PostgreSQL.
        deadline = time.monotonic() + 30
        for identifier in owned:
            while RUNNER.run_command(docker + ["inspect", identifier], childenv=env, check=False)[0] == 0:
                self.assertLess(time.monotonic(), deadline, "owned container survived lease cleanup")
                time.sleep(0.1)


if __name__ == "__main__":
    os.umask(0o077)
    unittest.main()
