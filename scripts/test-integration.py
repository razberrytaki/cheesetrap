#!/usr/bin/env python3
"""Always provision one fresh local Testcontainers PostgreSQL; never accept a DB URL.

Supported arguments: relative Go packages, -run REGEXP, -skip REGEXP, -timeout DURATION,
-v, -race. Go flags controlling execution/configuration cannot bypass the harness.
A successful run must pass an integration-tagged test discovered from the selected
packages. Package-only skip events mean no test files; real test skips fail.
An unfiltered ./... run uses three fresh stacks, keeping the same resource caps.
"""
import functools
import json
import os
from pathlib import Path
import re
import secrets
import signal
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]


class IntegrationInterrupted(Exception):
    """Cancellation must not inherit OSError: subprocess retries InterruptedError."""


def arguments(argv):
    packages, flags = [], []
    i = 0
    while i < len(argv):
        arg = argv[i]
        if re.fullmatch(r"\./(?:[A-Za-z0-9_-]+/)*(?:[A-Za-z0-9_-]+|\.\.\.)?", arg):
            packages.append(arg)
        elif arg in ("-v", "-race"):
            flags.append(arg)
        elif arg in ("-run", "-skip", "-timeout"):
            i += 1
            if i == len(argv):
                raise ValueError("test flag needs a value")
            flags.extend((arg, argv[i]))
        elif arg.startswith(("-run=", "-skip=", "-timeout=")):
            key, value = arg.split("=", 1)
            flags.extend((key, value))
        else:
            raise ValueError("unsupported argument; use relative packages, -run, -skip, -timeout, -v or -race")
        i += 1
    for i, flag in enumerate(flags):
        if flag == "-timeout":
            value = flags[i + 1]
            if not re.fullmatch(r"[1-9][0-9]*(s|m)", value):
                raise ValueError("timeout must be positive seconds or minutes (at most 10m)")
            if int(value[:-1]) * (60 if value[-1] == "m" else 1) > 600:
                raise ValueError("timeout exceeds 10m")
    return (packages or ["./internal/store"]), flags


def test_results(output):
    passed, failed, skipped, no_tests = set(), [], [], set()
    for line in output.splitlines():
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            continue
        identity = (event.get("Package"), event.get("Test"))
        if event.get("Action") == "pass":
            passed.add(identity)
        if event.get("Action") == "fail":
            failed.append(identity)
        if event.get("Action") == "skip" and event.get("Test"):
            skipped.append(identity)
        if event.get("Action") == "output" and "testing: warning: no tests to run" in event.get("Output", ""):
            no_tests.add(event.get("Package"))
        if event.get("Action") == "output" and ("--- FAIL:" in event.get("Output", "") or ".go:" in event.get("Output", "")):
            print(event["Output"], end="")
    return passed, failed, skipped, no_tests


def results_succeeded(code, passed, failed, skipped, no_tests, integrations):
    matched = integrations & passed
    # A selected parent may PASS even when its requested subtest never ran.
    # Warnings from unrelated unmatched packages are normal with ./... -run.
    empty_integration = no_tests & {package for package, _ in matched}
    return not (code or failed or not matched or skipped or empty_integration)


def run_command(command, *, childenv, cwd=ROOT, data=None, timeout=90, check=True):
    active = subprocess.Popen(command, cwd=cwd, env=childenv, stdin=subprocess.PIPE if data is not None else subprocess.DEVNULL,
                              stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        output, _ = active.communicate(data, timeout=timeout)
        code = active.returncode
    finally:
        if active.poll() is None:
            try:
                os.killpg(active.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                active.wait(timeout=5)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(active.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                active.wait()
    if check and code:
        # Commands and output may include private database error details.
        raise RuntimeError("integration subprocess failed")
    return code, output


def interrupted(signum, _frame):
    # Keep a second signal from interrupting child termination and owned cleanup.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, signal.SIG_IGN)
    raise IntegrationInterrupted("integration interrupted")


def validate_environment(environment):
    # Reject operational targets rather than silently appearing to use them.
    if any(value and ("DATABASE_URL" in key or key.startswith(("CHEESETRAP_TEST_", "CHEESETRAP_E2E_", "PLAYWRIGHT_"))) for key, value in environment.items()):
        raise ValueError("database/test credentials must be unset; this runner always creates its own")
    if environment.get("DOCKER_HOST") or environment.get("DOCKER_CONTEXT"):
        raise ValueError("Docker target overrides must be unset; select a local context first")

def full_suite_batches(packages, flags):
    """Separate persistent fixtures and the hard-memory regression, not tests."""
    return [
        ([p for p in packages if p != "./internal/store"], flags + ["-skip", "^TestSecurityAggregateMemory$"]),
        (["./internal/store"], flags),
        # The memory regression owns a four-minute context, including its child
        # builds and bounded workers. Let it report that deadline and clean up
        # before Go's package alarm; caller-supplied timeouts still take priority.
        (["./internal/reporting"], ["-timeout", "5m"] + flags + ["-run", "^TestSecurityAggregateMemory$"]),
    ]


class OwnedPostgres:
    """A Go Testcontainers process holds the DB until its stdin lease closes."""
    def __init__(self, env, endpoint, project, password):
        self.env, self.endpoint = env, endpoint
        self.project, self.password = project, password
        self.directory = None
        self.process = None

    def start(self):
        self.directory = tempfile.TemporaryDirectory(prefix="cheesetrap-testcontainers-")
        root = Path(self.directory.name)
        binary, ready = root / "postgres", root / "ready.json"
        run_command(["go", "build", "-o", str(binary), "./scripts/testpostgres"], childenv=self.env, timeout=180)
        # Ignore user Testcontainers properties and environment target overrides.
        home = root / "home"
        home.mkdir(mode=0o700)
        # Testcontainers otherwise derives the session from our Python PID.
        # Each batch owns a fresh Ryuk, even while the previous one is retiring.
        childenv = dict(self.env, HOME=str(home), DOCKER_HOST=self.endpoint,
                        TESTCONTAINERS_SESSION_ID=self.project,
                        CHEESETRAP_TEST_BOOTSTRAP_PASSWORD=self.password)
        self.process = subprocess.Popen([str(binary), self.project, str(ready), str(ROOT / "deploy/images.lock.json")],
                                        env=childenv, cwd=ROOT, stdin=subprocess.PIPE,
                                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                                        start_new_session=True)
        deadline = time.monotonic() + 180
        while not ready.exists():
            if self.process.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError("Testcontainers PostgreSQL startup failed")
            time.sleep(0.05)
        metadata = json.loads(ready.read_text())
        container, port = metadata["container"], metadata["port"]
        if not re.fullmatch(r"[a-f0-9]{64}", container) or not re.fullmatch(r"[0-9]{1,5}", port) or not 0 < int(port) < 65536:
            raise RuntimeError("invalid owned PostgreSQL readiness record")
        return container, port

    def close(self):
        try:
            if self.process is not None:
                self.process.stdin.close()
                try:
                    code = self.process.wait(timeout=60)
                except subprocess.TimeoutExpired:
                    self.process.terminate()
                    try:
                        self.process.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        self.process.kill()
                        self.process.wait()
                    raise RuntimeError("owned integration project cleanup failed")
                if code:
                    raise RuntimeError("owned integration project cleanup failed")
        finally:
            if self.directory is not None:
                self.directory.cleanup()


def main(e2e=False, selection=None):
    os.umask(0o077)
    if e2e and sys.argv[1:]:
        raise ValueError("E2E runner accepts no targets or arguments")
    packages, flags = selection or arguments(["./tests/acceptance", "./internal/api", "-run", "^(TestReviewFlow|TestHTTPSProxyAuth)$", "-timeout", "5m"] if e2e else sys.argv[1:])
    validate_environment(os.environ)
    env = {key: os.environ[key] for key in ("PATH", "HOME", "TMPDIR", "USER", "LANG") if key in os.environ}
    env.update({"GOENV": "off", "GOWORK": "off", "GOFLAGS": "", "GOTOOLCHAIN": "local"})
    # Preparation also starts owned process groups; cancellation must unwind
    # run_command and terminate them before any database stack exists.
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, interrupted)
    if not e2e and packages == ["./..."] and not any(f in flags for f in ("-run", "-skip")):
        _, listed = run_command(["go", "list", "-f", "{{.Dir}}", "./..."], childenv=env)
        all_packages = ["./" + str(Path(p).relative_to(ROOT)) for p in listed.splitlines()]
        for index, batch in enumerate(full_suite_batches(all_packages, flags), 1):
            print(f"Full integration batch {index}/3 (fresh bounded PostgreSQL)", flush=True)
            # Each invocation owns and cleans its own stack even on failure or
            # cancellation. No operational target or credential crosses batches.
            if main(selection=batch):
                return 1
        print("PASS: full integration suite across 3 isolated batches", flush=True)
        return 0
    if e2e:
        prepare = ROOT / ".local/e2e"
        prepare.mkdir(parents=True, exist_ok=True)
        for name, command, timeout in (
            ("npm-ci", ["npm", "ci"], 180),
            ("ui-build", ["npm", "run", "build"], 180),
            ("browser-install", ["node", "node_modules/@playwright/test/cli.js", "install", "chromium"], 300),
        ):
            print("Preparing E2E " + name, flush=True)
            code, output = run_command(command, childenv=env, cwd=ROOT / "web", timeout=timeout, check=False)
            log = prepare / (name + ".log")
            log.write_text(output)
            os.chmod(log, 0o600)
            if code:
                raise RuntimeError("E2E preparation failed; see " + str(log.relative_to(ROOT)))
    secret_values = []
    run = functools.partial(run_command, childenv=env)

    discovery_flags = ["-race"] if "-race" in flags else []
    _, discovered = run(["go", "run", "./scripts/list-integration-tests.go"] + discovery_flags + packages)
    integrations = {(test["Package"], test["Test"]) for test in json.loads(discovered)}
    if not integrations:
        raise RuntimeError("selected packages contain no integration-tagged tests")
    _, context = run(["docker", "context", "show"])
    context = context.strip()
    _, description = run(["docker", "context", "inspect", context])
    endpoint = json.loads(description)[0]["Endpoints"]["docker"]["Host"]
    if not endpoint.startswith("unix://"):
        raise ValueError("integration tests require a local Unix-socket Docker context")
    project = "cheesetrap-test-" + secrets.token_hex(8)
    docker = ["docker", "--context", context]
    bootstrap = secrets.token_hex(32)
    secret_values.append(bootstrap)
    owner = OwnedPostgres(env, endpoint, project, bootstrap)
    result = 1
    primary_failure = False
    print("Starting isolated PostgreSQL integration project " + project + " (Testcontainers)", flush=True)
    try:
        container, port = owner.start()
        bootstrap_env = dict(env, PGPASSWORD=bootstrap)
        test_env = dict(env, CHEESETRAP_TEST_CONTAINER=container)
        options = ["--env", "PGPASSWORD"]
        for role in ("migration", "api", "collector", "worker"):
            password = secrets.token_hex(32)
            secret_values.append(password)
            variable = "CHEESETRAP_TEST_" + role.upper() + "_PASSWORD"
            bootstrap_env[variable] = password
            options.extend(("--env", variable))
            test_env["CHEESETRAP_TEST_" + role.upper() + "_URL"] = (
                f"postgresql://cheesetrap_{role}:{password}@127.0.0.1:{port}/cheesetrap_test?sslmode=disable&connect_timeout=5")
            test_env["CHEESETRAP_TEST_EMPTY_" + role.upper() + "_URL"] = test_env["CHEESETRAP_TEST_" + role.upper() + "_URL"].replace("/cheesetrap_test?", "/cheesetrap_migration_test?")
            test_env["CHEESETRAP_TEST_INSTALL_" + role.upper() + "_URL"] = test_env["CHEESETRAP_TEST_" + role.upper() + "_URL"].replace("/cheesetrap_test?", "/cheesetrap_install_test?")
            test_env["CHEESETRAP_TEST_ENRICHMENT_" + role.upper() + "_URL"] = test_env["CHEESETRAP_TEST_" + role.upper() + "_URL"].replace("/cheesetrap_test?", "/cheesetrap_enrichment_test?")
            test_env["CHEESETRAP_TEST_DETECTION_" + role.upper() + "_URL"] = test_env["CHEESETRAP_TEST_" + role.upper() + "_URL"].replace("/cheesetrap_test?", "/cheesetrap_detection_test?")
        for domain in ("PROOF", "MEMORY", "POLICY", "POLICY_API", "EVENTRESULT", "RESTORE", "CAPACITY", "RETENTION", "REPORTING", "JOBS", "REVISION", "DRAFT_RUNTIME", "REVIEW", "RULECONFIG", "REVIEW_UPGRADE", "REVIEW_FLOW", "AUTOMATIC_API", "SMTP_UPGRADE", "RETRY_UPGRADE", "APPROVAL", "DELIVERY_UPGRADE", "CHUNKS"):
            for role in ("MIGRATION", "API", "COLLECTOR", "WORKER"):
                test_env[f"CHEESETRAP_TEST_{domain}_{role}_URL"] = test_env[f"CHEESETRAP_TEST_{role}_URL"].replace("/cheesetrap_test?", f"/cheesetrap_{domain.lower()}_test?")
        run(docker + ["exec", "-i"] + options + [container, "psql", "-X", "-q", "-v", "ON_ERROR_STOP=1", "-h", "127.0.0.1", "-U", "postgres", "-d", "cheesetrap_test"],
            childenv=bootstrap_env, data=(ROOT / "deploy/test-bootstrap.sql").read_text())
        _, version = run(docker + ["exec", "--env", "PGPASSWORD", container, "psql", "-X", "-At", "-h", "127.0.0.1", "-U", "postgres", "-d", "cheesetrap_test", "-c", "SHOW server_version"], childenv=bootstrap_env)
        print("PostgreSQL " + version.strip(), flush=True)
        migration_env = dict(env, CHEESETRAP_DATABASE_URL=test_env["CHEESETRAP_TEST_MIGRATION_URL"])
        run(["go", "run", "./cmd/cheesetrap", "migrate"], childenv=migration_env, timeout=180)
        install_env = dict(env, CHEESETRAP_DATABASE_URL=test_env["CHEESETRAP_TEST_INSTALL_MIGRATION_URL"])
        run(["go", "run", "./cmd/cheesetrap", "migrate"], childenv=install_env, timeout=180)
        detection_env = dict(env, CHEESETRAP_DATABASE_URL=test_env["CHEESETRAP_TEST_DETECTION_MIGRATION_URL"])
        run(["go", "run", "./cmd/cheesetrap", "migrate"], childenv=detection_env, timeout=180)
        enrichment_env = dict(env, CHEESETRAP_DATABASE_URL=test_env["CHEESETRAP_TEST_ENRICHMENT_MIGRATION_URL"])
        run(["go", "run", "./cmd/cheesetrap", "migrate"], childenv=enrichment_env, timeout=180)
        for domain in ("PROOF", "MEMORY", "POLICY", "POLICY_API", "EVENTRESULT", "RESTORE", "CAPACITY", "RETENTION", "REPORTING", "JOBS", "REVISION", "DRAFT_RUNTIME", "REVIEW", "RULECONFIG", "REVIEW_FLOW", "AUTOMATIC_API", "APPROVAL"):
            run(["go", "run", "./cmd/cheesetrap", "migrate"], childenv=dict(env, CHEESETRAP_DATABASE_URL=test_env[f"CHEESETRAP_TEST_{domain}_MIGRATION_URL"]), timeout=180)
        print("Prepared migrated test/acceptance/detection/enrichment/reporting/jobs/revision/draft-runtime databases and separate empty migration-test database", flush=True)
        if e2e:
            test_env["CHEESETRAP_E2E_RUN"] = "1"
        # One bounded PostgreSQL serves every domain. Do not multiply its
        # working sets by the host's CPU count through parallel Go packages.
        code, output = run(["go", "test", "-p=1", "-tags=" + ("integration,release" if e2e else "integration"), "-count=1", "-json", "-timeout=3m"] + flags + packages,
                           childenv=test_env, check=False, timeout=660)
        for secret in secret_values:
            output = output.replace(secret, "[REDACTED]")
        logs = ROOT / (".local/restore" if "TestRestoreDrafts" in " ".join(flags) else ".local/e2e" if e2e or "TestReviewFlow" in " ".join(flags) else ".local/integration")
        logs.mkdir(parents=True, exist_ok=True)
        log = logs / (project + ".jsonl")
        log.write_text(output)
        os.chmod(log, 0o600)
        passed, failed, skipped, no_tests = test_results(output)
        if not results_succeeded(code, passed, failed, skipped, no_tests, integrations):
            raise RuntimeError("integration failed, skipped, or no discovered integration test executed; see " + str(log.relative_to(ROOT)))
        print(f"PASS: {sum(test is not None for _, test in passed)} tests; evidence {log.relative_to(ROOT)}", flush=True)
        result = 0
    except BaseException:
        primary_failure = True
        raise
    finally:
        # Release only the owned Testcontainers lease, including on cancellation.
        for sig in (signal.SIGINT, signal.SIGTERM):
            signal.signal(sig, signal.SIG_IGN)
        try:
            owner.close()
        except Exception:
            if not primary_failure:
                raise RuntimeError("owned integration project cleanup failed") from None
            # Keep the original exception and its evidence path. Only a fixed
            # cleanup category is public; never echo a secondary runtime error.
            print("owned integration project cleanup failed", file=sys.stderr, flush=True)
        else:
            print("Cleaned isolated project " + project, flush=True)
    return result


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (ValueError, RuntimeError, IntegrationInterrupted, subprocess.TimeoutExpired, OSError, KeyError) as exc:
        # Exception text is fixed by this runner, never include subprocess output.
        message = str(exc) if isinstance(exc, (ValueError, RuntimeError, IntegrationInterrupted)) else "integration runner infrastructure failure"
        print(message, file=sys.stderr)
        sys.exit(1)
