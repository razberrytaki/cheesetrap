#!/usr/bin/env python3
"""Browser mode shares the integration runner's owned local stack and cleanup."""
import importlib.util
from pathlib import Path
import sys
spec = importlib.util.spec_from_file_location("integration_runner", Path(__file__).with_name("test-integration.py"))
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
try:
    sys.exit(runner.main(e2e=True))
except (ValueError, RuntimeError, runner.IntegrationInterrupted, runner.subprocess.TimeoutExpired, OSError, KeyError) as exc:
    print(str(exc) if isinstance(exc, (ValueError, RuntimeError, runner.IntegrationInterrupted)) else "E2E infrastructure failure", file=sys.stderr)
    sys.exit(1)
