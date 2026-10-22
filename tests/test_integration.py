"""Opt-in, read-only checks against a real Arcane instance.

    ARCANE_IT=1 ARCANE_URL=https://arcane.lan ARCANE_API_KEY=... pytest -m integration

Needs arcane-cli on PATH (or ARCANE_CLI_PATH). Only read-only commands are run.
"""

import io
import os

import pytest

from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.cli import CliRunner
from arcane_mcp.config import load_settings, write_cli_config

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("ARCANE_IT") != "1", reason="set ARCANE_IT=1 to run integration tests"),
]


@pytest.fixture(scope="module")
def live():
    env = {**os.environ, "ARCANE_MCP_READONLY": "true", "AUDIT_LOG_PATH": ""}
    settings = load_settings(env)
    write_cli_config(settings)
    red = Redactor(settings.secrets())
    stream = io.StringIO()
    return CliRunner(settings, red, AuditLog(None, red, stream)), settings, stream


def test_doctor(live):
    runner, _, _ = live
    r = runner.doctor()
    assert r["ok"], r


def test_environments_list(live):
    runner, _, _ = live
    r = runner.environments()
    assert r["ok"] and r["environments"], r


def test_containers_list(live):
    runner, _, _ = live
    r = runner.run(["containers", "list", "--limit", "5"])
    assert r["ok"] and "data" in r["data"], r


def test_containers_updates(live):
    runner, _, _ = live
    assert runner.run(["containers", "updates"])["ok"]


def test_readonly_blocks_mutation(live):
    runner, _, _ = live
    assert runner.run(["containers", "restart", "anything"], confirm=True)["blocked"]


def test_key_not_leaked(live):
    runner, settings, stream = live
    runner.run(["auth", "me"])
    # Compute a bool first: a bare `assert key not in text` would make pytest print the real key on failure.
    leaked = settings.arcane_api_key in stream.getvalue()
    assert not leaked, "API key found in audit output"
