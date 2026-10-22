from __future__ import annotations

import io
import sys
from pathlib import Path

import pytest

from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.cli import CliRunner
from arcane_mcp.config import Settings, write_cli_config

API_KEY = "arc_live_SUPERSECRETKEY_1234567890"
MCP_TOKEN = "mcp-token-abcdef-0987654321"
FAKE_CLI = Path(__file__).parent / "fake_arcane_cli.py"


def make_settings(tmp_path: Path, **overrides) -> Settings:
    base = dict(
        arcane_url="http://arcane.test:3552",
        arcane_api_key=API_KEY,
        default_env="0",
        auth_token=MCP_TOKEN,
        cli_path=sys.executable,  # replaced per test where a real exec is needed
        state_dir=tmp_path / "state",
        audit_log_path=tmp_path / "data" / "audit.log",
        max_output_chars=40000,
    )
    base.update(overrides)
    return Settings(**base)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    s = make_settings(tmp_path)
    write_cli_config(s)
    return s


@pytest.fixture
def audit_stream() -> io.StringIO:
    return io.StringIO()


@pytest.fixture
def runner(settings: Settings, audit_stream: io.StringIO) -> CliRunner:
    redactor = Redactor(settings.secrets())
    return CliRunner(settings, redactor, AuditLog(settings.audit_log_path, redactor, audit_stream))
