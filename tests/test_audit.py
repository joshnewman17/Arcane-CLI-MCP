import io
import json

from arcane_mcp.audit import REDACTED, AuditLog, Redactor
from arcane_mcp.config import load_settings, write_cli_config

from .conftest import API_KEY, MCP_TOKEN


def test_redacts_known_secrets():
    r = Redactor([API_KEY, MCP_TOKEN])
    assert r.text(f"key={API_KEY} tok {MCP_TOKEN}") == f"key={REDACTED} tok {REDACTED}"


def test_redacts_credential_patterns_without_known_value():
    r = Redactor([])
    assert r.text("X-Api-Key: abc123") == f"X-Api-Key: {REDACTED}"
    assert r.text("Authorization: Bearer eyJhbGciOi") == f"Authorization: Bearer {REDACTED}"
    assert r.text('{"api_key": "zzz"}') == f'{{"api_key": "{REDACTED}"}}'
    assert r.text('{"apiKey":"zzz"}') == f'{{"apiKey":"{REDACTED}"}}'
    assert r.text('"refresh_token": "abc"') == f'"refresh_token": "{REDACTED}"'


def test_redacted_json_stays_parseable():
    r = Redactor([])
    assert json.loads(r.text('{"apiKey":"secret","x":1}')) == {"apiKey": REDACTED, "x": 1}


def test_redacts_nested_objects():
    r = Redactor([API_KEY])
    out = r.obj({"a": [{"b": f"prefix-{API_KEY}"}], "n": 3})
    assert out == {"a": [{"b": f"prefix-{REDACTED}"}], "n": 3}


def test_short_secrets_ignored():
    # Redacting a 1-3 char "secret" would shred all output.
    assert Redactor(["ab"]).text("abc") == "abc"


def test_audit_writes_jsonl_to_stream_and_file(tmp_path):
    stream = io.StringIO()
    path = tmp_path / "data" / "audit.log"
    log = AuditLog(path, Redactor([API_KEY]), stream)
    log.record(tool="arcane_run", argv=["containers", "list", API_KEY], env_id="0", confirm=False,
               exit_code=0, duration_ms=5)
    for text in (stream.getvalue(), path.read_text()):
        entry = json.loads(text.strip())
        assert entry["argv"][-1] == REDACTED
        assert API_KEY not in text
        assert {"ts", "tool", "argv", "env_id", "confirm", "exit_code", "duration_ms"} <= set(entry)


def test_unwritable_audit_path_falls_back_to_stream(tmp_path):
    blocker = tmp_path / "file"
    blocker.write_text("x")
    stream = io.StringIO()
    log = AuditLog(blocker / "audit.log", Redactor([]), stream)  # parent is a file
    log.record(tool="t")
    assert '"tool":"t"' in stream.getvalue()


def test_settings_repr_hides_secrets(tmp_path):
    s = load_settings({"ARCANE_URL": "http://a:1", "ARCANE_API_KEY": API_KEY, "MCP_AUTH_TOKEN": MCP_TOKEN,
                       "ARCANE_MCP_STATE_DIR": str(tmp_path / "s")})
    assert API_KEY not in repr(s) and MCP_TOKEN not in repr(s)


def test_cli_config_file_is_private(tmp_path):
    s = load_settings({"ARCANE_URL": "http://a:1/", "ARCANE_API_KEY": API_KEY,
                       "ARCANE_MCP_STATE_DIR": str(tmp_path / "s"), "ARCANE_DEFAULT_ENV": "3"})
    path = write_cli_config(s)
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    assert oct(s.state_dir.stat().st_mode & 0o777) == "0o700"
    import yaml

    assert yaml.safe_load(path.read_text()) == {
        "server_url": "http://a:1", "api_key": API_KEY, "default_environment": "3", "log_level": "warn"}
