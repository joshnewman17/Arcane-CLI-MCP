import json
import subprocess
from types import SimpleNamespace

import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp.cli import fit_output, needs_confirmation, parse_json

from .conftest import API_KEY, MCP_TOKEN


class FakeRun:
    """Replacement for subprocess.run that returns canned output and records calls."""

    def __init__(self, stdout="", stderr="", returncode=0, raise_timeout=False):
        self.calls = []
        self.stdout, self.stderr, self.returncode = stdout, stderr, returncode
        self.raise_timeout = raise_timeout

    def __call__(self, argv, **kwargs):
        self.calls.append(SimpleNamespace(argv=argv, **kwargs))
        if self.raise_timeout:
            raise subprocess.TimeoutExpired(argv, kwargs["timeout"], output=b"partial", stderr=b"still pulling")
        return SimpleNamespace(returncode=self.returncode, stdout=self.stdout, stderr=self.stderr)

    @property
    def last(self):
        return self.calls[-1]


@pytest.fixture
def fake_run(monkeypatch):
    def install(**kw):
        fr = FakeRun(**kw)
        monkeypatch.setattr(cli_mod.subprocess, "run", fr)
        return fr

    return install


def test_argv_construction(runner, settings, fake_run):
    fr = fake_run(stdout='{"data": [], "pagination": {}}')
    r = runner.run(["containers", "list", "--all"], env_id="2")
    assert r["ok"] is True
    assert fr.last.argv == [
        settings.cli_path, "--config", str(settings.cli_config_path), "--no-color",
        "containers", "list", "--all", "--env", "2", "--json",
    ]
    assert "--yes" not in fr.last.argv
    assert fr.last.stdin is subprocess.DEVNULL
    assert fr.last.timeout == settings.default_timeout_s
    # no shell, argument list only
    assert "shell" not in fr.last.__dict__ or fr.last.shell is False


def test_default_env_used(runner, fake_run):
    fr = fake_run(stdout="{}")
    runner.run(["containers", "list"])
    i = fr.last.argv.index("--env")
    assert fr.last.argv[i + 1] == "0"


@pytest.mark.parametrize("bad", ["0; rm -rf /", "../x", "a b", "x" * 65])
def test_bad_env_id(runner, fake_run, bad):
    fr = fake_run(stdout="{}")
    r = runner.run(["containers", "list"], env_id=bad)
    assert r["ok"] is False and "env_id" in r["error"]
    # At most the environment lookup ran, never the command itself.
    assert not any("containers" in c.argv for c in fr.calls)


def test_confirm_appends_yes(runner, fake_run):
    fr = fake_run(stdout='{"ok": true}')
    r = runner.run(["projects", "destroy", "foo"], confirm=True)
    assert r["ok"] is True
    assert fr.last.argv[-1] == "--yes"


def test_destroy_without_confirm_does_not_execute(runner, fake_run):
    fr = fake_run(stdout="{}")
    r = runner.run(["projects", "destroy", "foo"])
    assert r["needs_confirmation"] is True and r["ok"] is False
    assert "Nothing was changed" in r["message"]
    assert fr.calls == []


def test_user_supplied_yes_and_force_stripped(runner, fake_run):
    fr = fake_run(stdout="{}")
    r = runner.run(["containers", "restart", "web", "--yes", "--force", "--json", "--output", "text"])
    assert r["ok"]
    assert r["stripped_args"] == ["--yes", "--force", "--json", "--output", "text"]
    argv = fr.last.argv
    assert "--yes" not in argv and "--force" not in argv and "text" not in argv
    assert argv.count("--json") == 1


def test_blocked_never_executes(runner, fake_run):
    fr = fake_run(stdout="{}")
    r = runner.run(["auth", "login"], confirm=True)
    assert r["blocked"] is True and "web UI" in r["error"]
    assert fr.calls == []


def test_readonly_mode(tmp_path, fake_run, audit_stream):
    from arcane_mcp.audit import AuditLog, Redactor
    from arcane_mcp.cli import CliRunner

    from .conftest import make_settings

    s = make_settings(tmp_path, readonly=True)
    red = Redactor(s.secrets())
    r = CliRunner(s, red, AuditLog(None, red, audit_stream))
    fr = fake_run(stdout="{}")
    assert r.run(["containers", "update", "web"], confirm=True)["blocked"] is True
    assert fr.calls == []
    assert r.run(["containers", "list"])["ok"] is True


@pytest.mark.parametrize(
    "args,long",
    [(["projects", "up", "x"], True), (["projects", "redeploy", "x"], True), (["projects", "pull", "x"], True),
     (["projects", "build", "x"], True), (["images", "pull", "nginx"], True), (["containers", "list"], False)],
)
def test_timeout_selection(runner, settings, fake_run, args, long):
    fr = fake_run(stdout="[]")
    runner.run(args)
    assert fr.last.timeout == (settings.long_timeout_s if long else settings.default_timeout_s)


def test_timeout_expired(runner, fake_run):
    fake_run(raise_timeout=True)
    r = runner.run(["projects", "redeploy", "x"])
    assert r["ok"] is False and r["timed_out"] is True
    assert "activities list" in r["error"]


def test_cli_confirmation_required_detected(runner, fake_run):
    # A command our policy doesn't gate, but the CLI itself prompts for.
    fake_run(stdout="", stderr="\n  Error\n  confirmation required: re-run with --yes (Are you sure?)\n", returncode=1)
    r = runner.run(["containers", "stop", "web"])
    assert r["ok"] is False
    assert r["needs_confirmation"] is True
    assert "confirmation required" in r["stderr_tail"]


def test_non_json_stdout(runner, fake_run):
    fake_run(stdout="\x1b[1mhello\x1b[0m world", stderr="warn: something", returncode=0)
    r = runner.run(["containers", "list"])
    assert r["raw_stdout"] == "hello world"
    assert r["stderr_tail"] == "warn: something"


def test_error_exit_code(runner, fake_run):
    fake_run(stdout="", stderr="Error\nnot found", returncode=1)
    r = runner.run(["projects", "get", "nope"])
    assert r["ok"] is False and r["exit_code"] == 1 and "not found" in r["stderr_tail"]
    assert "needs_confirmation" not in r


def test_subprocess_env_has_no_secrets(runner, fake_run, monkeypatch):
    monkeypatch.setenv("ARCANE_API_KEY", API_KEY)
    monkeypatch.setenv("MCP_AUTH_TOKEN", MCP_TOKEN)
    fr = fake_run(stdout="{}")
    runner.run(["containers", "list"])
    env = fr.last.env
    assert set(env) == {"PATH", "HOME", "LANG", "NO_COLOR", "TERM"}
    assert API_KEY not in json.dumps(env) and MCP_TOKEN not in json.dumps(env)
    assert API_KEY not in json.dumps(fr.last.argv)


def test_api_key_in_output_redacted(runner, fake_run, audit_stream, settings):
    fake_run(stdout=json.dumps({"data": {"key": API_KEY}}), stderr=f"debug: X-Api-Key: {API_KEY}", returncode=0)
    r = runner.run(["containers", "list"])
    blob = json.dumps(r)
    assert API_KEY not in blob and "[REDACTED]" in blob
    assert API_KEY not in audit_stream.getvalue()
    assert API_KEY not in settings.audit_log_path.read_text()


def test_audit_record(runner, fake_run, audit_stream):
    fake_run(stdout="{}")
    runner.run(["containers", "list"], env_id="2")
    entry = json.loads(audit_stream.getvalue().strip().splitlines()[-1])
    assert entry["tool"] == "arcane_run"
    assert entry["argv"] == ["containers", "list", "--env", "2", "--json"]
    assert entry["env_id"] == "2" and entry["confirm"] is False
    assert entry["exit_code"] == 0 and isinstance(entry["duration_ms"], int)
    assert "ts" in entry


def test_cli_not_found(runner, monkeypatch):
    def boom(*a, **k):
        raise FileNotFoundError

    monkeypatch.setattr(cli_mod.subprocess, "run", boom)
    r = runner.run(["containers", "list"])
    assert r["ok"] is False and r["exit_code"] == 127


# --- helpers ------------------------------------------------------------------------


def test_parse_json():
    assert parse_json('{"a": 1}') == (True, {"a": 1})
    assert parse_json("") == (True, None)
    assert parse_json("nope") == (False, "nope")


def test_needs_confirmation():
    assert needs_confirmation("Error\nconfirmation required: re-run with --yes")
    assert needs_confirmation("CONFIRMATION REQUIRED")
    assert not needs_confirmation("not found")


def test_fit_output_list_keeps_first_items():
    data = {"data": [{"id": i, "pad": "x" * 50} for i in range(1000)], "pagination": {"totalItems": 1000}}
    out, note = fit_output(data, 5000)
    assert len(json.dumps(out, separators=(",", ":"))) <= 5000
    assert out["data"][0]["id"] == 0 and len(out["data"]) < 1000
    assert out["pagination"] == {"totalItems": 1000}
    assert "--limit" in note


def test_fit_output_frames_keep_last():
    frames = [{"status": f"layer {i}", "pad": "y" * 80} for i in range(500)]
    out, note = fit_output(frames, 3000)
    assert out[-1]["status"] == "layer 499"
    assert "last" in note


def test_fit_output_scalar_truncated():
    out, note = fit_output({"blob": "z" * 10000}, 100)
    assert isinstance(out, str) and len(out) == 100 and "truncated" in note


def test_fit_output_small_untouched():
    assert fit_output({"a": 1}, 100) == ({"a": 1}, None)


def test_truncation_reported(runner, fake_run, tmp_path):
    big = {"data": [{"i": i, "pad": "p" * 100} for i in range(2000)], "pagination": {}}
    fake_run(stdout=json.dumps(big))
    r = runner.run(["containers", "list", "--all"], compact=False)
    assert r["truncated"] is True and "showing" in r["truncation_note"]
    assert len(json.dumps(r["data"], separators=(",", ":"))) <= runner.settings.max_output_chars


def test_help_rejects_flags_and_control_chars(runner, fake_run):
    fr = fake_run(stdout="USAGE")
    assert runner.help(["projects", "--config"])["ok"] is False
    assert runner.help(["projects\n"])["ok"] is False
    assert fr.calls == []
    r = runner.help(["projects"])
    assert r["ok"] and fr.last.argv[-2:] == ["projects", "--help"]


def test_help_notes_blocked_commands(runner, fake_run):
    fake_run(stdout="USAGE")
    assert "blocked" in runner.help(["auth", "login"])["policy"]


def test_environments_trimmed(runner, fake_run):
    payload = {"data": [{"id": "0", "name": "local", "status": "online", "apiUrl": "x", "big": "y" * 999}],
               "pagination": {}}
    fake_run(stdout=json.dumps(payload))
    r = runner.environments()
    assert r == {"ok": True, "default_env_id": "0",
                 "environments": [{"id": "0", "name": "local", "status": "online"}]}


def test_json_with_secret_named_object_keys_parses(runner, fake_run):
    payload = {"data": [{"name": "r", "apiKey": {"type": "string"}, "token": "ghp_secret"}], "pagination": {}}
    fake_run(stdout=json.dumps(payload))
    r = runner.run(["registries", "list"])
    assert "raw_stdout" not in r
    assert r["data"]["data"][0] == {"name": "r", "apiKey": {"type": "string"}, "token": "[REDACTED]"}
