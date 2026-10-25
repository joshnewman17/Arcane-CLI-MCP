"""arcane_project_compose: read the compose file, confirmed writes, no .env exposure."""

import io
import json
import subprocess
from types import SimpleNamespace

import httpx
import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp.api import ApiClient
from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.cli import CliRunner
from arcane_mcp.compose_edit import (
    MAX_COMPOSE_BYTES,
    PLACEHOLDER,
    ComposeEditor,
    env_template,
    unfilled,
)

from .conftest import API_KEY, make_settings

PROJECT_ID = "2e604cd4-7a09-46dc-86d8-afefd54f7b54"
CURRENT = "services:\n  app:\n    image: nginx:1.27\n"
NEW = "services:\n  app:\n    image: nginx:1.28\n    environment:\n      TOKEN: ${APP_TOKEN:?set it}\n"
ENV_SECRET = "TUNNEL_TOKEN=eyJsupersecrettunneltoken\nARCANE_API_KEY=arc_should_never_leave"


class FakeCli:
    """subprocess.run stand-in for `projects get` and `projects update -f <file>`."""

    def __init__(self, update_rc=0, existing=("app",)):
        self.calls = []
        self.uploaded = None
        self.uploaded_path = None
        self.uploaded_env = None
        self.update_rc = update_rc
        self.existing = existing

    def __call__(self, argv, **kw):
        args = argv[4:]
        self.calls.append(args)
        if args[:2] == ["environments", "list"]:
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"data": [{"id": "0", "name": "local"}]}))
        if args[:2] == ["projects", "get"]:
            if args[2] not in self.existing:
                return SimpleNamespace(returncode=1, stdout="", stderr="Error\nproject not found")
            return SimpleNamespace(returncode=0, stderr="",
                                   stdout=json.dumps({"data": {"id": PROJECT_ID, "name": args[2]}}))
        if args[:2] == ["projects", "update"]:
            path = args[args.index("-f") + 1]
            self.uploaded_path = path
            with open(path) as fh:
                self.uploaded = fh.read()
            return SimpleNamespace(returncode=self.update_rc, stderr="" if not self.update_rc else "Error\nboom",
                                   stdout=json.dumps({"data": {"name": args[2], "serviceCount": 1,
                                                               "status": "running", "updatedAt": "t"}}))
        if args[:2] == ["projects", "create"]:
            self.uploaded_path = args[args.index("-f") + 1]
            with open(self.uploaded_path) as fh:
                self.uploaded = fh.read()
            with open(args[args.index("--env-file") + 1]) as fh:
                self.uploaded_env = fh.read()
            name = args[args.index("--name") + 1]
            return SimpleNamespace(returncode=self.update_rc, stderr="" if not self.update_rc else "Error\nboom",
                                   stdout=json.dumps({"data": {"id": "new-id", "name": name, "serviceCount": 1,
                                                               "status": "stopped"}}))
        raise AssertionError(f"unexpected command {args}")


def compose_api(request: httpx.Request):
    assert request.method == "GET"
    assert request.url.path == f"/api/environments/0/projects/{PROJECT_ID}/compose"
    return httpx.Response(200, json={"data": {
        "id": PROJECT_ID, "name": "app", "composeFileName": "compose.yaml", "composeContent": CURRENT,
        "envContent": ENV_SECRET, "services": [{"service": "app", "state": "running"}]}})


@pytest.fixture
def setup(tmp_path, monkeypatch):
    def build(readonly=False, update_rc=0):
        settings = make_settings(tmp_path, readonly=readonly)
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        stream = io.StringIO()
        red = Redactor(settings.secrets())
        audit = AuditLog(settings.audit_log_path, red, stream)
        runner = CliRunner(settings, red, audit)
        api = ApiClient(settings, red, audit, transport=httpx.MockTransport(compose_api))
        fake = FakeCli(update_rc)
        monkeypatch.setattr(cli_mod.subprocess, "run", fake)
        return ComposeEditor(runner, api, red, audit), fake, stream, settings
    return build


def test_read_returns_compose_but_never_env(setup):
    editor, fake, stream, _ = setup()
    r = editor.read("app", "0")
    assert r["ok"] and r["compose"] == CURRENT and r["compose_file"] == "compose.yaml" and r["services"] == ["app"]
    blob = json.dumps(r) + stream.getvalue()
    assert "eyJsupersecret" not in blob and "arc_should_never_leave" not in blob and "envContent" not in r


def test_write_without_confirm_returns_diff_and_changes_nothing(setup):
    editor, fake, _, _ = setup()
    r = editor.write("app", NEW, "0")
    assert r["needs_confirmation"] is True and r["ok"] is False
    assert "-    image: nginx:1.27" in r["diff"] and "+    image: nginx:1.28" in r["diff"]
    assert not any(c[:2] == ["projects", "update"] for c in fake.calls)


def test_confirmed_write_uploads_exact_content_from_private_temp_file(setup):
    editor, fake, stream, settings = setup()
    r = editor.write("app", NEW, "0", confirm=True)
    assert r["ok"] is True and "redeploy" in r["message"]
    update = next(c for c in fake.calls if c[:2] == ["projects", "update"])
    assert update[2] == "app" and update[-3:] == ["0", "--json", "--yes"]
    assert fake.uploaded == NEW
    # The temp file lived under the server's private state dir and is gone afterwards.
    assert fake.uploaded_path.startswith(str(settings.state_dir))
    assert not list(settings.state_dir.glob("compose-*"))
    entry = [json.loads(line) for line in stream.getvalue().splitlines()][-1]
    assert entry["tool"] == "arcane_project_compose" and entry["outcome"] == "ok" and len(entry["sha256"]) == 16


def test_failed_update_reported_and_temp_file_removed(setup):
    editor, fake, _, settings = setup(update_rc=1)
    r = editor.write("app", NEW, "0", confirm=True)
    assert r["ok"] is False and "boom" in r["stderr_tail"]
    assert not list(settings.state_dir.glob("compose-*"))


def test_unchanged_is_a_noop(setup):
    editor, fake, _, _ = setup()
    r = editor.write("app", CURRENT, "0", confirm=True)
    assert r["ok"] and r["unchanged"] and not any(c[:2] == ["projects", "update"] for c in fake.calls)


def test_readonly_blocks_write_but_allows_read(setup):
    editor, fake, _, _ = setup(readonly=True)
    assert editor.write("app", NEW, "0", confirm=True)["blocked"] is True
    assert fake.calls == []
    assert editor.read("app", "0")["ok"] is True


@pytest.mark.parametrize(
    "compose,msg",
    [
        ("", "non-empty"),
        ("services: [unclosed", "not valid YAML"),
        ("just a string", "services"),
        ("version: '3'\n", "services"),
        ("services: {}\n", "services"),
        (CURRENT.replace("nginx:1.27", "[REDACTED]"), "REDACTED"),
        ("services:\n  a:\n    image: x\n" + "#" * MAX_COMPOSE_BYTES, "larger than"),
        ("services:\n  a:\n    image: x\x00\n", "NUL"),
    ],
)
def test_invalid_compose_rejected_before_any_call(setup, compose, msg):
    editor, fake, _, _ = setup()
    r = editor.write("app", compose, "0", confirm=True)
    assert r["ok"] is False and msg in r["error"]
    assert not any(c[:2] == ["projects", "update"] for c in fake.calls)


@pytest.mark.parametrize("project", ["../etc", "a b", "-f", "", "x" * 200])
def test_bad_project_names(setup, project):
    editor, fake, _, _ = setup()
    assert editor.read(project)["ok"] is False and fake.calls == []


def test_missing_project(setup):
    editor, _, _, _ = setup()
    r = editor.read("missing", "0")
    assert r["ok"] is False and "not found" in r["error"]


def test_arcane_run_still_rejects_file_flags(setup):
    editor, fake, _, _ = setup()
    r = editor.runner.run(["projects", "update", "app", "-f", "/tmp/arcane-cli-mcp/arcanecli.yml"])
    assert r["ok"] is False and "filesystem" in r["error"] and fake.calls == []


def test_api_get_on_compose_endpoint_withholds_env(setup):
    editor, _, _, _ = setup()
    r = editor.api.get(f"/api/environments/0/projects/{PROJECT_ID}/compose")
    assert r["data"]["data"]["envContent"] == "[REDACTED]"
    assert r["data"]["data"]["composeContent"] == CURRENT
    assert API_KEY not in json.dumps(r)


# -- project creation ------------------------------------------------------------------------------

CREATE = (
    "services:\n  app:\n    image: ghcr.io/x/app:${TAG:-1.2}\n    environment:\n"
    "      TOKEN: ${APP_TOKEN:?set it}\n      TZ: ${TZ-UTC}\n      LITERAL: $${NOT_A_VAR}\n"
    "      AGAIN: ${APP_TOKEN}\n      DOMAIN: ${DOMAIN}\n"
)


def test_env_template_defaults_placeholders_and_hints():
    env, placeholders = env_template(CREATE, {"APP_TOKEN": "Token from the vendor dashboard", "EXTRA": ""})
    lines = env.splitlines()
    assert lines[0].startswith("# Generated by arcane-cli-mcp")
    assert lines[1:] == ["TAG=1.2", "# Token from the vendor dashboard", f"APP_TOKEN={PLACEHOLDER}", "TZ=UTC",
                         f"DOMAIN={PLACEHOLDER}", f"EXTRA={PLACEHOLDER}"]
    assert placeholders == ["APP_TOKEN", "DOMAIN", "EXTRA"]
    assert "NOT_A_VAR" not in env


@pytest.mark.parametrize("hints", [{"bad-key": "x"}, {"OK": "two\nlines"}, {"OK": "x" * 500}, {"OK": "[REDACTED]"},
                                   ["OK"]])
def test_env_template_rejects_bad_hints(hints):
    with pytest.raises(ValueError):
        env_template(CREATE, hints)


def test_unfilled_names_only():
    assert unfilled(f"# c\nA={PLACEHOLDER}\nB=real\nexport C=\"{PLACEHOLDER}\"\nD=\n") == ["A", "C"]


def test_create_without_confirm_previews_and_runs_nothing(setup):
    editor, fake, _, _ = setup()
    r = editor.create("newapp", CREATE, "0", {"APP_TOKEN": "vendor token"})
    assert r["needs_confirmation"] is True and r["ok"] is False
    assert r["services"] == ["app"] and r["placeholders"] == ["APP_TOKEN", "DOMAIN"]
    assert f"APP_TOKEN={PLACEHOLDER}" in r["env_file"]
    assert not any(c[:2] == ["projects", "create"] for c in fake.calls)


def test_confirmed_create_uploads_compose_and_env_then_cleans_up(setup):
    editor, fake, stream, settings = setup()
    r = editor.create("newapp", CREATE, "0", confirm=True)
    assert r["ok"] is True and "NOT deployed" in r["message"] and "APP_TOKEN, DOMAIN" in r["message"]
    create = next(c for c in fake.calls if c[:2] == ["projects", "create"])
    assert create[create.index("--name") + 1] == "newapp" and create[-3:] == ["0", "--json", "--yes"]
    assert fake.uploaded == CREATE and f"DOMAIN={PLACEHOLDER}" in fake.uploaded_env
    assert fake.uploaded_path.startswith(str(settings.state_dir))
    assert not list(settings.state_dir.glob("compose-*"))
    entry = [json.loads(line) for line in stream.getvalue().splitlines()][-1]
    assert entry["tool"] == "arcane_project_create" and entry["outcome"] == "ok"


def test_create_refuses_existing_project(setup):
    editor, fake, _, _ = setup()
    r = editor.create("app", CREATE, "0", confirm=True)
    assert r["ok"] is False and "already exists" in r["error"]
    assert not any(c[:2] == ["projects", "create"] for c in fake.calls)


def test_failed_create_reported_and_temp_files_removed(setup):
    editor, _, _, settings = setup(update_rc=1)
    r = editor.create("newapp", CREATE, "0", confirm=True)
    assert r["ok"] is False and "boom" in r["stderr_tail"] and "message" not in r
    assert not list(settings.state_dir.glob("compose-*"))


def test_create_blocked_in_readonly_and_validates_compose(setup):
    editor, fake, _, _ = setup(readonly=True)
    assert editor.create("newapp", CREATE, "0", confirm=True)["blocked"] is True and fake.calls == []
    editor, fake, _, _ = setup()
    r = editor.create("newapp", CURRENT.replace("nginx:1.27", "[REDACTED]"), "0", confirm=True)
    assert r["ok"] is False and "REDACTED" in r["error"]
    assert not any(c[:2] == ["projects", "create"] for c in fake.calls)


def test_read_reports_unfilled_placeholders_without_values(tmp_path, monkeypatch):
    settings = make_settings(tmp_path)
    stream = io.StringIO()
    red = Redactor(settings.secrets())
    audit = AuditLog(settings.audit_log_path, red, stream)
    env = f"{ENV_SECRET}\nDOMAIN={PLACEHOLDER}\n"

    def handler(request):
        return httpx.Response(200, json={"data": {"composeFileName": "compose.yaml", "composeContent": CURRENT,
                                                  "envContent": env}})
    api = ApiClient(settings, red, audit, transport=httpx.MockTransport(handler))
    monkeypatch.setattr(cli_mod.subprocess, "run", FakeCli())
    r = ComposeEditor(CliRunner(settings, red, audit), api, red, audit).read("app", "0")
    assert r["env_unfilled"] == ["DOMAIN"] and "fill them" in r["note"]
    blob = json.dumps(r) + stream.getvalue()
    assert "eyJsupersecret" not in blob and "arc_should_never_leave" not in blob


def test_arcane_run_points_create_to_the_tool(setup):
    editor, fake, _, _ = setup()
    r = editor.runner.run(["projects", "create", "--name", "x", "-f", "/etc/passwd"])
    assert r["ok"] is False and "arcane_project_create" in r["error"] and fake.calls == []
