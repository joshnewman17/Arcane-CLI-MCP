"""Mutating commands aimed at the MCP server's own project or containers need confirm AND allow_self."""

import io
import json
from types import SimpleNamespace

import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp import policy
from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.cli import CliRunner

from .conftest import make_settings

SELF_PROJECT_ID = "9b2f6c1e-1d2a-4c3b-8e7f-0a1b2c3d4e5f"
SELF_CONTAINER_ID = "ab12cd34ef56" + "0" * 52
OTHER_CONTAINER_ID = "fe98dc76ba54" + "1" * 52


class FakeCli:
    def __init__(self):
        self.calls = []

    def __call__(self, argv, **kw):
        args = argv[4:]
        self.calls.append(args)
        out: dict = {"success": True, "data": {"ok": True}}
        if args[:2] == ["environments", "list"]:
            out = {"data": [{"id": "0", "name": "homelab"}, {"id": "3", "name": "AWS ARM Micro"}]}
        elif args[:2] == ["projects", "get"]:
            out = {"data": {"id": args[2], "name": "arcane-cli-mcp" if args[2] == SELF_PROJECT_ID else "other"}}
        elif args[:2] == ["containers", "get"]:
            if args[2] == SELF_CONTAINER_ID:
                out = {"data": {"id": args[2], "name": "renamed-tunnel",
                                "labels": {"com.docker.compose.project": "arcane-cli-mcp"}}}
            else:
                out = {"data": {"id": args[2], "name": "immich", "labels": {"com.docker.compose.project": "immich"}}}
        return SimpleNamespace(returncode=0, stdout=json.dumps(out), stderr="")


@pytest.fixture
def setup(tmp_path, monkeypatch):
    def build(**overrides):
        settings = make_settings(tmp_path, **overrides)
        settings.state_dir.mkdir(parents=True, exist_ok=True)
        red = Redactor(settings.secrets())
        runner = CliRunner(settings, red, AuditLog(None, red, io.StringIO()))
        fake = FakeCli()
        monkeypatch.setattr(cli_mod.subprocess, "run", fake)
        monkeypatch.setenv("HOSTNAME", "0123456789ab")  # not the self container
        return runner, fake
    return build


def executed(fake, path):
    """Calls of the command itself (not the get/list lookups the guard makes)."""
    return [c for c in fake.calls if tuple(c[: len(path)]) == path]


SELF_CONTAINER_VERBS = sorted(p for p in policy.SELF_MUTATING if p[0] == "containers")
SELF_PROJECT_VERBS = sorted(p for p in policy.SELF_MUTATING if p[0] == "projects")


@pytest.mark.parametrize("path", SELF_PROJECT_VERBS, ids=" ".join)
@pytest.mark.parametrize("target", ["arcane-cli-mcp", "ARCANE-CLI-MCP", SELF_PROJECT_ID])
def test_project_verbs_on_self(setup, path, target):
    runner, fake = setup()
    for confirm, allow_self in [(False, False), (True, False), (False, True)]:
        r = runner.run([*path, target], confirm=confirm, allow_self=allow_self)
        assert r["ok"] is False and r["self_target"] is True, (confirm, allow_self)
        assert "restart the MCP server itself" in r["message"]
    assert executed(fake, path) == []
    r = runner.run([*path, target], confirm=True, allow_self=True)
    assert r.get("self_target") is None and r["ok"] is True
    assert len(executed(fake, path)) == 1


@pytest.mark.parametrize("path", SELF_CONTAINER_VERBS, ids=" ".join)
@pytest.mark.parametrize("target", ["arcane-cli-mcp", "arcane-cli-mcp-tunnel", "/arcane-cli-mcp",
                                    "arcane-cli-mcp-cloudflared-1", SELF_CONTAINER_ID, SELF_CONTAINER_ID[:12]])
def test_container_verbs_on_self(setup, monkeypatch, path, target):
    runner, fake = setup()
    if target == SELF_CONTAINER_ID[:12]:
        # A short id is matched against the server's own hostname (Docker's short container id).
        monkeypatch.setenv("HOSTNAME", SELF_CONTAINER_ID[:12])
    r = runner.run([*path, target], confirm=True)
    assert r["ok"] is False and r["self_target"] is True
    assert executed(fake, path) == []
    assert runner.run([*path, target], confirm=True, allow_self=True)["ok"] is True


@pytest.mark.parametrize("path", [("system", "containers", "stop"), ("updater", "run")], ids=" ".join)
def test_environment_wide_commands(setup, path):
    runner, fake = setup()
    r = runner.run(list(path), confirm=True)
    assert r["self_target"] is True and executed(fake, path) == []


@pytest.mark.parametrize("args", [
    ["containers", "restart", "immich"],
    ["containers", "restart", OTHER_CONTAINER_ID],
    ["projects", "redeploy", "immich"],
    ["projects", "redeploy", "11111111-2222-3333-4444-555555555555"],
    ["containers", "get", "arcane-cli-mcp"],         # read-only
    ["containers", "logs", "arcane-cli-mcp"],        # not a mutating verb
    ["projects", "get", "arcane-cli-mcp"],
])
def test_other_targets_and_reads_unaffected(setup, args):
    runner, _ = setup()
    r = runner.run(args, confirm=True)
    assert r.get("self_target") is None


def test_other_environment_unaffected(setup):
    runner, _ = setup()
    assert runner.run(["projects", "down", "arcane-cli-mcp"], env_id="3", confirm=True).get("self_target") is None
    assert runner.run(["projects", "down", "arcane-cli-mcp"], env_id="AWS ARM Micro",
                      confirm=True).get("self_target") is None
    assert runner.run(["projects", "down", "arcane-cli-mcp"], env_id="homelab", confirm=True)["self_target"]


def test_self_env_and_names_configurable(setup):
    runner, _ = setup(self_env="3", self_project="mcp-stack", self_containers=("mcp",))
    assert runner.run(["projects", "down", "arcane-cli-mcp"], confirm=True).get("self_target") is None
    assert runner.run(["projects", "down", "mcp-stack"], env_id="3", confirm=True)["self_target"]
    assert runner.run(["containers", "stop", "mcp"], env_id="3")["self_target"]


def test_disabled_without_self_project(setup):
    runner, _ = setup(self_project=None, self_containers=())
    assert runner.run(["projects", "down", "arcane-cli-mcp"], confirm=True).get("self_target") is None


def test_blocked_and_readonly_take_precedence(setup):
    runner, _ = setup(readonly=True)
    r = runner.run(["containers", "restart", "arcane-cli-mcp"])
    assert r["blocked"] is True and "self_target" not in r


def test_self_target_without_confirm_precedes_needs_confirmation(setup):
    runner, _ = setup()
    r = runner.run(["projects", "destroy", "arcane-cli-mcp"])
    assert r["self_target"] is True and "needs_confirmation" not in r


def test_settings_from_env():
    from arcane_mcp.config import load_settings
    base = {"ARCANE_URL": "http://a:3552", "ARCANE_API_KEY": "k" * 10}
    s = load_settings(base)
    assert s.self_project == "arcane-cli-mcp" and s.self_containers == ("arcane-cli-mcp", "arcane-cli-mcp-tunnel")
    s = load_settings({**base, "SELF_PROJECT": "", "SELF_CONTAINERS": "a, b ,", "SELF_ENV": "2"})
    assert s.self_project is None and s.self_containers == ("a", "b") and s.self_env == "2"
