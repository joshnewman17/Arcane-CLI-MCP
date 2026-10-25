"""End-to-end: real MCP client -> server -> subprocess -> fake arcane-cli script."""

import json
import os
import sys
from pathlib import Path

import httpx
import pytest
from mcp import Client

from arcane_mcp.config import write_cli_config
from arcane_mcp.server import build_server, http_app

from .conftest import API_KEY, FAKE_CLI, MCP_TOKEN, make_settings

pytestmark = pytest.mark.anyio


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def e2e(tmp_path, audit_stream):
    wrapper = tmp_path / "arcane-cli"
    wrapper.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{FAKE_CLI}' \"$@\"\n")
    wrapper.chmod(0o755)
    settings = make_settings(tmp_path, cli_path=str(wrapper), max_output_chars=4000)
    write_cli_config(settings)
    server = build_server(settings, audit_stream=audit_stream)
    return settings, server


def calls(settings) -> list[dict]:
    path = Path(settings.cli_home) / "calls.jsonl"
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


async def call(server, name, args=None):
    async with Client(server) as c:
        r = await c.call_tool(name, args or {})
        return r.structured_content


async def test_logs_tool_can_be_disabled(tmp_path):
    server = build_server(make_settings(tmp_path, logs_enabled=False))
    async with Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
    assert "arcane_logs" not in names and "arcane_run" in names


async def test_lists_tools_with_examples(e2e):
    _, server = e2e
    async with Client(server) as c:
        tools = {t.name: t for t in (await c.list_tools()).tools}
    assert set(tools) == {"arcane_run", "arcane_cli_help", "arcane_api_get", "arcane_environments",
                          "arcane_project_compose", "arcane_logs", "arcane_playbook", "arcane_docs"}
    assert set(tools["arcane_project_compose"].input_schema["properties"]) == {"project", "compose", "env_id", "confirm"}
    for t in tools.values():
        assert "Example" in t.description or t.name == "arcane_playbook"
    assert "openapi.json" in tools["arcane_api_get"].description
    assert "needs_confirmation" in tools["arcane_run"].description


async def test_playbook_tool_and_prompts(e2e):
    _, server = e2e
    async with Client(server) as c:
        listing = (await c.call_tool("arcane_playbook", {})).structured_content
        names = {p["name"] for p in listing["playbooks"]}
        assert "arcane-safe-updates" in names and len(names) == 7
        one = (await c.call_tool("arcane_playbook", {"name": "arcane-github-deploy"})).structured_content
        assert "needs_confirmation" in (await c.call_tool("arcane_playbook", {"name": "arcane-safe-updates"})).structured_content["playbook"]
        assert not one["playbook"].startswith("---") and "templates/compose.yaml" in one["playbook"]
        bad = (await c.call_tool("arcane_playbook", {"name": "nope"})).structured_content
        assert bad["ok"] is False and bad["playbooks"]
        prompts = {p.name for p in (await c.list_prompts()).prompts}
        assert prompts == names
        got = await c.get_prompt("arcane-gitops")
        assert "GitOps" in got.messages[0].content.text


async def test_environments(e2e):
    settings, server = e2e
    r = await call(server, "arcane_environments")
    assert r["environments"] == [{"id": "0", "name": "local", "status": "online"},
                                 {"id": "2", "name": "nas", "status": "offline"}]
    argv = calls(settings)[-1]["argv"]
    assert argv[argv.index("--config") + 1] == str(settings.cli_config_path)


async def test_list_containers_compact_and_truncated(e2e):
    _, server = e2e
    full = await call(server, "arcane_run", {"args": ["containers", "list", "--all"], "compact": False})
    assert full["ok"] and full["truncated"] and full["data"]["data"][0]["names"] == ["/svc-0"]
    r = await call(server, "arcane_run", {"args": ["containers", "list", "--all"]})
    assert r["ok"] and r["compact"] and r["data"]["data"][0] == {"id": "c0", "name": "svc-0", "state": "running"}
    assert len(r["data"]["data"]) > len(full["data"]["data"])


async def test_destroy_needs_confirmation_and_changes_nothing(e2e):
    settings, server = e2e
    r = await call(server, "arcane_run", {"args": ["projects", "destroy", "foo"]})
    assert r["needs_confirmation"] is True and r["ok"] is False
    assert calls(settings) == []  # never reached the CLI
    r = await call(server, "arcane_run", {"args": ["projects", "destroy", "foo"], "confirm": True})
    assert r["ok"] is True
    assert calls(settings)[-1]["argv"][-1] == "--yes"


async def test_blocked_with_confirm(e2e):
    settings, server = e2e
    for args in (["auth", "login"], ["self-update", "run"], ["system", "upgrade"], ["admin", "users", "list"]):
        r = await call(server, "arcane_run", {"args": args, "confirm": True})
        assert r["blocked"] is True and r["ok"] is False
    assert calls(settings) == []


async def test_redeploy_returns_frames(e2e):
    _, server = e2e
    r = await call(server, "arcane_run", {"args": ["projects", "redeploy", "stack"]})
    assert r["ok"] and r["data"][-1] == {"status": "done"}


async def test_help(e2e):
    _, server = e2e
    r = await call(server, "arcane_cli_help", {"command": ["projects", "destroy"]})
    assert r["ok"] and "USAGE" in r["help"] and "\x1b" not in r["help"]


async def test_cli_child_never_sees_secrets(e2e, monkeypatch):
    monkeypatch.setenv("ARCANE_API_KEY", API_KEY)
    monkeypatch.setenv("MCP_AUTH_TOKEN", MCP_TOKEN)
    settings, server = e2e
    await call(server, "arcane_run", {"args": ["containers", "get", "x"]})
    blob = json.dumps(calls(settings))
    assert API_KEY not in blob and MCP_TOKEN not in blob


async def test_secrets_never_in_tool_output_or_logs(e2e, audit_stream):
    settings, server = e2e
    # The fake prints "X-Api-Key: abc123secret"; the server key itself goes through --config.
    r = await call(server, "arcane_run", {"args": ["leak", "test"]})
    assert "abc123secret" not in json.dumps(r)
    logs = audit_stream.getvalue() + settings.audit_log_path.read_text()
    assert API_KEY not in logs and MCP_TOKEN not in logs and "abc123secret" not in logs


async def test_readonly_rejects_mutations(tmp_path, audit_stream):
    settings = make_settings(tmp_path, readonly=True, cli_path="/nonexistent")
    write_cli_config(settings)
    server = build_server(settings, audit_stream=audit_stream)
    for args in (["containers", "update", "x"], ["projects", "redeploy", "x"], ["images", "pull", "nginx"],
                 ["projects", "destroy", "x"], ["gitops", "sync", "s"]):
        r = await call(server, "arcane_run", {"args": args, "confirm": True})
        assert r["blocked"] is True and "read-only" in r["error"]


# --- HTTP transport -------------------------------------------------------------------


async def test_healthz_and_bearer_auth(e2e):
    settings, server = e2e
    app = http_app(settings, server)
    inner = app.app  # the Starlette app behind BearerAuthMiddleware; its lifespan starts the session manager
    transport = httpx.ASGITransport(app=app)
    async with inner.router.lifespan_context(inner), \
            httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        h = await client.get("/healthz")
        assert h.status_code == 200 and h.json()["status"] == "ok"

        body = {"jsonrpc": "2.0", "id": 1, "method": "ping"}
        r = await client.post("/mcp", json=body)
        assert r.status_code == 401
        r = await client.post("/mcp", json=body, headers={"Authorization": "Bearer wrong"})
        assert r.status_code == 401
        r = await client.post("/mcp", json=body, headers={"Authorization": f"Bearer {MCP_TOKEN}",
                                                          "Accept": "application/json, text/event-stream"})
        assert r.status_code != 401


async def test_healthz_unhealthy(tmp_path, audit_stream):
    settings = make_settings(tmp_path, cli_path="/nonexistent/arcane-cli")
    write_cli_config(settings)
    app = http_app(settings, build_server(settings, audit_stream=audit_stream))
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test") as client:
        h = await client.get("/healthz")
    assert h.status_code == 503 and h.json()["status"] == "unhealthy"


def test_stdio_entrypoint_smoke(tmp_path):
    """The stdio transport speaks MCP on stdout and keeps audit lines off it."""
    import subprocess

    wrapper = tmp_path / "arcane-cli"
    wrapper.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{FAKE_CLI}' \"$@\"\n")
    wrapper.chmod(0o755)
    env = {**os.environ, "ARCANE_URL": "http://arcane.test", "ARCANE_API_KEY": API_KEY,
           "ARCANE_CLI_PATH": str(wrapper), "ARCANE_MCP_STATE_DIR": str(tmp_path / "s"),
           "AUDIT_LOG_PATH": str(tmp_path / "audit.log")}
    msgs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize",
         "params": {"protocolVersion": "2025-06-18", "capabilities": {},
                    "clientInfo": {"name": "t", "version": "1"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call",
         "params": {"name": "arcane_environments", "arguments": {}}},
    ]
    proc = subprocess.Popen([sys.executable, "-m", "arcane_mcp", "--transport", "stdio"], stdin=subprocess.PIPE,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    try:
        for m in msgs:
            proc.stdin.write(json.dumps(m) + "\n")
        proc.stdin.flush()
        lines = []
        while not any(line.get("id") == 2 for line in lines):  # keep stdin open until the reply arrives
            raw = proc.stdout.readline()
            assert raw, "server closed stdout early"
            lines.append(json.loads(raw))  # every stdout line must be a JSON-RPC message
    finally:
        stdin, proc.stdin = proc.stdin, None
        stdin.close()
        stdout_rest, stderr = proc.communicate(timeout=30)
    assert all(line.get("jsonrpc") == "2.0" for line in lines)
    result = next(line for line in lines if line.get("id") == 2)["result"]
    assert "local" in json.dumps(result)
    assert '"tool":"arcane_run"' in stderr
    assert API_KEY not in json.dumps(lines) + stdout_rest + stderr
