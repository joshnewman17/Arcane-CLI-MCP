"""MCP server: tool definitions, /healthz, and the stdio / Streamable HTTP transports."""

from __future__ import annotations

import argparse
import hmac
import json
import logging
import os
import sys
import threading
import time
from collections.abc import Callable
from typing import Any, TextIO, TypeVar

import anyio.to_thread
from mcp.server.mcpserver import Context, MCPServer
from mcp_types import ToolAnnotations
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from . import __version__
from .access import HEADER as ACCESS_HEADER
from .access import AccessDenied, AccessVerifier
from .api import ApiClient
from .audit import AuditLog, Redactor, current_user
from .cli import CliRunner
from .compose_edit import ComposeEditor
from .config import ConfigError, Settings, load_settings, write_cli_config

log = logging.getLogger("arcane_mcp")

HEALTH_CACHE_S = 60
# Set by AuthMiddleware after the Access JWT is verified; any client-supplied copy is stripped first.
USER_HEADER = "x-arcane-cli-mcp-user"
T = TypeVar("T")

INSTRUCTIONS = """\
Manage a Docker homelab through Arcane (https://getarcane.app) via the official arcane-cli.

Workflow:
- Call arcane_environments first when more than one environment may exist, and pass env_id explicitly.
- Use arcane_help to discover subcommands and flags before guessing; the CLI is young and flags change.
- Destructive commands return needs_confirmation=true. That means STOP and ask the user to approve
  that exact command. Only after a clear yes, call again with confirm=true. Never set confirm=true
  on your own initiative.
- Some commands are blocked (auth, users/roles, self-update, Arcane upgrades, backup restore,
  generate). Tell the user to do those in the Arcane web UI.
- To change a project's compose file use arcane_project_compose (read it first, then write the full
  file; writes return a diff and need the user's confirmation). Project .env files hold secrets and
  are only edited in the Arcane UI.
"""

RUN_DESCRIPTION = """\
Run an arcane-cli command against the Arcane instance and return its JSON output.

`args` is the command and its arguments WITHOUT the binary name. The server always adds `--json`,
`--env <env_id>` and, only when confirm=true, `--yes`. Any `--yes`/`-y`/`--force`/`--json`/`--output`
you pass is stripped. Use `env_id` instead of `--env`. Flags that read local files (`--file`,
`--env-file`, ...) are rejected.

Result: {ok, exit_code, data, stderr_tail, command}. List commands return {data, pagination};
use --limit/--start or filters when output is truncated (`--all` cannot be combined with --limit).
With compact=true (default), list commands for containers, projects, images, volumes, networks,
activities and vulnerabilities return one short summary per item (name, image, state, health,
project, ports, hasUpdate, ...) and the result has compact=true. Pass compact=false for the full
objects, or use the matching `get` command for one item.
Streaming commands (projects up/redeploy/pull/build, images pull/build, containers update) can take
up to 30 minutes and return an array of progress frames when done.

If the result has needs_confirmation=true, NOTHING was changed: show the user the command and ask.
Retry with confirm=true only after they approve. Blocked commands fail even with confirm=true.

Examples:
- {"args": ["containers", "list", "--all"]}
- {"args": ["containers", "updates"], "env_id": "0"}
- {"args": ["projects", "redeploy", "immich"], "env_id": "0"}
- {"args": ["projects", "destroy", "old-stack", "--remove-files=false"], "confirm": true}
  (only after the user explicitly approved this exact command)
- {"args": ["activities", "list", "--status", "failed", "--limit", "10"]}
"""

HELP_DESCRIPTION = """\
Show `arcane-cli <command...> --help`: the subcommands, positional arguments and flags for a command.
Use it before arcane_run whenever you are unsure of a command or flag. The CLI is in early development
and flags get renamed, so check rather than guess.

Examples:
- {"command": []}                                   (top-level command groups)
- {"command": ["projects"]}                         (project subcommands)
- {"command": ["images", "vulnerabilities", "ignore"]}
"""

API_DESCRIPTION = """\
Read-only escape hatch: GET a path on the Arcane REST API and return the JSON. Use it only for data
that arcane-cli does not expose. Every request carries the server's API key; you never need to send
one. Only GET is supported, and `path` must start with /api/ (no full URLs, no '..').

The OpenAPI 3.1 spec is at /api/openapi.json. Fetch it, with care because it is large, to find paths.
Environment-scoped paths look like /api/environments/{id}/projects.

Examples:
- {"path": "/api/environments"}
- {"path": "/api/environments/0/projects", "query": {"limit": 5}}
- {"path": "/api/openapi.json"}
"""

COMPOSE_DESCRIPTION = """\
Read or replace a project's compose file (docker-compose YAML).

- Read: pass only `project`. Returns the current compose file (values that look like secrets are
  hidden as [REDACTED]). The project's .env is never returned: it holds secrets and is edited in the
  Arcane UI only. Reference its values from compose as ${VAR}.
- Write: pass `project` and `compose` (the COMPLETE new file, not a fragment). Without confirm=true
  nothing changes: the result has needs_confirmation=true and a unified diff. Show the user the diff,
  and only after they approve it, call again with the same compose and confirm=true.
- Writing does not redeploy. Afterwards, with the user's OK, run arcane_run ['projects', 'redeploy', <project>].
- Content containing [REDACTED] is refused, so a hidden value is never written back over the real one.

Examples:
- {"project": "immich"}                                   (read)
- {"project": "immich", "compose": "services:\n  ...", "env_id": "0"}   (returns a diff to approve)
- {"project": "immich", "compose": "services:\n  ...", "confirm": true}  (after the user approved)
"""

ENV_DESCRIPTION = """\
List Arcane environments (Docker hosts) as a small payload of {id, name, status}, plus the server's
default env_id. Call this first and pass the chosen id as `env_id` to arcane_run.

Example: {}
"""


class HealthCache:
    def __init__(self, runner: CliRunner, ttl: float = HEALTH_CACHE_S) -> None:
        self._runner = runner
        self._ttl = ttl
        self._lock = threading.Lock()
        self._at = 0.0
        self._value: dict[str, Any] | None = None

    def get(self) -> dict[str, Any]:
        with self._lock:
            if self._value is None or time.monotonic() - self._at > self._ttl:
                self._value = self._runner.doctor()
                self._at = time.monotonic()
            return self._value


def build_server(settings: Settings, runner: CliRunner | None = None, api: ApiClient | None = None,
                 audit_stream: TextIO | None = None) -> MCPServer:
    redactor = Redactor(settings.secrets())
    audit = AuditLog(settings.audit_log_path, redactor, audit_stream)
    runner = runner or CliRunner(settings, redactor, audit)
    api = api or ApiClient(settings, redactor, audit)
    health = HealthCache(runner)
    compose_editor = ComposeEditor(runner, api, redactor, audit)

    mcp = MCPServer(name="arcane-cli-mcp", version=__version__, instructions=INSTRUCTIONS)

    def as_caller(ctx: Context | None, fn: Callable[[], T]) -> T:
        """Run ``fn`` with the verified caller (if any) attached to its audit records."""
        headers = None
        try:
            headers = ctx.headers if ctx is not None else None
        except ValueError:  # no request context (e.g. direct calls in tests)
            pass
        token = current_user.set((headers or {}).get(USER_HEADER) or None)
        try:
            return fn()
        finally:
            current_user.reset(token)

    @mcp.tool(
        name="arcane_run",
        description=RUN_DESCRIPTION,
        annotations=ToolAnnotations(title="Run arcane-cli", destructive_hint=True, open_world_hint=False),
    )
    def arcane_run(args: list[str], env_id: str | None = None, confirm: bool = False,
                   compact: bool = True, ctx: Context | None = None) -> dict[str, Any]:
        return as_caller(ctx, lambda: runner.run(args, env_id=env_id, confirm=confirm, compact=compact))

    @mcp.tool(
        name="arcane_help",
        description=HELP_DESCRIPTION,
        annotations=ToolAnnotations(title="arcane-cli help", read_only_hint=True, open_world_hint=False),
    )
    def arcane_help(command: list[str] | None = None, ctx: Context | None = None) -> dict[str, Any]:
        return as_caller(ctx, lambda: runner.help(command or []))

    @mcp.tool(
        name="arcane_api_get",
        description=API_DESCRIPTION,
        annotations=ToolAnnotations(title="Arcane API (GET)", read_only_hint=True, open_world_hint=False),
    )
    def arcane_api_get(path: str, query: dict[str, Any] | None = None,
                       ctx: Context | None = None) -> dict[str, Any]:
        return as_caller(ctx, lambda: api.get(path, query))

    @mcp.tool(
        name="arcane_project_compose",
        description=COMPOSE_DESCRIPTION,
        annotations=ToolAnnotations(title="Read or replace a project's compose file", destructive_hint=True,
                                    open_world_hint=False),
    )
    def arcane_project_compose(project: str, compose: str | None = None, env_id: str | None = None,
                               confirm: bool = False, ctx: Context | None = None) -> dict[str, Any]:
        if compose is None:
            return as_caller(ctx, lambda: compose_editor.read(project, env_id))
        return as_caller(ctx, lambda: compose_editor.write(project, compose, env_id, confirm))

    @mcp.tool(
        name="arcane_environments",
        description=ENV_DESCRIPTION,
        annotations=ToolAnnotations(title="List environments", read_only_hint=True, open_world_hint=False),
    )
    def arcane_environments(ctx: Context | None = None) -> dict[str, Any]:
        return as_caller(ctx, runner.environments)

    @mcp.custom_route("/healthz", methods=["GET"], include_in_schema=False)
    async def healthz(request: Request) -> Response:
        result = await anyio.to_thread.run_sync(health.get)
        return JSONResponse(
            {"status": "ok" if result["ok"] else "unhealthy", "version": __version__,
             "readonly": settings.readonly, **result},
            status_code=200 if result["ok"] else 503,
        )

    return mcp


async def _deny(send: Any, status: int, www_authenticate: bytes | None = None) -> None:
    headers = [(b"content-type", b"application/json")]
    if www_authenticate:
        headers.append((b"www-authenticate", www_authenticate))
    await send({"type": "http.response.start", "status": status, "headers": headers})
    await send({"type": "http.response.body", "body": json.dumps({"error": "unauthorized"}).encode()})


class AuthMiddleware:
    """Authenticate every request except /healthz.

    - Cloudflare Access mode (``verifier`` set): require a valid ``Cf-Access-Jwt-Assertion`` JWT.
      The bearer token is not consulted; Claude's OAuth token is handled by Access.
    - Bearer mode (``token`` set): require ``Authorization: Bearer <MCP_AUTH_TOKEN>``.

    The internal user header is always stripped from the incoming request, and in Access mode
    it is set to the verified email so tools can attribute audit records.
    """

    def __init__(self, app: Any, token: str | None = None, verifier: AccessVerifier | None = None) -> None:
        self.app = app
        self._token = token.encode() if token else None
        self._verifier = verifier

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http" or scope.get("path") == "/healthz":
            await self.app(scope, receive, send)
            return
        user_header = USER_HEADER.encode()
        headers = [(k, v) for k, v in scope.get("headers") or [] if k.lower() != user_header]
        lookup = {k.lower(): v for k, v in headers}

        if self._verifier is not None:
            assertion = lookup.get(ACCESS_HEADER.encode(), b"").decode("latin-1") or None
            try:
                identity = await anyio.to_thread.run_sync(self._verifier.verify, assertion)
            except AccessDenied as exc:
                log.warning("rejected request to %s: %s", scope.get("path"), exc)
                await _deny(send, 401)
                return
            if identity.email:
                headers.append((user_header, identity.email.encode()))
        elif self._token is not None:
            scheme, _, value = lookup.get(b"authorization", b"").partition(b" ")
            if scheme.lower() != b"bearer" or not hmac.compare_digest(value.strip(), self._token):
                await _deny(send, 401, b'Bearer realm="arcane-cli-mcp"')
                return

        await self.app({**scope, "headers": headers}, receive, send)


def http_app(settings: Settings, mcp: MCPServer, path: str = "/mcp",
             verifier: AccessVerifier | None = None) -> Any:
    app = mcp.streamable_http_app(streamable_http_path=path, host=settings.host)
    if verifier is None and settings.access_enabled:
        verifier = AccessVerifier(settings.access_team_domain or "", settings.access_aud or "")
    if verifier is None and not settings.auth_token:
        return app
    return AuthMiddleware(app, token=settings.auth_token, verifier=verifier)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="arcane-cli-mcp", description="MCP server for Arcane via arcane-cli")
    parser.add_argument("--transport", choices=["http", "stdio"], default="http")
    parser.add_argument("--path", default=None, help="HTTP path for the MCP endpoint (default: $MCP_PATH or /mcp)")
    opts = parser.parse_args(argv)

    # stdout carries the stdio protocol, so logs and audit go to stderr there.
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    try:
        settings = load_settings()
    except ConfigError as exc:
        log.error("configuration error: %s", exc)
        return 2
    write_cli_config(settings)
    if opts.transport == "stdio":
        import anyio

        mcp = build_server(settings, audit_stream=sys.stderr)
        anyio.run(mcp.run_stdio_async)
        return 0

    import uvicorn

    path = opts.path or os.environ.get("MCP_PATH", "/mcp")
    if settings.access_enabled:
        log.info("Cloudflare Access mode: requests need a valid Access JWT (team %s)", settings.access_team_domain)
        if settings.auth_token:
            log.info("MCP_AUTH_TOKEN is ignored in Cloudflare Access mode")
    elif not settings.auth_token:
        log.warning("=" * 72)
        log.warning("MCP_AUTH_TOKEN is not set: anyone who can reach port %s can control Docker", settings.port)
        log.warning("through Arcane. Set MCP_AUTH_TOKEN, or CF_ACCESS_TEAM_DOMAIN + CF_ACCESS_AUD.")
        log.warning("=" * 72)
    log.info("arcane-cli-mcp %s listening on %s:%s%s (readonly=%s, cli=%s)", __version__, settings.host,
             settings.port, "/<path>" if path != "/mcp" else path, settings.readonly, settings.cli_path)
    mcp = build_server(settings)
    uvicorn.run(http_app(settings, mcp, path), host=settings.host, port=settings.port,
                access_log=False, log_level="warning", proxy_headers=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
