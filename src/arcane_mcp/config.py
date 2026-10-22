"""Environment-variable configuration for the server.

The arcane-cli itself has no documented environment variables (as of v2.17.x).
It reads a YAML config file (default ``~/.config/arcanecli.yml``) with keys such
as ``server_url``, ``api_key`` and ``default_environment``, and accepts
``--config <path>`` to point at a different file. So at startup we write a
private config file from ARCANE_URL / ARCANE_API_KEY and pass ``--config`` on
every invocation. See https://getarcane.app/docs/reference/cli/config
"""

from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

import yaml


class ConfigError(ValueError):
    pass


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value.strip() == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, value: str | None, default: int) -> int:
    if value is None or value.strip() == "":
        return default
    try:
        parsed = int(value)
    except ValueError as exc:
        raise ConfigError(f"{name} must be an integer, got {value!r}") from exc
    if parsed <= 0:
        raise ConfigError(f"{name} must be positive")
    return parsed


@dataclass(frozen=True)
class Settings:
    arcane_url: str
    arcane_api_key: str = field(repr=False)
    default_env: str = "0"
    host: str = "0.0.0.0"
    port: int = 8080
    auth_token: str | None = field(default=None, repr=False)
    readonly: bool = False
    max_output_chars: int = 40000
    default_timeout_s: int = 120
    long_timeout_s: int = 1800
    cli_path: str = "arcane-cli"
    state_dir: Path = Path(tempfile.gettempdir()) / "arcane-cli-mcp"
    audit_log_path: Path | None = Path("/data/audit.log")
    verify_tls: bool = True
    # Cloudflare Access: when both are set, every MCP request must carry a valid Access JWT.
    access_team_domain: str | None = None
    access_aud: str | None = None
    # The MCP server's own deployment, so mutating commands can't restart it mid-call.
    self_project: str | None = "arcane-cli-mcp"
    self_containers: tuple[str, ...] = ("arcane-cli-mcp", "arcane-cli-mcp-tunnel")
    self_env: str | None = None  # defaults to default_env

    @property
    def access_enabled(self) -> bool:
        return bool(self.access_team_domain and self.access_aud)

    @property
    def cli_config_path(self) -> Path:
        return self.state_dir / "arcanecli.yml"

    @property
    def cli_home(self) -> Path:
        # HOME for the CLI subprocess, so auth.json etc. land somewhere private.
        return self.state_dir / "home"

    def secrets(self) -> list[str]:
        """Values that must never appear in logs or tool output."""
        return [s for s in (self.arcane_api_key, self.auth_token) if s]


def load_settings(env: dict[str, str] | None = None) -> Settings:
    env = dict(os.environ if env is None else env)

    url = env.get("ARCANE_URL", "").strip().rstrip("/")
    key = env.get("ARCANE_API_KEY", "").strip()
    key_file = env.get("ARCANE_API_KEY_FILE", "").strip()
    if not key and key_file:
        try:
            key = Path(key_file).read_text().strip()
        except OSError as exc:
            raise ConfigError(f"cannot read ARCANE_API_KEY_FILE: {exc.strerror}") from exc
    if not url:
        raise ConfigError("ARCANE_URL is required")
    if not url.startswith(("http://", "https://")):
        raise ConfigError("ARCANE_URL must start with http:// or https://")
    if not key:
        raise ConfigError("ARCANE_API_KEY (or ARCANE_API_KEY_FILE) is required")
    url_path = urlsplit(url).path
    if url_path.rstrip("/").endswith(("/dashboard", "/login", "/settings", "/environments")):
        # A URL copied from the browser points at a UI page; the API lives at <base>/api.
        raise ConfigError(
            f"ARCANE_URL ends in a web UI path ({url_path!r}); use the base URL of the instance instead"
        )
    if url_path:
        logging.getLogger("arcane_mcp").warning(
            "ARCANE_URL has a path (%s); arcane-cli will call %s/api/... - make sure that is right", url_path, url
        )

    team = env.get("CF_ACCESS_TEAM_DOMAIN", "").strip() or None
    aud = env.get("CF_ACCESS_AUD", "").strip() or None
    if bool(team) != bool(aud):
        raise ConfigError("set both CF_ACCESS_TEAM_DOMAIN and CF_ACCESS_AUD, or neither")

    audit = env.get("AUDIT_LOG_PATH", "/data/audit.log").strip()
    cli_path = env.get("ARCANE_CLI_PATH", "").strip() or shutil.which("arcane-cli") or "arcane-cli"

    return Settings(
        arcane_url=url,
        arcane_api_key=key,
        default_env=env.get("ARCANE_DEFAULT_ENV", "0").strip() or "0",
        host=env.get("MCP_HOST", "0.0.0.0").strip() or "0.0.0.0",
        port=_int("MCP_PORT", env.get("MCP_PORT"), 8080),
        auth_token=env.get("MCP_AUTH_TOKEN", "").strip() or None,
        readonly=_bool(env.get("ARCANE_MCP_READONLY")),
        max_output_chars=_int("MAX_OUTPUT_CHARS", env.get("MAX_OUTPUT_CHARS"), 40000),
        default_timeout_s=_int("DEFAULT_TIMEOUT_S", env.get("DEFAULT_TIMEOUT_S"), 120),
        long_timeout_s=_int("LONG_TIMEOUT_S", env.get("LONG_TIMEOUT_S"), 1800),
        cli_path=cli_path,
        state_dir=Path(env.get("ARCANE_MCP_STATE_DIR", "").strip() or Path(tempfile.gettempdir()) / "arcane-cli-mcp"),
        audit_log_path=Path(audit) if audit else None,
        verify_tls=_bool(env.get("ARCANE_VERIFY_TLS"), default=True),
        access_team_domain=team,
        access_aud=aud,
        self_project=env.get("SELF_PROJECT", "arcane-cli-mcp").strip() or None,
        self_containers=tuple(
            c.strip() for c in env.get("SELF_CONTAINERS", "arcane-cli-mcp,arcane-cli-mcp-tunnel").split(",") if c.strip()
        ),
        self_env=env.get("SELF_ENV", "").strip() or None,
    )


def write_cli_config(settings: Settings) -> Path:
    """Write the arcane-cli YAML config (0600) and return its path."""
    settings.state_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
    settings.cli_home.mkdir(mode=0o700, parents=True, exist_ok=True)
    os.chmod(settings.state_dir, 0o700)
    path = settings.cli_config_path
    body = yaml.safe_dump(
        {
            "server_url": settings.arcane_url,
            "api_key": settings.arcane_api_key,
            "default_environment": settings.default_env,
            "log_level": "warn",
        },
        sort_keys=False,
    )
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(body)
    os.chmod(path, 0o600)
    return path
