"""JSON-lines audit log and secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from contextvars import ContextVar
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

REDACTED = "[REDACTED]"

# The authenticated caller (Cloudflare Access email) for the tool call in progress, if any.
current_user: ContextVar[str | None] = ContextVar("current_user", default=None)

# Patterns that look like credentials in free text, even when we don't know the exact value.
# The value may not start with `{`, `[`, `$`, `?` or `-`, so `"apiKey": {...}` in JSON-ish text and
# compose placeholders like `ARCANE_API_KEY: ${ARCANE_API_KEY:?required}` are left alone.
_PATTERNS = [
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)(?![{\[$?-])([^\s,;\"']+)"),
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:(?:bearer|basic|token)\s+)?)(?![{\[$?-])([^\s,;\"']+)"),
    # A bare `Bearer <token>` / `Basic <b64>`; the lookahead keeps prose like "Basic authentication".
    re.compile(r"(\b(?:Bearer|Basic|bearer|basic)\s+)"
               r"(?=[A-Za-z0-9._~+/=-]*(?:[0-9+/=]|[A-Z][a-z]|[a-z][A-Z]))([A-Za-z0-9._~+/=-]{8,})"),
    re.compile(r"(?i)(\"?api[_-]?key\"?\s*[:=]\s*\"?)(?![{\[$?-])([^\s,;\"']+)"),
    re.compile(r"(?i)(\"?(?:access|refresh|jwt)[_-]?token\"?\s*[:=]\s*\"?)(?![{\[$?-])([^\s,;\"']+)"),
    # .env-style lines (and compose `environment:` mappings, and `KEY=value` items of env arrays)
    # whose key names a credential: `TUNNEL_TOKEN=eyJ...`, `DB_PASSWORD: ...`, `SENTRY_DSN=...`.
    re.compile(
        r"(?m)^(\s*(?:-\s*)?[\"']?(?:export\s+)?"
        r"(?:[A-Z0-9_]*(?:TOKEN|KEY|SECRET|PASSWORD|PASSWD|CREDENTIAL|COOKIE)[A-Z0-9_]*|(?:[A-Z0-9_]*_)?(?:PASS|PWD|DSN))"
        r"(?:\s*=\s*|:\s+))(?![$\s|>])(.+?)([\"']?)$"
    ),
    # Userinfo in any URL: `postgresql://user:pw@db`, `redis://:pw@cache`, `mongodb+srv://u:p@x`.
    re.compile(r"(?i)(\b[a-z][a-z0-9+.-]*://[^\s:/@\"']*:)(?!\$\{|\[REDACTED\])([^\s@/\"']+)(?=@)"),
    # Credential-like query parameters: `?token=...`, `&sig=...`.
    re.compile(
        r"(?i)([?&](?:password|passwd|pwd|pass|token|access_token|refresh_token|id_token|api[_-]?key|key|"
        r"secret|client_secret|sig|signature|auth)=)(?![$\[])([^&\s\"'#]+)"
    ),
]

# Credentials recognisable by shape alone; the whole match is replaced.
_SHAPES = [
    re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?(?:-----END [A-Z0-9 ]*PRIVATE KEY-----|$)", re.S),
    re.compile(r"\beyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*"),  # JWT
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[opsur]_[A-Za-z0-9]{20,}"),
    re.compile(r"\bsk-(?:[a-z]+-)?[A-Za-z0-9_-]{20,}"),  # OpenAI / Anthropic-style keys
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),  # Slack
    re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),  # AWS access key id
    re.compile(r"\bglpat-[A-Za-z0-9_-]{20,}"),  # GitLab
    # htpasswd hashes (traefik basicauth labels etc.), with compose's `$$` escaping.
    re.compile(r"\$\$?(?:apr1|2[abxy]|5|6|y)\$\$?[^\s,\"']+"),
    re.compile(r"\{SHA\}[A-Za-z0-9+/=]{20,}"),
]

# Object keys whose string values are credentials. `envContent` is a whole project .env file
# (Arcane returns it from the project compose endpoint), so it is withheld entirely.
_SECRET_KEYS = re.compile(
    r"(?i)^(x-)?(api[_-]?key|(access|refresh|jwt|auth|tunnel|bearer)?[_-]?token|password|passwd|"
    r"secret|client[_-]?secret|private[_-]?key|env[_-]?content)$"
)
# Dotted keys (container labels) that carry credentials, e.g. traefik's basicauth users.
_SECRET_LABELS = re.compile(r"(?i)(?:(?:basic|digest)auth\.users|[._-](?:password|passwd|secret|token))$")


def _is_secret_key(key: str) -> bool:
    return bool(_SECRET_KEYS.match(key) or _SECRET_LABELS.search(key))


def _keep_prefix(m: re.Match[str]) -> str:
    """Replace the credential (group 2), keeping the key before it and any closing quote (group 3)."""
    if m.group(2) == REDACTED:
        return m.group(0)
    return m.group(1) + REDACTED + (m.group(3) or "" if m.re.groups >= 3 else "")


class Redactor:
    def __init__(self, secrets: list[str] | None = None) -> None:
        self._secrets = sorted({s for s in (secrets or []) if s and len(s) >= 4}, key=len, reverse=True)

    def text(self, value: str) -> str:
        """Redact free text. Do not use on raw JSON that will be parsed afterwards: use ``obj``."""
        if not value:
            return value
        for s in self._secrets:
            value = value.replace(s, REDACTED)
        for pat in _SHAPES:
            value = pat.sub(REDACTED, value)
        for pat in _PATTERNS:
            value = pat.sub(_keep_prefix, value)
        return value

    def obj(self, value: Any) -> Any:
        """Recursively redact parsed JSON: secret-named keys, plus credentials inside any string."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {
                k: REDACTED if isinstance(v, str) and v and _is_secret_key(str(k)) else self.obj(v)
                for k, v in value.items()
            }
        return value


class AuditLog:
    def __init__(self, path: Path | None, redactor: Redactor, stream: TextIO | None = None) -> None:
        self._path = path
        # stdout by default (container logs); stderr under the stdio transport.
        self._stream = stream if stream is not None else sys.stdout
        self._redactor = redactor
        self._lock = threading.Lock()
        self._log = logging.getLogger("arcane_mcp.audit")
        if path is not None:
            try:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.touch(exist_ok=True)
            except OSError as exc:
                logging.getLogger("arcane_mcp").warning(
                    "audit log %s is not writable (%s); logging to stdout only", path, exc.strerror
                )
                self._path = None

    def record(self, **fields: Any) -> dict[str, Any]:
        entry = {"ts": datetime.now(timezone.utc).isoformat(timespec="milliseconds"), **fields}
        if current_user.get() and "user" not in entry:
            entry["user"] = current_user.get()
        entry = self._redactor.obj(entry)
        line = json.dumps(entry, default=str, separators=(",", ":"))
        with self._lock:
            print(line, file=self._stream, flush=True)
            if self._path is not None:
                try:
                    with self._path.open("a", encoding="utf-8") as fh:
                        fh.write(line + "\n")
                except OSError as exc:
                    self._log.warning("failed to write audit log: %s", exc.strerror)
        return entry
