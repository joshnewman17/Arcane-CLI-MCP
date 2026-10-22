"""JSON-lines audit log and secret redaction."""

from __future__ import annotations

import json
import logging
import re
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

REDACTED = "[REDACTED]"

# Patterns that look like credentials in free text, even when we don't know the exact value.
# The value may not start with `{` or `[`, so `"apiKey": {...}` in JSON-ish text is left alone.
_PATTERNS = [
    re.compile(r"(?i)(x-api-key\s*[:=]\s*)(?![{\[])([^\s,;\"']+)"),
    re.compile(r"(?i)(authorization\s*[:=]\s*(?:bearer\s+)?)(?![{\[])([^\s,;\"']+)"),
    re.compile(r"(?i)(\"?api[_-]?key\"?\s*[:=]\s*\"?)(?![{\[])([^\s,;\"']+)"),
    re.compile(r"(?i)(\"?(?:access|refresh|jwt)[_-]?token\"?\s*[:=]\s*\"?)(?![{\[])([^\s,;\"']+)"),
]

# Object keys whose string values are credentials.
_SECRET_KEYS = re.compile(
    r"(?i)^(x-)?(api[_-]?key|(access|refresh|jwt|auth|tunnel|bearer)?[_-]?token|password|passwd|"
    r"secret|client[_-]?secret|private[_-]?key)$"
)


class Redactor:
    def __init__(self, secrets: list[str] | None = None) -> None:
        self._secrets = sorted({s for s in (secrets or []) if s and len(s) >= 4}, key=len, reverse=True)

    def text(self, value: str) -> str:
        """Redact free text. Do not use on raw JSON that will be parsed afterwards: use ``obj``."""
        if not value:
            return value
        for s in self._secrets:
            value = value.replace(s, REDACTED)
        for pat in _PATTERNS:
            value = pat.sub(lambda m: m.group(1) + REDACTED, value)
        return value

    def obj(self, value: Any) -> Any:
        """Recursively redact parsed JSON: secret-named keys, plus credentials inside any string."""
        if isinstance(value, str):
            return self.text(value)
        if isinstance(value, list):
            return [self.obj(v) for v in value]
        if isinstance(value, dict):
            return {
                k: REDACTED if isinstance(v, str) and v and _SECRET_KEYS.match(str(k)) else self.obj(v)
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
