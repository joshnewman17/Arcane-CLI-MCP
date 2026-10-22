"""Read-only REST client for the Arcane API (GET only)."""

from __future__ import annotations

import json
import re
import time
from typing import Any
from urllib.parse import unquote

import httpx

from . import compact as compact_mod
from .audit import AuditLog, Redactor
from .cli import fit_output, truncate_text
from .config import Settings

_SAFE_PATH = re.compile(r"^/api/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*$")


class ApiPathError(ValueError):
    pass


def validate_path(path: str) -> str:
    if not isinstance(path, str) or not path:
        raise ApiPathError("path is required, e.g. /api/environments")
    if "://" in path or path.startswith("//"):
        raise ApiPathError("path must be relative to the Arcane instance (start with /api/), not a URL")
    if "?" in path or "#" in path:
        raise ApiPathError("put query parameters in `query`, not in `path`")
    decoded = path
    for _ in range(3):  # catch %2e%2e and double-encoding
        decoded = unquote(decoded)
    if "\\" in decoded or any(ord(c) < 0x20 for c in decoded):
        raise ApiPathError("path contains invalid characters")
    if any(seg in {"..", "."} for seg in decoded.split("/")):
        raise ApiPathError("path may not contain '.' or '..' segments")
    if not (path == "/api/" or _SAFE_PATH.match(path)) or not decoded.startswith("/api/"):
        raise ApiPathError("path must start with /api/")
    return path


def validate_query(query: dict[str, Any] | None) -> dict[str, str | list[str]]:
    if query is None:
        return {}
    if not isinstance(query, dict):
        raise ApiPathError("query must be an object of string keys to values")
    out: dict[str, str | list[str]] = {}
    for k, v in query.items():
        if not isinstance(k, str) or not k:
            raise ApiPathError("query keys must be non-empty strings")
        if isinstance(v, list):
            out[k] = [str(x) for x in v]
        elif isinstance(v, bool):
            out[k] = "true" if v else "false"
        elif v is None:
            continue
        else:
            out[k] = str(v)
    return out


class ApiClient:
    def __init__(self, settings: Settings, redactor: Redactor, audit: AuditLog,
                 transport: httpx.BaseTransport | None = None) -> None:
        self.settings = settings
        self.redactor = redactor
        self.audit = audit
        self._client = httpx.Client(
            base_url=settings.arcane_url,
            headers={"X-Api-Key": settings.arcane_api_key, "Accept": "application/json"},
            timeout=httpx.Timeout(settings.default_timeout_s, connect=10),
            verify=settings.verify_tls,
            follow_redirects=False,
            transport=transport,
        )

    def get(self, path: str, query: dict[str, Any] | None = None, fields: list[str] | None = None,
            compact: bool = True) -> dict[str, Any]:
        started = time.monotonic()
        try:
            validate_path(path)
            params = validate_query(query)
            if fields is not None and (not isinstance(fields, list) or not all(
                    isinstance(f, str) and f.strip(".") for f in fields)):
                raise ApiPathError("fields must be a list of field names or dotted paths, e.g. ['id', 'state.status']")
        except ApiPathError as exc:
            self.audit.record(tool="arcane_api_get", path=path, outcome="rejected", reason=str(exc))
            return {"ok": False, "error": str(exc)}

        try:
            resp = self._client.get(path, params=params)
        except httpx.HTTPError as exc:
            msg = self.redactor.text(f"{type(exc).__name__}: {exc}")
            self.audit.record(tool="arcane_api_get", path=path, query=params, outcome="error", reason=msg,
                              duration_ms=int((time.monotonic() - started) * 1000))
            return {"ok": False, "error": f"Request failed: {msg}"}

        duration_ms = int((time.monotonic() - started) * 1000)
        self.audit.record(tool="arcane_api_get", path=path, query=params, status=resp.status_code,
                          duration_ms=duration_ms)
        result: dict[str, Any] = {"ok": resp.is_success, "status": resp.status_code}
        if 300 <= resp.status_code < 400:
            result["error"] = "Redirects are not followed."
            return result
        try:
            # Parse first, then redact the structure: regex redaction on raw JSON can break it.
            parsed = compact_mod.cleanup(self.redactor.obj(json.loads(resp.text)))
            if fields:
                parsed = compact_mod.pick_fields(parsed, fields)
            elif compact:
                parsed, compacted = compact_mod.compact_api(path, parsed)
                if compacted:
                    result["compact"] = True
            data, note = fit_output(parsed, self.settings.max_output_chars)
            result["data"] = data
        except json.JSONDecodeError:
            result["raw"], note = truncate_text(self.redactor.text(resp.text), self.settings.max_output_chars)
        if note:
            result["truncated"] = True
            result["truncation_note"] = note
        return result

    def close(self) -> None:
        self._client.close()
