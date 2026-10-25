"""Collect container logs through Arcane's log download endpoint.

Arcane only offers ``GET /api/environments/{env}/containers/{id}/logs/download``, which ignores
``tail``/``since`` and returns the whole log as text (often megabytes). This module streams that
response, keeps only the lines the caller asked for (``since``, ``grep``, last ``tail``), strips ANSI
colour codes (docker's per-line timestamp is kept). Output is redacted, best-effort, and capped; the
tool can be disabled (``LOGS_ENABLED=false``) or kept off chosen containers (``LOGS_EXCLUDE``).
"""

from __future__ import annotations

import re
import time
from collections import deque
from datetime import datetime, timedelta, timezone
from typing import Any

import httpx

from .api import ApiClient, ApiPathError
from .audit import REDACTED, AuditLog, Redactor
from .cli import CliRunner, strip_ansi

DEFAULT_TAIL = 100
MAX_TAIL = 2000
MAX_LINE_CHARS = 2000
MAX_SCAN_BYTES = 64 * 1024 * 1024
MAX_PROJECT_CONTAINERS = 12
MAX_GREP_CHARS = 200
_ID = re.compile(r"^[0-9a-f]{12,64}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_REL = re.compile(r"^(\d+)\s*([smhdw])$")
_TS = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?\s")
# Credential-looking `name=value` / `"name":"value"` anywhere in a line (the shared redactor's
# env-style rule only matches at the start of a line, and log lines start with a timestamp).
_INLINE_SECRET = re.compile(
    r"(?i)(\b[\w.-]*(?:token|key|secret|passw(?:or)?d|pwd|credential|cookie|authorization)[\w.-]*[\"']?\s*[=:]\s*)"
    r"(?!\[REDACTED\])(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_UNITS = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}


class LogError(ValueError):
    pass


def parse_since(value: str | None, now: datetime | None = None) -> datetime | None:
    """Accept a relative age ("30m", "2h", "1d") or an ISO-8601 timestamp (UTC if no zone)."""
    if value is None or value == "":
        return None
    now = now or datetime.now(timezone.utc)
    m = _REL.match(value.strip().lower())
    if m:
        return now - timedelta(**{_UNITS[m.group(2)]: int(m.group(1))})
    try:
        parsed = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        raise LogError("since must be a relative age like '30m', '2h', '1d' or an ISO-8601 timestamp") from None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def line_time(line: str) -> datetime | None:
    m = _TS.match(line)
    if not m:
        return None
    try:
        # fromisoformat only takes up to 6 fractional digits; docker emits 9.
        frac = (m.group(2) or "0")[:6].ljust(6, "0")
        base = datetime.fromisoformat(f"{m.group(1)}.{frac}{(m.group(3) or 'Z').replace('Z', '+00:00')}")
    except ValueError:
        return None
    return base


def redact_logs(redactor: Redactor, lines: list[str]) -> list[str]:
    """Redact the kept lines as one block, so multi-line secrets (PEM keys) are caught whole."""
    text = redactor.text("\n".join(lines))
    text = _INLINE_SECRET.sub(lambda m: m.group(1) + REDACTED, text)
    return text.split("\n") if lines else []


class LogCollector:
    def __init__(self, api: ApiClient, runner: CliRunner, redactor: Redactor, audit: AuditLog) -> None:
        self.api = api
        self.runner = runner
        self.redactor = redactor
        self.audit = audit
        self.max_chars = runner.settings.max_output_chars
        self.exclude = set(runner.settings.logs_exclude)

    # -- container lookup ----------------------------------------------------------------------

    def _containers(self, env: str) -> list[dict[str, Any]]:
        res = self.api.get(f"/api/environments/{env}/containers", {"limit": 500}, compact=False,
                           fields=["id", "names", "name", "state", "labels"])
        if not res.get("ok"):
            raise LogError(f"could not list containers: {res.get('error') or res.get('status')}")
        data = res.get("data")
        items = data.get("data") if isinstance(data, dict) else data
        return [c for c in items or [] if isinstance(c, dict) and c.get("id")]

    @staticmethod
    def _names(c: dict[str, Any]) -> list[str]:
        raw = c.get("names") or [c.get("name")]
        return [n.lstrip("/") for n in raw if isinstance(n, str)]

    def _match(self, containers: list[dict[str, Any]], ref: str) -> dict[str, Any]:
        low = ref.lower()
        for c in containers:
            if c["id"].lower().startswith(low) and _ID.match(low):
                return c
        exact = [c for c in containers if any(n.lower() == low for n in self._names(c))]
        if len(exact) == 1:
            return exact[0]
        partial = exact or [c for c in containers if any(low in n.lower() for n in self._names(c))]
        if len(partial) == 1:
            return partial[0]
        if not partial:
            raise LogError(f"no container matches {ref!r}")
        raise LogError(f"{ref!r} is ambiguous: " + ", ".join(sorted(self._names(c)[0] for c in partial if self._names(c))))

    def _excluded(self, c: dict[str, Any]) -> bool:
        return any(n.lower() in self.exclude for n in self._names(c))

    # -- collection ----------------------------------------------------------------------------

    def _collect(self, env: str, container: dict[str, Any], tail: int, since: datetime | None,
                 pattern: re.Pattern[str] | None) -> dict[str, Any]:
        path = f"/api/environments/{env}/containers/{container['id']}/logs/download"
        keep: deque[str] = deque(maxlen=tail)
        scanned = matched = 0
        truncated_scan = False
        with self.api.stream(path) as resp:
            if not resp.is_success:
                resp.read()
                raise LogError(f"Arcane returned HTTP {resp.status_code} for the container's logs")
            for raw in resp.iter_lines():
                scanned += len(raw) + 1
                if scanned > MAX_SCAN_BYTES:
                    truncated_scan = True
                    break
                line = strip_ansi(raw).rstrip()
                if not line:
                    continue
                if since is not None:
                    at = line_time(line)
                    if at is not None and at < since:
                        continue
                if pattern is not None and not pattern.search(line):
                    continue
                matched += 1
                keep.append(line if len(line) <= MAX_LINE_CHARS else line[:MAX_LINE_CHARS - 1] + "…")
        out: dict[str, Any] = {"container": (self._names(container) or [container["id"][:12]])[0],
                               "id": container["id"][:12], "matched": matched, "returned": len(keep),
                               "lines": redact_logs(self.redactor, list(keep))}
        if truncated_scan:
            out["scan_truncated"] = f"stopped after {MAX_SCAN_BYTES // (1024 * 1024)} MB; use since to narrow"
        return out

    def collect(self, container: str | None = None, project: str | None = None, env_id: str | None = None,
                tail: int = DEFAULT_TAIL, since: str | None = None, grep: str | None = None,
                case_sensitive: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        target = container or project
        try:
            if bool(container) == bool(project):
                raise LogError("pass exactly one of `container` or `project`")
            if not isinstance(target, str) or not (_NAME.match(target) or _ID.match(target.lower())):
                raise LogError("container/project must be a name or id (letters, digits, '.', '_', '-')")
            if not isinstance(tail, int) or isinstance(tail, bool) or not 1 <= tail <= MAX_TAIL:
                raise LogError(f"tail must be an integer between 1 and {MAX_TAIL}")
            since_at = parse_since(since)
            pattern = None
            if grep:
                if len(grep) > MAX_GREP_CHARS:
                    raise LogError(f"grep is limited to {MAX_GREP_CHARS} characters")
                try:
                    pattern = re.compile(grep, 0 if case_sensitive else re.IGNORECASE)
                except re.error as exc:
                    raise LogError(f"grep is not a valid regular expression: {exc}") from None
            env = self.runner.resolve_env(env_id)
            containers = self._containers(env)
            if container:
                target_c = self._match(containers, container)
                if self._excluded(target_c):
                    raise LogError("logs for this container are disabled by LOGS_EXCLUDE")
                targets = [target_c]
            else:
                targets = [c for c in containers
                           if (c.get("labels") or {}).get("com.docker.compose.project") == project]
                if not targets:
                    raise LogError(f"no containers found for project {project!r}")
            note = None
            if project:
                kept = [c for c in targets if not self._excluded(c)]
                if len(kept) < len(targets):
                    note = f"{len(targets) - len(kept)} container(s) skipped (LOGS_EXCLUDE)"
                targets = kept
                if not targets:
                    raise LogError("logs for every container in this project are disabled by LOGS_EXCLUDE")
            if len(targets) > MAX_PROJECT_CONTAINERS:
                targets = targets[:MAX_PROJECT_CONTAINERS]
                note = (note + "; " if note else "") + f"only the first {MAX_PROJECT_CONTAINERS} containers"
            results = [self._collect(env, c, tail, since_at, pattern) for c in targets]
        except (LogError, ApiPathError) as exc:
            self.audit.record(tool="arcane_logs", target=target, outcome="rejected", reason=str(exc))
            return {"ok": False, "error": str(exc)}
        except httpx.HTTPError as exc:
            msg = self.redactor.text(f"{type(exc).__name__}: {exc}")
            self.audit.record(tool="arcane_logs", target=target, outcome="error", reason=msg)
            return {"ok": False, "error": f"Request failed: {msg}"}
        except Exception as exc:  # resolve_env raises policy errors with a helpful message
            self.audit.record(tool="arcane_logs", target=target, outcome="rejected", reason=str(exc))
            return {"ok": False, "error": str(exc)}

        result: dict[str, Any] = {"ok": True, "env_id": env, "logs": results}
        if note:
            result["note"] = note
        self._fit(result)
        self.audit.record(tool="arcane_logs", target=target, env=env, tail=tail, since=since, grep=bool(grep),
                          outcome="ok", duration_ms=int((time.monotonic() - started) * 1000))
        return result

    def _fit(self, result: dict[str, Any]) -> None:
        """Drop the oldest lines until the payload fits the output budget."""
        sections = result["logs"]
        budget = self.max_chars - 500
        per = max(budget // max(len(sections), 1), 1000)
        for sec in sections:
            lines: list[str] = sec["lines"]
            total = sum(len(x) + 3 for x in lines)
            dropped = 0
            while lines and total > per:
                total -= len(lines.pop(0)) + 3
                dropped += 1
            if dropped:
                sec["returned"] = len(lines)
                sec["truncated"] = f"dropped the {dropped} oldest lines to fit the output limit; use since/grep/tail"
