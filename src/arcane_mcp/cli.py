"""Runs ``arcane-cli`` as a subprocess (argument list, never a shell)."""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any

from . import compact as compact_mod
from . import policy
from .audit import AuditLog, Redactor
from .config import Settings

STDERR_TAIL_CHARS = 2000
ENV_CACHE_TTL_S = 300
ACTIVITIES_DEFAULT_LIMIT = 20
ACTIVITIES_MAX_FETCH = 500
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ENV_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
# Environment names may have spaces ("AWS ARM Micro"); they are resolved to an id before use.
_ENV_NAME = re.compile(r"^[A-Za-z0-9 _.()-]{1,64}$")
_HEX_ID = re.compile(r"^[0-9a-f]{12,64}$")
_UUID = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_HELP_WORD = re.compile(r"^[a-z][a-z0-9-]*$")
CONFIRMATION_MARKER = "confirmation required"
SELF_TARGET_MESSAGE = (
    "This would restart the MCP server itself; do it from the Arcane UI or confirm knowing the call will drop. "
    "Nothing was changed. Only with the user's explicit approval, retry with confirm=true and allow_self=true."
)


class UnknownEnv(policy.PolicyError):
    def __init__(self, env: str, known: list[dict[str, Any]]) -> None:
        names = ", ".join(f"{e['name']} ({e['id']})" for e in known)
        super().__init__(f"unknown env_id {env!r}. Known environments: {names}")
        self.known = known


def clean_error(stderr: str) -> str | None:
    """The useful part of arcane-cli's stderr, without the `Error` banner line."""
    lines = [line.strip() for line in strip_ansi(stderr).splitlines()]
    lines = [line for line in lines if line and line.lower().rstrip(":") != "error"]
    text = re.sub(r"^error:\s*", "", " ".join(lines), flags=re.I)
    return text[:500] or None


def strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def tail(text: str, n: int = STDERR_TAIL_CHARS) -> str:
    text = strip_ansi(text).strip()
    return text if len(text) <= n else "…" + text[-n:]


def needs_confirmation(stderr: str) -> bool:
    return CONFIRMATION_MARKER in stderr.lower()


def parse_json(stdout: str) -> tuple[bool, Any]:
    text = stdout.strip()
    if not text:
        return True, None
    try:
        return True, json.loads(text)
    except json.JSONDecodeError:
        return False, text


def _size(value: Any) -> int:
    return len(json.dumps(value, default=str, separators=(",", ":")))


def fit_output(data: Any, limit: int) -> tuple[Any, str | None]:
    """Shrink ``data`` to fit in ``limit`` characters of JSON.

    Returns ``(data, note)``; ``note`` is set when something was cut.
    - ``{"data": [...], "pagination": ...}`` (list commands): keep the first items.
    - top-level arrays (progress frames from streaming ops): keep the last items.
    - anything else: return a truncated JSON string.
    """
    if _size(data) <= limit:
        return data, None

    if isinstance(data, dict) and isinstance(data.get("data"), list):
        items = data["data"]
        total = len(items)
        lo, hi = 0, total
        while lo < hi:  # largest prefix that fits
            mid = (lo + hi + 1) // 2
            if _size({**data, "data": items[:mid]}) <= limit:
                lo = mid
            else:
                hi = mid - 1
        if lo > 0:
            return {**data, "data": items[:lo]}, (
                f"Output truncated: showing {lo} of {total} items. "
                "Narrow it with --limit/--start or the command's filter flags (see arcane_help)."
            )

    if isinstance(data, list) and data:
        total = len(data)
        lo, hi = 0, total
        while lo < hi:  # largest suffix that fits
            mid = (lo + hi + 1) // 2
            if _size(data[-mid:]) <= limit:
                lo = mid
            else:
                hi = mid - 1
        if lo > 0:
            return data[-lo:], f"Output truncated: showing the last {lo} of {total} entries."

    text = json.dumps(data, default=str)
    return text[:limit], f"Output truncated to {limit} of {len(text)} characters."


def truncate_text(text: str, limit: int) -> tuple[str, str | None]:
    if len(text) <= limit:
        return text, None
    return text[:limit], f"Output truncated to {limit} of {len(text)} characters."


def _limit(args: list[str]) -> tuple[int | None, list[str]]:
    """Return the ``--limit`` value and ``args`` without it."""
    out, value, i = [], None, 0
    while i < len(args):
        name, _, inline = args[i].partition("=")
        if name == "--limit":
            raw = inline if inline else (args[i + 1] if i + 1 < len(args) else "")
            i += 1 if inline else 2
            value = int(raw) if raw.isdigit() else None
            continue
        out.append(args[i])
        i += 1
    return value, out


@dataclass
class CliRunner:
    settings: Settings
    redactor: Redactor
    audit: AuditLog
    _env_cache: tuple[float, list[dict[str, Any]]] | None = field(default=None, init=False, repr=False)

    def base_argv(self) -> list[str]:
        return [self.settings.cli_path, "--config", str(self.settings.cli_config_path), "--no-color"]

    def subprocess_env(self) -> dict[str, str]:
        # Deliberately minimal: the API key and MCP token never reach the child's environment.
        return {
            "PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"),
            "HOME": str(self.settings.cli_home),
            "LANG": "C.UTF-8",
            "NO_COLOR": "1",
            "TERM": "dumb",
        }

    def timeout_for(self, path: policy.Path) -> int:
        return self.settings.long_timeout_s if path in policy.LONG_RUNNING else self.settings.default_timeout_s

    def known_envs(self) -> list[dict[str, Any]] | None:
        """``[{id, name}]`` from `environments list`, cached for ENV_CACHE_TTL_S; None if unavailable."""
        now = time.monotonic()
        if self._env_cache and now - self._env_cache[0] < ENV_CACHE_TTL_S:
            return self._env_cache[1]
        code, stdout, _, timed_out = self.exec(self.base_argv() + ["environments", "list", "--all", "--json"], 30)
        parsed, data = parse_json(stdout)
        items = data.get("data") if isinstance(data, dict) else data
        if code != 0 or timed_out or not parsed or not isinstance(items, list):
            return None
        envs = [{"id": str(i["id"]), "name": i.get("name")} for i in items
                if isinstance(i, dict) and i.get("id") is not None]
        if not envs:
            return None
        self._env_cache = (now, envs)
        return envs

    def resolve_env(self, env_id: str | None) -> str:
        """Validate ``env_id`` against Arcane's environments, accepting a name as well as an id."""
        if env_id in (None, ""):
            env = self.settings.default_env.strip()
        else:
            env = str(env_id).strip()
            if not _ENV_NAME.match(env):
                raise policy.PolicyError("env_id must be an environment id or name (from arcane_environments)")
            known = self.known_envs()
            if known is not None:
                if any(e["id"] == env for e in known):
                    return env
                by_name = [e for e in known if str(e.get("name") or "").lower() == env.lower()]
                if len(by_name) == 1:
                    return by_name[0]["id"]
                raise UnknownEnv(env, known)
        if not _ENV_ID.match(env):
            raise policy.PolicyError("env_id must be a short identifier (letters, digits, '.', '_' or '-')")
        return env

    # -- self-management guard -------------------------------------------------

    def _lookup(self, args: list[str], env: str) -> dict[str, Any] | None:
        code, stdout, _, _ = self.exec(self.base_argv() + args + ["--env", env, "--json"],
                                       self.settings.default_timeout_s)
        parsed, data = parse_json(stdout)
        if code != 0 or not parsed or not isinstance(data, dict):
            return None
        data = data.get("data", data)
        return data if isinstance(data, dict) else None

    def _is_self_project(self, target: str, env: str) -> bool:
        own = self.settings.self_project
        if not own:
            return False
        if target.lower() == own.lower():
            return True
        if _UUID.match(target) or _HEX_ID.match(target):
            found = self._lookup(["projects", "get", target], env)
            return bool(found) and str(found.get("name", "")).lower() == own.lower()
        return False

    def _is_self_container(self, target: str, env: str) -> bool:
        s = self.settings
        names = {n.lower() for n in s.self_containers}
        name = target.lstrip("/").lower()
        if name in names or (s.self_project and name.startswith(s.self_project.lower() + "-")):
            return True
        if not _HEX_ID.match(name):
            return False
        # Docker sets the hostname to the container's short id.
        own_id = (os.environ.get("HOSTNAME") or socket.gethostname()).lower()
        if _HEX_ID.match(own_id) and (name.startswith(own_id) or own_id.startswith(name)):
            return True
        found = self._lookup(["containers", "get", target], env)
        if not found:
            return False
        found_names = [str(n).lstrip("/").lower() for n in (found.get("names") or [found.get("name")]) if n]
        labels = found.get("labels") or (found.get("config") or {}).get("labels") or {}
        project = str(labels.get("com.docker.compose.project", "")).lower()
        return bool(set(found_names) & names) or bool(s.self_project and project == s.self_project.lower())

    def self_target(self, decision: policy.PolicyResult, env: str | None) -> str | None:
        """Describe what of the MCP server's own deployment ``decision`` would restart, if anything."""
        s = self.settings
        if env is None or env != (s.self_env or s.default_env):
            return None
        path = decision.command_path
        if path in policy.SELF_MUTATING_ALL:
            return "every container in this environment, including the MCP server"
        if path not in policy.SELF_MUTATING:
            return None
        for target in policy.positionals(decision.args, path):
            if path[0] == "projects" and self._is_self_project(target, env):
                return f"the MCP server's own project ({target})"
            if path[0] == "containers" and self._is_self_container(target, env):
                return f"the MCP server's own container ({target})"
        return None

    def exec(self, argv: list[str], timeout: int) -> tuple[int | None, str, str, bool]:
        try:
            proc = subprocess.run(
                argv,
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self.subprocess_env(),
                check=False,
            )
            return proc.returncode, proc.stdout or "", proc.stderr or "", False
        except subprocess.TimeoutExpired as exc:
            out = exc.stdout.decode() if isinstance(exc.stdout, bytes) else (exc.stdout or "")
            err = exc.stderr.decode() if isinstance(exc.stderr, bytes) else (exc.stderr or "")
            return None, out, err, True
        except FileNotFoundError:
            return 127, "", f"arcane-cli not found at {self.settings.cli_path}", False

    def display(self, args: list[str]) -> str:
        return self.redactor.text("arcane-cli " + " ".join(args))

    # -- tools -----------------------------------------------------------------

    def run(self, args: list[str], env_id: str | None = None, confirm: bool = False,
            compact: bool = True, allow_self: bool = False, exclude_types: list[str] | None = None,
            filters: dict[str, Any] | None = None) -> dict[str, Any]:
        started = time.monotonic()
        audit: dict[str, Any] = {"tool": "arcane_run", "argv": list(args) if isinstance(args, list) else args,
                                 "env_id": env_id, "confirm": confirm}
        if allow_self:
            audit["allow_self"] = True
        try:
            decision = policy.evaluate(args, confirm=confirm, readonly=self.settings.readonly)
            if decision.help:
                # Same output as arcane_help (no trailing padding, policy note), without the `--env` noise.
                return {**self.help(list(decision.command_path)), "note": "Answered by arcane_help."}
            env = self.resolve_env(env_id) if policy.env_scoped(decision.command_path) else None
            audit["env_id"] = env
            if exclude_types and decision.command_path != ("activities", "list"):
                raise policy.PolicyError("exclude_types only applies to ['activities', 'list']")
        except UnknownEnv as exc:
            self.audit.record(**audit, outcome="rejected", reason=str(exc), exit_code=None, duration_ms=0)
            return {"ok": False, "error": "unknown env_id", "message": str(exc), "known": exc.known}
        except policy.PolicyError as exc:
            self.audit.record(**audit, outcome="rejected", reason=str(exc), exit_code=None, duration_ms=0)
            return {"ok": False, "error": str(exc)}

        run_args, keep = decision.args, None
        if exclude_types:
            # Over-fetch so that `--limit N` still returns about N activities after filtering.
            requested, rest = _limit(decision.args)
            if "--all" not in rest:
                keep = requested or ACTIVITIES_DEFAULT_LIMIT
                run_args = rest + ["--limit", str(min(max(keep * 5, 50), ACTIVITIES_MAX_FETCH))]

        cmd_args = run_args + (["--env", env] if env is not None else []) + ["--json"]
        if confirm:
            cmd_args.append("--yes")
        audit["argv"] = cmd_args
        base: dict[str, Any] = {"command": self.display(cmd_args)}
        if decision.stripped:
            base["stripped_args"] = decision.stripped
            base["note"] = (
                "Removed confirmation/output flags from args. "
                "Confirmation is only given through confirm=true; --json is always added."
            )

        if decision.decision is policy.Decision.BLOCK:
            self.audit.record(**audit, outcome="blocked", reason=decision.reason, exit_code=None, duration_ms=0)
            return {**base, "ok": False, "blocked": True, "error": decision.reason}

        hit = self.self_target(decision, env)
        if hit and not (confirm and allow_self):
            self.audit.record(**audit, outcome="self_target", reason=hit, exit_code=None, duration_ms=0)
            return {**base, "ok": False, "self_target": True, "target": hit, "message": SELF_TARGET_MESSAGE}

        if decision.decision is policy.Decision.NEEDS_CONFIRM:
            self.audit.record(**audit, outcome="needs_confirmation", exit_code=None, duration_ms=0)
            return {
                **base,
                "ok": False,
                "needs_confirmation": True,
                "reason": decision.reason,
                "message": "Nothing was changed. Ask the user to confirm this exact command, "
                           "then call arcane_run again with confirm=true.",
            }

        timeout = self.timeout_for(decision.command_path)
        code, stdout, stderr, timed_out = self.exec(self.base_argv() + cmd_args, timeout)
        duration_ms = int((time.monotonic() - started) * 1000)
        stderr = self.redactor.text(stderr)  # stdout is redacted in _shape, after JSON parsing
        result = self._shape(base, code, stdout, stderr, decision.command_path, compact=compact,
                             exclude=exclude_types, keep=keep, filters=filters)
        if timed_out:
            result.update(ok=False, timed_out=True,
                          error=f"Timed out after {timeout}s. The operation may still be running in Arcane; "
                                "check `activities list` before retrying.")
        self.audit.record(**audit, outcome="ok" if result["ok"] else "error", exit_code=code,
                          duration_ms=duration_ms, timeout_s=timeout)
        return result

    def _shape(self, base: dict[str, Any], code: int | None, stdout: str, stderr: str,
               path: policy.Path = (), compact: bool = False, exclude: list[str] | None = None,
               keep: int | None = None, filters: dict[str, Any] | None = None) -> dict[str, Any]:
        limit = self.settings.max_output_chars
        result: dict[str, Any] = {**base, "ok": code == 0, "exit_code": code}
        parsed, data = parse_json(stdout)
        if parsed:
            data = compact_mod.cleanup(self.redactor.obj(data))
            if exclude:
                data, result["excluded"] = compact_mod.exclude_types(data, exclude)
                if keep is not None and isinstance(data, dict) and isinstance(data.get("data"), list):
                    data = {**data, "data": data["data"][:keep]}
            if filters:
                data, matched = compact_mod.apply_filters(path, data, filters)
                if matched is not None:
                    result["filtered"] = matched
                elif any(v not in (None, "") for v in filters.values()):
                    result["filter_note"] = "Filters ignored: this command doesn't return a list."
            if compact:
                data, compacted = compact_mod.compact(path, data)
                if compacted:
                    result["compact"] = True
            data, note = fit_output(data, limit)
            result["data"] = data
        else:
            text = strip_ansi(self.redactor.text(data))
            text = "\n".join(line.rstrip() for line in text.splitlines())
            result["raw_stdout"], note = truncate_text(text, limit)
        if note:
            result["truncated"] = True
            result["truncation_note"] = note
        if stderr.strip():
            result["stderr_tail"] = tail(stderr)
        if code not in (0, None):
            result["error"] = clean_error(stderr) or f"arcane-cli exited with code {code}"
        if code != 0 and needs_confirmation(stderr):
            result["needs_confirmation"] = True
            result["message"] = ("arcane-cli asked for confirmation; nothing was changed. Ask the user, "
                                 "then retry with confirm=true.")
        return result

    def help(self, command: list[str]) -> dict[str, Any]:
        started = time.monotonic()
        try:
            policy.check_tokens(command)
            bad = [c for c in command if not _HELP_WORD.match(c)]
            if bad:
                raise policy.PolicyError(
                    f"not a subcommand: {', '.join(repr(b) for b in bad)}. command must contain only subcommand "
                    "words (lowercase letters, digits, '-'), e.g. ['projects', 'destroy']"
                )
        except policy.PolicyError as exc:
            self.audit.record(tool="arcane_help", argv=command, outcome="rejected", reason=str(exc))
            return {"ok": False, "error": str(exc)}
        code, stdout, stderr, timed_out = self.exec(self.base_argv() + list(command) + ["--help"],
                                                    self.settings.default_timeout_s)
        text = strip_ansi(self.redactor.text(stdout or stderr))
        text = "\n".join(line.rstrip() for line in text.splitlines())
        text, note = truncate_text(text.strip(), self.settings.max_output_chars)
        self.audit.record(tool="arcane_help", argv=command, exit_code=code,
                          duration_ms=int((time.monotonic() - started) * 1000))
        out: dict[str, Any] = {"ok": code == 0 and not timed_out, "help": text}
        if note:
            out["truncation_note"] = note
        path = policy.command_path(list(command))
        if command and tuple(command) not in policy.KNOWN_COMMANDS:
            out["warning"] = (f"`{' '.join(command)}` is not a known arcane-cli command; the help shown is for "
                              f"the nearest parent (`{' '.join(path[:-1] if path == tuple(command[:2]) else path)}`)"
                              " or the top level. Check the subcommand list before using it.")
        blocked =next((r for r in policy.BLOCKED if path[: len(r.prefix)] == r.prefix), None)
        if blocked:
            out["policy"] = f"Note: `{' '.join(path)}` is blocked through MCP: {blocked.reason}"
        return out

    def environments(self) -> dict[str, Any]:
        result = self.run(["environments", "list", "--all"], compact=False)
        if not result.get("ok"):
            return result
        payload = result.get("data")
        items = payload.get("data") if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            return result
        trimmed = [
            {k: item.get(k) for k in ("id", "name", "status") if k in item}
            for item in items
            if isinstance(item, dict)
        ]
        return {"ok": True, "default_env_id": self.settings.default_env, "environments": trimmed}

    def doctor(self) -> dict[str, Any]:
        code, stdout, stderr, timed_out = self.exec(self.base_argv() + ["doctor", "--json"], 30)
        parsed, data = parse_json(stdout)
        return {
            "ok": code == 0 and not timed_out,
            "doctor": self.redactor.obj(data) if parsed else None,
            "stderr_tail": tail(self.redactor.text(stderr), 500) or None,
        }
