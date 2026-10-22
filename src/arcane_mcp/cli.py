"""Runs ``arcane-cli`` as a subprocess (argument list, never a shell)."""

from __future__ import annotations

import json
import os
import re
import subprocess
import time
from dataclasses import dataclass
from typing import Any

from . import policy
from .audit import AuditLog, Redactor
from .config import Settings

STDERR_TAIL_CHARS = 2000
_ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
_ENV_ID = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
CONFIRMATION_MARKER = "confirmation required"


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


@dataclass
class CliRunner:
    settings: Settings
    redactor: Redactor
    audit: AuditLog

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

    def resolve_env(self, env_id: str | None) -> str:
        env = (env_id if env_id not in (None, "") else self.settings.default_env).strip()
        if not _ENV_ID.match(env):
            raise policy.PolicyError("env_id must be a short identifier (letters, digits, '.', '_' or '-')")
        return env

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

    def run(self, args: list[str], env_id: str | None = None, confirm: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        audit: dict[str, Any] = {"tool": "arcane_run", "argv": list(args) if isinstance(args, list) else args,
                                 "env_id": env_id, "confirm": confirm}
        try:
            env = self.resolve_env(env_id)
            audit["env_id"] = env
            decision = policy.evaluate(args, confirm=confirm, readonly=self.settings.readonly)
        except policy.PolicyError as exc:
            self.audit.record(**audit, outcome="rejected", reason=str(exc), exit_code=None, duration_ms=0)
            return {"ok": False, "error": str(exc)}

        cmd_args = decision.args + ["--env", env, "--json"]
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
        stdout = self.redactor.text(stdout)
        stderr = self.redactor.text(stderr)
        result = self._shape(base, code, stdout, stderr)
        if timed_out:
            result.update(ok=False, timed_out=True,
                          error=f"Timed out after {timeout}s. The operation may still be running in Arcane; "
                                "check `activities list` before retrying.")
        self.audit.record(**audit, outcome="ok" if result["ok"] else "error", exit_code=code,
                          duration_ms=duration_ms, timeout_s=timeout)
        return result

    def _shape(self, base: dict[str, Any], code: int | None, stdout: str, stderr: str) -> dict[str, Any]:
        limit = self.settings.max_output_chars
        result: dict[str, Any] = {**base, "ok": code == 0, "exit_code": code}
        parsed, data = parse_json(stdout)
        if parsed:
            data, note = fit_output(data, limit)
            result["data"] = data
        else:
            result["raw_stdout"], note = truncate_text(strip_ansi(data), limit)
        if note:
            result["truncated"] = True
            result["truncation_note"] = note
        if stderr.strip():
            result["stderr_tail"] = tail(stderr)
        if code != 0 and needs_confirmation(stderr):
            result["needs_confirmation"] = True
            result["message"] = ("arcane-cli asked for confirmation; nothing was changed. Ask the user, "
                                 "then retry with confirm=true.")
        return result

    def help(self, command: list[str]) -> dict[str, Any]:
        started = time.monotonic()
        try:
            policy.check_tokens(command)
            if any(c.startswith("-") for c in command):
                raise policy.PolicyError("command must contain only subcommand words, e.g. ['projects', 'destroy']")
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
        blocked = next((r for r in policy.BLOCKED if path[: len(r.prefix)] == r.prefix), None)
        if blocked:
            out["policy"] = f"Note: `{' '.join(path)}` is blocked through MCP: {blocked.reason}"
        return out

    def environments(self) -> dict[str, Any]:
        result = self.run(["environments", "list", "--all"])
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
        parsed, data = parse_json(self.redactor.text(stdout))
        return {
            "ok": code == 0 and not timed_out,
            "doctor": data if parsed else None,
            "stderr_tail": tail(self.redactor.text(stderr), 500) or None,
        }
