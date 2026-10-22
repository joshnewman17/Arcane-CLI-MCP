"""Read and replace a project's compose file without exposing the MCP container's filesystem.

``arcane_run`` rejects every local-file flag (``projects update -f <path>`` would let a caller
upload any file inside this container, including the CLI config that holds the API key). This
module is the narrow alternative: the caller supplies compose *content*, the server writes it to a
private temp file of its own and runs ``projects update -f`` on exactly that file.

- Reads return the compose file only. The project's ``.env`` is never returned or written here:
  it holds secrets and stays in the Arcane UI.
- Writes need ``confirm=true``. Without it the result is ``needs_confirmation`` with a diff
  against the current file. They're blocked in read-only mode.
- Content is validated as a YAML mapping with ``services`` before anything is sent.
- The project is not redeployed: that stays a separate, visible step.
"""

from __future__ import annotations

import difflib
import hashlib
import os
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

import yaml

from .api import ApiClient
from .audit import REDACTED, AuditLog, Redactor
from .cli import CliRunner, parse_json, tail

MAX_COMPOSE_BYTES = 256 * 1024
MAX_DIFF_CHARS = 12000
_PROJECT = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")


class ComposeEditor:
    def __init__(self, runner: CliRunner, api: ApiClient, redactor: Redactor, audit: AuditLog) -> None:
        self.runner = runner
        self.api = api
        self.redactor = redactor
        self.audit = audit
        self.settings = runner.settings

    # -- helpers -------------------------------------------------------------------------------

    def _resolve(self, project: str, env_id: str | None) -> tuple[str, str]:
        if not isinstance(project, str) or not _PROJECT.match(project):
            raise ValueError("project must be a project name or id (letters, digits, '.', '_', '-')")
        return project, self.runner.resolve_env(env_id)

    def _project_id(self, project: str, env: str) -> str:
        code, stdout, stderr, _ = self.runner.exec(
            self.runner.base_argv() + ["projects", "get", project, "--env", env, "--json"],
            self.settings.default_timeout_s,
        )
        parsed, data = parse_json(stdout)
        if code != 0 or not parsed or not isinstance(data, dict):
            raise LookupError(tail(self.redactor.text(stderr), 300) or f"project {project!r} not found")
        data = data.get("data", data)
        if not isinstance(data, dict) or not data.get("id"):
            raise LookupError(f"project {project!r} not found")
        return str(data["id"])

    def _current(self, project: str, env: str) -> dict[str, Any]:
        project_id = self._project_id(project, env)
        r = self.api.get(f"/api/environments/{env}/projects/{project_id}/compose")
        if not r.get("ok"):
            raise LookupError(r.get("error") or f"Arcane returned HTTP {r.get('status')}")
        data = r.get("data") or {}
        data = data.get("data", data) if isinstance(data, dict) else {}
        compose = data.get("composeContent") or ""
        try:
            doc = yaml.safe_load(compose)
            services = list(doc["services"]) if isinstance(doc, dict) and isinstance(doc.get("services"), dict) else []
        except yaml.YAMLError:
            services = []
        return {
            "project_id": project_id,
            "compose_file": data.get("composeFileName"),
            # Already passed through the redactor by ApiClient; envContent is withheld there too.
            "compose": compose,
            "services": services,
        }

    @staticmethod
    def validate(compose: Any) -> None:
        if not isinstance(compose, str) or not compose.strip():
            raise ValueError("compose must be the full compose file as a non-empty string")
        if len(compose.encode()) > MAX_COMPOSE_BYTES:
            raise ValueError(f"compose is larger than {MAX_COMPOSE_BYTES // 1024} KiB")
        if "\x00" in compose:
            raise ValueError("compose may not contain NUL bytes")
        if REDACTED in compose:
            raise ValueError(
                f"compose contains {REDACTED!r}: a value was hidden when the file was read and can't be "
                "restored through MCP. Move that secret into the project's .env (in the Arcane UI) and "
                "reference it as ${VAR}."
            )
        try:
            doc = yaml.safe_load(compose)
        except yaml.YAMLError as exc:
            raise ValueError(f"compose is not valid YAML: {str(exc).splitlines()[0]}") from exc
        if not isinstance(doc, dict) or not isinstance(doc.get("services"), dict) or not doc["services"]:
            raise ValueError("compose must be a mapping with a non-empty 'services' section")

    # -- tool entry points -----------------------------------------------------------------------

    def read(self, project: str, env_id: str | None = None) -> dict[str, Any]:
        try:
            project, env = self._resolve(project, env_id)
            current = self._current(project, env)
        except (ValueError, LookupError) as exc:
            self.audit.record(tool="arcane_project_compose", action="read", project=project, outcome="error",
                              reason=str(exc))
            return {"ok": False, "error": str(exc)}
        self.audit.record(tool="arcane_project_compose", action="read", project=project, env_id=env,
                          outcome="ok", bytes=len(current["compose"]))
        return {"ok": True, "project": project, "env_id": env, **current,
                "note": "The project's .env is not shown; it holds secrets and is edited in the Arcane UI."}

    def write(self, project: str, compose: str, env_id: str | None = None,
              confirm: bool = False) -> dict[str, Any]:
        started = time.monotonic()
        audit: dict[str, Any] = {"tool": "arcane_project_compose", "action": "write", "project": project,
                                 "env_id": env_id, "confirm": confirm}
        if self.settings.readonly:
            self.audit.record(**audit, outcome="blocked", reason="read-only mode")
            return {"ok": False, "blocked": True,
                    "error": "Editing compose files is not permitted: the server is in read-only mode."}
        try:
            project, env = self._resolve(project, env_id)
            audit["env_id"] = env
            self.validate(compose)
            current = self._current(project, env)
        except (ValueError, LookupError) as exc:
            self.audit.record(**audit, outcome="rejected", reason=str(exc))
            return {"ok": False, "error": str(exc)}

        digest = hashlib.sha256(compose.encode()).hexdigest()[:16]
        audit.update(sha256=digest, bytes=len(compose.encode()))
        diff = "\n".join(difflib.unified_diff(
            current["compose"].splitlines(), compose.splitlines(),
            f"{project}/{current['compose_file'] or 'compose.yaml'} (current)", f"{project} (new)", lineterm="", n=2,
        ))
        if not diff:
            self.audit.record(**audit, outcome="unchanged")
            return {"ok": True, "unchanged": True, "message": "The compose file already has this content."}
        if len(diff) > MAX_DIFF_CHARS:
            diff = diff[:MAX_DIFF_CHARS] + f"\n… diff truncated at {MAX_DIFF_CHARS} characters"

        if not confirm:
            self.audit.record(**audit, outcome="needs_confirmation")
            return {"ok": False, "needs_confirmation": True, "project": project, "env_id": env, "diff": diff,
                    "message": "Nothing was changed. Show the user this diff and ask them to approve it, then call "
                               "arcane_project_compose again with the same compose and confirm=true. The project "
                               "is not redeployed by this tool."}

        tmpdir = Path(tempfile.mkdtemp(prefix="compose-", dir=self.settings.state_dir))
        try:
            os.chmod(tmpdir, 0o700)
            path = tmpdir / "compose.yaml"
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                fh.write(compose)
            argv = self.runner.base_argv() + ["projects", "update", project, "-f", str(path),
                                              "--env", env, "--json", "--yes"]
            code, stdout, stderr, timed_out = self.runner.exec(argv, self.settings.default_timeout_s)
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)

        ok = code == 0 and not timed_out
        self.audit.record(**audit, outcome="ok" if ok else "error", exit_code=code,
                          duration_ms=int((time.monotonic() - started) * 1000))
        result: dict[str, Any] = {"ok": ok, "exit_code": code, "project": project, "env_id": env, "diff": diff}
        parsed, data = parse_json(stdout)
        if parsed and isinstance(data, dict):
            data = self.redactor.obj(data.get("data", data))
            result["project_state"] = {k: data.get(k) for k in ("name", "status", "serviceCount", "updatedAt")}
        if stderr.strip():
            result["stderr_tail"] = tail(self.redactor.text(stderr))
        if ok:
            result["message"] = ("Compose file updated. Running containers are unchanged until the project is "
                                 "redeployed: ask the user, then run arcane_run ['projects', 'redeploy', "
                                 f"'{project}'].")
        return result
