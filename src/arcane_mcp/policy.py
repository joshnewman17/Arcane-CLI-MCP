"""Declarative command policy for ``arcane_run``.

Everything that decides whether a command may run lives in this file, so it can
be audited in one place. The tables are keyed by *command paths*: the leading
subcommand words of an ``arcane-cli`` invocation, e.g. ``("projects", "destroy")``.

Evaluation order (first match wins):

1. Argument sanitisation: confirmation and output flags are stripped, and
   unsafe flags are rejected (see ``sanitize_args``).
2. ``BLOCKED``: always rejected, even with ``confirm=true`` ("do it in the UI").
3. Read-only mode: when ``ARCANE_MCP_READONLY=true``, only ``READONLY`` paths
   run. Everything else is denied by default.
4. ``CONFIRM``, plus any command whose final word is in ``CONFIRM_VERBS``:
   these need ``confirm=true``. Without it the command does not run.

Verified against ``arcane-cli`` v2.17.0 ``--help``. Re-check this file when you
bump ``ARCANE_CLI_VERSION``; ``tests/test_policy.py`` covers every rule.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

Path = tuple[str, ...]


def _p(spec: str) -> Path:
    return tuple(spec.split())


@dataclass(frozen=True)
class Rule:
    prefix: Path
    reason: str = ""
    # The rule does not apply when any of these flags is present
    # (e.g. ``system upgrade --check`` is allowed).
    unless_flags: tuple[str, ...] = ()
    # For READONLY rules: the rule only applies when one of these flags is present.
    requires_flags: tuple[str, ...] = ()


_UI = "Do this in the Arcane web UI."
_LOCAL_FS = (
    "This command reads or writes files on the MCP server's own filesystem, "
    "which holds no user files and does hold credentials. Use the Arcane web UI."
)

# --- 1. Blocked entirely -----------------------------------------------------
BLOCKED: tuple[Rule, ...] = (
    # Credentials, sessions and identity.
    Rule(_p("auth login"), f"Interactive login is not supported. {_UI}"),
    Rule(_p("auth logout"), f"Would break this server's session. {_UI}"),
    Rule(_p("auth refresh"), "Session management is not exposed."),
    Rule(_p("auth password"), f"Password changes are out of scope. {_UI}"),
    Rule(_p("auth api-keys"), f"API key management is out of scope. {_UI}"),
    Rule(_p("auth federated"), "Federated credential exchange is not exposed."),
    Rule(_p("auth oidc"), "OIDC login is not exposed."),
    Rule(_p("admin users"), f"User management is out of scope. {_UI}"),
    Rule(_p("admin roles"), f"Role management is out of scope. {_UI}"),
    Rule(_p("admin federated"), f"Federated credential management is out of scope. {_UI}"),
    Rule(_p("admin oidc"), f"OIDC management is out of scope. {_UI}"),
    Rule(_p("admin api-keys"), f"API key management is out of scope. {_UI}"),
    Rule(_p("admin backups restore"), f"Restoring an Arcane backup is too destructive for automation. {_UI}"),
    Rule(_p("admin backups recovery"), f"Backup recovery keys are credentials. {_UI}"),
    Rule(_p("admin notifications settings set"), f"Settings management is out of scope. {_UI}"),
    Rule(_p("admin notifications settings delete"), f"Settings management is out of scope. {_UI}"),
    Rule(_p("settings update"), f"Settings management is out of scope. {_UI}"),
    # The CLI's own config holds the API key and is managed by this server.
    Rule(_p("config backup"), "The CLI config is managed by the MCP server."),
    Rule(_p("config init"), "The CLI config is managed by the MCP server."),
    Rule(_p("config set"), "The CLI config is managed by the MCP server."),
    Rule(_p("config show"), "The CLI config is managed by the MCP server."),
    # Binary / platform lifecycle.
    Rule(_p("self-update"), "The CLI version is pinned in the Docker image. Rebuild the image to upgrade."),
    Rule(
        _p("system upgrade"),
        f"Upgrading Arcane itself is not allowed here (only `--check` / `--status`). {_UI}",
        unless_flags=("--check", "--status"),
    ),
    Rule(_p("generate"), "Generating secrets and certificates is out of scope."),
    # Local filesystem of the MCP container.
    Rule(_p("images upload"), _LOCAL_FS),
    Rule(_p("images export"), _LOCAL_FS),
    Rule(_p("projects workspace download"), _LOCAL_FS),
    Rule(_p("volumes workspace download"), _LOCAL_FS),
    Rule(_p("volumes workspace put"), _LOCAL_FS),
    Rule(_p("volumes backups download"), _LOCAL_FS),
    Rule(_p("volumes backups upload"), _LOCAL_FS),
    Rule(_p("templates download"), _LOCAL_FS),
    Rule(_p("podman kube play"), _LOCAL_FS),
    Rule(_p("podman kube down"), _LOCAL_FS),
    Rule(_p("podman quadlets install"), _LOCAL_FS),
    # The secret value can only come from --file (a local file) or stdin (never connected),
    # so through MCP these could only create empty secrets.
    Rule(_p("podman secrets create"), f"Secret values can't be passed safely through MCP. {_UI}"),
    Rule(_p("podman secrets update"), f"Secret values can't be passed safely through MCP. {_UI}"),
)

# --- 3. Read-only allowlist (default deny in read-only mode) -------------------
READONLY: tuple[Rule, ...] = tuple(
    Rule(_p(s))
    for s in (
        "activities get", "activities list",
        "admin backups discover", "admin backups list", "admin backups s3 get", "admin backups s3 list",
        "admin events list", "admin events stats", "admin notifications settings get",
        "auth me",
        "config path", "config test",
        "containers counts", "containers get", "containers list", "containers updates",
        "doctor",
        "environments get", "environments list", "environments test", "environments version",
        "gitops files", "gitops get", "gitops list", "gitops status",
        "images attestations", "images builds get", "images counts", "images get", "images history",
        "images list", "images search", "images updates summary",
        "images vulnerabilities ignored", "images vulnerabilities image", "images vulnerabilities list",
        "images vulnerabilities status", "images vulnerabilities summary",
        "jobs list", "jobs schedules get",
        "networks counts", "networks get", "networks list", "networks topology",
        "projects counts", "projects get", "projects list", "projects tags", "projects updates",
        "projects workspace cat",
        "registries get", "registries list", "registries test", "registries usage",
        "repos branches", "repos files", "repos get", "repos list", "repos test",
        "settings list", "settings public",
        "system info",
        "templates content", "templates get", "templates list",
        "updater history", "updater status",
        "variables list",
        "version",
        "volumes backups files", "volumes backups list", "volumes counts", "volumes get", "volumes list",
        "volumes sizes", "volumes usage", "volumes workspace cat",
        "webhooks list",
        "podman status", "podman pods list", "podman pods inspect", "podman quadlets list", "podman quadlets get",
        "podman secrets list", "podman secrets inspect", "podman kube generate",
    )
) + (
    Rule(_p("system upgrade"), requires_flags=("--check", "--status")),
    Rule(_p("variables sync"), requires_flags=("--status",)),
    Rule(_p("podman autoupdate"), requires_flags=("--dry-run",)),
)

# --- 4. Require confirm=true ---------------------------------------------------
CONFIRM: tuple[Rule, ...] = (
    Rule(_p("projects destroy"), "Removes the project's containers and, by default, its files."),
    Rule(_p("projects down"), "Stops every service in the project."),
    Rule(_p("system prune"), "Removes unused containers, images, networks and build cache."),
    Rule(_p("system containers stop"), "Stops every container in the environment."),
    Rule(_p("images prune"), "Removes unused images."),
    Rule(_p("images remove"), "Removes an image."),
    Rule(_p("volumes delete"), "Deletes a volume and its data."),
    Rule(_p("volumes prune"), "Deletes all unused volumes and their data."),
    Rule(_p("volumes backups restore"), "Overwrites volume contents from a backup."),
    Rule(_p("containers delete"), "Removes a container."),
    Rule(_p("containers kill"), "Kills a running container."),
    Rule(_p("networks delete"), "Removes a network."),
    Rule(_p("networks prune"), "Removes all unused networks."),
    Rule(_p("activities clear"), "Clears activity history."),
)

# Any command whose final word is one of these also needs confirm=true.
CONFIRM_VERBS = frozenset({"delete", "remove", "prune", "destroy", "clear", "restore"})

# Commands that stream progress and can run for a long time (LONG_TIMEOUT_S).
LONG_RUNNING: frozenset[Path] = frozenset(
    _p(s)
    for s in (
        "projects up", "projects redeploy", "projects pull", "projects build", "projects upgrade",
        "images pull", "images build",
        "containers update", "containers redeploy",
        "updater run", "gitops sync", "system prune", "images vulnerabilities scan", "podman autoupdate",
    )
)

# Commands that stop, restart or recreate their target. Aimed at the MCP server's own project or
# containers they would kill the server mid-call, so they need confirm=true AND allow_self=true.
SELF_MUTATING: frozenset[Path] = frozenset(
    _p(s)
    for s in (
        "containers update", "containers redeploy", "containers restart", "containers stop", "containers kill",
        "containers delete", "containers pause", "containers edit",
        "projects redeploy", "projects down", "projects up", "projects pull", "projects restart",
        "projects destroy", "projects upgrade", "projects archive", "projects build",
    )
)
# Environment-wide commands that would also take the MCP server down with everything else.
SELF_MUTATING_ALL: frozenset[Path] = frozenset({_p("system containers stop"), _p("updater run")})

# Command groups that don't take `--env` (everything else is environment-scoped).
NON_ENV_GROUPS = frozenset({"auth", "config", "version", "completion", "self-update", "generate", "doctor", "help"})

# Every command path in arcane-cli v2.17.0.
# Used to work out where the command path ends and positional arguments begin.
KNOWN_COMMANDS: frozenset[Path] = frozenset(
    _p(s)
    for s in """
activities;activities cancel;activities clear;activities get;activities list;admin;admin api-keys;
admin api-keys create;admin api-keys delete;admin api-keys get;admin api-keys list;admin api-keys update;
admin backups;admin backups create;admin backups delete;admin backups discover;admin backups list;
admin backups policies;admin backups policies update;admin backups recovery;admin backups recovery generate;
admin backups recovery set;admin backups restore;admin backups s3;admin backups s3 create;
admin backups s3 delete;admin backups s3 get;admin backups s3 list;admin backups s3 test;
admin backups s3 update;admin backups upload;admin events;admin events delete;admin events list;
admin events stats;admin federated;admin federated create;admin federated delete;admin federated get;
admin federated list;admin federated update;admin notifications;admin notifications settings;
admin notifications settings delete;admin notifications settings get;admin notifications settings set;
admin notifications test;admin oidc;admin oidc create;admin oidc delete;admin oidc list;admin oidc update;
admin roles;admin roles assign;admin roles assignments;admin roles create;admin roles delete;admin roles get;
admin roles list;admin roles permissions;admin roles update;admin users;admin users create;
admin users delete;admin users get;admin users list;admin users update;auth;auth api-keys;
auth api-keys create;auth api-keys delete;auth api-keys list;auth federated;auth login;auth logout;auth me;
auth oidc;auth password;auth refresh;config;config backup;config init;config path;config set;config show;
config test;containers;containers auto-update;containers commit;containers counts;containers create;
containers delete;containers edit;containers get;containers kill;containers list;containers pause;
containers redeploy;containers restart;containers start;containers stop;containers unpause;
containers update;containers updates;doctor;environments;environments create;environments delete;
environments get;environments list;environments switch;environments test;environments update;
environments version;generate;generate apikey;generate mtls;generate secret;generate tls;gitops;
gitops create;gitops delete;gitops files;gitops get;gitops import;gitops list;gitops status;gitops sync;
gitops update;images;images attestations;images build;images builds;images builds get;images counts;
images export;images get;images history;images list;images prune;images pull;images remove;images search;
images tag;images updates;images updates check;images updates summary;images upload;images vulnerabilities;
images vulnerabilities ignore;images vulnerabilities ignored;images vulnerabilities image;
images vulnerabilities list;images vulnerabilities scan;images vulnerabilities status;
images vulnerabilities summary;images vulnerabilities unignore;jobs;jobs list;jobs run;jobs schedules;
jobs schedules get;jobs schedules update;networks;networks connect;networks counts;networks create;
networks delete;networks disconnect;networks get;networks list;networks prune;networks topology;projects;
projects archive;projects build;projects counts;projects create;projects destroy;projects down;
projects get;projects list;projects pull;projects redeploy;projects restart;projects tag;projects tags;
projects unarchive;projects up;projects update;projects updates;projects upgrade;projects workspace;
projects workspace cat;projects workspace download;projects workspace update;registries;registries create;
registries delete;registries get;registries list;registries test;registries update;registries usage;repos;
repos branches;repos create;repos delete;repos files;repos get;repos list;repos test;repos update;
self-update;self-update channel;self-update channel next;self-update channel stable;self-update run;
settings;settings list;settings public;settings update;system;system containers;system containers start;
system containers stop;system convert;system info;system prune;system upgrade;templates;templates content;
templates create;templates default;templates default save;templates delete;templates download;
templates fetch;templates get;templates list;templates registries;templates registries delete;
templates registries update;templates update;updater;updater history;updater run;updater status;variables;
variables create;variables delete;variables list;variables sync;variables update;version;volumes;
volumes backups;volumes backups create;volumes backups delete;volumes backups download;
volumes backups files;volumes backups list;volumes backups policy;volumes backups policy update;
volumes backups restore;volumes backups upload;volumes counts;volumes create;volumes delete;volumes get;
volumes list;volumes prune;volumes rename;volumes sizes;volumes usage;volumes workspace;
volumes workspace cat;volumes workspace download;volumes workspace put;webhooks;webhooks create;
webhooks delete;webhooks list;webhooks trigger;webhooks update;
podman;podman autoupdate;podman kube;podman kube down;podman kube generate;podman kube play;podman pods;
podman pods create;podman pods delete;podman pods inspect;podman pods list;podman pods restart;podman pods start;
podman pods stop;podman quadlets;podman quadlets delete;podman quadlets get;podman quadlets install;
podman quadlets list;podman quadlets restart;podman quadlets start;podman quadlets stop;podman secrets;
podman secrets create;podman secrets delete;podman secrets inspect;podman secrets list;podman secrets update;
podman status
""".replace("\n", "").split(";")
    if s.strip()
)

# --- Argument sanitisation tables ---------------------------------------------

# Stripped silently; confirmation only comes from confirm=true, and the server
# always adds --json itself.
STRIP_FLAGS = frozenset({"--yes", "-y", "--force", "--json"})
STRIP_FLAGS_WITH_VALUE = frozenset({"--output"})
# Diagnostic flags that could make the CLI log request details.
STRIP_DIAGNOSTIC_FLAGS = frozenset({"--log-json"})
STRIP_DIAGNOSTIC_FLAGS_WITH_VALUE = frozenset({"--log-level"})

# Commands where ``-f`` is short for ``--force`` (stripped). Everywhere else
# ``-f`` means ``--file`` (rejected, see LOCAL_FILE_FLAGS).
FORCE_SHORT_F: frozenset[Path] = frozenset(
    _p(s)
    for s in (
        "activities cancel", "activities clear", "containers delete", "images remove",
        "networks delete", "networks prune", "projects destroy", "system upgrade",
        "volumes delete", "volumes prune", "podman pods delete", "podman quadlets delete",
        "podman secrets delete", "podman autoupdate", "podman kube down",
        "admin events delete", "gitops delete", "registries delete", "repos delete",
        "templates delete", "variables delete", "webhooks delete", "environments delete",
        "volumes backups delete", "admin backups delete", "admin backups s3 delete",
        "templates registries delete",
    )
)
# Commands where ``-f/--file`` is a path inside a remote build context, not a local file.
REMOTE_FILE_FLAG_OK: frozenset[Path] = frozenset({_p("images build")})

REJECT_FLAGS: dict[str, str] = {
    "--config": "The CLI config is managed by the MCP server.",
    "-c": "The CLI config is managed by the MCP server.",
    "--env": "Pass the environment with the `env_id` parameter instead of `--env`.",
}
LOCAL_FILE_FLAGS = frozenset(
    {"--file", "-f", "--env-file", "--dockerfile-inline", "--token-file", "--extra-file", "--provider-config"}
)

MAX_ARGS = 64
MAX_ARG_LEN = 4096
_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


class Decision(str, Enum):
    ALLOW = "allow"
    BLOCK = "block"
    NEEDS_CONFIRM = "needs_confirmation"


@dataclass
class PolicyResult:
    decision: Decision
    command_path: Path
    args: list[str]
    reason: str = ""
    stripped: list[str] = field(default_factory=list)
    long_running: bool = False
    help: bool = False


class PolicyError(ValueError):
    """Raised for malformed or disallowed arguments."""


def command_path(args: list[str]) -> Path:
    """Return the longest known command path at the start of ``args``.

    Unknown commands fall back to the leading non-flag words (at most two), so
    prefix rules still apply to commands added in newer CLI versions.
    """
    words: list[str] = []
    for a in args:
        if a.startswith("-"):
            break
        words.append(a)
    best: Path = ()
    for i in range(1, len(words) + 1):
        if tuple(words[:i]) in KNOWN_COMMANDS:
            best = tuple(words[:i])
    if not best:
        best = tuple(words[:2])
    return best


def env_scoped(path: Path) -> bool:
    """Whether the command takes `--env` (see NON_ENV_GROUPS)."""
    return bool(path) and path[0] not in NON_ENV_GROUPS


def positionals(args: list[str], path: Path) -> list[str]:
    """Non-flag words after the command path (targets such as container or project names)."""
    return [a for a in args[len(path):] if not a.startswith("-")]


def _flag_name(token: str) -> str:
    return token.split("=", 1)[0] if token.startswith("-") else ""


def _matches(path: Path, rule: Rule) -> bool:
    return path[: len(rule.prefix)] == rule.prefix


def _has_flag(args: list[str], names: tuple[str, ...]) -> bool:
    return any(_flag_name(a) in names for a in args)


def check_tokens(args: list[str]) -> None:
    if not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        raise PolicyError("args must be a list of strings")
    if len(args) > MAX_ARGS:
        raise PolicyError(f"too many arguments (max {MAX_ARGS})")
    for a in args:
        if len(a) > MAX_ARG_LEN:
            raise PolicyError(f"argument too long (max {MAX_ARG_LEN} characters)")
        if _CONTROL.search(a):
            raise PolicyError("arguments may not contain control characters or newlines")


def sanitize_args(args: list[str]) -> tuple[list[str], list[str]]:
    """Strip confirmation/output flags and reject unsafe ones.

    Returns ``(clean_args, stripped)``. Raises ``PolicyError`` on rejection.
    """
    check_tokens(args)
    if args and args[0] in {"arcane-cli", "arcane"}:
        raise PolicyError("Do not include the binary name; start with the command group, e.g. ['containers', 'list'].")
    path = command_path(args)
    clean: list[str] = []
    stripped: list[str] = []
    i = 0
    while i < len(args):
        tok = args[i]
        name = _flag_name(tok)
        has_inline_value = "=" in tok
        if name in REJECT_FLAGS:
            raise PolicyError(REJECT_FLAGS[name])
        if re.match(r"^-[A-Za-z]{2,}$", tok):
            # Bundled short flags like `-yf` would hide --yes/--force from the checks above.
            raise PolicyError(f"Combined short flags ({tok}) are not supported; pass each flag separately.")
        if name == "-f" and path in FORCE_SHORT_F:
            stripped.append(tok)
            i += 1
            continue
        if name in LOCAL_FILE_FLAGS and not (path in REMOTE_FILE_FLAG_OK and name in {"-f", "--file"}):
            raise PolicyError(
                f"`{name}` reads a file from the MCP server's filesystem, which is not supported. "
                "Use the Arcane web UI for operations that need local files."
            )
        if name in STRIP_FLAGS or name in STRIP_DIAGNOSTIC_FLAGS:
            stripped.append(tok)
            i += 1
            continue
        if name in STRIP_FLAGS_WITH_VALUE or name in STRIP_DIAGNOSTIC_FLAGS_WITH_VALUE:
            stripped.append(tok)
            i += 1
            if not has_inline_value and i < len(args) and not args[i].startswith("-"):
                stripped.append(args[i])
                i += 1
            continue
        clean.append(tok)
        i += 1

    if path == _p("images build"):
        positionals = [a for a in clean[len(path):] if not a.startswith("-")]
        if positionals and not re.match(r"^(https?://|git@|ssh://)", positionals[0]):
            raise PolicyError("`images build` only accepts a git URL as the build context through MCP.")
    return clean, stripped


def evaluate(args: list[str], *, confirm: bool, readonly: bool) -> PolicyResult:
    clean, stripped = sanitize_args(args)
    path = command_path(clean)
    if not path:
        raise PolicyError("No command given. Example: ['containers', 'list'].")
    long_running = path in LONG_RUNNING

    def result(decision: Decision, reason: str = "") -> PolicyResult:
        return PolicyResult(decision, path, clean, reason, stripped, long_running, is_help)

    is_help = _has_flag(clean, ("--help", "-h"))

    for rule in BLOCKED:
        if _matches(path, rule) and not (rule.unless_flags and _has_flag(clean, rule.unless_flags)):
            return result(Decision.BLOCK, f"`{' '.join(path)}` is blocked: {rule.reason}")

    if is_help:
        return result(Decision.ALLOW)

    if readonly:
        allowed = any(
            path == rule.prefix and (not rule.requires_flags or _has_flag(clean, rule.requires_flags))
            for rule in READONLY
        )
        if not allowed:
            return result(
                Decision.BLOCK,
                f"`{' '.join(path)}` is not permitted: the server is in read-only mode (ARCANE_MCP_READONLY=true).",
            )
        return result(Decision.ALLOW)

    needs_confirm = next((r.reason for r in CONFIRM if _matches(path, r)), None)
    if needs_confirm is None and path and path[-1] in CONFIRM_VERBS:
        needs_confirm = "This command removes data."
    if needs_confirm is not None and not confirm:
        return result(Decision.NEEDS_CONFIRM, needs_confirm)
    return result(Decision.ALLOW)
