import pytest

from arcane_mcp import policy
from arcane_mcp.policy import Decision, PolicyError, command_path, evaluate, sanitize_args


def ev(*args, confirm=False, readonly=False):
    return evaluate(list(args), confirm=confirm, readonly=readonly)


# --- blocked ---------------------------------------------------------------------

BLOCKED_CASES = [
    ["auth", "login"],
    ["auth", "logout"],
    ["auth", "api-keys", "create", "--name", "x"],
    ["self-update", "run"],
    ["self-update", "channel", "next"],
    ["admin", "backups", "restore", "b1"],
    ["admin", "backups", "recovery", "generate"],
    ["system", "upgrade"],
    ["system", "upgrade", "--all"],
    ["generate", "secret"],
    ["generate", "apikey"],
    ["admin", "users", "list"],
    ["admin", "users", "create", "--username", "bob"],
    ["admin", "roles", "assign", "x"],
    ["admin", "federated", "list"],
    ["admin", "oidc", "list"],
    ["admin", "api-keys", "list"],
    ["settings", "update", "k", "v"],
    ["config", "show"],
    ["config", "set", "api-key", "x"],
    ["images", "upload", "/tmp/x.tar"],
    ["images", "export", "nginx", "/tmp/out.tar"],
    ["volumes", "workspace", "put", "vol", "/etc/passwd", "/x"],
    ["volumes", "backups", "download", "v", "b"],
    ["templates", "download", "t1"],
]


@pytest.mark.parametrize("args", BLOCKED_CASES, ids=lambda a: " ".join(a))
@pytest.mark.parametrize("confirm", [False, True])
@pytest.mark.parametrize("readonly", [False, True])
def test_blocked_even_with_confirm(args, confirm, readonly):
    r = ev(*args, confirm=confirm, readonly=readonly)
    assert r.decision is Decision.BLOCK
    assert "blocked" in r.reason or "read-only" in r.reason


@pytest.mark.parametrize("flag", ["--check", "--status"])
def test_system_upgrade_check_allowed(flag):
    assert ev("system", "upgrade", flag).decision is Decision.ALLOW
    assert ev("system", "upgrade", flag, readonly=True).decision is Decision.ALLOW


def test_help_on_blocked_command_still_blocked():
    assert ev("auth", "login", "--help").decision is Decision.BLOCK


# --- confirm ---------------------------------------------------------------------

CONFIRM_CASES = [
    ["projects", "destroy", "foo"],
    ["projects", "destroy", "foo", "--remove-volumes"],
    ["projects", "down", "foo"],
    ["system", "prune"],
    ["images", "prune"],
    ["images", "prune", "--dangling"],
    ["images", "remove", "nginx:old"],
    ["volumes", "delete", "data"],
    ["volumes", "prune"],
    ["containers", "delete", "web"],
    ["networks", "delete", "n1"],
    ["networks", "prune"],
    ["podman", "secrets", "create", "s"],
    ["podman", "secrets", "update", "s"],
    ["gitops", "delete", "s1"],  # generic *delete* verb
    ["activities", "clear"],
]


@pytest.mark.parametrize("args", CONFIRM_CASES, ids=lambda a: " ".join(a))
def test_confirm_required(args):
    r = ev(*args)
    assert r.decision is Decision.NEEDS_CONFIRM
    assert ev(*args, confirm=True).decision is Decision.ALLOW


@pytest.mark.parametrize("args", CONFIRM_CASES, ids=lambda a: " ".join(a))
def test_confirm_commands_denied_in_readonly(args):
    assert ev(*args, confirm=True, readonly=True).decision is Decision.BLOCK


def test_projects_destroy_with_yes_still_needs_confirm():
    r = ev("projects", "destroy", "foo", "--yes")
    assert r.decision is Decision.NEEDS_CONFIRM
    assert "--yes" not in r.args and "--yes" in r.stripped


# --- readonly ----------------------------------------------------------------------

READONLY_OK = [
    ["containers", "list", "--all"],
    ["containers", "get", "web"],
    ["containers", "updates"],
    ["projects", "list"],
    ["projects", "get", "immich"],
    ["volumes", "sizes"],
    ["volumes", "usage", "data"],
    ["updater", "status"],
    ["updater", "history", "-n", "5"],
    ["images", "vulnerabilities", "summary"],
    ["images", "vulnerabilities", "image", "nginx:latest", "--severity", "critical,high"],
    ["auth", "me"],
    ["environments", "test", "0"],
    ["environments", "list"],
    ["doctor"],
    ["activities", "list", "--status", "failed"],
    ["gitops", "status", "s1"],
    ["version"],
    ["projects", "redeploy", "--help"],
    ["variables", "sync", "--status"],
]

READONLY_DENY = [
    ["containers", "update", "web"],
    ["containers", "restart", "web"],
    ["containers", "stop", "web"],
    ["projects", "up", "foo"],
    ["projects", "redeploy", "foo"],
    ["images", "pull", "nginx"],
    ["images", "updates", "check"],
    ["images", "vulnerabilities", "ignore", "CVE-1", "--reason", "x"],
    ["gitops", "sync", "s1"],
    ["updater", "run"],
    ["webhooks", "trigger", "tok"],
    ["variables", "sync"],
    ["containers", "brand-new-verb"],  # default deny for unknown commands
    ["newgroup", "list"],
]


@pytest.mark.parametrize("args", READONLY_OK, ids=lambda a: " ".join(a))
def test_readonly_allows(args):
    assert ev(*args, readonly=True).decision is Decision.ALLOW


@pytest.mark.parametrize("args", READONLY_DENY, ids=lambda a: " ".join(a))
def test_readonly_denies(args):
    r = ev(*args, readonly=True, confirm=True)
    assert r.decision is Decision.BLOCK
    assert "read-only" in r.reason
    # ...but they are fine (no confirm needed) in normal mode
    assert ev(*args).decision is Decision.ALLOW


def test_every_readonly_rule_is_a_known_command():
    unknown = [r.prefix for r in policy.READONLY if r.prefix not in policy.KNOWN_COMMANDS]
    assert unknown == []


def test_no_readonly_rule_is_blocked_or_needs_confirm():
    for rule in policy.READONLY:
        args = list(rule.prefix) + list(rule.requires_flags[:1])
        assert ev(*args, readonly=True).decision is Decision.ALLOW, rule


# --- command path resolution -----------------------------------------------------------


@pytest.mark.parametrize(
    "args,expected",
    [
        (["containers", "get", "list"], ("containers", "get")),
        (["images", "vulnerabilities", "image", "nginx"], ("images", "vulnerabilities", "image")),
        (["admin", "backups", "restore", "x"], ("admin", "backups", "restore")),
        (["projects", "destroy", "--remove-volumes", "x"], ("projects", "destroy")),
        (["doctor"], ("doctor",)),
        (["mystery", "cmd", "arg"], ("mystery", "cmd")),
    ],
)
def test_command_path(args, expected):
    assert command_path(args) == expected


def test_positional_named_like_blocked_group_is_not_blocked():
    # A container literally named "auth" must not trip the `auth` rules.
    assert ev("containers", "get", "auth").decision is Decision.ALLOW


# --- sanitisation ---------------------------------------------------------------------


@pytest.mark.parametrize(
    "args,clean,stripped",
    [
        (["containers", "list", "--json"], ["containers", "list"], ["--json"]),
        (["containers", "list", "--json=true"], ["containers", "list"], ["--json=true"]),
        (["containers", "list", "--output", "json"], ["containers", "list"], ["--output", "json"]),
        (["containers", "list", "--output=text"], ["containers", "list"], ["--output=text"]),
        (["projects", "destroy", "x", "--yes"], ["projects", "destroy", "x"], ["--yes"]),
        (["projects", "destroy", "x", "-y"], ["projects", "destroy", "x"], ["-y"]),
        (["projects", "destroy", "x", "--force"], ["projects", "destroy", "x"], ["--force"]),
        (["projects", "destroy", "x", "--force=true"], ["projects", "destroy", "x"], ["--force=true"]),
        (["containers", "delete", "x", "-f"], ["containers", "delete", "x"], ["-f"]),
        (["volumes", "delete", "x", "-f"], ["volumes", "delete", "x"], ["-f"]),
        (["containers", "list", "--log-level", "debug"], ["containers", "list"], ["--log-level", "debug"]),
        (["containers", "list", "--log-json"], ["containers", "list"], ["--log-json"]),
    ],
)
def test_sanitize_strips(args, clean, stripped):
    assert sanitize_args(args) == (clean, stripped)


@pytest.mark.parametrize(
    "args,message",
    [
        (["containers", "list", "--config", "/etc/x"], "managed by the MCP server"),
        (["containers", "list", "-c", "/etc/x"], "managed by the MCP server"),
        (["containers", "list", "--config=/etc/x"], "managed by the MCP server"),
        (["containers", "list", "--env", "2"], "env_id"),
        (["containers", "list", "--env=2"], "env_id"),
        (["projects", "update", "p", "-f", "/root/compose.yml"], "filesystem"),
        (["projects", "update", "p", "--file", "/x"], "filesystem"),
        (["projects", "create", "--env-file", "/proc/1/environ"], "filesystem"),
        (["containers", "create", "--file=/x.json"], "filesystem"),
        (["projects", "destroy", "x", "-yf"], "Combined short flags"),
        (["containers", "list", "a\nb"], "control characters"),
        (["containers", "list", "a\x00b"], "control characters"),
        (["arcane-cli", "containers", "list"], "binary name"),
        (["images", "build", "/srv/app"], "git URL"),
        (["x"] * (policy.MAX_ARGS + 1), "too many"),
        (["containers", "get", "a" * (policy.MAX_ARG_LEN + 1)], "too long"),
    ],
)
def test_sanitize_rejects(args, message):
    with pytest.raises(PolicyError, match=message):
        sanitize_args(args)


def test_images_build_git_context_with_dockerfile_path_ok():
    clean, _ = sanitize_args(["images", "build", "https://github.com/me/app.git", "-f", "docker/Dockerfile"])
    assert clean[-2:] == ["-f", "docker/Dockerfile"]


def test_args_must_be_strings():
    with pytest.raises(PolicyError):
        sanitize_args(["containers", 5])  # type: ignore[list-item]


def test_empty_command_rejected():
    with pytest.raises(PolicyError, match="No command"):
        ev("--all")


# --- long-running ------------------------------------------------------------------------


@pytest.mark.parametrize(
    "args",
    [["projects", "up", "x"], ["projects", "redeploy", "x"], ["projects", "pull", "x"], ["projects", "build", "x"],
     ["images", "pull", "nginx"], ["images", "build", "https://g/x.git"]],
)
def test_long_running(args):
    assert ev(*args).long_running is True


def test_not_long_running():
    assert ev("containers", "list").long_running is False
