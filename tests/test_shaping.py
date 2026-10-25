"""P1-P3 output shaping: compactors from real Node804 payloads, filters, activities, env names, errors."""

import io
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp import compact as c
from arcane_mcp.api import ApiClient
from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.cli import clean_error

FIXTURES = Path(__file__).parent / "fixtures"


def fixture(name):
    return json.loads((FIXTURES / name).read_text())


class ScriptedCli:
    """subprocess.run stand-in answering by command words; records every call."""

    def __init__(self, responses=None, envs=None):
        self.calls = []
        self.responses = responses or {}
        self.envs = envs if envs is not None else [{"id": "0", "name": "Node804"},
                                                   {"id": "e5c1", "name": "AWS ARM Micro"}]

    def __call__(self, argv, **kw):
        args = argv[4:]
        self.calls.append(args)
        if args[:2] == ["environments", "list"]:
            return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"data": self.envs}))
        for key, (code, out, err) in self.responses.items():
            if tuple(args[: len(key)]) == key:
                return SimpleNamespace(returncode=code, stderr=err,
                                       stdout=out if isinstance(out, str) else json.dumps(out))
        return SimpleNamespace(returncode=0, stderr="", stdout=json.dumps({"data": {"argv": args}}))

    def command_calls(self):
        return [a for a in self.calls if a[:2] != ["environments", "list"]]


@pytest.fixture
def cli(monkeypatch):
    def install(**kw):
        fake = ScriptedCli(**kw)
        monkeypatch.setattr(cli_mod.subprocess, "run", fake)
        return fake
    return install


# -- volumes sizes ------------------------------------------------------------------------------

def test_volume_sizes_snapshot():
    out, changed = c.compact(("volumes", "sizes"), fixture("node804-volumes-sizes.json"))
    assert changed
    assert out["summary"] == {
        "total": 53, "total_size": "4.7 GB", "named_count": 7, "anonymous_count": 46,
        "unreferenced_count": 47, "unreferenced_bytes": 1316558584, "unreferenced_size": "1.3 GB",
        "zero_size_count": 45, "anonymous_unreferenced_empty": 41,
    }
    assert out["named"][:2] == [
        {"name": "arcane-trivy-cache", "size": "3.4 GB", "bytes": 3415474482, "refCount": 1},
        {"name": "hermes_shared_volume", "size": "1.3 GB", "bytes": 1255367394, "refCount": 0},
    ]
    assert [v["name"][:8] for v in out["anonymous"]] == ["37765df0", "e892f90a", "ed0f9f6d", "28a63d49"]
    assert all(v["bytes"] for v in out["anonymous"])


@pytest.mark.parametrize("n,text", [(0, "0 B"), (999, "999 B"), (4553, "4.6 KB"), (3415474482, "3.4 GB"),
                                    (2_500_000_000_000, "2.5 TB")])
def test_human_size(n, text):
    assert c.human_size(n) == text


# -- jobs list ----------------------------------------------------------------------------------

def test_jobs_snapshot():
    out, changed = c.compact(("jobs", "list"), c.cleanup(fixture("node804-jobs-list.json")))
    assert changed and out["observedAt"] == "2026-10-22T14:21:41Z" and "offline" not in out
    by_id = {j["id"]: j for j in out["jobs"]}
    assert by_id["analytics-heartbeat"] == {
        "id": "analytics-heartbeat", "name": "Analytics Heartbeat", "category": "telemetry", "enabled": True,
        "schedule": "automatic (checked hourly; sent once per 24h)",
        "lastRun": {"status": "skipped", "finishedAt": "2026-10-22T14:00:00Z"},
    }
    assert by_id["auto-update"] == {
        "id": "auto-update", "name": "Auto Update", "category": "updates", "enabled": False,
        "schedule": "0 0 0 * * *", "unmetPrerequisites": ["Auto update enabled"],
    }
    polling = by_id["image-polling"]
    assert polling["nextRun"] == "2026-10-22T15:00:00Z"  # was -05:00
    assert polling["lastRun"]["status"] == "partial"
    assert polling["lastRun"]["message"] == "Image update check completed: 85 checked, 1 errors"
    assert polling["lastRun"]["failures"][0]["id"] == "bmmbmm01/oldprivileged-unifiosserver:latest"
    assert "denied" in polling["lastRun"]["failures"][0]["message"]
    assert polling["currentRun"] == {"status": "running", "startedAt": "2026-10-22T15:00:00Z", "progress": "64/85"}
    blob = json.dumps(out)
    for noise in ("attempts", "owner", "remoteAccepted", "settingsUrl", "steps"):
        assert noise not in blob
    assert len(blob) < len(json.dumps(fixture("node804-jobs-list.json"))) / 3


# -- containers get / labels / untagged images ----------------------------------------------------

def test_containers_get_strips_noisy_labels():
    data = {"data": {"name": "x", "labels": {
        "org.opencontainers.image.source": "https://github.com/x", "dev.chainguard.package.main": "x",
        "com.docker.compose.config-hash": "abc", "com.docker.compose.project": "media",
        "traefik.enable": "true"}, "config": {"Labels": {"org.opencontainers.image.version": "1"}}}}
    out, changed = c.compact(("containers", "get"), data)
    assert changed
    assert out["data"]["labels"] == {"com.docker.compose.project": "media", "traefik.enable": "true"}
    assert out["data"]["config"]["Labels"] == {}


def test_untagged_image_resolved_or_flagged():
    base = {"names": ["/tunnel"], "image": "sha256:" + "b" * 64, "state": "running"}
    flagged = c.container({**base, "labels": {}})
    assert flagged["image"] == "b" * 12 and flagged["image_untagged"] is True
    tagged = c.container({**base, "labels": {"com.docker.compose.image": "cloudflare/cloudflared:2026.9.0"}})
    assert tagged["image"] == "cloudflare/cloudflared:2026.9.0" and "image_untagged" not in tagged
    assert "image_untagged" not in c.container({**base, "image": "redis:7"})


# -- global cleanup -----------------------------------------------------------------------------

def test_cleanup():
    data = {"$schema": "https://10.1.21.104:3552/api/schemas/X.json", "grandTotalItems": 0,
            "pagination": {"grandTotalItems": 0, "totalItems": 3},
            "items": [{"$schema": "x", "at": "2026-10-22T09:00:00.581565308-05:00", "b": "2026-10-22T14:00:00Z"}],
            "keep": {"grandTotalItems": 87, "note": "2026-10-22 is a date, not a timestamp"}}
    assert c.cleanup(data) == {
        "pagination": {"totalItems": 3},
        "items": [{"at": "2026-10-22T14:00:00Z", "b": "2026-10-22T14:00:00Z"}],
        "keep": {"note": "2026-10-22 is a date, not a timestamp"},
    }


@pytest.mark.parametrize("tz", ["UTC", "America/Chicago", "Asia/Tokyo"])
def test_timestamps_use_the_offset_not_local_tz(monkeypatch, tz):
    import time
    monkeypatch.setenv("TZ", tz)
    time.tzset()
    try:
        assert c.cleanup("2026-10-22T09:00:23.397-05:00") == "2026-10-22T14:00:23Z"
        assert c.cleanup("2026-10-22T14:00:23.397Z") == "2026-10-22T14:00:23Z"
        assert c.cleanup("2026-10-23T01:30:00+09:00") == "2026-10-22T16:30:00Z"
    finally:
        monkeypatch.undo()
        time.tzset()


def test_cleanup_applies_to_every_run(runner, cli):
    cli(responses={("gitops", "list"): (0, {"$schema": "https://10.1.21.104:3552/x", "data": []}, "")})
    r = runner.run(["gitops", "list"], compact=False)
    assert "$schema" not in json.dumps(r) and "10.1.21.104" not in json.dumps(r)


# -- filters ------------------------------------------------------------------------------------

def containers_payload():
    def item(name, state, project, has_update):
        return {"id": name * 3, "names": [f"/{name}"], "image": f"{name}:latest", "state": state,
                "status": state, "labels": {"com.docker.compose.project": project},
                "updateInfo": {"hasUpdate": has_update}}
    return {"data": [item("litellm", "running", "litellm", True), item("LiteLLM", "created", "", False),
                     item("immich", "running", "immich", False), item("mealie", "exited", "mealie", True)],
            "pagination": {"totalItems": 4}}


@pytest.mark.parametrize("filters,names", [
    ({"state": "running"}, ["litellm", "immich"]),
    ({"state": "Created"}, ["LiteLLM"]),
    ({"has_update": True}, ["litellm", "mealie"]),
    ({"has_update": False}, ["LiteLLM", "immich"]),
    ({"project": "immich"}, ["immich"]),
    ({"name_contains": "lite"}, ["litellm", "LiteLLM"]),
    ({"state": "running", "has_update": True}, ["litellm"]),
    ({"state": None, "project": ""}, ["litellm", "LiteLLM", "immich", "mealie"]),
])
def test_filters(runner, cli, filters, names):
    cli(responses={("containers", "list"): (0, containers_payload(), "")})
    r = runner.run(["containers", "list", "--all"], filters=filters)
    assert [i["name"] for i in r["data"]["data"]] == names
    if any(v not in (None, "") for v in filters.values()):
        assert r["filtered"] == {"matched": len(names), "of": 4}


def test_filters_on_projects_match_project_name(runner, cli):
    cli(responses={("projects", "list"): (0, {"data": [{"name": "immich", "status": "running"},
                                                        {"name": "mealie", "status": "stopped"}]}, "")})
    r = runner.run(["projects", "list"], filters={"project": "mealie"})
    assert [p["name"] for p in r["data"]["data"]] == ["mealie"]
    r = runner.run(["projects", "list"], filters={"state": "running"})
    assert [p["name"] for p in r["data"]["data"]] == ["immich"]


def test_filters_on_non_list_are_reported(runner, cli):
    r = runner.run(["system", "info"], filters={"state": "running"})
    assert "filter_note" in r


# -- activities: exclude_types + collapse -------------------------------------------------------

def activity(i, type_, msg, status="success"):
    return {"id": f"a{i}", "type": type_, "status": status, "latestMessage": msg,
            "startedAt": f"2026-10-22T14:{59 - i:02d}:00Z", "durationMs": 10}


SYNC = "Successfully synced compose file from deploy/arcane/compose.yaml to project arcane-cli-mcp"


def activities_payload(n=60):
    items = []
    for i in range(n):
        if i % 6 == 5:
            items.append(activity(i, "image_update_check", "checked 85 images"))
        elif i % 10 == 3:
            items.append(activity(i, "project_deploy", f"deploy {i} failed", "failed"))
        else:
            items.append(activity(i, "job_run", SYNC))
    return {"data": items, "pagination": {"totalItems": 844}}


def test_collapse_repeats():
    items = [c.activity(a) for a in [activity(0, "job_run", SYNC), activity(1, "job_run", SYNC),
                                     activity(2, "job_run", SYNC), activity(3, "project_deploy", "x", "failed"),
                                     activity(4, "job_run", SYNC)]]
    out = c.collapse_repeats(items)
    assert len(out) == 3
    assert out[0]["repeated"] == 3 and out[0]["firstAt"] == "2026-10-22T14:57:00Z"
    assert out[0]["lastAt"] == "2026-10-22T14:59:00Z" and "id" not in out[0]
    assert out[1]["id"] == "a3" and "repeated" not in out[1]
    assert out[2]["id"] == "a4"


def test_activities_compact_collapses(runner, cli):
    cli(responses={("activities", "list"): (0, activities_payload(12), "")})
    r = runner.run(["activities", "list"])
    assert any(i.get("repeated") for i in r["data"]["data"])
    full = runner.run(["activities", "list"], compact=False)
    assert len(full["data"]["data"]) == 12


def test_exclude_types_overfetches_and_trims(runner, cli):
    fake = cli(responses={("activities", "list"): (0, activities_payload(60), "")})
    r = runner.run(["activities", "list", "--limit", "5"], exclude_types=["job_run", "image_update_check"])
    argv = fake.command_calls()[-1]
    assert argv[argv.index("--limit") + 1] == "50" and argv.count("--limit") == 1
    # 4 failures survive among 60 fetched; the other 56 are noise.
    assert [i["type"] for i in r["data"]["data"]] == ["project_deploy"] * 4
    assert r["excluded"] == 56
    assert "job_run" not in json.dumps(r["data"])


class PagedActivities:
    """Honours --limit like the real CLI: returns the newest N of a long, mostly-noise history."""

    def __init__(self, items):
        self.items, self.limits = items, []

    def __call__(self, argv, **kw):
        args = argv[4:]
        n = int(args[args.index("--limit") + 1]) if "--limit" in args else 20
        self.limits.append(n)
        return SimpleNamespace(returncode=0, stderr="",
                               stdout=json.dumps({"data": self.items[:n], "pagination": {"totalItems": 844}}))


def noisy_history(noise=3):
    # `noise` sync runs, then one deploy, repeated; consecutive syncs fold into one row.
    items, i = [], 0
    for block in range(600 // (noise + 1)):
        for _ in range(noise):
            items.append(activity(i % 60, "job_run", SYNC)); i += 1
        items.append(activity(i % 60, "project_deploy", f"deploy {block}")); i += 1
    return items


def test_limit_counts_rows_after_folding(runner, monkeypatch):
    fake = PagedActivities(noisy_history())
    monkeypatch.setattr(cli_mod.subprocess, "run", fake)
    # Excluding nothing relevant: 8 rows requested, each row is either a folded sync run or a deploy.
    r = runner.run(["activities", "list", "--limit", "8"], exclude_types=["image_update_check"])
    assert len(r["data"]["data"]) == 8 and fake.limits == [50]
    assert "_rows" not in r and "_fetched" not in r


def test_limit_refetches_once_when_page_was_too_sparse(runner, monkeypatch):
    fake = PagedActivities(noisy_history(noise=9))
    monkeypatch.setattr(cli_mod.subprocess, "run", fake)
    # Excluding the syncs leaves 1 deploy in 10: 100 fetched → 10 rows, short of 20, so fetch the maximum.
    r = runner.run(["activities", "list", "--limit", "20"], exclude_types=["job_run"])
    assert fake.limits == [100, 500] and len(r["data"]["data"]) == 20
    r = runner.run(["activities", "list", "--limit", "30"], exclude_types=["job_run"])
    assert len(r["data"]["data"]) == 30 and fake.limits[-2:] == [150, 500]
    assert "--limit 500" in r["command"]


def test_limit_no_refetch_when_history_is_exhausted(runner, monkeypatch):
    fake = PagedActivities(noisy_history()[:40])
    monkeypatch.setattr(cli_mod.subprocess, "run", fake)
    r = runner.run(["activities", "list", "--limit", "20"], exclude_types=["job_run"])
    assert fake.limits == [100] and len(r["data"]["data"]) == 10


def test_exclude_types_defaults_and_inline_limit(runner, cli):
    fake = cli(responses={("activities", "list"): (0, activities_payload(60), "")})
    runner.run(["activities", "list", "--status", "failed"], exclude_types=["job_run"])
    argv = fake.command_calls()[-1]
    assert argv[argv.index("--limit") + 1] == "100" and "--status" in argv
    runner.run(["activities", "list", "--limit=200"], exclude_types=["job_run"])
    argv = fake.command_calls()[-1]
    assert argv[argv.index("--limit") + 1] == "500" and "--limit=200" not in argv
    runner.run(["activities", "list", "--all"], exclude_types=["job_run"])
    assert "--limit" not in fake.command_calls()[-1]


def test_exclude_types_only_for_activities(runner, cli):
    fake = cli()
    r = runner.run(["containers", "list"], exclude_types=["job_run"])
    assert r["ok"] is False and "activities" in r["error"] and fake.command_calls() == []


# -- --env only for environment-scoped commands, --help routing --------------------------------------

@pytest.mark.parametrize("args,scoped", [
    (["version"], False), (["doctor"], False), (["auth", "me"], False), (["config", "path"], False),
    (["containers", "list"], True), (["environments", "list"], True), (["jobs", "list"], True),
])
def test_env_flag_only_when_scoped(runner, cli, args, scoped):
    fake = cli()
    runner.run(args, env_id="Node804")
    assert ("--env" in fake.calls[-1]) is scoped


def test_help_via_run_is_routed_to_arcane_cli_help(runner, monkeypatch):
    calls = []

    def fake(argv, **kw):
        calls.append(argv[4:])
        return SimpleNamespace(returncode=0, stderr="", stdout="USAGE   \n  arcane-cli containers list    \n\n")
    monkeypatch.setattr(cli_mod.subprocess, "run", fake)
    r = runner.run(["containers", "list", "--help"])
    assert calls == [["containers", "list", "--help"]]
    assert r["ok"] is True and r["help"] == "USAGE\n  arcane-cli containers list" and "raw_stdout" not in r
    r = runner.run(["generate", "secret", "-h"])
    assert "blocked" in r["policy"]


def test_raw_stdout_lines_are_stripped(runner, cli):
    cli(responses={("system", "info"): (0, "line one    \nline two   \n", "")})
    assert runner.run(["system", "info"])["raw_stdout"] == "line one\nline two"


@pytest.mark.parametrize("command", [["containers", "; id"], ["containers", "$(id)"], ["Containers"],
                                     ["containers", "--all"], ["containers", "list x"]])
def test_help_rejects_non_subcommand_tokens(runner, cli, command):
    fake = cli()
    r = runner.help(command)
    assert r["ok"] is False and "not a subcommand" in r["error"] and fake.calls == []


def test_help_warns_on_unknown_subcommand(runner, cli):
    cli()
    assert "not a known" in runner.help(["containers", "bogus"])["warning"]
    assert "warning" not in runner.help(["containers", "list"])
    assert "warning" not in runner.help([])


# -- env_id validation and names ------------------------------------------------------------------

def test_env_name_resolves_to_id(runner, cli):
    fake = cli()
    runner.run(["containers", "list"], env_id="aws arm micro")
    argv = fake.command_calls()[-1]
    assert argv[argv.index("--env") + 1] == "e5c1"


def test_unknown_env_lists_known(runner, cli):
    fake = cli()
    r = runner.run(["containers", "list"], env_id="7")
    assert r == {"ok": False, "error": "unknown env_id", "message": r["message"],
                 "known": [{"id": "0", "name": "Node804"}, {"id": "e5c1", "name": "AWS ARM Micro"}]}
    assert "Node804 (0)" in r["message"] and fake.command_calls() == []


def test_env_list_is_cached(runner, cli, monkeypatch):
    fake = cli()
    for env in ("0", "Node804", "e5c1"):
        runner.run(["containers", "list"], env_id=env)
    assert sum(1 for a in fake.calls if a[:2] == ["environments", "list"]) == 1
    clock = [cli_mod.time.monotonic() + cli_mod.ENV_CACHE_TTL_S + 1]
    monkeypatch.setattr(cli_mod.time, "monotonic", lambda: clock[0])
    runner.run(["containers", "list"], env_id="0")
    assert sum(1 for a in fake.calls if a[:2] == ["environments", "list"]) == 2


def test_env_passthrough_when_list_unavailable(runner, monkeypatch):
    def fake(argv, **kw):
        if argv[4:6] == ["environments", "list"]:
            return SimpleNamespace(returncode=1, stdout="", stderr="Error\n  forbidden")
        return SimpleNamespace(returncode=0, stdout="{}", stderr="")
    monkeypatch.setattr(cli_mod.subprocess, "run", fake)
    assert runner.run(["containers", "list"], env_id="9")["ok"] is True
    assert "env_id" in runner.run(["containers", "list"], env_id="AWS ARM Micro")["error"]


def test_default_env_not_looked_up(runner, cli):
    fake = cli()
    runner.run(["containers", "list"])
    assert not any(a[:2] == ["environments", "list"] for a in fake.calls)


# -- clean error messages ---------------------------------------------------------------------------

@pytest.mark.parametrize("stderr,error", [
    ("Error\n  unknown flag: --limit", "unknown flag: --limit"),
    ("\x1b[31mError\x1b[0m\n  project not found\n", "project not found"),
    ("Error: request failed (404)", "request failed (404)"),
    ("", None),
])
def test_clean_error(stderr, error):
    assert clean_error(stderr) == error


def test_error_field_on_failure(runner, cli):
    cli(responses={("volumes", "sizes"): (1, "", "Error\n  unknown flag: --limit")})
    r = runner.run(["volumes", "sizes", "--limit", "5"])
    assert r["ok"] is False and r["error"] == "unknown flag: --limit"
    assert r["stderr_tail"] == "Error\n  unknown flag: --limit"


# -- arcane_api_get: compact and fields -------------------------------------------------------------

def api(settings, payload):
    red = Redactor(settings.secrets())
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
    return ApiClient(settings, red, AuditLog(None, red, io.StringIO()), transport=transport)


def project_payload():
    return {"$schema": "https://10.1.21.104:3552/api/schemas/P.json", "success": True, "data": {
        "id": "p1", "name": "immich", "status": "running", "serviceCount": 2, "runningCount": 2,
        "updateInfo": {"hasUpdate": True, "imagesWithUpdates": 1},
        "serviceUpdates": [{"service": "server", "hasUpdate": True}],
        "updateInfoByRef": {"ghcr.io/immich-app/immich-server:release": {"hasUpdate": True, "x": "y" * 500}}}}


def test_api_single_project_drops_duplicate_update_info(settings):
    r = api(settings, project_payload()).get("/api/environments/0/projects/p1")
    assert r["compact"] is True and "updateInfoByRef" not in r["data"]["data"]
    assert r["data"]["data"]["serviceUpdates"] and "$schema" not in r["data"]
    full = api(settings, project_payload()).get("/api/environments/0/projects/p1", compact=False)
    assert "updateInfoByRef" in full["data"]["data"] and "$schema" not in full["data"]


def test_api_list_reuses_projections(settings):
    r = api(settings, containers_payload()).get("/api/environments/0/containers")
    assert r["compact"] is True and r["data"]["data"][0] == {
        "id": "litellmlitel", "name": "litellm", "image": "litellm:latest", "state": "running",
        "status": "running", "project": "litellm", "hasUpdate": True}


def test_api_fields(settings):
    r = api(settings, project_payload()).get("/api/environments/0/projects/p1",
                                             fields=["name", "updateInfo.hasUpdate", "missing.path"])
    assert r["data"]["data"] == {"name": "immich", "updateInfo": {"hasUpdate": True}}
    r = api(settings, containers_payload()).get("/api/environments/0/containers", fields=["names", "state"])
    assert r["data"]["data"][0] == {"names": ["/litellm"], "state": "running"}
    # Raw containers have `names`; `name` (as in the compact summaries) maps to the first one.
    r = api(settings, containers_payload()).get("/api/environments/0/containers", fields=["name", "image"])
    assert r["data"]["data"][0] == {"name": "litellm", "image": "litellm:latest"}
    r = api(settings, project_payload()).get("/api/environments/0/projects/p1", fields=["name"])
    assert r["data"]["data"] == {"name": "immich"}


@pytest.mark.parametrize("fields", ["name", [1], [""], ["."]])
def test_api_fields_validated(settings, fields):
    assert api(settings, {}).get("/api/environments", fields=fields)["ok"] is False
