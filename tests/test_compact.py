"""Compact projections. Fixtures mirror Arcane v2.17.0 response shapes (synthetic values)."""

import json
from types import SimpleNamespace

import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp import compact as c


def container_item(i=0, **over):
    item = {
        "id": f"{i:040x}",
        "names": [f"/svc-{i}"],
        "image": "ghcr.io/example/app:latest",
        "imageId": "sha256:" + "a" * 64,
        "command": "/usr/bin/tini -- node app.js",
        "created": 1791010903,
        "ports": [{"ip": "0.0.0.0", "privatePort": 8080, "publicPort": 8088, "type": "tcp"},
                  {"ip": "::", "privatePort": 8080, "publicPort": 8088, "type": "tcp"},
                  {"privatePort": 9000, "type": "udp"}],
        "labels": {"com.docker.compose.project": "media", "com.docker.compose.service": "web",
                   **{f"org.opencontainers.image.l{n}": "x" * 60 for n in range(12)}},
        "state": "running",
        "status": "Up 2 days (healthy)",
        "hostConfig": {"networkMode": "bridge", "privileged": False},
        "networkSettings": {"networks": {"bridge": {"gwPriority": 0}, "media_default": {}}},
        "mounts": [{"type": "bind", "source": "/mnt/user/appdata/x", "destination": "/config"}] * 4,
        "updateStrategy": "digest",
        "updateInfo": {"checkTime": "2026-10-21T23:00:46Z", "currentVersion": "latest", "latestVersion": "",
                       "currentDigest": "sha256:1", "latestDigest": "sha256:2", "error": "", "hasUpdate": True},
        "redeployDisabled": False,
        "autoUpdateEnabled": True,
        "hidden": False,
    }
    item.update(over)
    return item


def wrap(items, **extra):
    return {"$schema": "https://x/schema.json", "success": True, "data": items,
            "pagination": {"totalItems": len(items)}, "resourceSortSupported": True, **extra}


def test_container_projection():
    out = c.container(container_item(1))
    assert out == {
        "id": "000000000000", "name": "svc-1", "image": "ghcr.io/example/app:latest", "state": "running",
        "status": "Up 2 days (healthy)", "health": "healthy", "project": "media", "service": "web",
        "ports": ["8088->8080/tcp", "9000/udp"], "networks": ["bridge", "media_default"],
        "hasUpdate": True, "autoUpdate": True,
    }


def test_container_update_error_and_no_health():
    out = c.container(container_item(status="Exited (0) 2 weeks ago", state="exited", labels={},
                                     updateInfo={"hasUpdate": False, "error": "manifest unknown"}))
    assert out["health"] if "health" in out else True
    assert "health" not in out and "project" not in out
    assert out["hasUpdate"] is False and out["updateError"] == "manifest unknown"


def test_container_compact_is_much_smaller():
    full = container_item()
    assert len(json.dumps(c.container(full))) * 5 < len(json.dumps(full))


def test_85_containers_fit_in_default_limit():
    data = wrap([container_item(i) for i in range(85)],
                counts={"runningContainers": 46, "stoppedContainers": 39, "totalContainers": 85})
    assert len(json.dumps(data)) > 40000
    out, changed = c.compact(("containers", "list"), data)
    assert changed and len(out["data"]) == 85
    assert len(json.dumps(out, separators=(",", ":"))) < 40000
    assert out["counts"]["totalContainers"] == 85 and out["pagination"] == {"totalItems": 85}
    assert "$schema" not in out and "resourceSortSupported" not in out


def test_project_projection():
    p = {"name": "media", "id": "uuid-1", "status": "running", "runningCount": 2, "serviceCount": 3,
         "path": "/app/data/projects/media", "tags": [],
         "updateInfo": {"hasUpdate": True, "imagesWithUpdates": 1, "errorCount": 0, "imageRefs": ["a", "b"]},
         "runtimeServices": [{"name": "web", "image": "nginx", "status": "running", "health": "healthy",
                              "containerId": "abc", "ports": []},
                             {"name": "db", "image": "postgres:16", "status": "exited", "health": ""}],
         "isArchived": False}
    assert c.project(p) == {
        "id": "uuid-1", "name": "media", "status": "running", "running": "2/3", "hasUpdate": True,
        "imagesWithUpdates": 1,
        "services": [{"name": "web", "status": "running", "health": "healthy", "image": "nginx"},
                     {"name": "db", "status": "exited", "image": "postgres:16"}],
    }


def test_image_projection():
    i = {"id": "sha256:f41b1fbe380d9f584b9cb7fc", "repoTags": ["example/unifi:10"], "size": 825648567,
         "inUse": True, "usedBy": [{"type": "container", "name": "unifi", "id": "x"}],
         "updateInfo": {"hasUpdate": False, "currentVersion": "10", "latestVersion": "10"},
         "vulnerabilityScan": {"status": "completed", "summary": {"critical": 2, "high": 9, "medium": 30}}}
    assert c.image(i) == {"id": "f41b1fbe380d", "tags": ["example/unifi:10"], "sizeMB": 826, "inUse": True,
                          "usedBy": ["unifi"], "hasUpdate": False, "vulns": {"critical": 2, "high": 9}}


def test_volume_network_activity_vuln_projections():
    assert c.volume({"name": "v", "driver": "local", "inUse": False, "size": 0, "containers": [],
                     "labels": {"com.docker.volume.anonymous": ""}, "mountpoint": "/var/lib/x"}) == \
        {"name": "v", "driver": "local", "inUse": False, "size": 0, "anonymous": True}
    assert c.network({"id": "4420bd2dc70f75ccc7f2", "name": "app_edge", "driver": "bridge", "scope": "local",
                      "inUse": True, "isDefault": False,
                      "labels": {"com.docker.compose.project": "app"}, "ipam": {}}) == \
        {"id": "4420bd2dc70f", "name": "app_edge", "driver": "bridge", "scope": "local", "inUse": True,
         "project": "app"}
    a = c.activity({"id": "a1", "type": "image_update_check", "status": "failed", "resourceType": "images",
                    "latestMessage": "done", "error": "done", "sourceEnvironmentName": "Node",
                    "startedAt": "t", "durationMs": 5, "batchId": "b"})
    assert a == {"id": "a1", "type": "image_update_check", "status": "failed", "resource": "images",
                 "message": "done", "environment": "Node", "startedAt": "t", "durationMs": 5}
    v = c.vulnerability({"vulnerabilityId": "CVE-1", "pkgName": "libssl", "installedVersion": "1",
                         "fixedVersion": "2", "severity": "HIGH", "title": "t" * 300,
                         "description": "long", "references": ["u"], "cvss": {"v3Score": 7.5}})
    assert v["id"] == "CVE-1" and v["cvss"] == 7.5 and len(v["title"]) == 120 and "description" not in v


@pytest.mark.parametrize("path", [("networks", "get"), ("doctor",), ("system", "info")])
def test_unknown_commands_untouched(path):
    data = wrap([{"a": 1}])
    assert c.compact(path, data) == (data, False)


def test_non_list_payload_untouched():
    assert c.compact(("containers", "list"), [{"status": "frame"}]) == ([{"status": "frame"}], False)


# --- through the runner ---------------------------------------------------------------


@pytest.fixture
def canned(monkeypatch):
    def install(payload):
        monkeypatch.setattr(cli_mod.subprocess, "run",
                            lambda argv, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(payload), stderr=""))
    return install


def test_runner_compacts_by_default(runner, canned):
    canned(wrap([container_item(i) for i in range(85)]))
    r = runner.run(["containers", "list", "--all"])
    assert r["compact"] is True and "truncated" not in r
    assert len(r["data"]["data"]) == 85 and r["data"]["data"][0]["name"] == "svc-0"


def test_runner_compact_false_returns_full(runner, canned):
    canned(wrap([container_item(0)]))
    r = runner.run(["containers", "list"], compact=False)
    assert "compact" not in r and "labels" in r["data"]["data"][0]


def test_environments_unaffected_by_compact(runner, canned):
    canned(wrap([{"id": "0", "name": "local", "status": "online", "apiUrl": "x"}]))
    assert runner.environments()["environments"] == [{"id": "0", "name": "local", "status": "online"}]
