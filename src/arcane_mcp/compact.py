"""Compact projections for list commands.

Arcane's list responses carry everything (labels, mounts, update metadata...),
about 2.3K characters per container, so a homelab's container list blows past
MAX_OUTPUT_CHARS. With ``compact=true`` (the default), ``arcane_run`` maps each
item of a known list command to the fields below and keeps ``pagination`` and
``counts``. ``compact=false``, or a ``get`` on one item, returns full objects.

Projections are keyed by command path, like the tables in ``policy.py``.
Field shapes verified against Arcane v2.17.0.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

Item = dict[str, Any]
_HEALTH = re.compile(r"\((healthy|unhealthy|health: starting)\)")


def _short(value: Any, n: int = 12) -> Any:
    if not isinstance(value, str):
        return value
    return value.split(":", 1)[1][:n] if value.startswith("sha256:") else value[:n]


def _clip(value: Any, n: int = 120) -> Any:
    return value if not isinstance(value, str) or len(value) <= n else value[: n - 1] + "…"


def _drop_empty(item: Item) -> Item:
    return {k: v for k, v in item.items() if v not in (None, "", [], {})}


def _update(info: Any) -> Item:
    if not isinstance(info, dict):
        return {}
    out: Item = {"hasUpdate": info.get("hasUpdate")}
    if info.get("latestVersion") and info.get("latestVersion") != info.get("currentVersion"):
        out["latestVersion"] = info["latestVersion"]
    if info.get("error"):
        out["updateError"] = _clip(info["error"])
    return out


def _ports(ports: Any) -> list[str]:
    seen: list[str] = []
    for p in ports or []:
        if not isinstance(p, dict):
            continue
        private, public, proto = p.get("privatePort"), p.get("publicPort"), p.get("type", "tcp")
        text = f"{public}->{private}/{proto}" if public else f"{private}/{proto}"
        if text not in seen:  # IPv4 and IPv6 bindings duplicate each other
            seen.append(text)
    return seen


def container(c: Item) -> Item:
    labels = c.get("labels") or {}
    names = c.get("names") or []
    status = c.get("status") or ""
    health = _HEALTH.search(status)
    networks = (c.get("networkSettings") or {}).get("networks") or {}
    return _drop_empty({
        "id": _short(c.get("id")),
        "name": names[0].lstrip("/") if names else None,
        "image": c.get("image"),
        "state": c.get("state"),
        "status": status,
        "health": health.group(1) if health else None,
        "project": labels.get("com.docker.compose.project"),
        "service": labels.get("com.docker.compose.service"),
        "ports": _ports(c.get("ports")),
        "networks": list(networks) if isinstance(networks, dict) else None,
        **_update(c.get("updateInfo")),
        "autoUpdate": c.get("autoUpdateEnabled"),
    })


def project(p: Item) -> Item:
    info = p.get("updateInfo") or {}
    services = [
        _drop_empty({"name": s.get("name"), "status": s.get("status"), "health": s.get("health"),
                     "image": s.get("image")})
        for s in p.get("runtimeServices") or []
        if isinstance(s, dict)
    ]
    return _drop_empty({
        "id": p.get("id"),
        "name": p.get("name"),
        "status": p.get("status"),
        "running": f"{p.get('runningCount', '?')}/{p.get('serviceCount', '?')}",
        "hasUpdate": info.get("hasUpdate"),
        "imagesWithUpdates": info.get("imagesWithUpdates") or None,
        "updateErrors": info.get("errorCount") or None,
        "services": services,
        "archived": p.get("isArchived") or None,
        "tags": p.get("tags"),
    })


def image(i: Item) -> Item:
    scan = (i.get("vulnerabilityScan") or {}).get("summary") or {}
    size = i.get("size")
    return _drop_empty({
        "id": _short(i.get("id")),
        "tags": i.get("repoTags"),
        "sizeMB": round(size / 1_000_000) if isinstance(size, (int, float)) and size >= 0 else None,
        "inUse": i.get("inUse"),
        "usedBy": [u.get("name") for u in i.get("usedBy") or [] if isinstance(u, dict)],
        **_update(i.get("updateInfo")),
        "vulns": {k: scan[k] for k in ("critical", "high") if k in scan} or None,
    })


def volume(v: Item) -> Item:
    return _drop_empty({
        "name": v.get("name"),
        "driver": v.get("driver"),
        "inUse": v.get("inUse"),
        "size": v.get("size"),
        "containers": v.get("containers"),
        "project": (v.get("labels") or {}).get("com.docker.compose.project"),
        "anonymous": True if "com.docker.volume.anonymous" in (v.get("labels") or {}) else None,
        "createdAt": v.get("createdAt"),
    })


def network(n: Item) -> Item:
    return _drop_empty({
        "id": _short(n.get("id")),
        "name": n.get("name"),
        "driver": n.get("driver"),
        "scope": n.get("scope"),
        "inUse": n.get("inUse"),
        "project": (n.get("labels") or {}).get("com.docker.compose.project"),
        "default": n.get("isDefault") or None,
    })


def activity(a: Item) -> Item:
    message = a.get("latestMessage")
    return _drop_empty({
        "id": a.get("id"),
        "type": a.get("type"),
        "status": a.get("status"),
        "resource": a.get("resourceType"),
        "message": _clip(message, 200),
        "error": _clip(a.get("error"), 300) if a.get("error") != message else None,
        "environment": a.get("sourceEnvironmentName"),
        "startedAt": a.get("startedAt"),
        "durationMs": a.get("durationMs"),
    })


def vulnerability(v: Item) -> Item:
    return _drop_empty({
        "id": v.get("vulnerabilityId"),
        "severity": v.get("severity"),
        "package": v.get("pkgName"),
        "installed": v.get("installedVersion"),
        "fixed": v.get("fixedVersion"),
        "cvss": (v.get("cvss") or {}).get("v3Score") or None,
        "title": _clip(v.get("title")),
    })


def _p(spec: str) -> tuple[str, ...]:
    return tuple(spec.split())


PROJECTIONS: dict[tuple[str, ...], Callable[[Item], Item]] = {
    _p("containers list"): container,
    _p("containers updates"): container,
    _p("projects list"): project,
    _p("projects updates"): project,
    _p("images list"): image,
    _p("volumes list"): volume,
    _p("networks list"): network,
    _p("activities list"): activity,
    _p("images vulnerabilities image"): vulnerability,
    _p("images vulnerabilities list"): vulnerability,
}


def compact(path: tuple[str, ...], data: Any) -> tuple[Any, bool]:
    """Project list items for ``path``. Returns ``(data, changed)``."""
    fn = PROJECTIONS.get(path)
    if fn is None or not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return data, False
    items = [fn(item) if isinstance(item, dict) else item for item in data["data"]]
    out = {k: v for k, v in data.items() if k not in {"$schema", "data", "resourceSortSupported"}}
    out["data"] = items
    return out, True
