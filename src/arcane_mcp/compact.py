"""Compact projections for list commands.

Arcane's list responses carry everything (labels, mounts, update metadata...),
about 2.3K characters per container, so a homelab's container list blows past
MAX_OUTPUT_CHARS. With ``compact=true`` (the default), ``arcane_run`` maps each
item of a known list command to the fields below and keeps ``pagination`` and
``counts``. ``compact=false``, or a ``get`` on one item, returns full objects.

Projections are keyed by command path, like the tables in ``policy.py``.
``SHAPERS`` reshape whole responses that aren't ``{data: [...]}`` lists
(``volumes sizes``, ``jobs list``, ``containers get``). ``cleanup`` runs on every
response, compact or not. Field shapes verified against Arcane v2.17.0.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from datetime import datetime, timezone
from typing import Any

Item = dict[str, Any]
_HEALTH = re.compile(r"\((healthy|unhealthy|health: starting)\)")
_ANON_VOLUME = re.compile(r"^[0-9a-f]{64}$")
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2})T(\d{2}:\d{2}:\d{2})(?:\.\d+)?(Z|[+-]\d{2}:\d{2})$")
# Image metadata labels that say nothing about how a container is run.
NOISY_LABEL_PREFIXES = ("org.opencontainers.", "dev.chainguard.", "org.label-schema.", "com.docker.compose.config-hash")
TOP_NAMED_VOLUMES = 25
TOP_ANONYMOUS_VOLUMES = 10


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


def human_size(n: Any) -> Any:
    if not isinstance(n, (int, float)) or n < 0:
        return n
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def _image(c: Item, labels: Item) -> Item:
    """The image reference, resolving bare ``sha256:`` ids to a tag when compose recorded one."""
    image = c.get("image")
    if not (isinstance(image, str) and image.startswith("sha256:")):
        return {"image": image}
    tag = labels.get("com.docker.compose.image")
    if isinstance(tag, str) and tag and not tag.startswith("sha256:"):
        return {"image": tag}
    # Arcane can't check updates for an image it only knows by id, hence no hasUpdate.
    return {"image": _short(image), "image_untagged": True}


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
        **_image(c, labels),
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


def collapse_repeats(items: list[Any]) -> list[Any]:
    """Fold runs of consecutive activities with the same type, status and message into one entry."""
    out: list[Any] = []
    for item in items:
        prev = out[-1] if out else None
        key = ("type", "status", "message")
        if (isinstance(item, dict) and isinstance(prev, dict)
                and all(item.get(k) == prev.get(k) for k in key) and item.get("type")):
            times = [t for t in (prev.get("firstAt"), prev.get("lastAt"), prev.get("startedAt"),
                                 item.get("startedAt")) if t]
            prev["repeated"] = prev.get("repeated", 1) + 1
            if times:
                prev["firstAt"], prev["lastAt"] = min(times), max(times)
            prev.pop("startedAt", None)
            prev.pop("id", None)  # the ids differ; `activities get` needs the uncollapsed list
            prev.pop("durationMs", None)
            continue
        out.append(dict(item) if isinstance(item, dict) else item)
    return out


def volume_sizes(data: Any) -> Any:
    items = data.get("data") if isinstance(data, dict) else data
    if not isinstance(items, list):
        return None
    rows = sorted((v for v in items if isinstance(v, dict)), key=lambda v: v.get("size") or 0, reverse=True)

    def row(v: Item) -> Item:
        return {"name": v.get("name"), "size": human_size(v.get("size")), "bytes": v.get("size"),
                "refCount": v.get("refCount")}

    named = [v for v in rows if not _ANON_VOLUME.match(str(v.get("name", "")))]
    anonymous = [v for v in rows if _ANON_VOLUME.match(str(v.get("name", "")))]
    unreferenced = [v for v in rows if v.get("refCount") == 0]
    unref_bytes = sum(v.get("size") or 0 for v in unreferenced)
    return {
        "summary": {
            "total": len(rows),
            "total_size": human_size(sum(v.get("size") or 0 for v in rows)),
            "named_count": len(named),
            "anonymous_count": len(anonymous),
            "unreferenced_count": len(unreferenced),
            "unreferenced_bytes": unref_bytes,
            "unreferenced_size": human_size(unref_bytes),
            "zero_size_count": sum(1 for v in rows if not v.get("size")),
            "anonymous_unreferenced_empty": sum(1 for v in anonymous if not v.get("size") and v.get("refCount") == 0),
        },
        "named": [row(v) for v in named[:TOP_NAMED_VOLUMES]],
        "anonymous": [row(v) for v in anonymous[:TOP_ANONYMOUS_VOLUMES] if v.get("size")],
        "note": f"Largest {TOP_NAMED_VOLUMES} named and {TOP_ANONYMOUS_VOLUMES} non-empty anonymous volumes, "
                "by size. Pass compact=false for every volume.",
    }


def _progress(run: Item) -> str | None:
    steps = (run.get("outcome") or {}).get("steps") or run.get("steps") or []
    steps = [st for st in steps if isinstance(st, dict) and isinstance(st.get("total"), int)]
    if not steps:
        return None
    big = max(steps, key=lambda st: st["total"])
    return f"{big.get('completed', 0)}/{big['total']}"


def _run(run: Any, last_error: Any = None) -> Item | None:
    if not isinstance(run, dict):
        return None
    outcome = run.get("outcome") or {}
    failures = [
        {"id": t.get("id"), "message": _clip(t.get("message"), 200)}
        for t in outcome.get("targets") or []
        if isinstance(t, dict) and t.get("status") == "failed" and t.get("resourceType") != "workflow"
    ]
    return _drop_empty({
        "status": run.get("status") or outcome.get("status"),
        "startedAt": run.get("startedAt"),
        "finishedAt": run.get("finishedAt"),
        "message": _clip(outcome.get("message") or last_error, 200),
        "progress": _progress(run),
        "failures": failures[:5],
    })


def job(j: Item) -> Item:
    last = _run(j.get("lastRun"), j.get("lastError"))
    if last:
        last.pop("progress", None)
        last.pop("startedAt", None)
    return _drop_empty({
        "id": j.get("id"),
        "name": j.get("name"),
        "category": j.get("category"),
        "enabled": j.get("enabled"),
        "schedule": j.get("schedule"),
        "nextRun": j.get("nextRun"),
        "lastRun": last,
        "currentRun": _run(j.get("currentRun") or j.get("activeRun")),
        "unmetPrerequisites": [p.get("label") or p.get("settingKey") for p in j.get("prerequisites") or []
                               if isinstance(p, dict) and p.get("isMet") is False],
    })


def jobs(data: Any) -> Any:
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), list):
        return None
    return _drop_empty({
        "observedAt": data.get("observedAt"),
        "offline": data.get("offline") or None,
        "jobs": [job(j) if isinstance(j, dict) else j for j in data["jobs"]],
    })


def strip_noisy_labels(value: Any) -> Any:
    """Drop image-metadata labels (see NOISY_LABEL_PREFIXES) from any ``labels`` mapping."""
    if isinstance(value, list):
        return [strip_noisy_labels(v) for v in value]
    if not isinstance(value, dict):
        return value
    out = {}
    for k, v in value.items():
        if k in ("labels", "Labels") and isinstance(v, dict):
            v = {lk: lv for lk, lv in v.items() if not str(lk).startswith(NOISY_LABEL_PREFIXES)}
        out[k] = strip_noisy_labels(v)
    return out


def _normalize_ts(value: str) -> str:
    m = _TIMESTAMP.match(value)
    if not m:
        return value
    date, time, tz = m.groups()
    try:
        dt = datetime.fromisoformat(f"{date}T{time}{'+00:00' if tz == 'Z' else tz}")
    except ValueError:
        return value
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def cleanup(value: Any) -> Any:
    """Applied to every response: drop ``$schema`` (it leaks Arcane's internal URL) and
    ``grandTotalItems`` (inconsistent across endpoints), and normalise timestamps to UTC
    ``YYYY-MM-DDTHH:MM:SSZ``. The conversion uses the offset in the string, never the local TZ."""
    if isinstance(value, str):
        return _normalize_ts(value)
    if isinstance(value, list):
        return [cleanup(v) for v in value]
    if isinstance(value, dict):
        return {k: cleanup(v) for k, v in value.items()
                if k not in ("$schema", "grandTotalItems")}
    return value


# -- post-CLI filters (arcane_run filter_* parameters) -------------------------------------------

def _matches(view: Item, filters: dict[str, Any], is_project: bool) -> bool:
    state = filters.get("state")
    if state and str(view.get("state") or view.get("status") or "").lower() != str(state).lower():
        return False
    has_update = filters.get("has_update")
    if has_update is not None and bool(view.get("hasUpdate")) != bool(has_update):
        return False
    project = filters.get("project")
    if project and str(view.get("name" if is_project else "project") or "").lower() != str(project).lower():
        return False
    needle = filters.get("name_contains")
    if needle:
        hay = " ".join(str(x) for x in [view.get("name"), *(view.get("tags") or [])] if x)
        if str(needle).lower() not in hay.lower():
            return False
    return True


def apply_filters(path: tuple[str, ...], data: Any, filters: dict[str, Any]) -> tuple[Any, dict[str, int] | None]:
    """Filter list items by state / hasUpdate / project / name. Returns ``(data, {matched, of})``."""
    filters = {k: v for k, v in filters.items() if v not in (None, "")}
    if not filters or not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return data, None
    fn = PROJECTIONS.get(path)
    items = data["data"]
    kept = [i for i in items
            if not isinstance(i, dict) or _matches(fn(i) if fn else i, filters, path[:1] == ("projects",))]
    return {**data, "data": kept}, {"matched": len(kept), "of": len(items)}


def exclude_types(data: Any, types: list[str]) -> tuple[Any, int]:
    if not types or not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return data, 0
    drop = {t.lower() for t in types}
    kept = [i for i in data["data"] if not (isinstance(i, dict) and str(i.get("type", "")).lower() in drop)]
    return {**data, "data": kept}, len(data["data"]) - len(kept)


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


SHAPERS: dict[tuple[str, ...], Callable[[Any], Any]] = {
    _p("volumes sizes"): volume_sizes,
    _p("jobs list"): jobs,
    _p("containers get"): strip_noisy_labels,
}


def compact(path: tuple[str, ...], data: Any) -> tuple[Any, bool]:
    """Project list items for ``path``. Returns ``(data, changed)``."""
    shaper = SHAPERS.get(path)
    if shaper is not None:
        out = shaper(data)
        return (data, False) if out is None else (out, True)
    fn = PROJECTIONS.get(path)
    if fn is None or not isinstance(data, dict) or not isinstance(data.get("data"), list):
        return data, False
    items = [fn(item) if isinstance(item, dict) else item for item in data["data"]]
    if path == _p("activities list"):
        items = collapse_repeats(items)
    out = {k: v for k, v in data.items() if k not in {"$schema", "data", "resourceSortSupported"}}
    out["data"] = items
    return out, True


# -- arcane_api_get ------------------------------------------------------------------------------

_API_LIST = re.compile(r"^/api/environments/[^/]+/(containers|projects|images|volumes|networks)/?$")
_API_ONE = re.compile(r"^/api/environments/[^/]+/(containers|projects)/[^/]+/?$")


def compact_api(path: str, data: Any) -> tuple[Any, bool]:
    """Reuse the list projections for the matching REST paths, and slim single containers/projects."""
    m = _API_LIST.match(path)
    if m:
        return compact(("volumes" if m.group(1) == "volumes" else m.group(1), "list"), data)
    m = _API_ONE.match(path)
    if m and isinstance(data, dict):
        if m.group(1) == "containers":
            return strip_noisy_labels(data), True
        inner = data.get("data", data)
        if isinstance(inner, dict) and "updateInfoByRef" in inner:
            inner = {k: v for k, v in inner.items() if k != "updateInfoByRef"}  # duplicates serviceUpdates
            return ({**data, "data": inner} if "data" in data else inner), True
    return data, False


def _get_path(obj: Any, parts: list[str]) -> tuple[bool, Any]:
    for part in parts:
        if not isinstance(obj, dict) or part not in obj:
            return False, None
        obj = obj[part]
    return True, obj


# Names that differ between the compact summaries and Arcane's raw objects.
FIELD_ALIASES: dict[str, Callable[[Item], tuple[bool, Any]]] = {
    "name": lambda o: (True, str(o["names"][0]).lstrip("/"))
    if isinstance(o.get("names"), list) and o["names"] else (False, None),
}


def select_fields(obj: Any, fields: list[str]) -> Any:
    """Keep only ``fields`` (top-level or dotted paths) of an object."""
    if not isinstance(obj, dict):
        return obj
    out: Item = {}
    for f in fields:
        parts = [p for p in str(f).split(".") if p]
        found, value = _get_path(obj, parts)
        if not found and len(parts) == 1 and parts[0] in FIELD_ALIASES:
            found, value = FIELD_ALIASES[parts[0]](obj)
        if not found:
            continue
        node = out
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = value
    return out


def pick_fields(data: Any, fields: list[str]) -> Any:
    """Apply ``select_fields`` to each list item, or to the single object, under ``data`` if present."""
    if isinstance(data, list):
        return [select_fields(i, fields) for i in data]
    if isinstance(data, dict) and isinstance(data.get("data"), list):
        return {**data, "data": [select_fields(i, fields) for i in data["data"]]}
    if isinstance(data, dict) and isinstance(data.get("data"), dict):
        return {**data, "data": select_fields(data["data"], fields)}
    return select_fields(data, fields)
