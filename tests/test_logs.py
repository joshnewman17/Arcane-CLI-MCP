from datetime import datetime, timedelta, timezone

import httpx
import pytest

from arcane_mcp.api import ApiClient
from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.logs import LogCollector, LogError, line_time, parse_since

from .conftest import API_KEY, make_settings

CONTAINERS = {"data": [
    {"id": "a" * 64, "names": ["/web"], "state": "running", "labels": {"com.docker.compose.project": "shop"}},
    {"id": "b" * 64, "names": ["/web-db"], "state": "running", "labels": {"com.docker.compose.project": "shop"}},
    {"id": "c" * 64, "names": ["/other"], "state": "running", "labels": {}},
]}
LOG = "\n".join([
    "2026-10-24T01:00:00.123456789Z \x1b[2mstarting\x1b[0m",
    "2026-10-24T02:00:00.000000000Z ERROR boom",
    f"2026-10-24T03:00:00.000000000Z token={API_KEY}",
    "2026-10-24T04:00:00.000000000Z info ok",
    "2026-10-24T05:00:00.000000000Z error again",
]) + "\n"


def make(tmp_path, runner, audit_stream, handler=None, **overrides):
    settings = make_settings(tmp_path, **overrides)
    red = Redactor(settings.secrets())
    audit = AuditLog(settings.audit_log_path, red, audit_stream)

    def default(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/logs/download"):
            return httpx.Response(200, text=LOG)
        return httpx.Response(200, json=CONTAINERS)

    api = ApiClient(settings, red, audit, transport=httpx.MockTransport(handler or default))
    runner.settings = settings
    return LogCollector(api, runner, red, audit)


@pytest.fixture
def collector(tmp_path, runner, audit_stream):
    return make(tmp_path, runner, audit_stream)


def test_parse_since():
    now = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
    assert parse_since("30m", now) == now - timedelta(minutes=30)
    assert parse_since("2h", now) == now - timedelta(hours=2)
    assert parse_since("2026-10-24T01:00:00Z") == datetime(2026, 10, 24, 1, tzinfo=timezone.utc)
    assert parse_since(None) is None
    with pytest.raises(LogError):
        parse_since("yesterday")


def test_line_time_handles_nanoseconds():
    assert line_time("2026-10-24T01:00:00.123456789Z hi") == datetime(2026, 10, 24, 1, 0, 0, 123456, tzinfo=timezone.utc)
    assert line_time("no timestamp") is None


def test_tail_strips_ansi_and_redacts(collector):
    r = collector.collect(container="web", tail=3)
    assert r["ok"] is True
    sec = r["logs"][0]
    assert sec["container"] == "web" and sec["matched"] == 5 and sec["returned"] == 3
    assert sec["lines"][-1].endswith("error again")
    assert API_KEY not in str(r)
    assert "\x1b" not in str(collector.collect(container="web")["logs"])


def test_grep_and_since(collector):
    r = collector.collect(container="web", grep="error")
    assert [x.split(" ", 1)[1] for x in r["logs"][0]["lines"]] == ["ERROR boom", "error again"]
    assert collector.collect(container="web", grep="error", case_sensitive=True)["logs"][0]["matched"] == 1
    r = collector.collect(container="web", since="2026-10-24T03:30:00Z")
    assert r["logs"][0]["matched"] == 2


def test_name_resolution(collector):
    assert collector.collect(container="WEB")["logs"][0]["id"] == "a" * 12  # exact beats substring
    assert collector.collect(container="other")["logs"][0]["id"] == "c" * 12
    assert collector.collect(container="b" * 12)["logs"][0]["id"] == "b" * 12
    assert "no container matches" in collector.collect(container="nope")["error"]


def test_ambiguous_name(collector):
    r = collector.collect(container="we")
    assert r["ok"] is False and "ambiguous" in r["error"] and "web-db" in r["error"]


def test_project_collects_each_container(collector):
    r = collector.collect(project="shop", tail=1)
    assert [s["container"] for s in r["logs"]] == ["web", "web-db"]
    assert "no containers found" in collector.collect(project="ghost")["error"]


@pytest.mark.parametrize("kwargs,msg", [
    ({}, "exactly one"),
    ({"container": "a", "project": "b"}, "exactly one"),
    ({"container": "web", "tail": 0}, "tail"),
    ({"container": "web", "tail": 99999}, "tail"),
    ({"container": "web", "grep": "("}, "regular expression"),
    ({"container": "web", "grep": "x" * 500}, "limited"),
    ({"container": "../etc"}, "name or id"),
    ({"container": "web", "since": "soon"}, "since"),
])
def test_rejections(collector, kwargs, msg):
    r = collector.collect(**kwargs)
    assert r["ok"] is False and msg in r["error"]


def test_output_budget_drops_oldest(tmp_path, runner, audit_stream):
    big = "".join(f"2026-10-24T01:00:{i % 60:02d}Z line {i} {'x' * 100}\n" for i in range(500))

    def handler(request):
        if request.url.path.endswith("/logs/download"):
            return httpx.Response(200, text=big)
        return httpx.Response(200, json=CONTAINERS)

    c = make(tmp_path, runner, audit_stream, handler, max_output_chars=5000)
    sec = c.collect(container="web", tail=500)["logs"][0]
    assert sec["returned"] < 500 and "oldest" in sec["truncated"] and sec["lines"][-1].split()[2] == "499"


def test_http_error_from_arcane(tmp_path, runner, audit_stream):
    def handler(request):
        if request.url.path.endswith("/logs/download"):
            return httpx.Response(500, text="boom")
        return httpx.Response(200, json=CONTAINERS)

    r = make(tmp_path, runner, audit_stream, handler).collect(container="web")
    assert r["ok"] is False and "HTTP 500" in r["error"]


def test_audit_records_call(collector, audit_stream):
    collector.collect(container="web", grep="secret-pattern")
    out = audit_stream.getvalue()
    assert '"arcane_logs"' in out and "secret-pattern" not in out
