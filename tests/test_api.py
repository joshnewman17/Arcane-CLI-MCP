import json

import httpx
import pytest

from arcane_mcp.api import ApiClient, ApiPathError, validate_path, validate_query
from arcane_mcp.audit import AuditLog, Redactor

from .conftest import API_KEY


@pytest.mark.parametrize(
    "path",
    ["/api/environments", "/api/environments/0/projects", "/api/openapi.json", "/api/environments/0/containers/abc-1"],
)
def test_valid_paths(path):
    assert validate_path(path) == path


@pytest.mark.parametrize(
    "path,msg",
    [
        ("", "required"),
        ("http://evil.example/api/x", "not a URL"),
        ("https://arcane.test/api/x", "not a URL"),
        ("//evil.example/api/x", "not a URL"),
        ("/api/../admin", r"'\.\.'"),
        ("/api/%2e%2e/x", r"'\.\.'"),
        ("/api/%252e%252e/x", r"'\.\.'"),
        ("/api/./x", r"'\.\.'"),
        ("/apix/environments", "must start with /api/"),
        ("/environments", "must start with /api/"),
        ("api/environments", "must start with /api/"),
        ("/api/x?apiKey=1", "query"),
        ("/api/x#frag", "query"),
        ("/api/x\\..\\y", "invalid"),
        ("/api/x%0d%0aHost: evil", "invalid"),
        ("/api/x y", "must start with /api/"),
    ],
)
def test_invalid_paths(path, msg):
    with pytest.raises(ApiPathError, match=msg):
        validate_path(path)


def test_validate_query():
    assert validate_query({"limit": 5, "all": True, "skip": None, "ids": [1, 2]}) == {
        "limit": "5", "all": "true", "ids": ["1", "2"]}
    with pytest.raises(ApiPathError):
        validate_query("limit=5")  # type: ignore[arg-type]


def make_client(settings, handler, stream):
    red = Redactor(settings.secrets())
    return ApiClient(settings, red, AuditLog(settings.audit_log_path, red, stream),
                     transport=httpx.MockTransport(handler))


def test_get_sends_api_key_and_returns_json(settings, audit_stream):
    seen = {}

    def handler(request: httpx.Request):
        seen["method"] = request.method
        seen["key"] = request.headers.get("X-Api-Key")
        seen["url"] = str(request.url)
        return httpx.Response(200, json={"data": [{"id": "0"}], "token": API_KEY})

    c = make_client(settings, handler, audit_stream)
    r = c.get("/api/environments", {"limit": 2})
    assert r["ok"] and r["status"] == 200
    assert seen == {"method": "GET", "key": API_KEY, "url": "http://arcane.test:3552/api/environments?limit=2"}
    assert r["data"]["token"] == "[REDACTED]"
    assert API_KEY not in audit_stream.getvalue()


def test_rejected_path_makes_no_request(settings, audit_stream):
    calls = []
    c = make_client(settings, lambda req: calls.append(req) or httpx.Response(200), audit_stream)
    r = c.get("/api/../../etc/passwd")
    assert r["ok"] is False and calls == []


def test_redirect_not_followed(settings, audit_stream):
    c = make_client(settings, lambda req: httpx.Response(302, headers={"Location": "http://evil/"}), audit_stream)
    r = c.get("/api/x")
    assert r["ok"] is False and r["status"] == 302


def test_non_json_and_truncation(settings, audit_stream, tmp_path):
    from .conftest import make_settings

    s = make_settings(tmp_path, max_output_chars=50)
    c = make_client(s, lambda req: httpx.Response(200, text="<html>" + "x" * 500), audit_stream)
    r = c.get("/api/docs")
    assert len(r["raw"]) == 50 and r["truncated"] is True


def test_http_error_is_redacted(settings, audit_stream):
    def handler(request):
        raise httpx.ConnectError(f"failed with key {API_KEY}")

    c = make_client(settings, handler, audit_stream)
    r = c.get("/api/x")
    assert r["ok"] is False and API_KEY not in json.dumps(r)


def test_openapi_like_payload_stays_json(settings, audit_stream):
    spec = {"components": {"schemas": {"Env": {"properties": {"apiKey": {"type": "string"}}}}},
            "paths": {"/api/x": {}}}
    c = make_client(settings, lambda req: httpx.Response(200, json=spec), audit_stream)
    r = c.get("/api/openapi.json")
    assert r["data"] == spec and "raw" not in r
