"""Value-based redaction: secrets inside values must not survive any of the three output paths."""

import io
import json
from types import SimpleNamespace

import httpx
import pytest

from arcane_mcp import cli as cli_mod
from arcane_mcp.api import ApiClient
from arcane_mcp.audit import REDACTED, AuditLog, Redactor
from arcane_mcp.compose_edit import ComposeEditor

PG_PW = "Pg-Pl41ntext-Passw0rd"
REDIS_PW = "redisHunter22"
MONGO_PW = "m0ngoS3cret"
QUERY_TOKEN = "qtok_9f8e7d6c5b4a"
JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
GHP = "ghp_" + "A1b2C3d4E5" * 4
PEM_BODY = "MIIEowIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun"
PEM = f"-----BEGIN RSA PRIVATE KEY-----\n{PEM_BODY}\n-----END RSA PRIVATE KEY-----"
HTPASSWD = "$$apr1$$H6uskkkW$$IgXLP6ewTrSuBkTrqE8wj/"
SK = "sk-proj-" + "x7Y" * 10
AKIA = "AKIAIOSFODNN7EXAMPLE"
BEARER = "abcDEF123456ghiJKL"

SECRETS = [PG_PW, REDIS_PW, MONGO_PW, QUERY_TOKEN, JWT, GHP, PEM_BODY, HTPASSWD, "IgXLP6ewTrSuBkTrqE8wj", SK,
           AKIA, BEARER]


def container_inspect() -> dict:
    """Shaped like `containers get` on Arcane v2.17.0 (synthetic values)."""
    return {"success": True, "data": {
        "id": "f" * 64,
        "name": "litellm",
        "config": {
            "env": [
                f"DATABASE_URL=postgresql://litellm:{PG_PW}@litellm-db:5432/litellm",
                f"REDIS_URL=redis://:{REDIS_PW}@cache:6379/0",
                f"MONGO_URI=mongodb+srv://admin:{MONGO_PW}@cluster0.example.mongodb.net/db?retryWrites=true",
                f"WEBHOOK=https://hooks.example.com/x?token={QUERY_TOKEN}&v=1",
                f"SESSION={JWT}",
                f"GH={GHP}",
                f"OPENAI={SK}",
                f"AWS_ID={AKIA}",
                "UI_USERNAME=admin",
                "PLAIN_URL=https://example.com/path",
            ],
            "cmd": ["--header", f"Authorization: Bearer {BEARER}", "--tls-key", PEM],
            "entrypoint": ["sh", "-c", f"exec app --db postgres://app:{PG_PW}@db/app"],
            "labels": {
                "traefik.http.middlewares.auth.basicauth.users": f"admin:{HTPASSWD}",
                "com.example.note": f"mirror at https://u:{PG_PW}@mirror.example.com",
                "com.docker.compose.project": "litellm",
            },
        },
    }}


def assert_clean(blob):
    text = json.dumps(blob) if not isinstance(blob, str) else blob
    leaked = [s for s in SECRETS if s in text]
    assert not leaked, f"secrets survived: {leaked}"


@pytest.mark.parametrize("text,expected", [
    (f"postgresql://litellm:{PG_PW}@db:5432/x", f"postgresql://litellm:{REDACTED}@db:5432/x"),
    (f"rediss://:{REDIS_PW}@cache", f"rediss://:{REDACTED}@cache"),
    (f"amqp://guest:{PG_PW}@mq/vhost", f"amqp://guest:{REDACTED}@mq/vhost"),
    (f"smtp://mailer:{PG_PW}@smtp.example.com:587", f"smtp://mailer:{REDACTED}@smtp.example.com:587"),
    (f"ftp://u:{PG_PW}@files", f"ftp://u:{REDACTED}@files"),
    (f"mysql://root:{PG_PW}@db/x?sslmode=require", f"mysql://root:{REDACTED}@db/x?sslmode=require"),
    (f"https://x/y?apikey={QUERY_TOKEN}", f"https://x/y?apikey={REDACTED}"),
    (f"https://x/y?a=1&sig={QUERY_TOKEN}#f", f"https://x/y?a=1&sig={REDACTED}#f"),
    (f"Authorization: Basic {BEARER}", f"Authorization: Basic {REDACTED}"),
    ("SENTRY_DSN=https://abc@sentry.io/1", f"SENTRY_DSN={REDACTED}"),
    ("SMTP_PASS=hunter2", f"SMTP_PASS={REDACTED}"),
    ("DB_PWD=hunter2", f"DB_PWD={REDACTED}"),
])
def test_value_patterns(text, expected):
    assert Redactor().text(text) == expected


@pytest.mark.parametrize("text", [
    "postgres://app:${DB_PASSWORD}@db/app",
    "DATABASE_URL: ${DATABASE_URL:?required}",
    "Uses Basic authentication with a Bearer token",
    "image: postgres:14@sha256:" + "a" * 64,
    "https://example.com/path?page=2&limit=10",
    "ssh://git@github.com/owner/repo.git",
    "disk-usage-abcdefghijklmnopqrstuvwxyz0123",
    "PASSTHROUGH=1",
])
def test_non_secrets_untouched(text):
    assert Redactor().text(text) == text


def test_redaction_is_idempotent():
    r = Redactor()
    once = r.text(f"postgres://u:{PG_PW}@db and SMTP_PASSWORD=x")
    assert r.text(once) == once


def test_arcane_run_container_get(runner, monkeypatch):
    stdout = json.dumps(container_inspect())
    monkeypatch.setattr(cli_mod.subprocess, "run",
                        lambda argv, **kw: SimpleNamespace(returncode=0, stdout=stdout, stderr=""))
    r = runner.run(["containers", "get", "litellm"])
    assert r["ok"] is True
    assert_clean(r)
    env = r["data"]["data"]["config"]["env"]
    assert f"DATABASE_URL=postgresql://litellm:{REDACTED}@litellm-db:5432/litellm" in env
    assert "UI_USERNAME=admin" in env and "PLAIN_URL=https://example.com/path" in env
    labels = r["data"]["data"]["config"]["labels"]
    assert labels["traefik.http.middlewares.auth.basicauth.users"] == REDACTED
    assert labels["com.docker.compose.project"] == "litellm"


def test_arcane_run_non_json_output(runner, monkeypatch):
    stdout = f"connecting to postgres://u:{PG_PW}@db with {GHP}\n"
    monkeypatch.setattr(cli_mod.subprocess, "run",
                        lambda argv, **kw: SimpleNamespace(returncode=1, stdout=stdout, stderr=stdout))
    r = runner.run(["containers", "get", "x"])
    assert_clean(r)


def test_api_get(settings):
    redactor = Redactor(settings.secrets())
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json=container_inspect()))
    api = ApiClient(settings, redactor, AuditLog(None, redactor, io.StringIO()), transport=transport)
    r = api.get("/api/environments/0/containers/litellm")
    assert r["ok"] is True
    assert_clean(r)


COMPOSE = f"""\
services:
  app:
    image: ghcr.io/example/app:latest
    environment:
      DATABASE_URL: postgresql://app:{PG_PW}@db:5432/app
      REDIS_URL: "redis://:{REDIS_PW}@cache:6379"
      API_KEY: ${{API_KEY:?required}}
    labels:
      - "traefik.http.middlewares.auth.basicauth.users=admin:{HTPASSWD}"
    command: ["--token", "{GHP}"]
"""


@pytest.fixture
def editor(settings, monkeypatch):
    redactor = Redactor(settings.secrets())
    audit = AuditLog(None, redactor, io.StringIO())
    project_id = "2e604cd4-7a09-46dc-86d8-afefd54f7b54"
    monkeypatch.setattr(cli_mod.subprocess, "run", lambda argv, **kw: SimpleNamespace(
        returncode=0, stderr="", stdout=json.dumps({"data": {"id": project_id, "name": "app"}})))
    transport = httpx.MockTransport(lambda req: httpx.Response(200, json={"data": {
        "composeFileName": "compose.yaml", "composeContent": COMPOSE, "envContent": "X=1"}}))
    runner = cli_mod.CliRunner(settings, redactor, audit)
    return ComposeEditor(runner, ApiClient(settings, redactor, audit, transport=transport), redactor, audit)


def test_project_compose_read(editor):
    r = editor.read("app")
    assert r["ok"] is True
    assert_clean(r)
    assert f"postgresql://app:{REDACTED}@db:5432/app" in r["compose"]
    assert "API_KEY: ${API_KEY:?required}" in r["compose"]


def test_project_compose_write_refuses_url_marker(editor):
    r = editor.read("app")
    r2 = editor.write("app", r["compose"].replace("ghcr.io/example/app:latest", "ghcr.io/example/app:v2"))
    assert r2["ok"] is False and REDACTED in r2["error"]
