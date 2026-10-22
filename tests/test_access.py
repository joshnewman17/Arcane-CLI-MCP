"""Cloudflare Access JWT validation and the HTTP auth middleware in Access mode."""

import io
import json
import sys
import time

import httpx
import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from arcane_mcp.access import AccessDenied, AccessVerifier, team_issuer
from arcane_mcp.config import ConfigError, load_settings, write_cli_config
from arcane_mcp.server import USER_HEADER, build_server, http_app

from .conftest import FAKE_CLI, make_settings

TEAM = "newmanshouse"
ISSUER = "https://newmanshouse.cloudflareaccess.com"
AUD = "c6c3528d039fad07dd8acfa4f2a542adafa0f053f1222d55073497ee6a980c04"


def keypair(kid):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    jwk = json.loads(RSAAlgorithm.to_jwk(key.public_key()))
    jwk.update(kid=kid, alg="RS256", use="sig")
    return key, jwk


KEY, JWK = keypair("k1")
OTHER_KEY, OTHER_JWK = keypair("k2")


def token(key=KEY, kid="k1", **overrides):
    now = int(time.time())
    claims = {"aud": [AUD], "iss": ISSUER, "iat": now, "exp": now + 300, "sub": "u-1",
              "email": "josh@newmanshouse.com", **overrides}
    claims = {k: v for k, v in claims.items() if v is not None}
    return jwt.encode(claims, key, algorithm="RS256", headers={"kid": kid})


class FakeJwks:
    def __init__(self, *keys):
        self.keys = list(keys)
        self.calls = 0
        self.fail = False

    def __call__(self, url):
        assert url == f"{ISSUER}/cdn-cgi/access/certs"
        self.calls += 1
        if self.fail:
            raise httpx.ConnectError("no route")
        return {"keys": self.keys}


@pytest.fixture
def jwks():
    return FakeJwks(JWK)


@pytest.fixture
def verifier(jwks):
    return AccessVerifier(TEAM, AUD, fetch_jwks=jwks)


@pytest.mark.parametrize("domain", ["newmanshouse", "newmanshouse.cloudflareaccess.com",
                                    "https://newmanshouse.cloudflareaccess.com/"])
def test_team_issuer(domain):
    assert team_issuer(domain) == ISSUER


def test_valid_token(verifier):
    ident = verifier.verify(token())
    assert ident.email == "josh@newmanshouse.com" and ident.subject == "u-1"


def test_string_audience_also_accepted(verifier):
    assert verifier.verify(token(aud=AUD)).email


@pytest.mark.parametrize(
    "bad",
    [
        pytest.param(lambda: None, id="missing"),
        pytest.param(lambda: "", id="empty"),
        pytest.param(lambda: "not.a.jwt", id="malformed"),
        pytest.param(lambda: token(aud=["some-other-app"]), id="wrong-audience"),
        pytest.param(lambda: token(iss="https://evil.cloudflareaccess.com"), id="wrong-issuer"),
        pytest.param(lambda: token(exp=int(time.time()) - 120, iat=int(time.time()) - 600), id="expired"),
        pytest.param(lambda: token(exp=None), id="no-exp"),
        pytest.param(lambda: token(key=OTHER_KEY, kid="k1"), id="forged-signature"),
        pytest.param(lambda: token(kid="unknown"), id="unknown-kid"),
        pytest.param(lambda: jwt.encode({"aud": AUD, "iss": ISSUER, "iat": 1, "exp": 4102444800}, "s" * 32,
                                        algorithm="HS256", headers={"kid": "k1"}), id="hs256-confusion"),
        pytest.param(lambda: jwt.encode({"aud": AUD, "iss": ISSUER, "iat": 1, "exp": 4102444800}, None,
                                        algorithm="none", headers={"kid": "k1"}), id="alg-none"),
    ],
)
def test_rejected(verifier, bad):
    with pytest.raises(AccessDenied):
        verifier.verify(bad())


def test_key_rotation_refetches_once_then_rate_limits():
    jwks = FakeJwks(JWK)
    clock = [1000.0]
    v = AccessVerifier(TEAM, AUD, fetch_jwks=jwks, clock=lambda: clock[0])
    v.verify(token())
    assert jwks.calls == 1
    jwks.keys.append(OTHER_JWK)  # Cloudflare publishes a new signing key
    clock[0] += 60
    assert v.verify(token(key=OTHER_KEY, kid="k2")).email  # unknown kid -> one refetch
    assert jwks.calls == 2
    with pytest.raises(AccessDenied):
        v.verify(token(kid="nope"))  # refetch is rate-limited
    assert jwks.calls == 2


def test_jwks_cached(verifier, jwks):
    for _ in range(5):
        verifier.verify(token())
    assert jwks.calls == 1


def test_fails_closed_without_keys(jwks):
    jwks.fail = True
    with pytest.raises(AccessDenied, match="cannot fetch"):
        AccessVerifier(TEAM, AUD, fetch_jwks=jwks).verify(token())


def test_keeps_cached_keys_when_refresh_fails():
    jwks = FakeJwks(JWK)
    clock = [0.0]
    v = AccessVerifier(TEAM, AUD, fetch_jwks=jwks, clock=lambda: clock[0])
    v.verify(token())
    jwks.fail = True
    clock[0] += 7200  # past the TTL
    assert v.verify(token()).email


# --- config ------------------------------------------------------------------------------------


def test_config_requires_both_access_settings():
    base = {"ARCANE_URL": "http://a", "ARCANE_API_KEY": "k"}
    with pytest.raises(ConfigError, match="both"):
        load_settings({**base, "CF_ACCESS_TEAM_DOMAIN": TEAM})
    with pytest.raises(ConfigError, match="both"):
        load_settings({**base, "CF_ACCESS_AUD": AUD})
    s = load_settings({**base, "CF_ACCESS_TEAM_DOMAIN": TEAM, "CF_ACCESS_AUD": AUD})
    assert s.access_enabled and not load_settings(base).access_enabled


# --- middleware, end to end -----------------------------------------------------------------------


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.fixture
def access_app(tmp_path, jwks):
    wrapper = tmp_path / "arcane-cli"
    wrapper.write_text(f"#!/bin/sh\nexec '{sys.executable}' '{FAKE_CLI}' \"$@\"\n")
    wrapper.chmod(0o755)
    settings = make_settings(tmp_path, cli_path=str(wrapper), access_team_domain=TEAM, access_aud=AUD)
    write_cli_config(settings)
    stream = io.StringIO()
    app = http_app(settings, build_server(settings, audit_stream=stream),
                   verifier=AccessVerifier(TEAM, AUD, fetch_jwks=jwks))
    return app, stream, settings


MCP_HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
INIT = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "t", "version": "1"}}}


async def _client(app):
    inner = app.app
    lifespan = inner.router.lifespan_context(inner)
    client = httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://test")
    return lifespan, client


@pytest.mark.anyio
async def test_access_mode_rejects_missing_forged_and_bearer(access_app):
    from .conftest import MCP_TOKEN

    app, _, _ = access_app
    lifespan, client = await _client(app)
    async with lifespan, client:
        assert (await client.post("/mcp", json=INIT, headers=MCP_HEADERS)).status_code == 401
        forged = {**MCP_HEADERS, "Cf-Access-Jwt-Assertion": token(key=OTHER_KEY)}
        assert (await client.post("/mcp", json=INIT, headers=forged)).status_code == 401
        # The MCP bearer token is not an alternative way in when Access mode is on.
        bearer = {**MCP_HEADERS, "Authorization": f"Bearer {MCP_TOKEN}"}
        assert (await client.post("/mcp", json=INIT, headers=bearer)).status_code == 401
        assert (await client.get("/healthz")).status_code == 200


@pytest.mark.anyio
async def test_access_mode_tool_call_is_attributed_and_spoofing_stripped(access_app):
    app, stream, _ = access_app
    lifespan, client = await _client(app)
    headers = {**MCP_HEADERS, "Cf-Access-Jwt-Assertion": token(),
               USER_HEADER: "attacker@example.com"}  # must be ignored
    async with lifespan, client:
        r = await client.post("/mcp", json=INIT, headers=headers)
        assert r.status_code == 200
        session = r.headers.get("mcp-session-id")
        if session:
            headers["mcp-session-id"] = session
        headers["mcp-protocol-version"] = "2025-06-18"
        await client.post("/mcp", json={"jsonrpc": "2.0", "method": "notifications/initialized"}, headers=headers)
        r = await client.post("/mcp", headers=headers, json={
            "jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "arcane_run", "arguments": {"args": ["containers", "get", "x"]}}})
        assert r.status_code == 200
    entries = [json.loads(line) for line in stream.getvalue().splitlines() if line.strip()]
    run = [e for e in entries if e.get("tool") == "arcane_run"]
    assert run and run[-1]["user"] == "josh@newmanshouse.com"
    assert "attacker@example.com" not in stream.getvalue()
