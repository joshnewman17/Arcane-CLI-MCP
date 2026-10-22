"""Cloudflare Access JWT validation.

When the server sits behind a Cloudflare Access application (with Managed OAuth for Claude's
connector), Access authenticates the caller and forwards a signed JWT in the
``Cf-Access-Jwt-Assertion`` header. Cloudflare requires MCP servers behind Managed OAuth to
validate it: https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/

Validating it here (signature, audience, issuer, expiry) means a request that reaches the
container without going through Access, e.g. from a neighbour on the same network, is rejected.
"""

from __future__ import annotations

import json
import logging
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import httpx
import jwt

log = logging.getLogger("arcane_mcp.access")

HEADER = "cf-access-jwt-assertion"
JWKS_TTL_S = 3600
# Don't hammer the certs endpoint when a token carries an unknown key id.
MIN_REFETCH_INTERVAL_S = 30
LEEWAY_S = 30


class AccessDenied(Exception):
    """The request has no valid Access JWT. The message is safe to log, not to return."""


@dataclass(frozen=True)
class AccessIdentity:
    email: str | None
    subject: str | None


def team_issuer(team_domain: str) -> str:
    """Normalise ``myteam``, ``myteam.cloudflareaccess.com`` or a URL to the issuer URL."""
    domain = team_domain.strip().removeprefix("https://").removeprefix("http://").rstrip("/")
    if "." not in domain:
        domain = f"{domain}.cloudflareaccess.com"
    return f"https://{domain}"


def _fetch_jwks(url: str) -> dict[str, Any]:
    resp = httpx.get(url, timeout=10, follow_redirects=False)
    resp.raise_for_status()
    return resp.json()


class AccessVerifier:
    def __init__(self, team_domain: str, audience: str,
                 fetch_jwks: Callable[[str], dict[str, Any]] = _fetch_jwks,
                 clock: Callable[[], float] = time.monotonic) -> None:
        if not audience.strip():
            raise ValueError("Cloudflare Access audience (AUD tag) is required")
        self.issuer = team_issuer(team_domain)
        self.audience = audience.strip()
        self.certs_url = f"{self.issuer}/cdn-cgi/access/certs"
        self._fetch = fetch_jwks
        self._clock = clock
        self._lock = threading.Lock()
        self._keys: dict[str, Any] = {}
        self._fetched_at: float | None = None

    def _refresh(self, force: bool) -> None:
        now = self._clock()
        if self._fetched_at is not None:
            age = now - self._fetched_at
            if (not force and age < JWKS_TTL_S) or (force and age < MIN_REFETCH_INTERVAL_S):
                return
        try:
            jwks = self._fetch(self.certs_url)
        except (httpx.HTTPError, json.JSONDecodeError, ValueError) as exc:
            if not self._keys:
                raise AccessDenied(f"cannot fetch Access signing keys: {type(exc).__name__}") from exc
            log.warning("could not refresh Access signing keys (%s); using cached keys", type(exc).__name__)
            return
        keys = {}
        for jwk in jwks.get("keys", []):
            try:
                key = jwt.PyJWK(jwk)
            except jwt.PyJWTError:
                continue
            if key.key_id:
                keys[key.key_id] = key
        if not keys:
            raise AccessDenied("Access certs endpoint returned no usable keys")
        self._keys, self._fetched_at = keys, now

    def _key_for(self, kid: str) -> Any:
        with self._lock:
            self._refresh(force=False)
            if kid not in self._keys:
                self._refresh(force=True)  # Cloudflare rotates keys; fetch again once
            key = self._keys.get(kid)
        if key is None:
            raise AccessDenied("token signed with an unknown key")
        return key

    def verify(self, token: str | None) -> AccessIdentity:
        if not token:
            raise AccessDenied("missing Cf-Access-Jwt-Assertion header")
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError as exc:
            raise AccessDenied("malformed token") from exc
        kid = header.get("kid")
        if not kid or header.get("alg") != "RS256":
            raise AccessDenied("unexpected token header")
        key = self._key_for(kid)
        try:
            claims = jwt.decode(
                token,
                key=key.key,
                algorithms=["RS256"],
                audience=self.audience,
                issuer=self.issuer,
                leeway=LEEWAY_S,
                options={"require": ["exp", "iat", "aud", "iss"]},
            )
        except jwt.PyJWTError as exc:
            raise AccessDenied(f"invalid token: {type(exc).__name__}") from exc
        return AccessIdentity(email=claims.get("email"), subject=claims.get("sub"))
