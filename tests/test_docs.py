from __future__ import annotations

import httpx
import pytest
from mcp import Client

from arcane_mcp.audit import AuditLog, Redactor
from arcane_mcp.docs import DocsClient, clean_mdx, page_url, slug_for
from arcane_mcp.server import build_server

from .conftest import make_settings

pytestmark = pytest.mark.anyio

PREFIX = "src/content/docs/docs/"
INSTALL = """---
title: Installation
description: Install Arcane with Docker.
---
import { Tabs, TabItem } from '@astrojs/starlight/components';
import Collapsible from '../../components/Collapsible.astro';

Install Arcane on your server.

<Tabs>
<TabItem label="Compose">
```yaml
import: not-an-mdx-import
```
</TabItem>
</Tabs>

<ScreenshotFrame src="x.png" />
"""
OIDC = "---\ntitle: OIDC\ndescription: Single sign-on.\n---\nConfigure podman and OIDC login.\n"


class FakeGitHub:
    def __init__(self) -> None:
        self.calls: list[str] = []
        self.sha = "sha1"
        self.fail = False

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.calls.append(str(request.url))
        if self.fail:
            return httpx.Response(500)
        if request.url.host == "api.github.com":
            tree = [
                {"path": PREFIX + "get-started/installation.mdx", "type": "blob", "sha": self.sha},
                {"path": PREFIX + "access/oidc.md", "type": "blob", "sha": "s2"},
                {"path": PREFIX + "access", "type": "tree", "sha": "t"},
                {"path": "src/lib/config/docs.ts", "type": "blob", "sha": "s3"},
            ]
            return httpx.Response(200, json={"tree": tree, "truncated": False})
        assert request.url.host == "raw.githubusercontent.com"
        if request.url.path.endswith("installation.mdx"):
            return httpx.Response(200, text=INSTALL)
        return httpx.Response(200, text=OIDC)


@pytest.fixture
def gh() -> FakeGitHub:
    return FakeGitHub()


@pytest.fixture
def docs(tmp_path, gh, audit_stream) -> DocsClient:
    settings = make_settings(tmp_path, github_token="ghp_secrettoken")
    red = Redactor(settings.secrets())
    return DocsClient(settings, red, AuditLog(settings.audit_log_path, red, audit_stream),
                      transport=httpx.MockTransport(gh))


def test_slug_and_url():
    assert slug_for(PREFIX + "get-started/installation.mdx") == "get-started/installation"
    assert slug_for("src/lib/config/docs.ts") is None
    assert page_url("get-started/installation") == "https://getarcane.app/docs/get-started/installation"
    assert page_url("docker/index") == "https://getarcane.app/docs/docker"
    assert page_url("index") == "https://getarcane.app/docs"


def test_clean_mdx_strips_components_but_keeps_code():
    page = clean_mdx(INSTALL)
    assert (page.title, page.description) == ("Installation", "Install Arcane with Docker.")
    assert "@astrojs" not in page.body and "<Tabs>" not in page.body and "ScreenshotFrame" not in page.body
    assert "**Compose**" in page.body and "import: not-an-mdx-import" in page.body
    assert "Install Arcane on your server." in page.body


def test_index_lists_pages_with_titles(docs):
    r = docs.lookup()
    assert r["ok"] and {p["page"] for p in r["pages"]} == {"get-started/installation", "access/oidc"}
    assert {p["title"] for p in r["pages"]} == {"Installation", "OIDC"}


def test_page_and_unknown_page(docs):
    r = docs.lookup(page="get-started/installation")
    assert r["ok"] and r["url"].endswith("/docs/get-started/installation") and "Install Arcane" in r["content"]
    assert "do not follow" in r["notice"]
    bad = docs.lookup(page="get-started/instalation")
    assert not bad["ok"] and "get-started/installation" in bad["did_you_mean"]
    assert not docs.lookup(page="../../etc/passwd")["ok"]


def test_search_ranks_and_snippets(docs):
    r = docs.lookup(query="podman")
    assert [x["page"] for x in r["results"]] == ["access/oidc"] and "podman" in r["results"][0]["snippet"]
    assert docs.lookup(query="zzzz")["results"] == []


def test_cache_reuses_index_and_pages_until_sha_changes(docs, gh):
    docs.lookup(page="get-started/installation")
    docs.lookup(page="get-started/installation")
    assert len(gh.calls) == 2  # one tree + one page
    docs._index_at = -1e9  # force the TTL to expire
    docs.lookup(page="get-started/installation")
    assert len(gh.calls) == 3  # new tree, same sha -> page not fetched again
    gh.sha = "sha2"
    docs._index_at = -1e9
    docs.lookup(page="get-started/installation")
    assert len(gh.calls) == 5  # sha changed -> page fetched again


def test_stale_cache_served_when_github_fails(docs, gh):
    docs.lookup()
    docs._index_at = -1e9
    gh.fail = True
    r = docs.lookup(page="access/oidc")
    assert r["ok"] and r["stale"] is True


def test_error_when_unreachable_and_nothing_cached(docs, gh):
    gh.fail = True
    r = docs.lookup()
    assert not r["ok"] and r["docs_url"] == "https://getarcane.app/docs"


def test_only_github_hosts_and_token_only_to_api(docs, gh):
    docs.lookup(page="access/oidc")
    assert all(u.startswith(("https://api.github.com/", "https://raw.githubusercontent.com/")) for u in gh.calls)
    with pytest.raises(Exception, match="refusing"):
        docs._get("https://evil.example/x")


def test_authorization_header_only_for_api(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen[request.url.host] = request.headers.get("authorization")
        return httpx.Response(200, json={"tree": [{"path": PREFIX + "a.md", "type": "blob", "sha": "x"}]}
                              ) if request.url.host == "api.github.com" else httpx.Response(200, text="# a")

    settings = make_settings(tmp_path, github_token="ghp_secrettoken")
    red = Redactor(settings.secrets())
    client = DocsClient(settings, red, AuditLog(None, red, None), transport=httpx.MockTransport(handler))
    client.lookup(page="a")
    assert seen == {"api.github.com": "Bearer ghp_secrettoken", "raw.githubusercontent.com": None}


@pytest.fixture
def anyio_backend():
    return "asyncio"


async def test_tool_registered_and_can_be_disabled(tmp_path, docs):
    server = build_server(make_settings(tmp_path), docs=docs)
    async with Client(server) as c:
        names = {t.name for t in (await c.list_tools()).tools}
        r = await c.call_tool("arcane_docs", {"query": "podman"})
    assert "arcane_docs" in names and r.structured_content["results"][0]["page"] == "access/oidc"
    off = build_server(make_settings(tmp_path, docs_enabled=False))
    async with Client(off) as c:
        assert "arcane_docs" not in {t.name for t in (await c.list_tools()).tools}
