"""Fixtures for driving the demo server with a real, DBSC-capable headless Chromium.

The suite only runs when ``DBSC_E2E_BROWSER`` names a Chromium binary that supports DBSC on
Linux (see ``scripts/fetch_e2e_browser.py`` for the pinned build and why it's pinned). Without
it, every test here is skipped.
"""

import asyncio
import os
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass
from pathlib import Path
from typing import override

import pytest
from playwright.async_api import Browser, BrowserContext, async_playwright

from dbsc import Config, DbscServer, ScopeRule
from examples.demo_server import DemoApp, FileStore, Request, Response, serve
from tests.support import RecordingAuditLogger

# What chrome://flags sets for "Device Bound Session Credentials (Standard): Enabled - For
# developers" plus "Device Bound Session Credentials with software keys" (Linux has no TPM
# provider). The developer parameters lift newer Chrome's origin-trial requirement, refresh quota
# and subdomain check; older builds ignore parameters they don't know. See
# scripts/fetch_e2e_browser.py for which versions actually register.
CHROMIUM_ARGS = [
    "--enable-features=DeviceBoundSessions:RequireOriginTrialTokens/false/RefreshQuota/false/"
    "CheckSubdomainRegistration/false/OriginTrialFeedback/true/SchemaVersion/2,"
    "EnableBoundSessionCredentialsSoftwareKeysForManualTesting",
]
BOUND_COOKIE = "__Host-e2e_dbsc"
SESSION_COOKIE = "demo_session"


@dataclass(frozen=True, slots=True)
class Hit:
    method: str
    path: str
    status: int
    headers: dict[str, str]


@dataclass
class Site:
    """The demo server as the browser sees it, plus what the server saw."""

    base_url: str
    hits: list[Hit]
    audit: RecordingAuditLogger
    store: FileStore

    def url(self, route: str) -> str:
        return f"{self.base_url}/?route={route}"

    def refreshes(self) -> list[int]:
        """Statuses of every ``/dbsc/refresh`` call so far, in order."""
        return [hit.status for hit in self.hits if hit.path == "/dbsc/refresh"]


class RecordingApp(DemoApp):
    """The demo app, recording every request it handles."""

    def __init__(self, dbsc: DbscServer) -> None:
        super().__init__(dbsc, origin="http://localhost")
        self.hits: list[Hit] = []

    @override
    async def handle(self, request: Request) -> Response:
        response = await super().handle(request)
        self.hits.append(Hit(request.method, request.path, response.status, request.headers))
        return response


type SiteFactory = Callable[..., Awaitable[Site]]


@pytest.fixture
def browser_path() -> str:
    path = os.environ.get("DBSC_E2E_BROWSER")
    if not path:
        pytest.skip("set DBSC_E2E_BROWSER (see scripts/fetch_e2e_browser.py) to run e2e tests")
    if not Path(path).is_file():
        pytest.fail(f"DBSC_E2E_BROWSER={path} does not exist")
    return path


@pytest.fixture
async def site(tmp_path: Path) -> AsyncIterator[SiteFactory]:
    """Start the demo server (stopped after the test).

    A short ``cookie_max_age_seconds`` lets a test force a refresh by waiting it out.
    """
    servers: list[asyncio.Server] = []

    async def start(*, cookie_max_age_seconds: int = 300) -> Site:
        config = Config(
            cookie_name=BOUND_COOKIE,
            cookie_max_age_seconds=cookie_max_age_seconds,
            # Every refresh spends a rate-limited signature; keep the favicon out of scope.
            scope_specification=[ScopeRule.exclude(path="/favicon.ico")],
        )
        audit = RecordingAuditLogger()
        store = FileStore(tmp_path / "store")
        app = RecordingApp(DbscServer(config, store, audit=audit))
        server = await serve(app, "127.0.0.1", 0, None)
        servers.append(server)
        port = server.sockets[0].getsockname()[1]
        # localhost, not 127.0.0.1: a secure context over plain HTTP, so __Host- cookies work.
        app.origin = f"http://localhost:{port}"
        return Site(app.origin, app.hits, audit, store)

    yield start
    for server in servers:
        server.close()
        await server.wait_closed()


@pytest.fixture
async def browser(browser_path: str) -> AsyncIterator[Browser]:
    async with async_playwright() as playwright:
        browser = await playwright.chromium.launch(executable_path=browser_path, args=CHROMIUM_ARGS)
        yield browser
        await browser.close()


@pytest.fixture
async def context(browser: Browser) -> AsyncIterator[BrowserContext]:
    context = await browser.new_context()
    yield context
    await context.close()


async def eventually[T](probe: Callable[[], Awaitable[T]], within: float = 15) -> T:
    """Poll ``probe`` until it returns something truthy, or fail after ``within`` seconds."""
    try:
        async with asyncio.timeout(within):
            while not (result := await probe()):  # noqa: ASYNC110 (external state; no event)
                await asyncio.sleep(0.1)
    except TimeoutError:
        pytest.fail(f"condition not met within {within}s")
    return result


async def bound_cookie(context: BrowserContext) -> str | None:
    """The browser's current bound-cookie value, if it holds one."""
    for cookie in await context.cookies():
        if cookie.get("name") == BOUND_COOKIE:
            return cookie.get("value")
    return None
