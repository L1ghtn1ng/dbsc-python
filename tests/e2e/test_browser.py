"""The full DBSC lifecycle against a real headless Chromium.

The unit suite's FakeDevice mimics Chrome; these tests check the library against the real
thing: Chrome-generated keys and JWTs, the browser's own refresh scheduling and request
deferral, and its cookie handling.
"""

import asyncio

import pytest
from playwright.async_api import Browser, BrowserContext

from dbsc import AuditEvent
from tests.e2e.conftest import SESSION_COOKIE, SiteFactory, bound_cookie, eventually

pytestmark = pytest.mark.e2e

COOKIE_MAX_AGE = 3  # short enough to force a refresh by waiting it out


async def test_registration(site: SiteFactory, context: BrowserContext) -> None:
    web = await site()
    page = await context.new_page()

    await page.goto(web.url("login"))
    await eventually(lambda: bound_cookie(context))

    register = [hit for hit in web.hits if hit.path == "/dbsc/register"]
    assert [hit.status for hit in register] == [200]
    assert register[0].headers.get("secure-session-response"), "Chrome sends the signed JWT"
    assert AuditEvent.REGISTERED in web.audit.events

    await page.goto(web.url("account"))
    assert "DBSC-bound" in await page.inner_text("body")


async def test_two_phase_refresh(site: SiteFactory, context: BrowserContext) -> None:
    """With no challenge cached, the browser's first refresh is 403-then-proof."""
    web = await site(cookie_max_age_seconds=COOKIE_MAX_AGE)
    page = await context.new_page()
    await page.goto(web.url("login"))
    registered = await eventually(lambda: bound_cookie(context))

    # No document load in between, so no challenge was advertised.
    await asyncio.sleep(COOKIE_MAX_AGE + 1)
    await page.goto(web.url("account"))

    assert "DBSC-bound" in await page.inner_text("body"), "request deferred until refreshed"
    assert web.refreshes()[:2] == [403, 200]
    assert AuditEvent.REFRESHED in web.audit.events
    assert await bound_cookie(context) not in (None, registered), "cookie value rotated"


async def test_advertised_challenge_is_harmless(site: SiteFactory, context: BrowserContext) -> None:
    """``advertise_refresh_challenge()`` sends the seed at most once and never breaks the session.

    Timing is the browser's: with a short-lived cookie, Chromium starts refreshing as soon as
    registration completes, and that refresh often lands between the gate's read and the
    advertise. The advertise then rightly stands down, because its seed is stale and writing the
    binding back would undo the refresh. Whether the browser later skips the 403 is up to it too.
    So only the invariants are asserted.
    """
    web = await site(cookie_max_age_seconds=COOKIE_MAX_AGE)
    page = await context.new_page()
    await page.goto(web.url("login"))
    await eventually(lambda: bound_cookie(context))

    loads = [await page.goto(web.url("account")) for _ in range(3)]
    advertised = [
        response
        for response in loads
        if response is not None and "secure-session-challenge" in await response.all_headers()
    ]
    assert len(advertised) <= 1, "the seed is delivered at most once"

    await asyncio.sleep(COOKIE_MAX_AGE + 1)
    await page.goto(web.url("account"))

    assert "DBSC-bound" in await page.inner_text("body")
    assert web.refreshes()[-1] == 200
    assert AuditEvent.REFRESH_FAILED not in web.audit.events


async def test_stolen_session_cookie_is_rejected(
    site: SiteFactory, context: BrowserContext, browser: Browser
) -> None:
    """The app session cookie alone, replayed without the device, ends the session."""
    web = await site()
    victim = await context.new_page()
    await victim.goto(web.url("login"))
    await eventually(lambda: bound_cookie(context))
    stolen = next(c for c in await context.cookies() if c.get("name") == SESSION_COOKIE)

    # The attacker replays the session cookie from their own HTTP client. Redirects aren't
    # followed: the demo's login route signs anyone straight in, which would muddy the result.
    attacker = await browser.new_context()
    try:
        replay = await attacker.request.get(
            web.url("account"),
            headers={
                "Cookie": f"{SESSION_COOKIE}={stolen.get('value')}",
                "Sec-Fetch-Dest": "document",
            },
            max_redirects=0,
        )
    finally:
        await attacker.close()
    assert replay.status == 302
    assert "route=login" in replay.headers["location"]
    assert web.audit.events[-1] == AuditEvent.ENFORCEMENT_TERMINATED

    # The whole session is gone, not just the attacker's request: the victim is logged out too.
    after = await context.request.get(web.url("account"), max_redirects=0)
    assert after.status == 302


async def test_logout_deletes_the_bound_cookie(site: SiteFactory, context: BrowserContext) -> None:
    web = await site()
    page = await context.new_page()
    await page.goto(web.url("login"))
    await eventually(lambda: bound_cookie(context))

    await page.goto(web.url("logout"))

    assert await bound_cookie(context) is None
    assert web.audit.events[-1] == AuditEvent.REVOKED
