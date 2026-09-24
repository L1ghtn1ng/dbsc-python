"""Drive the example server over a real socket, the way a DBSC browser would."""

import asyncio
import re
from collections.abc import AsyncIterator
from dataclasses import dataclass
from pathlib import Path

import pytest

from dbsc import Binding, Config, CorruptStateError, DbscServer, RequestContext
from examples.demo_server import DemoApp, FileStore, serve
from tests.support import FakeDevice

DBSC_COOKIE = "__Host-demo_dbsc"


@dataclass
class Reply:
    status: int
    headers: list[tuple[str, str]]
    body: str

    def header(self, name: str) -> str | None:
        return next((v for k, v in self.headers if k.lower() == name.lower()), None)

    def set_cookies(self) -> dict[str, str]:
        found = {}
        for name, value in self.headers:
            if name.lower() == "set-cookie":
                key, _, rest = value.partition("=")
                found[key] = rest.split(";", 1)[0]
        return found


class Browser:
    """Just enough of a cookie-keeping HTTP client."""

    def __init__(self, port: int) -> None:
        self.port = port
        self.cookies: dict[str, str] = {}

    async def request(
        self, method: str, target: str, headers: dict[str, str] | None = None
    ) -> Reply:
        reader, writer = await asyncio.open_connection("127.0.0.1", self.port)
        lines = [f"{method} {target} HTTP/1.1", f"Host: localhost:{self.port}"]
        if self.cookies:
            lines.append("Cookie: " + "; ".join(f"{k}={v}" for k, v in self.cookies.items()))
        lines += [f"{k}: {v}" for k, v in (headers or {}).items()]
        writer.write(("\r\n".join(lines) + "\r\n\r\n").encode())
        await writer.drain()
        raw = await reader.read()
        writer.close()

        head, _, body = raw.decode().partition("\r\n\r\n")
        status_line, *header_lines = head.split("\r\n")
        reply = Reply(
            int(status_line.split(" ")[1]),
            [(k, v.strip()) for k, _, v in (h.partition(":") for h in header_lines)],
            body,
        )
        for name, value in reply.set_cookies().items():
            if value:
                self.cookies[name] = value
            else:
                self.cookies.pop(name, None)
        return reply


@pytest.fixture
async def browser(tmp_path: Path) -> AsyncIterator[Browser]:
    store = FileStore(tmp_path)
    app = DemoApp(DbscServer(Config(cookie_name=DBSC_COOKIE), store), origin="http://localhost")
    server = await serve(app, "127.0.0.1", 0, None)
    port = server.sockets[0].getsockname()[1]
    app.origin = f"http://localhost:{port}"
    async with server:
        yield Browser(port)


async def test_demo_register_refresh_enforce_logout(browser: Browser) -> None:
    device = FakeDevice()

    login = await browser.request("GET", "/?route=login")
    offer = login.header("Secure-Session-Registration")
    assert offer is not None
    match = re.search(r'challenge="([^"]+)"', offer)
    assert match is not None

    registered = await browser.request(
        "POST",
        "/dbsc/register",
        {"Secure-Session-Response": f'"{device.registration_jwt(match.group(1))}"'},
    )
    assert registered.status == 200
    assert DBSC_COOKIE in browser.cookies

    account = await browser.request("GET", "/?route=account", {"Sec-Fetch-Dest": "document"})
    assert account.status == 200
    assert "DBSC-bound" in account.body
    advertised = account.header("Secure-Session-Challenge")
    assert advertised is not None, "seed challenge advertised once on a document response"

    # One-step first refresh with the advertised seed.
    refreshed = await browser.request(
        "POST",
        "/dbsc/refresh",
        {"Secure-Session-Response": device.refresh_jwt(advertised.split('"')[1])},
    )
    assert refreshed.status == 200

    # A refresh with no proof gets the reactive 403 + challenge.
    challenge = await browser.request("POST", "/dbsc/refresh")
    assert challenge.status == 403
    assert challenge.header("Secure-Session-Challenge") is not None

    # A stolen app-session cookie without the bound cookie trips the gate and logs out.
    stolen = dict(browser.cookies)
    browser.cookies.pop(DBSC_COOKIE)
    tripped = await browser.request("GET", "/?route=account", {"Sec-Fetch-Dest": "document"})
    assert tripped.status == 302
    browser.cookies = stolen
    assert (await browser.request("GET", "/?route=account")).status == 302, "session is gone"


async def test_demo_forged_refresh_is_terminal(browser: Browser) -> None:
    device = FakeDevice()
    login = await browser.request("GET", "/?route=login")
    match = re.search(r'challenge="([^"]+)"', login.header("Secure-Session-Registration") or "")
    assert match is not None
    await browser.request(
        "POST", "/dbsc/register", {"Sec-Session-Response": device.registration_jwt(match.group(1))}
    )
    challenge = await browser.request("POST", "/dbsc/refresh")
    value = (challenge.header("Secure-Session-Challenge") or "").split('"')[1]

    forged = await browser.request(
        "POST", "/dbsc/refresh", {"Sec-Session-Response": FakeDevice().refresh_jwt(value)}
    )
    assert forged.status == 401
    assert DBSC_COOKIE not in browser.cookies, "bound cookie deleted"
    assert (await browser.request("GET", "/?route=account")).status == 302


async def test_demo_rejects_malformed_request(browser: Browser) -> None:
    reader, writer = await asyncio.open_connection("127.0.0.1", browser.port)
    writer.write(b"garbage\r\n\r\n")
    await writer.drain()
    assert (await reader.read()).startswith(b"HTTP/1.1 400 ")
    writer.close()


async def test_demo_rotates_the_session_id_at_login(browser: Browser) -> None:
    """An id planted before login (session fixation) is dropped when the user logs in."""
    await browser.request("GET", "/")
    planted = browser.cookies["demo_session"]
    await browser.request("GET", "/?route=login")
    assert browser.cookies["demo_session"] != planted

    browser.cookies["demo_session"] = planted
    assert (await browser.request("GET", "/?route=account")).status == 302


async def test_demo_errors_reveal_nothing(browser: Browser) -> None:
    await browser.request("GET", "/?route=login")
    refused = await browser.request("POST", "/dbsc/register", {"Sec-Session-Response": "a.b.c"})
    assert refused.status == 401
    assert refused.body == '{"ok": false}'


async def test_demo_pages_are_hardened(browser: Browser) -> None:
    page = await browser.request("GET", "/")
    assert page.header("Cache-Control") == "no-store"
    assert page.header("X-Content-Type-Options") == "nosniff"
    assert "frame-ancestors 'none'" in (page.header("Content-Security-Policy") or "")


def test_demo_store_refuses_a_shared_directory(tmp_path: Path) -> None:
    shared = tmp_path / "shared"
    shared.mkdir()
    shared.chmod(0o777)
    with pytest.raises(SystemExit, match="mode 0700"):
        FileStore(shared)


@pytest.mark.parametrize(
    "content",
    [
        "{not json",
        "[]",
        '{"v": "x"}',
        '{"exp": 9999999999}',
        '{"exp": "soon", "v": "x"}',
        '{"exp": 9999999999, "v": 7}',
        b"\xff\xfe",
    ],
)
async def test_demo_store_fails_closed_on_a_corrupt_file(
    tmp_path: Path, content: str | bytes
) -> None:
    store = FileStore(tmp_path)
    server = DbscServer(Config(), store)
    request = RequestContext("s", "u", "https://example.test")
    await store.put_binding("s", Binding("u", "sid", "c", "pem", "ES256", "chal", 1, 1))
    record = next(tmp_path.glob("*.json"))
    if isinstance(content, bytes):
        record.write_bytes(content)
    else:
        record.write_text(content, encoding="utf-8")

    with pytest.raises(CorruptStateError):
        await server.get_binding(request)
    await server.revoke(request)  # a corrupt record must still be torn down
    assert not record.exists()


async def test_demo_store_read_never_deletes(tmp_path: Path) -> None:
    """Reads run without the write lock, so they must not remove even an expired record."""
    store = FileStore(tmp_path, session_ttl=-1)  # written already expired
    await store.put_binding("s", Binding("u", "sid", "c", "pem", "ES256", "chal", 1, 1))
    record = next(tmp_path.glob("*.json"))
    assert await store.get_binding("s") is None
    assert record.exists()
