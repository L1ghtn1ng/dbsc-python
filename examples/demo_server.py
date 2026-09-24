"""Reference DBSC integration: a minimal single-file asyncio HTTP server, stdlib only.

DBSC is driven entirely by the browser (no JS API), so there is no client page: you exercise this
with a real DBSC-capable browser (Chrome 146+ on Windows at the time of writing) over HTTPS.
Routes:

  GET  /?route=login     "log in": sets a session, emits Secure-Session-Registration
  POST /dbsc/register    browser posts the registration JWT (Sec-Session-Response header)
  POST /dbsc/refresh     browser's ~5-min refresh (two-phase: 403+challenge, then 200)
  GET  /?route=account   protected page; the enforcement gate runs here
  GET  /?route=logout    clears the session and revokes DBSC

The DBSC store is file-backed and keyed by the app session id: deliberately a DEDICATED key
space, NOT the app's session data. Putting DBSC state in a read-modify-written session blob is
the exact race (post-login navigation vs the register POST) that silently disables enforcement.

Illustrative only: HTTP/1.1 with one request per connection, no keep-alive, minimal parsing.

    uv run python -m examples.demo_server --cert cert.pem --key key.pem
"""

import argparse
import asyncio
import contextlib
import hashlib
import json
import logging
import os
import secrets
import signal
import ssl
import tempfile
import time
from dataclasses import dataclass, field
from http import HTTPStatus
from http.cookies import CookieError, SimpleCookie
from pathlib import Path
from typing import override
from urllib.parse import parse_qs, urlsplit

from dbsc import (
    Binding,
    Config,
    Cookie,
    CorruptStateError,
    DbscError,
    DbscResponse,
    DbscServer,
    PendingRegistration,
    RequestContext,
    RetryableRefreshError,
    ScopeRule,
    Store,
)

APP_SESSION_COOKIE = "demo_session"
MAX_HEADER_LINES = 100
MAX_BODY_BYTES = 64 * 1024
READ_TIMEOUT_SECONDS = 10

logger = logging.getLogger(__name__)


class FileStore(Store):
    """Dedicated file-backed store, keyed by session id: the correct pattern (NOT the session blob).

    Blocking file I/O runs in a worker thread so it never stalls the event loop. Writes are
    serialised by one lock, which makes :meth:`commit_registration` and :meth:`replace_binding`
    atomic within this one process; a store shared between processes needs its backend's own
    primitive instead (see README).
    """

    def __init__(self, directory: Path, challenge_ttl: int = 900, session_ttl: int = 64800) -> None:
        directory.mkdir(mode=0o700, parents=True, exist_ok=True)
        # The records are session secrets. Refuse a directory someone else owns or can write to
        # (for example one pre-created in a shared temp dir to read or plant records).
        info = directory.stat()
        if info.st_uid != os.geteuid() or info.st_mode & 0o077:
            raise SystemExit(
                f"Refusing store directory {directory}: must be owned by you, mode 0700."
            )
        self._dir = directory
        self._challenge_ttl = challenge_ttl
        self._session_ttl = session_ttl
        self._writes = asyncio.Lock()

    @override
    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        async with self._writes:
            await asyncio.to_thread(
                self._write, f"reg:{session_id}", pending.to_json(), self._challenge_ttl
            )

    @override
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        raw = await asyncio.to_thread(self._read, f"reg:{session_id}")
        return None if raw is None else PendingRegistration.from_json(raw)

    @override
    async def delete_pending_registration(self, session_id: str) -> None:
        async with self._writes:
            await asyncio.to_thread(self._unlink, f"reg:{session_id}")

    @override
    async def put_binding(self, session_id: str, binding: Binding) -> None:
        async with self._writes:
            await self._put_binding(session_id, binding)

    @override
    async def get_binding(self, session_id: str) -> Binding | None:
        raw = await asyncio.to_thread(self._read, f"bind:{session_id}")
        return None if raw is None else Binding.from_json(raw)

    @override
    async def delete(self, session_id: str) -> None:
        async with self._writes:
            await asyncio.to_thread(self._unlink, f"reg:{session_id}")
            await asyncio.to_thread(self._unlink, f"bind:{session_id}")

    @override
    async def commit_registration(
        self, session_id: str, offer: PendingRegistration, binding: Binding
    ) -> bool:
        async with self._writes:
            if await self.get_pending_registration(session_id) != offer:
                return False
            await asyncio.to_thread(self._unlink, f"reg:{session_id}")
            await self._put_binding(session_id, binding)
            return True

    @override
    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        async with self._writes:
            if await self.get_binding(session_id) != expected:
                return False
            await self._put_binding(session_id, new)
            return True

    async def _put_binding(self, session_id: str, binding: Binding) -> None:
        await asyncio.to_thread(
            self._write, f"bind:{session_id}", binding.to_json(), self._session_ttl
        )

    def _path(self, key: str) -> Path:
        return self._dir / f"{hashlib.sha256(key.encode()).hexdigest()}.json"

    def _read(self, key: str) -> str | None:
        path = self._path(key)
        try:
            envelope = json.loads(path.read_text())
        except FileNotFoundError:
            return None
        # The envelope is ours; its payload "v" is what from_json() validates (and fails closed on).
        if envelope["exp"] < time.time():
            path.unlink(missing_ok=True)
            return None
        return envelope["v"]

    def _write(self, key: str, value: str, ttl: int) -> None:
        # Write a uniquely named temp file, then rename it over the record: atomic, so a
        # concurrent reader never sees a half-written record, and concurrent writers (a refresh
        # racing a document load) never trip over each other's temp file.
        with tempfile.NamedTemporaryFile("w", dir=self._dir, suffix=".tmp", delete=False) as tmp:
            tmp.write(json.dumps({"v": value, "exp": int(time.time()) + ttl}))
        Path(tmp.name).replace(self._path(key))

    def _unlink(self, key: str) -> None:
        self._path(key).unlink(missing_ok=True)


@dataclass(frozen=True, slots=True)
class Request:
    method: str
    path: str
    query: dict[str, str]
    headers: dict[str, str]
    cookies: dict[str, str]


@dataclass(slots=True)
class Response:
    status: int = 200
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""

    def apply(self, dbsc: DbscResponse) -> None:
        """Apply a DbscResponse: the library never touches the transport itself."""
        for name, value in dbsc.headers.items():
            self.set_header(name, value)
        self.headers.extend(("Set-Cookie", set_cookie_header(c)) for c in dbsc.cookies)
        if dbsc.content_type is not None:
            self.set_header("Content-Type", dbsc.content_type)
        if dbsc.status is not None:
            self.status = dbsc.status
        if dbsc.body is not None:
            self.body = dbsc.body

    def set_header(self, name: str, value: str) -> None:
        """Set a single-valued header, replacing any earlier value (Set-Cookie is appended)."""
        self.headers = [(n, v) for n, v in self.headers if n.lower() != name.lower()]
        self.headers.append((name, value))

    def encode(self) -> bytes:
        reason = HTTPStatus(self.status).phrase
        body = self.body.encode()
        headers = [*self.headers, ("Content-Length", str(len(body))), ("Connection", "close")]
        present = {name.lower() for name, _ in headers}
        defaults = [
            ("Content-Type", "text/html; charset=utf-8"),
            # Every page here is session-specific; none may be cached or framed.
            ("Cache-Control", "no-store"),
            ("X-Content-Type-Options", "nosniff"),
            ("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"),
            ("Referrer-Policy", "no-referrer"),
        ]
        headers += [(name, value) for name, value in defaults if name.lower() not in present]
        head = f"HTTP/1.1 {self.status} {reason}\r\n"
        head += "".join(f"{name}: {value}\r\n" for name, value in headers)
        return head.encode("latin-1") + b"\r\n" + body


def set_cookie_header(cookie: Cookie) -> str:
    parts = [f"{cookie.name}={'' if cookie.delete else cookie.value}", f"Path={cookie.path}"]
    if cookie.delete:
        parts.append("Expires=Thu, 01 Jan 1970 00:00:01 GMT")
        parts.append("Max-Age=0")
    else:
        parts.append(f"Max-Age={max(cookie.expires_at - int(time.time()), 0)}")
    if cookie.secure:
        parts.append("Secure")
    if cookie.http_only:
        parts.append("HttpOnly")
    parts.append(f"SameSite={cookie.same_site}")
    return "; ".join(parts)


class DemoApp:
    """The demo's routes.

    ``origin`` is this site's own origin (``https://example.com``), fixed by configuration. Never
    derive it from the request's Host header: the client controls that, and it becomes the scope
    of the DBSC session.
    """

    def __init__(self, dbsc: DbscServer, *, origin: str) -> None:
        self._dbsc = dbsc
        self.origin = origin
        # App sessions: session id -> user id. Deliberately separate from the DBSC store.
        self._sessions: dict[str, str] = {}

    def _new_session(self, response: Response) -> str:
        session_id = secrets.token_urlsafe(32)
        self._sessions[session_id] = ""
        secure = "; Secure" if self.origin.startswith("https://") else ""
        response.headers.append(
            (
                "Set-Cookie",
                f"{APP_SESSION_COOKIE}={session_id}; Path=/; HttpOnly; SameSite=Lax{secure}",
            )
        )
        return session_id

    async def handle(self, request: Request) -> Response:
        response = Response()
        session_id = request.cookies.get(APP_SESSION_COOKIE, "")
        fresh = session_id not in self._sessions
        if fresh:
            session_id = self._new_session(response)

        # DBSC endpoints first: the enforcement gate never runs on these.
        match request.path, request.query.get("route"):
            case "/dbsc/register", _:
                await self._register(request, session_id, response)
            case "/dbsc/refresh", _:
                await self._refresh(request, session_id, response)
            case _, "login":
                # A new session id at login, so an id planted before login is worthless
                # (session fixation). Tear down whatever the old one had, DBSC included.
                if not fresh:
                    old = self._context(request, session_id)
                    response.apply(await self._dbsc.revoke(old))
                    del self._sessions[session_id]
                    session_id = self._new_session(response)
                self._sessions[session_id] = "demo-user"
                # After full auth, decorate the login response with the registration offer.
                ctx = self._context(request, session_id)
                response.apply(await self._dbsc.build_registration_header_response(ctx))
                response.body = (
                    "Logged in. DBSC registration offered. <a href='?route=account'>Account</a>"
                )
            case _, "logout":
                response.apply(await self._dbsc.revoke(self._context(request, session_id)))
                self._sessions[session_id] = ""
                response.body = "Logged out. <a href='?route=login'>Log in</a>"
            case _, "account":
                await self._account(request, session_id, response)
            case _:
                response.body = (
                    "<a href='?route=login'>Log in</a> to start the DBSC demo "
                    "(use a DBSC-capable browser over HTTPS)."
                )
        return response

    def _context(self, request: Request, session_id: str) -> RequestContext:
        return RequestContext(
            session_id,
            self._sessions.get(session_id, ""),
            self.origin,
            request.headers,
            request.cookies,
        )

    async def _register(self, request: Request, session_id: str, response: Response) -> None:
        ctx = self._context(request, session_id)
        jwt = _session_response_jwt(ctx)
        if not jwt:
            response.status = 400
            return
        try:
            response.apply(await self._dbsc.register(jwt, ctx))
        except DbscError as e:
            _json_error(response, 401, e)

    async def _refresh(self, request: Request, session_id: str, response: Response) -> None:
        ctx = self._context(request, session_id)
        jwt = _session_response_jwt(ctx)
        if not jwt:
            response.apply(
                await self._dbsc.issue_refresh_challenge(ctx)
            )  # phase 1: 403 + challenge
            return
        try:
            response.apply(await self._dbsc.refresh(jwt, ctx))  # phase 2: 200 + rotated cookie
        except RetryableRefreshError:
            # Stale/missing/mismatched challenge: hand out a fresh one.
            response.apply(await self._dbsc.issue_refresh_challenge(ctx))
        except DbscError as e:
            # Terminal proof failure: revoke + log the user out server-side. Do NOT rely on the
            # browser/cookie expiry to do it; that is the stolen-cookie-stays-alive hole.
            response.apply(await self._dbsc.revoke(ctx, enforcement_terminated=True))
            self._sessions[session_id] = ""
            _json_error(response, 401, e)

    async def _account(self, request: Request, session_id: str, response: Response) -> None:
        if not self._sessions.get(session_id):
            _redirect(response, "?route=login")
            return
        ctx = self._context(request, session_id)
        dbsc = self._dbsc

        # --- Recommended enforcement gate -----------------------------------------------------
        try:
            binding = await dbsc.get_binding(ctx)
        except CorruptStateError:
            # Present-but-unreadable binding: fail closed, never degrade to cookie auth.
            await self._terminate(ctx, response)
            return
        if binding is None:
            # Never registered (unsupported browser / not yet): degrade to cookie auth.
            response.body = "Account page (cookie auth: browser did not register DBSC)."
            return
        is_document = dbsc.is_document_request(ctx)
        must_check = is_document or not dbsc.is_within_registration_grace(binding)
        if must_check and not dbsc.bound_cookie_matches(binding, ctx):
            await self._terminate(ctx, response)
            return

        if is_document:
            # Optional: hand over the seed challenge once so the first refresh is one-step.
            response.apply(await dbsc.advertise_refresh_challenge(binding, ctx))
        response.body = "Account page (DBSC-bound: device-bound cookie verified)."

    async def _terminate(self, ctx: RequestContext, response: Response) -> None:
        """Bound session, bad/absent device cookie: revoke, log the user out, back to login."""
        response.apply(await self._dbsc.revoke(ctx, enforcement_terminated=True))
        self._sessions[ctx.session_id] = ""
        _redirect(response, "?route=login")


def _session_response_jwt(ctx: RequestContext) -> str:
    header = ctx.header("Sec-Session-Response") or ctx.header("Secure-Session-Response") or ""
    return header.strip('"')


def _json_error(response: Response, status: int, error: Exception) -> None:
    # The reason goes to the server log (and the DBSC audit trail), not to the client.
    logger.info("DBSC request refused: %s: %s", type(error).__name__, error)
    response.status = status
    response.set_header("Content-Type", "application/json")
    response.body = json.dumps({"ok": False})


def _redirect(response: Response, location: str) -> None:
    response.status = 302
    response.headers.append(("Location", location))


async def read_request(reader: asyncio.StreamReader) -> Request | None:
    """Parse one HTTP/1.1 request head (and discard any body); ``None`` if malformed."""
    request_line = (await reader.readline()).decode("latin-1").rstrip("\r\n")
    try:
        method, target, _version = request_line.split(" ")
    except ValueError:
        return None

    headers: dict[str, str] = {}
    for _ in range(MAX_HEADER_LINES):
        line = (await reader.readline()).decode("latin-1").rstrip("\r\n")
        if not line:
            break
        name, sep, value = line.partition(":")
        if not sep:
            return None
        name = name.strip().lower()
        joiner = "; " if name == "cookie" else ", "
        headers[name] = (
            f"{headers[name]}{joiner}{value.strip()}" if name in headers else value.strip()
        )
    else:
        return None

    length = int(headers.get("content-length", "0") or "0")
    if not 0 <= length <= MAX_BODY_BYTES:
        return None
    await reader.readexactly(length)  # the DBSC endpoints carry the JWT in a header, not the body

    cookies: dict[str, str] = {}
    if "cookie" in headers:
        jar = SimpleCookie()
        with contextlib.suppress(CookieError):
            jar.load(headers["cookie"])
        cookies = {name: morsel.value for name, morsel in jar.items()}

    url = urlsplit(target)
    query = {k: v[0] for k, v in parse_qs(url.query).items()}
    return Request(method, url.path, query, headers, cookies)


async def serve(app: DemoApp, host: str, port: int, tls: ssl.SSLContext | None) -> asyncio.Server:
    async def on_connection(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            try:
                async with asyncio.timeout(READ_TIMEOUT_SECONDS):
                    request = await read_request(reader)
            except TimeoutError, ValueError, asyncio.IncompleteReadError, ConnectionError:
                return  # slow, malformed or vanished client: just hang up
            try:
                response = Response(400) if request is None else await app.handle(request)
            except Exception:
                logger.exception("Unhandled error serving %s", request and request.path)
                response = Response(500, body="Internal Server Error")
            writer.write(response.encode())
            await writer.drain()
        except ConnectionError:
            pass
        finally:
            writer.close()

    return await asyncio.start_server(on_connection, host, port, ssl=tls)


async def main() -> None:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", type=Path, help="TLS certificate (PEM); omit for plain HTTP")
    parser.add_argument("--key", type=Path, help="TLS private key (PEM)")
    parser.add_argument(
        "--origin",
        help="this site's origin as browsers see it, e.g. https://dbsc.test:8443 "
        "(default: derived from --host/--port and TLS)",
    )
    parser.add_argument(
        "--store-dir",
        type=Path,
        help="where DBSC state lives (default: a fresh private temp dir, deleted on exit)",
    )
    args = parser.parse_args()

    tls = None
    if args.cert:
        tls = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        tls.load_cert_chain(args.cert, args.key)

    config = Config(
        cookie_name="__Host-demo_dbsc",
        scope_specification=[ScopeRule.exclude(path="/favicon.ico")],
    )
    scheme = "https" if tls else "http"
    host = "localhost" if args.host in {"127.0.0.1", "::1"} else args.host
    origin = args.origin or f"{scheme}://{host}:{args.port}"
    with tempfile.TemporaryDirectory(prefix="dbsc-demo-") as private_dir:
        store = FileStore(args.store_dir or Path(private_dir))
        app = DemoApp(DbscServer(config, store), origin=origin)
        server = await serve(app, args.host, args.port, tls)
        print(f"DBSC demo listening on {origin}/", flush=True)
        # Stop cleanly on Ctrl-C or SIGTERM, so the private store directory is removed.
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        async with server:
            await stop.wait()


if __name__ == "__main__":
    asyncio.run(main())
