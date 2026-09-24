[![CI](https://github.com/L1ghtn1ng/dbsc-python/actions/workflows/ci.yml/badge.svg)](https://github.com/L1ghtn1ng/dbsc-python/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/dbsc.svg)](https://pypi.org/project/dbsc/)
[![Python 3.14+](https://img.shields.io/badge/Python-3.14+-green.svg)](https://www.python.org)
[![Licensed under the MIT License](https://img.shields.io/badge/License-MIT-blue.svg)](https://github.com/L1ghtn1ng/dbsc-python/blob/main/LICENSE)

# dbsc-python
*A small, framework-agnostic, async Python server library for Device Bound Session Credentials (DBSC).*

[DBSC](https://github.com/w3c/webappsec-dbsc) cryptographically binds an authenticated session to a hardware-backed device key (TPM / secure enclave). A stolen session cookie can no longer be replayed from another device: the short-lived bound cookie expires every few minutes and is only refreshable by signing a server challenge with a private key that never leaves the device.

It is pure HTTP headers: **no JavaScript, no frontend assets, no database tables required**. Non-DBSC browsers simply ignore the registration header and continue on normal cookie auth, so enabling it cannot lock anyone out.

This is a Python port of [report-uri/dbsc-php](https://github.com/report-uri/dbsc-php), which is extracted from [Report URI](https://report-uri.com)'s production DBSC integration. It carries the wire-protocol corrections that only surface when integrating against a real browser (see [Wire-protocol notes](#wire-protocol-notes)).

## Contents

- [Design](#design)
- [Installation](#installation)
- [Flow](#flow)
- [Integrating](#integrating)
- [Enforcement gate](#enforcement-gate)
- [Storage](#storage)
- [Audit logging](#audit-logging)
- [API overview](#api-overview)
- [Wire-protocol notes](#wire-protocol-notes)
- [Contributing, security and changelog](#contributing-security-and-changelog)

## Design

- **One dependency.** [`cryptography`](https://cryptography.io) for ES256 verification, because the standard library has no elliptic-curve crypto. Everything else (JSON, base64url, nonces, constant-time comparison) is stdlib. About 700 lines of code, auditable in one sitting.
- **Async.** Everything that touches the store or the audit log is `async`, so a Redis- or database-backed store never blocks the event loop. Signature verification is CPU-bound (microseconds) and stays synchronous.
- **Framework-agnostic.** The library never reads the request, sends a header, or sets a cookie. Every operation takes a `RequestContext` you build from your framework's request and returns a `DbscResponse` you apply to your framework's response.
- **Storage is yours.** You implement the `Store` protocol (Redis, a table, …). An `InMemoryStore` is bundled for tests and experimentation.
- **The crypto is deliberately minimal**: ES256 only, signature plus a single-use challenge nonce. See the `JwtVerifier` docstring for why `iat`/`exp`/`iss`/`aud` are intentionally *not* checked.
- **Fully typed** (ships `py.typed`), checked with [ty](https://github.com/astral-sh/ty).
- **Secure by default.** Unsafe configuration is refused at startup, stored state fails closed, concurrent requests can't undo each other, and every state change is audited. [SECURITY.md](https://github.com/L1ghtn1ng/dbsc-python/blob/main/SECURITY.md) maps the design to the OWASP Top 10:2025 and lists what your integration must do.

## Installation

Requires Python 3.14+.

```bash
uv add dbsc
```

or

```bash
pip install dbsc
```

The entry point is `dbsc.DbscServer`:

```python
from dbsc import Config, DbscServer, InMemoryStore

dbsc = DbscServer(Config(cookie_name="__Host-myapp_dbsc"), InMemoryStore())
```

`InMemoryStore` is for tests and single-process experiments only. Use a shared, persistent store in production (see [Storage](#storage)).

## Flow

```
        BROWSER (DBSC-capable)              YOUR APP
   ----------------------------------------------------------------
   GET  /login  (full auth done) ----->  build_registration_header_response()
                                <-----   Secure-Session-Registration: (ES256); ...
   POST /dbsc/register (signed JWT) -->  register()
                                <-----   200 + Set-Cookie __Host-…_dbsc + Sec-Secure-Session-Id
                                          + session-instructions JSON
   ... every ~few minutes ...
   POST /dbsc/refresh (no body)  ----->  issue_refresh_challenge()
                                <-----   403 + Secure-Session-Challenge="…"; id="…"
   POST /dbsc/refresh (signed JWT) -->  refresh()
                                <-----   200 + rotated Set-Cookie + new challenge
   GET  /account (every request) ----->  enforcement gate (see below)
   GET  /logout                  ----->  revoke()
```

A complete reference server (stdlib `asyncio`, no framework) is in [`examples/demo_server.py`](https://github.com/L1ghtn1ng/dbsc-python/blob/main/examples/demo_server.py). DBSC is browser-native (there's no JS API to script), so exercise it with a DBSC-capable browser over HTTPS. From a clone of the repository:

```bash
uv run python -m examples.demo_server --cert cert.pem --key key.pem
```

## Integrating

You translate in both directions: build a `RequestContext` from your framework's request, and apply the returned `DbscResponse` to your framework's response.

```python
from dbsc import DbscResponse, RequestContext


def dbsc_context(request, session_id: str, user_id: str) -> RequestContext:
    return RequestContext(
        session_id=session_id,  # your stable session id (see Storage)
        user_id=user_id,  # pass it whenever known; "" only before login
        origin_host_url="https://example.com",  # from your config, never the Host header
        headers=dict(request.headers),  # any casing
        cookies=dict(request.cookies),
    )


def apply(result: DbscResponse, response) -> None:
    for name, value in result.headers.items():
        response.headers[name] = value
    for cookie in result.cookies:
        if cookie.delete:
            response.delete_cookie(cookie.name, path=cookie.path)
        else:
            response.set_cookie(
                cookie.name,
                cookie.value,
                expires=cookie.expires_at,  # Unix seconds
                path=cookie.path,
                secure=cookie.secure,
                httponly=cookie.http_only,
                samesite=cookie.same_site,
            )
    if result.content_type is not None:
        response.headers["Content-Type"] = result.content_type
    if result.status is not None:  # None: leave your own status alone
        response.status_code = result.status
    if result.body is not None:
        response.body = result.body
```

Every `DbscResponse` that carries session state includes `Cache-Control: no-store`, so it can't be cached and replayed to someone else. Apply the headers as given.

Depending on the browser version, the signed JWT arrives in either the `Secure-Session-Response` or the `Sec-Session-Response` header, so accept both. Strip surrounding double quotes before passing it on:

```python
jwt = (ctx.header("Secure-Session-Response") or ctx.header("Sec-Session-Response") or "").strip('"')
```

### Registration

After **full** authentication (post-2FA / post-passkey), merge the offer into the login response:

```python
apply(await dbsc.build_registration_header_response(ctx), response)
```

On `POST /dbsc/register`, return `register()`'s response. On any `DbscError`, respond 4xx and leave the user on plain cookie auth:

```python
try:
    apply(await dbsc.register(jwt, ctx), response)
except DbscError:
    response.status_code = 401
```

### Refresh

On `POST /dbsc/refresh`, a request with no JWT gets a challenge. A request with a JWT is verified under the failure contract below:

```python
if not jwt:
    apply(await dbsc.issue_refresh_challenge(ctx), response)  # phase 1: 403 + challenge
else:
    try:
        apply(await dbsc.refresh(jwt, ctx), response)  # phase 2: 200 + rotated cookie
    except RetryableRefreshError:
        apply(await dbsc.issue_refresh_challenge(ctx), response)  # benign: 403, browser retries
    except DbscError:
        apply(await dbsc.revoke(ctx, enforcement_terminated=True), response)  # terminal
        # ...and terminate the authenticated session server-side.
```

`MissingChallengeError`, `ChallengeExpiredError`, and `ChallengeMismatchError` subclass `RetryableRefreshError`, so you can catch that once instead of enumerating three classes. `ChallengeMismatchError` is retryable, not terminal, because `refresh()` only reaches the challenge comparison after the JWT signature has already verified against the device key. A mismatch at that point can only be a benign race (idle session, concurrent refresh, lost 403), never forgery. The audit log shows the difference too: a retryable failure logs `AuditEvent.REFRESH_RETRYABLE` (`"dbscRefreshRetryable"`), not `AuditEvent.REFRESH_FAILED`.

**Order matters:** every `RetryableRefreshError` is also a `DbscError`, so the `except RetryableRefreshError` clause must come first. A lone `except DbscError` force-logs users out over benign races.

**Terminal failures must end the session server-side.** Do not rely on the browser or on cookie expiry. That is the failure mode that leaves a stolen-cookie session alive.

### Logout

Call `revoke()` and apply its response. It deletes the DBSC state and the bound cookie, which is independent of your session cookie:

```python
apply(await dbsc.revoke(ctx), response)
```

## Enforcement gate

The library exposes the primitives but does **not** run the gate itself, because *where* you enforce depends on your routing. The recommended policy (also in `examples/demo_server.py`):

```python
async def enforce_dbsc(ctx: RequestContext, response) -> bool:
    """Run the gate. False means the session was terminated: log out and redirect to login."""
    try:
        binding = await dbsc.get_binding(ctx)
    except CorruptStateError:
        # Present but unreadable: fail closed. Never fall through to cookie auth.
        apply(await dbsc.revoke(ctx, enforcement_terminated=True), response)
        return False

    if binding is None:
        # Never registered: unsupported browser, or not yet. Degrade to normal cookie auth.
        # (Do NOT block here. This is what makes locking out a Firefox user impossible.)
        return True

    must_check = dbsc.is_document_request(ctx) or not dbsc.is_within_registration_grace(binding)
    if must_check and not dbsc.bound_cookie_matches(binding, ctx):
        # Bound session, bad/absent device cookie: revoke, then log the user out.
        apply(await dbsc.revoke(ctx, enforcement_terminated=True), response)
        return False
    return True
```

Enforce on document loads **and** on subresources past the registration grace. Document-only enforcement would let a stolen cookie exfiltrate via XHR within the cookie lifetime. Skip the gate on the `/dbsc/*` endpoints themselves.

Optionally, on a document response that passed the gate, call `await dbsc.advertise_refresh_challenge(binding, ctx)` and apply the result. This makes the first refresh single-phase (see [Wire-protocol notes](#wire-protocol-notes)).

## Storage

Key DBSC state by your **stable session id**, in a **dedicated key space**, never in a read-modify-written shared session blob.

> This is the one non-obvious correctness requirement. Report URI shipped DBSC with state in the PHP session blob. The post-login navigation raced the `/dbsc/register` POST, both rewrote the whole blob last-writer-wins, the binding was clobbered, and enforcement silently no-oped. That left exactly the stolen-cookie hole DBSC exists to close. The `Store` protocol documents the requirements; back it with Redis or a table keyed by session id.

A complete Redis-backed store, using [`redis.asyncio`](https://redis.readthedocs.io/) (not a dependency of this library):

```python
from redis.asyncio import Redis
from redis.exceptions import WatchError

from dbsc import Binding, PendingRegistration, Store


class RedisStore(Store):
    def __init__(self, redis: Redis, challenge_ttl: int = 900, session_ttl: int = 64800) -> None:
        self._redis = redis
        self._challenge_ttl = challenge_ttl  # match Config.challenge_ttl_seconds
        self._session_ttl = session_ttl  # match your authenticated session lifetime

    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        await self._redis.set(f"dbsc:reg:{session_id}", pending.to_json(), ex=self._challenge_ttl)

    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        raw = await self._redis.get(f"dbsc:reg:{session_id}")
        return None if raw is None else PendingRegistration.from_json(raw)  # corrupt -> raises

    async def delete_pending_registration(self, session_id: str) -> None:
        await self._redis.delete(f"dbsc:reg:{session_id}")

    async def put_binding(self, session_id: str, binding: Binding) -> None:
        await self._redis.set(f"dbsc:bind:{session_id}", binding.to_json(), ex=self._session_ttl)

    async def get_binding(self, session_id: str) -> Binding | None:
        raw = await self._redis.get(f"dbsc:bind:{session_id}")
        return None if raw is None else Binding.from_json(raw)  # corrupt -> raises

    async def delete(self, session_id: str) -> None:
        await self._redis.delete(f"dbsc:reg:{session_id}", f"dbsc:bind:{session_id}")

    async def commit_registration(
        self, session_id: str, offer: PendingRegistration, binding: Binding
    ) -> bool:
        reg_key, bind_key = f"dbsc:reg:{session_id}", f"dbsc:bind:{session_id}"
        async with self._redis.pipeline() as pipe:
            try:
                await pipe.watch(reg_key)  # EXEC fails if a logout or new offer changes it
                raw = await pipe.get(reg_key)
                if raw is None or PendingRegistration.from_json(raw) != offer:  # corrupt -> raises
                    return False
                pipe.multi()
                pipe.delete(reg_key)
                pipe.set(bind_key, binding.to_json(), ex=self._session_ttl)
                await pipe.execute()
            except WatchError:
                return False
        return True

    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        key = f"dbsc:bind:{session_id}"
        async with self._redis.pipeline() as pipe:
            try:
                await pipe.watch(key)  # EXEC fails if anyone writes or deletes the key meanwhile
                raw = await pipe.get(key)
                if raw is None or Binding.from_json(raw) != expected:  # corrupt -> raises
                    return False
                pipe.multi()
                pipe.set(key, new.to_json(), ex=self._session_ttl)
                await pipe.execute()
            except WatchError:
                return False
        return True
```

The rules any store must follow:

- **Separate keys.** Pending registrations and bindings live under separate keys. "A binding exists" is the authoritative hard-DBSC mark.
- **TTLs.** Pending registrations expire on the challenge TTL; bindings expire with the session lifetime.
- **Fail closed.** `get_binding()` returns `None` **only** when no record exists. A present-but-unparseable record must raise `CorruptStateError`, which `Binding.from_json()` already does. The gate then fails closed instead of silently degrading to cookie auth.
- **Atomic updates.** A browser's first refresh routinely races the page load that triggered it, so the server never blindly writes back state it read earlier. Two methods must be atomic in a shared store:
  - `commit_registration(session_id, offer, binding)` consumes the registration offer and stores the binding in one step, and only if that exact offer is still stored. Registration only consumes the offer when it succeeds, so junk attempts can't use it up. A logout or newer login that lands mid-registration wins, and so does the first of two registrations racing on one offer. Without atomicity, both racing registrations bind (the second silently replacing the first), or a binding appears for a session that just logged out. Redis `WATCH`/`MULTI` does this, as above; in SQL, a transaction that deletes the offer row (checking it's unchanged) and inserts the binding.
  - `replace_binding(session_id, expected, new)` writes `new` only if the stored binding still equals `expected`, and returns `False` otherwise, including when the record is gone. Compare the decoded `Binding`s, not raw JSON. Otherwise a stale write can undo a cookie rotation, which logs a legitimate user out, or bring back a session that was just revoked. Redis `WATCH`/`MULTI` does this, as above; in SQL, an `UPDATE ... WHERE` on the old value, or a row lock.

  Subclass `Store` and you inherit defaults for both, built from the other methods. They're only safe within a single process, so override them for anything shared.

## Audit logging

Pass any object with an `async def log(self, event: AuditEvent, message: str, user_id: str | None) -> None` method as `DbscServer(..., audit=...)`. Every state transition is reported:

| `AuditEvent` | Value | When |
|---|---|---|
| `REGISTERED` | `dbscRegistered` | A registration succeeded |
| `REGISTRATION_FAILED` | `dbscRegistrationFailed` | A registration was rejected |
| `REFRESHED` | `dbscRefreshed` | A refresh rotated the bound cookie |
| `REFRESH_RETRYABLE` | `dbscRefreshRetryable` | A benign refresh failure (issue a new challenge) |
| `REFRESH_FAILED` | `dbscRefreshFailed` | A terminal refresh failure (worth alerting on) |
| `REVOKED` | `dbscRevoked` | `revoke()` on a bound session |
| `ENFORCEMENT_TERMINATED` | `dbscEnforcementTerminated` | `revoke(..., enforcement_terminated=True)` on a bound session |

`AuditEvent` is a `StrEnum`, so members compare equal to the plain string values.

## API overview

Everything below is importable from `dbsc`. Full details are in the docstrings.

**`DbscServer(config, store, *, jwt_verifier=None, audit=None, clock=time.time)`**

| Method | Async | Returns | Purpose |
|---|---|---|---|
| `build_registration_header_response(ctx)` | yes | `DbscResponse` | Offer DBSC after login (headers only, `status=None`) |
| `register(jwt, ctx)` | yes | `DbscResponse` | Verify the registration JWT, create the binding (200) |
| `issue_refresh_challenge(ctx)` | yes | `DbscResponse` | Rotate and return a challenge (403) |
| `refresh(jwt, ctx)` | yes | `DbscResponse` | Verify the refresh JWT, rotate cookie + challenge (200) |
| `revoke(ctx, *, enforcement_terminated=False)` | yes | `DbscResponse` | Delete state, emit a cookie deletion |
| `get_binding(ctx)` | yes | `Binding \| None` | The gate's lookup; raises `CorruptStateError` on unreadable state |
| `bound_cookie_matches(binding, ctx)` | no | `bool` | Constant-time bound-cookie check (current or live previous value); `False` for another user's binding |
| `is_document_request(ctx)` | no | `bool` | `Sec-Fetch-Dest: document` |
| `is_within_registration_grace(binding)` | no | `bool` | Inside `registration_grace_seconds` after registration |
| `advertise_refresh_challenge(binding, ctx)` | yes | `DbscResponse` | One-time seed challenge for a single-phase first refresh |
| `session_instructions_json(ctx)` | yes | `str` | The session-instructions JSON, or `{}` if unbound |

**`Config`** (keyword-only, immutable)

| Field | Default | Notes |
|---|---|---|
| `cookie_name` | `"__Host-dbsc"` | Must carry the `__Host-` prefix |
| `cookie_max_age_seconds` | `300` | Bound-cookie lifetime, 1-3600 |
| `register_path` | `"/dbsc/register"` | Absolute same-origin path |
| `refresh_path` | `"/dbsc/refresh"` | Absolute same-origin path |
| `challenge_ttl_seconds` | `900` | Must exceed `cookie_max_age_seconds`; at most 86400 |
| `registration_grace_seconds` | `5` | Subresource exemption right after registration, 0-60 |
| `cookie_same_site` | `"Lax"` | `Lax`, `Strict` or `None` |
| `allowed_refresh_initiators` | `()` | Host patterns; see wire-protocol notes |
| `scope_specification` | `()` | `ScopeRule`s; see wire-protocol notes |

Anything outside these rules raises `ValueError` when the `Config` is built, so a misconfiguration can't reach a response header. The same applies to `ScopeRule` values and to the `RequestContext` origin (`https`, or `http` on loopback only) and initiator overrides.

**Other types:** `RequestContext`, `DbscResponse`, `Cookie`, `ScopeRule` / `ScopeRuleType`, `Binding`, `PendingRegistration`, `Store` / `InMemoryStore`, `AuditLogger` / `NullAuditLogger` / `AuditEvent`, and `JwtVerifier` / `ParsedJwt` / `RegistrationResult`.

**Exceptions:** everything derives from `DbscError`.

| Exception | On refresh |
|---|---|
| `MissingChallengeError`, `ChallengeExpiredError`, `ChallengeMismatchError` (all `RetryableRefreshError`) | Benign: issue a new challenge |
| `JwtInvalidError`, `SessionNotFoundError`, `CorruptStateError` | Terminal: revoke and end the session |

## Wire-protocol notes

Baked into this library from integration testing against real Chrome. Change with care:

- **Registration is single-phase; refresh is two-phase** (403 + challenge, then 200). This is the opposite of how the spec reads at first glance.
- **The *first* refresh can optionally be made single-phase.** Steady-state refreshes already are (every 200 hands back the next challenge). Call `await advertise_refresh_challenge(binding, ctx)` on an ordinary authenticated *document* response in the registration→first-refresh window. It attaches the seed `Secure-Session-Challenge` once and records a one-way mark on the binding so later responses stay silent. The browser then holds a challenge when its first `/dbsc/refresh` fires and skips the 403. The spec forbids attaching this to the registration response (§9.2.1/§8.7: the `id` must name an already-existing session). The method takes a `Binding`, which only exists post-registration, so that misuse is structurally impossible. If the single delivery is missed, the browser falls back to the two-phase path, so there's no regression. A reactive 403 racing the advertised value is covered by single-depth challenge overlap: the immediately-previous challenge is accepted in `refresh()` until its own TTL, mirroring the bound-cookie overlap. Whether the browser actually skips the 403 is up to the browser. In this project's end-to-end tests (headless Chromium 149 and 150 on Linux, software keys), it usually still made the 403 round-trip, and the fallback held every time.
- **No `Secure-Session-Challenge` on the registration response**: Chrome reports a Challenge Error. The first refresh-flow 403 issues the challenge; the binding seeds an internal one only to stay valid until then.
- **Both the cookie value and the challenge must rotate on every refresh.** Re-emitting the existing cookie value makes Chrome treat it as "no refresh happened" and terminate.
- **`Secure-Session-Challenge` must carry the `id` sf-parameter** naming the session.
- **`challenge_ttl_seconds` must exceed `cookie_max_age_seconds`** (the `Config` constructor enforces this) so a challenge the browser cached just before cookie expiry is still valid when it is used.
- **The bound cookie uses `__Host-`**, so `include_site` is `false` (no subdomain span).
- **Scope the session to what it protects, not to the whole origin.** This is the default that
  costs you, and it is not obvious. Scope decides which requests the browser DEFERS while it
  refreshes an expired bound cookie, and every refresh spends a signature from a rate-limited device
  key. With the default whole-origin scope, your static assets are in it. A cold page load with
  an expired cookie fires every stylesheet, script and icon at once, and the browser attempts a
  **separate refresh for each**; it does not coalesce them. Measured against Chrome 151: seven
  assets, seven signing attempts in the same second, `quota_exceeded`, and a wedged session. Once
  the quota is gone refreshes stop, the browser will not register a replacement for a scope it
  already covers, and the site becomes indistinguishable from one with no DBSC support at all.
  Only clearing site data recovers it. Exclude anything that needs no session:

  ```python
  Config(
      scope_specification=[
          ScopeRule.exclude(path="/assets/"),
          ScopeRule.exclude(path="/healthz"),
      ]
  )
  ```

  Omitted from the wire entirely when empty (the spec default). Overridable per request via
  `RequestContext(..., scope_specification=[...])`, where `None` inherits the `Config` value and
  `[]` forces the key off. `path` is a **prefix**, not an exact match.

- **`allowed_refresh_initiators`** ([spec](https://w3c.github.io/webappsec-dbsc/#allowed-refresh-initiators)) lists out-of-scope hosts allowed to trigger a refresh on a cross-site-initiated navigation. By default Chrome refuses (a timing side-channel mitigation). Omitted when empty (the spec default). Set a static default via `Config(allowed_refresh_initiators=[...])`, or override per request via `RequestContext(..., allowed_refresh_initiators=[...])` (`None` falls back to `Config`, `[]` forces the key off). Entries pass through verbatim, wildcards included. **Security note:** each listed host regains the authentication-state timing oracle this mitigation removes, so list only relying parties you trust.

## Contributing, security and changelog

- **Contributing:** development setup, the checks CI runs, and the release process are in [CONTRIBUTING.md](https://github.com/L1ghtn1ng/dbsc-python/blob/main/CONTRIBUTING.md).
- **Security:** please report vulnerabilities privately; see [SECURITY.md](https://github.com/L1ghtn1ng/dbsc-python/blob/main/SECURITY.md). Don't open public issues for them.
- **Changelog:** [CHANGELOG.md](https://github.com/L1ghtn1ng/dbsc-python/blob/main/CHANGELOG.md).

## License

MIT (see [LICENSE](https://github.com/L1ghtn1ng/dbsc-python/blob/main/LICENSE)). © 2026 Report-URI Ltd. (the original [dbsc-php](https://github.com/report-uri/dbsc-php)) and © 2026 L1ghtn1ng (this Python port).
