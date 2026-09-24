"""Hardening beyond the protocol flow, grouped by OWASP Top 10:2025 category."""

import base64
import dataclasses
import json
from collections.abc import Callable

import pytest

from dbsc import (
    AuditEvent,
    Binding,
    Config,
    CorruptStateError,
    DbscResponse,
    DbscServer,
    JwtInvalidError,
    JwtVerifier,
    PendingRegistration,
    RequestContext,
    ScopeRule,
    SessionNotFoundError,
)
from tests.conftest import ServerFactory
from tests.support import (
    COOKIE_NAME,
    ORIGIN,
    FakeDevice,
    RecordingAuditLogger,
    b64u,
    ctx,
    refresh_challenge,
    register,
    registration_challenge,
)

SID = "session-SEC"


def as_user(user_id: str, **kwargs: dict[str, str]) -> RequestContext:
    return RequestContext(
        SID, user_id, ORIGIN, kwargs.get("headers", {}), kwargs.get("cookies", {})
    )


# --- A07 Authentication Failures: session fixation ------------------------------------------
# If the app keeps a session id across login, an attacker can register their own device on a
# session id, plant that id in the victim's browser, and let the victim log in. Their device key
# would then keep refreshing the victim's session. A binding records its user; when both sides
# know the user and they differ, the binding is refused everywhere.


async def _bound_to_attacker(server: DbscServer, device: FakeDevice) -> tuple[Binding, str]:
    reg = await register(server, device, as_user("attacker"))
    binding = await server.get_binding(as_user("attacker"))
    assert binding is not None
    assert binding.user_id == "attacker"
    return binding, reg.cookies[0].value


async def test_gate_refuses_another_users_binding(server: DbscServer, device: FakeDevice) -> None:
    binding, cookie = await _bound_to_attacker(server, device)
    assert server.bound_cookie_matches(binding, as_user("attacker", cookies={COOKIE_NAME: cookie}))
    assert not server.bound_cookie_matches(
        binding, as_user("victim", cookies={COOKIE_NAME: cookie})
    )


async def test_refresh_refuses_another_users_binding(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    await _bound_to_attacker(server, device)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(as_user("victim")))
    before = await server.get_binding(as_user("victim"))

    with pytest.raises(SessionNotFoundError):  # terminal: revoke and log out
        await server.refresh(device.refresh_jwt(challenge), as_user("victim"))
    assert audit.events[-1] == AuditEvent.REFRESH_FAILED
    assert await server.get_binding(as_user("victim")) == before, "the cookie was not rotated"


async def test_advertise_skips_another_users_binding(
    server: DbscServer, device: FakeDevice
) -> None:
    binding, _ = await _bound_to_attacker(server, device)
    assert await server.advertise_refresh_challenge(binding, as_user("victim")) == DbscResponse()


async def test_registration_refuses_an_offer_made_to_another_user(
    server: DbscServer, device: FakeDevice
) -> None:
    offer = await server.build_registration_header_response(as_user("attacker"))
    jwt = device.registration_jwt(registration_challenge(offer))
    with pytest.raises(SessionNotFoundError):
        await server.register(jwt, as_user("victim"))
    assert await server.get_binding(as_user("victim")) is None


async def test_unknown_user_ids_skip_the_check(server: DbscServer, device: FakeDevice) -> None:
    """``""`` means "not known here"; the check only fires when both sides know the user."""
    binding, cookie = await _bound_to_attacker(server, device)
    assert server.bound_cookie_matches(binding, as_user("", cookies={COOKIE_NAME: cookie}))
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(as_user("")))
    assert (await server.refresh(device.refresh_jwt(challenge), as_user(""))).status == 200


async def test_same_user_is_unaffected(server: DbscServer, device: FakeDevice) -> None:
    await register(server, device, SID)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))
    assert (await server.refresh(device.refresh_jwt(challenge), ctx(SID))).status == 200


# --- A02 Security Misconfiguration / A05 Injection: configuration ---------------------------
# Config values end up in response headers and the session instructions; a bad value is refused
# when the Config is built, not discovered in production.


@pytest.mark.parametrize(
    "overrides",
    [
        pytest.param({"cookie_name": "dbsc"}, id="cookie-name-without-__Host-"),
        pytest.param({"cookie_name": "__Secure-dbsc"}, id="cookie-name-__Secure-"),
        pytest.param({"cookie_name": "__Host-a;b"}, id="cookie-name-separator"),
        pytest.param({"register_path": "dbsc/register"}, id="relative-path"),
        pytest.param({"refresh_path": "//evil.example/refresh"}, id="scheme-relative-path"),
        pytest.param({"register_path": '/a"; challenge="x'}, id="path-quote-injection"),
        pytest.param({"refresh_path": "/a\\b"}, id="path-backslash"),
        pytest.param({"refresh_path": "/a\r\nSet-Cookie: x=1"}, id="path-crlf"),
        pytest.param({"refresh_path": "/a b"}, id="path-space"),
        pytest.param({"cookie_same_site": "Lax; Domain=evil.example"}, id="samesite-injection"),
        pytest.param({"cookie_same_site": "lax"}, id="samesite-case"),
        pytest.param({"cookie_max_age_seconds": 0}, id="max-age-zero"),
        pytest.param({"cookie_max_age_seconds": 3601}, id="max-age-too-long"),
        pytest.param({"challenge_ttl_seconds": 86401}, id="challenge-ttl-too-long"),
        pytest.param({"registration_grace_seconds": -1}, id="grace-negative"),
        pytest.param({"registration_grace_seconds": 61}, id="grace-too-long"),
        pytest.param({"allowed_refresh_initiators": ["https://rp.example"]}, id="initiator-url"),
        pytest.param({"allowed_refresh_initiators": ["rp.example/x"]}, id="initiator-path"),
        pytest.param({"allowed_refresh_initiators": ["rp example"]}, id="initiator-space"),
    ],
)
def test_config_rejects_unsafe_values(overrides: dict[str, object]) -> None:
    with pytest.raises(ValueError, match="DBSC"):
        Config(**overrides)  # ty: ignore[invalid-argument-type]


def test_config_accepts_safe_values() -> None:
    Config(
        cookie_name="__Host-app_dbsc",
        register_path="/auth/dbsc/register",
        refresh_path="/auth/dbsc/refresh",
        cookie_same_site="Strict",
        cookie_max_age_seconds=600,
        challenge_ttl_seconds=1200,
        registration_grace_seconds=0,
        allowed_refresh_initiators=["rp.example", "*.rp.example", "rp.example:8443", "  "],
    )


@pytest.mark.parametrize(
    "make",
    [
        pytest.param(lambda: ScopeRule.exclude(path="assets/"), id="relative-path"),
        pytest.param(lambda: ScopeRule.exclude(path="//evil.example/"), id="scheme-relative"),
        pytest.param(lambda: ScopeRule.include(domain="https://x.example"), id="domain-url"),
        pytest.param(lambda: ScopeRule.include(domain="x.example/y"), id="domain-path"),
    ],
)
def test_scope_rule_rejects_unsafe_values(make: Callable[[], ScopeRule]) -> None:
    with pytest.raises(ValueError, match="DBSC"):
        make()


@pytest.mark.parametrize(
    "origin",
    ["http://example.com", "https://example.com/path", "ftp://example.com", "example.com", ""],
)
def test_request_context_rejects_non_secure_origins(origin: str) -> None:
    with pytest.raises(ValueError, match="DBSC"):
        RequestContext(SID, "u", origin)


@pytest.mark.parametrize(
    "origin",
    [
        "https://example.com",
        "https://example.com:8443",
        "http://localhost:8080",
        "http://127.0.0.1",
    ],
)
def test_request_context_accepts_secure_origins(origin: str) -> None:
    RequestContext(SID, "u", origin)


def test_request_context_rejects_unsafe_initiators() -> None:
    with pytest.raises(ValueError, match="DBSC"):
        RequestContext(SID, "u", ORIGIN, allowed_refresh_initiators=["https://rp.example"])


# --- A02: responses that carry session state are never cached -----------------------------


async def test_stateful_responses_are_not_cacheable(server: DbscServer, device: FakeDevice) -> None:
    offer = await server.build_registration_header_response(ctx(SID))
    reg = await server.register(device.registration_jwt(registration_challenge(offer)), ctx(SID))
    binding = await server.get_binding(ctx(SID))
    assert binding is not None
    advertised = await server.advertise_refresh_challenge(binding, ctx(SID))
    challenge_403 = await server.issue_refresh_challenge(ctx(SID))
    refreshed = await server.refresh(
        device.refresh_jwt(refresh_challenge(challenge_403)[0]), ctx(SID)
    )
    unbound_403 = await server.issue_refresh_challenge(ctx("nobody"))
    revoked = await server.revoke(ctx(SID))

    for response in (offer, reg, advertised, challenge_403, refreshed, unbound_403, revoked):
        assert response.headers.get("Cache-Control") == "no-store"


# --- A08 Software or Data Integrity Failures: stored records ---------------------------------
# Stored values flow into response headers and cookies. A tampered or corrupted record that could
# inject into them fails closed at decode time, like any other unreadable record.

GOOD = Binding("user-1", "sid", "cookie", "pem", "ES256", "chal", 1, 1)


@pytest.mark.parametrize(
    "field",
    ["session_identifier", "challenge", "previous_challenge"],
)
@pytest.mark.parametrize("bad", ['a"b', "a\\b", "a\r\nX: y", "a b", "é"])
def test_binding_rejects_header_unsafe_identifiers(field: str, bad: str) -> None:
    raw = dataclasses.replace(GOOD, **{field: "x"}).to_json().replace('"x"', json.dumps(bad), 1)
    with pytest.raises(CorruptStateError):
        Binding.from_json(raw)


@pytest.mark.parametrize("field", ["cookie_value", "previous_cookie_value"])
@pytest.mark.parametrize("bad", ["a;b", "a,b", 'a"b', "a b", "a\r\nb"])
def test_binding_rejects_cookie_unsafe_values(field: str, bad: str) -> None:
    raw = dataclasses.replace(GOOD, **{field: "x"}).to_json().replace('"x"', json.dumps(bad), 1)
    with pytest.raises(CorruptStateError):
        Binding.from_json(raw)


def test_stored_records_with_duplicate_keys_are_corrupt() -> None:
    raw = GOOD.to_json()[:-1] + ',"cookieValue":"other"}'
    with pytest.raises(CorruptStateError):
        Binding.from_json(raw)
    with pytest.raises(CorruptStateError):
        PendingRegistration.from_json(
            '{"userId":"u","regChallenge":"a","regChallenge":"b","regChallengeTime":1}'
        )


# --- A04 Cryptographic Failures / A08: JWT hardening --------------------------------------


def test_jwt_with_duplicate_header_members_is_rejected(device: FakeDevice) -> None:
    """Parsers disagree on duplicate members (first vs last wins); refuse them outright."""
    jwt = device.registration_jwt("x")
    header, payload, signature = jwt.split(".")
    decoded = base64.urlsafe_b64decode(header + "==").decode()
    forged = b64u('{"alg":"none",' + decoded[1:])
    with pytest.raises(JwtInvalidError):
        JwtVerifier().parse(f"{forged}.{payload}.{signature}")


def test_jwt_with_critical_extensions_is_rejected(device: FakeDevice) -> None:
    """RFC 7515 §4.1.11: a recipient that doesn't understand every ``crit`` entry must reject."""
    jwt = device.sign(
        {"alg": "ES256", "jwk": device.jwk, "crit": ["b64"], "b64": False}, {"jti": "x"}
    )
    with pytest.raises(JwtInvalidError, match="crit"):
        JwtVerifier().verify_registration_jwt(JwtVerifier().parse(jwt))


def test_oversized_jwt_is_rejected_before_decoding() -> None:
    with pytest.raises(JwtInvalidError, match="too large"):
        JwtVerifier().parse("a" * 9000 + ".b.c")


# --- A09 Security Logging and Alerting Failures -------------------------------------------


async def test_malformed_jwts_are_audited(make_server: ServerFactory, device: FakeDevice) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    await server.build_registration_header_response(ctx(SID))
    with pytest.raises(JwtInvalidError):
        await server.register("garbage", ctx(SID))
    assert audit.events[-1] == AuditEvent.REGISTRATION_FAILED

    await register(server, device, SID)
    await server.issue_refresh_challenge(ctx(SID))
    with pytest.raises(JwtInvalidError):
        await server.refresh("garbage", ctx(SID))
    assert audit.events[-1] == AuditEvent.REFRESH_FAILED


async def test_response_headers_are_never_shared(server: DbscServer) -> None:
    """Mutating one response's headers must not leak into any other response."""
    first = await server.revoke(ctx(SID))
    first.headers["X-Leak"] = "user-a"  # ty: ignore[invalid-assignment]
    second = await server.issue_refresh_challenge(ctx("nobody"))
    third = await server.revoke(ctx(SID))
    assert "X-Leak" not in second.headers
    assert "X-Leak" not in third.headers
