"""Full register → refresh → enforce → revoke flow, and the attack cases around it."""

import json

import pytest

from dbsc import (
    AuditEvent,
    Binding,
    ChallengeExpiredError,
    ChallengeMismatchError,
    Config,
    DbscServer,
    InMemoryStore,
    JwtInvalidError,
    MissingChallengeError,
    SessionNotFoundError,
)
from tests.conftest import ServerFactory
from tests.support import (
    COOKIE_NAME,
    FakeClock,
    FakeDevice,
    RecordingAuditLogger,
    ctx,
    refresh_challenge,
    refresh_via_403,
    register,
    registration_challenge,
)

SID = "session-AAA"


async def test_full_flow(server: DbscServer, device: FakeDevice) -> None:
    offer = await server.build_registration_header_response(ctx(SID))
    assert offer.status is None, "login decoration leaves the caller's status alone"
    assert registration_challenge(offer)
    assert offer.headers["Secure-Session-Registration"].startswith('(ES256); path="/dbsc/register"')
    assert await server.get_binding(ctx(SID)) is None, "no binding yet: gate degrades"

    reg = await server.register(device.registration_jwt(registration_challenge(offer)), ctx(SID))
    assert isinstance(await server.get_binding(ctx(SID)), Binding)
    assert reg.status == 200
    assert reg.content_type == "application/json"
    assert len(reg.cookies) == 1
    assert "Sec-Secure-Session-Id" in reg.headers
    assert "Secure-Session-Challenge" not in reg.headers, "Chrome rejects it on registration"
    cookie1 = reg.cookies[0].value

    challenge_403, refreshed = await refresh_via_403(server, device, SID)
    assert challenge_403.status == 403
    assert challenge_403.content_type == "application/json"
    cookie2 = refreshed.cookies[0].value
    assert refreshed.status == 200
    assert cookie2 not in ("", cookie1), "refresh rotates the bound cookie value"
    assert (
        refreshed.headers["Secure-Session-Challenge"]
        != challenge_403.headers["Secure-Session-Challenge"]
    ), "refresh rotates the challenge too"


async def test_register_emits_session_instructions(server: DbscServer, device: FakeDevice) -> None:
    reg = await register(server, device, SID)
    assert reg.body is not None
    assert json.loads(reg.body) == {
        "session_identifier": reg.headers["Sec-Secure-Session-Id"],
        "refresh_url": "/dbsc/refresh",
        "scope": {"origin": "https://example.test", "include_site": False},
        "credentials": [
            {
                "type": "cookie",
                "name": COOKIE_NAME,
                "attributes": "Path=/; Secure; HttpOnly; SameSite=Lax",
            },
        ],
    }
    cookie = reg.cookies[0]
    assert (cookie.name, cookie.path, cookie.secure, cookie.http_only, cookie.same_site) == (
        COOKIE_NAME,
        "/",
        True,
        True,
        "Lax",
    )


async def test_session_instructions_json_is_empty_object_when_unbound(server: DbscServer) -> None:
    assert await server.session_instructions_json(ctx("nobody")) == "{}"


async def test_bound_cookie_matching(server: DbscServer, device: FakeDevice) -> None:
    cookie1 = (await register(server, device, SID)).cookies[0].value
    _, refreshed = await refresh_via_403(server, device, SID)
    cookie2 = refreshed.cookies[0].value
    binding = await server.get_binding(ctx(SID))
    assert binding is not None

    def matches(b: Binding, cookies: dict[str, str]) -> bool:
        return server.bound_cookie_matches(b, ctx(SID, cookies=cookies))

    assert matches(binding, {COOKIE_NAME: cookie2}), "rotated cookie matches"
    assert matches(binding, {COOKIE_NAME: cookie1}), "previous cookie matches within its lifetime"
    assert not matches(binding, {}), "missing cookie does not match"
    assert not matches(binding, {COOKIE_NAME: ""})
    assert not matches(binding, {COOKIE_NAME: "never-issued"})
    assert not matches(binding, {COOKIE_NAME: "nön-ascii"}), "non-ASCII never raises"

    _, refreshed2 = await refresh_via_403(server, device, SID)
    cookie3 = refreshed2.cookies[0].value
    binding2 = await server.get_binding(ctx(SID))
    assert binding2 is not None
    assert matches(binding2, {COOKIE_NAME: cookie2}), "now-previous (2nd) cookie matches"
    assert not matches(binding2, {COOKIE_NAME: cookie1}), "single-depth: two rotations ago fails"
    assert matches(binding2, {COOKIE_NAME: cookie3})


async def test_previous_cookie_bounded_by_its_own_expiry(
    server: DbscServer, clock: FakeClock
) -> None:
    now = int(clock())

    def binding(previous_expires_at: int) -> Binding:
        return Binding(
            "user-1",
            "sid",
            "cur",
            "pem",
            "ES256",
            "chal",
            now,
            now,
            now,
            "prev",
            previous_expires_at,
        )

    def matches(b: Binding, value: str) -> bool:
        return server.bound_cookie_matches(b, ctx(SID, cookies={COOKIE_NAME: value}))

    live, dead = binding(now + 60), binding(now - 1)
    assert matches(live, "prev")
    assert not matches(dead, "prev")
    assert matches(dead, "cur"), "current still matches after the previous one expired"


async def test_previous_cookie_expiry_is_issuance_plus_max_age(
    server: DbscServer, device: FakeDevice, clock: FakeClock
) -> None:
    cookie1 = (await register(server, device, SID)).cookies[0].value
    issued_at = int(clock())
    clock.advance(100)
    await refresh_via_403(server, device, SID)
    binding = await server.get_binding(ctx(SID))
    assert binding is not None
    assert binding.previous_cookie_value == cookie1
    assert binding.previous_cookie_expires_at == issued_at + 300

    clock.advance(200)
    assert not server.bound_cookie_matches(binding, ctx(SID, cookies={COOKIE_NAME: cookie1}))


async def test_refresh_signed_by_a_different_device_is_terminal(
    server: DbscServer, device: FakeDevice
) -> None:
    await register(server, device, "session-BBB")
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx("session-BBB")))
    with pytest.raises(JwtInvalidError):
        await server.refresh(FakeDevice().refresh_jwt(challenge), ctx("session-BBB"))


async def test_wrong_challenge_is_benign(server: DbscServer, device: FakeDevice) -> None:
    await register(server, device, "session-BBB")
    await server.issue_refresh_challenge(ctx("session-BBB"))
    with pytest.raises(ChallengeMismatchError):
        await server.refresh(device.refresh_jwt("wrong-challenge"), ctx("session-BBB"))
    assert isinstance(await server.get_binding(ctx("session-BBB")), Binding), "not revoked"


async def test_refresh_on_unbound_session(server: DbscServer, device: FakeDevice) -> None:
    with pytest.raises(SessionNotFoundError):
        await server.refresh(device.refresh_jwt("x"), ctx("session-UNKNOWN"))


async def test_refresh_with_mismatched_session_identifier(
    server: DbscServer, device: FakeDevice
) -> None:
    await register(server, device, SID)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))
    with pytest.raises(SessionNotFoundError, match="identifier mismatch"):
        await server.refresh(
            device.refresh_jwt(challenge), ctx(SID, {"Sec-Secure-Session-Id": "someone-else"})
        )


async def test_refresh_with_empty_challenge_is_retryable(
    server: DbscServer, store: InMemoryStore, device: FakeDevice
) -> None:
    await register(server, device, SID)
    binding = await server.get_binding(ctx(SID))
    assert binding is not None
    await store.put_binding(SID, binding.with_challenge("", binding.challenge_time))
    with pytest.raises(MissingChallengeError):
        await server.refresh(device.refresh_jwt("x"), ctx(SID))


async def test_issue_refresh_challenge_when_unbound(server: DbscServer) -> None:
    response = await server.issue_refresh_challenge(ctx("nobody"))
    assert response.status == 403
    assert "Secure-Session-Challenge" not in response.headers, "nothing to refresh"


async def test_expired_registration_challenge_rejected(
    make_server: ServerFactory, device: FakeDevice, clock: FakeClock
) -> None:
    # The shortest valid config: challenge TTL 2s > cookie max-age 1s.
    server = make_server(Config(cookie_max_age_seconds=1, challenge_ttl_seconds=2))
    offer = await server.build_registration_header_response(ctx("session-CCC"))
    clock.advance(3)
    with pytest.raises(ChallengeExpiredError):
        await server.register(
            device.registration_jwt(registration_challenge(offer)), ctx("session-CCC")
        )


async def test_register_without_offer(server: DbscServer, device: FakeDevice) -> None:
    with pytest.raises(MissingChallengeError):
        await server.register(device.registration_jwt("x"), ctx("session-NOOFFER"))


async def test_register_with_wrong_challenge(server: DbscServer, device: FakeDevice) -> None:
    await server.build_registration_header_response(ctx(SID))
    with pytest.raises(JwtInvalidError, match="Challenge mismatch"):
        await server.register(device.registration_jwt("not-the-offered-one"), ctx(SID))
    assert await server.get_binding(ctx(SID)) is None


async def test_registration_challenge_is_single_use(server: DbscServer, device: FakeDevice) -> None:
    offer = await server.build_registration_header_response(ctx(SID))
    jwt = device.registration_jwt(registration_challenge(offer))
    await server.register(jwt, ctx(SID))
    with pytest.raises(MissingChallengeError):
        await server.register(jwt, ctx(SID))


async def test_registration_audit_events(make_server: ServerFactory, device: FakeDevice) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    await server.build_registration_header_response(ctx(SID))
    with pytest.raises(JwtInvalidError):
        await server.register(FakeDevice().sign({"alg": "none"}, {"jti": "x"}), ctx(SID))
    await register(server, device, SID)
    assert audit.events == [AuditEvent.REGISTRATION_FAILED, AuditEvent.REGISTERED]


async def test_revoke(make_server: ServerFactory, device: FakeDevice) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    await register(server, device, "session-DDD")
    assert isinstance(await server.get_binding(ctx("session-DDD")), Binding)

    revoked = await server.revoke(ctx("session-DDD"), enforcement_terminated=True)
    assert await server.get_binding(ctx("session-DDD")) is None
    assert revoked.cookies[0].delete is True
    assert revoked.cookies[0].name == COOKIE_NAME
    assert audit.events[-1] == AuditEvent.ENFORCEMENT_TERMINATED

    await register(server, device, "session-DDD")
    await server.revoke(ctx("session-DDD"))
    assert audit.events[-1] == AuditEvent.REVOKED


async def test_revoke_of_unbound_session_is_silent(make_server: ServerFactory) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    revoked = await server.revoke(ctx("nobody"))
    assert revoked.cookies[0].delete is True, "cookie deletion is still emitted"
    assert audit.events == []


async def test_enforcement_gate_helpers(
    server: DbscServer, device: FakeDevice, clock: FakeClock
) -> None:
    assert server.is_document_request(ctx(SID, {"sec-fetch-dest": "document"}))
    assert not server.is_document_request(ctx(SID, {"Sec-Fetch-Dest": "script"}))
    assert not server.is_document_request(ctx(SID))

    await register(server, device, SID)
    binding = await server.get_binding(ctx(SID))
    assert binding is not None
    assert server.is_within_registration_grace(binding)
    clock.advance(5)
    assert not server.is_within_registration_grace(binding)


async def test_failed_registration_attempt_does_not_burn_the_offer(
    server: DbscServer, device: FakeDevice
) -> None:
    """Junk registrations (e.g. from someone holding a stolen session cookie) can't use up the
    offer and keep the real browser from binding, which would leave the session on cookie auth.
    """
    offer = await server.build_registration_header_response(ctx(SID))
    challenge = registration_challenge(offer)

    for junk in (
        "not.a.jwt",
        FakeDevice().sign({"alg": "none"}, {"jti": challenge}),
        FakeDevice().registration_jwt("wrong-challenge"),
    ):
        with pytest.raises(JwtInvalidError):
            await server.register(junk, ctx(SID))

    await server.register(device.registration_jwt(challenge), ctx(SID))
    assert await server.get_binding(ctx(SID)) is not None
