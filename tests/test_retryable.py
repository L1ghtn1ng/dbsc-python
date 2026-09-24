"""A benign challenge mismatch must not terminate the session; a forged signature still must."""

import pytest

from dbsc import (
    AuditEvent,
    Binding,
    ChallengeExpiredError,
    ChallengeMismatchError,
    Config,
    CorruptStateError,
    DbscError,
    JwtInvalidError,
    MissingChallengeError,
    RetryableRefreshError,
    SessionNotFoundError,
)
from tests.conftest import ServerFactory
from tests.support import (
    FakeClock,
    FakeDevice,
    RecordingAuditLogger,
    ctx,
    refresh_challenge,
    register,
)


async def test_idle_session_concurrent_refreshes_are_benign(
    make_server: ServerFactory, device: FakeDevice, clock: FakeClock
) -> None:
    """Idle session past TTL, two concurrent refreshes holding the same stale challenge.

    Refresh A expires it (benign); refresh B must mismatch benignly too, not revoke.
    """
    audit = RecordingAuditLogger()
    server = make_server(Config(cookie_max_age_seconds=1, challenge_ttl_seconds=2), audit=audit)
    sid = "session-IDLE-RACE"
    await register(server, device, sid)

    # Drive one successful refresh so the loop is in steady state.
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(sid)))
    await server.refresh(device.refresh_jwt(challenge), ctx(sid))
    binding = await server.get_binding(ctx(sid))
    assert binding is not None
    stale = binding.challenge

    clock.advance(3)  # past challenge_ttl_seconds

    with pytest.raises(ChallengeExpiredError):
        await server.refresh(device.refresh_jwt(stale), ctx(sid))
    assert audit.events[-1] == AuditEvent.REFRESH_RETRYABLE

    fresh, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(sid)))
    assert fresh != stale

    # The demoted previous challenge is already past its own TTL, so this is a genuine mismatch.
    with pytest.raises(ChallengeMismatchError) as excinfo:
        await server.refresh(device.refresh_jwt(stale), ctx(sid))
    assert isinstance(excinfo.value, RetryableRefreshError)
    assert not isinstance(excinfo.value, JwtInvalidError)
    assert isinstance(await server.get_binding(ctx(sid)), Binding), "session not revoked"
    assert audit.events[-1] == AuditEvent.REFRESH_RETRYABLE
    assert AuditEvent.REFRESH_FAILED not in audit.events


async def test_forged_signature_is_still_terminal(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    audit = RecordingAuditLogger()
    server = make_server(audit=audit)
    sid = "session-FORGED"
    await register(server, device, sid)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(sid)))

    with pytest.raises(JwtInvalidError) as excinfo:
        await server.refresh(FakeDevice().refresh_jwt(challenge), ctx(sid))
    assert not isinstance(excinfo.value, RetryableRefreshError)
    assert audit.events[-1] == AuditEvent.REFRESH_FAILED


@pytest.mark.parametrize(
    "error", [ChallengeMismatchError, ChallengeExpiredError, MissingChallengeError]
)
def test_retryable_family(error: type[DbscError]) -> None:
    assert issubclass(error, RetryableRefreshError)
    assert issubclass(error, DbscError)


@pytest.mark.parametrize("error", [JwtInvalidError, SessionNotFoundError, CorruptStateError])
def test_terminal_family(error: type[DbscError]) -> None:
    assert not issubclass(error, RetryableRefreshError)
    assert issubclass(error, DbscError)
