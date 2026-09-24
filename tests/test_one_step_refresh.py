"""One-step first refresh: proactive challenge advertisement plus challenge-rotation overlap."""

import dataclasses
from collections.abc import Callable

import pytest

from dbsc import Binding, ChallengeMismatchError, DbscResponse, DbscServer, InMemoryStore
from tests.support import FakeClock, FakeDevice, ctx, refresh_via_403, register


async def _seed(server: DbscServer, device: FakeDevice, sid: str) -> Binding:
    await register(server, device, sid)
    binding = await server.get_binding(ctx(sid))
    assert binding is not None
    return binding


async def test_advertise_delivers_the_seed_exactly_once(
    server: DbscServer, device: FakeDevice
) -> None:
    sid = "session-ADV"
    binding = await _seed(server, device, sid)

    first = await server.advertise_refresh_challenge(binding, ctx(sid))
    assert first.headers["Secure-Session-Challenge"] == (
        f'"{binding.challenge}"; id="{binding.session_identifier}"'
    ), "carries the mandatory id sf-param"
    assert first.headers["Sec-Secure-Session-Id"] == binding.session_identifier

    after = await server.get_binding(ctx(sid))
    assert after is not None
    assert after.challenge == binding.challenge, "advertise does not rotate the challenge"
    assert after.challenge_time == binding.challenge_time
    assert after.challenge_advertised is True
    assert after.has_refreshed is False

    second = await server.advertise_refresh_challenge(after, ctx(sid))
    assert second.headers == {}
    assert second.cookies == ()


type Changes = Callable[[int], dict[str, object]]


@pytest.mark.parametrize(
    ("changes", "advertises"),
    [
        pytest.param(lambda _now: {}, True, id="control"),
        pytest.param(lambda _now: {"challenge": ""}, False, id="empty"),
        pytest.param(lambda now: {"challenge_time": now - 100_000}, False, id="expired"),
        pytest.param(lambda _now: {"has_refreshed": True}, False, id="already-refreshed"),
        pytest.param(lambda _now: {"challenge_advertised": True}, False, id="already-advertised"),
    ],
)
async def test_advertise_no_ops(
    server: DbscServer,
    store: InMemoryStore,
    clock: FakeClock,
    changes: Changes,
    advertises: bool,
) -> None:
    """Each guard alone stops the advertisement; the control shows the setup would advertise."""
    now = int(clock())
    seed = Binding("user-1", "sid", "c", "pem", "ES256", "seed", now, now)
    binding = dataclasses.replace(seed, **changes(now))
    await store.put_binding("s", binding)

    response = await server.advertise_refresh_challenge(binding, ctx("s"))

    assert ("Secure-Session-Challenge" in response.headers) is advertises
    if not advertises:
        assert response == DbscResponse()
        assert await store.get_binding("s") == binding, "nothing written"


async def test_refresh_accepts_the_advertised_then_rotated_challenge(
    server: DbscServer, device: FakeDevice
) -> None:
    """Advertise handed the browser the seed while a concurrent reactive 403 rotated it.

    Without the overlap, the pre-rotation value would be the terminal path, not a benign retry.
    """
    sid = "session-RACE"
    seed = (await _seed(server, device, sid)).challenge
    await server.issue_refresh_challenge(ctx(sid))
    rotated = await server.get_binding(ctx(sid))
    assert rotated is not None
    assert rotated.previous_challenge == seed
    assert (await server.refresh(device.refresh_jwt(seed), ctx(sid))).status == 200


async def test_challenge_overlap_is_single_depth(server: DbscServer, device: FakeDevice) -> None:
    sid = "session-DEPTH"
    seed = (await _seed(server, device, sid)).challenge
    await server.issue_refresh_challenge(ctx(sid))
    await server.issue_refresh_challenge(ctx(sid))
    binding = await server.get_binding(ctx(sid))
    assert binding is not None

    with pytest.raises(ChallengeMismatchError):
        await server.refresh(device.refresh_jwt(seed), ctx(sid))
    assert (
        await server.refresh(device.refresh_jwt(binding.previous_challenge), ctx(sid))
    ).status == 200


async def test_previous_challenge_is_bounded_by_its_own_ttl(
    server: DbscServer, store: InMemoryStore, device: FakeDevice, clock: FakeClock
) -> None:
    sid = "session-TTL"
    seed = (await _seed(server, device, sid)).challenge
    await server.issue_refresh_challenge(ctx(sid))
    binding = await server.get_binding(ctx(sid))
    assert binding is not None
    stale = dataclasses.replace(binding, previous_challenge_time=int(clock()) - 100_000)
    await store.put_binding(sid, stale)

    with pytest.raises(ChallengeMismatchError):
        await server.refresh(device.refresh_jwt(seed), ctx(sid))
    assert (await server.refresh(device.refresh_jwt(stale.challenge), ctx(sid))).status == 200


async def test_successful_refresh_does_not_retain_the_spent_challenge(
    server: DbscServer, device: FakeDevice
) -> None:
    """No success-path propagation window, so the spent challenge is dropped (unlike cookies)."""
    sid = "session-NORETAIN"
    await _seed(server, device, sid)
    challenge_403, _ = await refresh_via_403(server, device, sid)
    binding = await server.get_binding(ctx(sid))
    assert binding is not None
    assert binding.previous_challenge == ""
    assert binding.previous_challenge_time == 0
    assert binding.has_refreshed is True

    spent = challenge_403.headers["Secure-Session-Challenge"].split('"')[1]
    with pytest.raises(ChallengeMismatchError):
        await server.refresh(device.refresh_jwt(spent), ctx(sid))


async def test_refresh_200_challenge_is_usable_for_the_next_refresh(
    server: DbscServer, device: FakeDevice
) -> None:
    """Steady state: each 200 carries the challenge the next refresh proves, no 403 needed."""
    sid = "session-STEADY"
    await _seed(server, device, sid)
    _, refreshed = await refresh_via_403(server, device, sid)
    for _ in range(3):
        challenge = refreshed.headers["Secure-Session-Challenge"].split('"')[1]
        refreshed = await server.refresh(device.refresh_jwt(challenge), ctx(sid))
        assert refreshed.status == 200
