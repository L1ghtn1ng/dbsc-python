"""Lost updates between concurrent requests on the same session.

Covers read-modify-writes of the binding, plus two registrations racing on one single-use offer.

A real browser runs its first ``/dbsc/refresh`` alongside ordinary page loads (the e2e suite has
caught ``advertise_refresh_challenge()`` and ``refresh()`` writing the same binding at once). Each
operation reads the binding, derives a new one, and writes it back; if another write lands in
between, blindly writing back undoes it. Rolling back a cookie rotation leaves the browser holding
a cookie the store no longer knows, so the gate terminates a legitimate session.

The interleavings are forced deterministically: ``PausingStore`` parks one operation right after
it reads the binding, the test runs the competing operation to completion, then resumes it.
"""

import asyncio
from typing import override

import pytest

from dbsc import (
    Binding,
    ChallengeMismatchError,
    Config,
    DbscResponse,
    DbscServer,
    InMemoryStore,
    MissingChallengeError,
    PendingRegistration,
    SessionNotFoundError,
)
from tests.support import (
    COOKIE_NAME,
    FakeClock,
    FakeDevice,
    RecordingAuditLogger,
    ctx,
    refresh_challenge,
    register,
    registration_challenge,
)

SID = "session-RACE"


class PausingStore(InMemoryStore):
    """An InMemoryStore that can park the next ``get_binding()`` caller after its read."""

    def __init__(self, clock: FakeClock) -> None:
        super().__init__(clock=clock)
        self._pause_next = False
        self.paused = asyncio.Event()
        self._resume = asyncio.Event()

    def pause_next_read(self) -> None:
        self._pause_next = True
        self.paused.clear()
        self._resume.clear()

    def resume(self) -> None:
        self._resume.set()

    @override
    async def get_binding(self, session_id: str) -> Binding | None:
        binding = await super().get_binding(session_id)
        if self._pause_next:
            self._pause_next = False
            self.paused.set()
            await self._resume.wait()
        return binding


@pytest.fixture
def pausing_store(clock: FakeClock) -> PausingStore:
    return PausingStore(clock)


@pytest.fixture
def racy_server(pausing_store: PausingStore, clock: FakeClock) -> DbscServer:
    return DbscServer(Config(), pausing_store, clock=clock)


async def _stored(server: DbscServer) -> Binding:
    binding = await server.get_binding(ctx(SID))
    assert binding is not None
    return binding


def _cookie_accepted(server: DbscServer, binding: Binding, value: str) -> bool:
    return server.bound_cookie_matches(binding, ctx(SID, cookies={COOKIE_NAME: value}))


async def _refresh_with_current_challenge(server: DbscServer, device: FakeDevice) -> DbscResponse:
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))
    return await server.refresh(device.refresh_jwt(challenge), ctx(SID))


async def test_advertise_does_not_undo_a_concurrent_refresh(
    server: DbscServer, device: FakeDevice
) -> None:
    """The gate reads B0, the first refresh writes B1, then advertise runs with the stale B0."""
    await register(server, device, SID)
    gate_read = await _stored(server)

    refreshed = await _refresh_with_current_challenge(server, device)
    rotated_cookie = refreshed.cookies[0].value
    after_refresh = await _stored(server)

    advertised = await server.advertise_refresh_challenge(gate_read, ctx(SID))

    assert advertised == DbscResponse(), "nothing to advertise: the seed is already stale"
    assert await _stored(server) == after_refresh, "the refresh's write survives"
    assert _cookie_accepted(server, await _stored(server), rotated_cookie)


async def test_advertise_emits_once_even_when_racing_itself(
    server: DbscServer, device: FakeDevice
) -> None:
    """Two document loads read the same unadvertised binding; only one delivers the seed."""
    await register(server, device, SID)
    gate_read = await _stored(server)

    first = await server.advertise_refresh_challenge(gate_read, ctx(SID))
    second = await server.advertise_refresh_challenge(gate_read, ctx(SID))

    assert "Secure-Session-Challenge" in first.headers
    assert second == DbscResponse()
    assert (await _stored(server)).challenge_advertised is True


async def test_issue_refresh_challenge_does_not_undo_a_concurrent_refresh(
    racy_server: DbscServer, pausing_store: PausingStore, device: FakeDevice
) -> None:
    server = racy_server
    await register(server, device, SID)
    first_challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))

    # A reactive 403 reads the binding and stalls; meanwhile a refresh rotates the cookie.
    pausing_store.pause_next_read()
    issuing = asyncio.create_task(server.issue_refresh_challenge(ctx(SID)))
    await pausing_store.paused.wait()
    refreshed = await server.refresh(device.refresh_jwt(first_challenge), ctx(SID))
    rotated_cookie = refreshed.cookies[0].value
    pausing_store.resume()
    challenge_403 = await issuing

    stored = await _stored(server)
    assert stored.cookie_value == rotated_cookie, "cookie rotation was not rolled back"
    assert stored.has_refreshed is True
    assert _cookie_accepted(server, stored, rotated_cookie)
    # The 403 still hands out a challenge that works against the up-to-date binding.
    challenge, _ = refresh_challenge(challenge_403)
    assert (await server.refresh(device.refresh_jwt(challenge), ctx(SID))).status == 200


async def test_concurrent_refreshes_with_one_challenge_keep_the_winner(
    racy_server: DbscServer, pausing_store: PausingStore, device: FakeDevice
) -> None:
    """Two refreshes prove the same challenge; the loser must not overwrite the winner."""
    server = racy_server
    await register(server, device, SID)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))
    jwt = device.refresh_jwt(challenge)

    pausing_store.pause_next_read()
    loser = asyncio.create_task(server.refresh(jwt, ctx(SID)))
    await pausing_store.paused.wait()
    winner = await server.refresh(jwt, ctx(SID))
    pausing_store.resume()

    with pytest.raises(ChallengeMismatchError):  # retryable: the browser gets a fresh 403
        await loser
    stored = await _stored(server)
    assert _cookie_accepted(server, stored, winner.cookies[0].value)


async def test_refresh_does_not_resurrect_a_revoked_session(
    racy_server: DbscServer, pausing_store: PausingStore, device: FakeDevice
) -> None:
    server = racy_server
    await register(server, device, SID)
    challenge, _ = refresh_challenge(await server.issue_refresh_challenge(ctx(SID)))

    pausing_store.pause_next_read()
    refreshing = asyncio.create_task(server.refresh(device.refresh_jwt(challenge), ctx(SID)))
    await pausing_store.paused.wait()
    await server.revoke(ctx(SID))  # logout lands mid-refresh
    pausing_store.resume()

    with pytest.raises(SessionNotFoundError):
        await refreshing
    assert await server.get_binding(ctx(SID)) is None, "the revoked binding stays revoked"


class ContendedStore(InMemoryStore):
    """Every conditional write loses, as if another writer always got there first."""

    @override
    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        return False


async def test_persistent_contention_degrades_benignly(
    clock: FakeClock, device: FakeDevice
) -> None:
    store = ContendedStore(clock=clock)
    audit = RecordingAuditLogger()
    server = DbscServer(Config(), store, audit=audit, clock=clock)
    await register(server, device, SID)
    stored = await _stored(server)

    challenge_403 = await server.issue_refresh_challenge(ctx(SID))
    assert challenge_403.status == 403
    assert refresh_challenge(challenge_403)[0] == stored.challenge, "hands out the stored one"

    with pytest.raises(ChallengeMismatchError):
        await server.refresh(device.refresh_jwt(stored.challenge), ctx(SID))
    assert audit.events[-1] == "dbscRefreshRetryable"

    assert await server.advertise_refresh_challenge(stored, ctx(SID)) == DbscResponse()
    assert await _stored(server) == stored, "nothing was written"


class PausingPendingStore(InMemoryStore):
    """Parks the next caller right after it reads the pending registration."""

    def __init__(self, clock: FakeClock) -> None:
        super().__init__(clock=clock)
        self.paused = asyncio.Event()
        self._resume = asyncio.Event()
        self._pause_next = True

    def resume(self) -> None:
        self._resume.set()

    async def _park(self) -> None:
        if self._pause_next:
            self._pause_next = False
            self.paused.set()
            await self._resume.wait()

    @override
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        pending = await super().get_pending_registration(session_id)
        await self._park()
        return pending


async def test_one_registration_offer_registers_once(clock: FakeClock, device: FakeDevice) -> None:
    """Two registrations racing on one offer: exactly one wins, and it is the one stored.

    The offer is single-use. If both requests read it before either consumes it, both register,
    and the second binding silently replaces the first: the browser that received the first
    response then holds a cookie and session id the server no longer knows.
    """
    store = PausingPendingStore(clock)
    server = DbscServer(Config(), store, clock=clock)
    offer = await server.build_registration_header_response(ctx(SID))
    jwt = device.registration_jwt(registration_challenge(offer))

    first = asyncio.create_task(server.register(jwt, ctx(SID)))
    await store.paused.wait()
    second = asyncio.create_task(server.register(jwt, ctx(SID)))
    await asyncio.sleep(0)  # let the second run as far as it can while the first is parked
    await asyncio.sleep(0)
    store.resume()
    results = await asyncio.gather(first, second, return_exceptions=True)

    winners = [r for r in results if isinstance(r, DbscResponse)]
    assert len(winners) == 1, results
    assert sum(isinstance(r, MissingChallengeError) for r in results) == 1, results
    stored = await _stored(server)
    assert stored.session_identifier == winners[0].headers["Sec-Secure-Session-Id"]
    assert _cookie_accepted(server, stored, winners[0].cookies[0].value)


async def test_logout_during_registration_leaves_no_binding(
    clock: FakeClock, device: FakeDevice
) -> None:
    """A logout that lands mid-registration wins: no binding appears for a logged-out session."""
    store = PausingPendingStore(clock)
    server = DbscServer(Config(), store, clock=clock)
    offer = await server.build_registration_header_response(ctx(SID))
    jwt = device.registration_jwt(registration_challenge(offer))

    registering = asyncio.create_task(server.register(jwt, ctx(SID)))
    await store.paused.wait()
    await server.revoke(ctx(SID))
    store.resume()

    with pytest.raises(MissingChallengeError):
        await registering
    assert await server.get_binding(ctx(SID)) is None


async def test_newer_offer_supersedes_an_in_flight_registration(
    clock: FakeClock, device: FakeDevice
) -> None:
    """Re-login mid-registration replaces the offer; the stale registration must not bind."""
    store = PausingPendingStore(clock)
    server = DbscServer(Config(), store, clock=clock)
    offer = await server.build_registration_header_response(ctx(SID))
    jwt = device.registration_jwt(registration_challenge(offer))

    registering = asyncio.create_task(server.register(jwt, ctx(SID)))
    await store.paused.wait()
    fresh = await server.build_registration_header_response(ctx(SID))
    store.resume()

    with pytest.raises(MissingChallengeError):
        await registering
    assert await server.get_binding(ctx(SID)) is None
    # The newer offer is intact and still registers.
    await server.register(device.registration_jwt(registration_challenge(fresh)), ctx(SID))
    assert await server.get_binding(ctx(SID)) is not None
