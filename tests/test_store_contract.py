"""The ``Store`` concurrency contract (take-once offers, conditional binding writes).

Run against every implementation in the repo.
"""

import asyncio
import dataclasses
from collections.abc import Callable
from pathlib import Path
from typing import override

import pytest

from dbsc import Binding, CorruptStateError, InMemoryStore, PendingRegistration, Store
from examples.demo_server import FileStore
from tests.support import FakeClock

B0 = Binding("u", "sid", "cookie-0", "pem", "ES256", "chal-0", 100, 100, 100)
B1 = dataclasses.replace(B0, cookie_value="cookie-1", challenge="chal-1", has_refreshed=True)
B2 = dataclasses.replace(B0, challenge_advertised=True)


class DictStore(Store):
    """Implements only the six required methods, so it runs the inherited default."""

    def __init__(self) -> None:
        self.bindings: dict[str, str] = {}
        self.pending: dict[str, str] = {}

    @override
    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        self.pending[session_id] = pending.to_json()

    @override
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        raw = self.pending.get(session_id)
        return None if raw is None else PendingRegistration.from_json(raw)

    @override
    async def delete_pending_registration(self, session_id: str) -> None:
        self.pending.pop(session_id, None)

    @override
    async def put_binding(self, session_id: str, binding: Binding) -> None:
        self.bindings[session_id] = binding.to_json()

    @override
    async def get_binding(self, session_id: str) -> Binding | None:
        raw = self.bindings.get(session_id)
        return None if raw is None else Binding.from_json(raw)

    @override
    async def delete(self, session_id: str) -> None:
        self.bindings.pop(session_id, None)
        self.pending.pop(session_id, None)


STORES: dict[str, Callable[[Path], Store]] = {
    "in-memory": lambda _: InMemoryStore(),
    "file (demo)": FileStore,
    "inherited default": lambda _: DictStore(),
}


@pytest.fixture(params=list(STORES), ids=list(STORES))
def store(request: pytest.FixtureRequest, tmp_path: Path) -> Store:
    return STORES[request.param](tmp_path)


async def test_replaces_when_unchanged(store: Store) -> None:
    await store.put_binding("s", B0)
    assert await store.replace_binding("s", B0, B1) is True
    assert await store.get_binding("s") == B1


async def test_refuses_when_changed(store: Store) -> None:
    await store.put_binding("s", B1)  # someone else already rotated it
    assert await store.replace_binding("s", B0, B2) is False
    assert await store.get_binding("s") == B1, "the other write survives"


async def test_refuses_when_absent(store: Store) -> None:
    assert await store.replace_binding("s", B0, B1) is False
    assert await store.get_binding("s") is None, "nothing created"


async def test_refuses_after_delete(store: Store) -> None:
    await store.put_binding("s", B0)
    await store.delete("s")
    assert await store.replace_binding("s", B0, B1) is False
    assert await store.get_binding("s") is None, "a revoked binding is never resurrected"


async def test_compares_records_not_raw_json() -> None:
    """A record written by PHP (escaped slashes, other spacing) still matches its decoded form."""
    store = DictStore()
    pem = "-----BEGIN PUBLIC KEY-----\nab/cd\n-----END PUBLIC KEY-----\n"
    php_json = (
        dataclasses.replace(B0, public_key_pem=pem).to_json().replace("/", "\\/").replace(",", ", ")
    )
    store.bindings["s"] = php_json
    expected = Binding.from_json(php_json)
    assert expected.public_key_pem == pem
    assert await store.replace_binding("s", expected, B1) is True
    assert await store.get_binding("s") == B1


async def test_in_memory_refuses_an_expired_record() -> None:
    clock = FakeClock()
    store = InMemoryStore(session_lifetime_seconds=10, clock=clock)
    await store.put_binding("s", B0)
    clock.advance(11)
    assert await store.replace_binding("s", B0, B1) is False
    assert await store.get_binding("s") is None


async def test_default_fails_closed_on_corrupt_state() -> None:
    store = DictStore()
    store.bindings["s"] = "garbage"
    with pytest.raises(CorruptStateError):
        await store.replace_binding("s", B0, B1)
    assert store.bindings["s"] == "garbage", "nothing overwritten"


OFFER = PendingRegistration("u", "reg-chal", 100)
NEWER_OFFER = PendingRegistration("u", "reg-chal-2", 200)


async def test_commit_consumes_the_offer_and_binds(store: Store) -> None:
    await store.put_pending_registration("s", OFFER)
    assert await store.commit_registration("s", OFFER, B0) is True
    assert await store.get_pending_registration("s") is None
    assert await store.get_binding("s") == B0


async def test_commit_happens_once_per_offer(store: Store) -> None:
    await store.put_pending_registration("s", OFFER)
    assert await store.commit_registration("s", OFFER, B0) is True
    assert await store.commit_registration("s", OFFER, B1) is False
    assert await store.get_binding("s") == B0, "the first registration stays bound"


async def test_concurrent_commits_bind_exactly_one(store: Store) -> None:
    await store.put_pending_registration("s", OFFER)
    candidates = [dataclasses.replace(B0, session_identifier=f"sid-{i}") for i in range(8)]
    results = await asyncio.gather(*(store.commit_registration("s", OFFER, b) for b in candidates))
    assert results.count(True) == 1
    assert await store.get_binding("s") == candidates[results.index(True)]


async def test_commit_refuses_after_logout(store: Store) -> None:
    await store.put_pending_registration("s", OFFER)
    await store.delete("s")
    assert await store.commit_registration("s", OFFER, B0) is False
    assert await store.get_binding("s") is None


async def test_commit_refuses_a_superseded_offer(store: Store) -> None:
    await store.put_pending_registration("s", OFFER)
    await store.put_pending_registration("s", NEWER_OFFER)
    assert await store.commit_registration("s", OFFER, B0) is False
    assert await store.get_binding("s") is None
    assert await store.get_pending_registration("s") == NEWER_OFFER, "the newer offer survives"


async def test_in_memory_commit_refuses_an_expired_offer() -> None:
    clock = FakeClock()
    store = InMemoryStore(challenge_ttl_seconds=10, clock=clock)
    await store.put_pending_registration("s", OFFER)
    clock.advance(11)
    assert await store.commit_registration("s", OFFER, B0) is False


async def test_default_commit_fails_closed_on_corrupt_state() -> None:
    store = DictStore()
    store.pending["s"] = "garbage"
    with pytest.raises(CorruptStateError):
        await store.commit_registration("s", OFFER, B0)
    assert "s" not in store.bindings
