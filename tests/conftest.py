from collections.abc import Callable

import pytest

from dbsc import AuditLogger, Config, DbscServer, InMemoryStore
from tests.support import FakeClock, FakeDevice

type ServerFactory = Callable[..., DbscServer]


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()


@pytest.fixture
def store(clock: FakeClock) -> InMemoryStore:
    return InMemoryStore(clock=clock)


@pytest.fixture
def device() -> FakeDevice:
    return FakeDevice()


@pytest.fixture
def make_server(store: InMemoryStore, clock: FakeClock) -> ServerFactory:
    """Build a server over the shared in-memory store and fake clock."""

    def factory(config: Config | None = None, *, audit: AuditLogger | None = None) -> DbscServer:
        return DbscServer(config or Config(), store, audit=audit, clock=clock)

    return factory


@pytest.fixture
def server(make_server: ServerFactory) -> DbscServer:
    return make_server()
