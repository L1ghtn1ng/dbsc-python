"""``allowed_refresh_initiators`` and ``scope_specification`` in the session-instructions JSON."""

import json

from dbsc import Config, DbscResponse, RequestContext, ScopeRule
from tests.conftest import ServerFactory
from tests.support import ORIGIN, FakeDevice, ctx, refresh_via_403, register


def body(response: DbscResponse) -> dict[str, object]:
    assert response.body is not None
    return json.loads(response.body)


def scope_rules(response: DbscResponse) -> object:
    scope = body(response)["scope"]
    assert isinstance(scope, dict)
    return scope.get("scope_specification")


def with_overrides(
    sid: str,
    *,
    initiators: list[str] | None = None,
    scope: list[ScopeRule] | None = None,
) -> RequestContext:
    return RequestContext(sid, "user-1", ORIGIN, {}, {}, initiators, scope)


# --- allowed_refresh_initiators --------------------------------------------------------------


async def test_initiators_omitted_by_default(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    server = make_server()
    reg = await register(server, device, "session-INIT1")
    assert "allowed_refresh_initiators" not in body(reg)
    _, refreshed = await refresh_via_403(server, device, "session-INIT1")
    assert "allowed_refresh_initiators" not in body(refreshed)


async def test_initiators_from_config(make_server: ServerFactory, device: FakeDevice) -> None:
    server = make_server(Config(allowed_refresh_initiators=["example.com", "*.example.com"]))
    sid = "session-INIT2"
    expected = ["example.com", "*.example.com"]

    reg = await register(server, device, sid)
    assert body(reg)["allowed_refresh_initiators"] == expected, "order preserved"
    _, refreshed = await refresh_via_403(server, device, sid)
    assert body(refreshed)["allowed_refresh_initiators"] == expected
    instructions = json.loads(await server.session_instructions_json(ctx(sid)))
    assert instructions["allowed_refresh_initiators"] == expected


async def test_initiators_per_request_override(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    server = make_server(Config(allowed_refresh_initiators=["configured.example"]))
    sid = "session-INIT3"
    reg = await register(server, device, with_overrides(sid, initiators=["rp.example"]))
    assert body(reg)["allowed_refresh_initiators"] == ["rp.example"]

    # An explicit empty override forces the key off despite a non-empty Config default.
    instructions = await server.session_instructions_json(with_overrides(sid, initiators=[]))
    assert "allowed_refresh_initiators" not in instructions


async def test_initiators_filtered_and_trimmed(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    server = make_server()
    request = with_overrides(
        "session-INIT4", initiators=["rp.example", "", "   ", " other.example "]
    )
    reg = await register(server, device, request)
    assert body(reg)["allowed_refresh_initiators"] == ["rp.example", "other.example"]


# --- scope_specification ---------------------------------------------------------------------


async def test_scope_omitted_by_default(make_server: ServerFactory, device: FakeDevice) -> None:
    """No rules means the key is absent entirely: the spec default of "the whole origin"."""
    server = make_server()
    reg = await register(server, device, "session-SCOPE1")
    assert scope_rules(reg) is None
    _, refreshed = await refresh_via_403(server, device, "session-SCOPE1")
    assert scope_rules(refreshed) is None


async def test_scope_from_config(make_server: ServerFactory, device: FakeDevice) -> None:
    """Rules ride on register, refresh and session_instructions_json alike.

    A browser that missed the registration response must still learn the scope from the next
    refresh.
    """
    server = make_server(
        Config(
            scope_specification=[
                ScopeRule.exclude(path="/assets/"),
                ScopeRule.include(path="/only_this", domain="trusted.example.com"),
            ]
        )
    )
    sid = "session-SCOPE2"
    expected = [
        {"type": "exclude", "path": "/assets/"},  # absent domain omitted, not null
        {"type": "include", "domain": "trusted.example.com", "path": "/only_this"},
    ]

    reg = await register(server, device, sid)
    assert scope_rules(reg) == expected, "rules sit INSIDE scope, order preserved"
    assert "scope_specification" not in body(reg), "not beside scope"
    _, refreshed = await refresh_via_403(server, device, sid)
    assert scope_rules(refreshed) == expected
    instructions = json.loads(await server.session_instructions_json(ctx(sid)))
    assert instructions["scope"]["scope_specification"] == expected


async def test_scope_per_request_override(make_server: ServerFactory, device: FakeDevice) -> None:
    server = make_server(Config(scope_specification=[ScopeRule.exclude(path="/assets/")]))
    reg = await register(
        server,
        device,
        with_overrides("session-SCOPE3", scope=[ScopeRule.exclude(path="/per-request")]),
    )
    assert scope_rules(reg) == [{"type": "exclude", "path": "/per-request"}]


async def test_scope_empty_override_forces_key_off(
    make_server: ServerFactory, device: FakeDevice
) -> None:
    server = make_server(Config(scope_specification=[ScopeRule.exclude(path="/assets/")]))
    reg = await register(server, device, with_overrides("session-SCOPE4", scope=[]))
    assert scope_rules(reg) is None
