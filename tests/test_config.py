import dataclasses

import pytest

from dbsc import Config, Cookie, InMemoryStore, PendingRegistration, RequestContext, ScopeRule
from tests.support import FakeClock


def test_challenge_ttl_must_exceed_cookie_max_age() -> None:
    with pytest.raises(ValueError, match="challenge_ttl_seconds must exceed"):
        Config(cookie_max_age_seconds=300, challenge_ttl_seconds=300)


def test_config_is_immutable() -> None:
    initiators = ["a.example"]
    config = Config(allowed_refresh_initiators=initiators)
    initiators.append("b.example")
    assert config.allowed_refresh_initiators == ("a.example",)
    with pytest.raises(dataclasses.FrozenInstanceError):
        config.cookie_name = "other"  # ty: ignore[invalid-assignment]


def test_scope_rule_needs_domain_or_path() -> None:
    with pytest.raises(ValueError, match="needs a domain, a path, or both"):
        ScopeRule.exclude()


def test_scope_rule_type_is_validated() -> None:
    with pytest.raises(ValueError, match='"include" or "exclude"'):
        ScopeRule("bogus", path="/x")  # ty: ignore[invalid-argument-type]
    assert ScopeRule("exclude", path="/x") == ScopeRule.exclude(path="/x")  # ty: ignore[invalid-argument-type]


def test_scope_rule_wire_form() -> None:
    assert ScopeRule.include(domain="*.example.com").to_dict() == {
        "type": "include",
        "domain": "*.example.com",
    }


def test_request_context_headers_are_case_insensitive() -> None:
    request = RequestContext("s", "u", "https://x", {"Sec-Secure-Session-Id": "abc"}, {"c": "v"})
    assert request.header("sec-secure-session-id") == "abc"
    assert request.header("SEC-SECURE-SESSION-ID") == "abc"
    assert request.header("missing") is None
    assert request.cookie("c") == "v"
    assert request.cookie("C") is None, "cookie names are case-sensitive"


def test_cookie_deletion() -> None:
    cookie = Cookie.deletion("__Host-dbsc")
    assert (cookie.delete, cookie.value, cookie.expires_at, cookie.path) == (True, "", 0, "/")


async def test_in_memory_store_expires_records() -> None:
    clock = FakeClock()
    store = InMemoryStore(challenge_ttl_seconds=10, session_lifetime_seconds=100, clock=clock)
    await store.put_pending_registration("s", PendingRegistration("u", "c", 0))
    clock.advance(10)
    assert await store.get_pending_registration("s") is not None
    clock.advance(1)
    assert await store.get_pending_registration("s") is None
