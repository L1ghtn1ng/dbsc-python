"""Stored-record encoding, and the fail-closed contract for corrupt state.

A stored record that is present but unparseable MUST raise CorruptStateError, never decode to
None. None is reserved for "no record" (degrade to cookie auth). Returning None for a corrupt
binding would silently downgrade a hard-DBSC session and re-open the stolen-cookie hole DBSC
exists to close. Clients can't trigger this; it guards against serializer/version/truncation
events.
"""

from dataclasses import dataclass
from typing import override

import pytest

from dbsc import (
    AuditEvent,
    Binding,
    Config,
    CorruptStateError,
    DbscServer,
    PendingRegistration,
    Store,
)
from tests.support import RecordingAuditLogger, ctx

LEGACY_JSON = (
    '{"userId":"u","sessionIdentifier":"s","cookieValue":"c","publicKeyPem":"p",'
    '"algorithm":"a","challenge":"x","challengeTime":1,"createdAt":7}'
)


def test_binding_round_trips_rotation_overlap_fields() -> None:
    binding = Binding("u", "sid", "cookie", "pem", "ES256", "chal", 100, 100, 90, "prevcookie", 390)
    assert Binding.from_json(binding.to_json()) == binding


def test_binding_round_trips_one_step_fields() -> None:
    binding = Binding(
        user_id="u",
        session_identifier="sid",
        cookie_value="cookie",
        public_key_pem="pem",
        algorithm="ES256",
        challenge="chal",
        challenge_time=100,
        created_at=100,
        cookie_issued_at=90,
        previous_cookie_value="pc",
        previous_cookie_expires_at=390,
        has_refreshed=True,
        previous_challenge="prevchal",
        previous_challenge_time=77,
        challenge_advertised=True,
    )
    assert Binding.from_json(binding.to_json()) == binding


def test_binding_json_uses_the_php_store_format() -> None:
    """Keys stay camelCase so a store shared with the PHP library stays readable both ways."""
    binding = Binding("u", "sid", "cookie", "pem", "ES256", "chal", 100, 100)
    assert binding.to_json().startswith('{"userId":"u","sessionIdentifier":"sid","cookieValue"')


def test_binding_decodes_a_php_written_record() -> None:
    # PHP's json_encode escapes "/" by default.
    php_json = LEGACY_JSON.replace('"publicKeyPem":"p"', '"publicKeyPem":"a\\/b"')
    assert Binding.from_json(php_json).public_key_pem == "a/b"


def test_legacy_binding_decodes_with_safe_defaults() -> None:
    """A record written before the overlap/one-step fields existed is fully valid.

    It defaults to "no previous-value overlap": strict current-value match only, with
    cookie_issued_at falling back to created_at. Graceful and fail-closed: never a lockout, never
    a fail-open.
    """
    legacy = Binding.from_json(LEGACY_JSON)
    assert legacy.previous_cookie_value == ""
    assert legacy.previous_cookie_expires_at == 0
    assert legacy.cookie_issued_at == 7
    assert legacy.has_refreshed is False
    assert legacy.previous_challenge == ""
    assert legacy.previous_challenge_time == 0
    assert legacy.challenge_advertised is False


def test_wrong_typed_optional_fields_fall_back_to_defaults() -> None:
    raw = LEGACY_JSON[:-1] + ',"cookieIssuedAt":"9","hasRefreshed":1,"previousChallengeTime":true}'
    binding = Binding.from_json(raw)
    assert binding.cookie_issued_at == 7
    assert binding.has_refreshed is False
    assert binding.previous_challenge_time == 0


@pytest.mark.parametrize(
    "bad",
    [
        "not-json",
        '"a string"',
        "12",
        "[]",
        '{"userId":"u"}',
        LEGACY_JSON.replace('"userId":"u"', '"userId":1'),
        LEGACY_JSON.replace('"createdAt":7', '"createdAt":true'),  # bool is not an int
        LEGACY_JSON.replace('"createdAt":7', '"createdAt":7.0'),
        b"\xff\xfe",
    ],
)
def test_binding_from_json_rejects_corrupt_input(bad: str | bytes) -> None:
    with pytest.raises(CorruptStateError):
        Binding.from_json(bad)


def test_pending_registration_round_trips() -> None:
    pending = PendingRegistration("u", "chal", 100)
    assert PendingRegistration.from_json(pending.to_json()) == pending


@pytest.mark.parametrize(
    "bad",
    [
        "{",
        "[]",
        '{"userId":"u","regChallenge":"c"}',
        '{"userId":"u","regChallenge":"c","regChallengeTime":false}',
    ],
)
def test_pending_registration_rejects_corrupt_input(bad: str) -> None:
    with pytest.raises(CorruptStateError):
        PendingRegistration.from_json(bad)


@dataclass
class CorruptStore(Store):
    """A store whose binding key is present but unreadable."""

    deleted: bool = False

    @override
    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        pass

    @override
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        return PendingRegistration.from_json("garbage")

    @override
    async def delete_pending_registration(self, session_id: str) -> None:
        pass

    @override
    async def put_binding(self, session_id: str, binding: Binding) -> None:
        pass

    @override
    async def get_binding(self, session_id: str) -> Binding | None:
        return Binding.from_json("garbage")

    @override
    async def delete(self, session_id: str) -> None:
        self.deleted = True


async def test_corrupt_binding_fails_closed() -> None:
    store = CorruptStore()
    audit = RecordingAuditLogger()
    server = DbscServer(Config(), store, audit=audit)

    with pytest.raises(CorruptStateError):
        await server.get_binding(ctx("session-EEE"))
    with pytest.raises(CorruptStateError):
        await server.issue_refresh_challenge(ctx("session-EEE"))
    with pytest.raises(CorruptStateError):
        await server.refresh("a.b.c", ctx("session-EEE"))
    with pytest.raises(CorruptStateError):
        await server.register("a.b.c", ctx("session-EEE"))
    with pytest.raises(CorruptStateError):
        await server.session_instructions_json(ctx("session-EEE"))

    revoked = await server.revoke(ctx("session-EEE"), enforcement_terminated=True)
    assert store.deleted, "revoke tears down despite the corrupt binding"
    assert revoked.cookies[0].delete is True
    assert audit.events == [AuditEvent.ENFORCEMENT_TERMINATED]
