"""The established device-bound session record."""

import dataclasses
from dataclasses import dataclass
from typing import Self

from dbsc._json import as_int, as_str, dumps, loads_object
from dbsc._validate import is_cookie_value, is_sf_string_safe, require
from dbsc.exceptions import CorruptStateError


def _or[T](value: T | None, default: T) -> T:
    """``value`` unless it is ``None`` (absent or wrong-typed optional field)."""
    return default if value is None else value


@dataclass(frozen=True, slots=True)
class Binding:
    """The established device-bound session record.

    Its existence in the :class:`~dbsc.store.Store`, keyed by the host application's session id,
    is the authoritative "this session is hard-DBSC" mark. It must NOT be stored in a shared,
    last-writer-wins session blob: two concurrent requests on the same session (the post-login
    navigation racing the registration POST) will clobber it and silently disable enforcement.
    Key it by the stable session id in a dedicated store instead (see README, "Storage").

    ``cookie_value`` rotates on every refresh; ``session_identifier`` is stable and is what the
    browser echoes back in ``Sec-Secure-Session-Id``.

    ``previous_cookie_value`` / ``previous_cookie_expires_at`` retain the single immediately-prior
    cookie value until the instant that value would itself have expired in the browser. The bound
    cookie rotates on every refresh, but the refresh round-trip is a propagation window: a request
    that left the browser just before it stored the rotated Set-Cookie still carries the prior
    value. Accepting it for the remainder of its own natural lifetime (see
    :meth:`DbscServer.bound_cookie_matches() <dbsc.server.DbscServer.bound_cookie_matches>`) stops
    the enforcement gate from terminating legitimate sessions over that benign window, without
    weakening DBSC: only the single most-recent value, only until its own expiry, and an attacker
    still cannot complete a refresh without the device-bound key.

    ``has_refreshed`` is false from registration and flips true (one-way) on the first successful
    refresh, the point at which the steady-state loop becomes self-sustaining (every refresh 200
    carries the next challenge, so the browser always holds one). It exists solely so
    ``DbscServer.advertise_refresh_challenge()`` can stop proactively re-advertising the
    pre-first-refresh seed challenge once it is no longer needed; it is never a security gate.

    ``challenge_advertised`` is false from registration and flips true (one-way) the first time
    ``DbscServer.advertise_refresh_challenge()`` actually emits the seed challenge. The browser
    caches the advertised challenge for the session, so one in-scope delivery is sufficient;
    without this flag every document navigation in the registration→first-refresh window would
    re-emit the identical seed (one chrome://dbsc-internals Challenge entry per request, all the
    same). It gates *delivery frequency* only, never security. It is preserved across
    :meth:`with_challenge` (the reactive 403 rotates the challenge but delivers the new value in
    its own 403 response, so a re-advertise would be redundant). If the single delivery is lost,
    the browser simply falls back to the reactive 403 two-step on its first refresh: no
    regression, by design.

    ``previous_challenge`` / ``previous_challenge_time`` are the challenge analogue of the
    cookie-overlap pair, and exist for the same propagation-window reason, but only on the
    reactive-403 rotation (:meth:`with_challenge`). ``DbscServer.advertise_refresh_challenge()``
    can hand the browser the seed challenge while a concurrent
    ``DbscServer.issue_refresh_challenge()`` rotates it; a request that left the browser carrying
    the pre-rotation challenge would otherwise fail the challenge match in ``DbscServer.refresh()``.
    Accepting the single immediately-previous challenge until its own TTL closes that race without
    weakening DBSC: the challenge is a replay nonce *inside* a JWT the device-bound key must still
    sign, so an attacker without the key cannot mint a valid refresh for any challenge, current or
    previous. Single depth, own-expiry-bounded: the same envelope as the cookie overlap.
    Deliberately NOT retained across a successful refresh (:meth:`with_rotated_cookie_and_challenge`
    clears it): the refresh 200 delivers the new challenge synchronously with the rotated cookie,
    so there is no success-path propagation window to bridge, and not retaining it keeps the spent
    challenge from being replayable. This asymmetry vs the cookie overlap (which IS retained
    across refresh) is intentional; do not consistency-refactor the two into one.

    All timestamps are integer Unix seconds.
    """

    user_id: str
    session_identifier: str
    cookie_value: str
    public_key_pem: str
    algorithm: str
    challenge: str
    challenge_time: int
    created_at: int
    cookie_issued_at: int = 0
    previous_cookie_value: str = ""
    previous_cookie_expires_at: int = 0
    has_refreshed: bool = False
    previous_challenge: str = ""
    previous_challenge_time: int = 0
    challenge_advertised: bool = False

    def __post_init__(self) -> None:
        # These values are emitted in response headers and cookies; refuse anything that could
        # inject into them (a tampered or corrupted store record fails closed in from_json()).
        for name in ("session_identifier", "challenge", "previous_challenge"):
            require(is_sf_string_safe(getattr(self, name)), f"Binding.{name} is not header-safe.")
        for name in ("cookie_value", "previous_cookie_value"):
            require(is_cookie_value(getattr(self, name)), f"Binding.{name} is not cookie-safe.")

    def to_json(self) -> str:
        """Serialise for storage.

        Keys are camelCase so records stay interchangeable with the PHP library's store format.
        """
        return dumps(
            {
                "userId": self.user_id,
                "sessionIdentifier": self.session_identifier,
                "cookieValue": self.cookie_value,
                "publicKeyPem": self.public_key_pem,
                "algorithm": self.algorithm,
                "challenge": self.challenge,
                "challengeTime": self.challenge_time,
                "createdAt": self.created_at,
                "cookieIssuedAt": self.cookie_issued_at,
                "previousCookieValue": self.previous_cookie_value,
                "previousCookieExpiresAt": self.previous_cookie_expires_at,
                "hasRefreshed": self.has_refreshed,
                "previousChallenge": self.previous_challenge,
                "previousChallengeTime": self.previous_challenge_time,
                "challengeAdvertised": self.challenge_advertised,
            }
        )

    @classmethod
    def from_json(cls, raw: str | bytes) -> Self:
        """Parse a stored binding.

        Raises on a present-but-unreadable value rather than returning ``None``: callers MUST
        treat that as fail-closed and NOT collapse it to "no binding", which would degrade a bound
        session to plain cookie auth (the fail-open DBSC exists to prevent). Absence is represented
        by the store returning ``None`` without ever calling this method.

        The cookie-rotation-overlap fields (``cookieIssuedAt`` / ``previousCookieValue`` /
        ``previousCookieExpiresAt``), ``hasRefreshed``, ``challengeAdvertised``, and the
        challenge-overlap pair (``previousChallenge`` / ``previousChallengeTime``) are OPTIONAL
        with safe defaults: records written by an older library version predate them, and a record
        without them is fully valid. It simply has no previous-value overlap (strict current-value
        match only), ``hasRefreshed`` defaults false so the proactive seed challenge is
        re-advertised until its next refresh re-issues it, ``challengeAdvertised`` defaults false
        so the seed is delivered once more (a harmless duplicate at worst), and the challenge
        overlap is empty until the next reactive-403 rotation populates it. That is a graceful,
        fail-closed default, never a lockout and never a fail-open. Every field that was required
        stays strictly type-checked.

        Raises:
            CorruptStateError: the record is not a JSON object or a required field is missing or
                has the wrong type.
        """
        data = loads_object(raw)
        if data is None:
            raise CorruptStateError("Binding record is not a JSON object")
        user_id = as_str(data.get("userId"))
        session_identifier = as_str(data.get("sessionIdentifier"))
        cookie_value = as_str(data.get("cookieValue"))
        public_key_pem = as_str(data.get("publicKeyPem"))
        algorithm = as_str(data.get("algorithm"))
        challenge = as_str(data.get("challenge"))
        challenge_time = as_int(data.get("challengeTime"))
        created_at = as_int(data.get("createdAt"))
        if (
            user_id is None
            or session_identifier is None
            or cookie_value is None
            or public_key_pem is None
            or algorithm is None
            or challenge is None
            or challenge_time is None
            or created_at is None
        ):
            raise CorruptStateError("Binding record has missing or wrong-typed fields")
        try:
            return cls(
                user_id=user_id,
                session_identifier=session_identifier,
                cookie_value=cookie_value,
                public_key_pem=public_key_pem,
                algorithm=algorithm,
                challenge=challenge,
                challenge_time=challenge_time,
                created_at=created_at,
                cookie_issued_at=_or(as_int(data.get("cookieIssuedAt")), created_at),
                previous_cookie_value=_or(as_str(data.get("previousCookieValue")), ""),
                previous_cookie_expires_at=_or(as_int(data.get("previousCookieExpiresAt")), 0),
                has_refreshed=data.get("hasRefreshed") is True,
                previous_challenge=_or(as_str(data.get("previousChallenge")), ""),
                previous_challenge_time=_or(as_int(data.get("previousChallengeTime")), 0),
                challenge_advertised=data.get("challengeAdvertised") is True,
            )
        except ValueError as e:
            raise CorruptStateError(f"Binding record has an unsafe value: {e}") from None

    def with_challenge(self, challenge: str, challenge_time: int) -> Self:
        """Rotate ONLY the cached challenge (the reactive-403 path).

        The value being demoted is retained as ``previous_challenge`` / ``previous_challenge_time``
        and accepted by ``DbscServer.refresh()`` until its own TTL, bridging the propagation window
        where ``DbscServer.advertise_refresh_challenge()`` handed the browser the pre-rotation
        value. Single-depth: a second reactive rotation discards the challenge from two rotations
        ago.

        ``challenge_advertised`` is preserved, not reset: this 403 already delivered the rotated
        challenge to the browser in its own response, so re-advertising it on a later document
        response would be the redundant emission the flag exists to prevent.
        """
        return dataclasses.replace(
            self,
            challenge=challenge,
            challenge_time=challenge_time,
            previous_challenge=self.challenge,
            previous_challenge_time=self.challenge_time,
        )

    def mark_challenge_advertised(self) -> Self:
        """Flip ``challenge_advertised`` true (one-way, idempotent).

        Called by ``DbscServer.advertise_refresh_challenge()`` the first time it actually emits
        the seed, so subsequent document responses in the pre-first-refresh window stay silent.
        """
        return dataclasses.replace(self, challenge_advertised=True)

    def with_rotated_cookie_and_challenge(
        self,
        cookie_value: str,
        challenge: str,
        challenge_time: int,
        now: int,
        cookie_max_age_seconds: int,
    ) -> Self:
        """Rotate the bound cookie (and challenge).

        The value being demoted is retained as ``previous_cookie_value``, accepted only until
        ``previous_cookie_expires_at``: the instant the demoted cookie would itself have expired
        in the browser, i.e. its own issuance time (``self.cookie_issued_at``) plus the configured
        max-age. Single-depth: a second rotation discards the value from two rotations ago.

        Also flips ``has_refreshed`` true (one-way, idempotent on later rotations): a successful
        refresh is exactly the point past which the proactive seed-challenge advertisement is no
        longer needed.

        Unlike :meth:`with_challenge`, this deliberately does NOT retain the just-proved challenge
        as ``previous_challenge`` (it resets the pair to empty): the refresh 200 hands the browser
        the new challenge synchronously with the rotated cookie, so there is no propagation window
        to bridge here, and dropping the spent challenge keeps it from being replayable. The
        cookie IS retained across this same transition because the cookie genuinely has such a
        window; the asymmetry is intentional. ``challenge_advertised`` is carried through
        unchanged; it is moot post-refresh anyway since ``has_refreshed`` now gates the advertise
        path.
        """
        return dataclasses.replace(
            self,
            cookie_value=cookie_value,
            challenge=challenge,
            challenge_time=challenge_time,
            cookie_issued_at=now,
            previous_cookie_value=self.cookie_value,
            previous_cookie_expires_at=self.cookie_issued_at + cookie_max_age_seconds,
            has_refreshed=True,
            previous_challenge="",
            previous_challenge_time=0,
        )
