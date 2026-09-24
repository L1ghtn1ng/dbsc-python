"""The framework-agnostic DBSC server."""

import secrets
import time
from collections.abc import Callable
from types import MappingProxyType
from typing import Final

from dbsc._json import constant_time_equals, dumps
from dbsc.audit import AuditEvent, AuditLogger, NullAuditLogger
from dbsc.binding import Binding
from dbsc.config import Config
from dbsc.exceptions import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    CorruptStateError,
    JwtInvalidError,
    MissingChallengeError,
    SessionNotFoundError,
)
from dbsc.jwt import JwtVerifier
from dbsc.pending import PendingRegistration
from dbsc.request import RequestContext
from dbsc.response import Cookie, DbscResponse
from dbsc.scope import ScopeRule
from dbsc.store import Store

_ALGORITHM: Final = "ES256"
_NONCE_BYTES: Final = 32
_SESSION_ID_BYTES: Final = 32
_COOKIE_VALUE_BYTES: Final = 32
# Conditional binding writes retried against fresh state before giving up. A conflict means
# another request wrote the same binding in between; three in a row is already pathological.
_MAX_UPDATE_ATTEMPTS: Final = 3
# Every response that carries session state (challenges, session ids, bound cookies, their
# deletion) must never be stored by a shared cache and replayed to someone else.
_NO_STORE: Final = MappingProxyType({"Cache-Control": "no-store"})


class DbscServer:
    """Framework-agnostic DBSC server.

    Every method takes a :class:`~dbsc.request.RequestContext` the host built from its own request
    and returns a :class:`~dbsc.response.DbscResponse` the host applies to its own response. The
    library never reads the request, sends headers, or sets cookies itself.

    DBSC state lives in the injected :class:`~dbsc.store.Store`, keyed by the host's session id.
    It is deliberately NOT in a shared session blob: the blob is read-modify-written by every
    request, so the post-login navigation racing the registration POST would clobber the binding
    and silently disable enforcement (a stolen cookie would then still work, exactly what DBSC
    exists to prevent). Keying by the stable session id removes that shared cell entirely.

    Two store keys, deliberately separate (see :class:`~dbsc.store.Store`): a pending registration
    is written when DBSC is *offered* at login; a binding is written only on a *successful*
    registration and its existence is the authoritative "this session is hard-DBSC" mark.

    ``clock`` returns the current Unix time; inject a fake one in tests.
    """

    def __init__(
        self,
        config: Config,
        store: Store,
        *,
        jwt_verifier: JwtVerifier | None = None,
        audit: AuditLogger | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Create a server.

        Args:
            config: Static DBSC configuration.
            store: Where DBSC state lives, keyed by the host's session id.
            jwt_verifier: Override the ES256 verifier (rarely needed).
            audit: Receives every state transition; defaults to discarding them.
            clock: Returns the current Unix time; defaults to :func:`time.time`.
        """
        self._config = config
        self._store = store
        self._jwt_verifier = jwt_verifier or JwtVerifier()
        self._audit = audit or NullAuditLogger()
        self._clock = clock

    async def build_registration_header_response(self, ctx: RequestContext) -> DbscResponse:
        """Offer DBSC registration. Call after full authentication (post-2FA / post-passkey).

        Returns a response carrying the ``Secure-Session-Registration`` header, telling the browser
        to generate a device-bound key and POST a registration JWT. The challenge is stored as a
        pending registration (never the binding key) and echoed back as the JWT ``jti``.
        ``status`` is ``None``: merge these headers into the normal login response. A non-DBSC
        browser ignores the header and never registers, so the binding is never created and the
        gate degrades to plain cookie auth: locking such a user out is structurally impossible.
        """
        challenge = _nonce()
        await self._store.put_pending_registration(
            ctx.session_id, PendingRegistration(ctx.user_id, challenge, self._now())
        )
        value = f'({_ALGORITHM}); path="{self._config.register_path}"; challenge="{challenge}"'
        return DbscResponse(headers={"Secure-Session-Registration": value, **_NO_STORE})

    async def register(self, jwt: str, ctx: RequestContext) -> DbscResponse:
        """Verify a registration JWT (single-phase, per the W3C spec).

        On success creates the binding (the authoritative hard-DBSC mark) and returns 200 with the
        bound cookie, the ``Sec-Secure-Session-Id`` header, and the session-instructions JSON body.

        Only ``Sec-Secure-Session-Id`` is emitted here: a ``Secure-Session-Challenge`` on the
        registration response makes Chrome report a Challenge Error. The challenge belongs to the
        refresh flow and is issued via the first /dbsc/refresh 403. The binding carries an
        internally-seeded challenge purely so it stays valid until that first rotation.

        The offer is consumed only by a registration that verifies, and only if it is still the
        live offer at that moment (:meth:`Store.commit_registration
        <dbsc.store.Store.commit_registration>`). Failed attempts leave it intact, so junk
        registrations sent with a stolen session cookie cannot use it up and keep the real browser
        on plain cookie auth. A logout, or a newer login offer, that lands mid-registration wins,
        and so does the first of two registrations racing on one offer.

        Raises:
            JwtInvalidError: the JWT is invalid or signs the wrong challenge.
            ChallengeExpiredError: the pending registration challenge is past its TTL.
            MissingChallengeError: no live offer: none was made, it was already used, or a logout
                or newer offer replaced it while this registration was in flight.
            SessionNotFoundError: the offer was made to a different user than ``ctx.user_id``.
            CorruptStateError: a pending-registration record exists but is unreadable.
        """
        pending = await self._store.get_pending_registration(ctx.session_id)
        if pending is None:
            await self._fail(
                AuditEvent.REGISTRATION_FAILED, "No pending registration challenge.", ctx
            )
            raise MissingChallengeError("No pending registration challenge")
        if not _same_user(pending.user_id, ctx.user_id):
            await self._fail(
                AuditEvent.REGISTRATION_FAILED, "Offer was made to a different user.", ctx
            )
            raise SessionNotFoundError("Registration offer belongs to a different user")
        if self._now() - pending.reg_challenge_time > self._config.challenge_ttl_seconds:
            await self._fail(AuditEvent.REGISTRATION_FAILED, "Registration challenge expired.", ctx)
            raise ChallengeExpiredError("Registration challenge expired")

        try:
            result = self._jwt_verifier.verify_registration_jwt(self._jwt_verifier.parse(jwt))
        except JwtInvalidError as e:
            await self._fail(AuditEvent.REGISTRATION_FAILED, f"Invalid JWT: {e}", ctx)
            raise

        if not constant_time_equals(pending.reg_challenge, result.challenge):
            await self._fail(AuditEvent.REGISTRATION_FAILED, "Challenge mismatch.", ctx)
            raise JwtInvalidError("Challenge mismatch")

        now = self._now()
        session_identifier = _nonce(_SESSION_ID_BYTES)
        cookie_value = _nonce(_COOKIE_VALUE_BYTES)
        binding = Binding(
            user_id=pending.user_id or ctx.user_id,
            session_identifier=session_identifier,
            cookie_value=cookie_value,
            public_key_pem=result.public_key_pem,
            algorithm=result.algorithm,
            challenge=_nonce(),
            challenge_time=now,
            created_at=now,
            cookie_issued_at=now,
        )
        if not await self._store.commit_registration(ctx.session_id, pending, binding):
            await self._fail(
                AuditEvent.REGISTRATION_FAILED, "Offer withdrawn or used concurrently.", ctx
            )
            raise MissingChallengeError("Registration offer is no longer live")
        await self._audit.log(AuditEvent.REGISTERED, "DBSC session registered.", ctx.user_id)

        return DbscResponse(
            headers={"Sec-Secure-Session-Id": session_identifier, **_NO_STORE},
            cookies=(self._bound_cookie(cookie_value),),
            status=200,
            body=self._instructions_json(session_identifier, ctx),
            content_type="application/json",
        )

    async def issue_refresh_challenge(self, ctx: RequestContext) -> DbscResponse:
        """Rotate the cached refresh challenge and return a 403 carrying it.

        The 403 carries ``Secure-Session-Challenge`` (with the mandatory ``id`` sf-parameter) plus
        ``Sec-Secure-Session-Id``. Use this when the browser hits /dbsc/refresh with no (or a
        stale) cached challenge; it caches the new one and retries. Returns a bare 403 (no binding
        means nothing to refresh) if unbound.

        The rotation is a conditional write, so it never undoes a concurrent refresh or revoke; on
        a conflict it rotates the fresh state instead. If it keeps losing, the 403 carries the
        challenge stored now, unrotated, rather than none.

        Raises:
            CorruptStateError: the binding record exists but is unreadable.
        """
        for _ in range(_MAX_UPDATE_ATTEMPTS):
            binding = await self._store.get_binding(ctx.session_id)
            if binding is None:
                return DbscResponse(
                    headers=dict(_NO_STORE), status=403, content_type="application/json"
                )
            challenge = _nonce()
            rotated = binding.with_challenge(challenge, self._now())
            if await self._store.replace_binding(ctx.session_id, binding, rotated):
                return _challenge_403(rotated.session_identifier, challenge)

        binding = await self._store.get_binding(ctx.session_id)
        if binding is None:
            return DbscResponse(
                headers=dict(_NO_STORE), status=403, content_type="application/json"
            )
        return _challenge_403(binding.session_identifier, binding.challenge)

    async def refresh(self, jwt: str, ctx: RequestContext) -> DbscResponse:
        """Verify a refresh JWT, reissue the bound cookie, and rotate the cached challenge.

        The browser treats a refresh response that re-emits the existing cookie value as "no
        refresh happened" and terminates, so BOTH the cookie value and challenge must rotate.
        Returns 200 with the rotated cookie and the echoed session-instructions JSON.

        On any :class:`~dbsc.exceptions.RetryableRefreshError` (i.e.
        :class:`~dbsc.exceptions.MissingChallengeError`,
        :class:`~dbsc.exceptions.ChallengeExpiredError`,
        :class:`~dbsc.exceptions.ChallengeMismatchError`) the caller should call
        :meth:`issue_refresh_challenge` and 403 (benign retry); the audit log records
        :attr:`AuditEvent.REFRESH_RETRYABLE`, not :attr:`AuditEvent.REFRESH_FAILED`, so alerting
        on the latter isn't tripped by ordinary concurrency. On any other
        :class:`~dbsc.exceptions.DbscError` the caller MUST terminate the authenticated session
        server-side. Do not rely on the browser or cookie expiry; that is the failure mode that
        leaves a stolen-cookie session alive.

        The rotation is a conditional write. If another request changed the binding after it was
        read (a concurrent refresh, a reactive 403, a revoke), the proof is checked again against
        the fresh state, exactly as if the requests had arrived one after the other: a proof
        another refresh already spent becomes a benign challenge mismatch, and a revoked session
        stays revoked.

        Raises:
            JwtInvalidError: terminal; the JWT is malformed or not signed by the device key.
            SessionNotFoundError: terminal; unbound session, session identifier mismatch, or a
                binding that belongs to a different user than ``ctx.user_id``.
            CorruptStateError: terminal; the binding record exists but is unreadable.
            ChallengeExpiredError: retryable.
            ChallengeMismatchError: retryable (includes losing a write race repeatedly).
            MissingChallengeError: retryable.
        """
        for _ in range(_MAX_UPDATE_ATTEMPTS):
            binding = await self._binding_proved_by(jwt, ctx)
            now = self._now()
            new_cookie = _nonce(_COOKIE_VALUE_BYTES)
            new_challenge = _nonce()
            rotated = binding.with_rotated_cookie_and_challenge(
                new_cookie, new_challenge, now, now, self._config.cookie_max_age_seconds
            )
            if await self._store.replace_binding(ctx.session_id, binding, rotated):
                await self._audit.log(AuditEvent.REFRESHED, "DBSC cookie refreshed.", ctx.user_id)
                return DbscResponse(
                    headers={
                        **_challenge_headers(rotated.session_identifier, new_challenge),
                        **_NO_STORE,
                    },
                    cookies=(self._bound_cookie(new_cookie),),
                    status=200,
                    body=self._instructions_json(rotated.session_identifier, ctx),
                    content_type="application/json",
                )

        await self._fail(AuditEvent.REFRESH_RETRYABLE, "Binding changed concurrently.", ctx)
        raise ChallengeMismatchError("Binding changed concurrently")

    async def _binding_proved_by(self, jwt: str, ctx: RequestContext) -> Binding:
        """Read the binding and check the refresh proof against it (see :meth:`refresh`)."""
        binding = await self._store.get_binding(ctx.session_id)
        if binding is None:
            await self._fail(AuditEvent.REFRESH_FAILED, "No DBSC session bound.", ctx)
            raise SessionNotFoundError("No DBSC session bound to this user")
        if not _same_user(binding.user_id, ctx.user_id):
            await self._fail(AuditEvent.REFRESH_FAILED, "Binding belongs to a different user.", ctx)
            raise SessionNotFoundError("DBSC session belongs to a different user")

        presented_id = ctx.header("Sec-Secure-Session-Id")
        if presented_id and not constant_time_equals(binding.session_identifier, presented_id):
            await self._fail(AuditEvent.REFRESH_FAILED, "Session identifier mismatch.", ctx)
            raise SessionNotFoundError("DBSC session identifier mismatch")

        if not binding.challenge:
            await self._fail(AuditEvent.REFRESH_RETRYABLE, "No pending challenge.", ctx)
            raise MissingChallengeError("No pending challenge")
        if self._now() - binding.challenge_time > self._config.challenge_ttl_seconds:
            await self._fail(AuditEvent.REFRESH_RETRYABLE, "Challenge expired.", ctx)
            raise ChallengeExpiredError("Challenge expired")

        try:
            parsed = self._jwt_verifier.parse(jwt)
            jti = self._jwt_verifier.verify_refresh_jwt(parsed, binding.public_key_pem)
        except JwtInvalidError as e:
            await self._fail(AuditEvent.REFRESH_FAILED, f"Invalid JWT: {e}", ctx)
            raise

        # Accept the current challenge, or the single immediately-previous one until its own TTL
        # (bridges a concurrent issue_refresh_challenge() rotation; see the Binding docstring).
        # Constant-time, current first.
        challenge_matches = constant_time_equals(binding.challenge, jti) or (
            binding.previous_challenge != ""
            and self._now() - binding.previous_challenge_time <= self._config.challenge_ttl_seconds
            and constant_time_equals(binding.previous_challenge, jti)
        )
        if not challenge_matches:
            # Signature already verified above (device-bound key), so a mismatch here is benign,
            # never forgery. See the ChallengeMismatchError docstring.
            await self._fail(AuditEvent.REFRESH_RETRYABLE, "Challenge mismatch.", ctx)
            raise ChallengeMismatchError("Challenge mismatch")
        return binding

    async def revoke(
        self, ctx: RequestContext, *, enforcement_terminated: bool = False
    ) -> DbscResponse:
        """Terminate DBSC for this session.

        Deletes the stored state and emits a deletion for the bound cookie (it is independent of
        the application session cookie). Call on logout, and on a refresh terminal failure
        *before* you log the user out so the audit row carries the user id.
        ``enforcement_terminated`` flips the audit event to
        :attr:`AuditEvent.ENFORCEMENT_TERMINATED`.
        """
        try:
            was_bound = await self._store.get_binding(ctx.session_id) is not None
        except CorruptStateError:
            # A corrupt record still represents a session that must be torn down: delete and
            # audit it; don't let the unreadable value abort revocation (this method is the
            # fail-closed path callers reach precisely when state is unreadable).
            was_bound = True
        await self._store.delete(ctx.session_id)
        if was_bound:
            if enforcement_terminated:
                await self._audit.log(
                    AuditEvent.ENFORCEMENT_TERMINATED,
                    "DBSC enforcement terminated session (cookie missing or mismatched).",
                    ctx.user_id,
                )
            else:
                await self._audit.log(AuditEvent.REVOKED, "DBSC session revoked.", ctx.user_id)
        return DbscResponse(
            headers=dict(_NO_STORE), cookies=(Cookie.deletion(self._config.cookie_name),)
        )

    # --- Enforcement-gate primitives -------------------------------------------------------
    # The library deliberately does not run the gate itself: where you enforce depends on your
    # routing. The recommended policy is in the README: no binding means degrade to cookie auth;
    # binding present + cookie missing/mismatched on a document request (or a subresource past
    # the registration grace), not on the DBSC endpoints, means revoke + log the user out.

    async def get_binding(self, ctx: RequestContext) -> Binding | None:
        """The session's binding, or ``None`` ONLY when it has none (degrade to cookie auth).

        A present-but-unreadable binding raises instead, so the gate fails closed.

        Raises:
            CorruptStateError: the binding record exists but is unreadable.
        """
        return await self._store.get_binding(ctx.session_id)

    def bound_cookie_matches(self, binding: Binding, ctx: RequestContext) -> bool:
        """Constant-time comparison of the presented bound cookie against the stored value.

        The stored value rotates every refresh; this checks the value, not mere presence. Also
        False when the binding belongs to a different user than ``ctx.user_id`` (both known): a
        session-fixation defence, since a device bound by someone else must never vouch for this
        user's session.
        """
        if not _same_user(binding.user_id, ctx.user_id):
            return False
        presented = ctx.cookie(self._config.cookie_name)
        if not presented:
            return False
        if binding.cookie_value and constant_time_equals(binding.cookie_value, presented):
            return True
        # Accept the single immediately-previous cookie value until the instant it would itself
        # have expired in the browser. The bound cookie rotates on every refresh, but the
        # refresh round-trip is a propagation window: a request that left the browser just
        # before it stored the rotated Set-Cookie still legitimately carries the prior value.
        # Rejecting it as a stolen cookie terminates legitimate sessions whenever a normal
        # request races a refresh (the failure is latency-proportional, so it bites in
        # production and not on loopback). The exposure stays bounded (single-depth history,
        # the value's own natural expiry) and a truly stolen cookie still cannot complete a
        # refresh without the device-bound key, so it still hard-fails at the next refresh.
        return (
            binding.previous_cookie_value != ""
            and self._now() < binding.previous_cookie_expires_at
            and constant_time_equals(binding.previous_cookie_value, presented)
        )

    def is_document_request(self, ctx: RequestContext) -> bool:
        """True for a top-level document load (``Sec-Fetch-Dest: document``)."""
        return ctx.header("Sec-Fetch-Dest") == "document"

    def is_within_registration_grace(self, binding: Binding) -> bool:
        """True during the first ``registration_grace_seconds`` after registration.

        Subresource requests already in flight when the registration response landed carry no
        bound cookie yet; the recommended gate exempts them (but never document loads) here.
        """
        return self._now() - binding.created_at < self._config.registration_grace_seconds

    async def advertise_refresh_challenge(
        self, binding: Binding, ctx: RequestContext
    ) -> DbscResponse:
        """Proactively advertise this session's CURRENT cached challenge.

        Attaches it as a ``Secure-Session-Challenge`` header on an ordinary, already-authenticated
        response, so the browser holds a challenge when its first /dbsc/refresh fires and that
        refresh is single-step instead of the 403-then-proof two-step.

        No challenge rotation: it re-emits the value the binding already stores (the seed minted
        by :meth:`register`), exactly what the next refresh will be asked to prove. It is
        delivered exactly ONCE: the browser caches the advertised challenge for the session, so on
        the single emission this records ``challenge_advertised`` on the binding (one store write,
        keyed by ``ctx.session_id``, mirroring :meth:`issue_refresh_challenge`) and every later call
        no-ops. The caller passes the binding it already read for the enforcement gate, so the
        no-op path costs nothing; only the first delivery touches the store.

        Per spec this MUST NOT be attached to the registration response: the
        ``Secure-Session-Challenge`` ``id`` parameter (§9.2.1) must name an EXISTING session, and
        §8.7 silently drops a challenge whose session it cannot identify. The registration response
        is the very response that creates the session, so the id resolves to nothing there. Call
        this only where a Binding already exists (the enforcement-gate path, which already called
        :meth:`get_binding`); you cannot misuse it on registration because you have no Binding to
        pass.

        Returns an empty (no-op) :class:`~dbsc.response.DbscResponse` (nothing to apply, nothing
        written) when there is nothing safe or useful to advertise: the seed was already
        delivered, the session has already refreshed (steady state is self-sustaining), or the
        cached challenge is empty / past its TTL (let the reactive 403 path mint a fresh one).

        The mark is a conditional write against the binding you pass in. If the stored binding has
        changed since you read it (typically the browser's first refresh racing this page load),
        nothing is written or emitted: writing back the stale binding would undo that refresh and
        strand the browser's rotated cookie, and its seed challenge is stale anyway. The same
        condition keeps two racing page loads from both delivering the seed.
        """
        if (
            not _same_user(binding.user_id, ctx.user_id)
            or binding.challenge_advertised
            or binding.has_refreshed
            or not binding.challenge
            or self._now() - binding.challenge_time > self._config.challenge_ttl_seconds
        ):
            return DbscResponse()
        marked = binding.mark_challenge_advertised()
        if not await self._store.replace_binding(ctx.session_id, binding, marked):
            return DbscResponse()
        return DbscResponse(
            headers={
                **_challenge_headers(binding.session_identifier, binding.challenge),
                **_NO_STORE,
            }
        )

    async def session_instructions_json(self, ctx: RequestContext) -> str:
        """The session-instructions JSON for the current binding, or ``{}`` if unbound.

        Echoed on the refresh 200 so the browser can confirm it is the same session it registered.

        Raises:
            CorruptStateError: the binding record exists but is unreadable.
        """
        binding = await self._store.get_binding(ctx.session_id)
        if binding is None or not binding.session_identifier:
            return "{}"
        return self._instructions_json(binding.session_identifier, ctx)

    def _instructions_json(self, session_identifier: str, ctx: RequestContext) -> str:
        same_site = self._config.cookie_same_site
        scope: dict[str, object] = {"origin": ctx.origin_host_url, "include_site": False}
        if scope_rules := self._scope_specification(ctx):
            scope["scope_specification"] = [rule.to_dict() for rule in scope_rules]

        instructions: dict[str, object] = {
            "session_identifier": session_identifier,
            "refresh_url": self._config.refresh_path,
            "scope": scope,
            "credentials": [
                {
                    "type": "cookie",
                    "name": self._config.cookie_name,
                    "attributes": f"Path=/; Secure; HttpOnly; SameSite={same_site}",
                },
            ],
        }
        if initiators := self._allowed_refresh_initiators(ctx):
            instructions["allowed_refresh_initiators"] = initiators

        return dumps(instructions)

    def _scope_specification(self, ctx: RequestContext) -> list[ScopeRule]:
        if ctx.scope_specification is not None:
            return list(ctx.scope_specification)
        return list(self._config.scope_specification)

    def _allowed_refresh_initiators(self, ctx: RequestContext) -> list[str]:
        # Both sources are already trimmed and validated as host patterns.
        initiators = ctx.allowed_refresh_initiators
        if initiators is None:
            initiators = self._config.allowed_refresh_initiators
        return list(initiators)

    def _bound_cookie(self, value: str) -> Cookie:
        return Cookie(
            self._config.cookie_name,
            value,
            self._now() + self._config.cookie_max_age_seconds,
            same_site=self._config.cookie_same_site,
        )

    def _now(self) -> int:
        return int(self._clock())

    async def _fail(self, event: AuditEvent, message: str, ctx: RequestContext) -> None:
        await self._audit.log(event, message, ctx.user_id)


def _challenge_headers(session_identifier: str, challenge: str) -> dict[str, str]:
    # Per the W3C draft the challenge structured-field MUST carry an `id` sf-parameter
    # pointing at the session it refers to.
    id_param = f'; id="{session_identifier}"' if session_identifier else ""
    headers = {"Secure-Session-Challenge": f'"{challenge}"{id_param}'}
    if session_identifier:
        headers["Sec-Secure-Session-Id"] = session_identifier
    return headers


def _same_user(recorded: str, current: str) -> bool:
    """False only when both user ids are known and differ (see ``RequestContext.user_id``)."""
    return not recorded or not current or recorded == current


def _challenge_403(session_identifier: str, challenge: str) -> DbscResponse:
    return DbscResponse(
        headers={**_challenge_headers(session_identifier, challenge), **_NO_STORE},
        status=403,
        content_type="application/json",
    )


def _nonce(num_bytes: int = _NONCE_BYTES) -> str:
    return secrets.token_hex(num_bytes)
