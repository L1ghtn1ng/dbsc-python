"""Persistence for DBSC state."""

import time
from collections.abc import Callable
from typing import Protocol, override

from dbsc.binding import Binding
from dbsc.pending import PendingRegistration


class Store(Protocol):
    """Persistence for DBSC state, keyed by the host application's session id.

    Implementation requirements:

    - The pending-registration and binding records MUST be stored under separate keys. "A binding
      exists" is the authoritative hard-DBSC mark; conflating it with the pending challenge would
      let a browser that merely *received* the registration offer be treated as bound.
    - State MUST NOT live in a read-modify-written shared session blob (last-writer-wins). Use a
      dedicated key space (Redis, a table, etc.). See README, "Storage".
    - Pending registrations should expire on a short TTL (the challenge TTL). Bindings should
      expire with the authenticated session lifetime.
    - :meth:`get_binding` / :meth:`get_pending_registration` MUST return ``None`` ONLY when no
      record exists. A record that is present but unparseable MUST raise
      :class:`~dbsc.exceptions.CorruptStateError` (the bundled value objects' ``from_json()``
      already does this; call it only for a record that exists). Returning ``None`` for corrupt
      data would degrade a bound session to plain cookie auth, the fail-open DBSC exists to
      prevent.
    - :meth:`commit_registration` SHOULD be atomic: it consumes the registration offer and creates
      the binding in one step, and only if that exact offer is still stored. Otherwise two
      registrations racing on one offer both bind (the second silently replacing the first), and a
      logout landing mid-registration leaves a binding behind for a logged-out session. Redis
      ``WATCH``/``MULTI`` or a SQL transaction do this.
    - :meth:`replace_binding` SHOULD be atomic. The server updates a binding by reading it,
      deriving a new one and writing it back conditionally; the condition is what stops a
      concurrent write (a refresh racing a page load, a logout racing a refresh) from being
      silently undone. The inherited default is a check-then-write: fine for a single-process
      store with no awaits in between, but it leaves a small window elsewhere. Override it with
      your backend's primitive (Redis ``WATCH``/``MULTI``, SQL ``UPDATE ... WHERE``, a row lock).

    Subclass :class:`Store` explicitly so you inherit those defaults until you override them.
    """

    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        """Store the registration offer, expiring on the challenge TTL."""
        ...

    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        """The pending registration, or ``None`` if absent.

        Raises:
            CorruptStateError: a record exists but is unreadable.
        """
        ...

    async def delete_pending_registration(self, session_id: str) -> None:
        """Remove the pending registration (it is single-use). A no-op if absent."""
        ...

    async def put_binding(self, session_id: str, binding: Binding) -> None:
        """Store the binding, expiring with the authenticated session lifetime."""
        ...

    async def get_binding(self, session_id: str) -> Binding | None:
        """The binding, or ``None`` ONLY if no record exists.

        Raises:
            CorruptStateError: a record exists but is unreadable. Never return ``None`` for it.
        """
        ...

    async def delete(self, session_id: str) -> None:
        """Remove both the binding and any pending registration. A no-op if absent."""
        ...

    async def commit_registration(
        self, session_id: str, offer: PendingRegistration, binding: Binding
    ) -> bool:
        """Consume ``offer`` and store ``binding``, only if ``offer`` is still the stored offer.

        Returns ``False``, changing nothing, if the stored offer differs or is gone: it was used by
        a concurrent registration, withdrawn by :meth:`delete` (logout), or replaced by a newer
        offer. Compare decoded records (``PendingRegistration`` equality), not raw JSON. The
        binding expires like :meth:`put_binding`.

        This default is a non-atomic check-then-write; override it atomically (see the class
        docstring).

        Raises:
            CorruptStateError: the stored offer exists but is unreadable.
        """
        if await self.get_pending_registration(session_id) != offer:
            return False
        await self.delete_pending_registration(session_id)
        await self.put_binding(session_id, binding)
        return True

    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        """Write ``new`` only if the stored binding still equals ``expected`` (compare-and-set).

        Returns ``False``, writing nothing, if the stored binding differs or no longer exists:
        someone else updated or revoked it since ``expected`` was read. Compare the decoded
        records (``Binding`` equality), not raw JSON, so records written by another library
        version with different formatting still compare equal. Expires like :meth:`put_binding`.

        This default is a non-atomic check-then-write; override it atomically (see the class
        docstring).

        Raises:
            CorruptStateError: the stored record exists but is unreadable.
        """
        if await self.get_binding(session_id) != expected:
            return False
        await self.put_binding(session_id, new)
        return True


class InMemoryStore(Store):
    """Reference :class:`Store` that keeps state in process memory with TTL semantics.

    Intended for tests, the bundled demo, and single-process experimentation only. State is lost
    on restart and is not shared between worker processes; ship a Redis- or database-backed store
    in production (see README, "Storage", and ``examples/demo_server.py`` for a file-backed one).
    """

    def __init__(
        self,
        challenge_ttl_seconds: int = 900,
        session_lifetime_seconds: int = 64800,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        """Create an empty store; TTLs are in seconds, ``clock`` returns Unix time."""
        self._challenge_ttl_seconds = challenge_ttl_seconds
        self._session_lifetime_seconds = session_lifetime_seconds
        self._clock = clock
        self._reg: dict[str, tuple[str, int]] = {}
        self._bind: dict[str, tuple[str, int]] = {}

    @override
    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        self._reg[session_id] = (pending.to_json(), self._now() + self._challenge_ttl_seconds)

    @override
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        raw = self._live(self._reg, session_id)
        return None if raw is None else PendingRegistration.from_json(raw)

    @override
    async def delete_pending_registration(self, session_id: str) -> None:
        self._reg.pop(session_id, None)

    @override
    async def put_binding(self, session_id: str, binding: Binding) -> None:
        self._bind[session_id] = (binding.to_json(), self._now() + self._session_lifetime_seconds)

    @override
    async def get_binding(self, session_id: str) -> Binding | None:
        raw = self._live(self._bind, session_id)
        return None if raw is None else Binding.from_json(raw)

    @override
    async def delete(self, session_id: str) -> None:
        self._bind.pop(session_id, None)
        self._reg.pop(session_id, None)

    @override
    async def commit_registration(
        self, session_id: str, offer: PendingRegistration, binding: Binding
    ) -> bool:
        # Atomic: no await between the check and the writes.
        raw = self._live(self._reg, session_id)
        if raw is None or PendingRegistration.from_json(raw) != offer:
            return False
        del self._reg[session_id]
        self._bind[session_id] = (binding.to_json(), self._now() + self._session_lifetime_seconds)
        return True

    @override
    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        # Atomic: no await between the check and the write, so nothing can interleave.
        raw = self._live(self._bind, session_id)
        if raw is None or Binding.from_json(raw) != expected:
            return False
        self._bind[session_id] = (new.to_json(), self._now() + self._session_lifetime_seconds)
        return True

    def _now(self) -> int:
        return int(self._clock())

    def _live(self, bucket: dict[str, tuple[str, int]], session_id: str) -> str | None:
        entry = bucket.get(session_id)
        if entry is None:
            return None
        value, expires_at = entry
        return None if expires_at < self._now() else value
