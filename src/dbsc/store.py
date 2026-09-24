"""Persistence for DBSC state."""

import time
from abc import abstractmethod
from collections.abc import Callable
from typing import Protocol, override

from dbsc.binding import Binding
from dbsc.pending import PendingRegistration


class Store(Protocol):
    """Persistence for DBSC state, keyed by the host application's session id.

    Every method is abstract: a subclass that leaves any of them out raises ``TypeError`` when
    instantiated, so an incomplete store fails at startup rather than in production. There are
    deliberately no default implementations, because the two conditional writes can only be made
    atomic with the backend's own primitive.

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
    - :meth:`commit_registration` and :meth:`replace_binding` MUST be atomic: the check and the
      write happen as one indivisible operation against the backend (Redis ``WATCH``/``MULTI``, a
      SQL transaction or ``UPDATE ... WHERE``, a row lock). A check-then-write split across
      ``await`` points is NOT atomic, even in a single process: two concurrent callers can both
      pass the check and both report success. That lets one registration offer bind twice, and
      a stale write undo a refresh's cookie rotation (logging a legitimate user out) or bring
      back a session that was just revoked.
    """

    @abstractmethod
    async def put_pending_registration(self, session_id: str, pending: PendingRegistration) -> None:
        """Store the registration offer, expiring on the challenge TTL."""

    @abstractmethod
    async def get_pending_registration(self, session_id: str) -> PendingRegistration | None:
        """The pending registration, or ``None`` if absent.

        Raises:
            CorruptStateError: a record exists but is unreadable.
        """

    @abstractmethod
    async def delete_pending_registration(self, session_id: str) -> None:
        """Remove the pending registration. A no-op if absent."""

    @abstractmethod
    async def put_binding(self, session_id: str, binding: Binding) -> None:
        """Store the binding, expiring with the authenticated session lifetime."""

    @abstractmethod
    async def get_binding(self, session_id: str) -> Binding | None:
        """The binding, or ``None`` ONLY if no record exists.

        Raises:
            CorruptStateError: a record exists but is unreadable. Never return ``None`` for it.
        """

    @abstractmethod
    async def delete(self, session_id: str) -> None:
        """Remove both the binding and any pending registration. A no-op if absent."""

    @abstractmethod
    async def commit_registration(
        self, session_id: str, offer: PendingRegistration, binding: Binding
    ) -> bool:
        """Atomically consume ``offer`` and store ``binding``, only if ``offer`` is still stored.

        Returns ``False``, changing nothing, if the stored offer differs or is gone: it was used by
        a concurrent registration, withdrawn by :meth:`delete` (logout), or replaced by a newer
        offer. Compare decoded records (``PendingRegistration`` equality), not raw JSON. The
        binding expires like :meth:`put_binding`. MUST be atomic (see the class docstring).

        Raises:
            CorruptStateError: the stored offer exists but is unreadable.
        """

    @abstractmethod
    async def replace_binding(self, session_id: str, expected: Binding, new: Binding) -> bool:
        """Atomically write ``new`` only if the stored binding still equals ``expected``.

        Returns ``False``, writing nothing, if the stored binding differs or no longer exists:
        someone else updated or revoked it since ``expected`` was read. Compare the decoded
        records (``Binding`` equality), not raw JSON, so records written by another library
        version with different formatting still compare equal. Expires like :meth:`put_binding`.
        MUST be atomic (see the class docstring).

        Raises:
            CorruptStateError: the stored record exists but is unreadable.
        """


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
