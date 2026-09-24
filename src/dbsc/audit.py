"""Optional hook for recording DBSC state transitions in the host application's audit trail."""

from enum import StrEnum
from typing import Protocol, override


class AuditEvent(StrEnum):
    """Every DBSC state transition reported to an :class:`AuditLogger`.

    Members are ``str`` subclasses, so comparing against the raw wire names (``"dbscRegistered"``,
    ...) keeps working for hosts that persist or filter on the plain string.
    """

    REGISTERED = "dbscRegistered"
    REGISTRATION_FAILED = "dbscRegistrationFailed"
    REFRESHED = "dbscRefreshed"
    REFRESH_FAILED = "dbscRefreshFailed"
    REFRESH_RETRYABLE = "dbscRefreshRetryable"
    REVOKED = "dbscRevoked"
    ENFORCEMENT_TERMINATED = "dbscEnforcementTerminated"


class AuditLogger(Protocol):
    """Receives every DBSC transition. Pass :class:`NullAuditLogger` to ignore them."""

    async def log(self, event: AuditEvent, message: str, user_id: str | None) -> None:
        """Record one transition. ``user_id`` is ``None`` or ``""`` when not yet known."""
        ...


class NullAuditLogger(AuditLogger):
    """An :class:`AuditLogger` that discards everything."""

    @override
    async def log(self, event: AuditEvent, message: str, user_id: str | None) -> None:
        """Discard the event."""
