"""A small, framework-agnostic, async server library for Device Bound Session Credentials (DBSC).

The entry point is :class:`DbscServer`::

    from dbsc import Config, DbscServer

    dbsc = DbscServer(Config(cookie_name="__Host-myapp_dbsc"), my_store)
"""

from dbsc.audit import AuditEvent, AuditLogger, NullAuditLogger
from dbsc.binding import Binding
from dbsc.config import Config
from dbsc.exceptions import (
    ChallengeExpiredError,
    ChallengeMismatchError,
    CorruptStateError,
    DbscError,
    JwtInvalidError,
    MissingChallengeError,
    RetryableRefreshError,
    SessionNotFoundError,
)
from dbsc.jwt import JwtVerifier, ParsedJwt, RegistrationResult
from dbsc.pending import PendingRegistration
from dbsc.request import RequestContext
from dbsc.response import Cookie, DbscResponse
from dbsc.scope import ScopeRule, ScopeRuleType
from dbsc.server import DbscServer
from dbsc.store import InMemoryStore, Store

__all__ = [
    "AuditEvent",
    "AuditLogger",
    "Binding",
    "ChallengeExpiredError",
    "ChallengeMismatchError",
    "Config",
    "Cookie",
    "CorruptStateError",
    "DbscError",
    "DbscResponse",
    "DbscServer",
    "InMemoryStore",
    "JwtInvalidError",
    "JwtVerifier",
    "MissingChallengeError",
    "NullAuditLogger",
    "ParsedJwt",
    "PendingRegistration",
    "RegistrationResult",
    "RequestContext",
    "RetryableRefreshError",
    "ScopeRule",
    "ScopeRuleType",
    "SessionNotFoundError",
    "Store",
]
