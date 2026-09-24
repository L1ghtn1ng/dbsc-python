"""The framework-agnostic view of an inbound request."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType

from dbsc._validate import host_patterns, is_origin, require
from dbsc.scope import ScopeRule


@dataclass(frozen=True, slots=True)
class RequestContext:
    """Everything the library needs to know about the inbound request, decoupled from any HTTP
    framework. The host application builds one of these from its own request object.

    Attributes:
        session_id: The host application's stable authenticated-session identifier (e.g. the
            session-cookie value). DBSC state is keyed by it. It MUST be the same value across the
            post-login navigation and the registration POST, and it MUST NOT itself live inside a
            read-modify-written shared session blob.
        user_id: The authenticated user, recorded on the binding and in audit events. Pass it
            whenever it is known: a binding recorded for one user is refused for another (a
            session-fixation defence). ``""`` means "not known here" and skips that check.
        origin_host_url: The scheme+host[:port] (e.g. ``https://example.com``) for the DBSC
            scope. Must be ``https``, or plain ``http`` on loopback for local development.
        headers: Request headers, any casing. Look them up with :meth:`header`.
        cookies: Request cookies. Look them up with :meth:`cookie`.
        allowed_refresh_initiators: Per-request override for
            :attr:`Config.allowed_refresh_initiators
            <dbsc.config.Config.allowed_refresh_initiators>`; ``None`` falls back to the Config
            value, ``[]`` forces the key off.
        scope_specification: Per-request override for :attr:`Config.scope_specification
            <dbsc.config.Config.scope_specification>`; ``None`` falls back to the Config value,
            ``[]`` forces the key off.
    """

    session_id: str
    user_id: str
    origin_host_url: str
    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Mapping[str, str] = field(default_factory=dict)
    allowed_refresh_initiators: Sequence[str] | None = None
    scope_specification: Sequence[ScopeRule] | None = None

    def __post_init__(self) -> None:
        require(
            is_origin(self.origin_host_url),
            "origin_host_url must be an https origin (scheme://host[:port], no path); "
            "plain http is only allowed on loopback.",
        )
        if self.allowed_refresh_initiators is not None:
            object.__setattr__(
                self,
                "allowed_refresh_initiators",
                host_patterns(self.allowed_refresh_initiators, "allowed_refresh_initiators"),
            )
        normalised = {name.lower(): value for name, value in self.headers.items()}
        object.__setattr__(self, "headers", MappingProxyType(normalised))
        object.__setattr__(self, "cookies", MappingProxyType(dict(self.cookies)))

    def header(self, name: str) -> str | None:
        """Case-insensitive header lookup."""
        return self.headers.get(name.lower())

    def cookie(self, name: str) -> str | None:
        """Cookie lookup. Cookie names are case-sensitive."""
        return self.cookies.get(name)
