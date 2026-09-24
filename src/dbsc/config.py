"""Static DBSC configuration."""

from collections.abc import Sequence
from dataclasses import dataclass

from dbsc._validate import SAME_SITE_VALUES, host_patterns, is_cookie_name, is_path, require
from dbsc.scope import ScopeRule

MAX_COOKIE_MAX_AGE_SECONDS = 3600
MAX_CHALLENGE_TTL_SECONDS = 86400
MAX_REGISTRATION_GRACE_SECONDS = 60


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    """Static DBSC configuration.

    Defaults match the wire behaviour validated against real Chrome (see README, "Wire-protocol
    notes"). Two constraints are load-bearing:

    - ``challenge_ttl_seconds`` MUST exceed ``cookie_max_age_seconds``, so the challenge the
      browser cached just before cookie expiry is still valid when it presents it. The
      constructor enforces this.
    - ``include_site`` is always false because the bound cookie uses the ``__Host-`` prefix and
      cannot span subdomains. ``cookie_name`` must therefore carry that prefix.

    Every value is validated when the Config is built (``ValueError`` on anything unsafe): paths
    must be absolute, same-origin URL paths; ``cookie_same_site`` is one of ``Lax``, ``Strict``,
    ``None``; lifetimes are bounded (bound cookie 1s-1h, challenge TTL up to 24h, registration
    grace 0-60s), because a long-lived bound cookie or a long grace window defeats the point of
    DBSC; and refresh initiators must be host patterns.

    Attributes:
        registration_grace_seconds: Seconds after a successful registration during which
            subresource fetches are exempt from the enforcement gate. Covers the inherent
            in-flight race where a page's XHR/script/image requests are already on the wire
            (without the bound cookie) when the registration response lands client-side. Raise
            only if production termination audits show legitimate post-registration traffic still
            tripping the gate.
        allowed_refresh_initiators: Hosts allowed to initiate a cross-site DBSC refresh
            (``allowed_refresh_initiators``). Overridable per request via
            :attr:`RequestContext.allowed_refresh_initiators
            <dbsc.request.RequestContext.allowed_refresh_initiators>`.
        scope_specification: Modifications to the default scope (``scope_specification``),
            overridable per request via :attr:`RequestContext.scope_specification
            <dbsc.request.RequestContext.scope_specification>`. Omitted from the wire entirely
            when empty, which is the spec default of "the whole origin". Almost every deployment
            wants at least one exclude rule here. Scope decides which requests the browser DEFERS
            to refresh an expired cookie, and each refresh costs a signature from a rate-limited
            device key, so anything that needs no session (assets, health checks, status polling)
            should be excluded. See :class:`~dbsc.scope.ScopeRule` for what happens when it is not.
    """

    cookie_name: str = "__Host-dbsc"
    cookie_max_age_seconds: int = 300
    register_path: str = "/dbsc/register"
    refresh_path: str = "/dbsc/refresh"
    challenge_ttl_seconds: int = 900
    registration_grace_seconds: int = 5
    cookie_same_site: str = "Lax"
    allowed_refresh_initiators: Sequence[str] = ()
    scope_specification: Sequence[ScopeRule] = ()

    def __post_init__(self) -> None:
        require(
            is_cookie_name(self.cookie_name),
            "cookie_name must be a cookie-name token with the __Host- prefix.",
        )
        for name in ("register_path", "refresh_path"):
            require(
                is_path(getattr(self, name)),
                f"{name} must be an absolute path of URL path characters (no '//' prefix).",
            )
        require(
            self.cookie_same_site in SAME_SITE_VALUES,
            f"cookie_same_site must be one of {sorted(SAME_SITE_VALUES)}.",
        )
        require(
            1 <= self.cookie_max_age_seconds <= MAX_COOKIE_MAX_AGE_SECONDS,
            f"cookie_max_age_seconds must be 1-{MAX_COOKIE_MAX_AGE_SECONDS}.",
        )
        require(
            self.challenge_ttl_seconds <= MAX_CHALLENGE_TTL_SECONDS,
            f"challenge_ttl_seconds must be at most {MAX_CHALLENGE_TTL_SECONDS}.",
        )
        require(
            self.challenge_ttl_seconds > self.cookie_max_age_seconds,
            "challenge_ttl_seconds must exceed cookie_max_age_seconds, else the browser's cached "
            "challenge expires before it can use it just before cookie expiry.",
        )
        require(
            0 <= self.registration_grace_seconds <= MAX_REGISTRATION_GRACE_SECONDS,
            f"registration_grace_seconds must be 0-{MAX_REGISTRATION_GRACE_SECONDS}.",
        )
        # Normalise and freeze caller-supplied lists so the config really is immutable.
        object.__setattr__(
            self,
            "allowed_refresh_initiators",
            host_patterns(self.allowed_refresh_initiators, "allowed_refresh_initiators"),
        )
        object.__setattr__(self, "scope_specification", tuple(self.scope_specification))
