"""``scope_specification`` rules."""

from dataclasses import dataclass
from enum import StrEnum
from typing import Self

from dbsc._validate import is_host_pattern, is_path, require


class ScopeRuleType(StrEnum):
    """Whether a :class:`ScopeRule` pulls requests into scope or pushes them out."""

    INCLUDE = "include"
    EXCLUDE = "exclude"


@dataclass(frozen=True, slots=True)
class ScopeRule:
    """One rule in a session's ``scope_specification``: a modification to the default scope,
    either pulling something in or pushing something out.

    WHY THIS MATTERS MORE THAN IT LOOKS. A session's scope decides which requests the browser will
    DEFER while it refreshes an expired bound cookie, and every refresh spends a signature from a
    rate-limited device key. Leave the default whole-origin scope in place and your static assets
    are in it: a cold page load with an expired cookie fires every stylesheet, script and icon at
    once, and the browser attempts a separate refresh for each; it does not coalesce them.
    Measured against Chrome 151, seven assets produced seven signing attempts in the same second,
    which is enough to exhaust the quota. Once exhausted the session wedges: refreshes stop, the
    browser will not register a replacement for a scope it already covers, and the site becomes
    indistinguishable from one the browser has no DBSC support for.

    So the rule of thumb is: scope the session to the authenticated surface it protects, not to
    the whole origin. Anything that needs no session (assets, health checks, status polling)
    should be excluded, because including it buys nothing and costs a signature per request.

    Build rules with :meth:`include` / :meth:`exclude`. ``domain`` is a host pattern (``None``
    means the session's own host); ``path`` is a path PREFIX, not an exact match: ``"/assets/"``
    covers everything under it.

    See https://w3c.github.io/webappsec-dbsc/#scope-specification
    """

    type: ScopeRuleType
    domain: str | None = None
    path: str | None = None

    def __post_init__(self) -> None:
        try:
            object.__setattr__(self, "type", ScopeRuleType(self.type))
        except ValueError:
            raise ValueError('DBSC: scope rule type must be "include" or "exclude".') from None
        require(
            self.domain is not None or self.path is not None,
            "a scope rule needs a domain, a path, or both.",
        )
        require(
            self.path is None or is_path(self.path),
            "a scope rule path must be an absolute URL path (no '//' prefix).",
        )
        require(
            self.domain is None or is_host_pattern(self.domain),
            "a scope rule domain must be a host pattern (no scheme or path).",
        )

    @classmethod
    def include(cls, path: str | None = None, domain: str | None = None) -> Self:
        """Bring something into scope that the default scope leaves out."""
        return cls(ScopeRuleType.INCLUDE, domain, path)

    @classmethod
    def exclude(cls, path: str | None = None, domain: str | None = None) -> Self:
        """Take something out of scope. This is the one you almost always want."""
        return cls(ScopeRuleType.EXCLUDE, domain, path)

    def to_dict(self) -> dict[str, str]:
        """The wire form.

        Absent members are omitted rather than sent as null: the spec treats a missing domain or
        path as "unconstrained", which is not the same as an explicit null.
        """
        rule = {"type": self.type.value}
        if self.domain is not None:
            rule["domain"] = self.domain
        if self.path is not None:
            rule["path"] = self.path
        return rule
