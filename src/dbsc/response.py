"""What the host application must emit after a DBSC operation."""

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from typing import Self


@dataclass(frozen=True, slots=True)
class Cookie:
    """A cookie the host application must emit.

    The bound DBSC cookie is independent of the application session cookie and must be
    set/deleted explicitly. ``delete=True`` means emit a deletion (expire in the past); ``value``
    is ignored in that case. ``expires_at`` is integer Unix seconds.
    """

    name: str
    value: str
    expires_at: int
    delete: bool = False
    path: str = "/"
    secure: bool = True
    http_only: bool = True
    same_site: str = "Lax"

    @classmethod
    def deletion(cls, name: str, path: str = "/") -> Self:
        """A cookie that tells the browser to delete ``name``."""
        return cls(name, "", 0, delete=True, path=path)


@dataclass(frozen=True, slots=True)
class DbscResponse:
    """What the host application must emit in response to a DBSC operation.

    Headers, cookies, and (for endpoint responses) an HTTP status and body. ``status`` is ``None``
    for operations that only decorate an existing response (the login registration header), so
    the caller leaves its own status untouched.

    The DBSC endpoint responses intentionally set ``Content-Type: application/json`` even when the
    body is empty (the 403 challenge), so a framework debug bar / error page is not injected into
    a response the browser parses strictly.
    """

    headers: Mapping[str, str] = field(default_factory=dict)
    cookies: Sequence[Cookie] = ()
    status: int | None = None
    body: str | None = None
    content_type: str | None = None
