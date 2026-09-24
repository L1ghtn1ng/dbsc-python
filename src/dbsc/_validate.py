"""Input validation shared by configuration, request context and stored records.

Everything here guards a value that ends up in a response header, a cookie, or the session
instructions the browser acts on. Failing fast on a bad value keeps a misconfiguration (or a
tampered store record) from turning into header injection or a mis-scoped session.
"""

import re
from collections.abc import Iterable

# RFC 6265 cookie-name token, and the __Host- prefix the whole design assumes: Secure, Path=/,
# no Domain, so include_site is false and the cookie can never span subdomains.
_COOKIE_NAME = re.compile(r"__Host-[!#$%&'*+\-.^_`|~0-9A-Za-z]+")
# An absolute path of RFC 3986 path characters. Excludes quotes, backslashes, whitespace and
# control characters (header injection) and a leading "//" (a scheme-relative URL that would
# point the browser's refresh at another host).
_PATH = re.compile(r"/(?!/)[A-Za-z0-9\-._~!$&'()*+,;=:@%/]*")
_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_PORT = r"(?::[0-9]{1,5})?"
# A host, optionally with a leading "*." wildcard and a port. No scheme, path or whitespace.
_HOST_PATTERN = re.compile(rf"(?:\*\.)?{_LABEL}(?:\.{_LABEL})*{_PORT}")
# DBSC only runs in secure contexts: https, or plain http on loopback for local development.
_ORIGIN = re.compile(
    rf"https://(?:{_LABEL}(?:\.{_LABEL})*|\[[0-9A-Fa-f:.]+\]){_PORT}"
    rf"|http://(?:localhost|127\.0\.0\.1|\[::1\]){_PORT}"
)
# Safe inside a structured-field string (RFC 8941): visible ASCII except '"' and '\'.
_SF_STRING = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]*")
# RFC 6265 cookie-octet: visible ASCII except '"', ',', ';' and '\'.
_COOKIE_VALUE = re.compile(r"[\x21\x23-\x2b\x2d-\x3a\x3c-\x5b\x5d-\x7e]*")

SAME_SITE_VALUES = frozenset({"Lax", "Strict", "None"})


def require(condition: bool, message: str) -> None:  # noqa: FBT001 (reads as an assertion)
    """Raise ``ValueError("DBSC: <message>")`` unless ``condition`` holds."""
    if not condition:
        raise ValueError(f"DBSC: {message}")


def is_cookie_name(value: str) -> bool:
    return _COOKIE_NAME.fullmatch(value) is not None


def is_path(value: str) -> bool:
    return _PATH.fullmatch(value) is not None


def is_host_pattern(value: str) -> bool:
    return _HOST_PATTERN.fullmatch(value) is not None


def is_origin(value: str) -> bool:
    return _ORIGIN.fullmatch(value) is not None


def is_sf_string_safe(value: str) -> bool:
    return _SF_STRING.fullmatch(value) is not None


def is_cookie_value(value: str) -> bool:
    return _COOKIE_VALUE.fullmatch(value) is not None


def host_patterns(values: Iterable[str], what: str) -> tuple[str, ...]:
    """Trim, drop blanks, and require every remaining entry to be a host pattern."""
    hosts = tuple(host for host in (value.strip() for value in values) if host)
    for host in hosts:
        require(is_host_pattern(host), f"{what} entries must be host patterns, got {host!r}.")
    return hosts
