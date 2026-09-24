"""Test doubles: a simulated DBSC device, a controllable clock, and small flow helpers."""

import base64
import json
import re
import time
from dataclasses import dataclass, field
from typing import override

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from dbsc import AuditEvent, AuditLogger, DbscResponse, DbscServer, RequestContext

ORIGIN = "https://example.test"
COOKIE_NAME = "__Host-dbsc"


def b64u(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeClock:
    """A settable stand-in for ``time.time`` so TTL tests don't sleep."""

    def __init__(self, now: float | None = None) -> None:
        self.now = time.time() if now is None else now

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


class FakeDevice:
    """A simulated DBSC device: holds an EC P-256 key and signs JWTs the way Chrome does.

    ES256 with a raw ``r || s`` signature, and the public key as an RFC 7518 JWK (fixed-width,
    left-padded 32-byte coordinates) in the registration header.
    """

    def __init__(self) -> None:
        self._key = ec.generate_private_key(ec.SECP256R1())
        numbers = self._key.public_key().public_numbers()
        self.jwk = {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(32)),
            "y": b64u(numbers.y.to_bytes(32)),
        }

    def registration_jwt(self, challenge: str) -> str:
        header = {"alg": "ES256", "typ": "dbsc+jwt", "jwk": self.jwk}
        return self.sign(header, {"jti": challenge, "iat": int(time.time())})

    def refresh_jwt(self, challenge: str) -> str:
        return self.sign(
            {"alg": "ES256", "typ": "dbsc+jwt"}, {"jti": challenge, "iat": int(time.time())}
        )

    def sign(self, header: dict[str, object], payload: dict[str, object]) -> str:
        signing_input = f"{b64u(json.dumps(header))}.{b64u(json.dumps(payload))}"
        der = self._key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256()))
        r, s = decode_dss_signature(der)
        return f"{signing_input}.{b64u(r.to_bytes(32) + s.to_bytes(32))}"


@dataclass
class RecordingAuditLogger(AuditLogger):
    events: list[AuditEvent] = field(default_factory=list)

    @override
    async def log(self, event: AuditEvent, message: str, user_id: str | None) -> None:
        self.events.append(event)


def ctx(
    session_id: str,
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
) -> RequestContext:
    return RequestContext(session_id, "user-1", ORIGIN, headers or {}, cookies or {})


def registration_challenge(response: DbscResponse) -> str:
    match = re.search(r'challenge="([^"]+)"', response.headers["Secure-Session-Registration"])
    assert match is not None
    return match.group(1)


def refresh_challenge(response: DbscResponse) -> tuple[str, str]:
    """``(challenge, session_id)`` from a ``Secure-Session-Challenge`` header."""
    match = re.fullmatch(r'"([^"]+)"; id="([^"]+)"', response.headers["Secure-Session-Challenge"])
    assert match is not None
    return match.group(1), match.group(2)


async def register(
    server: DbscServer, device: FakeDevice, request: RequestContext | str
) -> DbscResponse:
    """Offer registration and complete it with ``device``; returns the register response."""
    request = ctx(request) if isinstance(request, str) else request
    offer = await server.build_registration_header_response(request)
    return await server.register(device.registration_jwt(registration_challenge(offer)), request)


async def refresh_via_403(
    server: DbscServer, device: FakeDevice, session_id: str
) -> tuple[DbscResponse, DbscResponse]:
    """Run the two-phase refresh; returns ``(challenge_403, refresh_200)``."""
    challenge_response = await server.issue_refresh_challenge(ctx(session_id))
    challenge, sid = refresh_challenge(challenge_response)
    refreshed = await server.refresh(
        device.refresh_jwt(challenge), ctx(session_id, {"Sec-Secure-Session-Id": sid})
    )
    return challenge_response, refreshed
