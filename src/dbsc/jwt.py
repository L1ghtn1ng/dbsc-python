"""Verification of the registration and refresh JWTs presented by the browser."""

import base64
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from dbsc._json import as_str, loads_object
from dbsc.exceptions import JwtInvalidError

SUPPORTED_ALG = "ES256"
# Browser DBSC JWTs are well under 1 KiB (the registration one carries a P-256 JWK); anything far
# larger is refused before any decoding work.
MAX_JWT_LENGTH = 8192

_P256_COORDINATE_BYTES = 32
_ES256_SIGNATURE_BYTES = 2 * _P256_COORDINATE_BYTES
_URLSAFE_TO_STD = str.maketrans("-_", "+/")


@dataclass(frozen=True, slots=True)
class ParsedJwt:
    """A split and decoded compact JWS, ready for signature verification.

    ``signing_input`` is the original ``header.payload`` text, exactly as signed.
    ``signature`` is the raw decoded signature bytes (64-byte ``r || s`` for ES256).
    """

    header: dict[str, object]
    payload: dict[str, object]
    signing_input: str
    signature: bytes


@dataclass(frozen=True, slots=True)
class RegistrationResult:
    """The outcome of verifying a registration JWT.

    The device public key (PEM, extracted from the embedded JWK), the algorithm, and the ``jti``
    the device signed (matched against the issued registration challenge by the caller).
    """

    public_key_pem: str
    algorithm: str
    challenge: str


class JwtVerifier:
    """Verifies the registration and refresh JWTs presented by the browser's DBSC implementation.

    Deliberately minimal validation. We check only ``alg``, the signature, and ``jti``:

    - ``alg`` is pinned to ES256 to block algorithm confusion (``none``, RS-with-EC-key).
    - ``crit`` is refused (RFC 7515 §4.1.11: we understand no extensions), duplicate JSON members
      are refused (parsers disagree on which wins), and tokens over ``MAX_JWT_LENGTH`` are refused
      before decoding.
    - The signature binds to the embedded JWK on registration and to the stored PEM on refresh,
      so a JWT minted against another integration cannot produce a matching signature here.
    - ``jti`` is matched (by the caller) against the currently-stored single-use server
      challenge, which has its own TTL. That nonce is the replay defence.

    We do NOT check ``iat``/``exp``/``typ``/``iss``/``aud``: the W3C DBSC draft lists them as
    optional and browser emission is not stable across versions; the challenge TTL is already
    stricter than any ``exp`` a browser would emit. Tighten here if a future spec revision
    mandates more claims. Don't speculatively add checks that only risk false rejects.

    Verification is CPU-bound and takes microseconds, so these methods are synchronous.
    """

    def parse(self, jwt: str) -> ParsedJwt:
        """Split and decode a compact JWS.

        Raises:
            JwtInvalidError: not three parts, header/payload not JSON objects, or empty signature.
        """
        if len(jwt) > MAX_JWT_LENGTH:
            raise JwtInvalidError("JWT is too large")
        parts = jwt.split(".")
        if len(parts) != 3:
            raise JwtInvalidError("JWT must have three parts")
        header_b64, payload_b64, signature_b64 = parts

        header = loads_object(_b64url_decode(header_b64))
        payload = loads_object(_b64url_decode(payload_b64))
        if header is None or payload is None:
            raise JwtInvalidError("JWT header or payload is not a JSON object")

        signature = _b64url_decode(signature_b64)
        if not signature:
            raise JwtInvalidError("JWT signature is empty")

        return ParsedJwt(header, payload, f"{header_b64}.{payload_b64}", signature)

    def verify_registration_jwt(self, parsed: ParsedJwt) -> RegistrationResult:
        """Verify a registration JWT: the device public key is embedded in the header as a JWK.

        Raises:
            JwtInvalidError: wrong ``alg``, missing/unsupported JWK, bad signature, or no ``jti``.
        """
        header = parsed.header
        _check_header(header)
        jwk = header.get("jwk")
        if not isinstance(jwk, dict):
            raise JwtInvalidError("JWT header is missing jwk")
        pem = _jwk_to_pem(jwk)

        if not _verify_signature(parsed.signing_input, parsed.signature, pem):
            raise JwtInvalidError("JWT signature verification failed")

        return RegistrationResult(pem, SUPPORTED_ALG, _require_jti(parsed.payload))

    def verify_refresh_jwt(self, parsed: ParsedJwt, pem: str) -> str:
        """Verify a refresh JWT against the device PEM stored at registration.

        Returns:
            The ``jti`` claim (matched against the stored challenge by the caller).

        Raises:
            JwtInvalidError: wrong ``alg``, bad signature, or no ``jti``.
        """
        _check_header(parsed.header)
        if not _verify_signature(parsed.signing_input, parsed.signature, pem):
            raise JwtInvalidError("JWT signature verification failed")
        return _require_jti(parsed.payload)


def _check_header(header: dict[str, object]) -> None:
    if header.get("alg") != SUPPORTED_ALG:
        raise JwtInvalidError("Unsupported algorithm")
    # RFC 7515 §4.1.11: extensions listed in "crit" MUST be understood, and we support none.
    if "crit" in header:
        raise JwtInvalidError("Unsupported critical header (crit)")


def _require_jti(payload: dict[str, object]) -> str:
    jti = as_str(payload.get("jti"))
    if not jti:
        raise JwtInvalidError("JWT payload is missing jti")
    return jti


def _verify_signature(signing_input: str, raw_signature: bytes, pem: str) -> bool:
    # DBSC ES256 signatures are the raw 64-byte (r||s) concatenation; OpenSSL expects DER.
    if len(raw_signature) != _ES256_SIGNATURE_BYTES:
        return False
    try:
        key = serialization.load_pem_public_key(pem.encode())
    except ValueError, UnsupportedAlgorithm:
        return False
    # Pin the key type as well as the header alg: a stored non-P-256 key must never verify.
    if not isinstance(key, ec.EllipticCurvePublicKey) or not isinstance(key.curve, ec.SECP256R1):
        return False
    r = int.from_bytes(raw_signature[:_P256_COORDINATE_BYTES])
    s = int.from_bytes(raw_signature[_P256_COORDINATE_BYTES:])
    try:
        key.verify(encode_dss_signature(r, s), signing_input.encode(), ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


def _jwk_to_pem(jwk: dict[object, object]) -> str:
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise JwtInvalidError("Unsupported JWK key type or curve")
    x_b64 = as_str(jwk.get("x"))
    y_b64 = as_str(jwk.get("y"))
    x = b"" if x_b64 is None else _b64url_decode(x_b64)
    y = b"" if y_b64 is None else _b64url_decode(y_b64)
    if len(x) != _P256_COORDINATE_BYTES or len(y) != _P256_COORDINATE_BYTES:
        raise JwtInvalidError("JWK x/y coordinates are the wrong length")

    try:
        # Validates the point is on the curve, so a malformed key fails here, not at verify time.
        key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + x + y)
    except ValueError as e:
        raise JwtInvalidError("JWK is not a valid P-256 public key") from e
    return key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def _b64url_decode(data: str) -> bytes:
    """Strict base64url decode tolerating absent padding; ``b""`` on any malformed input."""
    padded = data.translate(_URLSAFE_TO_STD) + "=" * (-len(data) % 4)
    try:
        return base64.b64decode(padded, validate=True)
    except ValueError:  # binascii.Error, or non-ASCII input
        return b""
