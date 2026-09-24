import base64

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from dbsc import JwtInvalidError, JwtVerifier
from tests.support import FakeDevice, b64u

verifier = JwtVerifier()


def test_registration_jwt_verifies_and_extracts_jti(device: FakeDevice) -> None:
    result = verifier.verify_registration_jwt(verifier.parse(device.registration_jwt("chal-abc")))
    assert result.challenge == "chal-abc"
    assert result.algorithm == "ES256"
    assert "PUBLIC KEY" in result.public_key_pem


def test_refresh_jwt_verifies_against_stored_pem(device: FakeDevice) -> None:
    pem = verifier.verify_registration_jwt(
        verifier.parse(device.registration_jwt("x"))
    ).public_key_pem
    assert (
        verifier.verify_refresh_jwt(verifier.parse(device.refresh_jwt("chal-xyz")), pem)
        == "chal-xyz"
    )


def test_refresh_jwt_rejected_against_a_different_key(device: FakeDevice) -> None:
    other = FakeDevice().registration_jwt("y")
    other_pem = verifier.verify_registration_jwt(verifier.parse(other)).public_key_pem
    with pytest.raises(JwtInvalidError):
        verifier.verify_refresh_jwt(verifier.parse(device.refresh_jwt("chal")), other_pem)


@pytest.mark.parametrize(
    "jwt",
    [
        "not.a.jwt.really",
        "only.two",
        "",
        f"{b64u('[]')}.{b64u('{}')}.{b64u('sig')}",  # header is a list, not an object
        f"{b64u('{}')}.{b64u('not json')}.{b64u('sig')}",
        f"{b64u('{}')}.{b64u('{}')}.",  # empty signature
        f"{b64u('{}')}.{b64u('{}')}.!!!",  # signature isn't base64url
        f"{b64u('{}')}.é.{b64u('sig')}",  # non-ASCII segment
    ],
)
def test_malformed_jwt_rejected(jwt: str) -> None:
    with pytest.raises(JwtInvalidError):
        verifier.parse(jwt)


def test_alg_none_rejected() -> None:
    alg_none = f"{b64u('{"alg":"none"}')}.{b64u('{"jti":"x"}')}.{b64u('sig')}"
    with pytest.raises(JwtInvalidError, match="Unsupported algorithm"):
        verifier.verify_registration_jwt(verifier.parse(alg_none))


def test_alg_none_rejected_on_refresh(device: FakeDevice) -> None:
    pem = verifier.verify_registration_jwt(
        verifier.parse(device.registration_jwt("x"))
    ).public_key_pem
    forged = device.sign({"alg": "none"}, {"jti": "x"})
    with pytest.raises(JwtInvalidError, match="Unsupported algorithm"):
        verifier.verify_refresh_jwt(verifier.parse(forged), pem)


@pytest.mark.parametrize(
    ("jwk_patch", "message"),
    [
        ({"kty": "RSA"}, "key type or curve"),
        ({"crv": "P-384"}, "key type or curve"),
        ({"x": b64u(b"\x01" * 31)}, "wrong length"),
        ({"y": 12}, "wrong length"),
        ({"x": b64u(b"\x01" * 32), "y": b64u(b"\x02" * 32)}, "not a valid P-256"),  # off-curve
    ],
)
def test_bad_jwk_rejected(device: FakeDevice, jwk_patch: dict[str, object], message: str) -> None:
    jwk = device.jwk | jwk_patch
    jwt = device.sign({"alg": "ES256", "jwk": jwk}, {"jti": "x"})
    with pytest.raises(JwtInvalidError, match=message):
        verifier.verify_registration_jwt(verifier.parse(jwt))


def test_missing_jwk_rejected(device: FakeDevice) -> None:
    with pytest.raises(JwtInvalidError, match="missing jwk"):
        verifier.verify_registration_jwt(
            verifier.parse(device.sign({"alg": "ES256"}, {"jti": "x"}))
        )


@pytest.mark.parametrize("payload", [{}, {"jti": ""}, {"jti": 7}])
def test_missing_jti_rejected(device: FakeDevice, payload: dict[str, object]) -> None:
    jwt = device.sign({"alg": "ES256", "jwk": device.jwk}, payload)
    with pytest.raises(JwtInvalidError, match="missing jti"):
        verifier.verify_registration_jwt(verifier.parse(jwt))


def test_der_signature_rejected(device: FakeDevice) -> None:
    """Only the raw 64-byte r||s form is accepted, not an ASN.1 DER blob."""
    header, payload, _ = device.registration_jwt("x").split(".")
    der_like = b64u(b"\x30" + b"\x00" * 69)
    with pytest.raises(JwtInvalidError, match="signature verification failed"):
        verifier.verify_registration_jwt(verifier.parse(f"{header}.{payload}.{der_like}"))


def test_tampered_payload_rejected(device: FakeDevice) -> None:
    header, _, signature = device.registration_jwt("x").split(".")
    with pytest.raises(JwtInvalidError, match="signature verification failed"):
        verifier.verify_registration_jwt(
            verifier.parse(f"{header}.{b64u('{"jti":"y"}')}.{signature}")
        )


def test_refresh_rejects_non_p256_stored_key(device: FakeDevice) -> None:
    p384_pem = (
        ec.generate_private_key(ec.SECP384R1())
        .public_key()
        .public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
        .decode()
    )
    for pem in (p384_pem, "not a pem"):
        with pytest.raises(JwtInvalidError, match="signature verification failed"):
            verifier.verify_refresh_jwt(verifier.parse(device.refresh_jwt("x")), pem)


def test_pem_is_byte_identical_to_the_php_encoding(device: FakeDevice) -> None:
    """Bindings written by the PHP library store this PEM; ours must match it exactly."""
    x = base64.urlsafe_b64decode(device.jwk["x"] + "==")
    y = base64.urlsafe_b64decode(device.jwk["y"] + "==")
    ec_p256_oid_der = bytes.fromhex("301306072a8648ce3d020106082a8648ce3d030107")
    spki = b"\x30\x59" + ec_p256_oid_der + b"\x03\x42\x00\x04" + x + y
    b64 = base64.b64encode(spki).decode()
    php_pem = (
        "-----BEGIN PUBLIC KEY-----\n"
        + "".join(f"{b64[i : i + 64]}\n" for i in range(0, len(b64), 64))
        + "-----END PUBLIC KEY-----\n"
    )

    result = verifier.verify_registration_jwt(verifier.parse(device.registration_jwt("x")))
    assert result.public_key_pem == php_pem
    serialization.load_pem_public_key(php_pem.encode())  # and it round-trips
