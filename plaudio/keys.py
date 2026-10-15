"""RSA helpers.

Reference facts (openplod native bridges):
* privateKey is base64 of a DER RSA private key. The Swift bridge (SecKeyCreateWithData)
  and Android (BouncyCastle RSAPrivateKey.getInstance) require PKCS#1 RSAPrivateKey; the
  Rust bridge also accepts PKCS#8. We accept both, plus PEM for convenience.
* Unwrapping (session material and audio file keys) is RSA PKCS#1 v1.5 decryption of a
  256-byte ciphertext.
* publicKey is sent to the device as the raw UTF-8 bytes of the string returned by the
  cloud gen-key endpoint. The reference never inspects it, so its exact encoding is NOT
  known. For locally generated keys we default to base64 PKCS#1 RSAPublicKey DER (mirrors
  the private key format). UNVERIFIED against a device.
"""

from __future__ import annotations

import base64
import binascii
from dataclasses import dataclass
from typing import Literal

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

PublicKeyFormat = Literal["pkcs1", "spki", "pem-pkcs1", "pem-spki"]
PUBLIC_KEY_FORMATS: tuple[str, ...] = ("pkcs1", "spki", "pem-pkcs1", "pem-spki")


class RSAKeyError(ValueError):
    pass


def load_private_key(encoded: str) -> rsa.RSAPrivateKey:
    text = (encoded or "").strip()
    try:
        if text.startswith("-----BEGIN"):
            key = serialization.load_pem_private_key(text.encode(), password=None)
        else:
            der = base64.b64decode(text, validate=False)
            try:
                key = serialization.load_der_private_key(der, password=None)
            except ValueError:
                key = _load_pkcs1_der(der)
    except (ValueError, TypeError, binascii.Error):
        raise RSAKeyError("Invalid RSA private key") from None
    if not isinstance(key, rsa.RSAPrivateKey):
        raise RSAKeyError("Private key is not RSA")
    return key


def _load_pkcs1_der(der: bytes):
    # cryptography's DER loader accepts "traditional" PKCS#1 too; wrap in PEM as a fallback.
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + base64.encodebytes(der) + b"-----END RSA PRIVATE KEY-----\n"
    return serialization.load_pem_private_key(pem, password=None)


def rsa_unwrap(private_key: str | rsa.RSAPrivateKey, ciphertext: bytes) -> bytes:
    """RSA-2048 PKCS#1 v1.5 decrypt, matching the reference bridges' rsa-decrypt op.

    Note: OpenSSL 3 may apply implicit rejection and return random bytes for a wrong key
    instead of raising; callers must check the plaintext (length, marker, Ogg CRCs)."""
    if len(ciphertext) != 256:
        raise RSAKeyError("Invalid RSA ciphertext size")
    key = load_private_key(private_key) if isinstance(private_key, str) else private_key
    try:
        return key.decrypt(bytes(ciphertext), padding.PKCS1v15())
    except ValueError:
        raise RSAKeyError("RSA unwrap failed (key does not match this identity?)") from None


def encode_public_key(public_key: rsa.RSAPublicKey, fmt: PublicKeyFormat = "pkcs1") -> str:
    if fmt in ("pkcs1", "pem-pkcs1"):
        pub_format = serialization.PublicFormat.PKCS1
    elif fmt in ("spki", "pem-spki"):
        pub_format = serialization.PublicFormat.SubjectPublicKeyInfo
    else:
        raise RSAKeyError(f"Unknown public key format {fmt}")
    if fmt.startswith("pem-"):
        return public_key.public_bytes(serialization.Encoding.PEM, pub_format).decode()
    return base64.b64encode(public_key.public_bytes(serialization.Encoding.DER, pub_format)).decode()


def describe_public_key(encoded: str) -> str:
    """Classify a public-key string without revealing it (used to learn gen-key's format)."""
    text = (encoded or "").strip()
    if "BEGIN RSA PUBLIC KEY" in text:
        return "pem-pkcs1"
    if "BEGIN PUBLIC KEY" in text:
        return "pem-spki"
    try:
        der = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        return "unknown"
    # Both DER forms are an outer SEQUENCE; SPKI nests an AlgorithmIdentifier SEQUENCE,
    # PKCS#1 RSAPublicKey starts directly with the modulus INTEGER.
    if len(der) < 4 or der[0] != 0x30:
        return "unknown"
    length_byte = der[1]
    inner = 2 + (length_byte & 0x7F if length_byte & 0x80 else 0)
    if inner >= len(der):
        return "unknown"
    kind = {0x30: "spki", 0x02: "pkcs1"}.get(der[inner], "unknown")
    try:
        if kind == "spki":
            serialization.load_der_public_key(der)
        elif kind == "pkcs1":
            pem = b"-----BEGIN RSA PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END RSA PUBLIC KEY-----\n"
            serialization.load_pem_public_key(pem)
    except ValueError:
        return "unknown"
    return kind


@dataclass(frozen=True)
class LocalKeyPair:
    public_key: str
    private_key: str  # base64 PKCS#1 DER, the format every reference bridge accepts


def generate_local_keypair(fmt: PublicKeyFormat = "pkcs1") -> LocalKeyPair:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_der = key.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.TraditionalOpenSSL, serialization.NoEncryption()
    )
    return LocalKeyPair(public_key=encode_public_key(key.public_key(), fmt), private_key=base64.b64encode(private_der).decode())
