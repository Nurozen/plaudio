"""Post-key-exchange session cipher (ported from plaud-session-cipher.ts).

The device sends 80 bytes of RSA-wrapped material:
    key[0:32] | nonce[32:44] | associated_data[44:56] | ChaCha20-Poly1305("PLAUD.AI")[56:80]

Every packet in both directions is ChaCha20-Poly1305 under that same key, nonce and AD
(the device defines it that way; the nonce is not per-packet). Inside the plaintext a
4-byte little-endian counter precedes the command:
    * host -> device: counter starts at 2 and increments per packet
    * device -> host: counter must strictly increase (replay guard)
"""

from __future__ import annotations

import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

MATERIAL_LENGTH = 80
VERIFY_MARKER = b"PLAUD.AI"
TAG_LENGTH = 16


class SessionCipherError(ValueError):
    pass


class SessionCipher:
    def __init__(self, material: bytes) -> None:
        if len(material) != MATERIAL_LENGTH:
            raise SessionCipherError(f"Invalid Plaud session material length ({len(material)})")
        self._nonce = bytes(material[32:44])
        self._ad = bytes(material[44:56])
        self._aead: ChaCha20Poly1305 | None = ChaCha20Poly1305(bytes(material[0:32]))
        self._send_counter = 1
        self._receive_counter = -1
        try:
            if self._open(bytes(material[56:])) != VERIFY_MARKER:
                raise SessionCipherError("Invalid device key verification marker")
        except Exception:
            self.destroy()
            raise SessionCipherError("Plaud key-exchange verification failed") from None

    @property
    def closed(self) -> bool:
        return self._aead is None

    def _open(self, ciphertext: bytes) -> bytes:
        if self._aead is None or len(ciphertext) < TAG_LENGTH:
            raise SessionCipherError("Invalid encrypted Plaud packet")
        try:
            return self._aead.decrypt(self._nonce, bytes(ciphertext), self._ad)
        except InvalidTag:
            raise SessionCipherError("Plaud packet failed authentication") from None

    def encrypt(self, packet: bytes) -> bytes:
        if self._aead is None or len(packet) < 3 or self._send_counter >= 0xFFFFFFFF:
            raise SessionCipherError("Plaud session unavailable")
        self._send_counter += 1
        plaintext = struct.pack("<I", self._send_counter) + bytes(packet)
        return self._aead.encrypt(self._nonce, plaintext, self._ad)

    def decrypt(self, packet: bytes) -> bytes:
        plaintext = self._open(packet)
        if len(plaintext) < 7:
            raise SessionCipherError("Truncated encrypted Plaud response")
        counter = struct.unpack_from("<I", plaintext, 0)[0]
        if counter <= self._receive_counter:
            raise SessionCipherError("Replayed or out-of-order Plaud response")
        self._receive_counter = counter
        return plaintext[4:]

    def destroy(self) -> None:
        # Python cannot reliably zero immutable bytes; dropping references is the best we can do.
        self._aead = None
        self._nonce = b""
        self._ad = b""
