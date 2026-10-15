import os
import struct

import pytest
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from plaudio.cipher import SessionCipher, SessionCipherError
from plaudio.protocol import build_handshake


def fixture(marker=b"PLAUD.AI"):
    key, nonce, ad = os.urandom(32), os.urandom(12), os.urandom(12)
    aead = ChaCha20Poly1305(key)
    seal = lambda plain: aead.encrypt(nonce, plain, ad)  # noqa: E731
    return key, nonce, ad, seal, bytearray(key + nonce + ad + seal(marker))


def test_cryptokit_reference_vector():
    material = bytes([7]) * 32 + bytes([3]) * 12 + bytes([5]) * 12 + bytes.fromhex(
        "bbea0c32d2ba19b0fc2584562a17f81b2978a3b15c8bf8e4"
    )
    session = SessionCipher(material)
    assert session.decrypt(bytes.fromhex("eaa64d67978e5840f3cd7315f9c4762025d028e0833515")).hex() == "011a00"


def test_verification_marker_required():
    *_, material = fixture()
    SessionCipher(bytes(material))
    with pytest.raises(SessionCipherError, match="verification"):
        SessionCipher(bytes(fixture(b"WRONG.AI")[4]))
    material[79] ^= 1
    with pytest.raises(SessionCipherError, match="verification"):
        SessionCipher(bytes(material))
    with pytest.raises(SessionCipherError, match="length"):
        SessionCipher(bytes(56))


def test_send_counter_starts_at_two_inside_ciphertext():
    key, nonce, ad, _, material = fixture()
    session = SessionCipher(bytes(material))
    packet = bytes(build_handshake("test-token", 20))
    for expected in (2, 3):
        plain = ChaCha20Poly1305(key).decrypt(nonce, session.encrypt(packet), ad)
        assert struct.unpack_from("<I", plain)[0] == expected
        assert plain[4:] == packet


def test_receive_rejects_tamper_and_replay():
    key, nonce, ad, seal, material = fixture()
    session = SessionCipher(bytes(material))
    packet = seal(bytes.fromhex("01000000011a00"))
    corrupted = bytearray(packet)
    corrupted[0] ^= 1
    with pytest.raises(SessionCipherError):
        session.decrypt(bytes(corrupted))
    assert session.decrypt(packet).hex() == "011a00"
    with pytest.raises(SessionCipherError, match="Replayed"):
        session.decrypt(packet)
    with pytest.raises(SessionCipherError, match="Truncated"):
        session.decrypt(seal(bytes(4)))
    session.destroy()
    with pytest.raises(SessionCipherError):
        session.encrypt(bytes([1, 1, 0]))
    with pytest.raises(SessionCipherError):
        session.decrypt(packet)


def test_roundtrip_against_simulated_device():
    key, nonce, ad, seal, material = fixture()
    host = SessionCipher(bytes(material))
    device = ChaCha20Poly1305(key)
    for counter, body in enumerate([b"\x01\x1a\x00abc", b"\x02" + bytes(20)], start=5):
        assert host.decrypt(seal(struct.pack("<I", counter) + body)) == body
    out = device.decrypt(nonce, host.encrypt(b"\x01\x1c\x00xyz"), ad)
    assert out[4:] == b"\x01\x1c\x00xyz"
