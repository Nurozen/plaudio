import os
import shutil
import struct
import subprocess

import pytest
from cryptography.hazmat.primitives.asymmetric import padding

from plaudio import audio, keys


def ogg_page(flags=6, sequence=0, channels=1, serial=3):
    page = bytearray(47)
    page[0:4] = b"OggS"
    page[5] = flags
    struct.pack_into("<II", page, 14, serial, sequence)
    page[26] = 1
    page[27] = 19
    page[28:36] = b"OpusHead"
    page[36] = 1
    page[37] = channels
    struct.pack_into("<I", page, 22, audio.ogg_crc(page))
    return bytes(page)


def plaud_header(nonce, wrapped_key=bytes(256), channels=1):
    header = bytearray(512)
    header[0:8] = b"PLAUD.AI"
    struct.pack_into("<HH", header, 8, 1, 512)
    struct.pack_into("<HHH", header, 48, 1, channels, 1)
    header[132:144] = nonce
    header[256:512] = wrapped_key
    return bytes(header)


def test_ogg_crc_and_integrity():
    assert audio.ogg_crc(b"123456789") == 0x89A1897F
    valid = ogg_page()
    assert audio.validate_ogg(valid, 1).pages == 1
    with pytest.raises(audio.AudioError, match="channel"):
        audio.validate_ogg(valid, 2)
    with pytest.raises(audio.AudioError, match="Incomplete"):
        audio.validate_ogg(valid[:-1], 1)
    with pytest.raises(audio.AudioError, match="Incomplete"):
        audio.validate_ogg(ogg_page(2), 1)
    with pytest.raises(audio.AudioError, match="Discontinuous"):
        audio.validate_ogg(ogg_page(6, 2), 1)
    with pytest.raises(audio.AudioError, match="Discontinuous"):
        audio.validate_ogg(valid + valid, 1)
    broken = bytearray(valid)
    broken[46] ^= 1
    with pytest.raises(audio.AudioError, match="checksum"):
        audio.validate_ogg(bytes(broken), 1)


def test_reference_style_unwrap_with_injected_key():
    key, nonce = bytes([3]) * 32, bytes([5]) * 12
    data = bytearray(plaud_header(nonce) + audio.chacha20_xor(key, nonce, ogg_page()))
    assert audio.parse_header(data).channels == 1
    assert audio.decrypt_plaud(bytes(data), lambda _: key).integrity.pages == 1
    with pytest.raises(audio.AudioError, match="key"):
        audio.decrypt_plaud(bytes(data), lambda _: bytes(31))
    with pytest.raises(audio.AudioError):
        audio.decrypt_plaud(bytes(data), lambda _: bytes([4]) * 32)
    data[52] = 2
    with pytest.raises(audio.AudioError, match="Unsupported"):
        audio.parse_header(bytes(data))


def test_chacha20_matches_rfc8439_vector():
    # RFC 8439 section 2.4.2 (counter = 1)
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    plain = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, "
        b"sunscreen would be it."
    )
    assert audio.chacha20_xor(key, nonce, plain, counter=1)[:16].hex() == "6e2e359a2568f98041ba0728dd0d6981"


def synthetic_plaud_file(public_key, channels=1):
    """Build a .plaud exactly as the device would: random file key RSA-wrapped to our key."""
    file_key, nonce = os.urandom(32), os.urandom(12)
    wrapped = public_key.encrypt(file_key, padding.PKCS1v15())
    ogg = ogg_page(channels=channels)
    return plaud_header(nonce, wrapped, channels) + audio.chacha20_xor(file_key, nonce, ogg), ogg


def test_rsa_wrapped_file_decrypts_with_our_identity():
    pair = keys.generate_local_keypair()
    private = keys.load_private_key(pair.private_key)
    data, ogg = synthetic_plaud_file(private.public_key(), channels=2)
    decoded = audio.decrypt_plaud(data, lambda block: keys.rsa_unwrap(pair.private_key, block))
    assert decoded.ogg == ogg and decoded.integrity.channels == 2
    other = keys.generate_local_keypair()
    # OpenSSL's PKCS#1 v1.5 implicit rejection may return random bytes instead of raising,
    # so a wrong key surfaces as either an unwrap error or a key-length / Ogg failure.
    with pytest.raises((keys.RSAKeyError, audio.AudioError)):
        audio.decrypt_plaud(data, lambda block: keys.rsa_unwrap(other.private_key, block))


@pytest.mark.skipif(not (shutil.which("ffmpeg") or os.path.exists("/opt/homebrew/bin/ffmpeg")), reason="ffmpeg missing")
def test_ogg_to_wav_16k_mono(tmp_path):
    ffmpeg = audio.find_ffmpeg()
    ogg_path = tmp_path / "tone.ogg"
    subprocess.run(
        [ffmpeg, "-v", "error", "-f", "lavfi", "-i", "sine=frequency=440:duration=0.5:sample_rate=48000",
         "-ac", "2", "-c:a", "libopus", str(ogg_path)],
        check=True,
    )
    wav = audio.ogg_to_wav(ogg_path, tmp_path / "tone.wav")
    header = wav.read_bytes()[:44]
    assert header[:4] == b"RIFF" and header[8:12] == b"WAVE"
    channels, rate = struct.unpack_from("<HI", header, 22)
    assert (channels, rate) == (1, 16000)
