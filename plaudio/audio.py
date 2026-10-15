"""Decode downloaded .plaud files (ported from plaud-audio.ts).

File layout (little endian):
    [0:8]     "PLAUD.AI"
    [8:10]    u16 version == 1
    [10:12]   u16 header size == 512
    [48:50]   u16 == 1        (codec? only 1 seen)
    [50:52]   u16 channels (1 or 2)
    [52:54]   u16 == 1        (cipher? only 1 seen)
    [128:132] u32 ChaCha20 block counter (must be 0)
    [132:144] 12-byte ChaCha20 nonce
    [256:512] RSA-2048 PKCS#1 v1.5 wrapped 32-byte file key
    [512:]    raw ChaCha20 (RFC 8439, no tag) of an Ogg Opus stream

Raw ChaCha20 is unauthenticated, so the result is accepted only if every Ogg page CRC,
per-stream sequence and end-of-stream flag checks out.
"""

from __future__ import annotations

import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

HEADER_SIZE = 512
MAGIC = b"PLAUD.AI"


class AudioError(ValueError):
    pass


@dataclass(frozen=True)
class AudioHeader:
    channels: int
    counter: int
    nonce: bytes
    encrypted_key: bytes


@dataclass(frozen=True)
class OggIntegrity:
    pages: int
    streams: int
    channels: int


def parse_header(data: bytes) -> AudioHeader:
    data = bytes(data[:HEADER_SIZE + 1])
    u16 = lambda o: struct.unpack_from("<H", data, o)[0]  # noqa: E731
    if (
        len(data) <= HEADER_SIZE
        or data[:8] != MAGIC
        or u16(8) != 1
        or u16(10) != HEADER_SIZE
        or u16(48) != 1
        or u16(52) != 1
    ):
        raise AudioError("Unsupported Plaud audio header")
    channels = u16(50)
    if channels not in (1, 2):
        raise AudioError("Unsupported Plaud audio channels")
    return AudioHeader(
        channels=channels,
        counter=struct.unpack_from("<I", data, 128)[0],
        nonce=data[132:144],
        encrypted_key=data[256:512],
    )


def _crc_table() -> list[int]:
    table = []
    for i in range(256):
        crc = i << 24
        for _ in range(8):
            crc = ((crc << 1) ^ 0x04C11DB7) if crc & 0x80000000 else (crc << 1)
        table.append(crc & 0xFFFFFFFF)
    return table


_CRC_TABLE = _crc_table()


def ogg_crc(data: bytes) -> int:
    """Ogg's CRC-32 (poly 0x04C11DB7, no reflection, init 0, no final xor)."""
    crc = 0
    table = _CRC_TABLE
    for byte in data:
        crc = ((crc << 8) & 0xFFFFFFFF) ^ table[(crc >> 24) ^ byte]
    return crc


def validate_ogg(data: bytes, expected_channels: int) -> OggIntegrity:
    data = bytes(data)
    streams: dict[int, tuple[int, bool]] = {}
    offset = pages = 0
    opus = False
    while offset < len(data):
        if offset + 27 > len(data) or data[offset : offset + 4] != b"OggS" or data[offset + 4] != 0:
            raise AudioError("Truncated or invalid Ogg page")
        segments = data[offset + 26]
        header_end = offset + 27 + segments
        if header_end > len(data):
            raise AudioError("Truncated Ogg segment table")
        length = sum(data[offset + 27 : header_end])
        end = header_end + length
        if end > len(data):
            raise AudioError("Incomplete Ogg payload")
        page = bytearray(data[offset:end])
        checksum = struct.unpack_from("<I", page, 22)[0]
        page[22:26] = b"\0\0\0\0"
        if ogg_crc(page) != checksum:
            raise AudioError("Ogg checksum mismatch")
        serial, sequence = struct.unpack_from("<II", page, 14)
        flags = page[5]
        previous = streams.get(serial)
        if (previous is None and (sequence != 0 or not flags & 2)) or (
            previous is not None and (previous[1] or sequence != previous[0] + 1 or flags & 2)
        ):
            raise AudioError("Discontinuous Ogg stream")
        streams[serial] = (sequence, bool(flags & 4))
        if previous is None and data[header_end : header_end + 8] == b"OpusHead":
            if length < 19 or data[header_end + 9] != expected_channels:
                raise AudioError("Opus channel mismatch")
            opus = True
        pages += 1
        offset = end
    if not opus or not streams or any(not ended for _, ended in streams.values()):
        raise AudioError("Incomplete Opus recording")
    return OggIntegrity(pages=pages, streams=len(streams), channels=expected_channels)


def chacha20_xor(key: bytes, nonce: bytes, data: bytes, counter: int = 0) -> bytes:
    """RFC 8439 ChaCha20 keystream XOR (cryptography wants a 16-byte counter||nonce)."""
    if len(key) != 32 or len(nonce) != 12:
        raise AudioError("Invalid ChaCha20 key or nonce")
    full_nonce = struct.pack("<I", counter) + bytes(nonce)
    encryptor = Cipher(algorithms.ChaCha20(bytes(key), full_nonce), mode=None).encryptor()
    return encryptor.update(bytes(data)) + encryptor.finalize()


@dataclass(frozen=True)
class DecodedAudio:
    ogg: bytes
    integrity: OggIntegrity


def decrypt_plaud(data: bytes, unwrap: Callable[[bytes], bytes]) -> DecodedAudio:
    """Decrypt a .plaud file to Ogg Opus. `unwrap` RSA-decrypts the 256-byte key block."""
    header = parse_header(data)
    key = unwrap(header.encrypted_key)
    if len(key) != 32:
        raise AudioError("Plaud audio key does not match the authorized identity")
    if header.counter != 0:
        raise AudioError("Unsupported Plaud audio counter")
    ogg = chacha20_xor(key, header.nonce, bytes(data[HEADER_SIZE:]))
    return DecodedAudio(ogg=ogg, integrity=validate_ogg(ogg, header.channels))


def find_ffmpeg() -> str:
    path = shutil.which("ffmpeg") or ("/opt/homebrew/bin/ffmpeg" if Path("/opt/homebrew/bin/ffmpeg").exists() else None)
    if not path:
        raise AudioError("ffmpeg not found (brew install ffmpeg)")
    return path


def ogg_to_wav(ogg_path: Path, wav_path: Path, sample_rate: int = 16000) -> Path:
    """Transcode to 16 kHz mono PCM WAV. Maps only the first audio stream: Plaud files
    carry an extra non-audio Ogg stream that some demuxers choke on."""
    cmd = [
        find_ffmpeg(), "-v", "error", "-y", "-i", str(ogg_path),
        "-map", "0:a:0", "-ac", "1", "-ar", str(sample_rate), "-c:a", "pcm_s16le", str(wav_path),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
    if result.returncode != 0:
        raise AudioError(f"ffmpeg failed: {result.stderr.strip()[:500]}")
    return wav_path
