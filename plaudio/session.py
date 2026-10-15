"""Transport-agnostic protocol flows (ported from plaud-connection.ts / plaud-transfer.ts).

Everything here talks to a `PacketLink` (write one packet / read one notification), so the
flows are unit-testable with a fake device and reusable over any BLE stack.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import time
from pathlib import Path
from typing import Awaitable, Callable, Protocol

from . import protocol as p
from .cipher import SessionCipher
from .keys import rsa_unwrap

log = logging.getLogger("plaudio")

PRE_HANDSHAKE_TIMEOUT = 30.0
HANDSHAKE_TIMEOUT = 15.0
LIST_TIMEOUT = 15.0
DOWNLOAD_TIMEOUT = 15 * 60.0
PACKET_TIMEOUT = 15.0
CHECKPOINT_EVERY = 64 * 1024


class PacketLink(Protocol):
    async def write(self, packet: bytes) -> None: ...
    async def packet(self, timeout: float) -> bytes: ...


class SessionError(RuntimeError):
    pass


def _remaining(deadline: float, cap: float | None = None) -> float:
    left = deadline - time.monotonic()
    if left <= 0:
        raise TimeoutError("Plaud response timeout")
    return min(left, cap) if cap else left


# Commands believed to be destructive or irreversible (see "Never send" in docs/protocol.md):
# unbind, password reset, delete one/all recordings, firmware update, factory reset, and
# opcodes that end the connection. Never sent by plaudio.
BLOCKED_COMMANDS = frozenset({5, 7, 12, 13, 30, 50, 51, 52, 102, 103, 104, 105, 109, 121, 125, 128, 151})


class BlockedCommand(RuntimeError):
    pass


def check_outgoing(packet: bytes) -> None:
    if len(packet) < 3 or packet[0] != 1:
        raise BlockedCommand(f"refusing to send non-command frame type {packet[:1].hex() or 'empty'}")
    cmd = int.from_bytes(packet[1:3], "little")
    if cmd in BLOCKED_COMMANDS:
        raise BlockedCommand(f"refusing to send blocked command {cmd}")


class EncryptedLink:
    """Wraps a raw link with the session cipher once the key exchange has completed."""

    def __init__(self, raw: PacketLink, cipher: SessionCipher) -> None:
        self.raw = raw
        self.cipher = cipher

    async def write(self, packet: bytes) -> None:
        check_outgoing(packet)
        await self.raw.write(self.cipher.encrypt(packet))

    async def packet(self, timeout: float) -> bytes:
        return self.cipher.decrypt(await self.raw.packet(timeout))

    def close(self) -> None:
        self.cipher.destroy()


async def establish_encryption(
    raw: PacketLink,
    signature_b64: str,
    public_key: str,
    unwrap: Callable[[bytes], bytes],
    progress: Callable[[str], None] = lambda _stage: None,
) -> EncryptedLink:
    """FE10 (signature) -> FE11 (accepted) -> FE12 (our public key) -> FE12 (wrapped material)."""
    progress("sending_signed_identity")
    for chunk in p.build_prehandshake_chunks(p.Cmd.SIGNATURE, base64.b64decode(signature_b64)):
        await raw.write(chunk)
    collector = p.KeyChunks()
    encrypted: bytes | None = None
    public_key_sent = False
    deadline = time.monotonic() + PRE_HANDSHAKE_TIMEOUT
    while encrypted is None:
        packet = await raw.packet(_remaining(deadline, 10.0))
        if len(packet) < 2:
            raise SessionError("Truncated pre-handshake response")
        opcode = int.from_bytes(packet[:2], "little")
        if opcode == p.Cmd.SIGNATURE_ACCEPTED and not public_key_sent:
            progress("identity_accepted_sending_public_key")
            for chunk in p.build_prehandshake_chunks(p.Cmd.PUBLIC_KEY, public_key.encode("utf-8")):
                await raw.write(chunk)
            public_key_sent = True
        elif opcode == p.Cmd.PUBLIC_KEY:
            encrypted = collector.add(packet)
        else:
            raise SessionError(f"Unexpected pre-handshake response (opcode 0x{opcode:04x}, {len(packet)} bytes)")
    material = unwrap(encrypted)
    cipher = SessionCipher(material)
    del material
    progress("encrypted_session_verified")
    return EncryptedLink(raw, cipher)


def describe_handshake_reply(reply: bytes) -> str:
    """Verbatim hex plus the fields we think we understand (status byte [3] for opcode 1)."""
    opcode = int.from_bytes(reply[1:3], "little") if len(reply) >= 3 else None
    status = reply[3] if opcode == p.Cmd.HANDSHAKE and len(reply) > 3 else None
    detail = f"opcode={opcode}" + (f" status={status}" if status is not None else "")
    return f"handshake reply raw={reply.hex()} ({detail}, {len(reply)} bytes)"


async def recording_handshake(
    link: PacketLink,
    binding_token: str,
    protocol_version: int = 20,
    on_reply: Callable[[str], None] = lambda _line: None,
) -> p.HandshakeResult:
    """Send cmd 1 with the binding token. On a factory-fresh device this BINDS it to the token.

    A rejection status raises HandshakeRejected and is never retried here. The only resend
    is the reference's one-time "second mode" request after an opcode-2 serial reply.
    """
    request = p.build_handshake(binding_token, protocol_version)
    state = p.HandshakeState(request)
    await link.write(bytes(request))
    deadline = time.monotonic() + HANDSHAKE_TIMEOUT
    while True:
        reply = await link.packet(_remaining(deadline))
        on_reply(describe_handshake_reply(reply))
        outcome = state.feed(reply)
        if isinstance(outcome, p.HandshakeResult):
            return outcome
        if outcome is not None:
            on_reply("sending second-mode handshake (byte 5 = 1) after serial reply")
            await link.write(outcome)


_request_sequence = int(time.time()) & 0xFFFFFFFF


def _next_request_id() -> int:
    global _request_sequence
    _request_sequence = (_request_sequence + 1) & 0xFFFFFFFF
    return _request_sequence


async def list_sessions(link: PacketLink, protocol_version: int = 20) -> list[p.SessionEntry]:
    request_id = _next_request_id()
    pages = p.SessionPages(request_id, protocol_version)
    await link.write(p.build_session_request(request_id, 0))
    deadline = time.monotonic() + LIST_TIMEOUT
    while True:
        packet = await link.packet(_remaining(deadline))
        if len(packet) < 3 or packet[0] != 1 or int.from_bytes(packet[1:3], "little") != p.Cmd.SESSIONS:
            continue  # unsolicited notification; never read it as an empty list
        sessions = pages.add(packet)
        if sessions is not None:
            return sessions


Checkpoint = Callable[[bytes], Awaitable[None] | None]


async def download_session(
    link: PacketLink,
    session: p.SessionEntry,
    prefix: bytes = b"",
    checkpoint: Checkpoint | None = None,
    progress: Callable[[int, int], None] | None = None,
) -> p.DownloadResult:
    download = p.Download(session, prefix)
    await link.write(p.build_download_request(session.session_id, len(prefix), session.size))
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT
    checkpointed = len(prefix)

    async def save() -> None:
        if checkpoint is not None:
            result = checkpoint(download.downloaded)
            if asyncio.iscoroutine(result):
                await result

    try:
        while True:
            result = download.add(await link.packet(_remaining(deadline, PACKET_TIMEOUT)))
            if progress:
                progress(download.offset, session.size)
            if download.offset - checkpointed >= CHECKPOINT_EVERY:
                await save()
                checkpointed = download.offset
            if result is not None:
                return result
    finally:
        if download.offset:
            await save()


class PartFile:
    """Append-only, fsynced resume buffer holding a contiguous prefix of one recording."""

    def __init__(self, path: Path, size: int) -> None:
        self.path = path
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        existing = path.read_bytes() if path.exists() else b""
        # Keep at most size-1 bytes so the device always sends a fresh completion tail.
        self.prefix = existing[: max(0, min(len(existing), size - 1))]
        fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        self.handle = os.fdopen(fd, "r+b")
        self.handle.truncate(len(self.prefix))
        self.handle.seek(len(self.prefix))
        self.written = len(self.prefix)

    def save(self, data: bytes) -> None:
        if len(data) > self.written:
            self.handle.write(data[self.written :])
            self.handle.flush()
            os.fsync(self.handle.fileno())
            self.written = len(data)

    def close(self) -> None:
        self.handle.close()


def local_unwrap(private_key: str) -> Callable[[bytes], bytes]:
    return lambda ciphertext: rsa_unwrap(private_key, ciphertext)
