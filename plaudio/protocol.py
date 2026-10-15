"""Plaud Note Pro BLE framing.

Pure functions and small state machines only: nothing here touches Bluetooth.
Ported from the openplod reference (src/sync/plaud-protocol.ts, plaud-transfer.ts).

Packet shapes (all integers little endian):

* Command:        01 | u16 opcode | payload
* Pre-handshake:  u16 opcode | u8 total | u8 index | <=100 payload bytes   (0xFE10 / 0xFE12)
* Data packet:    02 | u32 session | u32 position | u8 length | bytes
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from enum import IntEnum

SERVICE_UUID = "00001910-0000-1000-8000-00805f9b34fb"
NOTIFY_UUID = "00002bb0-0000-1000-8000-00805f9b34fb"
WRITE_UUID = "00002bb1-0000-1000-8000-00805f9b34fb"
COMPANY_ID = 0x005D
SUPPORTED_PROJECTS = (881, 883)

PREHANDSHAKE_CHUNK = 100
MAX_DOWNLOAD_BYTES = 64 * 1024 * 1024
_ASCII_TOKEN = re.compile(r"^[\x21-\x7e]+$")


class Cmd(IntEnum):
    HANDSHAKE = 1
    HANDSHAKE_SERIAL = 2  # device -> host only
    GET_STATE = 3
    TIME_SYNC = 4
    BATTERY = 9
    RECORD_START = 20
    RECORD_PAUSE = 21  # device -> host notification only (we never pause)
    RECORD_RESUME = 22  # device -> host notification only
    RECORD_STOP = 23
    SESSIONS = 26
    DOWNLOAD = 28
    TAIL = 29  # device -> host: transfer tail. host -> device (empty): stop sync
    SYNC_STOP_ACK = 30  # device -> host only. Host-sent 30 is DELETE, never send it.
    SIGNATURE = 0xFE10
    SIGNATURE_ACCEPTED = 0xFE11  # device -> host only
    PUBLIC_KEY = 0xFE12


# The only framed commands this toolkit will ever build for the device.
_SENDABLE_COMMANDS = {
    Cmd.HANDSHAKE, Cmd.GET_STATE, Cmd.TIME_SYNC, Cmd.BATTERY,
    Cmd.RECORD_START, Cmd.RECORD_STOP, Cmd.SESSIONS, Cmd.DOWNLOAD, Cmd.TAIL,
}
_SENDABLE_PREHANDSHAKE = {Cmd.SIGNATURE, Cmd.PUBLIC_KEY}


class ProtocolError(ValueError):
    pass


def _u16(data: bytes, offset: int) -> int:
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    return struct.unpack_from("<I", data, offset)[0]


def _pack_u32(value: int) -> bytes:
    if not isinstance(value, int) or not 0 <= value <= 0xFFFFFFFF:
        raise ProtocolError("Invalid unsigned integer")
    return struct.pack("<I", value)


# --------------------------------------------------------------------------- advertisement


@dataclass(frozen=True)
class Advertisement:
    project: int
    serial: str
    protocol_version: int

    @property
    def encrypted(self) -> bool:
        return self.protocol_version >= 20


def parse_advertisement(data: bytes) -> Advertisement:
    """Parse Note Pro manufacturer data.

    Accepts either bleak's payload (company id already stripped) or the reference's
    framed form that keeps the 2-byte company id (5d 00) in front.
    """
    data = bytes(data)
    if not (len(data) >= 2 and data[:2] == COMPANY_ID.to_bytes(2, "little") and len(data) >= 3 and data[2] == 2):
        data = COMPANY_ID.to_bytes(2, "little") + data
    if len(data) < 22 or data[2] != 2 or data[5] != 4 or data[10] != 8:
        raise ProtocolError("Unsupported or truncated Note Pro advertisement")
    project = _u16(data, 3)
    if project not in SUPPORTED_PROJECTS:
        raise ProtocolError("Not a supported Note Pro project")
    return Advertisement(project=project, serial=data[11:19].hex().upper(), protocol_version=_u16(data, 20))


# --------------------------------------------------------------------------- commands


def build_command(opcode: int, payload: bytes = b"") -> bytes:
    if opcode not in _SENDABLE_COMMANDS:
        raise ProtocolError(f"Refusing to build undocumented command {opcode}")
    return bytes([1]) + struct.pack("<H", opcode) + bytes(payload)


def sdk_handshake_token(sub: str) -> str:
    """Binding token derived from the user token's `sub` claim.

    Drop a `client_user_` prefix and remove every '-'; build_handshake then truncates or
    pads to the 32-character field. This matches the token derivation the official SDK
    uses on the wire (observed binding behaviour: a fresh recorder bound with this token
    and accepted it again on reconnect).
    """
    return sub.removeprefix("client_user_").replace("-", "")


def build_handshake(binding_token: str, protocol_version: int) -> bytearray:
    """Recording handshake (cmd 1). Returned mutable: the second-mode retry flips byte 5.

    Token is truncated/padded with ASCII '0' to 32 chars (16 below protocol 9), matching
    the OpenPlod reference and the observed wire format.
    """
    if not isinstance(binding_token, str) or not _ASCII_TOKEN.match(binding_token):
        raise ProtocolError("A nonempty ASCII device binding token is required")
    if not isinstance(protocol_version, int) or protocol_version < 1:
        raise ProtocolError("Invalid protocol version")
    length = 32 if protocol_version >= 9 else 16
    token = binding_token[:length].ljust(length, "0").encode("ascii")
    # The optional third option byte is a mode flag (0, then 1 on retry), not a firmware version.
    options = bytes([2, 0, 0]) if protocol_version >= 3 else bytes([2, 0])
    return bytearray(build_command(Cmd.HANDSHAKE, options + token))


def build_session_request(request_id: int, cursor: int = 0, ascending: bool = False) -> bytes:
    return build_command(Cmd.SESSIONS, _pack_u32(request_id) + _pack_u32(cursor) + bytes([1 if ascending else 0]))


def build_download_request(session_id: int, offset: int, end: int) -> bytes:
    if offset >= end:
        raise ProtocolError("Download range must be nonempty")
    return build_command(Cmd.DOWNLOAD, _pack_u32(session_id) + _pack_u32(offset) + _pack_u32(end))


def build_prehandshake_chunks(opcode: int, payload: bytes) -> list[bytes]:
    """Split a pre-handshake payload into unencrypted 100-byte chunks (no 01 prefix)."""
    if opcode not in _SENDABLE_PREHANDSHAKE:
        raise ProtocolError("Unsupported pre-handshake command")
    payload = bytes(payload)
    total = -(-len(payload) // PREHANDSHAKE_CHUNK)
    if not 1 <= total <= 255:
        raise ProtocolError("Invalid pre-handshake payload size")
    return [
        struct.pack("<HBB", opcode, total, i) + payload[i * PREHANDSHAKE_CHUNK : (i + 1) * PREHANDSHAKE_CHUNK]
        for i in range(total)
    ]


class KeyChunks:
    """Reassemble the device's 0xFE12 reply: a 256-byte RSA-2048 ciphertext in <=3 chunks."""

    def __init__(self) -> None:
        self.total: int | None = None
        self.chunks: dict[int, bytes] = {}

    def add(self, packet: bytes) -> bytes | None:
        packet = bytes(packet)
        if not 5 <= len(packet) <= 104 or _u16(packet, 0) != Cmd.PUBLIC_KEY:
            raise ProtocolError("Invalid key-exchange packet")
        total, index = packet[2], packet[3]
        if total == 0 or total > 3 or index >= total or (self.total is not None and total != self.total):
            raise ProtocolError("Inconsistent RSA-2048 key-exchange chunks")
        payload = packet[4:]
        if index in self.chunks and self.chunks[index] != payload:
            raise ProtocolError("Conflicting key chunk")
        self.total = total
        self.chunks[index] = payload
        if len(self.chunks) != total:
            return None
        result = b"".join(self.chunks[i] for i in range(total))
        if len(result) != 256:
            raise ProtocolError("Invalid RSA-2048 ciphertext size")
        return result


# --------------------------------------------------------------------------- handshake reply


@dataclass(frozen=True)
class HandshakeResult:
    protocol: int
    channels: int
    raw: bytes = b""


class HandshakeRejected(ProtocolError):
    """The device answered the handshake with a nonzero status. Never retry automatically."""


class HandshakeState:
    """Interpret recording-handshake replies.

    feed() returns a packet to (re)send, a HandshakeResult when done, or None to keep reading.
    Reply layout as interpreted by the reference (only partly understood):
      opcode 2: serial info (>= 59 bytes) -> resend the request with mode byte [5] = 1, once
      opcode 1: [3] status (0 = ok), [4:6] u16 protocol (must be 20), [8] channels, [11] must be 1
    """

    def __init__(self, request: bytearray) -> None:
        self.request = bytearray(request)
        self.second_sent = False

    def feed(self, reply: bytes) -> bytes | HandshakeResult | None:
        reply = bytes(reply)
        if len(reply) < 3 or reply[0] != 1:
            raise ProtocolError("Malformed recording handshake")
        opcode = _u16(reply, 1)
        if opcode == Cmd.HANDSHAKE_SERIAL and not self.second_sent:
            if len(reply) < 59:
                raise ProtocolError("Truncated serial handshake")
            if len(self.request) < 6 + 16:
                raise ProtocolError("Second handshake mode needs protocol >= 3")
            self.second_sent = True
            self.request[5] = 1
            return bytes(self.request)
        if opcode == Cmd.HANDSHAKE:
            status = reply[3] if len(reply) > 3 else None
            if len(reply) < 12 or status != 0:
                raise HandshakeRejected(
                    f"Plaud recording access rejected (status {status if status is not None else 'unknown'}, "
                    f"raw reply {reply.hex()})"
                )
            if _u16(reply, 4) != 20 or reply[11] != 1 or reply[8] not in (1, 2):
                raise ProtocolError(f"Unsupported negotiated Plaud audio protocol (raw reply {reply.hex()})")
            return HandshakeResult(protocol=_u16(reply, 4), channels=reply[8], raw=reply)
        return None


# --------------------------------------------------------------------------- session list


@dataclass(frozen=True)
class SessionEntry:
    session_id: int
    size: int
    scene: int = 0
    timezone: int = 0


@dataclass(frozen=True)
class SessionPage:
    request_id: int
    total: int
    offset: int
    entries: list[SessionEntry]


def session_stride(protocol_version: int) -> int:
    if not isinstance(protocol_version, int) or protocol_version < 1:
        raise ProtocolError("Invalid protocol version")
    return 8 if protocol_version == 1 else 9 if protocol_version < 7 else 10


def parse_session_page(packet: bytes, protocol_version: int) -> SessionPage:
    """01 1a 00 | u32 request | u16 total | u16 offset | entries (stride 8/9/10)."""
    packet = bytes(packet)
    if len(packet) < 11 or packet[0] != 1 or _u16(packet, 1) != Cmd.SESSIONS:
        raise ProtocolError("Invalid recording-list response")
    stride = session_stride(protocol_version)
    total, offset = _u16(packet, 7), _u16(packet, 9)
    body = len(packet) - 11
    if body % stride or offset + body // stride > total:
        raise ProtocolError("Truncated or inconsistent recording-list page")
    entries = []
    for start in range(11, len(packet), stride):
        entries.append(
            SessionEntry(
                session_id=_u32(packet, start),
                size=_u32(packet, start + 4),
                scene=0 if stride == 8 else packet[start + stride - 1],
                timezone=packet[start + 8] if stride == 10 else 0,
            )
        )
    return SessionPage(request_id=_u32(packet, 3), total=total, offset=offset, entries=entries)


class SessionPages:
    """Collect possibly repeated / out-of-order list pages into one consistent snapshot."""

    def __init__(self, request_id: int, protocol_version: int) -> None:
        self.request_id = request_id
        self.protocol_version = protocol_version
        self.total: int | None = None
        self.entries: dict[int, SessionEntry] = {}

    def add(self, packet: bytes) -> list[SessionEntry] | None:
        page = parse_session_page(packet, self.protocol_version)
        if page.request_id != self.request_id:
            raise ProtocolError("Recording list request mismatch")
        if self.total is not None and self.total != page.total:
            raise ProtocolError("Recording list changed during pagination")
        self.total = page.total
        for i, entry in enumerate(page.entries):
            position = page.offset + i
            previous = self.entries.get(position)
            if previous is not None and previous != entry:
                raise ProtocolError("Conflicting recording list page")
            self.entries[position] = entry
        if len(self.entries) != page.total:
            return None
        result = [self.entries[i] for i in range(page.total)]
        if len({e.session_id for e in result}) != len(result):
            raise ProtocolError("Duplicate session IDs")
        return result


# --------------------------------------------------------------------------- download


@dataclass(frozen=True)
class DownloadResult:
    data: bytes
    tail_crc: int  # reported by the device; its algorithm is unknown, so it is not validated


class Download:
    """Assemble a recording from decrypted transfer packets.

    Expects: head (01 1c00 | u32 session | u8 status=0), contiguous data packets, then
    tail (01 1d00 | u32 session | u16 crc). A data packet with position 0xFFFFFFFF is a
    device-side stop marker: [10] == 1 is benign (ignored), anything else aborts.
    """

    def __init__(self, session: SessionEntry, prefix: bytes = b"") -> None:
        if not 0 < session.size <= MAX_DOWNLOAD_BYTES:
            raise ProtocolError("Recording exceeds the 64 MiB Bluetooth transfer limit")
        if len(prefix) >= session.size:
            raise ProtocolError("Resume prefix must leave a nonempty download range")
        self.session = session
        self.buffer = bytearray(session.size)
        self.buffer[: len(prefix)] = prefix
        self.offset = len(prefix)
        self.head = False
        self.completed = False

    @property
    def downloaded(self) -> bytes:
        return bytes(self.buffer[: self.offset])

    def add(self, packet: bytes) -> DownloadResult | None:
        if self.completed:
            raise ProtocolError("Download already completed")
        packet = bytes(packet)
        if len(packet) >= 3 and packet[0] == 1:
            opcode = _u16(packet, 1)
            if opcode not in (Cmd.DOWNLOAD, Cmd.TAIL):
                return None  # unrelated notification
            minimum = 8 if opcode == Cmd.DOWNLOAD else 9
            if len(packet) < minimum or _u32(packet, 3) != self.session.session_id:
                raise ProtocolError("Download session mismatch or truncated control packet")
            if opcode == Cmd.DOWNLOAD:
                if self.head or packet[7] != 0:
                    raise ProtocolError("Recording download rejected")
                self.head = True
                return None
            if not self.head or self.offset != self.session.size:
                raise ProtocolError("Incomplete recording transfer")
            self.completed = True
            return DownloadResult(data=bytes(self.buffer), tail_crc=_u16(packet, 7))
        if packet and packet[0] == 2:
            if not self.head or len(packet) < 10 or _u32(packet, 1) != self.session.session_id:
                raise ProtocolError("Invalid recording data packet")
            position, length = _u32(packet, 5), packet[9]
            if position == 0xFFFFFFFF:
                if len(packet) < 11 or packet[10] != 1:
                    raise ProtocolError("Device stopped the recording transfer")
                return None
            if (
                position != self.offset
                or length == 0
                or len(packet) != length + 10
                or position + length > self.session.size
            ):
                raise ProtocolError("Noncontiguous or malformed recording data")
            self.buffer[position : position + length] = packet[10:]
            self.offset += length
        return None


# --------------------------------------------------------------------------- live recording
# Layouts observed on a Note Pro (protocol 20), see docs/protocol.md.

SCENE_NORMAL = 1
LIVE_STATUS_OFFSET = 0xFFFFFFFF  # data frame carrying a status code instead of audio


def command_id(packet: bytes) -> int | None:
    return _u16(packet, 1) if len(packet) >= 3 and packet[0] == 1 else None


def build_time_sync(unix_seconds: int, tz_minutes_east: int) -> bytes:
    hours, minutes = divmod(abs(tz_minutes_east), 60)
    sign = -1 if tz_minutes_east < 0 else 1
    return build_command(Cmd.TIME_SYNC, _pack_u32(unix_seconds) + struct.pack("<bb", sign * hours, sign * minutes))


def build_record_start(scene: int = SCENE_NORMAL) -> bytes:
    return build_command(Cmd.RECORD_START, bytes([1, scene]))


def build_record_stop(scene: int = SCENE_NORMAL) -> bytes:
    return build_command(Cmd.RECORD_STOP, bytes([1, scene]))


def build_live_sync(session_id: int, start: int) -> bytes:
    """cmd 28 with end = 0: open-ended sync that follows a recording in progress."""
    return build_command(Cmd.DOWNLOAD, _pack_u32(session_id) + _pack_u32(start) + _pack_u32(0))


def build_sync_stop() -> bytes:
    return build_command(Cmd.TAIL)


@dataclass(frozen=True)
class RecordEvent:
    cmd: int
    session_id: int
    start: int = 0  # start/resume only: file offset to begin live sync from
    status: int = 0  # start/resume: 0 ok, 4 already recording. stop: reason
    file_size: int | None = None  # stop only, when the device includes it


def parse_record_event(packet: bytes) -> RecordEvent | None:
    cmd = command_id(packet)
    if cmd not in (Cmd.RECORD_START, Cmd.RECORD_PAUSE, Cmd.RECORD_RESUME, Cmd.RECORD_STOP) or len(packet) < 7:
        return None
    session_id = _u32(packet, 3)
    if cmd in (Cmd.RECORD_START, Cmd.RECORD_RESUME) and len(packet) >= 12:
        return RecordEvent(cmd, session_id, start=_u32(packet, 7), status=packet[11])
    file_size = _u32(packet, 9) if cmd == Cmd.RECORD_STOP and len(packet) >= 13 and packet[8] == 1 else None
    return RecordEvent(cmd, session_id, status=packet[7] if len(packet) > 7 else 0, file_size=file_size)


@dataclass(frozen=True)
class DeviceState:
    raw_state: int
    key_state: int
    session_id: int

    @property
    def recording(self) -> bool:
        return self.raw_state == 0x1003

    @property
    def name(self) -> str:
        if self.recording:
            return "recording"
        return {0: "idle", 1: "record", 2: "transfer", 3: "switch_on", 4: "switch_off"}.get(self.key_state, f"unknown({self.key_state})")


def parse_state(packet: bytes) -> DeviceState:
    if command_id(packet) != Cmd.GET_STATE or len(packet) < 9:
        raise ProtocolError("Invalid state response")
    return DeviceState(_u32(packet, 3), packet[8], _u32(packet, 11) if len(packet) >= 15 else 0)


@dataclass(frozen=True)
class LiveChunk:
    offset: int
    data: bytes


def parse_live_data(packet: bytes, session_id: int) -> LiveChunk | None:
    """Type-2 frame `[02][sessionId u32][offset u32][len u8][data]`. None for other sessions
    and for status frames (offset 0xFFFFFFFF)."""
    if len(packet) < 10 or packet[0] != 2 or _u32(packet, 1) != session_id:
        return None
    offset, length = _u32(packet, 5), packet[9]
    if offset == LIVE_STATUS_OFFSET:
        return None
    if len(packet) != 10 + length:
        raise ProtocolError("Truncated live audio frame")
    return LiveChunk(offset, bytes(packet[10:]))
