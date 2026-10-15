"""Live capture: start a recording and follow it over BLE while the device writes it.

There is no dedicated streaming command. We start a recording
(cmd 20) and run an open-ended file sync (cmd 28, end = 0) on that session. On the Note Pro
(`isOggAudio` = 1) the bytes are the session file itself: the 512-byte PLAUD.AI header, then
ChaCha20-encrypted Ogg Opus. LiveDecryptor turns them into plaintext Ogg as they arrive.
"""

from __future__ import annotations

import asyncio
import subprocess
import time
from dataclasses import dataclass, field
from typing import Callable

from . import protocol as p
from .audio import HEADER_SIZE, AudioError, chacha20_xor, find_ffmpeg, parse_header
from .session import PacketLink, SessionError

COMMAND_TIMEOUT = 10.0
POLL = 0.25
DRAIN_IDLE = 2.0  # after a stop, close the sync once no data has arrived for this long
DRAIN_MAX = 15.0


class LiveDecryptor:
    """Incremental .plaud decryptor. Feed contiguous file bytes from offset 0, get Ogg back."""

    def __init__(self, unwrap: Callable[[bytes], bytes]) -> None:
        self.unwrap = unwrap
        self.head = bytearray()
        self.key: bytes | None = None
        self.nonce = b""
        self.channels = 0
        self.position = 0  # file bytes consumed

    def feed(self, data: bytes) -> bytes:
        if self.key is None:
            self.head += data
            self.position += len(data)
            if len(self.head) <= HEADER_SIZE:
                return b""
            header = parse_header(self.head)
            if header.counter != 0:
                raise AudioError("Unsupported Plaud audio counter")
            key = self.unwrap(header.encrypted_key)
            if len(key) != 32:
                raise AudioError("Plaud audio key does not match the authorized identity")
            self.key, self.nonce, self.channels = key, header.nonce, header.channels
            body = bytes(self.head[HEADER_SIZE:])
            self.head.clear()
            return self._decrypt(0, body)
        start = self.position - HEADER_SIZE
        self.position += len(data)
        return self._decrypt(start, data)

    def _decrypt(self, cipher_offset: int, data: bytes) -> bytes:
        # RFC 8439 ChaCha20 is seekable by 64-byte block.
        block, skip = divmod(cipher_offset, 64)
        return chacha20_xor(self.key, self.nonce, bytes(skip) + data, counter=block)[skip:]


class PcmSink:
    """ffmpeg reading Ogg Opus on stdin; 16 kHz mono s16le PCM goes to on_pcm (from a thread)."""

    BYTES_PER_SECOND = 32000

    def __init__(self, on_pcm: Callable[[bytes], None]) -> None:
        self.proc = subprocess.Popen(
            [find_ffmpeg(), "-v", "error", "-probesize", "32", "-analyzeduration", "0", "-f", "ogg", "-i", "pipe:0",
             "-map", "0:a:0", "-ac", "1", "-ar", "16000", "-flush_packets", "1", "-f", "s16le", "pipe:1"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, bufsize=0,
        )
        self.on_pcm = on_pcm
        self.pcm_bytes = 0
        self.first_pcm_at: float | None = None
        self._reader = asyncio.get_running_loop().run_in_executor(None, self._pump)

    @property
    def seconds(self) -> float:
        return self.pcm_bytes / self.BYTES_PER_SECOND

    def _pump(self) -> None:
        while chunk := self.proc.stdout.read(3200):  # 100 ms
            if self.first_pcm_at is None:
                self.first_pcm_at = time.monotonic()
            self.pcm_bytes += len(chunk)
            self.on_pcm(chunk)

    def write(self, ogg: bytes) -> None:
        if ogg:
            self.proc.stdin.write(ogg)

    async def close(self) -> None:
        self.proc.stdin.close()
        await self._reader
        await asyncio.get_running_loop().run_in_executor(None, self.proc.wait)


@dataclass
class LiveStats:
    session_id: int = 0
    started_recording: bool = False
    started_at: float = 0.0
    first_byte_at: float | None = None
    bytes: int = 0
    frames: int = 0
    resyncs: int = 0
    stop_reason: str = ""
    events: list[str] = field(default_factory=list)


async def _await_cmd(link: PacketLink, cmd: int, timeout: float, stats: LiveStats) -> bytes:
    deadline = time.monotonic() + timeout
    while True:
        left = deadline - time.monotonic()
        if left <= 0:
            raise TimeoutError(f"No response to cmd {cmd}")
        packet = await link.packet(left)
        if p.command_id(packet) == cmd:
            return packet
        stats.events.append(f"skipped {packet[:3].hex()} while waiting for cmd {cmd}")


async def follow_recording(
    link: PacketLink,
    on_bytes: Callable[[int, bytes], None],
    stop: asyncio.Event,
    progress: Callable[[str], None] = lambda _m: None,
    start_recording: bool = True,
    stop_recording: bool = True,
    on_session: Callable[[int], None] = lambda _sid: None,
) -> LiveStats:
    """Start (or attach to) a recording and stream its file bytes to on_bytes(offset, data).

    Returns when `stop` is set (we stop the recording, then drain the tail) or when the
    device stops on its own (button press). Only sends cmds 3, 4, 20, 23, 28, 29.
    """
    stats = LiveStats(started_at=time.monotonic())
    await link.write(p.build_time_sync(int(time.time()), time.localtime().tm_gmtoff // 60))
    await _await_cmd(link, p.Cmd.TIME_SYNC, COMMAND_TIMEOUT, stats)

    await link.write(p.build_command(p.Cmd.GET_STATE))
    state = p.parse_state(await _await_cmd(link, p.Cmd.GET_STATE, COMMAND_TIMEOUT, stats))
    progress(f"device state: {state.name}")

    if state.recording:
        stats.session_id = state.session_id
        progress(f"attaching to recording in progress (session {state.session_id})")
    elif start_recording:
        await link.write(p.build_record_start())
        event = p.parse_record_event(await _await_cmd(link, p.Cmd.RECORD_START, COMMAND_TIMEOUT, stats))
        if event is None or event.status not in (0, 4):
            raise SessionError(f"Recording did not start (status {event.status if event else '?'})")
        stats.session_id, stats.started_recording = event.session_id, True
        progress(f"recording started (session {event.session_id}, device start offset {event.start})")
    else:
        raise SessionError("Device is not recording")
    on_session(stats.session_id)

    # Always sync from 0 so we get the header (file key). Backlog catches up at ~5x real time.
    count = 0
    await link.write(p.build_live_sync(stats.session_id, count))
    head = await _await_cmd(link, p.Cmd.DOWNLOAD, COMMAND_TIMEOUT, stats)
    if len(head) < 8 or head[7] != 0:
        raise SessionError(f"Live sync rejected: {head.hex()}")
    progress("live sync open")

    stopping_since: float | None = None
    last_data = time.monotonic()
    sync_stop_sent = False
    final_size: int | None = None  # from the stop event: drain until we hold this many bytes
    fetching_tail = False
    while True:
        now = time.monotonic()
        if stop.is_set() and stopping_since is None:
            stopping_since = now
            stats.stop_reason = stats.stop_reason or "requested"
            if stop_recording:
                progress("stopping recording; draining")
                await link.write(p.build_record_stop())
        # The device sends no tail for an open-ended sync, so close it ourselves once
        # the recording has stopped and the remaining bytes have drained.
        complete = final_size is not None and count >= final_size
        if stopping_since is not None and not sync_stop_sent and not fetching_tail and (
            complete or now - last_data > DRAIN_IDLE or now - stopping_since > DRAIN_MAX
        ):
            await link.write(p.build_sync_stop())
            sync_stop_sent = True
            if not complete and final_size is not None and count < final_size:
                # The open-ended sync stalled short of the final size: fetch the rest bounded.
                await _await_cmd(link, p.Cmd.SYNC_STOP_ACK, COMMAND_TIMEOUT, stats)
                progress(f"fetching last {final_size - count} bytes")
                await link.write(p.build_download_request(stats.session_id, count, final_size))
                sync_stop_sent, fetching_tail = False, True
                last_data = time.monotonic()
        if sync_stop_sent and now - stopping_since > DRAIN_MAX + COMMAND_TIMEOUT:
            stats.events.append("no sync-stop ack")
            break
        try:
            packet = await link.packet(POLL)
        except TimeoutError:
            continue

        chunk = p.parse_live_data(packet, stats.session_id)
        if chunk is not None:
            if chunk.offset < count:  # duplicate after a resync
                overlap = count - chunk.offset
                if overlap >= len(chunk.data):
                    continue
                chunk = p.LiveChunk(count, chunk.data[overlap:])
            if chunk.offset > count:
                stats.resyncs += 1
                progress(f"gap at {count} (got {chunk.offset}); resyncing")
                await link.write(p.build_sync_stop())
                await _await_cmd(link, p.Cmd.SYNC_STOP_ACK, COMMAND_TIMEOUT, stats)
                await link.write(p.build_live_sync(stats.session_id, count))
                continue
            if stats.first_byte_at is None:
                stats.first_byte_at = time.monotonic()
            on_bytes(chunk.offset, chunk.data)
            last_data = time.monotonic()
            count += len(chunk.data)
            stats.bytes, stats.frames = count, stats.frames + 1
            continue

        cmd = p.command_id(packet)
        event = p.parse_record_event(packet)
        if event and event.session_id == stats.session_id:
            if event.cmd == p.Cmd.RECORD_STOP:
                final_size = event.file_size
                stats.events.append(f"device stop (reason {event.status}, file size {event.file_size}) raw={packet.hex()}")
                stats.stop_reason = stats.stop_reason or "device"
                stopping_since = stopping_since or time.monotonic()
                progress("device stopped recording; draining")
            else:
                stats.events.append(f"record event cmd {event.cmd}")
        elif cmd == p.Cmd.TAIL:
            progress("transfer tail received")
            if final_size is None or count >= final_size or fetching_tail:
                break
        elif cmd == p.Cmd.SYNC_STOP_ACK:
            progress("live sync closed")
            break
        elif cmd is not None:
            stats.events.append(f"notification cmd {cmd}: {packet.hex()[:40]}")
    return stats
