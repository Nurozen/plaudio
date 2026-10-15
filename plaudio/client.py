"""Async BLE client for the Plaud Note Pro (bleak / CoreBluetooth).

Only ever writes: 0xFE10 signature chunks, 0xFE12 public-key chunks, and encrypted
cmd 1 (handshake), 3 (get state), 4 (time sync), 20 (record start), 23 (record stop),
26 (list), 28 (download / live sync) and 29 (sync stop). Before writing anything it checks
that the advertised serial matches the saved identity.
"""

from __future__ import annotations

import asyncio
import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.scanner import AdvertisementData

from . import protocol as p
from .audio import AudioError, decrypt_plaud, ogg_to_wav
from .keys import RSAKeyError
from .provision import Identity
from .session import (
    EncryptedLink,
    PartFile,
    download_session,
    establish_encryption,
    list_sessions,
    local_unwrap,
    recording_handshake,
)

log = logging.getLogger("plaudio")
MAX_WRITE = 247 - 3  # negotiated ATT MTU 247


@dataclass(frozen=True)
class FoundDevice:
    device: BLEDevice
    name: str
    rssi: int | None
    advertisement: p.Advertisement | None


def _parse_adv(adv: AdvertisementData) -> p.Advertisement | None:
    data = adv.manufacturer_data.get(p.COMPANY_ID)
    if data is None:
        return None
    try:
        return p.parse_advertisement(data)
    except p.ProtocolError:
        return None


def _is_plaud(device: BLEDevice, adv: AdvertisementData) -> bool:
    return (adv.local_name or device.name or "").startswith("Plaud")


async def scan(timeout: float = 8.0) -> list[FoundDevice]:
    """Passive scan (no connection) for advertising Plaud recorders."""
    found = await BleakScanner.discover(timeout=timeout, return_adv=True)
    return [
        FoundDevice(dev, adv.local_name or dev.name or "", adv.rssi, _parse_adv(adv))
        for dev, adv in found.values()
        if _is_plaud(dev, adv)
    ]


async def find_device(serial: str, identifier: str = "", timeout: float = 20.0) -> tuple[BLEDevice, p.Advertisement]:
    matched: dict[str, p.Advertisement] = {}

    def accept(device: BLEDevice, adv: AdvertisementData) -> bool:
        if not _is_plaud(device, adv):
            return False
        if identifier and device.address.lower() != identifier.lower():
            return False
        parsed = _parse_adv(adv)
        if parsed is None or parsed.serial != serial:
            return False
        matched["adv"] = parsed
        return True

    device = await BleakScanner.find_device_by_filter(accept, timeout=timeout)
    if device is None:
        raise ConnectionError(f"Plaud recorder with serial {serial} not found (is it awake and not connected to a phone?)")
    return device, matched["adv"]


class BleLink:
    """One BLE notification == one protocol packet (as in the reference bridges)."""

    def __init__(self, client: BleakClient) -> None:
        self.client = client
        self.queue: asyncio.Queue[bytes | None] = asyncio.Queue()

    def on_notify(self, _sender, data: bytearray) -> None:
        self.queue.put_nowait(bytes(data))

    def on_disconnect(self, _client) -> None:
        self.queue.put_nowait(None)

    async def start(self) -> None:
        await self.client.start_notify(p.NOTIFY_UUID, self.on_notify)

    async def write(self, packet: bytes) -> None:
        if not packet or len(packet) > MAX_WRITE:
            raise ValueError(f"Packet size {len(packet)} exceeds the BLE write limit")
        await self.client.write_gatt_char(p.WRITE_UUID, packet, response=True)

    async def packet(self, timeout: float) -> bytes:
        try:
            item = await asyncio.wait_for(self.queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError("Bluetooth response timeout") from None
        if item is None:
            raise ConnectionError("Plaud disconnected")
        return item


class PlaudClient:
    """async with PlaudClient(identity) as plaud: sessions = await plaud.list_sessions()"""

    def __init__(
        self,
        identity: Identity,
        progress: Callable[[str], None] | None = None,
        handshake: bool = True,
    ) -> None:
        """handshake=False stops after the encrypted session is verified (dry run: no cmd 1).

        The handshake binds a factory-fresh recorder to the token derived from
        identity.bindingToken (the JWT `sub`), see protocol.sdk_handshake_token.
        """
        identity.validate()
        self.identity = identity
        self.progress = progress or (lambda stage: log.info(stage))
        self.do_handshake = handshake
        self.client: BleakClient | None = None
        self.link: EncryptedLink | None = None
        self.channels = 1
        self.handshake_result: p.HandshakeResult | None = None


    async def __aenter__(self) -> "PlaudClient":
        await self.connect()
        return self

    async def __aexit__(self, *exc) -> None:
        await self.close()

    async def connect(self) -> None:
        identity = self.identity
        self.progress("scanning")
        device, adv = await find_device(identity.serial, identity.identifier)
        if not adv.encrypted:
            raise ConnectionError(f"Recorder advertises protocol {adv.protocol_version}; only encrypted (>= 20) is supported")
        self.progress(f"connecting to {device.address}")
        raw = None
        self.client = BleakClient(device, disconnected_callback=lambda c: raw and raw.on_disconnect(c))
        raw = BleLink(self.client)
        await self.client.connect()
        try:
            await raw.start()
            self.link = await establish_encryption(
                raw, identity.signature, identity.publicKey, local_unwrap(identity.privateKey), self.progress
            )
            if not self.do_handshake:
                self.progress("dry run: encrypted session verified; stopping before the handshake (cmd 1)")
                return
            # Only ever the provisioned `sub`; validate() above guarantees it is a real token.
            result = await recording_handshake(
                self.link, p.sdk_handshake_token(identity.bindingToken), adv.protocol_version, on_reply=self.progress
            )
            self.handshake_result = result
            self.channels = result.channels
            self.progress(f"handshake accepted (protocol {result.protocol}, {result.channels} ch, raw={result.raw.hex()})")
        except BaseException:
            await self.close()
            raise

    async def close(self) -> None:
        if self.link is not None:
            self.link.close()
            self.link = None
        if self.client is not None:
            try:
                await self.client.disconnect()
            finally:
                self.client = None

    def _require_link(self) -> EncryptedLink:
        if self.link is None:
            raise ConnectionError("Not connected")
        if self.handshake_result is None:
            raise ConnectionError("Handshake not completed (dry run?)")
        return self.link

    async def list_sessions(self) -> list[p.SessionEntry]:
        return await list_sessions(self._require_link(), self.identity.protocolVersion)

    async def follow_recording(self, on_bytes, stop: asyncio.Event, **kwargs):
        from .live import follow_recording

        return await follow_recording(self._require_link(), on_bytes, stop, self.progress, **kwargs)

    async def download(
        self, session: p.SessionEntry, resume_dir: Path, progress: Callable[[int, int], None] | None = None
    ) -> p.DownloadResult:
        part = PartFile(resume_dir / f"{self.identity.serial}-{session.session_id}-{session.size}.part", session.size)
        try:
            if part.prefix:
                self.progress(f"resuming session {session.session_id} at byte {len(part.prefix)}")
            return await download_session(self._require_link(), session, part.prefix, part.save, progress)
        finally:
            part.close()


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(tmp, path)


def decode_file(plaud_path: Path, private_key: str, out_dir: Path | None = None, wav: bool = True) -> tuple[Path, Path | None]:
    """Decrypt FILE.plaud -> FILE.ogg (+ 16 kHz mono FILE.wav)."""
    out_dir = out_dir or plaud_path.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    decoded = decrypt_plaud(plaud_path.read_bytes(), local_unwrap(private_key))
    ogg_path = out_dir / (plaud_path.stem + ".ogg")
    _atomic_write(ogg_path, decoded.ogg)
    wav_path = ogg_to_wav(ogg_path, out_dir / (plaud_path.stem + ".wav")) if wav else None
    return ogg_path, wav_path


async def pull(
    identity: Identity,
    out_dir: Path,
    session_ids: list[int] | None = None,
    wav: bool = True,
    progress: Callable[[str], None] = print,
) -> list[Path]:
    """Download sessions (all if session_ids is None) into out_dir as .plaud/.ogg/.wav."""
    out_dir.mkdir(parents=True, exist_ok=True)
    resume_dir = out_dir / ".partial"
    written: list[Path] = []
    async with PlaudClient(identity, progress) as plaud:
        sessions = await plaud.list_sessions()
        wanted = sessions if session_ids is None else [s for s in sessions if s.session_id in set(session_ids)]
        missing = set(session_ids or []) - {s.session_id for s in wanted}
        if missing:
            progress(f"not on device: {sorted(missing)}")
        for session in wanted:
            stem = f"{identity.serial}-{session.session_id}"
            plaud_path = out_dir / f"{stem}.plaud"
            if not (plaud_path.exists() and plaud_path.stat().st_size == session.size):
                progress(f"downloading session {session.session_id} ({session.size} bytes)")
                last = [-1]

                def report(done: int, total: int) -> None:
                    pct = done * 100 // total
                    if pct >= last[0] + 5:
                        last[0] = pct
                        progress(f"  {pct}%")

                result = await plaud.download(session, resume_dir, report)
                _atomic_write(plaud_path, result.data)
                (resume_dir / f"{identity.serial}-{session.session_id}-{session.size}.part").unlink(missing_ok=True)
            written.append(plaud_path)
            try:
                ogg, wav_path = decode_file(plaud_path, identity.privateKey, out_dir, wav)
                written += [ogg] + ([wav_path] if wav_path else [])
                progress(f"decoded {ogg.name}" + (f" and {wav_path.name}" if wav_path else ""))
            except (AudioError, RSAKeyError) as error:
                progress(f"session {session.session_id}: kept {plaud_path.name} but decode failed: {error}")
        # Read-only retention check, as in the reference: the device must still list what we pulled.
        retained = {(s.session_id, s.size) for s in await plaud.list_sessions()}
        for session in wanted:
            if (session.session_id, session.size) not in retained:
                progress(f"warning: session {session.session_id} no longer listed on device")
    return written
