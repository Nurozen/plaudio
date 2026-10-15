"""End-to-end flows against a simulated recorder (no Bluetooth)."""

import asyncio
import base64
import os
import struct
from types import SimpleNamespace

import pytest
from fake_device import FakeBleakClient, FakeNotePro
from test_audio import synthetic_plaud_file

from plaudio import client as client_mod
from plaudio import keys
from plaudio import protocol as p
from plaudio.provision import Identity
from plaudio.session import PartFile, download_session

SERIAL = "8810000000000001"
TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz012345"


def make_identity(fmt="pkcs1", token=TOKEN):
    pair = keys.generate_local_keypair(fmt)
    signature = os.urandom(256)
    identity = Identity(
        identifier="", serial=SERIAL, bindingToken=token, signature=base64.b64encode(signature).decode(),
        publicKey=pair.public_key, privateKey=pair.private_key,
    )
    return identity, signature


@pytest.fixture
def rig(monkeypatch):
    def build(identity, signature, recordings=None, status=0):
        device = FakeNotePro(signature, recordings or {}, handshake_status=status)
        holder = {}

        async def fake_find(serial, identifier="", timeout=20.0):
            assert serial == SERIAL
            return SimpleNamespace(address="FAKE-UUID"), p.Advertisement(881, SERIAL, 20)

        def fake_client(_device, disconnected_callback=None):
            holder["client"] = FakeBleakClient(device, disconnected_callback)
            return holder["client"]

        monkeypatch.setattr(client_mod, "find_device", fake_find)
        monkeypatch.setattr(client_mod, "BleakClient", fake_client)
        return device, holder

    return build


@pytest.mark.parametrize("fmt", ["pkcs1", "spki", "pem-pkcs1"])
def test_full_session_list_and_pull(rig, tmp_path, fmt):
    identity, signature = make_identity(fmt)
    private = keys.load_private_key(identity.privateKey)
    recording, ogg = synthetic_plaud_file(private.public_key())
    device, holder = rig(identity, signature, {1700000001: recording})
    log = []

    async def run():
        async with client_mod.PlaudClient(identity, log.append) as plaud:
            sessions = await plaud.list_sessions()
            assert sessions == [p.SessionEntry(1700000001, len(recording), scene=1, timezone=0)]
        return await client_mod.pull(identity, tmp_path, None, wav=False, progress=log.append)

    written = asyncio.run(run())
    assert (tmp_path / f"{SERIAL}-1700000001.plaud").read_bytes() == recording
    assert (tmp_path / f"{SERIAL}-1700000001.ogg").read_bytes() == ogg
    assert len(written) == 2
    # Handshake used the provisioned token, then the one-time second mode.
    # Each connection: handshake with the provisioned token, then the one-time second mode.
    assert [h[6:].decode() for h in device.handshakes] == [TOKEN] * 4
    assert [h[5] for h in device.handshakes] == [0, 1, 0, 1]
    assert any("handshake reply raw=010100" in line and "status=0" in line for line in log)
    # Nothing beyond the documented commands was ever written.
    assert set(device.commands) <= {1, 26, 28}


def test_dry_run_stops_before_handshake(rig):
    identity, signature = make_identity()
    device, holder = rig(identity, signature)
    log = []

    async def run():
        async with client_mod.PlaudClient(identity, log.append, handshake=False) as plaud:
            assert plaud.link is not None
            with pytest.raises(ConnectionError):
                await plaud.list_sessions()

    asyncio.run(run())
    assert device.encrypted and device.commands == [] and device.handshakes == []
    assert {struct.unpack_from("<H", w)[0] for w in holder["client"].writes} == {0xFE10, 0xFE12}


def test_rejected_handshake_is_surfaced_and_not_retried(rig):
    identity, signature = make_identity()
    device, _ = rig(identity, signature, status=2)
    log = []

    async def run():
        async with client_mod.PlaudClient(identity, log.append):
            pass

    with pytest.raises(p.HandshakeRejected, match="status 2, raw reply 01010002"):
        asyncio.run(run())
    assert len(device.handshakes) == 1
    assert any("status=2" in line for line in log)


def test_handshake_uses_sdk_token_derivation(rig):
    sub = "abc123_4def_12345678-9abc-def0-1234-56789abcdef0"
    identity, signature = make_identity(token=sub)
    device, _ = rig(identity, signature)

    async def run():
        async with client_mod.PlaudClient(identity, lambda _: None):
            pass

    asyncio.run(run())
    assert device.handshakes[0][6:].decode() == "abc123_4def_123456789abcdef01234"


def test_bad_signature_disconnects(rig):
    identity, _ = make_identity()
    rig(identity, os.urandom(256))
    with pytest.raises(ConnectionError):
        asyncio.run(client_mod.PlaudClient(identity, lambda _: None).connect())


class ScriptedLink:
    def __init__(self, packets):
        self.packets = list(packets)
        self.writes = []

    async def write(self, packet):
        self.writes.append(bytes(packet))

    async def packet(self, timeout):
        if not self.packets:
            raise ConnectionError("disconnected")
        return self.packets.pop(0)


SESSION = p.SessionEntry(7, 4)
HEAD = bytes.fromhex("011c000700000000")
TAIL = bytes.fromhex("011d0007000000ffff")


def test_resume_requests_exact_offset_and_requires_tail(tmp_path):
    part = tmp_path / "x.part"
    part.write_bytes(bytes([1, 2]))
    buffer = PartFile(part, SESSION.size)
    link = ScriptedLink([HEAD, bytes.fromhex("020700000002000000020304"), TAIL])
    result = asyncio.run(download_session(link, SESSION, buffer.prefix, buffer.save))
    buffer.close()
    assert struct.unpack_from("<I", link.writes[0], 7)[0] == 2
    assert result.data == bytes([1, 2, 3, 4]) and part.read_bytes() == result.data


def test_interrupted_transfer_checkpoints_received_bytes(tmp_path):
    part = tmp_path / "y.part"
    buffer = PartFile(part, SESSION.size)
    link = ScriptedLink([HEAD, bytes.fromhex("0207000000000000000401020304")])
    with pytest.raises(ConnectionError):
        asyncio.run(download_session(link, SESSION, buffer.prefix, buffer.save))
    buffer.close()
    assert part.read_bytes() == bytes([1, 2, 3, 4])
    # A full prefix is clipped to size-1 so the device must send a fresh tail.
    assert PartFile(part, SESSION.size).prefix == bytes([1, 2, 3])


def test_blocked_commands_never_leave_the_host():
    from plaudio.session import BlockedCommand, check_outgoing

    for cmd in (5, 30, 102, 103, 104, 151):
        with pytest.raises(BlockedCommand):
            check_outgoing(bytes([1]) + cmd.to_bytes(2, "little"))
    with pytest.raises(BlockedCommand):
        check_outgoing(b"\x02\x00\x00\x00")
    check_outgoing(p.build_command(26, b"\x00" * 9))
