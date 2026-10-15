"""A simulated Note Pro, implementing the device side of the protocol as the reference describes it."""

from __future__ import annotations

import asyncio
import base64
import os
import struct

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

from plaudio import protocol as p


def load_public(encoded: str):
    text = encoded.strip()
    if text.startswith("-----"):
        return serialization.load_pem_public_key(text.encode())
    der = base64.b64decode(text)
    try:
        return serialization.load_der_public_key(der)
    except ValueError:
        pem = b"-----BEGIN RSA PUBLIC KEY-----\n" + base64.encodebytes(der) + b"-----END RSA PUBLIC KEY-----\n"
        return serialization.load_pem_public_key(pem)


class FakeNotePro:
    def __init__(self, expected_signature: bytes, recordings: dict[int, bytes], handshake_status: int = 0):
        self.expected_signature = expected_signature
        self.recordings = recordings
        self.handshake_status = handshake_status
        self.notify = None
        self.reset()
        self.handshakes: list[bytes] = []
        self.commands: list[int] = []
        self.disconnected = False

    def reset(self) -> None:
        """New connection: fresh session keys and pre-handshake state."""
        self.key, self.nonce, self.ad = os.urandom(32), os.urandom(12), os.urandom(12)
        self.aead = ChaCha20Poly1305(self.key)
        self.inbox: dict[int, dict[int, bytes]] = {}
        self.encrypted = False
        self.counter = 100

    # transport side ------------------------------------------------------
    def send(self, packet: bytes, encrypt: bool = True) -> None:
        if encrypt:
            self.counter += 1
            packet = self.aead.encrypt(self.nonce, struct.pack("<I", self.counter) + packet, self.ad)
        asyncio.get_running_loop().call_soon(self.notify, None, bytearray(packet))

    def receive(self, data: bytes) -> None:
        if not self.encrypted:
            opcode, total, index = struct.unpack_from("<HBB", data)
            chunks = self.inbox.setdefault(opcode, {})
            chunks[index] = data[4:]
            if len(chunks) < total:
                return
            payload = b"".join(chunks[i] for i in range(total))
            if opcode == p.Cmd.SIGNATURE:
                if payload != self.expected_signature:
                    self.disconnected = True
                    raise ConnectionError("device disconnected (bad signature)")
                self.send(struct.pack("<H", p.Cmd.SIGNATURE_ACCEPTED) + b"\x00", encrypt=False)
            elif opcode == p.Cmd.PUBLIC_KEY:
                public = load_public(payload.decode())
                marker = self.aead.encrypt(self.nonce, b"PLAUD.AI", self.ad)
                wrapped = public.encrypt(self.key + self.nonce + self.ad + marker, padding.PKCS1v15())
                self.encrypted = True
                for i in range(3):
                    self.send(struct.pack("<HBB", p.Cmd.PUBLIC_KEY, 3, i) + wrapped[i * 100 : (i + 1) * 100], encrypt=False)
            return
        plain = self.aead.decrypt(self.nonce, data, self.ad)
        command = plain[4:]
        opcode = struct.unpack_from("<H", command, 1)[0]
        self.commands.append(opcode)
        if opcode == p.Cmd.HANDSHAKE:
            self.handshakes.append(command)
            if command[5] == 0 and self.handshake_status == 0:
                self.send(bytes([1, 2, 0]) + bytes(56))  # serial info -> host resends with mode 1
            else:
                self.send(bytes.fromhex("010100") + bytes([self.handshake_status]) + bytes.fromhex("140000000100000156000000"))
        elif opcode == p.Cmd.SESSIONS:
            request_id = struct.unpack_from("<I", command, 3)[0]
            self.send(bytes.fromhex("0109000100"))  # unrelated notification
            ids = list(self.recordings)
            header = bytes([1]) + struct.pack("<HIHH", 26, request_id, len(ids), 0)
            body = b"".join(struct.pack("<II", sid, len(self.recordings[sid])) + bytes([0, 1]) for sid in ids)
            self.send(header + body)
        elif opcode == p.Cmd.DOWNLOAD:
            sid, offset, end = struct.unpack_from("<III", command, 3)
            data = self.recordings[sid]
            self.send(bytes([1]) + struct.pack("<HI", 28, sid) + b"\x00")
            position = offset
            while position < end:
                piece = data[position : min(end, position + 200)]
                self.send(bytes([2]) + struct.pack("<IIB", sid, position, len(piece)) + piece)
                position += len(piece)
            self.send(bytes([1]) + struct.pack("<HIH", 29, sid, 0xABCD))


class FakeBleakClient:
    def __init__(self, device: FakeNotePro, disconnected_callback=None):
        self.device = device
        self.disconnected_callback = disconnected_callback
        self.writes: list[bytes] = []

    async def connect(self):
        self.device.reset()
        return True

    async def start_notify(self, uuid, callback):
        assert uuid == p.NOTIFY_UUID
        self.device.notify = callback

    async def write_gatt_char(self, uuid, data, response=True):
        assert uuid == p.WRITE_UUID and response
        self.writes.append(bytes(data))
        self.device.receive(bytes(data))

    async def disconnect(self):
        return True
