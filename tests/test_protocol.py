import os
import struct

import pytest

from plaudio import protocol as p


def test_advertisement_reference_vector_with_company_prefix():
    data = bytearray.fromhex("5d000271030456000701088810000000000001441400040101")
    adv = p.parse_advertisement(bytes(data))
    assert adv == p.Advertisement(project=881, serial="8810000000000001", protocol_version=20)
    assert adv.encrypted
    with pytest.raises(p.ProtocolError):
        p.parse_advertisement(bytes(data[:21]))
    data[3] = 0
    with pytest.raises(p.ProtocolError):
        p.parse_advertisement(bytes(data))


def test_advertisement_bleak_payload():
    adv = p.parse_advertisement(bytes.fromhex("0271030456000701088810000000000001441400040100"))
    assert (adv.project, adv.serial, adv.protocol_version, adv.encrypted) == (881, "8810000000000001", 20, True)


def test_handshake_padding_and_mode():
    packet = p.build_handshake("test-token", 20)
    assert packet[:6].hex() == "010100020000"
    assert packet[6:].decode() == "test-token".ljust(32, "0")
    assert len(p.build_handshake("x", 2)) == 21
    assert len(p.build_handshake("x", 3)) == 22
    assert len(p.build_handshake("x" * 40, 20)[6:]) == 32
    for bad in ("", "bad\nvalue", "has space"):
        with pytest.raises(p.ProtocolError):
            p.build_handshake(bad, 20)


def test_list_and_download_builders():
    assert p.build_session_request(7, 100).hex() == "011a00070000006400000000"
    assert p.build_download_request(10, 20, 30).hex() == "011c000a000000140000001e000000"
    with pytest.raises(p.ProtocolError):
        p.build_download_request(10, 30, 20)
    with pytest.raises(p.ProtocolError):
        p.build_session_request(-1, 0)


def test_only_documented_commands_are_buildable():
    for opcode in (2, 5, 30, 102, 104, 151, 0xFE11, 99):
        with pytest.raises(p.ProtocolError):
            p.build_command(opcode)


def test_prehandshake_chunks_and_reassembly():
    payload = os.urandom(256)
    chunks = p.build_prehandshake_chunks(p.Cmd.PUBLIC_KEY, payload)
    assert [len(c) for c in chunks] == [104, 104, 60]
    assert chunks[0][:4].hex() == "12fe0300"
    assert p.build_prehandshake_chunks(p.Cmd.SIGNATURE, payload)[0][:2].hex() == "10fe"
    with pytest.raises(p.ProtocolError, match="Unsupported"):
        p.build_prehandshake_chunks(0xFE20, payload)
    collector = p.KeyChunks()
    assert collector.add(chunks[2]) is None
    assert collector.add(chunks[0]) is None
    assert collector.add(chunks[0]) is None
    assert collector.add(chunks[1]) == payload


def test_key_chunks_reject_bad_material():
    chunks = p.build_prehandshake_chunks(p.Cmd.PUBLIC_KEY, os.urandom(256))
    collector = p.KeyChunks()
    collector.add(chunks[0])
    conflict = bytearray(chunks[0])
    conflict[4] ^= 1
    with pytest.raises(p.ProtocolError, match="Conflicting"):
        collector.add(bytes(conflict))
    with pytest.raises(p.ProtocolError):
        collector.add(bytes([0x12, 0xFE, 4, 3, 1]))
    with pytest.raises(p.ProtocolError):
        collector.add(bytes([0x12, 0xFE, 2, 1, 1]))
    with pytest.raises(p.ProtocolError):
        p.KeyChunks().add(bytes([0x12, 0xFE, 1, 0, 1]))
    for opcode, size in ((0xFE12, 25501), (0xFE12, 0), (99, 1)):
        with pytest.raises(p.ProtocolError):
            p.build_prehandshake_chunks(opcode, bytes(size))


def test_session_page_parse_and_strides():
    packet = bytearray.fromhex("011a0007000000030001000a000000640000002c02")
    page = p.parse_session_page(bytes(packet), 20)
    assert (page.request_id, page.total, page.offset) == (7, 3, 1)
    assert page.entries == [p.SessionEntry(session_id=10, size=100, timezone=44, scene=2)]
    with pytest.raises(p.ProtocolError):
        p.parse_session_page(bytes(packet[:-1]), 20)
    struct.pack_into("<H", packet, 9, 3)
    with pytest.raises(p.ProtocolError):
        p.parse_session_page(bytes(packet), 20)
    assert p.parse_session_page(bytes.fromhex("011a000700000000000000"), 20).total == 0
    with pytest.raises(p.ProtocolError):
        p.parse_session_page(b"", 20)
    assert [p.session_stride(v) for v in (1, 2, 6, 7, 20)] == [8, 9, 9, 10, 10]
    v1 = bytes.fromhex("011a00070000000100000005000000ff000000")
    assert p.parse_session_page(v1, 1).entries == [p.SessionEntry(5, 255, 0, 0)]
    v2 = bytes.fromhex("011a0007000000010000000500000010000000" + "03")
    assert p.parse_session_page(v2, 5).entries == [p.SessionEntry(5, 16, 3, 0)]


def page(request, total, offset, ids):
    packet = bytearray(11 + len(ids) * 10)
    packet[0] = 1
    struct.pack_into("<HIHH", packet, 1, 26, request, total, offset)
    for i, sid in enumerate(ids):
        struct.pack_into("<II", packet, 11 + i * 10, sid, 100)
    return bytes(packet)


def test_session_pages_pagination():
    pages = p.SessionPages(7, 20)
    assert pages.add(page(7, 3, 2, [30])) is None
    assert pages.add(page(7, 3, 2, [30])) is None
    with pytest.raises(p.ProtocolError, match="request"):
        pages.add(page(8, 3, 0, [10]))
    with pytest.raises(p.ProtocolError, match="changed"):
        pages.add(page(7, 4, 0, [10]))
    with pytest.raises(p.ProtocolError, match="Conflicting"):
        pages.add(page(7, 3, 2, [40]))
    assert [e.session_id for e in pages.add(page(7, 3, 0, [10, 20]))] == [10, 20, 30]
    assert p.SessionPages(1, 20).add(page(1, 0, 0, [])) == []
    with pytest.raises(p.ProtocolError, match="Duplicate"):
        p.SessionPages(1, 20).add(page(1, 2, 0, [10, 10]))


SESSION = p.SessionEntry(session_id=7, size=4)
HEAD = bytes.fromhex("011c000700000000")
TAIL = bytes.fromhex("011d0007000000ffff")
DATA = bytes.fromhex("0207000000000000000401020304")


def test_download_head_data_tail():
    transfer = p.Download(SESSION)
    with pytest.raises(p.ProtocolError):
        transfer.add(DATA)
    assert transfer.add(HEAD) is None
    with pytest.raises(p.ProtocolError, match="Incomplete"):
        transfer.add(TAIL)
    assert transfer.add(bytes.fromhex("0109000100")) is None
    assert transfer.add(DATA) is None
    assert transfer.add(TAIL) == p.DownloadResult(data=bytes([1, 2, 3, 4]), tail_crc=0xFFFF)
    with pytest.raises(p.ProtocolError, match="completed"):
        transfer.add(TAIL)


def test_download_rejects_bad_packets():
    bad_session = bytearray(DATA)
    struct.pack_into("<I", bad_session, 1, 8)
    gap = bytearray(DATA)
    struct.pack_into("<I", gap, 5, 1)
    length = bytearray(DATA)
    length[9] = 3
    stop = bytes.fromhex("0207000000ffffffff0102")
    for bad in (bad_session, gap, length, DATA[:-1], stop):
        transfer = p.Download(SESSION)
        transfer.add(HEAD)
        with pytest.raises(p.ProtocolError):
            transfer.add(bytes(bad))
    benign_stop = bytes.fromhex("0207000000ffffffff0101")
    transfer = p.Download(SESSION)
    transfer.add(HEAD)
    assert transfer.add(benign_stop) is None
    with pytest.raises(p.ProtocolError, match="limit"):
        p.Download(p.SessionEntry(7, 65 * 1024 * 1024))
    with pytest.raises(p.ProtocolError, match="prefix"):
        p.Download(SESSION, bytes(4))
    rejected = p.Download(SESSION)
    with pytest.raises(p.ProtocolError, match="rejected"):
        rejected.add(bytes.fromhex("011c000700000001"))


def test_handshake_state_machine():
    request = p.build_handshake("a" * 32, 20)
    state = p.HandshakeState(request)
    serial = bytes([1, 2]) + bytes(57)
    resend = state.feed(serial)
    assert isinstance(resend, bytes) and resend[5] == 1 and resend[:5] == bytes(request[:5])
    assert state.feed(serial) is None  # second serial reply is ignored
    accepted = bytes.fromhex("01010000140000000100000156000000")
    result = state.feed(accepted)
    assert (result.protocol, result.channels, result.raw) == (20, 1, accepted)
    rejected = bytearray(accepted)
    rejected[3] = 2
    with pytest.raises(p.HandshakeRejected, match="status 2, raw reply 01010002"):
        p.HandshakeState(request).feed(bytes(rejected))
    wrong_protocol = bytearray(accepted)
    wrong_protocol[4] = 19
    with pytest.raises(p.ProtocolError, match="Unsupported"):
        p.HandshakeState(request).feed(bytes(wrong_protocol))
    with pytest.raises(p.ProtocolError, match="Truncated"):
        p.HandshakeState(request).feed(bytes([1, 2, 0]))


def test_sdk_handshake_token():
    assert p.sdk_handshake_token("client_user_ab-cd") == "abcd"
    assert p.sdk_handshake_token("abc123_4def_12345678-9abc-def0-1234-56789abcdef0") == "abc123_4def_123456789abcdef0123456789abcdef0"
