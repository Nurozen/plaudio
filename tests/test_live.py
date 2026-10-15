"""Live capture: cmd builders/parsers, incremental decrypt, and follow_recording against a scripted device."""

import asyncio
import os
import random
import struct

import pytest
from cryptography.hazmat.primitives.asymmetric import padding
from test_audio import plaud_header

from plaudio import audio, keys, live
from plaudio import protocol as p
from plaudio.session import BLOCKED_COMMANDS, check_outgoing

SID = 1700000001  # synthetic session id (a unix timestamp, as on the device)
FRAME = 180

# --------------------------------------------------------------------------- builders / parsers


def test_live_command_builders():
    assert p.build_time_sync(0x01020304, 330).hex() == "010400" + "04030201" + "051e"
    assert p.build_time_sync(0x01020304, -90).hex() == "010400" + "04030201" + "ffe2"
    assert p.build_time_sync(0, 0).hex() == "010400" + "00000000" + "0000"
    assert p.build_record_start().hex() == "0114000101"
    assert p.build_record_stop().hex() == "0117000101"
    assert p.build_live_sync(SID, 1234).hex() == "011c00" + "01f15365" + "d2040000" + "00000000"
    assert p.build_sync_stop().hex() == "011d00"
    with pytest.raises(p.ProtocolError):
        p.build_live_sync(SID, -1)


def test_parse_stop_event_with_file_size():
    event = p.parse_record_event(bytes.fromhex("01170001f15365020100000100"))
    assert event == p.RecordEvent(cmd=p.Cmd.RECORD_STOP, session_id=SID, status=2, file_size=65536)


def test_parse_record_events():
    no_size = p.parse_record_event(bytes.fromhex("01170001f1536502"))
    assert (no_size.status, no_size.file_size) == (2, None)
    file_missing = p.parse_record_event(bytes.fromhex("01170001f15365020000000100"))
    assert file_missing.file_size is None
    start = p.parse_record_event(bytes.fromhex("01140001f15365" + "401f0000" + "04"))
    assert start == p.RecordEvent(cmd=p.Cmd.RECORD_START, session_id=SID, start=8000, status=4)
    pause = p.parse_record_event(bytes.fromhex("01150001f1536501"))
    assert (pause.cmd, pause.session_id, pause.file_size) == (p.Cmd.RECORD_PAUSE, SID, None)
    assert p.parse_record_event(bytes.fromhex("011c0001f1536500")) is None  # not a record event
    assert p.parse_record_event(bytes.fromhex("011700")) is None  # truncated
    assert p.parse_record_event(bytes.fromhex("02170001f1536500")) is None  # data frame


def test_parse_state():
    recording = p.parse_state(bytes.fromhex("010300" + "03100000" + "00" + "01" + "0000" + "01f15365"))
    assert recording.recording and recording.name == "recording" and recording.session_id == SID
    idle = p.parse_state(bytes.fromhex("010300" + "00000000" + "00" + "00"))
    assert not idle.recording and idle.name == "idle" and idle.session_id == 0
    assert p.parse_state(bytes.fromhex("010300" + "00000000" + "00" + "02")).name == "transfer"
    assert p.parse_state(bytes.fromhex("010300" + "00000000" + "00" + "09")).name == "unknown(9)"
    with pytest.raises(p.ProtocolError):
        p.parse_state(bytes.fromhex("010400" + "00000000" + "0000"))
    with pytest.raises(p.ProtocolError):
        p.parse_state(bytes.fromhex("01030003100000"))


def test_parse_live_data():
    frame = bytes([2]) + struct.pack("<IIB", SID, 512, 3) + b"abc"
    assert p.parse_live_data(frame, SID) == p.LiveChunk(512, b"abc")
    assert p.parse_live_data(frame, SID + 1) is None
    status = bytes([2]) + struct.pack("<IIB", SID, p.LIVE_STATUS_OFFSET, 1) + b"\x05"
    assert p.parse_live_data(status, SID) is None
    assert p.parse_live_data(bytes([1]) + frame[1:], SID) is None
    with pytest.raises(p.ProtocolError, match="Truncated"):
        p.parse_live_data(frame[:-1], SID)
    assert p.command_id(frame) is None and p.command_id(bytes.fromhex("011d00")) == 29


# --------------------------------------------------------------------------- incremental decrypt


def ogg_stream(payload_pages=12, channels=1, serial=7):
    """A valid multi-page Ogg Opus stream (BOS OpusHead page, random data pages, EOS)."""

    def page(flags, sequence, body):
        segments = [255] * (len(body) // 255) + [len(body) % 255]
        raw = bytearray(b"OggS\x00" + bytes([flags]) + struct.pack("<qIII", sequence, serial, sequence, 0))
        raw += bytes([len(segments)]) + bytes(segments) + body
        struct.pack_into("<I", raw, 22, audio.ogg_crc(raw))
        return bytes(raw)

    head = b"OpusHead" + bytes([1, channels]) + bytes(9)
    pages = [page(2, 0, head)]
    for seq in range(1, payload_pages + 1):
        pages.append(page(4 if seq == payload_pages else 0, seq, os.urandom(random.randint(1, 1500))))
    return b"".join(pages)


@pytest.fixture(scope="module")
def identity():
    pair = keys.generate_local_keypair()
    public = keys.load_private_key(pair.private_key).public_key()
    return pair.private_key, public


def make_file(public, pages=12):
    file_key, nonce = os.urandom(32), os.urandom(12)
    ogg = ogg_stream(pages)
    wrapped = public.encrypt(file_key, padding.PKCS1v15())
    return plaud_header(nonce, wrapped) + audio.chacha20_xor(file_key, nonce, ogg), ogg


def unwrapper(private_key):
    return lambda block: keys.rsa_unwrap(private_key, block)


def test_live_decryptor_matches_one_shot_for_random_splits(identity):
    private_key, public = identity
    data, ogg = make_file(public)
    expected = audio.decrypt_plaud(data, unwrapper(private_key)).ogg
    assert expected == ogg
    rng = random.Random(1234)
    splits = [[1] * 600 + [len(data)], [512, len(data)], [513, len(data)], [len(data)]]
    splits += [[rng.randint(1, 300) for _ in range(200)] for _ in range(20)]
    for sizes in splits:
        decryptor = live.LiveDecryptor(unwrapper(private_key))
        out, position = bytearray(), 0
        for size in sizes:
            if position >= len(data):
                break
            out += decryptor.feed(data[position : position + size])
            position += size
        out += decryptor.feed(data[position:])
        assert bytes(out) == expected
        assert decryptor.position == len(data)


def test_live_decryptor_rejects_wrong_key_length(identity):
    private_key, public = identity
    data, _ = make_file(public, pages=1)
    decryptor = live.LiveDecryptor(lambda _block: bytes(31))
    assert decryptor.feed(data[:512]) == b""
    with pytest.raises(audio.AudioError, match="key"):
        decryptor.feed(data[512:])


# --------------------------------------------------------------------------- follow_recording


class ScriptedDevice:
    """Answers the commands follow_recording sends, the way the Note Pro did on the wire."""

    def __init__(self, file, live_limit=None, recording=False, segments=None, drop_first=(), button_stop=False):
        self.file = file
        self.live_limit = len(file) if live_limit is None else live_limit
        self.recording = recording
        self.segments = segments  # explicit (offset, length) frames for the first live sync
        self.drop_first = set(drop_first)  # frame offsets lost on the first live sync
        self.button_stop = button_stop
        self.live_syncs = 0

    def frame(self, offset, length):
        return bytes([2]) + struct.pack("<IIB", SID, offset, length) + self.file[offset : offset + length]

    def frames(self, start, end, drop=()):
        return [self.frame(o, min(FRAME, end - o)) for o in range(start, end, FRAME) if o not in drop]

    def stop_event(self, reason):
        return bytes([1]) + struct.pack("<HIBBI", p.Cmd.RECORD_STOP, SID, reason, 1, len(self.file))

    def respond(self, packet):
        cmd = p.command_id(packet)
        if cmd == p.Cmd.TIME_SYNC:
            return [bytes([1]) + struct.pack("<HIbB", 4, 0, 0, 0)]
        if cmd == p.Cmd.GET_STATE:
            state, sid = (0x1003, SID) if self.recording else (0, 0)
            return [bytes([1]) + struct.pack("<HIBBHI", 3, state, 0, 1 if self.recording else 0, 0, sid)]
        if cmd == p.Cmd.RECORD_START:
            self.recording = True
            return [bytes([1]) + struct.pack("<HIIB", 20, SID, 0, 0)]
        if cmd == p.Cmd.RECORD_STOP:
            self.recording = False
            return [self.stop_event(1)]
        if cmd == p.Cmd.TAIL:  # host sync stop
            return [bytes([1]) + struct.pack("<HI", p.Cmd.SYNC_STOP_ACK, SID)]
        if cmd == p.Cmd.DOWNLOAD:
            sid, start, end = struct.unpack_from("<III", packet, 3)
            assert sid == SID
            out = [bytes([1]) + struct.pack("<HI", 28, SID) + b"\x00"]
            if end:  # bounded fetch: data, then the transfer tail
                return out + self.frames(start, end) + [bytes([1]) + struct.pack("<HIH", 29, SID, 0x1234)]
            self.live_syncs += 1
            first = self.live_syncs == 1
            if first and self.segments:
                out += [self.frame(o, n) for o, n in self.segments]
            else:
                out += self.frames(start, self.live_limit, self.drop_first if first else ())
            if self.button_stop:
                self.recording = False
                out.append(self.stop_event(2))
            return out
        raise AssertionError(f"unexpected command {packet.hex()}")


class FakeLiveLink:
    def __init__(self, device):
        self.device = device
        self.queue = asyncio.Queue()
        self.writes = []

    async def write(self, packet):
        self.writes.append(bytes(packet))
        check_outgoing(packet)
        for reply in self.device.respond(bytes(packet)):
            self.queue.put_nowait(reply)

    async def packet(self, timeout):
        try:
            return await asyncio.wait_for(self.queue.get(), timeout)
        except asyncio.TimeoutError:
            raise TimeoutError from None


@pytest.fixture(autouse=True)
def fast_timers(monkeypatch):
    monkeypatch.setattr(live, "POLL", 0.01)
    monkeypatch.setattr(live, "DRAIN_IDLE", 0.05)
    monkeypatch.setattr(live, "DRAIN_MAX", 2.0)
    monkeypatch.setattr(live, "COMMAND_TIMEOUT", 2.0)


def run_follow(device, stop_after=None, **kwargs):
    """Run follow_recording; set the stop event once `stop_after` bytes have arrived."""
    link = FakeLiveLink(device)
    received = bytearray()

    async def go():
        stop = asyncio.Event()

        def on_bytes(offset, data):
            assert offset == len(received)
            received.extend(data)
            if stop_after is not None and len(received) >= stop_after:
                stop.set()

        return await asyncio.wait_for(live.follow_recording(link, on_bytes, stop, **kwargs), 10)

    stats = asyncio.run(go())
    for packet in link.writes:
        assert p.command_id(packet) not in BLOCKED_COMMANDS
    return stats, link.writes, bytes(received)


def assert_time_sync_and_state(writes):
    assert writes[0][:3] == bytes.fromhex("010400") and len(writes[0]) == 9
    assert writes[1] == bytes.fromhex("010300")


def assert_decodes(private_key, received, ogg):
    decryptor = live.LiveDecryptor(unwrapper(private_key))
    assert decryptor.feed(received) == ogg


def test_requested_stop_drains_then_fetches_remainder(identity):
    private_key, public = identity
    data, ogg = make_file(public, pages=20)
    live_limit = len(data) - 3000  # the open-ended sync never sends the last few KB
    device = ScriptedDevice(data, live_limit=live_limit)
    stats, writes, received = run_follow(device, stop_after=live_limit)
    assert_time_sync_and_state(writes)
    assert writes[2:] == [
        p.build_record_start(),
        p.build_live_sync(SID, 0),
        p.build_record_stop(),
        p.build_sync_stop(),
        p.build_download_request(SID, live_limit, len(data)),
    ]
    assert received == data
    assert_decodes(private_key, received, ogg)
    assert (stats.session_id, stats.started_recording, stats.stop_reason) == (SID, True, "requested")
    assert stats.bytes == len(data) and stats.resyncs == 0
    assert any(f"file size {len(data)}" in e for e in stats.events)


def test_gap_triggers_resync_from_count(identity):
    private_key, public = identity
    data, ogg = make_file(public, pages=10)
    lost = 5 * FRAME
    device = ScriptedDevice(data, drop_first={lost})
    stats, writes, received = run_follow(device, stop_after=len(data))
    assert_time_sync_and_state(writes)
    assert writes[2:] == [
        p.build_record_start(),
        p.build_live_sync(SID, 0),
        p.build_sync_stop(),
        p.build_live_sync(SID, lost),
        p.build_record_stop(),
        p.build_sync_stop(),  # stop event size reached: close the sync, no bounded fetch
    ]
    assert stats.resyncs == 1 and received == data
    assert_decodes(private_key, received, ogg)


def test_duplicate_and_overlapping_frames_are_trimmed(identity):
    private_key, public = identity
    data, ogg = make_file(public, pages=6)
    segments = [(0, 180), (180, 180), (180, 180), (0, 100), (300, 200), (450, 50), (500, 200)]
    segments += [(o, min(FRAME, len(data) - o)) for o in range(700, len(data), FRAME)]
    device = ScriptedDevice(data, segments=segments)
    stats, writes, received = run_follow(device, stop_after=len(data))
    assert writes[2:] == [
        p.build_record_start(),
        p.build_live_sync(SID, 0),
        p.build_record_stop(),
        p.build_sync_stop(),
    ]
    assert received == data and stats.resyncs == 0
    assert_decodes(private_key, received, ogg)


def test_device_button_stop(identity):
    private_key, public = identity
    data, ogg = make_file(public, pages=8)
    device = ScriptedDevice(data, button_stop=True)
    stats, writes, received = run_follow(device)  # never requested
    assert_time_sync_and_state(writes)
    assert writes[2:] == [p.build_record_start(), p.build_live_sync(SID, 0), p.build_sync_stop()]
    assert p.build_record_stop() not in writes
    assert stats.stop_reason == "device" and received == data
    assert_decodes(private_key, received, ogg)


def test_button_stop_short_of_file_size_fetches_remainder(identity):
    _private_key, public = identity
    data, _ogg = make_file(public, pages=8)
    live_limit = len(data) - 1000
    device = ScriptedDevice(data, live_limit=live_limit, button_stop=True)
    stats, writes, received = run_follow(device)
    assert writes[2:] == [
        p.build_record_start(),
        p.build_live_sync(SID, 0),
        p.build_sync_stop(),
        p.build_download_request(SID, live_limit, len(data)),
    ]
    assert stats.stop_reason == "device" and received == data


def test_attach_and_leave_recording(identity):
    _private_key, public = identity
    data, _ogg = make_file(public, pages=4)
    device = ScriptedDevice(data, recording=True)
    stats, writes, received = run_follow(device, stop_after=len(data), stop_recording=False)
    assert_time_sync_and_state(writes)
    # No cmd 20 (already recording) and no cmd 23 (left recording). With no stop event the
    # sync closes once data has been idle for DRAIN_IDLE.
    assert writes[2:] == [p.build_live_sync(SID, 0), p.build_sync_stop()]
    assert not stats.started_recording and device.recording and received == data


def test_stream_output_files_are_private(tmp_path):
    import stat
    import wave

    from plaudio.cli import _private_file

    path = tmp_path / "x.live.wav"
    path.write_bytes(b"old")
    path.chmod(0o644)
    raw = _private_file(path)
    w = wave.open(raw, "wb")
    w.setnchannels(1), w.setsampwidth(2), w.setframerate(16000)
    w.writeframes(bytes(3200))
    w.close()
    raw.close()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    with wave.open(str(path)) as r:
        assert (r.getnchannels(), r.getframerate(), r.getnframes()) == (1, 16000, 1600)
