# Plaud Note Pro BLE protocol

This describes the Bluetooth LE protocol spoken by a Plaud Note Pro, from the point of view
of a host talking to the device. It is a description of wire behaviour for
interoperability; it reproduces no vendor code. Where a detail has not been exercised against
hardware, it is tagged as such.

Each fact is tagged with where it comes from:

- **[observed]**: observed on a Note Pro (project 881, protocol 20) with plaudio.
- **[OpenPlod]**: reported by other open-source implementations, mainly
  [OpenPlod](https://github.com/RemiPelloux/OpenPlod), and covered by plaudio's unit tests
  against OpenPlod's vectors, but not separately confirmed on hardware.
- **[unverified]**: believed to be the layout but never exercised by plaudio. Treat with care.

All integers are little endian. Offsets are absolute byte positions in the plaintext frame
(byte 0 is the frame type).

## 1. Discovery and GATT

- Advertised name `Plaud Note Pro`. **[observed]**
- Service `0x1910`, notify characteristic `0x2BB0`, write characteristic `0x2BB1` (write with
  response). Negotiated MTU 247 on macOS. **[observed]**
- One notification carries exactly one protocol packet. **[observed]**

Manufacturer data, company id `0x005D`. Shown with the company id in front (some BLE stacks,
such as bleak, strip it):

| Offset | Size | Meaning |
|---|---|---|
| 0 | 2 | company id `5d 00` |
| 2 | 1 | `0x02` |
| 3 | 2 | project id (881 = Note Pro; 883 also accepted) |
| 5 | 1 | `0x04` |
| 6 | 4 | unknown |
| 10 | 1 | `0x08` (serial length) |
| 11 | 8 | serial, rendered as 16 uppercase hex characters |
| 19 | 1 | unknown |
| 20 | 2 | protocol version (20 on the Note Pro; >= 20 means the link is encrypted) |
| 22.. | | unknown |

Example (synthetic serial): `5d00 02 7103 04 56000701 08 8810000000000001 44 1400 040100`.
**[observed]** layout, **[OpenPlod]** field names.

## 2. Framing

- Command frame: `[type u8][cmd u16][payload]`. Type 1 = command / response / event,
  type 2 = file data. **[observed]**
- Types 4 (throughput test data) and 5 (device log data) exist. **[unverified]**
- Pre-handshake frames (before encryption) have no type byte:
  `[opcode u16][total u8][index u8][<= 100 payload bytes]`. **[observed]**
- Responses are matched on the response cmd id. It is usually the request id, but not
  always: sync stop is request 29, ack 30. **[observed]**

## 3. Key exchange

Runs right after connecting, unencrypted, using pre-handshake frames.

1. Host sends `0xFE10` with the device signature: the binary result of the cloud `sn-sign`
   call for this serial, split into 100-byte chunks. **[observed]**
2. Device answers `0xFE11` if it accepts the signature. A bogus signature makes the device
   disconnect, so a real signature is required. **[observed]**
3. Host sends `0xFE12` with its public key, as the UTF-8 bytes of the string returned by the
   cloud `gen-key` call. **[observed]** The exact string format the device expects is not
   known; sending the `gen-key` string unchanged works. **[OpenPlod]**
4. Device answers `0xFE12` in up to 3 chunks, together 256 bytes: an RSA-2048 PKCS#1 v1.5
   ciphertext under the host's key. **[observed]**

A locally generated RSA key pair is rejected in practice: the device's reply does not
decrypt under it, so the cloud `gen-key` pair is required. **[observed]**

The decrypted material is 80 bytes:

```
key[0:32] | nonce[32:44] | associated_data[44:56] | seal("PLAUD.AI")[56:80]
```

The last 24 bytes are the ChaCha20-Poly1305 seal of the 8-byte marker `PLAUD.AI` under that
key, nonce and AD. Opening it verifies the exchange. **[observed]**

### Session cipher

Every later packet in both directions is ChaCha20-Poly1305 with the same key, nonce and AD
(the nonce is fixed, not per packet). The plaintext is `[counter u32][frame]`:

- host to device: counter starts at 2 and increases by 1 per packet;
- device to host: counter must strictly increase; a frame that does not is dropped.

**[observed]**, with the CryptoKit test vector from **[OpenPlod]**.

## 4. Handshake (cmd 1) and binding

Request payload: `[0x02][0x00][mode u8][token]`.

- `token` is 32 ASCII characters for protocol >= 9 (16 below), truncated or right-padded
  with `'0'`. **[observed]** for 32.
- `mode` is 0. The third option byte is absent below protocol 3. **[OpenPlod]**

Token derivation rule: take the `sub` claim of the user access token, drop a
`client_user_` prefix if present, remove every `-`, then truncate or pad to 32. This matches
the token derivation the official SDK uses on the wire. **[observed]**: a factory-fresh
recorder bound with this token and accepted the same token on every reconnect.

**Binding.** On a factory-fresh recorder the first handshake binds the device to the token
it receives. Later handshakes with a different token are expected to fail. **[observed]** for
the first part. Never retry a rejected handshake blindly.

Reply (cmd 1):

| Offset | Meaning | Source |
|---|---|---|
| 3 | status, 0 = accepted | **[observed]** |
| 4 | protocol version u16 (20) | **[observed]** |
| 8 | audio channels (1 on the Note Pro) | **[observed]** |
| 11 | 1 = audio is Ogg-wrapped Opus | **[observed]** value 1 |
| 6, 7 | timezone hours / minutes | **[unverified]** |
| 9, 10 | Wi-Fi support, noise suppression / AGC flags | **[unverified]** |
| last 4 | firmware version: type char + u24 | **[unverified]** |

If the device answers with cmd 2 (serial info, >= 59 bytes) instead, resend the same request
once with byte 5 (mode) set to 1. **[OpenPlod]**

After the handshake, send a time sync (cmd 4) before starting a recording. **[observed]**
that this sequence works; whether the device requires it is **[unverified]**.

## 5. Session list (cmd 26)

Request payload: `[requestId u32][cursor u32][ascending u8]`. **[observed]**

Response pages, possibly repeated or out of order:

```
01 1a 00 | requestId u32 | total u16 | offset u16 | entries
```

Entry stride depends on protocol version: 10 bytes for >= 7, 9 for 2..6, 8 for 1.
**[observed]** for 10, **[OpenPlod]** for the others.

```
sessionId u32 | size u32 | timezone u8 (stride 10 only) | scene u8 (absent at stride 8)
```

Session ids look like Unix timestamps of the recording start. `size` is the file size in
bytes. Collect pages until `total` entries are known; reject duplicate ids. **[observed]**

## 6. File download (cmd 28)

Request payload: `[sessionId u32][start u32][end u32]`. A nonzero `end` requests the range
`[start, end)`. **[observed]**

Replies:

- Head: `01 1c 00 | sessionId u32 | status u8`, status 0 = ok. **[observed]**
- Data, type 2: `[02][sessionId u32][offset u32][len u8][len bytes]`. `offset` is the byte
  position in the session file; chunks arrive contiguously. **[observed]**
- A data frame with `offset == 0xFFFFFFFF` carries a status code at byte 10 instead of data.
  Code 1 is benign; anything else means the device stopped the transfer. **[OpenPlod]**
- Tail: `01 1d 00 | sessionId u32 | crc u16`. The CRC algorithm is unknown, so plaudio
  records it but validates the Ogg page CRCs instead. **[observed]** layout.

Resuming is a new request with `start` set to the bytes already held. **[observed]**
On protocol < 7 the data frame has no session id: `[02][offset u32][len u8][data]`.
**[unverified]**

## 7. Live recording

There is no dedicated streaming command. Live audio is an ordinary file sync that follows a
recording while the device is still writing it. **[observed]**

Sequence used by plaudio:

1. Time sync (cmd 4), wait for the cmd 4 reply.
2. Get state (cmd 3). If the device is already recording, attach to that session.
3. Otherwise start recording: cmd 20, payload `[mode=1][scene=1]`.
4. Open an open-ended sync: cmd 28 with `start = 0` and `end = 0`. Starting at 0 delivers the
   file header, which carries the file key.
5. Decrypt and decode type-2 frames as they arrive (see section 9).
6. Stop: cmd 23, payload `[mode=1][scene=1]`.
7. Drain and close (below).

**[observed]** for the whole sequence.

### Record start reply / event (cmd 20)

`@3 sessionId u32`, `@7 start u32` (a file offset to begin a live sync from), `@11 status u8`.
Status 0 = started. **[observed]** Status 4 is also treated as success and probably means
"already recording". **[unverified]** Optional `@12 scene u8`, `@13 startTime u32`.
**[unverified]**

### Record stop reply / event (cmd 23)

`@3 sessionId u32`, `@7 reason u8`, `@8 fileExists u8 (1 = yes)`, `@9 fileSize u32`.
The last two may be absent. **[observed]**

Example (synthetic session id 1700000001): `01 17 00 | 01 f1 53 65 | 02 | 01 | 00 00 01 00`
is reason 2, file exists, final size 65536.

The device sends the same cmd 20/21/22/23 frames unsolicited when recording is started,
paused, resumed or stopped with its button. plaudio handles a button stop exactly like a
requested stop. **[unverified]** for pause and resume.

### Sync stop (cmd 29) and its ack (cmd 30)

Host sends cmd 29 with an empty payload to close a sync. The device acks with cmd 30.
**[observed]** Note that a host-sent cmd 30 is believed to delete a recording; see
section 11.

### Drain to file size, then a bounded fetch

An open-ended sync sends no tail. After a stop:

1. Keep reading data frames until the held byte count reaches `fileSize` from the stop
   event.
2. The open-ended sync never delivers the last few KB. Once it stalls (plaudio waits 2 s with
   no data, at most 15 s overall), close it with cmd 29 and wait for cmd 30.
3. Fetch the remainder with a bounded cmd 28 (`start` = bytes held, `end` = `fileSize`).
   This one ends with a normal tail.

**[observed]**: the resulting file is byte-identical to the one stored on the device.

### Gaps and duplicates

If a data frame's offset is ahead of the bytes held, close the sync (cmd 29, wait for 30)
and reopen it (cmd 28, `end = 0`) from the last good offset. Trim frames that overlap bytes
already held. Ignore frames with a different session id. **[observed]** for the handling;
gaps themselves are rare.

### Measured timing (Note Pro)

- First file byte about 0.06 s after the record start.
- About 4.6 KB/s of encrypted Ogg while recording; backlog from offset 0 catches up at about
  5x real time.
- Decoded PCM lags real time by about 0.9 to 1.4 s, steady.

**[observed]**

## 8. State, time sync, battery, other getters

| What | cmd | Request | Reply | Source |
|---|---|---|---|---|
| Time sync | 4 | `[unixSeconds u32][tzHours i8][tzMinutes i8]` (negative for west) | cmd 4; `@3 stamp u32`, `@7 tz i8`, `@8 hasStatistics u8` | **[observed]** request and reply id, **[unverified]** reply fields |
| Get state | 3 | none | see below | **[observed]** |
| Battery | 9 | none | `@3 charging u8`, `@4 level u8` (percent) | **[unverified]** |
| Storage | 6 | none | `@3 free u64`, `@11 total u64`, `@19 duration u64` | **[unverified]** |
| Read setting | 8 | `[0x01][settingId u16]` | `@3 settingId u16`, `@5 value u32` | **[unverified]** |
| Get serial | 2 | none | serial info | **[unverified]** |
| Sub-firmware version | 54 | none | | **[unverified]** |
| Detailed status | 141 | none | `@3` 4 raw bytes | **[unverified]** |

Get state reply: `@3 state u32`, `@7 privacy u8`, `@8 keyState u8`, `@9 usb u8`,
`@10 scene u8`, `@11 sessionId u32` (the active recording), `@15 findMy u8`.

- `state == 0x1003` means recording, and `@11` is then the active session id. **[observed]**
- Otherwise `keyState`: 0 idle, 1 record, 2 transfer, 3 switch on, 4 switch off.
  **[observed]** for 0, **[unverified]** for the rest.

Unsolicited notifications besides the record events: 3 state changed, 6 storage changed,
8 setting changed, 9 battery changed, 10 Wi-Fi mode, 50 firmware update result,
126 Wi-Fi sync start, 138 feature bitmap, 141 detailed status, 144/145 log sync end/stop.
**[unverified]**. plaudio ignores anything it is not waiting for.

## 9. File format (`.plaud`)

The session file, both as downloaded and as streamed live:

| Offset | Size | Meaning |
|---|---|---|
| 0 | 8 | `PLAUD.AI` |
| 8 | 2 | version, 1 |
| 10 | 2 | header size, 512 |
| 48 | 2 | 1 (only value seen; possibly codec) |
| 50 | 2 | channels (1 or 2) |
| 52 | 2 | 1 (only value seen; possibly cipher) |
| 128 | 4 | ChaCha20 block counter, 0 |
| 132 | 12 | ChaCha20 nonce |
| 256 | 256 | RSA-2048 PKCS#1 v1.5 wrapped 32-byte file key (same RSA key as the key exchange) |
| 512.. | | raw ChaCha20 (RFC 8439, no tag) of an Ogg Opus stream |

**[observed]**, layout first described by **[OpenPlod]**.

Raw ChaCha20 is unauthenticated. Accept the result only if every Ogg page CRC, per-stream
page sequence and end-of-stream flag checks out. ChaCha20 is seekable by 64-byte block, so
the body can be decrypted incrementally while a live sync is still running.

## 10. Codec

- Note Pro: Ogg Opus inside the `.plaud` body (handshake byte 11 = 1). Mono. Recorded
  levels sit around -37 dBFS, quieter than most speech-to-text models expect. **[observed]**
- Models without Ogg wrapping are reported to send raw Opus: 16 kHz, CBR, 80 bytes per 20 ms
  frame per channel (32 kbps mono), sliced every `channels * 80` bytes with no container.
  **[unverified]**
- When piping live Ogg to ffmpeg, do not use `-fflags nobuffer`: it drops audio. **[observed]**

## 11. Never send

These commands are believed to be destructive, irreversible, or to end the connection.
plaudio refuses to build or send them. None of them has been tested, on purpose.
**[unverified]**

| cmd | What |
|---|---|
| 5 | Unbind / depair |
| 7 | Reset password |
| 8 with byte 3 = 2 | Setting write (reads, byte 3 = 1, are harmless). Setting 4 is auto delete recordings |
| 12 | Clear data |
| 13 | Reset / close Wi-Fi |
| 30 | Delete one recording, payload `[sessionId u32]` (the device-to-host cmd 30 is the sync stop ack) |
| 50, 51, 52 | Firmware update start / pack finish / pack |
| 102 | Restore factory settings |
| 103 | Privacy set |
| 104 | Delete all recordings |
| 105 | Unnamed; the link drops right after (possibly power off) |
| 109 | Set device active flag |
| 121, 125 | Write / delete Wi-Fi sync configuration |
| 128 | Reset Find My |
| 151 | OTA file info |
| any | Outgoing frames of type 2, 3 or 5 (bulk / OTA data) |

Also avoid unless you know why you need them: 10 (open Wi-Fi), 14 to 17 (router SSID,
websocket URL), 61 (statistics sync), 101 (throughput test), 143 (log dump).

plaudio's own allowlist: pre-handshake `0xFE10` and `0xFE12`, then commands 1, 3, 4, 9, 20,
23, 26, 28 and 29. Every outgoing frame is also checked against the blocklist above.
