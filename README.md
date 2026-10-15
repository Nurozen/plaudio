# plaudio

plaudio is a Python library and command line tool that talks to a Plaud Note Pro voice
recorder directly over Bluetooth LE. It can:

- list the recordings on the device,
- pull them and decrypt them to Ogg Opus and 16 kHz mono WAV,
- start a recording and stream it live, with about 1 second of lag.

No Plaud app or cloud is involved at runtime. You need a one-time setup with your own Plaud
developer account (see below), and after that everything happens locally between your
computer and the recorder.

It has been tested on macOS. bleak also supports Linux and Windows, but those are untested.

## How trust works

The Note Pro only opens an encrypted session for a client that presents two things issued
by Plaud's developer platform:

- a signature over the recorder's serial number (`sn-sign`), and
- an RSA key pair (`gen-key`).

Each user needs their own Plaud developer account at
[portal.plaud.ai](https://portal.plaud.ai) and an Embedded SDK app there. `plaudio provision
--partner` uses those credentials once to call `gen-key` and `sn-sign` for your recorder and
saves the result locally. **No keys, tokens or signatures ship with plaudio.**

After provisioning, the device verifies everything offline. plaudio does not bypass any
authentication: it presents the same credentials the official tools would, issued to you by
Plaud.

Signing in to web.plaud.ai is not enough: web sign-in tokens are rejected by `sn-sign`, so
partner credentials are required.

## Binding warning

On a factory-fresh recorder, the **first handshake binds the device** to the token it
receives. plaudio derives that token from your own developer user token, prints every raw
handshake reply in hex, and never retries after a rejection (exit code 3).

Run `plaudio list --dry-run` first. It stops once the signature and key exchange succeed and
does not send the handshake.

## Install

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
git clone https://github.com/Nurozen/plaudio
cd plaudio
uv sync
uv run pytest -q
```

ffmpeg is needed for WAV output and live PCM (`brew install ffmpeg`). On macOS, the first BLE
command will ask for Bluetooth permission for your terminal.

## Usage

```sh
uv run plaudio scan                                   # passive scan, no connection
uv run plaudio provision --partner                    # one time: gen-key + sn-sign
uv run plaudio list --dry-run                         # key exchange only, no handshake
uv run plaudio list                                   # handshake (binds a fresh device) + list
uv run plaudio pull 1700000001 --out ~/plaud          # or: pull --all --out DIR
uv run plaudio decode ~/plaud/SERIAL-1700000001.plaud
```

`provision --partner` reads `PLAUD_CLIENT_ID`, `PLAUD_CLIENT_SECRET` and `PLAUD_USER_ID`, or
`~/.plaudio/developer.json` with the keys `clientId`, `clientSecret` and `userId`. It mints a
user token from those credentials itself. `--token` accepts an already-minted SDK user token
instead (raw JWT, `Bearer ...`, `@file`, or `-` for stdin). `--serial` skips the scan, and
`--domain platform-jp.plaud.ai` selects the JP region.

The identity is saved to `~/.plaudio/identity.json` with mode 0600 (set `PLAUDIO_HOME` to
change the directory). Commands print it with secrets redacted. Partial downloads go to
`OUT/.partial/` and resume automatically.

## Live streaming

`plaudio stream` starts a recording and decodes it while the device is still writing it.

```sh
uv run plaudio stream --seconds 30          # -> OUT/SERIAL-SESSION.live.{plaud,ogg,wav}
uv run plaudio stream --pcm | consumer      # raw 16 kHz mono s16le PCM on stdout, logs on stderr
uv run plaudio stream --leave-recording     # Ctrl-C closes the sync but keeps the device recording
```

Output goes to `~/plaudio-recordings` by default (`--out`), with mode 0600. If the device is
already recording, `stream` attaches to that session instead of starting a new one.
`scripts/live_transcribe.py` shows how to feed the PCM into faster-whisper.

How it works: there is no dedicated streaming command. plaudio syncs the clock, starts a
recording, and opens an open-ended file sync on the active session. The device streams the
session file itself (an encrypted header followed by ChaCha20-encrypted Ogg Opus), which
plaudio decrypts incrementally and pipes to ffmpeg. On stop, it drains up to the final file
size the device reports and fetches the last few KB with a bounded request, because the
open-ended sync never sends them. See [docs/protocol.md](docs/protocol.md) for details.

Measured on a Note Pro, with the live output byte-identical to the file stored on the device:

- first audio byte about 0.06 s after the record start,
- PCM lag about 0.9 to 1.7 s, steady,
- about 4.6 KB/s of encrypted audio.

## What is verified

Tested on a Note Pro (protocol 20):

- discovery, advertisement parsing and the GATT layout,
- partner provisioning (`gen-key` + `sn-sign`) and the key exchange,
- the handshake, including binding a factory-fresh device and reconnecting afterwards,
- listing, pulling and decrypting recordings,
- live streaming, start and stop.

Covered by unit tests but not separately confirmed on hardware:

- older protocol versions (session list strides, short handshake tokens),
- transfer status frames and some error paths,
- other Plaud models. Project 883 is accepted but untested; Note Pin and others are not
  supported.

Unknown or ambiguous:

- the download tail CRC algorithm (Ogg page CRCs are checked instead),
- most handshake reply fields beyond status, protocol and channel count,
- the public key string format the device expects for locally generated keys.

## Known dead ends

- **USB.** The Note Pro's USB CDC port stays silent; plaudio is BLE only.
- **Local RSA keys.** A locally generated key pair is rejected in practice: the device's
  wrapped session key does not decrypt under it. `--local-key` is kept but expected to fail;
  use the cloud `gen-key` pair.
- **web.plaud.ai tokens.** Rejected by `sn-sign` (`ACCESS_TOKEN_INVALID`).

## Safety

plaudio is built to never change or delete anything on the recorder:

- **Allowlist.** It only builds the commands it needs: key exchange, handshake, get state,
  time sync, battery, record start/stop, list, download/sync and sync stop.
- **Blocklist.** Every outgoing frame is checked against a list of commands believed to be
  destructive (unbind, delete one or all recordings, factory reset, firmware update, setting
  writes and others) and refused if it matches.
- The handshake is never retried after a rejection, and `--dry-run` lets you test the key
  exchange without it.

## Project layout

- `plaudio/protocol.py`: framing and parsers
- `plaudio/cipher.py`: session cipher
- `plaudio/keys.py`: RSA helpers
- `plaudio/audio.py`: `.plaud` decoding and WAV conversion
- `plaudio/provision.py`: partner API calls and identity storage
- `plaudio/session.py`: transport-agnostic flows
- `plaudio/live.py`: live capture
- `plaudio/client.py`: bleak client
- `plaudio/cli.py`: command line
- `docs/protocol.md`: protocol description
- `scripts/`: diagnostic scripts, see [scripts/README.md](scripts/README.md)

## Acknowledgements

plaudio's protocol framing, session cipher, file format handling and download logic are
ported from [OpenPlod](https://github.com/RemiPelloux/OpenPlod) (MIT, Copyright (c) 2026 Remi
Pelloux and OpenPlod contributors). OpenPlod notes an unresolved provenance question about
code it inherited from jddavenportOpen/openplaud. See
[THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for the full license text.

Background research from
[mar-maradnus/openplaudit](https://github.com/mar-maradnus/openplaudit) and
[Shawn-TKD/plaud-direct-pc-research](https://github.com/Shawn-TKD/plaud-direct-pc-research)
was also helpful.

## Disclaimer

plaudio is not affiliated with or endorsed by Plaud. "Plaud" and "Note Pro" are trademarks
of their respective owners.

This is an interoperability project for devices you own. Use it with your own recorder and
your own Plaud developer account, and check Plaud's developer terms before you do. Firmware
updates from Plaud may change the protocol and break plaudio at any time.

## License

MIT, see [LICENSE](LICENSE).
