# scripts

Standalone diagnostic scripts, kept for anyone poking at a recorder. Each declares its own
dependencies inline, so run them with `uv run scripts/NAME.py`. None of them is needed to use
plaudio.

BLE (need a recorder in range; none sends a handshake or anything that changes the device):

- `ble_scan.py`: passive scan; prints Plaud devices and their manufacturer data.
- `ble_gatt.py`: connects and dumps the GATT table, reading readable characteristics. No writes.
- `ble_auth_probe.py`: subscribes to notifications; with `--bogus-sig` it sends a random
  `0xFE10` signature to show that the device disconnects on a bad signature.

USB (the Note Pro's USB CDC port stayed silent in every test; kept for completeness). The
default port `/dev/cu.usbmodem0123456789A1` is the Realtek SDK default serial; pass your own
as an argument if it differs:

- `listen.py [port] [seconds]`: passively hexdumps whatever the port sends.
- `probe.py <hex|text:...> [wait] [port]`: sends one payload and hexdumps the response.
- `write_sink_test.py [port]`: writes 64 KB of zeros to see whether the device drains or
  blocks writes on its CDC OUT pipe.

Live transcription:

- `live_transcribe.py`: reads 16 kHz mono s16le PCM on stdin and transcribes it with
  faster-whisper. Pipe `plaudio stream --pcm --no-wav` into it.
