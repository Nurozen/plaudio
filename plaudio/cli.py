"""plaudio command line: scan, provision, list, pull, stream, decode."""

from __future__ import annotations

import argparse
import asyncio
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from . import keys
from .protocol import HandshakeRejected
from .provision import load_partner_credentials, DEFAULT_DOMAIN, PLAUD_DOMAINS, ProvisionError, Provisioner, identity_path, load_identity, save_identity


def _read_token(value: str | None) -> str:
    """Token from --token VALUE, --token @file, --token - (stdin) or an interactive prompt."""
    if value is None:
        return getpass.getpass("Paste a partner-minted Plaud user token (input hidden): ")
    if value == "-":
        return sys.stdin.read()
    if value.startswith("@"):
        return Path(value[1:]).expanduser().read_text()
    return value


async def _cmd_scan(args) -> int:
    from .client import scan

    devices = await scan(args.timeout)
    if not devices:
        print("no Plaud recorders found")
        return 1
    for found in devices:
        adv = found.advertisement
        info = f"project {adv.project} serial {adv.serial} protocol {adv.protocol_version}" if adv else "no manufacturer data"
        print(f"{found.device.address}  {found.name!r}  rssi {found.rssi}  {info}")
    return 0


async def _cmd_provision(args) -> int:
    serial, identifier, protocol_version = args.serial, args.identifier or "", 20
    if not serial:
        from .client import scan

        print("no --serial given; scanning passively for the recorder ...")
        devices = [d for d in await scan(args.timeout) if d.advertisement]
        if len(devices) != 1:
            print(f"found {len(devices)} recorders; pass --serial (and --identifier)", file=sys.stderr)
            return 1
        serial = devices[0].advertisement.serial
        identifier = identifier or devices[0].device.address
        protocol_version = devices[0].advertisement.protocol_version
    provisioner = Provisioner()
    if args.partner:
        creds = load_partner_credentials()
        if not creds:
            print("--partner needs PLAUD_CLIENT_ID/PLAUD_CLIENT_SECRET or ~/.plaudio/developer.json", file=sys.stderr)
            return 1
        token = provisioner.partner_user_token(creds, args.domain)
        print("minted SDK user token from partner credentials")
    else:
        token = _read_token(args.token)
    identity = provisioner.provision(
        token,
        serial.upper(),
        identifier=identifier,
        domain=args.domain,
        protocol_version=protocol_version,
        local_key=args.local_key,
        public_key_format=args.public_key_format,
    )
    path = save_identity(identity, Path(args.identity) if args.identity else None)
    print(f"saved identity to {path} (0600)")
    print(json.dumps(identity.redacted(), indent=2))
    if args.local_key:
        print("note: --local-key is UNVERIFIED; if the device rejects the key exchange, re-run without it.")
    return 0


def _load(args):
    return load_identity(Path(args.identity) if args.identity else None)


async def _cmd_list(args) -> int:
    from .client import PlaudClient

    client = PlaudClient(_load(args), print, handshake=not args.dry_run)
    async with client as plaud:
        if args.dry_run:
            print("dry run complete: signature and key exchange accepted, no handshake sent")
            return 0
        sessions = await plaud.list_sessions()
    for s in sessions:
        print(f"{s.session_id}\t{s.size}\tscene={s.scene}\ttz={s.timezone}")
    print(f"{len(sessions)} recordings")
    return 0


async def _cmd_pull(args) -> int:
    from .client import pull

    ids = None if args.all else [int(v) for v in args.session_ids]
    if ids is not None and not ids:
        print("give session ids or --all", file=sys.stderr)
        return 2
    written = await pull(
        _load(args), Path(args.out).expanduser(), ids, wav=not args.no_wav
    )
    for path in written:
        print(path)
    return 0


def _private_file(path: Path):
    """Open PATH for binary writing with mode 0600, like client._atomic_write."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "wb")


async def _cmd_stream(args) -> int:
    """Start a recording and decode it live. Ctrl-C (or --seconds) stops it cleanly."""
    import signal
    import time
    import wave

    from .client import PlaudClient
    from .live import LiveDecryptor, PcmSink
    from .session import local_unwrap

    identity = _load(args)
    out = Path(args.out).expanduser()
    out.mkdir(parents=True, exist_ok=True)
    log = lambda m: print(m, file=sys.stderr, flush=True)  # noqa: E731
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    loop.add_signal_handler(signal.SIGINT, stop.set)

    decryptor = LiveDecryptor(local_unwrap(identity.privateKey))
    files: dict[str, object] = {}
    record_started = time.monotonic()

    def on_pcm(chunk: bytes) -> None:
        if args.pcm:
            sys.stdout.buffer.write(chunk)
            sys.stdout.buffer.flush()
        if "wav" in files:
            files["wav"].writeframes(chunk)

    sink = PcmSink(on_pcm)

    def on_bytes(offset: int, data: bytes) -> None:
        if not files:
            stem = f"{identity.serial}-{session['id']}.live"
            files["plaud"] = _private_file(out / f"{stem}.plaud")
            files["ogg"] = _private_file(out / f"{stem}.ogg")
            if not args.no_wav:
                raw = _private_file(out / f"{stem}.wav")
                w = wave.open(raw, "wb")
                w.setnchannels(1), w.setsampwidth(2), w.setframerate(16000)
                files["wav"] = w
                files["wav_file"] = raw  # wave does not close a file object it was given; close after "wav"
        files["plaud"].write(data)
        ogg = decryptor.feed(data)
        files["ogg"].write(ogg)
        sink.write(ogg)

    session = {"id": 0}

    def on_session(session_id: int) -> None:
        nonlocal record_started
        session["id"], record_started = session_id, time.monotonic()
        if args.seconds:
            loop.call_later(args.seconds, stop.set)

    async def meter() -> None:
        while not stop.is_set():
            await asyncio.sleep(1)
            if sink.pcm_bytes:
                elapsed = time.monotonic() - record_started
                log(f"  recorded {elapsed:6.1f}s  decoded {sink.seconds:6.1f}s  lag {elapsed - sink.seconds:5.2f}s  bytes {decryptor.position}")

    client = PlaudClient(identity, log)
    async with client as plaud:
        meter_task = asyncio.create_task(meter())
        try:
            stats = await plaud.follow_recording(on_bytes, stop, stop_recording=not args.leave_recording, on_session=on_session)
        finally:
            stop.set()
            await meter_task
    await sink.close()
    for f in files.values():
        f.close()
    first = (stats.first_byte_at - record_started) if stats.first_byte_at else float("nan")
    first_pcm = (sink.first_pcm_at - record_started) if sink.first_pcm_at else float("nan")
    log(f"session {stats.session_id}: {stats.bytes} bytes, {sink.seconds:.1f}s audio, stop={stats.stop_reason}, "
        f"resyncs={stats.resyncs}, first byte +{first:.2f}s, first PCM +{first_pcm:.2f}s")
    for e in stats.events[-10:]:
        log(f"  event: {e}")
    if files:
        log(f"wrote {out}/{identity.serial}-{stats.session_id}.live.{{plaud,ogg{',wav' if not args.no_wav else ''}}}")
    return 0


async def _cmd_decode(args) -> int:
    from .client import decode_file

    identity = _load(args)
    ogg, wav = decode_file(Path(args.file), identity.privateKey, Path(args.out) if args.out else None, wav=not args.no_wav)
    print(ogg)
    if wav:
        print(wav)
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="plaudio", description=__doc__)
    parser.add_argument("-v", "--verbose", action="store_true")
    parser.add_argument("--identity", help=f"identity file (default {identity_path()})")
    sub = parser.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="passive BLE scan for Plaud recorders (no connection)")
    s.add_argument("--timeout", type=float, default=8.0)
    s.set_defaults(func=_cmd_scan)

    s = sub.add_parser("provision", help="one-time gen-key + sn-sign; writes ~/.plaudio/identity.json")
    s.add_argument("--token", help="JWT, JSON blob, '@file' or '-' for stdin (prompted if omitted)")
    s.add_argument("--partner", action="store_true", help="mint the token from Embedded SDK app credentials (portal.plaud.ai)")
    s.add_argument("--serial", help="16-hex serial (scanned from the advertisement if omitted)")
    s.add_argument("--identifier", help="CoreBluetooth UUID of the recorder (optional)")
    s.add_argument("--domain", choices=PLAUD_DOMAINS, default=DEFAULT_DOMAIN)
    s.add_argument("--local-key", action="store_true", help="generate the RSA key pair locally; only sn-sign uses the cloud (UNVERIFIED)")
    s.add_argument("--public-key-format", choices=keys.PUBLIC_KEY_FORMATS, default="pkcs1", help="string format of the local public key")
    s.add_argument("--timeout", type=float, default=8.0)
    s.set_defaults(func=_cmd_provision)

    s = sub.add_parser("list", help="list recordings on the device (first run BINDS a fresh recorder to your token)")
    s.add_argument("--dry-run", action="store_true", help="stop after the encrypted session is verified; no handshake")
    s.set_defaults(func=_cmd_list)

    s = sub.add_parser("pull", help="download recordings and decode to .ogg/.wav")
    s.add_argument("session_ids", nargs="*")
    s.add_argument("--all", action="store_true")
    s.add_argument("--out", required=True)
    s.add_argument("--no-wav", action="store_true")
    s.set_defaults(func=_cmd_pull)

    s = sub.add_parser("stream", help="start a recording and decode it live (Ctrl-C stops)")
    s.add_argument("--out", default="~/plaudio-recordings")
    s.add_argument("--seconds", type=float, help="stop after N seconds")
    s.add_argument("--pcm", action="store_true", help="write raw 16 kHz mono s16le PCM to stdout")
    s.add_argument("--no-wav", action="store_true")
    s.add_argument("--leave-recording", action="store_true", help="on stop, close the sync but keep the device recording")
    s.set_defaults(func=_cmd_stream)

    s = sub.add_parser("decode", help="decrypt a downloaded .plaud file")
    s.add_argument("file")
    s.add_argument("--out")
    s.add_argument("--no-wav", action="store_true")
    s.set_defaults(func=_cmd_decode)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING, format="%(message)s")
    try:
        return asyncio.run(args.func(args))
    except HandshakeRejected as error:
        print(f"error: {error}\nThe handshake was NOT retried. Inspect the raw status before trying again.", file=sys.stderr)
        return 3
    except (ProvisionError, keys.RSAKeyError, ValueError, ConnectionError, TimeoutError) as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
