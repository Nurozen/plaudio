# /// script
# requires-python = ">=3.10,<3.14"
# dependencies = ["faster-whisper", "numpy"]
# ///
"""Transcribe 16 kHz mono s16le PCM from stdin in near real time.

    uv run python -m plaudio stream --pcm --no-wav | uv run scripts/live_transcribe.py

Cuts the stream at pauses (or every --max-window seconds), normalizes gain (Plaud audio sits
around -37 dBFS, too quiet for Whisper's VAD), and prints each segment as it's decoded.
"""
import argparse
import sys
import time

import numpy as np
from faster_whisper import WhisperModel

RATE = 16000


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="base.en")
    ap.add_argument("--max-window", type=float, default=8.0)
    ap.add_argument("--min-window", type=float, default=2.0)
    ap.add_argument("--silence-db", type=float, default=-50.0, help="frame RMS below this counts as a pause")
    args = ap.parse_args()

    model = WhisperModel(args.model, device="cpu", compute_type="int8")
    print(f"[ready: {args.model}]", file=sys.stderr, flush=True)
    buf = np.zeros(0, np.float32)
    total = 0.0  # seconds of audio consumed
    frame = RATE // 10  # 100 ms

    def flush(audio: np.ndarray, t0: float) -> None:
        peak = float(np.abs(audio).max()) if audio.size else 0.0
        if peak < 1e-3:
            return
        started = time.monotonic()
        segments, _ = model.transcribe(audio / peak * 0.9, vad_filter=False, condition_on_previous_text=False)
        text = " ".join(s.text.strip() for s in segments).strip()
        if text:
            print(f"[{t0:6.1f}s +{time.monotonic() - started:.1f}s] {text}", flush=True)

    while chunk := sys.stdin.buffer.read(frame * 2):
        samples = np.frombuffer(chunk[: len(chunk) // 2 * 2], np.int16).astype(np.float32) / 32768
        buf = np.concatenate([buf, samples])
        seconds = buf.size / RATE
        rms_db = 20 * np.log10(max(1e-9, float(np.sqrt(np.mean(samples**2)))))
        if seconds >= args.max_window or (seconds >= args.min_window and rms_db < args.silence_db):
            flush(buf, total)
            total += seconds
            buf = np.zeros(0, np.float32)
    flush(buf, total)


main()
