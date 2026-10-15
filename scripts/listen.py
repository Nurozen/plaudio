# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial"]
# ///
"""Passively read from the Plaud serial port and hexdump whatever arrives."""
import sys, time, serial

port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbmodem0123456789A1"
secs = float(sys.argv[2]) if len(sys.argv) > 2 else 5
s = serial.Serial(port, 115200, timeout=0.2)
s.dtr = True
s.rts = True
end = time.time() + secs
buf = b""
while time.time() < end:
    buf += s.read(4096)
print(f"{len(buf)} bytes")
for i in range(0, min(len(buf), 1024), 16):
    chunk = buf[i:i+16]
    print(f"{i:06x}  {chunk.hex(' '):<48}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
