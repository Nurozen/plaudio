# /// script
# dependencies = ["pyserial"]
# ///
"""Check whether the device's CDC OUT pipe drains writes (accepts) or NAKs them (blocks)."""
import sys, time, serial
port = sys.argv[1] if len(sys.argv) > 1 else "/dev/cu.usbmodem0123456789A1"
s = serial.Serial(port, 115200, timeout=0.2, write_timeout=3)
s.dtr = True
t = time.time()
try:
    n = s.write(b"\x00" * 65536)
    s.flush()
    print(f"wrote {n} bytes in {time.time()-t:.3f}s (device is draining the OUT pipe)")
except serial.SerialTimeoutException:
    print(f"write timed out after {time.time()-t:.1f}s (device is NAKing OUT)")
print(f"read back {len(s.read(65536))} bytes")
