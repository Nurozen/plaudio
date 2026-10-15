# /// script
# requires-python = ">=3.10"
# dependencies = ["pyserial"]
# ///
"""Send a payload to the Plaud serial port and hexdump the response.

usage: probe.py <hex|text:...> [wait_secs] [port]
"""
import sys, time, serial

arg = sys.argv[1]
wait = float(sys.argv[2]) if len(sys.argv) > 2 else 1.5
port = sys.argv[3] if len(sys.argv) > 3 else "/dev/cu.usbmodem0123456789A1"
payload = arg[5:].encode().decode("unicode_escape").encode("latin1") if arg.startswith("text:") else bytes.fromhex(arg)

s = serial.Serial(port, 115200, timeout=0.1)
s.dtr = True
s.reset_input_buffer()
s.write(payload)
s.flush()
end = time.time() + wait
buf = b""
while time.time() < end:
    buf += s.read(4096)
print(f"> {payload!r}\n< {len(buf)} bytes")
for i in range(0, min(len(buf), 2048), 16):
    chunk = buf[i:i+16]
    print(f"{i:06x}  {chunk.hex(' '):<48}  {''.join(chr(c) if 32 <= c < 127 else '.' for c in chunk)}")
