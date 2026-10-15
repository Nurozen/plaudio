# /// script
# dependencies = ["bleak"]
# ///
"""Subscribe to Plaud notifications, then optionally send a bogus 0xFE10 signature to observe the auth gate.

Never sends the handshake (cmd 1): on older Plauds a handshake with an unknown token can rebind the device.
usage: ble_auth_probe.py [--bogus-sig]
"""
import asyncio, sys, os
from bleak import BleakClient, BleakScanner

NOTIFY = "00002bb0-0000-1000-8000-00805f9b34fb"
WRITE = "00002bb1-0000-1000-8000-00805f9b34fb"

def chunks(opcode, payload):
    total = -(-len(payload) // 100)
    return [opcode.to_bytes(2, "little") + bytes([total, i]) + payload[i*100:(i+1)*100] for i in range(total)]

async def main():
    dev = await BleakScanner.find_device_by_filter(lambda d, a: (a.local_name or "").startswith("Plaud"), timeout=10)
    if not dev:
        sys.exit("Plaud not found")
    async with BleakClient(dev, disconnected_callback=lambda c: print("** disconnected")) as c:
        await c.start_notify(NOTIFY, lambda _, d: print(f"< {bytes(d).hex()}"))
        print("subscribed; idle 4s")
        await asyncio.sleep(4)
        if "--bogus-sig" in sys.argv:
            for p in chunks(0xFE10, os.urandom(256)):
                print(f"> {p[:8].hex()}... ({len(p)}B)")
                await c.write_gatt_char(WRITE, p, response=True)
            await asyncio.sleep(6)

asyncio.run(main())
