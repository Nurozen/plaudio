# /// script
# dependencies = ["bleak"]
# ///
"""Connect to the Plaud Note Pro and dump its GATT table (read-only: reads readable chars, no writes)."""
import asyncio, sys
from bleak import BleakClient, BleakScanner

async def main():
    dev = await BleakScanner.find_device_by_filter(lambda d, a: (a.local_name or "").startswith("Plaud"), timeout=10)
    if not dev:
        sys.exit("Plaud not found")
    async with BleakClient(dev) as c:
        print("connected", dev.address, "mtu", c.mtu_size)
        for svc in c.services:
            print(f"svc {svc.uuid} {svc.description}")
            for ch in svc.characteristics:
                val = ""
                if "read" in ch.properties:
                    try:
                        v = await c.read_gatt_char(ch)
                        val = f" = {v.hex()} {v!r}"[:160]
                    except Exception as e:
                        val = f" (read err {e})"
                print(f"  chr {ch.uuid} {ch.properties}{val}")

asyncio.run(main())
