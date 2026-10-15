# /// script
# dependencies = ["bleak"]
# ///
"""Scan BLE for Plaud devices (service 0x1910 or name containing PLAUD)."""
import asyncio
from bleak import BleakScanner

PLAUD_SVC = "00001910-0000-1000-8000-00805f9b34fb"

async def main():
    found = await BleakScanner.discover(timeout=8, return_adv=True)
    for addr, (dev, adv) in found.items():
        name = adv.local_name or dev.name or ""
        if PLAUD_SVC in adv.service_uuids or "plaud" in name.lower():
            print(addr, repr(name), adv.rssi, adv.service_uuids, {k: v.hex() for k, v in adv.manufacturer_data.items()})
    print(f"{len(found)} devices seen")

asyncio.run(main())
