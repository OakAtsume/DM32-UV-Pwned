#!/usr/bin/env python3
"""Parse USB serial capture from tshark into readable protocol log."""

import subprocess
import sys
import re

if len(sys.argv) < 2:
    print("Usage: python3 parse_usbcap.py dm32_usb.pcap")
    sys.exit(1)

pcap = sys.argv[1]

# Use tshark to extract USB bulk transfer data
result = subprocess.run([
    "tshark", "-r", pcap,
    "-T", "fields",
    "-e", "frame.time_relative",
    "-e", "usb.endpoint_address",
    "-e", "usb.transfer_type",
    "-e", "usb.data_len",
    "-e", "usb.capdata",
    "-Y", "usb.capdata",
], capture_output=True, text=True)

if result.returncode != 0:
    # Try alternative field names
    result = subprocess.run([
        "tshark", "-r", pcap,
        "-T", "fields",
        "-e", "frame.time_relative",
        "-e", "usb.endpoint_address",
        "-e", "usb.urb_type",
        "-e", "data.len",
        "-e", "usb.capdata",
    ], capture_output=True, text=True)

print(f"{'='*70}")
print(f"DM-32UV USB Serial Capture: {pcap}")
print(f"{'='*70}")

for line in result.stdout.strip().split("\n"):
    if not line.strip():
        continue
    parts = line.split("\t")
    if len(parts) < 5:
        continue

    t = parts[0].strip()
    endpoint = parts[1].strip()
    transfer = parts[2].strip()
    length = parts[3].strip()
    hexdata = parts[4].strip().replace(":", " ")

    if not hexdata:
        continue

    # Endpoint 0x02/0x82 are typically bulk OUT/IN for CH340
    # OUT (host→device) = CPS→Radio, IN (device→host) = Radio→CPS
    is_out = endpoint in ["0x02", "02", "2"]
    direction = "CPS->RADIO" if is_out else "RADIO->CPS"

    # Convert hex to bytes
    try:
        data = bytes.fromhex(hexdata.replace(" ", ""))
    except:
        continue

    asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    print(f"[{t:>10s}] {direction:12s} ({len(data):3d}B): {hexdata:<60s} |{asc}|")

print(f"\n{'='*70}")
print("Done.")
