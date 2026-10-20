#!/usr/bin/env python3
"""DM-32UV: Focus on what happens after PROGRAM ACK.
The radio shows 'computer program' screen — we need the right follow-up."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def fresh():
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.8)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(0.3)
    return ser

def tx(ser, data, label=""):
    if isinstance(data, str): data = data.encode('ascii')
    print(f"  TX [{label}]: {data.hex(' ').upper()}")
    ser.write(data)
    ser.flush()

def rx(ser, size=256, timeout=2):
    ser.timeout = timeout
    data = ser.read(size)
    if data:
        asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data)
        print(f"  RX ({len(data)}B): {data.hex(' ').upper()}  |{asc}|")
    else:
        print("  RX: (timeout)")
    return data

def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        c = data[i:i+16]; h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{prefix}{i:04X}: {h:<48s} |{a}|")
    return "\n".join(lines)

def enter_program(ser):
    """PSEARCH → SYSINFO → PROGRAM (bypass)."""
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("  PSEARCH fail"); return False
    time.sleep(0.05)
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.2)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("  SYSINFO fail"); return False
    time.sleep(0.05)
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    if not r or r[0] != 0x06:
        print("  PROGRAM fail"); return False
    print("  PROGRAM ACK!")
    return True


# ============================================================
# Test different post-PROGRAM sequences
# ============================================================

tests = [
    # A: Standard mode 02 with long waits
    ("A: mode 02 with 3s wait", lambda ser: [
        time.sleep(3.0),
        ser.reset_input_buffer(),
        tx(ser, b"\x02", "mode 02"),
        time.sleep(2.0),
        rx(ser, 16, timeout=3),
    ]),
    # B: Direct read immediately
    ("B: direct READ immediately", lambda ser: [
        time.sleep(0.5),
        ser.reset_input_buffer(),
        tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ 0x000000"),
        time.sleep(1.0),
        rx(ser, 300, timeout=5),
    ]),
    # C: Send 0x06 (ACK) first, then read
    ("C: ACK then READ", lambda ser: [
        time.sleep(0.5),
        ser.reset_input_buffer(),
        tx(ser, b"\x06", "ACK"),
        time.sleep(0.5),
        rx(ser, 8),
        tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ"),
        time.sleep(1.0),
        rx(ser, 300, timeout=5),
    ]),
    # D: Send 0x02 0x02 0x02 (multiple)
    ("D: triple mode 02", lambda ser: [
        time.sleep(1.0),
        ser.reset_input_buffer(),
        tx(ser, b"\x02\x02\x02", "3x mode 02"),
        time.sleep(2.0),
        rx(ser, 32, timeout=3),
    ]),
    # E: V-frame after PROGRAM
    ("E: V-frame 0x01 after PROGRAM", lambda ser: [
        time.sleep(0.5),
        ser.reset_input_buffer(),
        tx(ser, bytes([0x56, 0x00, 0x00, 0x00, 0x01]), "V-frame 0x01"),
        time.sleep(0.5),
        rx(ser, 64, timeout=3),
    ]),
    # F: Monitor what radio sends (passive listen)
    ("F: passive listen 5 seconds after PROGRAM", lambda ser: [
        print("  Listening..."),
        *[
            (time.sleep(0.5), rx(ser, 64, timeout=0.5))
            for _ in range(10)
        ],
    ]),
    # G: Send 0x02 then immediately 0x06
    ("G: mode02 + immediate ACK", lambda ser: [
        time.sleep(1.0),
        ser.reset_input_buffer(),
        tx(ser, b"\x02", "mode 02"),
        time.sleep(0.1),
        tx(ser, b"\x06", "immediate ACK"),
        time.sleep(2.0),
        rx(ser, 32, timeout=3),
    ]),
    # H: Send PROGRAM preamble (FF FF FF FF 0C) then mode 02
    ("H: FF preamble then mode 02", lambda ser: [
        time.sleep(0.5),
        ser.reset_input_buffer(),
        tx(ser, b"\xFF\xFF\xFF\xFF", "FF preamble"),
        time.sleep(0.3),
        rx(ser, 16, timeout=1),
        tx(ser, b"\x02", "mode 02"),
        time.sleep(2.0),
        rx(ser, 16, timeout=3),
    ]),
]

for name, test_fn in tests:
    print(f"\n{'='*60}")
    print(f"TEST {name}")
    print(f"{'='*60}")
    ser = fresh()
    if enter_program(ser):
        test_fn(ser)
    ser.close()
    time.sleep(2.0)

print("\nAll tests done.")
