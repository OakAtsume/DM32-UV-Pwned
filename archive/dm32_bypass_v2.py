#!/usr/bin/env python3
"""DM-32UV: Full bypass v2 — try different PROGRAM formats and mode02 variants."""

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

def drain(ser, timeout=0.5):
    """Drain all pending bytes."""
    ser.timeout = timeout
    total = b""
    while True:
        d = ser.read(256)
        if not d:
            break
        total += d
    if total:
        print(f"  (drained {len(total)}B: {total.hex(' ').upper()})")
    return total

def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        c = data[i:i+16]
        h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{prefix}{i:04X}: {h:<48s} |{a}|")
    return "\n".join(lines)


def attempt(name, program_cmd, use_passsta=False, pre_mode02=None):
    """Try a full bypass sequence with a given PROGRAM command format."""
    print(f"\n{'='*60}")
    print(f"ATTEMPT: {name}")
    print(f"  PASSSTA: {'yes' if use_passsta else 'SKIPPED'}")
    print(f"  PROGRAM format: {program_cmd.hex(' ').upper()}")
    print(f"{'='*60}")

    ser = fresh()

    # PSEARCH
    print("\n[PSEARCH]")
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.15)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        ser.close(); return False
    drain(ser)

    if use_passsta:
        print("\n[PASSSTA]")
        tx(ser, "PASSSTA", "PASSSTA")
        time.sleep(0.15)
        rx(ser, 8)
        drain(ser)

    # SYSINFO
    print("\n[SYSINFO]")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    r = rx(ser, 8)
    drain(ser)

    # PROGRAM
    print("\n[PROGRAM]")
    tx(ser, program_cmd, "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    if not r or r[0] != 0x06:
        print("    PROGRAM failed")
        ser.close(); return False
    print("    PROGRAM ACK!")

    # Long drain to clear async status bytes
    time.sleep(0.5)
    drain(ser, timeout=1.0)

    # Optional pre-mode02 bytes
    if pre_mode02:
        print(f"\n[pre-mode02]")
        tx(ser, pre_mode02, "pre")
        time.sleep(0.3)
        rx(ser, 16)
        drain(ser)

    # Mode 02
    print("\n[mode 02]")
    tx(ser, b"\x02", "mode 02")
    time.sleep(1.0)
    r = rx(ser, 16, timeout=3)
    if r:
        if all(b == 0xFF for b in r):
            print(f"    {len(r)}x 0xFF !!!")
            tx(ser, b"\x06", "confirm")
            time.sleep(0.2)
            r2 = rx(ser, 4)
            if r2 and r2[0] == 0x06:
                print("    *** PROGRAMMING MODE ***")
                # Read!
                print("\n[READ 0x000000]")
                tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ")
                time.sleep(0.5)
                r = rx(ser, 300, timeout=5)
                if r and r[0] == 0x57:
                    print(f"    *** READ OK! ***")
                    print(hexdump(r[5:min(len(r), 5+64)]))
                ser.close(); return True
        else:
            print(f"    Got non-0xFF response")
    else:
        print("    timeout")

    # Try direct read anyway
    print("\n[direct READ attempt]")
    tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ")
    time.sleep(0.5)
    r = rx(ser, 300, timeout=3)
    if r and r[0] == 0x57:
        print("    *** DIRECT READ WORKS! ***")
        print(hexdump(r[5:min(len(r), 5+64)]))
        ser.close(); return True

    ser.close()
    return False


# ============================================================
# Try multiple approaches
# ============================================================

# A: Plain PROGRAM, no PASSSTA
attempt("A: Plain PROGRAM, skip PASSSTA",
        b"PROGRAM")

# B: PROGRAM with FF preamble, no PASSSTA
attempt("B: PROGRAM+preamble, skip PASSSTA",
        b"\xFF\xFF\xFF\xFF\x0CPROGRAM")

# C: PROGRAM padded to 8 bytes, no PASSSTA
attempt("C: PROGRAM padded to 8, skip PASSSTA",
        b"PROGRAM\x00")

# D: Check DTR/RTS — some radios need these toggled
print(f"\n{'='*60}")
print("ATTEMPT D: DTR/RTS toggle before mode02")
print(f"{'='*60}")
ser = fresh()
tx(ser, "PSEARCH", "PSEARCH")
time.sleep(0.15)
r = rx(ser, 8)
if r and r[0] == 0x06:
    drain(ser)
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    rx(ser, 8)
    drain(ser)
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    drain(ser, timeout=1.0)

    if r and r[0] == 0x06:
        print("\n[Toggle DTR/RTS]")
        ser.dtr = False
        ser.rts = False
        time.sleep(0.2)
        ser.dtr = True
        ser.rts = True
        time.sleep(0.2)
        drain(ser)

        print("\n[mode 02 after DTR toggle]")
        tx(ser, b"\x02", "mode 02")
        time.sleep(1.0)
        r = rx(ser, 16, timeout=3)
        if r and all(b == 0xFF for b in r):
            print("    *** GOT 0xFF ***")
ser.close()

# E: Monitor what the radio sends unprompted for 3 seconds
print(f"\n{'='*60}")
print("MONITOR: What does the radio send after PROGRAM ACK?")
print(f"{'='*60}")
ser = fresh()
tx(ser, "PSEARCH", "PSEARCH")
time.sleep(0.15)
rx(ser, 8)
drain(ser)
tx(ser, "SYSINFO", "SYSINFO")
time.sleep(0.15)
rx(ser, 8)
drain(ser)
tx(ser, "PROGRAM", "PROGRAM")
time.sleep(0.3)
r = rx(ser, 16, timeout=1)
if r:
    print(f"  PROGRAM response: {r.hex(' ').upper()}")
    print("\n  Monitoring for 3 seconds...")
    for i in range(6):
        time.sleep(0.5)
        d = rx(ser, 64, timeout=0.3)
        if d:
            print(f"    t={0.5*(i+1):.1f}s: {d.hex(' ').upper()}")
ser.close()

print("\nDone.")
