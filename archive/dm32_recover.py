#!/usr/bin/env python3
"""DM-32UV: Recovery ping + targeted bypass test.
Run this after reconnecting USB or power cycling radio."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def tx(ser, data, label=""):
    if isinstance(data, str): data = data.encode('ascii')
    print(f"  TX [{label}]: {data.hex(' ').upper()}")
    ser.write(data); ser.flush()

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

# ============================================================
# Step 0: Recovery ping
# ============================================================
print("Attempting to connect to radio...")
try:
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
except Exception as e:
    print(f"Can't open {PORT}: {e}")
    print("Reconnect USB cable or power cycle radio, then retry.")
    sys.exit(1)

time.sleep(0.5)
ser.reset_input_buffer()

# Try PSEARCH up to 5 times with increasing delays
connected = False
for i in range(5):
    print(f"\nPing attempt {i+1}/5...")
    ser.reset_input_buffer()
    time.sleep(0.3)
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    r = rx(ser, 8)
    if r and r[0] == 0x06:
        print(f"  Radio alive! Model: {r[1:].decode('ascii', errors='replace')}")
        connected = True
        break
    time.sleep(2)

if not connected:
    print("\nRadio not responding. Please:")
    print("  1. Power off the radio")
    print("  2. Unplug USB cable")
    print("  3. Wait 5 seconds")
    print("  4. Plug USB cable back in")
    print("  5. Power on radio")
    print("  6. Re-run this script")
    ser.close()
    sys.exit(1)

ser.close()
time.sleep(1)

# ============================================================
# The key test: bypass via PSEARCH → SYSINFO → PROGRAM
# No draining between commands — just simple delays
# ============================================================
mode = sys.argv[1] if len(sys.argv) > 1 else "bypass"

if mode == "bypass":
    print("\n" + "=" * 60)
    print("BYPASS TEST: PSEARCH → SYSINFO → PROGRAM → 0x02 → READ")
    print("=" * 60)

    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()

    # PSEARCH
    print("\n[1] PSEARCH")
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    r = rx(ser, 8)

    # SYSINFO — skip PASSSTA
    print("\n[2] SYSINFO")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.2)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("  SYSINFO failed — maybe got stray bytes, try reading more")
        r2 = rx(ser, 8, timeout=1)

    # PROGRAM
    print("\n[3] PROGRAM")
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    prog_ok = r and r[0] == 0x06
    if prog_ok:
        print("    *** PROGRAM ACK ***")
    else:
        print("    PROGRAM response unclear, continuing anyway")

    # Wait for radio to settle, read any stray bytes
    time.sleep(1.0)
    stray = b""
    ser.timeout = 0.5
    while True:
        d = ser.read(64)
        if not d: break
        stray += d
    if stray:
        print(f"    (stray: {stray.hex(' ').upper()})")

    # Mode 02
    print("\n[4] Mode 02")
    tx(ser, b"\x02", "0x02")
    time.sleep(1.0)
    r = rx(ser, 16, timeout=3)
    if r:
        if all(b == 0xFF for b in r):
            print(f"    {len(r)}x 0xFF!")
            tx(ser, b"\x06", "confirm")
            time.sleep(0.3)
            r2 = rx(ser, 4)
            if r2 and r2[0] == 0x06:
                print("    *** PROGRAMMING MODE — NO PASSWORD! ***")
                # READ
                for addr in [0x000000, 0x001000]:
                    print(f"\n  [READ 0x{addr:06X}]")
                    tx(ser, bytes([0x52,
                        addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
                        0x00, 0x01]), f"READ")
                    time.sleep(0.5)
                    r3 = rx(ser, 300, timeout=5)
                    if r3 and r3[0] == 0x57 and len(r3) > 5:
                        print(f"    DATA:")
                        print(hexdump(r3[5:min(len(r3), 5+64)]))
        else:
            print(f"    Unexpected response (not 0xFF)")
    else:
        print("    mode 02 timeout")
        # Try read anyway
        print("\n[4alt] Direct READ without mode02")
        tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ")
        time.sleep(0.5)
        r = rx(ser, 300, timeout=3)
        if r and r[0] == 0x57:
            print("    *** DIRECT READ OK ***")
            print(hexdump(r[5:min(len(r), 5+64)]))

    # Try END
    tx(ser, b"\x45", "END")
    time.sleep(0.2)
    rx(ser, 8)
    ser.close()

elif mode == "vframes":
    print("\n" + "=" * 60)
    print("V-FRAME SURVEY")
    print("=" * 60)
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    rx(ser, 8)

    for vid in range(0x00, 0x20):
        time.sleep(0.05)
        tx(ser, bytes([0x56, 0x00, 0x00, 0x00, vid]), f"V{vid:02X}")
        time.sleep(0.1)
        r = rx(ser, 64, timeout=1)
    ser.close()

elif mode == "hidden":
    print("\n" + "=" * 60)
    print("HIDDEN COMMANDS (after PSEARCH)")
    print("=" * 60)
    for name, data in [("588999", b"588999\x00\x00"), ("PCTESTM", b"PCTESTM\x00"),
                        ("IDCHECK", b"IDCHECK\x00"), ("RTCITEM", b"RTCITEM\x00"),
                        ("DEL-RCD", b"DEL-RCD\x00")]:
        print(f"\n--- {name} ---")
        ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
        time.sleep(0.5)
        ser.reset_input_buffer()
        tx(ser, "PSEARCH", "PSEARCH")
        time.sleep(0.2)
        r = rx(ser, 8)
        if r and r[0] == 0x06:
            tx(ser, data, name)
            time.sleep(0.3)
            r = rx(ser, 128, timeout=3)
        ser.close()
        time.sleep(1)

elif mode == "auth":
    print("\n" + "=" * 60)
    print("PROPER AUTH TEST (watch what CPS would do)")
    print("=" * 60)
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()

    print("\n[PSEARCH]")
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    rx(ser, 8)

    print("\n[PASSSTA]")
    tx(ser, "PASSSTA", "PASSSTA")
    time.sleep(0.2)
    r = rx(ser, 8)
    if r:
        print(f"  PW needed: {r[0]==0x50}, bytes: {r.hex(' ')}")

    # Try password as PASWORD command (7 bytes) followed by password
    print("\n[PASWORD then '123' padded to 6]")
    tx(ser, "PASWORD", "PASWORD")
    time.sleep(0.2)
    r = rx(ser, 8)
    print(f"  PASWORD response: {r.hex(' ') if r else 'none'}")

    if r and r[0] == 0x06:
        # PASWORD accepted, now send password digits
        tx(ser, b"123\x00\x00\x00", "pw-6byte")
        time.sleep(0.3)
        r = rx(ser, 8)
        print(f"  pw-6byte response: {r.hex(' ') if r else 'none'}")

        if not r:
            # Try 8-byte
            tx(ser, b"123\x00\x00\x00\x00\x00", "pw-8byte")
            time.sleep(0.3)
            r = rx(ser, 8)
            print(f"  pw-8byte response: {r.hex(' ') if r else 'none'}")

    print("\n[SYSINFO]")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.2)
    rx(ser, 8)

    print("\n[PROGRAM]")
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    if r:
        print(f"  PROGRAM: first byte 0x{r[0]:02X}")

    print("\n[mode 02]")
    time.sleep(0.5)
    tx(ser, b"\x02", "0x02")
    time.sleep(1.0)
    r = rx(ser, 16, timeout=3)
    if r:
        print(f"  mode02: {r.hex(' ')}")

    ser.close()

print("\nDone.")
