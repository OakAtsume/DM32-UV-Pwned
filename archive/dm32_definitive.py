#!/usr/bin/env python3
"""DM-32UV: Definitive protocol test.
Systematically test the state machine to understand exact requirements."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def fresh():
    """Fresh serial connection with clean state."""
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


def do_handshake(ser, send_passsta=True, send_password=False, password_method=None):
    """Do handshake. Returns True if PROGRAM entered."""
    # PSEARCH
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.2)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("    PSEARCH FAIL"); return False

    if send_passsta:
        time.sleep(0.05)
        tx(ser, "PASSSTA", "PASSSTA")
        time.sleep(0.2)
        r = rx(ser, 8)
        pw_required = r and r[0] == 0x50
        print(f"    PW required: {pw_required}")

        if send_password and pw_required:
            time.sleep(0.05)
            if password_method == "cmd_then_pw":
                # Send PASWORD command, then password bytes
                tx(ser, "PASWORD", "PASWORD cmd")
                time.sleep(0.15)
                r = rx(ser, 8)
                time.sleep(0.05)
                tx(ser, b"123\x00\x00\x00", "pw 6B")
                time.sleep(0.3)
                r = rx(ser, 8, timeout=2)
            elif password_method == "pw_in_cmd":
                # Send PASWORD+password as one command
                tx(ser, b"PASWORD\x31\x32\x33\x00\x00\x00", "PASWORD+123")
                time.sleep(0.3)
                r = rx(ser, 8, timeout=2)
            elif password_method == "cmd_only":
                # Just send PASWORD (ACKs — maybe that's all that's needed?)
                tx(ser, "PASWORD", "PASWORD cmd")
                time.sleep(0.15)
                r = rx(ser, 8)
            elif password_method == "numeric_bytes":
                # Password as numeric bytes [1,2,3,0,0,0]
                tx(ser, "PASWORD", "PASWORD cmd")
                time.sleep(0.15)
                rx(ser, 8)
                time.sleep(0.05)
                tx(ser, bytes([1, 2, 3, 0, 0, 0]), "pw numeric")
                time.sleep(0.3)
                r = rx(ser, 8, timeout=2)
            elif password_method == "hex_encoded":
                # Password as hex string "010203000000"
                tx(ser, "PASWORD", "PASWORD cmd")
                time.sleep(0.15)
                rx(ser, 8)
                time.sleep(0.05)
                tx(ser, b"010203000000", "pw hex-enc")
                time.sleep(0.3)
                r = rx(ser, 8, timeout=2)
            elif password_method == "bcd":
                # BCD: 0x12 0x30 0x00 (123 as BCD)
                tx(ser, "PASWORD", "PASWORD cmd")
                time.sleep(0.15)
                rx(ser, 8)
                time.sleep(0.05)
                tx(ser, bytes([0x12, 0x30, 0x00, 0x00]), "pw BCD")
                time.sleep(0.3)
                r = rx(ser, 8, timeout=2)

    time.sleep(0.05)
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.2)
    r = rx(ser, 8)
    sysinfo_ok = r and r[0] == 0x06
    print(f"    SYSINFO: {'ACK' if sysinfo_ok else 'FAIL'}")

    return sysinfo_ok


def try_program_and_read(ser):
    """Try PROGRAM, mode 02, and read."""
    time.sleep(0.1)
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.5)
    r = rx(ser, 16, timeout=3)
    if not r or r[0] != 0x06:
        print("    PROGRAM failed")
        return False
    print("    PROGRAM ACK!")

    # Try mode 02 with longer wait
    time.sleep(1.0)
    ser.reset_input_buffer()
    tx(ser, b"\x02", "mode 02")
    time.sleep(1.5)
    r = rx(ser, 16, timeout=3)
    if r:
        if all(b == 0xFF for b in r):
            print(f"    MODE 02: {len(r)}x 0xFF !!!")
            tx(ser, b"\x06", "confirm")
            time.sleep(0.3)
            r2 = rx(ser, 4)
            if r2 and r2[0] == 0x06:
                print("    *** PROGRAMMING MODE ***")
                # Read
                tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ 0x000000")
                time.sleep(0.5)
                r3 = rx(ser, 300, timeout=5)
                if r3 and r3[0] == 0x57 and len(r3) > 5:
                    print(f"    *** READ OK! ***")
                    print(hexdump(r3[5:min(len(r3), 5+64)]))
                    return True
        else:
            print(f"    mode 02 non-0xFF: {r.hex(' ').upper()}")
    else:
        print("    mode 02 timeout")
        # Try direct read
        tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ direct")
        time.sleep(0.5)
        r = rx(ser, 300, timeout=3)
        if r and r[0] == 0x57:
            print("    *** DIRECT READ ***")
            print(hexdump(r[5:min(len(r), 5+64)]))
            return True

    return False


# ============================================================
# Run tests
# ============================================================
tests = [
    ("A: PASSSTA + PASWORD(cmd_only) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "cmd_only"}),

    ("B: PASSSTA + PASWORD(cmd+pw6) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "cmd_then_pw"}),

    ("C: PASSSTA + PASWORD(numeric 1,2,3) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "numeric_bytes"}),

    ("D: PASSSTA + PASWORD(BCD) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "bcd"}),

    ("E: No PASSSTA, SYSINFO + PROGRAM (bypass)",
     {"send_passsta": False}),

    ("F: PASSSTA + PASWORD(in_cmd) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "pw_in_cmd"}),

    ("G: PASSSTA + PASWORD(hex_encoded) + SYSINFO + PROGRAM",
     {"send_passsta": True, "send_password": True, "password_method": "hex_encoded"}),
]

for name, opts in tests:
    print(f"\n{'='*60}")
    print(f"TEST {name}")
    print(f"{'='*60}")
    ser = fresh()
    ok = do_handshake(ser, **opts)
    if ok:
        try_program_and_read(ser)
    ser.close()
    time.sleep(1.5)

print("\nAll tests done.")
