#!/usr/bin/env python3
"""DM-32UV: Test different password formats + clean bypass + hidden commands."""

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

def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        c = data[i:i+16]
        h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{prefix}{i:04X}: {h:<48s} |{a}|")
    return "\n".join(lines)

def do_psearch(ser):
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.15)
    r = rx(ser, 8)
    return r and r[0] == 0x06

def do_passsta(ser):
    tx(ser, "PASSSTA", "PASSSTA")
    time.sleep(0.15)
    return rx(ser, 8)


# ============================================================
# TEST 1: Password format experiments
# ============================================================
def test_password_formats():
    print("\n" + "=" * 60)
    print("TEST 1: PASSWORD FORMAT EXPERIMENTS")
    print("=" * 60)

    formats = [
        ("A: PASWORD cmd then '123\\0x5'", "PASWORD", b"123\x00\x00\x00\x00\x00"),
        ("B: '123' padded to 6 then \\0\\0", None, b"123\x00\x00\x00\x00\x00"),
        ("C: PASWORD + '123' in one write", None, b"PASWORD123\x00\x00\x00"),
        ("D: 7-byte PASWORD then 6-byte pw", "PASWORD", b"123\x00\x00\x00"),
        ("E: 8-byte '123\\0' + 0xFF pad", None, b"123\x00\xFF\xFF\xFF\xFF"),
        ("F: pw as ASCII '123456' (wrong pw)", "PASWORD", b"123456\x00\x00"),
    ]

    for desc, prefix_cmd, pw_data in formats:
        print(f"\n--- {desc} ---")
        ser = fresh()
        if not do_psearch(ser):
            ser.close(); continue

        r = do_passsta(ser)
        time.sleep(0.05)

        if prefix_cmd:
            tx(ser, prefix_cmd, "cmd")
            time.sleep(0.15)
            r = rx(ser, 8)
            if r:
                print(f"    cmd response: {r.hex(' ').upper()}")
            time.sleep(0.05)

        tx(ser, pw_data, "pw_data")
        time.sleep(0.3)
        r = rx(ser, 8, timeout=2)
        if r:
            if r[0] == 0x06:
                print("    *** ACK — password accepted! ***")
            elif r[0] == 0x15:
                print("    NACK — password rejected")
            else:
                print(f"    Response: 0x{r[0]:02X}")

            # Try SYSINFO after
            tx(ser, "SYSINFO", "SYSINFO")
            time.sleep(0.15)
            r2 = rx(ser, 8)
            if r2 and r2[0] == 0x06:
                print("    SYSINFO ACK — auth worked!")
        ser.close()
        time.sleep(0.3)


# ============================================================
# TEST 2: Clean bypass — minimal commands, no detours
# ============================================================
def test_clean_bypass():
    print("\n" + "=" * 60)
    print("TEST 2: CLEAN BYPASS — PSEARCH→PASSSTA→SYSINFO→PROGRAM")
    print("  (no password, no V-frames, clean state machine)")
    print("=" * 60)

    ser = fresh()

    print("\n[1] PSEARCH")
    if not do_psearch(ser):
        ser.close(); return
    time.sleep(0.05)

    print("\n[2] PASSSTA")
    r = do_passsta(ser)
    time.sleep(0.05)

    print("\n[3] SYSINFO (no password sent)")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print(f"    SYSINFO rejected: {r.hex(' ') if r else 'timeout'}")
        ser.close(); return
    print("    ACK!")
    time.sleep(0.05)

    print("\n[4] PROGRAM (no password!)")
    ser.reset_input_buffer()
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.3)
    r = rx(ser, 8, timeout=3)
    if not r:
        print("    timeout — trying with preamble")
        tx(ser, b"\xFF\xFF\xFF\xFF\x0CPROGRAM", "PROGRAM+preamble")
        time.sleep(0.3)
        r = rx(ser, 8, timeout=3)
    if not r or r[0] != 0x06:
        print("    PROGRAM rejected")
        ser.close(); return
    print(f"    PROGRAM ACK! (full response: {r.hex(' ').upper()})")
    time.sleep(0.05)

    print("\n[5] Mode 02")
    ser.reset_input_buffer()
    time.sleep(0.1)
    tx(ser, b"\x02", "mode 02")
    time.sleep(0.5)
    r = rx(ser, 8, timeout=3)
    if not r:
        print("    timeout")
        ser.close(); return

    if all(b == 0xFF for b in r):
        print(f"    {len(r)}x 0xFF!")
        tx(ser, b"\x06", "confirm")
        time.sleep(0.2)
        r2 = rx(ser, 4)
        if r2 and r2[0] == 0x06:
            print("    *** PROGRAMMING MODE — NO PASSWORD ***\n")
            # Read!
            for addr in [0x000000, 0x001000, 0x010000]:
                print(f"  [READ 0x{addr:06X}]")
                tx(ser, bytes([0x52,
                    addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
                    0x00, 0x01]), f"READ 0x{addr:06X}")
                time.sleep(0.3)
                r = rx(ser, 300, timeout=5)
                if r and r[0] == 0x57 and len(r) > 5:
                    print(f"    Data ({len(r)-5} bytes):")
                    print(hexdump(r[5:min(len(r), 5+64)]))
                print()
    else:
        print(f"    Got {r.hex(' ').upper()} (not 0xFF)")

    ser.close()


# ============================================================
# TEST 3: Bypass without PASSSTA — skip it entirely
# ============================================================
def test_bypass_no_passsta():
    print("\n" + "=" * 60)
    print("TEST 3: BYPASS WITHOUT PASSSTA")
    print("  PSEARCH → SYSINFO → PROGRAM (skip PASSSTA entirely)")
    print("=" * 60)

    ser = fresh()

    print("\n[1] PSEARCH")
    if not do_psearch(ser):
        ser.close(); return
    time.sleep(0.05)

    print("\n[2] SYSINFO (skip PASSSTA entirely)")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    r = rx(ser, 8)
    if r and r[0] == 0x06:
        print("    ACK!")
    else:
        print(f"    Response: {r.hex(' ') if r else 'timeout'}")
    time.sleep(0.05)

    print("\n[3] PROGRAM")
    ser.reset_input_buffer()
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.3)
    r = rx(ser, 8, timeout=3)
    if r and r[0] == 0x06:
        print("    PROGRAM ACK!")
    else:
        print(f"    Response: {r.hex(' ') if r else 'timeout'}")

    ser.close()


# ============================================================
# TEST 4: V-frame survey (all IDs 0x00-0x1F)
# ============================================================
def test_vframes():
    print("\n" + "=" * 60)
    print("TEST 4: V-FRAME SURVEY (0x00-0x1F)")
    print("=" * 60)

    ser = fresh()
    if not do_psearch(ser):
        ser.close(); return

    for vid in range(0x00, 0x20):
        tx(ser, bytes([0x56, 0x00, 0x00, 0x00, vid]), f"V{vid:02X}")
        time.sleep(0.08)
        r = rx(ser, 64, timeout=1)
        if r and len(r) > 3 and r[0] == 0x56:
            try:
                txt = r[3:].decode('ascii', errors='replace').rstrip('\x00')
                if txt and all(32 <= ord(c) < 127 for c in txt):
                    print(f"    -> \"{txt}\"")
            except:
                pass
    ser.close()


# ============================================================
# TEST 5: Hidden commands after PSEARCH
# ============================================================
def test_hidden():
    print("\n" + "=" * 60)
    print("TEST 5: HIDDEN COMMANDS")
    print("=" * 60)

    cmds = {
        "588999":  b"588999\x00\x00",
        "PCTESTM": b"PCTESTM\x00",
        "IDCHECK": b"IDCHECK\x00",
        "RTCITEM": b"RTCITEM\x00",
        "DEL-RCD": b"DEL-RCD\x00",
    }

    for name, data in cmds.items():
        print(f"\n--- {name} (after PSEARCH) ---")
        ser = fresh()
        if not do_psearch(ser):
            ser.close(); continue
        time.sleep(0.05)
        tx(ser, data, name)
        time.sleep(0.3)
        r = rx(ser, 128, timeout=3)
        if r:
            print(f"    {len(r)} bytes response")
            if len(r) > 8:
                print(hexdump(r))
        ser.close()
        time.sleep(0.3)

    # Also try 588999 as the very first byte (no PSEARCH)
    print(f"\n--- 588999 RAW (no handshake) ---")
    ser = fresh()
    tx(ser, b"588999\x00\x00", "588999-raw")
    time.sleep(0.5)
    r = rx(ser, 128, timeout=3)
    ser.close()


if __name__ == "__main__":
    tests = sys.argv[1:] if len(sys.argv) > 1 else ["1", "2", "3", "4", "5"]
    try:
        if "1" in tests: test_password_formats()
        if "2" in tests: test_clean_bypass()
        if "3" in tests: test_bypass_no_passsta()
        if "4" in tests: test_vframes()
        if "5" in tests: test_hidden()
    except KeyboardInterrupt:
        print("\nInterrupted")
    except Exception as e:
        import traceback; traceback.print_exc()
    print("\nDone.")
