#!/usr/bin/env python3
"""DM-32UV: Read codeplug using the exact CPS protocol.
Uses byte-level response parsing to handle async stray bytes."""

import serial
import time
import sys
import os

PORT = "/dev/ttyUSB0"
BAUD = 115200

def wait_for(ser, expected_first, count, timeout=1.0):
    """Read bytes, skip stray ones, return response starting with expected_first byte.
    `expected_first` is a set of valid first-byte values.
    `count` is total bytes to read after finding the first byte (including it)."""
    end = time.time() + timeout
    ser.timeout = 0.05
    skipped = bytearray()
    while time.time() < end:
        b = ser.read(1)
        if not b:
            continue
        if b[0] in expected_first:
            # Found expected start, read rest
            ser.timeout = min(timeout, 0.5)
            rest = ser.read(count - 1)
            result = bytes([b[0]]) + rest
            if skipped:
                pass  # silently ignore stray bytes
            return result
        else:
            skipped.append(b[0])
    return b""

def read_bulk(ser, size, timeout=15):
    """Read exactly `size` bytes, tolerating brief gaps."""
    ser.timeout = 0.5
    data = bytearray()
    end = time.time() + timeout
    while len(data) < size and time.time() < end:
        chunk = ser.read(size - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)

def hexdump(data, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        c = data[i:i+16]; h = " ".join(f"{b:02X}" for b in c)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in c)
        lines.append(f"{prefix}{i:04X}: {h:<48s} |{a}|")
    return "\n".join(lines)

def make_password(pw_str):
    pw = b"PR" + pw_str.encode('ascii') + b"\x00"
    return pw.ljust(10, b"\xFF")


def full_read(password="123", skip_auth=False, pages_to_read=999, dump_file=None):
    print("=" * 60)
    print(f"DM-32UV Codeplug Reader")
    print(f"Password: {'BYPASS' if skip_auth else repr(password)}")
    print("=" * 60)

    ser = serial.Serial(PORT, BAUD, timeout=0.5, bytesize=8, parity='N', stopbits=1)
    time.sleep(1.0)  # let radio settle
    ser.reset_input_buffer()

    codeplug = {}
    ACK = {0x06}
    NACK = {0x15}

    # --- 1. PSEARCH ---
    print("\n[1] PSEARCH")
    ser.write(b"PSEARCH"); ser.flush()
    r = wait_for(ser, ACK, 8, timeout=2)
    if not r or r[0] != 0x06:
        print("    FAIL: no radio response"); ser.close(); return False
    model = r[1:].decode('ascii', errors='replace').rstrip('\x00')
    print(f"    Model: {model}")

    if not skip_auth:
        # --- 2. PASSSTA ---
        print("\n[2] PASSSTA")
        ser.write(b"PASSSTA"); ser.flush()
        r = wait_for(ser, {0x50, 0x06}, 3, timeout=1)
        pw_required = r and r[0] == 0x50
        print(f"    Password required: {pw_required}")

        if pw_required:
            # --- 3. PASWORD cmd ---
            print("\n[3] PASWORD")
            ser.write(b"PASWORD"); ser.flush()
            r = wait_for(ser, ACK | NACK, 1, timeout=0.5)
            if not r or r[0] != 0x06:
                print("    PASWORD cmd rejected"); ser.close(); return False

            # --- 4. Password data ---
            pw_data = make_password(password)
            print(f"    Sending: {pw_data.hex(' ').upper()}")
            ser.write(pw_data); ser.flush()
            r = wait_for(ser, ACK | NACK, 1, timeout=1)
            if not r or r[0] != 0x06:
                print("    *** PASSWORD REJECTED ***"); ser.close(); return False
            print("    Password accepted!")

    # --- 5. SYSINFO ---
    print("\n[5] SYSINFO")
    ser.write(b"SYSINFO"); ser.flush()
    r = wait_for(ser, ACK, 1, timeout=0.5)
    if not r or r[0] != 0x06:
        print("    SYSINFO failed"); ser.close(); return False
    print("    OK")

    # --- 6. V-Frames (matching exact CPS sequence) ---
    print("\n[6] V-Frames")

    # V-frame 0x0D with 0x40 (64-byte device info query)
    ser.write(bytes([0x56, 0x00, 0x00, 0x40, 0x0D])); ser.flush()
    r = wait_for(ser, {0x56}, 67, timeout=0.5)
    if r and r[0] == 0x56:
        print(f"    V0D device info: {len(r)} bytes")
    else:
        print(f"    V0D: no response")

    # V-frames 0x01 through 0x10 (CPS skips 0x0C)
    for vid in range(0x01, 0x11):
        if vid == 0x0C:
            continue
        ser.write(bytes([0x56, 0x00, 0x00, 0x00, vid])); ser.flush()
        # Response: 0x56 + VID + LEN + data (variable size)
        # Read header first (3 bytes: 56 VV LL)
        r = wait_for(ser, {0x56}, 3, timeout=0.3)
        if r and r[0] == 0x56 and len(r) >= 3:
            datalen = r[2]
            if datalen > 0:
                ser.timeout = 0.3
                payload = ser.read(datalen)
                try:
                    txt = payload.decode('ascii', errors='replace').rstrip('\x00')
                    if txt and all(32 <= ord(c) < 127 for c in txt):
                        print(f"    V{vid:02X}: {txt}")
                    else:
                        print(f"    V{vid:02X}: [{payload.hex(' ')}]")
                except:
                    print(f"    V{vid:02X}: [{payload.hex(' ')}]")
            else:
                print(f"    V{vid:02X}: (empty)")

    # --- 7. G-Query ---
    print("\n[7] G-Query")
    ser.write(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01])); ser.flush()
    r = wait_for(ser, {0x53}, 6, timeout=1)  # header: 53 + 5 bytes
    if r and r[0] == 0x53:
        # Read remaining 250 bytes of data
        data = read_bulk(ser, 250, timeout=2)
        print(f"    G-query: {6 + len(data)} bytes total")
    # Drain trailing data (capture shows 6x FF after G-query)
    time.sleep(0.2)
    ser.timeout = 0.3
    ser.read(64)

    # --- 8. Preamble + PROGRAM ---
    print("\n[8] PROGRAM")
    ser.write(b"\xFF\xFF\xFF\xFF\x0C"); ser.flush()
    time.sleep(0.01)
    ser.write(b"PROGRAM"); ser.flush()
    r = wait_for(ser, ACK | NACK, 1, timeout=1)
    if not r or r[0] != 0x06:
        print(f"    PROGRAM failed")
        ser.close(); return False
    print("    PROGRAM ACK!")

    # --- 9. Mode 02 ---
    print("\n[9] Mode 02")
    ser.write(b"\x02"); ser.flush()
    r = wait_for(ser, {0xFF}, 8, timeout=2)
    if not r or len(r) < 8 or not all(b == 0xFF for b in r):
        print(f"    Mode 02 failed: {r.hex(' ') if r else 'timeout'}")
        ser.close(); return False
    print(f"    Got 8x 0xFF")

    # --- 10. Confirm ---
    ser.write(b"\x06"); ser.flush()
    r = wait_for(ser, ACK, 1, timeout=1)
    if not r or r[0] != 0x06:
        print(f"    Confirm failed"); ser.close(); return False
    print("    *** PROGRAMMING MODE ***\n")

    # --- 11. Block ID scan ---
    print("[10] Scanning 256 pages...")
    block_map = {}
    for page in range(0x00, 0x100):
        addr = page * 0x1000 + 0xFFF
        cmd = bytes([0x52, addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, 0x01, 0x00])
        ser.write(cmd); ser.flush()
        r = wait_for(ser, {0x57}, 7, timeout=0.5)
        if r and r[0] == 0x57 and len(r) >= 7:
            block_id = r[6]
            if block_id != 0x00:
                block_map[page] = block_id
        if page % 32 == 31:
            sys.stdout.write(f"\r    {page+1}/256 scanned, {len(block_map)} non-empty")
            sys.stdout.flush()
    print(f"\r    256 pages scanned: {len(block_map)} non-empty blocks          ")

    for p, bid in sorted(block_map.items()):
        print(f"      0x{p*0x1000:06X}: type 0x{bid:02X}")

    # --- 12. Read data ---
    read_pages = sorted(block_map.keys())[:pages_to_read]
    total = len(read_pages) * 4096
    print(f"\n[11] Reading {len(read_pages)} pages ({total} bytes)...")

    for idx, page in enumerate(read_pages):
        addr = page * 0x1000
        bid = block_map[page]

        cmd = bytes([0x52, addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, 0x00, 0x10])
        ser.write(cmd); ser.flush()
        # Response header: W(1) + addr(3) + len(2) = 6 bytes
        hdr = wait_for(ser, {0x57}, 6, timeout=5)
        if hdr and hdr[0] == 0x57:
            # Read 4096 bytes of payload
            data = read_bulk(ser, 4096, timeout=15)
            codeplug[addr] = data
            sys.stdout.write(f"\r    [{idx+1}/{len(read_pages)}] 0x{addr:06X}: {len(data)} bytes")
            sys.stdout.flush()
        else:
            print(f"\r    [{idx+1}/{len(read_pages)}] 0x{addr:06X}: FAILED")

    print()

    # Show sample data
    for addr, data in list(sorted(codeplug.items()))[:3]:
        print(f"\n  Page 0x{addr:06X}:")
        print(hexdump(data[:64]))
        if len(data) > 64:
            print(f"    ... (+{len(data)-64} bytes)")

    # --- 13. END ---
    print("\n[12] END")
    ser.write(b"\x45"); ser.flush()
    time.sleep(0.5)
    ser.close()

    # Save dump
    if dump_file and codeplug:
        with open(dump_file, "wb") as f:
            for addr in sorted(codeplug.keys()):
                f.write(codeplug[addr])
        total_bytes = sum(len(v) for v in codeplug.values())
        print(f"\nSaved: {dump_file} ({total_bytes} bytes)")

    total_bytes = sum(len(v) for v in codeplug.values())
    print(f"\nDone! {len(codeplug)} pages, {total_bytes} bytes")
    return True


if __name__ == "__main__":
    pw = "123"
    skip = False
    pages = 999
    dump = None

    for arg in sys.argv[1:]:
        if arg == "--bypass":
            skip = True
        elif arg.startswith("--pages="):
            pages = int(arg.split("=")[1])
        elif arg.startswith("--dump="):
            dump = arg.split("=", 1)[1]
        elif arg.startswith("--pw="):
            pw = arg.split("=", 1)[1]
        elif not arg.startswith("-"):
            pw = arg

    if dump is None:
        dump = os.path.join(os.path.dirname(__file__), "codeplug_dump.bin")

    full_read(password=pw, skip_auth=skip, pages_to_read=pages, dump_file=dump)
