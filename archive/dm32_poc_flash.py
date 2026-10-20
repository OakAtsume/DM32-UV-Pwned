#!/usr/bin/env python3
"""DM-32UV Flash Read/Patch PoC
=================================
Demonstrates flash read and write access through the CPS serial protocol.

Modes:
  read     — Attempt to read flash/EEPROM sectors (test if READ works)
  patch    — Patch a visible display string in firmware (reversible)
  restore  — Re-flash original bytes from backup
  dump     — Dump a flash address range to file

The write path uses the decoded CPS firmware update protocol:
  'W' + 3-byte addr (LE) + 2-byte size (LE) + data  →  ACK (0x06)

The read path uses the CPS programming READ command:
  'R' + 3-byte addr (LE) + 2-byte size (LE)  →  'W' + 3-byte addr + 2-byte size + data

SAFETY:
  - All patches are same-length string replacements (no code changes)
  - Original bytes are backed up before any write
  - The --restore flag reverts to original
  - --dry-run simulates without sending anything

WARNING: Writing to flash CAN brick the radio. For security research only.
         Keep the original firmware .bin for recovery via bootloader.
"""

import serial
import time
import sys
import struct
import hashlib
import argparse
import json
import os

BAUD = 115200
ACK = 0x06
BLOCK_SIZE = 0x1000  # 4KB max per write
BACKUP_FILE = "dm32_patch_backup.json"

# === Patch targets (from firmware RE) ===
# Each target: (name, flash_addr, original_bytes, patched_bytes, description)
PATCH_TARGETS = {
    "welcome": {
        "desc": "Startup screen text: WELCOME → 801LABS",
        "flash_addr": 0x030A1940,
        "original": b"WELCOME\x00",
        "patched":  b"801LABS\x00",
    },
    "dmr-radio": {
        "desc": "Startup screen subtitle: DMR Radio → 801 Labs",
        "flash_addr": 0x030A1948,
        "original": b"DMR Radio\x00",
        "patched":  b"801 Labs!\x00",
    },
    "power-on": {
        "desc": "Power-on message: Power On... → 801Labs !!",
        "flash_addr": 0x030B0774,
        "original": b"Power On...\x00",
        "patched":  b"801Labs !!!\x00",
    },
    "version": {
        "desc": "Firmware version string (Versions menu)",
        "flash_addr": 0x0309F858,
        "original": b"DM32.01.L01.048\x00",
        "patched":  b"DM32.01.PWNED!!\x00",
    },
    "build-date": {
        "desc": "Build date string (Versions menu)",
        "flash_addr": 0x0309F868,
        "original": b"2022-06-27\x00",
        "patched":  b"2026-OWNED\x00",
    },
}


def hexdump(data, base_addr=0, prefix="  "):
    if not data:
        return f"{prefix}(empty)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{base_addr+i:08X}: {hexpart:<48s} |{ascpart}|")
    return "\n".join(lines)


# === Serial helpers ===

def serial_write(ser, data):
    ser.write(data)
    ser.flush()
    return True

def serial_read(ser, count, timeout=2.0):
    end = time.time() + timeout
    data = bytearray()
    while len(data) < count and time.time() < end:
        ser.timeout = max(0.01, end - time.time())
        chunk = ser.read(count - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)

def serial_read_any(ser, timeout=1.0):
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    last_rx = time.time()
    while time.time() < end:
        b = ser.read(64)
        if b:
            data.extend(b)
            last_rx = time.time()
        elif data and time.time() - last_rx > 0.15:
            break
    return bytes(data)


# === CPS Protocol ===

def cps_handshake(ser, full=True):
    """CPS handshake up to programming mode.
    If full=True, does the complete V-frame + G-query + PROGRAM sequence.
    If full=False, does minimal PSEARCH + SYSINFO only (for READ testing).
    """
    # PSEARCH
    for attempt in range(5):
        print(f"  PSEARCH (attempt {attempt+1}/5)...", end=" ", flush=True)
        ser.reset_input_buffer()
        serial_write(ser, b"PSEARCH")
        resp = serial_read(ser, 8, timeout=2.0)
        if len(resp) >= 1 and resp[0] == ACK:
            model = resp[1:].decode("ascii", errors="replace").rstrip("\x00")
            print(f"ACK — model: {model}")
            break
        print("no ACK" + (f" ({resp.hex()})" if resp else ""))
        time.sleep(0.5)
    else:
        print("  [!] Radio not responding")
        return False

    # PASSSTA
    print("  PASSSTA...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, b"PASSSTA")
    resp = serial_read(ser, 8, timeout=1.0)
    print(f"{'ACK' if resp and resp[0] == ACK else resp.hex() if resp else 'none'}")

    # SYSINFO
    print("  SYSINFO...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, b"SYSINFO")
    resp = serial_read(ser, 1, timeout=1.0)
    print(f"{'ACK' if resp and resp[0] == ACK else resp.hex() if resp else 'none'}")

    if not full:
        return True

    # V-frame 0x0D
    print("  V-frame 0x0D...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, bytes([0x56, 0x00, 0x00, 0x40, 0x0D]))
    resp = serial_read(ser, 3, timeout=0.5)
    if resp and len(resp) >= 3 and resp[0] == 0x56:
        dlen = resp[2]
        if dlen > 0:
            serial_read(ser, dlen, timeout=0.5)
        print(f"OK ({dlen}B data)")
    else:
        print(f"{'unexpected: ' + resp.hex() if resp else 'none'}")

    # V-frames 6-8
    for vid in range(6, 9):
        print(f"  V-frame 0x{vid:02X}...", end=" ", flush=True)
        ser.reset_input_buffer()
        serial_write(ser, bytes([0x56, 0x00, 0x00, 0x00, vid]))
        resp = serial_read(ser, 3, timeout=0.5)
        if resp and len(resp) >= 3 and resp[0] == 0x56:
            dlen = resp[2]
            if dlen > 0:
                serial_read(ser, dlen, timeout=0.5)
            print(f"OK ({dlen}B data)")
        else:
            print(f"{'resp: ' + resp.hex() if resp else 'none'}")

    # G-query
    print("  G-query...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01]))
    resp = serial_read(ser, 0x106, timeout=1.0)
    if resp and resp[0] == 0x53:
        print(f"OK ({len(resp)}B)")
    else:
        print(f"{'resp: ' + resp[:8].hex() + '...' if resp else 'none'}")
    # drain remaining
    time.sleep(0.3)
    ser.timeout = 0.3
    ser.read(512)
    time.sleep(0.2)
    ser.read(128)

    # Preamble + PROGRAM
    print("  Preamble + PROGRAM...", end=" ", flush=True)
    serial_write(ser, b"\xFF\xFF\xFF\xFF\x0C")
    time.sleep(0.01)
    ser.reset_input_buffer()
    serial_write(ser, b"PROGRAM")
    resp = serial_read(ser, 1, timeout=1.0)
    if not resp or resp[0] != ACK:
        print(f"PROGRAM failed ({resp.hex() if resp else 'none'})")
        return False
    print("ACK")

    # Mode 0x02
    print("  Mode 0x02...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, bytes([0x02]))
    resp = serial_read(ser, 8, timeout=2.0)
    if len(resp) < 8:
        print(f"failed (got {len(resp)}B)")
        return False
    print(f"device: {resp.hex()}")

    # Confirm ACK
    print("  Confirm...", end=" ", flush=True)
    ser.reset_input_buffer()
    serial_write(ser, bytes([ACK]))
    resp = serial_read(ser, 1, timeout=1.0)
    if resp and resp[0] == ACK:
        print("ACK — programming mode ACTIVE")
        return True
    print(f"{'resp: ' + resp.hex() if resp else 'no response'}")
    return False


def cps_end(ser):
    """End CPS session."""
    serial_write(ser, bytes([0x45]))
    time.sleep(0.5)


# === Flash Read ===

def flash_read(ser, addr, size, timeout=2.0):
    """Read from flash/EEPROM using CPS READ command.

    Protocol: 'R'(0x52) + addr[3 LE] + size[2 LE]
    Response: 'W'(0x57) + addr[3 LE] + size[2 LE] + data

    NOTE: This may only work for codeplug addresses (0x000000-0x0C3FFF).
    Flash addresses (0x03xxxxxx) may require a different approach.
    """
    addr_bytes = struct.pack("<I", addr)[:3]  # 3-byte LE
    size_bytes = struct.pack("<H", size)       # 2-byte LE

    cmd = bytes([0x52]) + addr_bytes + size_bytes
    ser.reset_input_buffer()
    serial_write(ser, cmd)

    # Expected response: 0x57 + 3-byte addr + 2-byte size + data
    header_size = 1 + 3 + 2  # W + addr + size = 6 bytes
    resp = serial_read(ser, header_size + size, timeout=timeout)

    if len(resp) < header_size:
        return None

    if resp[0] != 0x57:  # 'W'
        return None

    # Verify echo addr/size
    resp_addr = struct.unpack_from("<I", resp, 1)[0] & 0xFFFFFF
    resp_size = struct.unpack_from("<H", resp, 4)[0]

    if resp_size != size:
        return None

    data = resp[header_size:header_size + size]
    if len(data) != size:
        return None

    return data


def try_read_flash(ser, addr, size=16):
    """Attempt to read flash and show result."""
    data = flash_read(ser, addr, size)
    if data:
        print(f"  READ 0x{addr:08X} ({size}B): SUCCESS")
        print(hexdump(data, base_addr=addr))
        return data
    else:
        # Try with just the low 3 bytes (24-bit address space)
        addr24 = addr & 0xFFFFFF
        if addr24 != addr:
            data = flash_read(ser, addr24, size)
            if data:
                print(f"  READ 0x{addr24:06X} ({size}B): SUCCESS (24-bit)")
                print(hexdump(data, base_addr=addr24))
                return data
        print(f"  READ 0x{addr:08X}: no valid response")
        return None


# === Flash Write ===

def flash_write_block(ser, addr, data, timeout=5.0):
    """Write a block to flash using CPS firmware write protocol.

    Protocol: 'W'(0x57) + addr[3 LE] + size[2 LE] + data
    Response: ACK (0x06)
    """
    size = len(data)
    if size > BLOCK_SIZE:
        raise ValueError(f"Block too large: {size} > {BLOCK_SIZE}")

    addr_lo = addr & 0xFF
    addr_mid = (addr >> 8) & 0xFF
    addr_hi = (addr >> 16) & 0xFF
    size_lo = size & 0xFF
    size_hi = (size >> 8) & 0xFF

    header = bytes([0x57, addr_lo, addr_mid, addr_hi, size_lo, size_hi])
    packet = header + data

    ser.reset_input_buffer()
    serial_write(ser, packet)

    resp = serial_read(ser, 1, timeout=timeout)
    if resp and resp[0] == ACK:
        return True
    return False


# === Commands ===

def cmd_read(ser, args):
    """Test READ access on various address ranges."""
    print("\n=== Flash/EEPROM Read Test ===\n")

    # Do minimal handshake first
    if not cps_handshake(ser, full=False):
        return

    print("\n--- Testing READ on codeplug addresses ---")
    for addr in [0x000000, 0x00C000, 0x00D000, 0x0C3000]:
        try_read_flash(ser, addr, 32)
        time.sleep(0.1)

    print("\n--- Testing READ on flash addresses (may fail) ---")
    # These are where the patch targets live
    for name, target in PATCH_TARGETS.items():
        addr = target["flash_addr"]
        print(f"\n  [{name}] flash 0x{addr:08X}:")
        try_read_flash(ser, addr, 32)
        time.sleep(0.1)

    # Also try with full handshake (programming mode)
    print("\n--- Retrying in full programming mode ---")
    cps_end(ser)
    time.sleep(1)
    ser.reset_input_buffer()

    if cps_handshake(ser, full=True):
        print()
        for name, target in list(PATCH_TARGETS.items())[:2]:
            addr = target["flash_addr"]
            print(f"  [{name}] flash 0x{addr:08X} (programming mode):")
            try_read_flash(ser, addr, 32)
            time.sleep(0.1)

    cps_end(ser)


def cmd_dump(ser, args):
    """Dump flash range to file."""
    addr = int(args.address, 16)
    size = int(args.size, 16) if args.size else 0x1000
    output = args.output or f"dm32_dump_{addr:08X}.bin"

    print(f"\n=== Flash Dump: 0x{addr:08X}, {size} bytes ===\n")

    if not cps_handshake(ser, full=True):
        return

    data = bytearray()
    offset = 0
    while offset < size:
        block = min(256, size - offset)  # read in 256-byte chunks
        chunk = flash_read(ser, addr + offset, block)
        if chunk is None:
            print(f"\n  [!] Read failed at offset 0x{offset:X}")
            break
        data.extend(chunk)
        offset += block
        pct = (offset * 100) // size
        print(f"\r  [{pct:3d}%] Read 0x{offset:X}/{size:X}", end="", flush=True)

    print()
    if data:
        with open(output, "wb") as f:
            f.write(data)
        print(f"  Written {len(data)} bytes to {output}")
        print(hexdump(data[:64], base_addr=addr))

    cps_end(ser)


def cmd_patch(ser, args):
    """Patch a visible string in firmware flash."""
    target_name = args.target
    if target_name not in PATCH_TARGETS:
        print(f"  [!] Unknown target: {target_name}")
        print(f"  Available: {', '.join(PATCH_TARGETS.keys())}")
        return

    target = PATCH_TARGETS[target_name]
    addr = target["flash_addr"]
    original = target["original"]
    patched = target["patched"]

    assert len(original) == len(patched), "Patch must be same length!"

    print(f"\n=== Patch: {target['desc']} ===")
    print(f"  Flash address: 0x{addr:08X}")
    print(f"  Original: {original}")
    print(f"  Patched:  {patched}")
    print(f"  Size: {len(original)} bytes (same length)")

    if args.dry_run:
        print("\n  *** DRY RUN — no data will be sent ***")
        print(f"\n  Would write to 0x{addr:08X}:")
        print(hexdump(patched, base_addr=addr))
        return

    # Safety confirmation
    print(f"\n  This will WRITE to flash address 0x{addr:08X}")
    print(f"  Make sure you have the original firmware for recovery!")
    confirm = input("  Type 'PATCH' to proceed: ")
    if confirm != "PATCH":
        print("  Aborted.")
        return

    print("\n--- Handshake ---")
    if not cps_handshake(ser, full=True):
        print("  [!] Handshake failed")
        return

    # Try to read current value first (for backup)
    print("\n--- Reading current value ---")
    current = flash_read(ser, addr, len(original))
    if current:
        print(f"  Current value at 0x{addr:08X}:")
        print(hexdump(current, base_addr=addr))

        # Save backup
        backup = {
            "target": target_name,
            "flash_addr": f"0x{addr:08X}",
            "original_hex": current.hex(),
            "patched_hex": patched.hex(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        with open(BACKUP_FILE, "w") as f:
            json.dump(backup, f, indent=2)
        print(f"  Backup saved to {BACKUP_FILE}")

        if current == patched:
            print("  [!] Already patched!")
            cps_end(ser)
            return
        if current != original:
            print(f"  [!] WARNING: Current value doesn't match expected original!")
            print(f"  Expected: {original.hex()}")
            print(f"  Got:      {current.hex()}")
            confirm2 = input("  Continue anyway? (yes/no): ")
            if confirm2 != "yes":
                cps_end(ser)
                return
    else:
        print("  [!] Could not read current value (READ may not work for flash)")
        print("  Proceeding with blind write...")
        # Save what we expect
        backup = {
            "target": target_name,
            "flash_addr": f"0x{addr:08X}",
            "original_hex": original.hex(),
            "patched_hex": patched.hex(),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "blind_write": True,
        }
        with open(BACKUP_FILE, "w") as f:
            json.dump(backup, f, indent=2)

    # Write the patch
    print(f"\n--- Writing patch to 0x{addr:08X} ---")
    if flash_write_block(ser, addr, patched):
        print("  WRITE: ACK received!")

        # Verify by reading back
        print("  Verifying...", end=" ", flush=True)
        time.sleep(0.2)
        verify = flash_read(ser, addr, len(patched))
        if verify == patched:
            print("VERIFIED — patch successful!")
        elif verify:
            print(f"readback differs: {verify.hex()}")
        else:
            print("could not read back (normal if READ doesn't work for flash)")
    else:
        print("  [!] WRITE FAILED — no ACK received")

    cps_end(ser)
    print("\n  Power cycle the radio to see the change.")
    print("  Use --restore to revert.")


def cmd_restore(ser, args):
    """Restore original bytes from backup."""
    if not os.path.exists(BACKUP_FILE):
        print(f"  [!] No backup file found ({BACKUP_FILE})")
        print("  Use 'patch' first, or reflash original firmware.")
        return

    with open(BACKUP_FILE) as f:
        backup = json.load(f)

    addr = int(backup["flash_addr"], 16)
    original = bytes.fromhex(backup["original_hex"])

    print(f"\n=== Restore: {backup['target']} ===")
    print(f"  Flash address: {backup['flash_addr']}")
    print(f"  Original bytes: {backup['original_hex']}")
    print(f"  Backup from: {backup['timestamp']}")

    if args.dry_run:
        print("\n  *** DRY RUN ***")
        print(f"  Would write to 0x{addr:08X}:")
        print(hexdump(original, base_addr=addr))
        return

    confirm = input("  Type 'RESTORE' to proceed: ")
    if confirm != "RESTORE":
        print("  Aborted.")
        return

    print("\n--- Handshake ---")
    if not cps_handshake(ser, full=True):
        return

    print(f"\n--- Writing original bytes to 0x{addr:08X} ---")
    if flash_write_block(ser, addr, original):
        print("  WRITE: ACK — restored!")
    else:
        print("  [!] WRITE FAILED")

    cps_end(ser)
    print("\n  Power cycle to verify restoration.")


def cmd_list(args):
    """List available patch targets."""
    print("\n=== Available Patch Targets ===\n")
    for name, target in PATCH_TARGETS.items():
        print(f"  {name:12s}  flash 0x{target['flash_addr']:08X}")
        print(f"               {target['desc']}")
        print(f"               \"{target['original'].rstrip(b'\\x00').decode()}\" → "
              f"\"{target['patched'].rstrip(b'\\x00').decode()}\"")
        print()


def main():
    parser = argparse.ArgumentParser(
        description="DM-32UV Flash Read/Patch PoC",
        epilog="For authorized security research only.")
    parser.add_argument("command", choices=["read", "dump", "patch", "restore", "list"],
                        help="Command to execute")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="Serial port")
    parser.add_argument("--baud", type=int, default=BAUD, help="Baud rate")
    parser.add_argument("--target", default="welcome",
                        help="Patch target name (use 'list' to see options)")
    parser.add_argument("--address", default="0x030A1940",
                        help="Address for dump command")
    parser.add_argument("--size", default=None,
                        help="Size for dump command (hex)")
    parser.add_argument("--output", default=None,
                        help="Output file for dump")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate without sending data")
    args = parser.parse_args()

    if args.command == "list":
        cmd_list(args)
        return

    print("=" * 64)
    print("  DM-32UV Flash Read/Patch PoC")
    print("  For authorized security research only")
    print("=" * 64)

    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.5,
                           bytesize=8, parity="N", stopbits=1)
    except Exception as e:
        print(f"  [!] Cannot open {args.port}: {e}")
        return 1

    time.sleep(0.5)
    ser.reset_input_buffer()

    try:
        if args.command == "read":
            cmd_read(ser, args)
        elif args.command == "dump":
            cmd_dump(ser, args)
        elif args.command == "patch":
            cmd_patch(ser, args)
        elif args.command == "restore":
            cmd_restore(ser, args)
    finally:
        try:
            cps_end(ser)
        except:
            pass
        ser.close()

    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
