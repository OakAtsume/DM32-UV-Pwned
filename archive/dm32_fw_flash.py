#!/usr/bin/env python3
"""DM-32UV Firmware Flash Protocol — Full CPS Protocol Reimplementation
========================================================================
Decoded from CPS.exe (DMR CPS.exe) FUN_0041d280: the complete firmware
update handshake + write loop, reverse engineered from x86 disassembly.

Supports two modes:
  --bootloader : Flash via hardware bootloader (SK1+PTT power-on, green LED)
  --cps        : Flash via normal CPS firmware update (radio powered on normally)

The CPS firmware update protocol is the SAME serial protocol as CPS
programming, reused with larger write blocks (4KB vs 48B for config).

Protocol decoded from CPS.exe at:
  FUN_0041d280 (0x0041d280-0x0041f0a2) — 7714 bytes, main firmware handler
  Handshake: PSEARCH→PASSSTA→SYSINFO→V-frames→G-query→PROGRAM→mode 0x02
  Write: 'W' + 3-byte addr (LE) + 2-byte size (LE) + data (up to 4096B)

DANGER: Flashing modified firmware WILL brick the radio if the image is
        wrong. For authorized security research only.
"""

import serial
import time
import sys
import struct
import hashlib
import argparse
import os

BAUD = 115200
MAGIC = b"BFUV32-V2"
END_MARKER = b"END"
HEADER_SIZE = 0x100
FLASH_BASE = 0x03000000
BLOCK_SIZE = 0x1000  # 4096 bytes per write block
ACK = 0x06

# Hardcoded factory password for firmware flash mode (from CPS @ 0x004e616c)
FW_PASSWORD = "66660501"


def hexdump(data, prefix="  "):
    if not data:
        return f"{prefix}(empty)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04X}: {hexpart:<48s} |{ascpart}|")
    return "\n".join(lines)


def serial_write(ser, data, timeout=10):
    """Write data to serial, return True on success."""
    try:
        ser.write(data)
        ser.flush()
        return True
    except Exception as e:
        print(f"  [!] Write error: {e}")
        return False


def serial_read(ser, count, timeout=2.0):
    """Read exactly count bytes with timeout."""
    end = time.time() + timeout
    data = bytearray()
    while len(data) < count and time.time() < end:
        remaining = count - len(data)
        ser.timeout = max(0.01, end - time.time())
        chunk = ser.read(remaining)
        if chunk:
            data.extend(chunk)
    return bytes(data)


def serial_read_any(ser, timeout=2.0):
    """Read whatever comes back within timeout."""
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    last_rx = time.time()
    while time.time() < end:
        b = ser.read(64)
        if b:
            data.extend(b)
            last_rx = time.time()
        elif data and time.time() - last_rx > 0.2:
            break
    return bytes(data)


def validate_firmware(path):
    """Validate firmware file format."""
    with open(path, "rb") as f:
        data = f.read()

    if len(data) < HEADER_SIZE + 16:
        print(f"  [!] File too small: {len(data)} bytes")
        return None

    if data[0:9] != MAGIC:
        print(f"  [!] Bad magic: {data[0:9]} (expected {MAGIC})")
        return None

    if data[0xFD:0x100] != END_MARKER:
        print(f"  [!] Missing END marker at offset 0xFD")
        return None

    payload = data[HEADER_SIZE:]
    print(f"  File: {path}")
    print(f"  Size: {len(data)} bytes (header: {HEADER_SIZE}, payload: {len(payload)})")
    print(f"  Magic: {data[0:9].decode('ascii')}")
    print(f"  SHA-256: {hashlib.sha256(data).hexdigest()[:16]}...")
    print(f"  Payload SHA-256: {hashlib.sha256(payload).hexdigest()[:16]}...")
    return payload


def handshake_psearch(ser, retries=5):
    """Phase 1: PSEARCH — discover radio."""
    for attempt in range(retries):
        print(f"  PSEARCH (attempt {attempt+1}/{retries})...", end=" ")
        ser.reset_input_buffer()
        serial_write(ser, b"PSEARCH")
        resp = serial_read(ser, 8, timeout=2.0)
        if len(resp) >= 1 and resp[0] == ACK:
            model = resp[1:].decode("ascii", errors="replace").rstrip("\x00")
            print(f"ACK — model: {model}")
            return model
        print(f"no ACK ({len(resp)}B: {resp.hex() if resp else 'empty'})")
        time.sleep(0.5)
    return None


def handshake_passsta(ser):
    """Phase 2: PASSSTA — password/auth negotiation."""
    print("  PASSSTA...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, b"PASSSTA")
    resp = serial_read(ser, 8, timeout=1.0)
    if resp:
        print(f"response: {resp.hex()}")
    else:
        print("no response (may be OK for bootloader)")
    return resp


def handshake_sysinfo(ser):
    """Phase 3: SYSINFO — system info query."""
    print("  SYSINFO...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, b"SYSINFO")
    resp = serial_read(ser, 1, timeout=1.0)
    if resp and resp[0] == ACK:
        print("ACK")
        return True
    print(f"response: {resp.hex() if resp else 'none'}")
    return resp


def send_vframe(ser, vid, page=0x00):
    """Send V-frame command and return response data."""
    cmd = bytes([0x56, 0x00, 0x00, page, vid])
    ser.reset_input_buffer()
    serial_write(ser, cmd)
    # V-frame response: 0x56 + 2 bytes (includes data length at byte[2])
    header = serial_read(ser, 3, timeout=0.5)
    if len(header) < 3 or header[0] != 0x56:
        return header
    data_len = header[2]
    if data_len > 0:
        data = serial_read(ser, data_len, timeout=0.5)
        return header + data
    return header


def handshake_vframes(ser):
    """Phase 4: V-frame queries for device version info."""
    print("  V-frame 0x0D (page 0x40)...", end=" ")
    resp = send_vframe(ser, 0x0D, page=0x40)
    if resp:
        print(f"{len(resp)}B: {resp[:16].hex()}")
    else:
        print("no response")

    versions = {}
    for vid in range(6, 9):
        print(f"  V-frame 0x{vid:02X}...", end=" ")
        resp = send_vframe(ser, vid, page=0x00)
        if resp and len(resp) >= 3:
            data_len = resp[2] if len(resp) > 2 else 0
            print(f"{len(resp)}B (data: {data_len}B)")
            versions[vid] = resp
        else:
            print(f"response: {resp.hex() if resp else 'none'}")
    return versions


def handshake_gquery(ser):
    """Phase 5: G-query — get extended device info (262 bytes)."""
    print("  G-query...", end=" ")
    cmd = bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01])
    ser.reset_input_buffer()
    serial_write(ser, cmd)
    resp = serial_read(ser, 0x106, timeout=1.0)
    if len(resp) >= 1 and resp[0] == 0x53:  # 'S' response
        print(f"OK — {len(resp)} bytes (starts with 'S')")
        return resp
    print(f"unexpected: {len(resp)}B")
    # Drain any remaining data
    extra = serial_read_any(ser, timeout=0.5)
    if extra:
        resp += extra
    return resp


def handshake_program(ser):
    """Phase 6: Enter PROGRAM mode (preamble + PROGRAM + mode 0x02)."""
    # Preamble
    print("  Preamble FF FF FF FF 0C...", end=" ")
    serial_write(ser, b"\xFF\xFF\xFF\xFF\x0C")
    time.sleep(0.01)
    print("sent")

    # PROGRAM command
    print("  PROGRAM...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, b"PROGRAM")
    resp = serial_read(ser, 1, timeout=1.0)
    if not resp or resp[0] != ACK:
        print(f"FAILED — expected ACK, got: {resp.hex() if resp else 'none'}")
        return False
    print("ACK")

    # Mode 0x02
    print("  Mode 0x02...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, bytes([0x02]))
    resp = serial_read(ser, 8, timeout=2.0)
    if len(resp) < 8:
        print(f"FAILED — expected 8 bytes, got {len(resp)}")
        return False
    model_info = resp
    print(f"device info: {resp.hex()}")

    # Send ACK
    print("  Confirm ACK...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, bytes([ACK]))
    resp = serial_read(ser, 1, timeout=1.0)
    if resp and resp[0] == ACK:
        print("ACK — programming mode ACTIVE")
        return True
    print(f"response: {resp.hex() if resp else 'none'}")
    return False


def write_firmware(ser, payload, base_addr=0, dry_run=False):
    """Write firmware payload in 4KB blocks using 'W' command.

    Protocol (from CPS FUN_0041d280 @ 0x0041E710):
      TX: 'W' + addr_lo + addr_mid + addr_hi + size_lo + size_hi + data
      RX: ACK (0x06) — 5 second timeout per block

    Address is 3 bytes LE = (base_addr + offset) split into bytes.
    Block size is 2 bytes LE, max 0x1000 (4096).
    """
    total = len(payload)
    blocks = (total + BLOCK_SIZE - 1) // BLOCK_SIZE
    print(f"\n  Writing {total} bytes in {blocks} blocks of {BLOCK_SIZE}B max")
    print(f"  Base address: 0x{base_addr:06X}")

    offset = 0
    block_num = 0
    errors = 0

    while offset < total:
        remaining = total - offset
        block_size = min(remaining, BLOCK_SIZE)

        addr = base_addr + offset
        addr_lo = addr & 0xFF
        addr_mid = (addr >> 8) & 0xFF
        addr_hi = (addr >> 16) & 0xFF
        size_lo = block_size & 0xFF
        size_hi = (block_size >> 8) & 0xFF

        header = bytes([0x57, addr_lo, addr_mid, addr_hi, size_lo, size_hi])
        data = payload[offset:offset + block_size]
        packet = header + data

        pct = (offset * 100) // total
        print(f"\r  [{pct:3d}%] Block {block_num}/{blocks}: "
              f"addr 0x{addr:06X}, {block_size}B", end="", flush=True)

        if dry_run:
            offset += block_size
            block_num += 1
            continue

        ser.reset_input_buffer()
        if not serial_write(ser, packet):
            print(f"\n  [!] Write failed at block {block_num}")
            return False

        resp = serial_read(ser, 1, timeout=5.0)
        if not resp or resp[0] != ACK:
            errors += 1
            print(f"\n  [!] No ACK at block {block_num} "
                  f"(got: {resp.hex() if resp else 'none'})")
            if errors > 3:
                print("  [!] Too many errors, aborting")
                return False
            continue

        offset += block_size
        block_num += 1

    print(f"\r  [100%] Done — {block_num} blocks written, {errors} errors")
    return errors == 0


def do_full_cps_flash(ser, payload, dry_run=False):
    """Full CPS firmware update sequence (normal mode, not bootloader)."""
    print("\n=== CPS Firmware Flash Protocol ===")
    print("  Decoded from CPS.exe FUN_0041d280\n")

    # Phase 1: PSEARCH
    model = handshake_psearch(ser)
    if not model:
        print("  [!] Radio not responding to PSEARCH")
        return False

    # Phase 2: PASSSTA
    handshake_passsta(ser)

    # Phase 3: SYSINFO
    handshake_sysinfo(ser)

    # Phase 4: V-frames
    handshake_vframes(ser)

    # Phase 5: G-query
    gdata = handshake_gquery(ser)
    # Drain any leftover G-query data
    time.sleep(0.3)
    ser.timeout = 0.3
    ser.read(300)
    time.sleep(0.2)
    ser.read(64)

    # Phase 6: PROGRAM mode
    if not handshake_program(ser):
        print("  [!] Failed to enter programming mode")
        return False

    # Phase 7: Write firmware
    print("\n  --- Firmware Write ---")
    success = write_firmware(ser, payload, base_addr=0, dry_run=dry_run)

    # Phase 8: End
    print("\n  Sending END (0x45)...")
    serial_write(ser, bytes([0x45]))
    time.sleep(0.5)

    return success


def do_bootloader_flash(ser, payload, dry_run=False):
    """Bootloader mode firmware flash (SK1+PTT power-on).

    The bootloader may use a different/simplified protocol.
    This tries the CPS protocol first, then falls back to probing.
    """
    print("\n=== Bootloader Mode Flash ===")
    print("  Radio must be in bootloader mode (green LED)\n")

    # Try CPS protocol first — bootloader might accept it
    model = handshake_psearch(ser)
    if model:
        print(f"  Bootloader responds to PSEARCH! Model: {model}")
        print("  Attempting CPS protocol...")
        return do_full_cps_flash(ser, payload, dry_run=dry_run)

    # Bootloader doesn't respond to PSEARCH — try alternatives
    print("\n  PSEARCH failed. Trying bootloader-specific probes...\n")

    # Try direct PROGRAM
    print("  Direct PROGRAM...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, b"PROGRAM")
    resp = serial_read(ser, 1, timeout=1.0)
    if resp and resp[0] == ACK:
        print("ACK!")
        if handshake_program(ser):
            return write_firmware(ser, payload, dry_run=dry_run)

    # Try preamble + PROGRAM
    print("  Preamble + PROGRAM...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, b"\xFF\xFF\xFF\xFF\x0C")
    time.sleep(0.01)
    serial_write(ser, b"PROGRAM")
    resp = serial_read(ser, 1, timeout=1.0)
    if resp and resp[0] == ACK:
        print("ACK!")
        ser.reset_input_buffer()
        serial_write(ser, bytes([0x02]))
        resp = serial_read(ser, 8, timeout=2.0)
        if len(resp) >= 8:
            serial_write(ser, bytes([ACK]))
            serial_read(ser, 1, timeout=1.0)
            return write_firmware(ser, payload, dry_run=dry_run)

    # Try firmware magic as handshake
    print("  BFUV32-V2 magic...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, MAGIC)
    resp = serial_read_any(ser, timeout=1.0)
    if resp:
        print(f"response: {resp.hex()}")
    else:
        print("no response")

    # Try mode byte alone
    print("  Mode 0x02 alone...", end=" ")
    ser.reset_input_buffer()
    serial_write(ser, bytes([0x02]))
    resp = serial_read_any(ser, timeout=1.0)
    if resp:
        print(f"response: {resp.hex()}")
    else:
        print("no response")

    print("\n  [!] Could not establish bootloader protocol.")
    print("  [!] Run dm32_bootloader_probe.py for comprehensive protocol scan.")
    return False


def main():
    parser = argparse.ArgumentParser(
        description="DM-32UV Firmware Flash — CPS Protocol Reimplementation",
        epilog="DANGER: Flashing wrong firmware WILL brick your radio!")
    parser.add_argument("firmware", help="Firmware .bin file to flash")
    parser.add_argument("--port", default="/dev/ttyUSB0", help="Serial port")
    parser.add_argument("--baud", type=int, default=BAUD, help="Baud rate")
    parser.add_argument("--bootloader", action="store_true",
                        help="Use bootloader mode (SK1+PTT)")
    parser.add_argument("--cps", action="store_true",
                        help="Use CPS mode (normal power-on)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Simulate write without actually sending data")
    parser.add_argument("--raw", action="store_true",
                        help="Send raw file bytes (skip header validation)")
    args = parser.parse_args()

    if not args.bootloader and not args.cps:
        parser.error("Must specify --bootloader or --cps mode")

    print("=" * 64)
    print("  DM-32UV Firmware Flash Tool")
    print("  Decoded from CPS.exe — for security research only")
    print("=" * 64)

    if not os.path.exists(args.firmware):
        print(f"  [!] File not found: {args.firmware}")
        return 1

    # Validate and extract firmware payload
    print(f"\n--- Firmware Validation ---")
    if args.raw:
        with open(args.firmware, "rb") as f:
            payload = f.read()
        print(f"  Raw mode: {len(payload)} bytes")
    else:
        payload = validate_firmware(args.firmware)
        if payload is None:
            return 1

    if args.dry_run:
        print("\n  *** DRY RUN MODE — no data will be sent to radio ***")

    if not args.dry_run:
        print(f"\n  WARNING: This will overwrite the radio's firmware!")
        print(f"  Payload: {len(payload)} bytes")
        confirm = input("  Type 'FLASH' to proceed: ")
        if confirm != "FLASH":
            print("  Aborted.")
            return 0

    # Open serial
    print(f"\n--- Serial: {args.port} @ {args.baud} ---")
    try:
        ser = serial.Serial(args.port, args.baud, timeout=0.5,
                           bytesize=8, parity="N", stopbits=1)
    except Exception as e:
        print(f"  [!] Cannot open {args.port}: {e}")
        return 1

    time.sleep(0.5)
    ser.reset_input_buffer()

    try:
        if args.bootloader:
            success = do_bootloader_flash(ser, payload, dry_run=args.dry_run)
        else:
            success = do_full_cps_flash(ser, payload, dry_run=args.dry_run)
    finally:
        ser.close()

    if success:
        print("\n  Flash complete!")
        print("  Power cycle the radio.")
        print("  If radio doesn't boot: factory reset (SK1+SK2 during power-on)")
    else:
        print("\n  [!] Flash FAILED — radio may be in unknown state")
        print("  [!] Try bootloader mode (SK1+PTT) to recover")

    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
