#!/usr/bin/env python3
"""DM-32UV YMODEM Firmware Flasher
====================================
Decoded from live CPS capture (2026-10-20).

The firmware update uses YMODEM-1K with a custom pre-handshake:
  Phase 1: 'R' (0x52) polling until ACK
  Phase 2: 'M' command → model string (BFUV32-V2)
  Phase 3: 'E' command → erase/prepare flash
  Phase 4: YMODEM-1K CRC-16 transfer (0x31 → 'C')
  Phase 5: SOH block 0 (filename + size metadata)
  Phase 6: STX blocks 1-N (1024B firmware data + CRC)
  Phase 7: EOT (0x04) → done

Firmware .bin format: 256-byte header (BFUV32-V2 + padding) + raw flash image.
YMODEM transfers only the flash image (offset 256+), not the header.

Usage:
  python3 dm32_ymodem_flash.py flash firmware.bin [--port /dev/ttyUSB0]
  python3 dm32_ymodem_flash.py read-model [--port /dev/ttyUSB0]
  python3 dm32_ymodem_flash.py verify firmware.bin [--port /dev/ttyUSB0]
"""

import serial
import struct
import sys
import time
import os
import argparse

SOH = 0x01
STX = 0x02
EOT = 0x04
ACK = 0x06
NAK = 0x15
CRC_MODE = 0x43  # 'C'

FW_HEADER_SIZE = 256
FW_MAGIC = b"BFUV32-V2"
BLOCK_SIZE = 1024
META_BLOCK_SIZE = 128

DEFAULT_PORT = "/dev/ttyUSB0"
DEFAULT_BAUD = 115200


def crc16_xmodem(data):
    crc = 0
    for b in data:
        crc ^= b << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc


def read_response(ser, count=1, timeout=5.0):
    end = time.time() + timeout
    data = bytearray()
    while len(data) < count and time.time() < end:
        ser.timeout = max(0.01, end - time.time())
        chunk = ser.read(count - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)


def read_any(ser, timeout=2.0):
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    last = time.time()
    while time.time() < end:
        b = ser.read(64)
        if b:
            data.extend(b)
            last = time.time()
        elif data and time.time() - last > 0.3:
            break
    return bytes(data)


def validate_firmware(path):
    with open(path, "rb") as f:
        header = f.read(FW_HEADER_SIZE)
        f.seek(0, 2)
        total = f.tell()

    if len(header) < FW_HEADER_SIZE:
        return None, "File too small for firmware header"

    if not header.startswith(FW_MAGIC):
        return None, f"Bad magic: expected {FW_MAGIC}, got {header[:9]}"

    flash_size = total - FW_HEADER_SIZE
    if flash_size <= 0:
        return None, "No flash data after header"

    blocks = (flash_size + BLOCK_SIZE - 1) // BLOCK_SIZE
    return {
        "path": path,
        "total_size": total,
        "flash_size": flash_size,
        "blocks": blocks,
        "magic": header[:9].decode("ascii", errors="replace"),
    }, None


def phase1_contact(ser, max_retries=10):
    """Send 'R' (0x52) until radio ACKs."""
    for i in range(max_retries):
        ser.reset_input_buffer()
        ser.write(b"\x52")
        ser.flush()
        resp = read_response(ser, 1, timeout=3.0)
        if resp == bytes([ACK]):
            return True
        status = f"0x{resp[0]:02X}" if resp else "timeout"
        print(f"  Attempt {i+1}/{max_retries}: {status}")
        time.sleep(1.0)
    return False


def phase2_model(ser):
    """Send 'M' command, receive model string."""
    ser.write(bytes([0x4D, 0x00, 0x00, 0x00, 0x01]))
    ser.flush()
    resp = read_response(ser, 3, timeout=3.0)
    if len(resp) < 3 or resp[0] != 0x4D:
        return None
    data_len = resp[2]
    ser.write(bytes([ACK]))
    ser.flush()
    model_data = read_response(ser, data_len, timeout=3.0)
    return model_data.decode("ascii", errors="replace")


def phase3_erase(ser):
    """Send 'E' command to erase/prepare flash."""
    ser.write(bytes([0x45, 0x00, 0x00, 0x00, 0x00]))
    ser.flush()
    resp = read_response(ser, 1, timeout=10.0)
    return resp == bytes([ACK])


def phase4_ymodem_init(ser):
    """Initiate YMODEM CRC-16 mode."""
    ser.write(bytes([0x31]))
    ser.flush()
    resp = read_response(ser, 1, timeout=5.0)
    return resp == bytes([CRC_MODE])


def send_metadata_block(ser, filename, filesize):
    """Send YMODEM block 0 (SOH, 128-byte metadata)."""
    ser.write(bytes([SOH]))
    ser.flush()
    resp = read_response(ser, 1, timeout=5.0)
    if resp != bytes([CRC_MODE]):
        return False

    payload = bytearray(META_BLOCK_SIZE)
    name_bytes = os.path.basename(filename).encode("ascii")
    size_bytes = str(filesize).encode("ascii")
    offset = 0
    payload[offset:offset + len(name_bytes)] = name_bytes
    offset += len(name_bytes) + 1
    payload[offset:offset + len(size_bytes)] = size_bytes

    crc = crc16_xmodem(payload)
    packet = bytes([0x00, 0xFF]) + bytes(payload) + struct.pack(">H", crc)
    ser.write(packet)
    ser.flush()

    resp = read_response(ser, 2, timeout=10.0)
    return len(resp) >= 1 and resp[0] == ACK


def send_data_block(ser, block_num, data):
    """Send one YMODEM-1K data block (STX, 1024 bytes)."""
    ser.write(bytes([STX]))
    ser.flush()
    resp = read_response(ser, 1, timeout=5.0)
    if resp != bytes([CRC_MODE]):
        return False

    padded = bytearray(BLOCK_SIZE)
    padded[:len(data)] = data

    crc = crc16_xmodem(padded)
    blk = block_num & 0xFF
    packet = bytes([blk, 0xFF - blk]) + bytes(padded) + struct.pack(">H", crc)
    ser.write(packet)
    ser.flush()

    resp = read_response(ser, 1, timeout=5.0)
    return resp == bytes([ACK])


def send_eot(ser):
    """Send EOT to finish transfer."""
    ser.write(bytes([EOT]))
    ser.flush()
    resp = read_any(ser, timeout=3.0)
    return resp


def cmd_flash(args):
    info, err = validate_firmware(args.firmware)
    if err:
        print(f"Error: {err}")
        return 1

    print(f"Firmware: {info['path']}")
    print(f"  Magic:      {info['magic']}")
    print(f"  Flash size:  {info['flash_size']} bytes ({info['blocks']} blocks)")

    if not args.yes:
        ans = input("\nFlash this firmware? This will OVERWRITE the radio's firmware. [y/N] ")
        if ans.lower() != "y":
            print("Aborted.")
            return 0

    ser = serial.Serial(args.port, DEFAULT_BAUD, timeout=0.5,
                        bytesize=8, parity="N", stopbits=1)
    time.sleep(0.3)
    ser.reset_input_buffer()

    print("\n[1/7] Contacting radio...")
    if not phase1_contact(ser):
        print("FAILED: No response. Is radio in bootloader mode (SK1+PTT)?")
        ser.close()
        return 1
    print("  OK — radio responded")

    print("[2/7] Reading model...")
    model = phase2_model(ser)
    if not model:
        print("FAILED: No model response")
        ser.close()
        return 1
    print(f"  Model: {model}")

    if model != "BFUV32-V2":
        print(f"  WARNING: Expected BFUV32-V2, got {model}")
        if not args.yes:
            ans = input("  Continue anyway? [y/N] ")
            if ans.lower() != "y":
                ser.close()
                return 0

    print("[3/7] Erasing flash...")
    if not phase3_erase(ser):
        print("FAILED: Erase command not acknowledged")
        ser.close()
        return 1
    print("  OK — flash prepared")

    print("[4/7] Initiating YMODEM transfer...")
    if not phase4_ymodem_init(ser):
        print("FAILED: YMODEM init rejected")
        ser.close()
        return 1
    print("  OK — CRC-16 mode active")

    print("[5/7] Sending metadata...")
    if not send_metadata_block(ser, info["path"], info["flash_size"]):
        print("FAILED: Metadata block rejected")
        ser.close()
        return 1
    print("  OK")

    print(f"[6/7] Flashing {info['blocks']} blocks...")
    with open(args.firmware, "rb") as f:
        f.seek(FW_HEADER_SIZE)
        flash_data = f.read()

    start = time.time()
    for i in range(info["blocks"]):
        offset = i * BLOCK_SIZE
        chunk = flash_data[offset:offset + BLOCK_SIZE]
        if not send_data_block(ser, i + 1, chunk):
            print(f"\n  FAILED at block {i+1}/{info['blocks']} (offset 0x{offset:06X})")
            ser.close()
            return 1
        elapsed = time.time() - start
        pct = (i + 1) / info["blocks"] * 100
        rate = (i + 1) * BLOCK_SIZE / elapsed / 1024 if elapsed > 0 else 0
        eta = (elapsed / (i + 1)) * (info["blocks"] - i - 1) if i > 0 else 0
        print(f"\r  [{pct:5.1f}%] Block {i+1}/{info['blocks']}  "
              f"{rate:.1f} KB/s  ETA {eta:.0f}s   ", end="", flush=True)

    elapsed = time.time() - start
    print(f"\n  Done in {elapsed:.1f}s ({info['flash_size']/1024:.0f} KB)")

    print("[7/7] Finalizing...")
    resp = send_eot(ser)
    if resp:
        print(f"  Radio response: {' '.join(f'{b:02X}' for b in resp)}")
    print("  Flash complete! Power cycle the radio.")

    ser.close()
    return 0


def cmd_read_model(args):
    ser = serial.Serial(args.port, DEFAULT_BAUD, timeout=0.5,
                        bytesize=8, parity="N", stopbits=1)
    time.sleep(0.3)
    ser.reset_input_buffer()

    print("Contacting radio...")
    if not phase1_contact(ser):
        print("FAILED: No response")
        ser.close()
        return 1
    print("  OK")

    model = phase2_model(ser)
    if model:
        print(f"Model: {model}")
    else:
        print("No model response")

    ser.close()
    return 0


def cmd_verify(args):
    info, err = validate_firmware(args.firmware)
    if err:
        print(f"Error: {err}")
        return 1

    print(f"Firmware: {info['path']}")
    print(f"  Magic:       {info['magic']}")
    print(f"  Total size:  {info['total_size']} bytes")
    print(f"  Flash size:  {info['flash_size']} bytes")
    print(f"  Blocks:      {info['blocks']} x {BLOCK_SIZE}B")

    with open(args.firmware, "rb") as f:
        header = f.read(FW_HEADER_SIZE)
        flash = f.read()

    last_nonzero = len(flash) - 1
    while last_nonzero > 0 and flash[last_nonzero] == 0:
        last_nonzero -= 1
    print(f"  Last non-zero byte at flash offset 0x{last_nonzero:06X}")

    total_crc = crc16_xmodem(flash)
    print(f"  Flash CRC-16/XMODEM: 0x{total_crc:04X}")
    print("  Valid: YES")
    return 0


def main():
    parser = argparse.ArgumentParser(description="DM-32UV YMODEM Firmware Flasher")
    parser.add_argument("--port", default=DEFAULT_PORT)
    sub = parser.add_subparsers(dest="command")

    p_flash = sub.add_parser("flash", help="Flash firmware to radio")
    p_flash.add_argument("firmware", help="Firmware .bin file")
    p_flash.add_argument("--port", default=None, help="Override serial port")
    p_flash.add_argument("-y", "--yes", action="store_true", help="Skip confirmation")

    p_model = sub.add_parser("read-model", help="Read bootloader model string")
    p_model.add_argument("--port", default=None, help="Override serial port")

    p_verify = sub.add_parser("verify", help="Verify firmware file integrity")
    p_verify.add_argument("firmware", help="Firmware .bin file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    # Subcommand --port overrides top-level --port
    if hasattr(args, "port") and args.port is None:
        args.port = parser.parse_args([]).port  # get top-level default
    # Re-parse to get top-level --port if subcommand didn't override
    top_args, _ = parser.parse_known_args()
    if not hasattr(args, "port") or args.port is None:
        args.port = top_args.port

    if args.command == "flash":
        return cmd_flash(args)
    elif args.command == "read-model":
        return cmd_read_model(args)
    elif args.command == "verify":
        return cmd_verify(args)


if __name__ == "__main__":
    sys.exit(main())
