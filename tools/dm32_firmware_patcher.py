#!/usr/bin/env python3
"""DM-32UV Firmware Patcher — PoC for V10: No Firmware Signing
================================================================
Demonstrates that the firmware binary has no integrity protection.
The file format is: BFUV32-V2 + 0xFF pad + END + raw flash image.
No checksum, no signature, no encryption.

This tool can:
  1. Parse and display firmware structure
  2. Patch arbitrary bytes (by flash address or file offset)
  3. Extract/replace the IRAM code section
  4. Generate a minimal valid firmware (header + custom payload)

WARNING: Flashing modified firmware can permanently brick your radio.
         For security research purposes only.
"""

import struct
import sys
import hashlib
import os

MAGIC = b"BFUV32-V2"
END_MARKER = b"END"
HEADER_SIZE = 0x100
FLASH_BASE = 0x03000000
IRAM_SRC_FLASH = 0x030BD768
IRAM_DST = 0x00010000

def parse_firmware(path):
    with open(path, "rb") as f:
        data = bytearray(f.read())

    info = {}
    info["path"] = path
    info["size"] = len(data)
    info["magic"] = data[0:9]
    info["end_marker"] = data[0xFD:0x100]
    info["valid"] = (info["magic"] == MAGIC and info["end_marker"] == END_MARKER)
    info["code"] = data[HEADER_SIZE:]
    info["sha256"] = hashlib.sha256(data).hexdigest()
    info["code_sha256"] = hashlib.sha256(info["code"]).hexdigest()

    iram_file_off = (IRAM_SRC_FLASH - FLASH_BASE) + HEADER_SIZE
    info["iram_offset"] = iram_file_off
    info["iram_size"] = len(data) - iram_file_off
    info["iram_data"] = data[iram_file_off:]

    return info, data

def show_info(info):
    print(f"  File: {info['path']}")
    print(f"  Size: {info['size']} bytes (0x{info['size']:X})")
    print(f"  Magic: {info['magic']}")
    print(f"  END marker: {info['end_marker']} ({'OK' if info['end_marker'] == END_MARKER else 'MISSING'})")
    print(f"  Valid header: {'YES' if info['valid'] else 'NO'}")
    print(f"  SHA-256 (full): {info['sha256']}")
    print(f"  SHA-256 (code): {info['code_sha256']}")
    print()
    print(f"  Flash image: 0x{HEADER_SIZE:X}-0x{info['size']-1:X} ({len(info['code'])} bytes)")
    print(f"  Flash mapping: file_offset = flash_addr - 0x{FLASH_BASE:X} + 0x{HEADER_SIZE:X}")
    print(f"  IRAM source: file 0x{info['iram_offset']:X} ({info['iram_size']} bytes)")
    print(f"  IRAM destination: 0x{IRAM_DST:08X}")

def flash_addr_to_file(addr):
    return (addr - FLASH_BASE) + HEADER_SIZE

def file_to_flash_addr(offset):
    return (offset - HEADER_SIZE) + FLASH_BASE

def cmd_info(args):
    path = args[0] if args else "DM32_L01_048_20250821.bin"
    info, _ = parse_firmware(path)
    print("\n=== Firmware Info ===")
    show_info(info)

def cmd_patch(args):
    if len(args) < 3:
        print("Usage: patch <firmware.bin> <address> <hex_bytes> [output.bin]")
        print("  address: 0x03XXXXXX (flash) or +0xXXXX (file offset)")
        return

    path, addr_str, hex_bytes = args[0], args[1], args[2]
    output = args[3] if len(args) > 3 else None

    info, data = parse_firmware(path)

    if addr_str.startswith("+"):
        file_off = int(addr_str[1:], 16)
    elif addr_str.startswith("0x03") or addr_str.startswith("03"):
        flash_addr = int(addr_str, 16)
        file_off = flash_addr_to_file(flash_addr)
    else:
        file_off = int(addr_str, 16)

    patch_bytes = bytes.fromhex(hex_bytes.replace(" ", ""))

    print(f"\n=== Patching Firmware ===")
    print(f"  File offset: 0x{file_off:06X}")
    print(f"  Flash addr:  0x{file_to_flash_addr(file_off):08X}")
    print(f"  Patch size:  {len(patch_bytes)} bytes")
    print(f"  Original:    {' '.join(f'{data[file_off+i]:02X}' for i in range(len(patch_bytes)))}")
    print(f"  New value:   {' '.join(f'{b:02X}' for b in patch_bytes)}")

    data[file_off:file_off+len(patch_bytes)] = patch_bytes

    out_path = output or path.replace(".bin", "_patched.bin")
    with open(out_path, "wb") as f:
        f.write(data)
    print(f"\n  Written to: {out_path}")
    print(f"  SHA-256: {hashlib.sha256(data).hexdigest()}")

def cmd_extract_iram(args):
    path = args[0] if args else "DM32_L01_048_20250821.bin"
    output = args[1] if len(args) > 1 else "dm32_iram.bin"

    info, _ = parse_firmware(path)
    with open(output, "wb") as f:
        f.write(info["iram_data"])
    print(f"\n=== IRAM Extraction ===")
    print(f"  Source: {path} offset 0x{info['iram_offset']:X}")
    print(f"  Size: {info['iram_size']} bytes")
    print(f"  Written to: {output}")
    print(f"  Load address: 0x{IRAM_DST:08X}")

def cmd_build_minimal(args):
    """Build a minimal valid firmware file (for testing bootloader acceptance)."""
    output = args[0] if args else "dm32_minimal.bin"

    header = bytearray(HEADER_SIZE)
    header[0:len(MAGIC)] = MAGIC
    for i in range(len(MAGIC), 0xFD):
        header[i] = 0xFF
    header[0xFD:0x100] = END_MARKER

    # Minimal payload: NOP sled + infinite loop
    # CK803S: NOP = 0x6C00 (mov r0, r0), infinite loop: br . = 0x0400
    nop = struct.pack("<H", 0x6C00)
    loop = struct.pack("<H", 0x0400)
    payload = nop * 64 + loop
    # Pad to reasonable size
    payload = payload + b"\xFF" * (4096 - len(payload))

    firmware = header + payload
    with open(output, "wb") as f:
        f.write(firmware)

    print(f"\n=== Minimal Firmware ===")
    print(f"  Size: {len(firmware)} bytes")
    print(f"  Header: BFUV32-V2 + END")
    print(f"  Payload: 64 NOPs + infinite loop + 0xFF padding")
    print(f"  Written to: {output}")
    print(f"  SHA-256: {hashlib.sha256(firmware).hexdigest()}")
    print()
    print("  WARNING: Do NOT flash this on a radio you want to keep working!")

def cmd_diff(args):
    if len(args) < 2:
        print("Usage: diff <original.bin> <modified.bin>")
        return

    info1, data1 = parse_firmware(args[0])
    info2, data2 = parse_firmware(args[1])

    print(f"\n=== Firmware Diff ===")
    print(f"  File 1: {args[0]} ({len(data1)} bytes)")
    print(f"  File 2: {args[1]} ({len(data2)} bytes)")

    min_len = min(len(data1), len(data2))
    diffs = []
    for i in range(min_len):
        if data1[i] != data2[i]:
            diffs.append(i)

    if len(data1) != len(data2):
        print(f"  Size difference: {len(data2) - len(data1):+d} bytes")

    if not diffs:
        print("  Files are identical (up to common length)")
        return

    print(f"  Differences: {len(diffs)} bytes")
    print()

    # Group consecutive diffs
    groups = []
    start = diffs[0]
    for i in range(1, len(diffs)):
        if diffs[i] != diffs[i-1] + 1:
            groups.append((start, diffs[i-1]))
            start = diffs[i]
    groups.append((start, diffs[-1]))

    for gstart, gend in groups[:20]:
        size = gend - gstart + 1
        flash_addr = file_to_flash_addr(gstart) if gstart >= HEADER_SIZE else gstart
        region = "HEADER" if gstart < HEADER_SIZE else "FLASH"
        print(f"  0x{gstart:06X} ({region} 0x{flash_addr:08X}): {size} bytes")
        for off in range(gstart, min(gend + 1, gstart + 32)):
            print(f"    [{off:06X}] 0x{data1[off]:02X} → 0x{data2[off]:02X}")


COMMANDS = {
    "info": (cmd_info, "Show firmware structure and hashes"),
    "patch": (cmd_patch, "Patch bytes at address: patch <fw> <addr> <hex> [output]"),
    "extract-iram": (cmd_extract_iram, "Extract IRAM code section"),
    "build-minimal": (cmd_build_minimal, "Build minimal valid firmware header"),
    "diff": (cmd_diff, "Compare two firmware files"),
}

def main():
    if len(sys.argv) < 2 or sys.argv[1] not in COMMANDS:
        print("DM-32UV Firmware Patcher")
        print()
        print("Commands:")
        for name, (_, desc) in COMMANDS.items():
            print(f"  {name:20s} {desc}")
        print()
        print("Examples:")
        print("  python3 dm32_firmware_patcher.py info DM32_L01_048_20250821.bin")
        print("  python3 dm32_firmware_patcher.py patch DM32_L01_048_20250821.bin 0x03061BD4 90909090")
        print("  python3 dm32_firmware_patcher.py extract-iram DM32_L01_048_20250821.bin")
        print("  python3 dm32_firmware_patcher.py build-minimal test_fw.bin")
        return

    cmd = sys.argv[1]
    COMMANDS[cmd][0](sys.argv[2:])


if __name__ == "__main__":
    main()
