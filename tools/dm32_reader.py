#!/usr/bin/env python3
"""DM-32UV Codeplug/Flash Reader
==================================
Uses the CPS programming protocol (PSEARCH handshake) to read
data from the radio in NORMAL mode (not bootloader).

Protocol decoded from live CPS capture (dm32_capture2.log).
Radio must be powered on normally — NOT in bootloader mode.

Usage:
  python3 dm32_reader.py info                    # Read radio info (model, version, IDs)
  python3 dm32_reader.py read 0x000000 256       # Read 256 bytes from address
  python3 dm32_reader.py dump 0x000000 0x001000 out.bin  # Dump range to file
  python3 dm32_reader.py keys                    # Read AES encryption keys
  python3 dm32_reader.py id                      # Read DMR ID, callsign, owner name
"""

import serial
import time
import sys
import struct
import os

PORT = "/dev/ttyUSB0"
BAUD = 115200
ACK = 0x06


def hexdump(data, base_addr=0, prefix="  "):
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        h = " ".join(f"{b:02X}" for b in chunk)
        a = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{base_addr+i:06X}: {h:<48s} |{a}|")
    return "\n".join(lines)


def read_resp(ser, count, timeout=3.0):
    end = time.time() + timeout
    data = bytearray()
    while len(data) < count and time.time() < end:
        ser.timeout = max(0.01, end - time.time())
        chunk = ser.read(count - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)


def read_any(ser, timeout=1.5):
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    last = time.time()
    while time.time() < end:
        b = ser.read(512)
        if b:
            data.extend(b)
            last = time.time()
        elif data and time.time() - last > 0.3:
            break
    return bytes(data)


def drain(ser):
    ser.timeout = 0.05
    while ser.read(256):
        pass


class DM32Reader:
    def __init__(self, port=PORT):
        self.ser = serial.Serial(port, BAUD, timeout=0.5,
                                 bytesize=8, parity="N", stopbits=1)
        time.sleep(0.3)
        self.ser.reset_input_buffer()
        self.in_program_mode = False

    def close(self):
        if self.in_program_mode:
            self.ser.write(b"\x45")  # END
            self.ser.flush()
            time.sleep(0.2)
        self.ser.close()

    def handshake(self, password="123"):
        """Full CPS handshake: PSEARCH → PASSSTA → PASWORD → PR → SYSINFO → V-frames → PROGRAM → mode"""
        ser = self.ser

        # PSEARCH
        print("  PSEARCH...", end=" ", flush=True)
        for i in range(5):
            drain(ser)
            ser.write(b"PSEARCH")
            ser.flush()
            resp = read_resp(ser, 8, timeout=2.0)
            if resp and resp[0] == ACK:
                model = resp[1:].rstrip(b"\x00").decode("ascii", errors="replace")
                print(f"OK — model: {model!r}")
                break
            time.sleep(0.5)
        else:
            print("FAILED")
            return False

        # PASSSTA
        print("  PASSSTA...", end=" ", flush=True)
        drain(ser)
        ser.write(b"PASSSTA")
        ser.flush()
        resp = read_any(ser, 1.0)
        if not resp:
            print("no response")
            return False
        if resp[0] == 0x50:
            print(f"password required ({' '.join(f'{b:02X}' for b in resp)})")
            # PASWORD
            ser.write(b"PASWORD")
            ser.flush()
            resp2 = read_resp(ser, 1, timeout=1.0)
            if resp2 and resp2[0] == ACK:
                print("  PASWORD...OK")
            # PR + password
            pw_bytes = password.encode("ascii")
            pr_cmd = b"PR" + pw_bytes + b"\x00" + b"\xFF" * (10 - 2 - len(pw_bytes) - 1)
            pr_cmd = pr_cmd[:10]
            ser.write(pr_cmd)
            ser.flush()
            resp3 = read_resp(ser, 1, timeout=1.0)
            if resp3 and resp3[0] == ACK:
                print(f"  PR({password})...OK")
            else:
                print(f"  PR({password})...rejected")
                return False
        elif resp[0] == ACK:
            print("OK (no password needed)")
        else:
            print(f"unexpected: {' '.join(f'{b:02X}' for b in resp)}")

        # SYSINFO
        print("  SYSINFO...", end=" ", flush=True)
        drain(ser)
        ser.write(b"SYSINFO")
        ser.flush()
        resp = read_resp(ser, 1, timeout=1.0)
        if resp and resp[0] == ACK:
            print("OK")
        else:
            print(f"{'no response' if not resp else ' '.join(f'{b:02X}' for b in resp)}")

        # V-frame 0x0D (device info)
        print("  V-frames...", end=" ", flush=True)
        drain(ser)
        ser.write(bytes([0x56, 0x00, 0x00, 0x40, 0x0D]))
        ser.flush()
        resp = read_any(ser, 1.0)
        v_count = 0
        if resp and resp[0] == 0x56:
            v_count += 1

        # V-frames 0x01-0x0B (skip 0x0C)
        for vid in range(1, 12):
            drain(ser)
            ser.write(bytes([0x56, 0x00, 0x00, 0x00, vid]))
            ser.flush()
            resp = read_any(ser, 0.5)
            if resp and resp[0] == 0x56:
                v_count += 1
                if vid == 1 and len(resp) >= 3:
                    ver = resp[3:].decode("ascii", errors="replace")
                    print(f"version={ver!r}", end=" ", flush=True)
        # Skip 0x0C, do 0x0D again if needed
        drain(ser)
        ser.write(bytes([0x56, 0x00, 0x00, 0x00, 0x0D]))
        ser.flush()
        read_any(ser, 0.5)
        print(f"({v_count} frames)")

        # G-query
        print("  G-query...", end=" ", flush=True)
        drain(ser)
        ser.write(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01]))
        ser.flush()
        resp = read_any(ser, 2.0)
        if resp and resp[0] == 0x53:
            print(f"OK ({len(resp)}B)")
        else:
            print(f"{'no response' if not resp else resp[0]:02X}")

        # Preamble + PROGRAM
        print("  PROGRAM...", end=" ", flush=True)
        drain(ser)
        ser.write(b"\xFF\xFF\xFF\xFF\x0C")
        ser.flush()
        time.sleep(0.05)
        ser.write(b"PROGRAM")
        ser.flush()
        resp = read_resp(ser, 1, timeout=2.0)
        if not resp or resp[0] != ACK:
            print("FAILED")
            return False
        print("OK")

        # Mode 0x02
        print("  Mode 0x02...", end=" ", flush=True)
        drain(ser)
        ser.write(bytes([0x02]))
        ser.flush()
        resp = read_any(ser, 1.0)
        if resp and len(resp) >= 8:
            print(f"OK — device info: {' '.join(f'{b:02X}' for b in resp[:8])}")
        else:
            print(f"unexpected: {' '.join(f'{b:02X}' for b in resp) if resp else 'none'}")
            return False

        # ACK exchange
        drain(ser)
        ser.write(bytes([ACK]))
        ser.flush()
        resp = read_resp(ser, 1, timeout=1.0)
        if resp and resp[0] == ACK:
            print("  Programming mode ACTIVE")
            self.in_program_mode = True
            return True
        else:
            print(f"  ACK exchange failed")
            return False

    def read_block(self, addr, size=4096):
        """Read a block using the CPS READ command.
        Format: R(52) + addr(3B LE) + size(2B LE) → W(57) + addr(3B) + size(2B) + data"""
        ser = self.ser
        drain(ser)
        cmd = bytes([0x52,
            addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
            size & 0xFF, (size >> 8) & 0xFF])
        ser.write(cmd)
        ser.flush()

        # Expect: 57 + 3-byte addr + 2-byte size + data (6-byte header total)
        header = read_resp(ser, 6, timeout=3.0)
        if len(header) < 6 or header[0] != 0x57:
            return None
        resp_size = header[4] | (header[5] << 8)
        if resp_size == 0:
            resp_size = size
        data = read_resp(ser, resp_size, timeout=10.0)
        return data

    def read_range(self, start, length, block_size=4096, progress=True):
        """Read a range of addresses, block by block."""
        result = bytearray()
        offset = 0
        while offset < length:
            chunk_size = min(block_size, length - offset)
            addr = start + offset
            data = self.read_block(addr, chunk_size)
            if data is None:
                if progress:
                    print(f"\n  Read failed at 0x{addr:06X}")
                return None
            result.extend(data)
            offset += len(data)
            if progress:
                pct = offset / length * 100
                print(f"\r  [{pct:5.1f}%] 0x{addr:06X}  ", end="", flush=True)
        if progress:
            print()
        return bytes(result)


def cmd_info(args):
    reader = DM32Reader(args.port)
    print("Connecting to radio (normal mode)...")
    if not reader.handshake():
        print("\nHandshake failed. Is the radio in normal mode (not bootloader)?")
        reader.close()
        return 1
    print("\nRadio info:")

    # Read radio info block at 0x0C3000
    data = reader.read_block(0x0C3000, 4096)
    if data:
        print(f"\n  Radio Info Block (0x0C3000):")
        print(hexdump(data[:128], 0x0C3000))
        # Known fields from CPS capture
        dmr_id_bytes = data[0x10:0x13]
        if len(dmr_id_bytes) >= 3:
            dmr_id = dmr_id_bytes[0] | (dmr_id_bytes[1] << 8) | (dmr_id_bytes[2] << 16)
            print(f"\n  DMR ID:    {dmr_id}")
        name = data[0x13:0x23].split(b"\x00")[0].decode("ascii", errors="replace")
        callsign = data[0x20:0x30].split(b"\x00")[0].decode("ascii", errors="replace")
        owner = data[0x33:0x43].split(b"\x00")[0].decode("ascii", errors="replace")
        print(f"  Name:      {name}")
        print(f"  Callsign:  {callsign}")
        print(f"  Owner:     {owner}")
    else:
        print("  Failed to read radio info block")

    reader.close()
    return 0


def cmd_read(args):
    addr = int(args.address, 0)
    size = int(args.size, 0)

    reader = DM32Reader(args.port)
    print("Connecting to radio...")
    if not reader.handshake():
        reader.close()
        return 1

    print(f"\nReading {size} bytes from 0x{addr:06X}...")
    data = reader.read_range(addr, size)
    if data:
        print(hexdump(data, addr))
    else:
        print("Read failed")

    reader.close()
    return 0 if data else 1


def cmd_dump(args):
    start = int(args.start, 0)
    end = int(args.end, 0)
    length = end - start

    if length <= 0:
        print(f"Error: end (0x{end:X}) must be > start (0x{start:X})")
        return 1

    reader = DM32Reader(args.port)
    print("Connecting to radio...")
    if not reader.handshake():
        reader.close()
        return 1

    print(f"Dumping 0x{start:06X}-0x{end:06X} ({length} bytes)...")
    data = reader.read_range(start, length)
    if data:
        with open(args.output, "wb") as f:
            f.write(data)
        print(f"Saved to {args.output} ({len(data)} bytes)")
    else:
        print("Dump failed")

    reader.close()
    return 0 if data else 1


def cmd_keys(args):
    reader = DM32Reader(args.port)
    print("Connecting to radio...")
    if not reader.handshake():
        reader.close()
        return 1

    print("\nReading AES encryption keys (0x00C000)...")
    data = reader.read_range(0x00C000, 4096, progress=False)
    if data:
        # Key names are at the start, key values at offset 0x300
        print("\n  Key Names (0x00C000):")
        for i in range(16):
            name = data[i*32:(i+1)*32].split(b"\x00")[0].decode("ascii", errors="replace")
            if name:
                key_offset = 0x300 + i * 32
                key_data = data[key_offset:key_offset + 32]
                key_hex = " ".join(f"{b:02X}" for b in key_data[:16])
                print(f"  [{i:2d}] {name:<20s}  Key: {key_hex}")
    else:
        print("  Failed to read key data")

    reader.close()
    return 0


def cmd_id(args):
    reader = DM32Reader(args.port)
    print("Connecting to radio...")
    if not reader.handshake():
        reader.close()
        return 1

    data = reader.read_block(0x0C3000, 256)
    if data:
        dmr_id = data[0x10] | (data[0x11] << 8) | (data[0x12] << 16)
        name = data[0x13:0x23].split(b"\x00")[0].decode("ascii", errors="replace")
        callsign = data[0x20:0x30].split(b"\x00")[0].decode("ascii", errors="replace")
        owner = data[0x33:0x43].split(b"\x00")[0].decode("ascii", errors="replace")
        print(f"\n  DMR ID:    {dmr_id}")
        print(f"  Name:      {name}")
        print(f"  Callsign:  {callsign}")
        print(f"  Owner:     {owner}")
    else:
        print("Failed to read radio info")

    reader.close()
    return 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description="DM-32UV Radio Reader")
    parser.add_argument("--port", "-p", default=PORT)
    sub = parser.add_subparsers(dest="command")

    sub.add_parser("info", help="Read radio info")
    sub.add_parser("keys", help="Read AES encryption keys")
    sub.add_parser("id", help="Read DMR ID and callsign")

    p_read = sub.add_parser("read", help="Read bytes from address")
    p_read.add_argument("address", help="Start address (hex)")
    p_read.add_argument("size", help="Number of bytes (hex or decimal)")

    p_dump = sub.add_parser("dump", help="Dump address range to file")
    p_dump.add_argument("start", help="Start address (hex)")
    p_dump.add_argument("end", help="End address (hex)")
    p_dump.add_argument("output", help="Output file")

    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return 1

    cmds = {"info": cmd_info, "read": cmd_read, "dump": cmd_dump,
            "keys": cmd_keys, "id": cmd_id}
    return cmds[args.command](args)


if __name__ == "__main__":
    sys.exit(main())
