#!/usr/bin/env python3
"""DM-32UV Bootloader Protocol Test
=====================================
Targeted probing of the bootloader based on what we learned:
  - PSEARCH works (ACK + empty model)
  - PASSSTA/SYSINFO/READ do NOT work
  - Need to find what commands the bootloader DOES accept

Tests the bootloader's actual command set after PSEARCH.
Power cycle radio into bootloader (SK1+PTT) between runs.
"""

import serial
import time
import sys
import struct

PORT = sys.argv[1] if len(sys.argv) > 1 else "/dev/ttyUSB0"
BAUD = 115200
ACK = 0x06


def hexdump(data, prefix="    "):
    if not data:
        return f"{prefix}(empty)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04X}: {hexpart:<48s} |{ascpart}|")
    return "\n".join(lines)


def serial_read(ser, count, timeout=2.0):
    end = time.time() + timeout
    data = bytearray()
    while len(data) < count and time.time() < end:
        ser.timeout = max(0.01, end - time.time())
        chunk = ser.read(count - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)


def serial_read_any(ser, timeout=1.5):
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    last_rx = time.time()
    while time.time() < end:
        b = ser.read(128)
        if b:
            data.extend(b)
            last_rx = time.time()
        elif data and time.time() - last_rx > 0.3:
            break
    return bytes(data)


def probe(ser, name, payload, timeout=2.0):
    print(f"\n  [{name}]")
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    print(f"    TX ({len(payload)}B): {' '.join(f'{b:02X}' for b in payload[:32])}")
    ser.reset_input_buffer()
    ser.write(payload)
    ser.flush()
    resp = serial_read_any(ser, timeout=timeout)
    if resp:
        print(f"    RX ({len(resp)}B):")
        print(hexdump(resp))
    else:
        print(f"    RX: (no response)")
    time.sleep(0.2)
    return resp


def main():
    print("=" * 64)
    print("  DM-32UV Bootloader Command Probe")
    print("  Radio must be in bootloader mode (SK1+PTT, green LED)")
    print("=" * 64)

    ser = serial.Serial(PORT, BAUD, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()

    # === Phase 1: Verify bootloader is alive ===
    print("\n--- Phase 1: PSEARCH handshake ---")
    resp = probe(ser, "PSEARCH", b"PSEARCH")
    if not resp or resp[0] != ACK:
        print("\n  [!] No ACK from PSEARCH. Is radio in bootloader mode?")
        ser.close()
        return

    model = resp[1:].rstrip(b"\x00").decode("ascii", errors="replace")
    print(f"\n  Model: '{model}' ({'bootloader (empty)' if not model.strip() else model})")

    # === Phase 2: Test what commands work after PSEARCH ===
    print("\n--- Phase 2: Post-PSEARCH command probe ---")

    # Direct PROGRAM (no preamble)
    resp = probe(ser, "PROGRAM (direct)", b"PROGRAM")

    # If PROGRAM got ACK, try mode 0x02
    if resp and resp[0] == ACK:
        print("\n    *** PROGRAM accepted! ***")
        resp = probe(ser, "Mode 0x02", bytes([0x02]))
        if resp and len(resp) >= 8:
            print(f"\n    *** Device info: {resp.hex()} ***")
            # Send ACK to confirm
            resp = probe(ser, "Confirm ACK", bytes([ACK]))
            if resp and resp[0] == ACK:
                print("\n    *** PROGRAMMING MODE ACTIVE ***")

                # Now test READ in programming mode
                print("\n--- Phase 3: READ test in programming mode ---")
                # Codeplug addr
                resp = probe(ser, "READ 0x000000 (16B)",
                    bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x10]))
                # Flash addr (24-bit: 0x0A1940 maps to flash 0x030A1940?)
                resp = probe(ser, "READ 0x0A1940 (WELCOME, 16B)",
                    bytes([0x52, 0x40, 0x19, 0x0A, 0x10, 0x00]))
                # Try full 32-bit-ish
                resp = probe(ser, "READ 0x030A1940 (full flash addr)",
                    struct.pack("<BIH", 0x52, 0x030A1940, 0x10)[:6])

                # Test WRITE with tiny payload (just the header, no data change)
                # Read what's there first if READ worked
                print("\n--- Phase 4: WRITE test (version string) ---")
                # The version string at flash 0x0309F858
                # file offset 0x09F958, let's try writing the ORIGINAL bytes back
                # to test if the WRITE command works without changing anything
                addr = 0x09F858  # 24-bit flash-relative
                original = b"DM32.01.L01.048\x00"
                addr_lo = addr & 0xFF
                addr_mid = (addr >> 8) & 0xFF
                addr_hi = (addr >> 16) & 0xFF
                size = len(original)
                header = bytes([0x57, addr_lo, addr_mid, addr_hi,
                               size & 0xFF, (size >> 8) & 0xFF])
                packet = header + original
                resp = probe(ser, f"WRITE 0x{addr:06X} (original version string, {size}B)",
                    packet, timeout=5.0)
                if resp and resp[0] == ACK:
                    print("\n    *** WRITE ACCEPTED! ***")
                else:
                    print("\n    WRITE: no ACK (trying alternate addr format)")
                    # Try with 0x030xxxxx style
                    addr2 = 0x030A1940
                    addr_lo = addr2 & 0xFF
                    addr_mid = (addr2 >> 8) & 0xFF
                    addr_hi = (addr2 >> 16) & 0xFF
                    test_data = b"WELCOME\x00"
                    header2 = bytes([0x57, addr_lo, addr_mid, addr_hi,
                                    len(test_data) & 0xFF, 0x00])
                    resp = probe(ser, f"WRITE 0x{addr2:06X} (WELCOME, original)",
                        header2 + test_data, timeout=5.0)

                # End session cleanly
                print("\n--- Cleanup ---")
                probe(ser, "END (0x45)", bytes([0x45]))
            else:
                print("    Confirm failed")
        else:
            print(f"    Mode 0x02 unexpected response")
    else:
        # PROGRAM didn't work direct, try with preamble
        print("    PROGRAM not accepted. Trying with preamble...")

        resp = probe(ser, "Preamble FF FF FF FF 0C", b"\xFF\xFF\xFF\xFF\x0C")
        time.sleep(0.05)
        resp = probe(ser, "PROGRAM (after preamble)", b"PROGRAM")

        if resp and resp[0] == ACK:
            print("\n    *** PROGRAM with preamble accepted! ***")
            resp = probe(ser, "Mode 0x02", bytes([0x02]))
            if resp and len(resp) >= 1:
                print(f"    Response: {resp.hex()}")
                if len(resp) >= 8:
                    probe(ser, "Confirm ACK", bytes([ACK]))
        else:
            # Try UPDATE command
            probe(ser, "UPDATE", b"UPDATE")
            # Try just sending mode 0x02 directly
            probe(ser, "Mode 0x02 (direct)", bytes([0x02]))
            # Try sending firmware magic
            probe(ser, "BFUV32-V2 (magic)", b"BFUV32-V2")

    ser.close()
    print("\n  Done! Power cycle radio before next test.")


if __name__ == "__main__":
    main()
