#!/usr/bin/env python3
"""DM-32UV Bootloader Protocol Probe
=====================================
Probes the radio's bootloader mode to discover the firmware update protocol.

Prerequisites:
  1. Put radio in bootloader mode: hold SK1 + PTT, then power on
  2. LED should turn green
  3. Connect USB programming cable

Tested approaches:
  - CPS-style handshake (PSEARCH/SYSINFO/PROGRAM)
  - UART autobaud sync (0x7F)
  - XMODEM/YMODEM negotiation
  - Raw command probing
  - Known Baofeng bootloader patterns from similar radios
"""

import serial
import time
import sys
import struct

PORT = "/dev/ttyUSB0"
BAUD = 115200

def hexdump(data, prefix=""):
    if not data:
        return f"{prefix}(empty)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        ascpart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}  {i:04X}: {hexpart:<48s} |{ascpart}|")
    return "\n".join(lines)

def wait_response(ser, timeout=2.0):
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

def probe(ser, name, payload, timeout=2.0, pause=0.3):
    print(f"\n  [{name}]")
    if isinstance(payload, str):
        payload = payload.encode("ascii")
    print(f"    TX ({len(payload)}B): {' '.join(f'{b:02X}' for b in payload[:32])}"
          + ("..." if len(payload) > 32 else ""))
    ser.reset_input_buffer()
    ser.write(payload)
    ser.flush()
    resp = wait_response(ser, timeout=timeout)
    if resp:
        print(f"    RX ({len(resp)}B):")
        print(hexdump(resp, "    "))
    else:
        print(f"    RX: (no response)")
    time.sleep(pause)
    return resp

def main():
    port = sys.argv[1] if len(sys.argv) > 1 else PORT
    baud = int(sys.argv[2]) if len(sys.argv) > 2 else BAUD

    print("=" * 64)
    print("  DM-32UV Bootloader Protocol Probe")
    print("=" * 64)
    print(f"  Port: {port}  Baud: {baud}")
    print()
    print("  IMPORTANT: Radio must be in bootloader mode!")
    print("  (Hold SK1 + PTT, then power on → green LED)")
    print()

    ser = serial.Serial(port, baud, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()

    results = {}

    # === Phase 1: CPS-style handshake ===
    print("\n--- Phase 1: CPS Protocol Commands ---")
    results["PSEARCH"] = probe(ser, "PSEARCH", b"PSEARCH")
    results["SYSINFO"] = probe(ser, "SYSINFO", b"SYSINFO")
    results["PROGRAM"] = probe(ser, "PROGRAM", b"PROGRAM")
    results["UPDATE"] = probe(ser, "UPDATE", b"UPDATE")

    # CPS preamble + PROGRAM
    results["preamble+PROGRAM"] = probe(ser, "Preamble + PROGRAM",
        b"\xFF\xFF\xFF\xFF\x0C" + b"PROGRAM")

    # === Phase 2: UART autobaud / sync ===
    print("\n--- Phase 2: UART Sync Patterns ---")
    results["0x7F"] = probe(ser, "UART autobaud (0x7F)", bytes([0x7F]))
    results["0x7F_x3"] = probe(ser, "UART autobaud x3", bytes([0x7F, 0x7F, 0x7F]))
    results["0x55"] = probe(ser, "Sync 0x55 (alternating bits)", bytes([0x55] * 4))

    # === Phase 3: Common bootloader commands ===
    print("\n--- Phase 3: Common Bootloader Commands ---")
    results["ACK"] = probe(ser, "ACK (0x06)", bytes([0x06]))
    results["NAK"] = probe(ser, "NAK (0x15)", bytes([0x15]))
    results["SOH"] = probe(ser, "SOH (0x01 - XMODEM)", bytes([0x01]))
    results["STX"] = probe(ser, "STX (0x02 - XMODEM-1K)", bytes([0x02]))
    results["C"] = probe(ser, "XMODEM-CRC 'C'", b"C")
    results["EOT"] = probe(ser, "EOT (0x04)", bytes([0x04]))

    # === Phase 4: Known Baofeng patterns ===
    print("\n--- Phase 4: Baofeng/HR_C7000 Patterns ---")
    # Model ID from CPS: 66660501
    results["model_id"] = probe(ser, "Model ID 66660501",
        bytes.fromhex("66660501"))
    # BFUV32-V2 magic
    results["magic"] = probe(ser, "Firmware magic BFUV32-V2",
        b"BFUV32-V2")
    # Try sending just the 0x02 mode byte (used in CPS handshake)
    results["mode02"] = probe(ser, "Mode 0x02", bytes([0x02]))
    # End command
    results["end_0x45"] = probe(ser, "End 0x45 ('E')", bytes([0x45]))

    # === Phase 5: Address-based commands ===
    print("\n--- Phase 5: Memory Read Probes ---")
    # Try READ command from CPS protocol: 0x52 + 3-byte addr + 2-byte len
    # Read address 0x000000 (could be bootloader ROM)
    results["read_0x0"] = probe(ser, "READ 0x000000 (16B)",
        bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x10]))
    # Read flash start
    results["read_flash"] = probe(ser, "READ 0x030000 (16B)",
        bytes([0x52, 0x00, 0x00, 0x03, 0x00, 0x10]))

    # === Phase 6: Alternate baud rates ===
    print("\n--- Phase 6: Alternate Baud Rate Test ---")
    for alt_baud in [9600, 19200, 57600, 230400, 460800, 921600]:
        ser.close()
        try:
            ser = serial.Serial(port, alt_baud, timeout=0.5,
                              bytesize=8, parity="N", stopbits=1)
            time.sleep(0.2)
            ser.reset_input_buffer()
            r = probe(ser, f"PSEARCH @ {alt_baud} baud", b"PSEARCH", timeout=1.0, pause=0.2)
            if r:
                results[f"baud_{alt_baud}"] = r
                print(f"    *** GOT RESPONSE AT {alt_baud} BAUD! ***")
        except Exception as e:
            print(f"    [{alt_baud} baud] Error: {e}")
    # Restore original baud
    ser.close()
    ser = serial.Serial(port, baud, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(0.3)

    # === Phase 7: Brute-force first byte ===
    print("\n--- Phase 7: Single-Byte Scan (0x00-0xFF) ---")
    print("  Sending each byte value and checking for response...")
    responsive_bytes = []
    for val in range(256):
        ser.reset_input_buffer()
        ser.write(bytes([val]))
        ser.flush()
        time.sleep(0.05)
        r = ser.read(64)
        if r:
            responsive_bytes.append((val, r))

    if responsive_bytes:
        print(f"  Found {len(responsive_bytes)} responsive bytes:")
        for val, resp in responsive_bytes:
            print(f"    0x{val:02X} → {' '.join(f'{b:02X}' for b in resp[:16])}"
                  + (f"  |{''.join(chr(b) if 32<=b<127 else '.' for b in resp[:16])}|" if resp else ""))
    else:
        print("  No responses to any single byte.")

    # === Summary ===
    print("\n" + "=" * 64)
    print("  SUMMARY")
    print("=" * 64)
    responding = {k: v for k, v in results.items() if v}
    if responding:
        print(f"  Commands that got responses: {len(responding)}")
        for name, resp in responding.items():
            print(f"    {name}: {len(resp)}B → {' '.join(f'{b:02X}' for b in resp[:16])}")
    else:
        print("  No responses received from any probe.")
        print()
        print("  Possible reasons:")
        print("  - Radio is not in bootloader mode (check green LED)")
        print("  - Bootloader uses different USB interface")
        print("  - Bootloader requires specific init sequence")
        print("  - Baud rate is non-standard")

    if responsive_bytes:
        print(f"\n  Single-byte scan: {len(responsive_bytes)} bytes got responses")

    # Cleanup
    ser.close()
    print("\n  Done!")


if __name__ == "__main__":
    main()
