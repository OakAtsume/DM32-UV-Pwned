#!/usr/bin/env python3
"""DM-32UV: Test hidden/debug commands after entering programming mode.
Commands found in firmware: PCTESTM, 588999, IDCHECK, RTCITEM, DEL-RCD"""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def wait_for_any(ser, timeout=1.0):
    """Read any response, skipping stray bytes."""
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    while time.time() < end:
        b = ser.read(1)
        if b:
            data.append(b[0])
            # Once we get a meaningful byte, read the rest quickly
            if len(data) == 1 and data[0] not in (0xC0, 0x90, 0x48):
                ser.timeout = 0.3
                rest = ser.read(256)
                data.extend(rest)
                break
    return bytes(data)

def hexline(data):
    return " ".join(f"{b:02X}" for b in data)

def asciiline(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)

def test_cmd(ser, cmd, label=""):
    """Send a command and show the response."""
    if isinstance(cmd, str):
        cmd = cmd.encode('ascii')
    print(f"\n  [{label or cmd}]")
    print(f"    TX: {hexline(cmd)}  |{asciiline(cmd)}|")
    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()
    time.sleep(0.1)
    r = wait_for_any(ser, timeout=2)
    if r:
        print(f"    RX ({len(r)}B): {hexline(r)}  |{asciiline(r)}|")
    else:
        print(f"    RX: (timeout)")
    return r


def main():
    print("=" * 60)
    print("DM-32UV Hidden Command Tester")
    print("=" * 60)

    ser = serial.Serial(PORT, BAUD, timeout=0.5, bytesize=8, parity='N', stopbits=1)
    time.sleep(1)
    ser.reset_input_buffer()

    # Basic handshake (no password)
    print("\n--- Handshake ---")
    ser.write(b"PSEARCH"); ser.flush()
    time.sleep(0.2)
    r = ser.read(64)
    print(f"  PSEARCH: {hexline(r)}")
    if not r or r[0] != 0x06:
        print("  Radio not responding!"); ser.close(); return

    print("\n--- Testing commands BEFORE SYSINFO ---")
    for cmd in ["PCTESTM", "588999", "IDCHECK", "RTCITEM", "DEL-RCD"]:
        test_cmd(ser, cmd, f"pre-SYSINFO: {cmd}")

    print("\n--- SYSINFO ---")
    ser.write(b"SYSINFO"); ser.flush()
    time.sleep(0.2)
    r = ser.read(16)
    print(f"  SYSINFO: {hexline(r)}")

    print("\n--- Testing commands AFTER SYSINFO ---")
    for cmd in ["PCTESTM", "588999", "IDCHECK", "RTCITEM", "DEL-RCD"]:
        test_cmd(ser, cmd, f"post-SYSINFO: {cmd}")

    # Try some known password/backdoor sequences
    print("\n--- Testing embedded CPS passwords ---")
    for pw in ["66660501", "bfcps", "374612"]:
        # Try sending as-is
        test_cmd(ser, pw, f"raw: {pw}")

    # Enter programming mode and test commands there
    print("\n--- Entering PROGRAM mode (no auth) ---")
    # V-frame 0x0D first
    ser.write(bytes([0x56, 0x00, 0x00, 0x40, 0x0D])); ser.flush()
    time.sleep(0.2); ser.read(128)
    # V-frames
    for vid in range(0x01, 0x11):
        if vid == 0x0C: continue
        ser.write(bytes([0x56, 0x00, 0x00, 0x00, vid])); ser.flush()
        time.sleep(0.15); ser.read(64)
    # G-query
    ser.write(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01])); ser.flush()
    time.sleep(0.3); ser.read(300)
    time.sleep(0.2); ser.read(64)
    # PROGRAM
    ser.write(b"\xFF\xFF\xFF\xFF\x0C"); ser.flush()
    time.sleep(0.01)
    ser.write(b"PROGRAM"); ser.flush()
    time.sleep(0.2)
    r = ser.read(16)
    if r and r[0] == 0x06:
        print("  PROGRAM ACK!")
        # Mode 02
        ser.write(b"\x02"); ser.flush()
        time.sleep(0.2)
        r = ser.read(8)
        if r and all(b == 0xFF for b in r):
            ser.write(b"\x06"); ser.flush()
            time.sleep(0.2)
            r = ser.read(4)
            if r and r[0] == 0x06:
                print("  *** IN PROGRAMMING MODE ***")

                print("\n--- Testing commands IN PROGRAMMING MODE ---")
                for cmd in ["PCTESTM", "588999", "IDCHECK", "RTCITEM", "DEL-RCD"]:
                    test_cmd(ser, cmd, f"prog-mode: {cmd}")

                # Try WRITE command (0x57) to see if we can write
                print("\n--- Testing WRITE capability ---")
                # Read a known address first
                addr = 0x097000  # A page we know has data
                read_cmd = bytes([0x52, addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, 0x01, 0x00])
                test_cmd(ser, read_cmd, f"READ 0x{addr:06X} x1")

    # End
    print("\n--- END ---")
    ser.write(b"\x45"); ser.flush()
    time.sleep(0.5)
    ser.close()
    print("Done!")


if __name__ == "__main__":
    main()
