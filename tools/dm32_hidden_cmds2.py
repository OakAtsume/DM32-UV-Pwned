#!/usr/bin/env python3
"""DM-32UV Hidden Command Tester v2
====================================
Tests hidden/debug commands found in firmware with various parameter formats.

Key findings from RE:
  PCTESTM  — Factory LCD/signal test. Handler at 0x0302b980 branches on
             param values 4, 5, 6. Does NOT send USB response — it only
             updates the display. Watch the radio screen!
  RTCITEM  — Handler pointer (0x030ad770) targets DATA, not code → crash
  DEL-RCD  — Handler pointer (0x030ad77c) targets DATA, not code → crash
  IDCHECK  — OOB table read → jumps to 0x6b736174 ("task") → crash
  588999   — OOB table read → crash
  SYSINFO  — OOB in flash table but works → handled by IRAM dispatch
"""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def wait_for(ser, expected, count, timeout=1.0):
    end = time.time() + timeout
    ser.timeout = 0.05
    while time.time() < end:
        b = ser.read(1)
        if not b:
            continue
        if b[0] in expected:
            ser.timeout = min(timeout, 0.5)
            rest = ser.read(count - 1)
            return bytes([b[0]]) + rest
    return b""

def wait_any(ser, timeout=2.0):
    end = time.time() + timeout
    ser.timeout = 0.05
    data = bytearray()
    while time.time() < end:
        b = ser.read(1)
        if b:
            data.append(b[0])
            if data[-1] not in (0xC0, 0x90, 0x48) or len(data) > 2:
                ser.timeout = 0.3
                rest = ser.read(256)
                data.extend(rest)
                break
    return bytes(data)

def hexdump(data):
    return " ".join(f"{b:02X}" for b in data) if data else "(empty)"

def ascii_safe(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)

def send_and_show(ser, cmd, label="", timeout=2.0):
    if isinstance(cmd, str):
        cmd = cmd.encode("ascii")
    tag = label or ascii_safe(cmd)
    print(f"\n  [{tag}]")
    print(f"    TX ({len(cmd)}B): {hexdump(cmd)}")
    ser.reset_input_buffer()
    ser.write(cmd)
    ser.flush()
    r = wait_any(ser, timeout=timeout)
    if r:
        print(f"    RX ({len(r)}B): {hexdump(r)}  |{ascii_safe(r)}|")
    else:
        print(f"    RX: (timeout — check radio screen for visual change)")
    return r

def handshake_bypass(ser):
    """Minimal handshake: PSEARCH → SYSINFO (skip password)."""
    ser.reset_input_buffer()
    ser.write(b"PSEARCH"); ser.flush()
    r = wait_for(ser, {0x06}, 8, timeout=2)
    if not r or r[0] != 0x06:
        print("  [!] Radio not responding")
        return False
    model = r[1:].decode("ascii", errors="replace").rstrip("\x00")
    print(f"  Model: {model}")

    ser.write(b"SYSINFO"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=1)
    if not r:
        print("  [!] SYSINFO failed")
        return False
    print("  SYSINFO: ACK")
    return True

def enter_programming(ser):
    """Full handshake to programming mode (V-frames, G-query, PROGRAM, mode 02)."""
    # V-frame 0x0D
    ser.write(bytes([0x56, 0x00, 0x00, 0x40, 0x0D])); ser.flush()
    wait_for(ser, {0x56}, 67, timeout=0.5)

    # V-frames 0x01-0x10
    for vid in range(0x01, 0x11):
        if vid == 0x0C: continue
        ser.write(bytes([0x56, 0x00, 0x00, 0x00, vid])); ser.flush()
        r = wait_for(ser, {0x56}, 3, timeout=0.3)
        if r and len(r) >= 3:
            dlen = r[2]
            if dlen > 0:
                ser.read(dlen)

    # G-query
    ser.write(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01])); ser.flush()
    wait_for(ser, {0x53}, 6, timeout=1)
    time.sleep(0.3)
    ser.timeout = 0.3; ser.read(300)
    time.sleep(0.2); ser.read(64)

    # PROGRAM
    ser.write(b"\xFF\xFF\xFF\xFF\x0C"); ser.flush()
    time.sleep(0.01)
    ser.write(b"PROGRAM"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=1)
    if not r:
        print("  [!] PROGRAM failed")
        return False

    # Mode 02
    ser.write(b"\x02"); ser.flush()
    r = wait_for(ser, {0xFF}, 8, timeout=2)
    if not r or len(r) < 8:
        print("  [!] Mode 02 failed")
        return False
    ser.write(b"\x06"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=1)
    if not r:
        print("  [!] Confirm failed")
        return False
    print("  Programming mode: ACTIVE")
    return True


def main():
    print("=" * 64)
    print("  DM-32UV Hidden Command Tester v2")
    print("  Watch radio screen for visual changes!")
    print("=" * 64)

    ser = serial.Serial(PORT, BAUD, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(1)
    ser.reset_input_buffer()

    # --- Phase 1: Basic handshake ---
    print("\n--- Phase 1: Handshake (bypass) ---")
    if not handshake_bypass(ser):
        ser.close(); return

    # --- Phase 2: Test PCTESTM with parameter bytes ---
    # The handler branches on values 4, 5, 6
    # Try different parameter encoding formats
    print("\n--- Phase 2: PCTESTM parameter tests (watch radio screen!) ---")
    print("  The handler renders signal info on LCD, no USB response expected.")

    # Format A: command + ASCII digit
    for digit in ["4", "5", "6"]:
        send_and_show(ser, f"PCTESTM{digit}", f"PCTESTM + ASCII '{digit}'")
        time.sleep(0.5)

    # Format B: command + binary byte
    for val in [4, 5, 6]:
        send_and_show(ser, b"PCTESTM" + bytes([val]), f"PCTESTM + 0x{val:02X}")
        time.sleep(0.5)

    # Format C: command + null + parameter
    for val in [4, 5, 6]:
        send_and_show(ser, b"PCTESTM\x00" + bytes([val]), f"PCTESTM + NUL + 0x{val:02X}")
        time.sleep(0.5)

    # Format D: bare command (default mode?)
    send_and_show(ser, "PCTESTM", "PCTESTM bare")
    time.sleep(0.5)

    # --- Phase 3: Try with PROGRAM preamble ---
    print("\n--- Phase 3: Commands with PROGRAM-style preamble ---")
    for cmd in ["PCTESTM", "RTCITEM", "DEL-RCD", "IDCHECK", "588999"]:
        ser.write(b"\xFF\xFF\xFF\xFF\x0C"); ser.flush()
        time.sleep(0.01)
        send_and_show(ser, cmd, f"preamble + {cmd}")
        time.sleep(0.5)

    # --- Phase 4: Enter programming mode, test there ---
    print("\n--- Phase 4: Full programming mode ---")

    # Need fresh connection for clean state
    ser.write(b"\x45"); ser.flush()
    time.sleep(1)
    ser.close()
    ser = serial.Serial(PORT, BAUD, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(1)
    ser.reset_input_buffer()

    if not handshake_bypass(ser):
        ser.close(); return
    if not enter_programming(ser):
        ser.close(); return

    # In programming mode, try commands
    for cmd in ["PCTESTM", "RTCITEM", "DEL-RCD"]:
        send_and_show(ser, cmd, f"prog: {cmd}")
        time.sleep(0.5)

    # PCTESTM with params in prog mode
    for val in [4, 5, 6]:
        send_and_show(ser, b"PCTESTM" + bytes([val]), f"prog: PCTESTM+0x{val:02X}")
        time.sleep(0.5)

    # --- Phase 5: OOB crash test ---
    print("\n--- Phase 5: OOB commands (may crash radio!) ---")
    print("  IDCHECK → OOB read → handler ptr 0x6b736174 ('task')")
    print("  588999  → OOB read → handler ptr past 'task' string")
    input("  Press ENTER to send IDCHECK (radio may crash/reboot)... ")

    send_and_show(ser, "IDCHECK", "IDCHECK (OOB crash test)", timeout=5)
    time.sleep(2)

    # Check if radio is still responsive
    print("\n  Checking if radio survived...")
    ser.write(b"PSEARCH"); ser.flush()
    r = wait_any(ser, timeout=3)
    if r and len(r) > 0 and r[0] == 0x06:
        print(f"  Radio still alive! Response: {hexdump(r)}")
    else:
        print(f"  Radio may have crashed. Response: {hexdump(r)}")
        print("  (Power cycle radio and reconnect to continue)")

    # --- Cleanup ---
    print("\n--- END ---")
    ser.write(b"\x45"); ser.flush()
    time.sleep(0.5)
    ser.close()
    print("  Done!")


if __name__ == "__main__":
    port = sys.argv[1] if len(sys.argv) > 1 else PORT
    main()
