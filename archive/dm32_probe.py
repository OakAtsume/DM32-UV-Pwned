#!/usr/bin/env python3
"""DM-32UV UART Protocol Probe — tests handshake, password bypass, and hidden commands."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200
PASSWORD = "123"

def hexdump(data, prefix="  "):
    if not data:
        return f"{prefix}(empty)"
    hex_str = " ".join(f"{b:02X}" for b in data)
    ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
    return f"{prefix}{hex_str}  |{ascii_str}|"

class DM32:
    def __init__(self, port=PORT, baud=BAUD):
        self.ser = serial.Serial(port, baud, timeout=2,
                                 bytesize=8, parity='N', stopbits=1)
        time.sleep(0.4)
        self.ser.reset_input_buffer()
        time.sleep(0.2)

    def send(self, data, label=""):
        if isinstance(data, str):
            data = data.encode('ascii')
        print(f"  TX [{label}]: {' '.join(f'{b:02X}' for b in data)}  |{''.join(chr(b) if 32<=b<127 else '.' for b in data)}|")
        self.ser.write(data)

    def recv(self, size=256, timeout=2):
        self.ser.timeout = timeout
        data = self.ser.read(size)
        if data:
            print(hexdump(data, "  RX: "))
        else:
            print("  RX: (timeout - no response)")
        return data

    def recv_exact(self, size, timeout=5):
        self.ser.timeout = timeout
        data = self.ser.read(size)
        if data:
            print(hexdump(data, "  RX: "))
        else:
            print("  RX: (timeout - no response)")
        return data

    def flush(self):
        self.ser.reset_input_buffer()

    def close(self):
        self.ser.close()


def test_normal_handshake(dm):
    """Test 1: Normal handshake flow with password."""
    print("\n" + "="*60)
    print("TEST 1: Normal Handshake (with password)")
    print("="*60)

    print("\n[PSEARCH]")
    dm.send("PSEARCH", "PSEARCH")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp and resp[0] == 0x06:
        model = resp[1:].decode('ascii', errors='replace')
        print(f"  -> ACK + model: '{model}'")
    else:
        print("  -> UNEXPECTED RESPONSE")
        return False

    time.sleep(0.05)
    print("\n[PASSSTA]")
    dm.send("PASSSTA", "PASSSTA")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp:
        print(f"  -> First byte: 0x{resp[0]:02X} ({'P=password needed' if resp[0]==0x50 else 'unknown'})")
        if len(resp) >= 2:
            print(f"  -> Status bytes: {' '.join(f'0x{b:02X}' for b in resp[1:])}")
    else:
        return False

    time.sleep(0.05)
    print("\n[PASWORD] sending password: " + PASSWORD)
    # Password is likely sent as the ASCII string padded to 8 bytes
    pw_bytes = PASSWORD.encode('ascii').ljust(8, b'\x00')
    dm.send(pw_bytes, "PASWORD")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp:
        print(f"  -> Response: {' '.join(f'0x{b:02X}' for b in resp)}")

    time.sleep(0.05)
    print("\n[SYSINFO]")
    dm.send("SYSINFO", "SYSINFO")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp and resp[0] == 0x06:
        print("  -> ACK OK")
    else:
        print("  -> UNEXPECTED")

    return True


def test_vframes(dm):
    """Test 2: V-frame metadata queries."""
    print("\n" + "="*60)
    print("TEST 2: V-Frame Queries")
    print("="*60)

    for vid in range(0x01, 0x11):
        label = {
            0x01: "firmware ver", 0x02: "unknown", 0x03: "build date",
            0x04: "DSP ver", 0x05: "radio ver", 0x06: "range",
            0x07: "range", 0x08: "range", 0x09: "range",
            0x0A: "main config", 0x0B: "codeplug ver", 0x0C: "NEVER QUERIED",
            0x0D: "HIDDEN (len=0)", 0x0E: "boot image", 0x0F: "contacts",
            0x10: "max contacts",
        }.get(vid, "unknown")

        print(f"\n[V-Frame 0x{vid:02X}] {label}")
        dm.send(bytes([0x56, 0x00, 0x00, 0x00, vid]), f"V-Frame 0x{vid:02X}")
        time.sleep(0.05)
        resp = dm.recv(64)

        if vid == 0x0D:
            # Also try the hidden 64-byte variant
            time.sleep(0.1)
            print(f"\n[V-Frame 0x0D len=0x40] HIDDEN VARIANT")
            dm.send(bytes([0x56, 0x00, 0x00, 0x40, 0x0D]), "V-Frame 0x0D/0x40")
            time.sleep(0.05)
            resp = dm.recv(128)


def test_g_query(dm):
    """Test 3: Undocumented 0x47 (G) query."""
    print("\n" + "="*60)
    print("TEST 3: G-Query (0x47) — Undocumented")
    print("="*60)

    print("\n[G-Query]")
    dm.send(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01]), "G-Query")
    time.sleep(0.15)
    resp = dm.recv_exact(262, timeout=5)  # 0x53 + 5 header + 256 data


def test_password_bypass(dm):
    """Test 4: Try to enter PROGRAM mode without password."""
    print("\n" + "="*60)
    print("TEST 4: Password Bypass — skip PASWORD, go to PROGRAM")
    print("="*60)

    print("\n[PSEARCH]")
    dm.send("PSEARCH", "PSEARCH")
    time.sleep(0.15)
    resp = dm.recv(8)
    if not (resp and resp[0] == 0x06):
        print("  -> Failed at PSEARCH")
        return

    time.sleep(0.05)
    print("\n[PASSSTA] (will check status but NOT send password)")
    dm.send("PASSSTA", "PASSSTA")
    time.sleep(0.15)
    resp = dm.recv(8)
    print(f"  -> Status: {' '.join(f'0x{b:02X}' for b in resp) if resp else 'none'}")

    time.sleep(0.05)
    print("\n[Skipping PASWORD — going straight to SYSINFO]")
    dm.send("SYSINFO", "SYSINFO")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp:
        print(f"  -> Response: 0x{resp[0]:02X} ({'ACK!' if resp[0]==0x06 else 'rejected?'})")

    time.sleep(0.05)
    print("\n[Attempting PROGRAM mode without password]")
    dm.send(b"\xFF\xFF\xFF\xFF\x0CPROGRAM", "PROGRAM")
    time.sleep(0.15)
    resp = dm.recv(8)
    if resp and resp[0] == 0x06:
        print("  -> *** ACK! PASSWORD BYPASS WORKS ***")
        # Try mode 02
        dm.send(b"\x02", "mode 02")
        time.sleep(0.15)
        resp = dm.recv(8)
        if resp:
            print(f"  -> mode02 response: {' '.join(f'0x{b:02X}' for b in resp)}")
    else:
        print("  -> Rejected (password required)")


def test_direct_read(dm):
    """Test 5: Try read command without entering PROGRAM mode."""
    print("\n" + "="*60)
    print("TEST 5: Direct Read — 0x52 without PROGRAM mode")
    print("="*60)

    print("\n[PSEARCH only, then attempt read]")
    dm.send("PSEARCH", "PSEARCH")
    time.sleep(0.15)
    resp = dm.recv(8)

    time.sleep(0.05)
    # Try to read block ID at 0x001FFF (first page ID byte)
    print("\n[Read 0x001FFF, 1 byte — block ID probe]")
    dm.send(bytes([0x52, 0xFF, 0x1F, 0x00, 0x01, 0x00]), "READ")
    time.sleep(0.15)
    resp = dm.recv(16)
    if resp and resp[0] == 0x57:
        print("  -> *** READ WITHOUT AUTH WORKS ***")
    else:
        print("  -> Rejected or no response")


def test_hidden_commands(dm):
    """Test 6: Send undocumented firmware commands."""
    print("\n" + "="*60)
    print("TEST 6: Hidden Firmware Commands")
    print("="*60)

    for cmd_name in ["588999\x00\x00", "PCTESTM\x00", "RTCITEM\x00", "DEL-RCD\x00", "IDCHECK\x00"]:
        # Need to do PSEARCH first to get into command state
        dm.flush()
        time.sleep(0.3)

        print(f"\n[PSEARCH -> {cmd_name.rstrip(chr(0))}]")
        dm.send("PSEARCH", "PSEARCH")
        time.sleep(0.15)
        resp = dm.recv(8)
        if not (resp and resp[0] == 0x06):
            print("  -> PSEARCH failed, skipping")
            continue

        time.sleep(0.05)
        cmd_bytes = cmd_name.encode('ascii') if isinstance(cmd_name, str) else cmd_name
        dm.send(cmd_bytes, cmd_name.rstrip('\x00'))
        time.sleep(0.2)
        resp = dm.recv(64)
        if resp:
            print(f"  -> Got {len(resp)} bytes response!")
        else:
            print("  -> No response")


def test_588999_before_auth(dm):
    """Test 7: Send 588999 as the very first command."""
    print("\n" + "="*60)
    print("TEST 7: 588999 as First Command (no PSEARCH)")
    print("="*60)

    dm.flush()
    time.sleep(0.3)
    print("\n[588999 raw — no handshake]")
    dm.send("588999\x00\x00", "588999")
    time.sleep(0.3)
    resp = dm.recv(64)


def main():
    print("DM-32UV Protocol Probe")
    print(f"Port: {PORT} | Baud: {BAUD} | Password: {PASSWORD}")
    print("=" * 60)

    if len(sys.argv) > 1:
        tests = sys.argv[1:]
    else:
        tests = ["all"]

    try:
        dm = DM32(PORT, BAUD)
        print("Serial port opened OK")
    except Exception as e:
        print(f"Failed to open {PORT}: {e}")
        sys.exit(1)

    try:
        if "1" in tests or "all" in tests or "handshake" in tests:
            dm.close()
            dm = DM32(PORT, BAUD)
            test_normal_handshake(dm)

        if "2" in tests or "all" in tests or "vframe" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            # Do handshake first
            dm.send("PSEARCH", "PSEARCH")
            time.sleep(0.15)
            dm.recv(8)
            test_vframes(dm)

        if "3" in tests or "all" in tests or "gquery" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            dm.send("PSEARCH", "PSEARCH")
            time.sleep(0.15)
            dm.recv(8)
            test_g_query(dm)

        if "4" in tests or "all" in tests or "bypass" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            test_password_bypass(dm)

        if "5" in tests or "all" in tests or "directread" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            test_direct_read(dm)

        if "6" in tests or "all" in tests or "hidden" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            test_hidden_commands(dm)

        if "7" in tests or "all" in tests or "588raw" in tests:
            dm.close()
            time.sleep(0.5)
            dm = DM32(PORT, BAUD)
            test_588999_before_auth(dm)

    except KeyboardInterrupt:
        print("\n\nInterrupted.")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    finally:
        dm.close()
        print("\nPort closed.")


if __name__ == "__main__":
    main()
