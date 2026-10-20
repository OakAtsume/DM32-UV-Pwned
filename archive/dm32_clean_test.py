#!/usr/bin/env python3
"""DM-32UV: Clean protocol tests — proper auth, bypass, and hidden commands."""

import serial
import time
import sys

PORT = "/dev/ttyUSB0"
BAUD = 115200

def hexdump(data, prefix="  "):
    if not data:
        return f"{prefix}(empty)"
    lines = []
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hex_str = " ".join(f"{b:02X}" for b in chunk)
        ascii_str = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{prefix}{i:04X}: {hex_str:<48s} |{ascii_str}|")
    return "\n".join(lines)

def fresh_serial():
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.5)
    ser.reset_input_buffer()
    ser.reset_output_buffer()
    time.sleep(0.2)
    return ser

def tx(ser, data, label=""):
    if isinstance(data, str):
        data = data.encode('ascii')
    print(f"  TX [{label}]: {data.hex(' ').upper()}")
    ser.write(data)
    ser.flush()

def rx(ser, size=256, timeout=2):
    ser.timeout = timeout
    data = ser.read(size)
    if data:
        print(f"  RX ({len(data)}B): {data[:48].hex(' ').upper()}" +
              (f" ... (+{len(data)-48})" if len(data) > 48 else ""))
        if len(data) > 3:
            try:
                ascii_str = data.decode('ascii', errors='replace')
                if any(32 <= b < 127 for b in data):
                    print(f"       ASCII: {ascii_str}")
            except:
                pass
    else:
        print("  RX: (timeout)")
    return data


def test_a_proper_auth():
    """Test A: Full proper authentication + read."""
    print("\n" + "=" * 60)
    print("TEST A: PROPER AUTH (password=123) + READ")
    print("=" * 60)
    ser = fresh_serial()

    # 1. PSEARCH
    print("\n[1] PSEARCH")
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.15)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("FAIL: No ACK"); ser.close(); return False

    # 2. PASSSTA
    print("\n[2] PASSSTA")
    tx(ser, "PASSSTA", "PASSSTA")
    time.sleep(0.15)
    r = rx(ser, 8)
    pw_needed = r and r[0] == 0x50
    print(f"    Password required: {pw_needed}")

    # 3. Send password "123" padded to 8 bytes
    if pw_needed:
        print("\n[3] PASWORD (sending '123' padded)")
        # Try sending the command name first, then the password
        # Method 1: Just send password bytes directly (like CPS might)
        pw = b"123\x00\x00\x00\x00\x00"
        tx(ser, pw, "password")
        time.sleep(0.2)
        r = rx(ser, 8)
        if not r:
            print("    No response to password — trying 'PASWORD' command prefix")
            # Method 2: Send PASWORD as command, wait for response
            tx(ser, "PASWORD", "PASWORD cmd")
            time.sleep(0.15)
            r = rx(ser, 8)
            if r:
                print(f"    PASWORD cmd response: {r.hex(' ').upper()}")
                # Now send the actual password
                tx(ser, pw, "password digits")
                time.sleep(0.2)
                r = rx(ser, 8)

        if r:
            print(f"    Password response: 0x{r[0]:02X} ({'ACK' if r[0]==0x06 else 'FAIL' if r[0]==0x15 else '??'})")
        else:
            print("    Still no response — password format unknown")

    # 4. SYSINFO
    print("\n[4] SYSINFO")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    r = rx(ser, 8)
    if r and r[0] == 0x06:
        print("    ACK OK")

    # 5. PROGRAM
    print("\n[5] PROGRAM")
    ser.reset_input_buffer()
    tx(ser, "PROGRAM", "PROGRAM (plain)")
    time.sleep(0.3)
    r = rx(ser, 8, timeout=3)
    if r and r[0] == 0x06:
        print("    PROGRAM ACK'd!")
    else:
        print("    No ACK — trying with FF preamble")
        ser.reset_input_buffer()
        time.sleep(0.2)
        tx(ser, b"\xFF\xFF\xFF\xFF\x0CPROGRAM", "PROGRAM (preamble)")
        time.sleep(0.3)
        r = rx(ser, 8, timeout=3)
        if r and r[0] == 0x06:
            print("    PROGRAM ACK'd (with preamble)!")
        else:
            print("    PROGRAM failed both ways")
            ser.close()
            return False

    # 6. Mode 02 handshake
    print("\n[6] Mode 02")
    ser.reset_input_buffer()
    time.sleep(0.1)
    tx(ser, b"\x02", "mode 02")
    time.sleep(0.5)
    r = rx(ser, 8, timeout=3)
    if r and all(b == 0xFF for b in r):
        print(f"    {len(r)}x 0xFF — programming mode confirmed!")
        # Confirm
        tx(ser, b"\x06", "confirm")
        time.sleep(0.2)
        r2 = rx(ser, 4)
        if r2 and r2[0] == 0x06:
            print("    FULLY IN PROGRAMMING MODE")
            # Try a read
            print("\n[7] READ 256 bytes from addr 0x000000")
            tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ 0x000000 x256")
            time.sleep(0.5)
            r = rx(ser, 300, timeout=5)
            if r and r[0] == 0x57:
                print(f"    READ SUCCESS! Got {len(r)} bytes")
                print(hexdump(r[5:min(len(r), 5+64)]))
            else:
                print("    Read failed")
    else:
        print("    Mode 02 didn't return 0xFF bytes")

    ser.close()
    return True


def test_b_bypass():
    """Test B: Skip password entirely — PSEARCH, PASSSTA, SYSINFO, PROGRAM."""
    print("\n" + "=" * 60)
    print("TEST B: PASSWORD BYPASS — NO PASSWORD SENT")
    print("=" * 60)
    ser = fresh_serial()

    # 1. PSEARCH
    print("\n[1] PSEARCH")
    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.15)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        print("FAIL"); ser.close(); return

    # 2. PASSSTA (check only, don't respond with password)
    print("\n[2] PASSSTA (check only)")
    tx(ser, "PASSSTA", "PASSSTA")
    time.sleep(0.15)
    r = rx(ser, 8)
    print(f"    Status: {r.hex(' ').upper() if r else 'none'}")

    # 3. Skip password — go straight to SYSINFO
    print("\n[3] SYSINFO (skip password)")
    tx(ser, "SYSINFO", "SYSINFO")
    time.sleep(0.15)
    r = rx(ser, 8)
    sysinfo_ok = r and r[0] == 0x06
    print(f"    {'ACK!' if sysinfo_ok else 'Failed'}")
    if not sysinfo_ok:
        ser.close(); return

    # 4. PROGRAM (no password ever sent!)
    print("\n[4] PROGRAM (no password!)")
    ser.reset_input_buffer()
    time.sleep(0.1)
    tx(ser, "PROGRAM", "PROGRAM")
    time.sleep(0.3)
    r = rx(ser, 8, timeout=3)
    if r and r[0] == 0x06:
        print("    *** PROGRAM ACK WITHOUT PASSWORD ***")
        extra = r[1:]
        if extra:
            print(f"    Extra bytes: {extra.hex(' ').upper()}")
    else:
        print("    PROGRAM plain failed — trying preamble")
        ser.reset_input_buffer()
        time.sleep(0.2)
        tx(ser, b"\xFF\xFF\xFF\xFF\x0CPROGRAM", "PROGRAM+preamble")
        time.sleep(0.3)
        r = rx(ser, 8, timeout=3)
        if r and r[0] == 0x06:
            print("    *** PROGRAM ACK WITHOUT PASSWORD (preamble) ***")
        else:
            print("    Both PROGRAM variants failed without password")
            ser.close(); return

    # 5. Mode 02
    print("\n[5] Mode 02")
    ser.reset_input_buffer()
    time.sleep(0.1)
    tx(ser, b"\x02", "mode 02")
    time.sleep(0.5)
    r = rx(ser, 8, timeout=3)
    if r and all(b == 0xFF for b in r):
        print(f"    {len(r)}x 0xFF — programming mode!")
        tx(ser, b"\x06", "confirm")
        time.sleep(0.2)
        r2 = rx(ser, 4)
        if r2 and r2[0] == 0x06:
            print("    *** FULL READ ACCESS WITHOUT PASSWORD ***")
            # Read first page
            print("\n[6] READ 256 bytes from 0x000000")
            tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ")
            time.sleep(0.5)
            r = rx(ser, 300, timeout=5)
            if r and r[0] == 0x57:
                print(f"    *** BYPASS CONFIRMED — GOT DATA ***")
                print(hexdump(r[5:min(len(r), 5+64)]))
    else:
        print("    Mode 02 failed — trying read anyway")
        print("\n[6alt] Direct READ without mode 02")
        tx(ser, bytes([0x52, 0x00, 0x00, 0x00, 0x00, 0x01]), "READ")
        time.sleep(0.3)
        r = rx(ser, 300, timeout=3)
        if r and r[0] == 0x57:
            print("    *** READ WORKS WITHOUT MODE 02 ***")
            print(hexdump(r[5:min(len(r), 5+64)]))
        else:
            print("    Read also failed")

    ser.close()


def test_c_hidden_cmds():
    """Test C: Hidden firmware commands (PCTESTM, 588999, etc.)."""
    print("\n" + "=" * 60)
    print("TEST C: HIDDEN COMMANDS")
    print("=" * 60)

    cmds = [
        ("PCTESTM", b"PCTESTM\x00"),
        ("IDCHECK", b"IDCHECK\x00"),
        ("588999",  b"588999\x00\x00"),
        ("RTCITEM", b"RTCITEM\x00"),
        ("DEL-RCD", b"DEL-RCD\x00"),
    ]

    for name, cmd_bytes in cmds:
        print(f"\n--- {name} ---")
        ser = fresh_serial()

        # Handshake
        tx(ser, "PSEARCH", "PSEARCH")
        time.sleep(0.15)
        r = rx(ser, 8)
        if not r or r[0] != 0x06:
            print("  PSEARCH failed"); ser.close(); continue

        # Send hidden command
        print(f"  Sending {name}:")
        tx(ser, cmd_bytes, name)
        time.sleep(0.3)
        r = rx(ser, 128, timeout=3)
        if r:
            print(f"  *** {name} RESPONDED with {len(r)} bytes! ***")
            if len(r) > 16:
                print(hexdump(r))
        else:
            print(f"  {name}: no response")

        # Try after PASSSTA too
        ser.close()
        time.sleep(0.3)
        ser = fresh_serial()
        tx(ser, "PSEARCH", "PSEARCH")
        time.sleep(0.15)
        rx(ser, 8)
        tx(ser, "PASSSTA", "PASSSTA")
        time.sleep(0.15)
        rx(ser, 8)
        print(f"  Sending {name} after PASSSTA:")
        tx(ser, cmd_bytes, name)
        time.sleep(0.3)
        r = rx(ser, 128, timeout=3)
        if r:
            print(f"  *** {name} after PASSSTA: {len(r)} bytes! ***")
            if len(r) > 16:
                print(hexdump(r))

        ser.close()
        time.sleep(0.3)


def test_d_vframes():
    """Test D: All V-frame queries."""
    print("\n" + "=" * 60)
    print("TEST D: V-FRAME SURVEY")
    print("=" * 60)
    ser = fresh_serial()

    tx(ser, "PSEARCH", "PSEARCH")
    time.sleep(0.15)
    r = rx(ser, 8)
    if not r or r[0] != 0x06:
        ser.close(); return

    for vid in range(0x00, 0x20):
        label = {
            0x01: "fw_ver", 0x03: "build_date", 0x04: "dsp_ver",
            0x05: "radio_ver", 0x06: "uhf_range", 0x07: "vhf_range",
            0x0A: "config_range", 0x0B: "codeplug_ver", 0x0E: "boot_img",
            0x0F: "contacts", 0x10: "max_contacts",
        }.get(vid, "")
        tx(ser, bytes([0x56, 0x00, 0x00, 0x00, vid]), f"V{vid:02X} {label}")
        time.sleep(0.08)
        r = rx(ser, 64, timeout=1)
        if r and len(r) > 3:
            # Try to decode as ASCII
            try:
                txt = r[3:].decode('ascii', errors='replace').strip('\x00').strip()
                if txt and all(32 <= ord(c) < 127 for c in txt):
                    print(f"    -> {txt}")
            except:
                pass

    ser.close()


if __name__ == "__main__":
    tests = sys.argv[1:] if len(sys.argv) > 1 else ["a", "b", "c", "d"]
    try:
        if "a" in tests:
            test_a_proper_auth()
        if "b" in tests:
            test_b_bypass()
        if "c" in tests:
            test_c_hidden_cmds()
        if "d" in tests:
            test_d_vframes()
    except KeyboardInterrupt:
        print("\nInterrupted")
    except Exception as e:
        print(f"\nError: {e}")
        import traceback
        traceback.print_exc()
    print("\nAll tests complete.")
