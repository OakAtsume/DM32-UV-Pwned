#!/usr/bin/env python3
"""DM-32UV: Test password bypass + attempt actual data read."""

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

def open_port():
    ser = serial.Serial(PORT, BAUD, timeout=2, bytesize=8, parity='N', stopbits=1)
    time.sleep(0.4)
    ser.reset_input_buffer()
    time.sleep(0.2)
    return ser

def send(ser, data, label=""):
    if isinstance(data, str):
        data = data.encode('ascii')
    print(f"  TX [{label}]: {' '.join(f'{b:02X}' for b in data)}")
    ser.write(data)
    ser.flush()

def recv(ser, size=256, timeout=2):
    ser.timeout = timeout
    data = ser.read(size)
    return data

def recv_show(ser, size=256, timeout=2):
    data = recv(ser, size, timeout)
    if data:
        print(f"  RX ({len(data)} bytes): {' '.join(f'{b:02X}' for b in data[:32])}" +
              (f" ... (+{len(data)-32} more)" if len(data) > 32 else ""))
    else:
        print("  RX: (timeout)")
    return data


print("=" * 60)
print("DM-32UV PASSWORD BYPASS + DATA READ TEST")
print("=" * 60)

ser = open_port()
print("Port open\n")

# Step 1: PSEARCH
print("[1] PSEARCH")
send(ser, "PSEARCH", "PSEARCH")
time.sleep(0.15)
resp = recv_show(ser, 8)
if not (resp and resp[0] == 0x06):
    print("PSEARCH failed!"); sys.exit(1)
print(f"    Model: {resp[1:].decode('ascii', errors='replace')}\n")

# Step 2: PASSSTA (check but don't authenticate)
print("[2] PASSSTA (check only)")
send(ser, "PASSSTA", "PASSSTA")
time.sleep(0.15)
resp = recv_show(ser, 8)
pw_required = resp and resp[0] == 0x50
print(f"    Password required: {pw_required}\n")

# Step 3: Skip password, try SYSINFO
print("[3] SYSINFO (no password sent)")
send(ser, "SYSINFO", "SYSINFO")
time.sleep(0.15)
resp = recv_show(ser, 8)
print()

# Step 4: Try V-frame queries without password
print("[4] V-Frame 0x01 (firmware version, no password)")
send(ser, bytes([0x56, 0x00, 0x00, 0x00, 0x01]), "V-Frame 0x01")
time.sleep(0.1)
resp = recv_show(ser, 64)
if resp and len(resp) > 3:
    print(f"    Firmware: {resp[3:].decode('ascii', errors='replace').strip()}")
print()

print("[4b] V-Frame 0x0A (main config range)")
send(ser, bytes([0x56, 0x00, 0x00, 0x00, 0x0A]), "V-Frame 0x0A")
time.sleep(0.1)
resp = recv_show(ser, 16)
if resp and len(resp) >= 11:
    start = int.from_bytes(resp[3:7], 'little')
    end = int.from_bytes(resp[7:11], 'little')
    print(f"    Config range: 0x{start:06X} - 0x{end:06X}")
print()

# Step 5: Enter PROGRAM mode without password
print("[5] PROGRAM (no password!)")
ser.reset_input_buffer()
time.sleep(0.1)
send(ser, b"\xFF\xFF\xFF\xFF\x0CPROGRAM", "PROGRAM")
time.sleep(0.2)
resp = recv_show(ser, 8)
if not resp or resp[0] != 0x06:
    print("PROGRAM rejected."); ser.close(); sys.exit(1)
print("    PROGRAM ACK'd!\n")

# Step 5b: Mode 02
print("[5b] Mode 02")
ser.reset_input_buffer()
time.sleep(0.1)
send(ser, b"\x02", "mode 02")
time.sleep(0.3)
resp = recv_show(ser, 8, timeout=3)
if resp and all(b == 0xFF for b in resp):
    print(f"    Got {len(resp)} x 0xFF — programming mode confirmed!\n")

    # Step 5c: Confirm with 0x06
    print("[5c] Confirm 0x06")
    send(ser, b"\x06", "confirm")
    time.sleep(0.15)
    resp = recv_show(ser, 8)
    if resp and resp[0] == 0x06:
        print("    *** FULL PROGRAMMING MODE — NO PASSWORD ***\n")

        # Step 6: Try reading actual codeplug data!
        print("[6] READ block ID at page 0x001FFF")
        send(ser, bytes([0x52, 0xFF, 0x1F, 0x00, 0x01, 0x00]), "READ 0x001FFF x1")
        time.sleep(0.2)
        resp = recv_show(ser, 16)
        if resp and resp[0] == 0x57:
            block_id = resp[6] if len(resp) > 6 else None
            print(f"    *** READ WORKS! Block ID: 0x{block_id:02X} ***\n" if block_id is not None else "")

            # Read first 256 bytes of radio settings (block 0x04)
            # First scan for block 0x04
            print("[7] Scanning for block 0x04 (radio settings)...")
            for page in range(0x001, 0x0C9):
                addr = page * 0x1000
                id_addr = addr + 0xFFF
                send(ser, bytes([
                    0x52,
                    id_addr & 0xFF, (id_addr >> 8) & 0xFF, (id_addr >> 16) & 0xFF,
                    0x01, 0x00
                ]), f"scan 0x{addr:06X}")
                time.sleep(0.02)
                r = recv(ser, 7, timeout=1)
                if r and len(r) >= 7 and r[0] == 0x57 and r[6] == 0x04:
                    print(f"    Found block 0x04 at page 0x{addr:06X}!")

                    # Read first 256 bytes
                    print(f"\n[8] Reading 256 bytes from 0x{addr:06X}")
                    send(ser, bytes([
                        0x52,
                        addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF,
                        0x00, 0x01  # 256 bytes
                    ]), f"READ 0x{addr:06X} x256")
                    time.sleep(0.5)
                    r2 = recv(ser, 261, timeout=5)
                    if r2 and r2[0] == 0x57 and len(r2) > 5:
                        print(f"    Got {len(r2)} bytes!")
                        print(hexdump(r2[5:min(len(r2), 5+256)]))
                    break
            else:
                print("    Block 0x04 not found in scan")
        else:
            print("    Read failed or rejected")
    else:
        print("    Confirm failed")
else:
    print("    Mode 02 failed — may need password for PROGRAM after all")
    print("    Trying direct read anyway...\n")

    # Try read without full PROGRAM entry
    print("[6alt] Direct READ attempt")
    send(ser, bytes([0x52, 0xFF, 0x1F, 0x00, 0x01, 0x00]), "READ 0x001FFF x1")
    time.sleep(0.2)
    resp = recv_show(ser, 16)

ser.close()
print("\nDone. Port closed.")
