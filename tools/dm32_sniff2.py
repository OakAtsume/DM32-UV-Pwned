#!/usr/bin/env python3
"""DM-32UV Serial Sniffer v2 — threaded, robust PTY proxy.
Uses threads instead of select() to avoid PTY read issues."""

import serial
import os
import pty
import sys
import time
import threading
import tty
import fcntl
import termios
import struct
import signal

PORT = "/dev/ttyUSB0"
BAUD = 115200
LOG_FILE = "/home/oak/Downloads/Baofeng_DM-32UV_Firmware_v1.01.048/dm32_fw_update_capture.log"
DOSDEVICES = "/home/oak/.local/share/bottles/bottles/DMR-CPS/dosdevices"

lock = threading.Lock()
start_time = time.time()
logf = None
running = True

def log(msg):
    t = time.time() - start_time
    line = f"[{t:10.6f}] {msg}"
    with lock:
        print(line)
        logf.write(line + "\n")
        logf.flush()

def hexline(data):
    return " ".join(f"{b:02X}" for b in data)

def asciiline(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)

def forward_cps_to_radio(master_fd, radio_ser):
    """Thread: read from PTY master (CPS writes), forward to radio."""
    global running
    while running:
        try:
            data = os.read(master_fd, 4096)
            if data:
                log(f"CPS->RADIO ({len(data):3d}B): {hexline(data)}  |{asciiline(data)}|")
                radio_ser.write(data)
                radio_ser.flush()
        except OSError as e:
            if running:
                log(f"PTY read error: {e}")
            break

def forward_radio_to_cps(master_fd, radio_ser):
    """Thread: read from radio, forward to PTY master (CPS reads)."""
    global running
    while running:
        try:
            data = radio_ser.read(256)
            if data:
                log(f"RADIO->CPS ({len(data):3d}B): {hexline(data)}  |{asciiline(data)}|")
                os.write(master_fd, data)
        except OSError as e:
            if running:
                log(f"Serial read error: {e}")
            break
        except Exception as e:
            if running:
                log(f"Error: {e}")
            break

def main():
    global logf, running

    logf = open(LOG_FILE, "w")
    log("=== DM-32UV Serial Capture v2 (threaded) ===")

    # Open real serial port
    try:
        radio = serial.Serial(PORT, BAUD, timeout=0.1,
                              bytesize=8, parity='N', stopbits=1)
    except Exception as e:
        print(f"Can't open {PORT}: {e}")
        return
    log(f"Radio: {PORT} @ {BAUD}")

    # Create PTY pair
    master_fd, slave_fd = pty.openpty()
    slave_path = os.ttyname(slave_fd)

    # Set raw mode on both master and slave
    tty.setraw(master_fd)
    tty.setraw(slave_fd)

    # Set baud rate on slave to match
    attrs = termios.tcgetattr(slave_fd)
    # Set speed constants - B115200 = 0x1002 on Linux
    for speed_const in [termios.B115200]:
        attrs[4] = speed_const  # ispeed
        attrs[5] = speed_const  # ospeed
    attrs[2] = attrs[2] | termios.CS8 | termios.CREAD | termios.CLOCAL
    attrs[2] = attrs[2] & ~(termios.PARENB | termios.CSTOPB)
    termios.tcsetattr(slave_fd, termios.TCSANOW, attrs)

    # Make master_fd non-blocking? No, keep blocking for thread
    # But set a reasonable read size
    log(f"Virtual port: {slave_path}")

    # Update Wine COM33
    com33_path = os.path.join(DOSDEVICES, "com33")
    old_target = os.readlink(com33_path) if os.path.islink(com33_path) else None
    os.remove(com33_path)
    os.symlink(slave_path, com33_path)
    log(f"COM33 -> {slave_path} (was {old_target})")

    print(f"\n*** Sniffer ready! COM33 -> {slave_path} ***")
    print(f"*** Open CPS, do a READ, then Ctrl+C ***\n")

    # Start forwarding threads
    t1 = threading.Thread(target=forward_cps_to_radio, args=(master_fd, radio),
                          daemon=True)
    t2 = threading.Thread(target=forward_radio_to_cps, args=(master_fd, radio),
                          daemon=True)
    t1.start()
    t2.start()

    def cleanup(sig=None, frame=None):
        global running
        running = False
        log("Stopping...")
        # Restore COM33
        if old_target:
            os.remove(com33_path)
            os.symlink(old_target, com33_path)
            log(f"COM33 restored -> {old_target}")
        radio.close()
        os.close(master_fd)
        os.close(slave_fd)
        logf.close()
        print(f"\nCapture saved to {LOG_FILE}")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # Keep main thread alive
    while running:
        time.sleep(0.5)

if __name__ == "__main__":
    main()
