#!/usr/bin/env python3
"""DM-32UV Serial Sniffer/Proxy.

Creates a virtual serial port (PTY) and forwards all data to/from the real
radio while logging every byte with microsecond timestamps.

Usage:
  1. Run this script: python3 dm32_sniff.py
  2. It prints a PTY path like /dev/pts/XX
  3. Connect the CPS to that PTY (or use socat TCP bridge)
  4. All bytes are logged to dm32_capture.log

For Windows CPS via TCP:
  - This also listens on TCP port 5555
  - On Windows, use com0com or a TCP-COM redirector to map to a COM port
  - Or: socat creates the bridge automatically
"""

import serial
import os
import pty
import select
import sys
import time
import socket
import threading

PORT = "/dev/ttyUSB0"
BAUD = 115200
TCP_PORT = 5555
LOG_FILE = "dm32_capture.log"

def hexline(data):
    return " ".join(f"{b:02X}" for b in data)

def asciiline(data):
    return "".join(chr(b) if 32 <= b < 127 else "." for b in data)


class SerialSniffer:
    def __init__(self):
        self.logf = open(LOG_FILE, "w")
        self.start_time = time.time()
        self.log("=== DM-32UV Serial Capture Started ===")

    def log(self, msg):
        t = time.time() - self.start_time
        line = f"[{t:10.6f}] {msg}"
        print(line)
        self.logf.write(line + "\n")
        self.logf.flush()

    def log_data(self, direction, data):
        """Log data transfer with hex and ASCII."""
        t = time.time() - self.start_time
        arrow = "CPS->RADIO" if direction == "tx" else "RADIO->CPS"
        hex_str = hexline(data)
        asc_str = asciiline(data)
        line = f"[{t:10.6f}] {arrow} ({len(data):3d}B): {hex_str}  |{asc_str}|"
        print(line)
        self.logf.write(line + "\n")
        self.logf.flush()

    def run_pty(self):
        """Create a PTY and proxy between it and the real serial port."""
        # Open real serial port
        try:
            radio = serial.Serial(PORT, BAUD, timeout=0.01,
                                  bytesize=8, parity='N', stopbits=1)
        except Exception as e:
            print(f"Can't open {PORT}: {e}")
            return

        # Create PTY
        master_fd, slave_fd = pty.openpty()
        slave_path = os.ttyname(slave_fd)
        self.log(f"Virtual serial port: {slave_path}")
        self.log(f"Real radio: {PORT}")
        self.log(f"Connect your CPS to: {slave_path}")
        print(f"\n*** Connect CPS to: {slave_path} ***\n")

        # Set raw mode on master
        import termios, tty
        tty.setraw(master_fd)

        radio_fd = radio.fileno()

        self.log("Proxy running. Press Ctrl+C to stop.")
        print("Waiting for CPS connection...\n")

        try:
            while True:
                rlist, _, _ = select.select([master_fd, radio_fd], [], [], 0.1)

                for fd in rlist:
                    if fd == master_fd:
                        # CPS -> Radio
                        try:
                            data = os.read(master_fd, 4096)
                        except OSError:
                            data = b""
                        if data:
                            self.log_data("tx", data)
                            radio.write(data)
                            radio.flush()

                    elif fd == radio_fd:
                        # Radio -> CPS
                        data = radio.read(4096)
                        if data:
                            self.log_data("rx", data)
                            os.write(master_fd, data)

        except KeyboardInterrupt:
            self.log("Stopped by user")
        finally:
            radio.close()
            os.close(master_fd)
            os.close(slave_fd)
            self.logf.close()
            print(f"\nCapture saved to {LOG_FILE}")

    def run_tcp(self):
        """TCP bridge mode — CPS connects via TCP, we proxy to serial."""
        try:
            radio = serial.Serial(PORT, BAUD, timeout=0.01,
                                  bytesize=8, parity='N', stopbits=1)
        except Exception as e:
            print(f"Can't open {PORT}: {e}")
            return

        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind(("0.0.0.0", TCP_PORT))
        server.listen(1)

        self.log(f"TCP bridge listening on port {TCP_PORT}")
        print(f"\n*** TCP proxy on port {TCP_PORT} ***")
        print(f"On Windows, map TCP to COM port, then connect CPS\n")

        try:
            while True:
                print("Waiting for TCP connection...")
                conn, addr = server.accept()
                self.log(f"TCP connection from {addr}")
                conn.settimeout(0.01)
                radio_fd = radio.fileno()

                try:
                    while True:
                        rlist, _, _ = select.select([conn.fileno(), radio_fd], [], [], 0.1)
                        for fd in rlist:
                            if fd == conn.fileno():
                                try:
                                    data = conn.recv(4096)
                                except socket.timeout:
                                    continue
                                if not data:
                                    raise ConnectionError("CPS disconnected")
                                self.log_data("tx", data)
                                radio.write(data)
                                radio.flush()
                            elif fd == radio_fd:
                                data = radio.read(4096)
                                if data:
                                    self.log_data("rx", data)
                                    conn.sendall(data)
                except (ConnectionError, BrokenPipeError):
                    self.log("CPS disconnected")
                    conn.close()
        except KeyboardInterrupt:
            self.log("Stopped by user")
        finally:
            radio.close()
            server.close()
            self.logf.close()
            print(f"\nCapture saved to {LOG_FILE}")


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "pty"
    sniffer = SerialSniffer()
    if mode == "tcp":
        sniffer.run_tcp()
    else:
        sniffer.run_pty()
