#!/bin/bash
# Capture USB serial traffic to/from the radio using tshark.
# The CPS connects directly to the radio — no proxy needed.
# Run with: sudo bash capture_usb.sh
# Stop with: Ctrl+C
# Then parse with: python3 parse_usbcap.py dm32_usb.pcap

echo "Loading usbmon..."
modprobe usbmon 2>/dev/null

echo "Starting capture on usbmon1 (bus 1)..."
echo "Now use the CPS to read from the radio."
echo "Press Ctrl+C when done."
echo ""

tshark -i usbmon1 \
  -f "host 1-1.3.3" \
  -w dm32_usb.pcap \
  -P 2>&1

echo ""
echo "Capture saved to dm32_usb.pcap"
echo "Parse with: python3 parse_usbcap.py dm32_usb.pcap"
