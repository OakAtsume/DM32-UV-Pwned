#!/bin/bash
# DM-32UV Serial Sniffer using socat
# Creates a virtual serial port and logs all traffic with hex dump
#
# Usage:
#   1. Run: bash start_sniff.sh
#   2. It prints the PTY path and updates COM33
#   3. Open CPS in Bottles and do a READ
#   4. Press Ctrl+C when done
#   5. Run: bash stop_sniff.sh  (restores COM33)

DOSDEVICES="/home/oak/.local/share/bottles/bottles/DMR-CPS/dosdevices"
LOGFILE="/home/oak/Downloads/Baofeng_DM-32UV_Firmware_v1.01.048/dm32_socat.log"
PTY_LINK="/tmp/dm32_vcom"

echo "=== DM-32UV Serial Sniffer ==="
echo "Log file: $LOGFILE"
echo ""

# Start socat with hex dump logging
# -x = hex dump, -v = show data direction
# The '>' side is CPS, the '<' side is radio
socat -x -v \
  PTY,link=$PTY_LINK,raw,echo=0,b115200 \
  /dev/ttyUSB0,b115200,raw,echo=0 \
  2>"$LOGFILE" &

SOCAT_PID=$!
sleep 1

if [ ! -e "$PTY_LINK" ]; then
    echo "ERROR: socat failed to create PTY"
    kill $SOCAT_PID 2>/dev/null
    exit 1
fi

echo "Virtual port: $PTY_LINK"
echo "socat PID: $SOCAT_PID"
echo "$SOCAT_PID" > /tmp/dm32_sniff_pid.txt

# Repoint COM33 to virtual port
ln -sf "$PTY_LINK" "$DOSDEVICES/com33"
echo "COM33 -> $PTY_LINK"
echo ""
echo "*** Ready! Open CPS and do a READ. ***"
echo "*** Press Ctrl+C when done.         ***"
echo ""

# Wait for Ctrl+C
trap "echo 'Stopping...'; kill $SOCAT_PID 2>/dev/null; ln -sf /dev/ttyUSB0 $DOSDEVICES/com33; echo 'COM33 restored to /dev/ttyUSB0'; echo 'Capture saved to $LOGFILE'" INT
wait $SOCAT_PID
