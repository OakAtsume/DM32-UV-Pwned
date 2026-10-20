# Tool Documentation

All tools require Python 3 and pyserial (`pip install pyserial`).

The radio connects via CH340 USB-serial (VID:PID `1a86:7523`) at 115200 baud, 8N1. On Linux it typically appears as `/dev/ttyUSB0`.

---

## dm32_reader.py — EEPROM Reader

The primary data extraction tool. Uses the CPS programming protocol to read arbitrary addresses from the radio's external SPI flash/EEPROM in **normal operating mode** (radio powered on normally, not in bootloader).

The 24-bit address space covers the entire 16 MB external flash with no boundary enforcement. The radio accepts the trivial password `"123"` — and the password check itself is cosmetic (see `dm32_poc.py`).

### Commands

#### `info` — Read Radio Info
```bash
python3 tools/dm32_reader.py -p /dev/ttyUSB0 info
```
Performs the full CPS handshake, then reads the radio info block at `0x0C3000`. Displays:
- Raw hex dump of the first 128 bytes
- DMR ID (24-bit, little-endian at offset `+0x10`)
- Radio name (offset `+0x13`)
- Callsign (offset `+0x20`)
- Owner name (offset `+0x33`)

#### `keys` — Extract AES Encryption Keys
```bash
python3 tools/dm32_reader.py -p /dev/ttyUSB0 keys
```
Reads the 4 KB key block at `0x00C000`. Displays all programmed AES-256 encryption key names and their full 32-byte key values in hex. Key storage format:
- Names: 32-byte slots starting at `0x00C000` (null-padded)
- Values: starting at `0x00C300`, format is `[index][name\0][type_byte][32B key]`
- Type byte `0x04` = AES-256

#### `id` — Quick DMR ID Lookup
```bash
python3 tools/dm32_reader.py -p /dev/ttyUSB0 id
```
Compact version of `info` — reads only the identity fields (DMR ID, name, callsign, owner).

#### `read` — Read Arbitrary Address
```bash
python3 tools/dm32_reader.py -p /dev/ttyUSB0 read 0x0BF000 256
```
Reads `<size>` bytes starting at `<address>` and displays a hex dump. Address and size accept hex (`0x...`) or decimal. Useful for exploring specific EEPROM regions.

Notable addresses to inspect:
| Address | Content |
|---------|---------|
| `0x00C000` | AES encryption keys |
| `0x00D000` | Channel data (zone 1) |
| `0x05F000` | DMR contact list |
| `0x0A7000` | RF calibration data |
| `0x0AC000` | Boot icon (RGB565) |
| `0x0BF000` | Boot display strings |
| `0x0C3000` | Radio identity |
| `0x0C5000` | EEPROM-resident executable code |
| `0x201000` | Contact database index |

#### `dump` — Dump Address Range to File
```bash
# Dump full 16 MB EEPROM (~30 minutes at 9.3 KB/s)
python3 tools/dm32_reader.py -p /dev/ttyUSB0 dump 0x000000 0x1000000 dumps/eeprom.bin

# Dump just the codeplug (~1 minute)
python3 tools/dm32_reader.py -p /dev/ttyUSB0 dump 0x000000 0x0A0000 dumps/codeplug.bin

# Dump RF calibration region
python3 tools/dm32_reader.py -p /dev/ttyUSB0 dump 0x0A7000 0x0A8000 dumps/calibration.bin
```
Reads the range `[start, end)` in 4 KB blocks and writes raw binary to the output file. Shows progress with percentage, address, and speed.

### Protocol Details

The handshake follows the CPS protocol exactly:
1. `PSEARCH` → radio responds with model ID (`DP570UV`)
2. `PASSSTA` → radio says password required (`50 A5 A5`)
3. `PASWORD` → radio ACKs (always, without checking)
4. `PR` + `"123"` + null + padding → radio ACKs
5. `SYSINFO` → ACK
6. V-frames (`0x56`) — 11 device info queries
7. G-query (`0x47`) → 256 bytes of config data
8. Preamble (`FF FF FF FF 0C`) + `PROGRAM` → programming mode
9. Mode `0x02` → device info + ACK exchange

Then READ commands: `52 <addr:3 LE> <size:2 LE>` → `57 <addr:3> <size:2> <data>`

---

## dm32_ymodem_flash.py — YMODEM-1K Firmware Flasher

Decoded from live serial capture of the CPS firmware update process. Uses YMODEM-1K with a custom pre-handshake. The radio must be in **bootloader mode** (hold SK1 + PTT while powering on — green LED).

**WARNING:** The `flash` command writes firmware to the radio. A bad flash can brick the device. The radio has no firmware signing, so it will accept anything with the correct magic header.

### Commands

#### `read-model` — Query Bootloader Model
```bash
python3 tools/dm32_ymodem_flash.py read-model --port /dev/ttyUSB0
```
Contacts the bootloader and reads the model string. Expected response: `BFUV32-V2`. Safe, read-only operation. Useful to confirm the radio is in bootloader mode and responding.

#### `verify` — Verify Firmware File
```bash
python3 tools/dm32_ymodem_flash.py verify firmware/DM32_L01_048_20250821.bin
```
Offline check of a firmware `.bin` file. Verifies:
- Magic header (`BFUV32-V2` at offset 0)
- Total and flash payload sizes
- Block count for YMODEM transfer
- Last non-zero byte offset
- CRC-16/XMODEM of the flash payload

Does not connect to the radio.

#### `flash` — Flash Firmware
```bash
python3 tools/dm32_ymodem_flash.py flash firmware/DM32_L01_048_20250821.bin --port /dev/ttyUSB0
```
Full 7-phase firmware flash:
1. **Contact** — `R` (0x52) polling until the bootloader ACKs
2. **Model** — `M` command to read and verify model string
3. **Erase** — `E` command to prepare/erase flash
4. **YMODEM init** — `1` (0x31) → `C` (CRC-16 mode active)
5. **Metadata** — SOH block 0 with filename and file size
6. **Data** — 840 STX blocks (1024 bytes each) with CRC-16/XMODEM
7. **Finalize** — EOT (0x04) to end transfer

Prompts for confirmation before flashing. Use `-y` to skip the prompt. After flashing, power cycle the radio. A factory reset (SK1 + SK2 during power-on) is typically required.

### YMODEM-1K Block Format

```
[STX] [blk_num] [0xFF - blk_num] [1024 bytes payload] [CRC-16 high] [CRC-16 low]
```
- CRC-16/XMODEM: polynomial 0x1021, init 0x0000, computed over the 1024-byte payload only
- Block numbers start at 1 and wrap at 256
- The firmware `.bin` header (first 256 bytes) is stripped before transfer

---

## dm32_firmware_patcher.py — Firmware Parser

Offline tool for analyzing and modifying firmware `.bin` files. Does not connect to the radio.

### Commands

#### `parse` — Analyze Firmware Structure
```bash
python3 tools/dm32_firmware_patcher.py parse firmware/DM32_L01_048_20250821.bin
```
Displays: header magic, total/flash sizes, block count, IRAM region offsets, entry points, and file structure map.

#### `patch` — Apply Binary Patch
```bash
python3 tools/dm32_firmware_patcher.py patch firmware/DM32_L01_048_20250821.bin 0x1000 DEADBEEF output.bin
```
Writes hex bytes at the specified flash offset and saves to a new file. The offset is relative to the flash payload (after the 256-byte header).

#### `diff` — Compare Two Firmware Files
```bash
python3 tools/dm32_firmware_patcher.py diff original.bin modified.bin
```
Shows byte-level differences between two firmware files, grouped by region.

#### `build` — Build Minimal Firmware
```bash
python3 tools/dm32_firmware_patcher.py build payload.raw output.bin
```
Wraps a raw flash payload with the correct DM-32UV firmware header (magic + padding + END marker).

---

## dm32_poc.py — Authentication Bypass PoC

Demonstrates that the CPS programming password is not enforced by the radio firmware. Performs a targeted extraction of 5 codeplug pages in ~3.3 seconds without any authentication.

```bash
python3 tools/dm32_poc.py -p /dev/ttyUSB0
```

Extracts and displays:
- AES-256 encryption key names and values (from `0x00C000`)
- Channel data summaries (from `0x00D000`, `0x00E000`)
- DMR contact list entries (from `0x05F000`)
- Radio identity: DMR ID, callsign, owner name (from `0x0C3000`)

Output is also saved as JSON to `poc_output.json`.

The bypass works by skipping the `PASSSTA`/`PASWORD` handshake steps entirely — the radio enters programming mode without checking.

---

## dm32_sniff2.py — Serial Traffic Sniffer

Creates a virtual serial port (PTY pair) that acts as a transparent proxy between the CPS Windows software (running under Wine) and the real radio. All bidirectional traffic is logged with timestamps.

```bash
python3 tools/dm32_sniff2.py
```

This:
1. Creates a PTY pair (`/dev/pts/N` master + slave)
2. Symlinks the slave as `~/.wine/dosdevices/com33` (Wine COM33)
3. Opens the real radio on `/dev/ttyUSB0` at 115200 baud
4. Forwards all bytes bidirectionally, logging each transfer

**Setup:**
1. Start the sniffer in one terminal
2. Launch CPS under Wine: `wine "cps-software/DMR CPS.exe"`
3. In CPS, set the COM port to COM33
4. Perform any CPS operation (read codeplug, write, firmware update)
5. The full byte-level protocol exchange is logged

Edit the constants at the top of the file to change:
- `REAL_PORT` — the actual serial device (default `/dev/ttyUSB0`)
- `WINE_COM` — the Wine COM port number (default `com33`)
- `LOG_FILE` — output log file path

The log format is: `[timestamp] [direction TX/RX] [hex bytes]`

---

## dm32_hidden_cmds2.py — Hidden Command Tester

Tests the 5 hidden/debug USB commands found in the firmware's flash command table. These commands are normally unreachable (the active IRAM dispatcher doesn't route them), but can be sent directly over serial.

```bash
python3 tools/dm32_hidden_cmds2.py -p /dev/ttyUSB0
```

Commands tested:
| Command | Effect |
|---------|--------|
| `PCTESTM` | Factory LCD/signal test — watch the radio screen (no USB response) |
| `RTCITEM` | Handler targets DATA region → undefined instruction fault |
| `DEL-RCD` | Same as RTCITEM — crash trigger |
| `IDCHECK` | OOB table read → jump to unmapped address → hard fault |
| `588999` | OOB table read → crash |

**Warning:** `RTCITEM`, `DEL-RCD`, `IDCHECK`, and `588999` will crash the radio, requiring a power cycle. `PCTESTM` is safe — it only updates the display.

The tool enters programming mode first (same handshake as `dm32_reader.py`), then sends each command and records the radio's response or lack thereof.
