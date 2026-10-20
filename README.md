# Baofeng DM-32UV Security Research

Security assessment of the Baofeng DM-32UV (DP570UV) DMR radio firmware.

**Researcher:** Oak (CR1KK7ISG) — 801 Labs  
**Date:** 2026-10-20  
**Target:** DM-32UV, firmware DM32.01.L01.048 (2022-06-27)  
**Platform:** HR_C7000 DMR SoC, C-SKY CK803S, uC/OS-III RTOS

## Summary

13 vulnerabilities identified across USB, OTA, and firmware update interfaces. No authentication is enforced at the radio firmware level — all CPS password checks are cosmetic (Windows-side only). AES-256 encryption keys are stored in plaintext. Remote radio control commands (stun, kill, monitor) require zero authentication. Firmware updates have no code signing.

Full 16 MB EEPROM dump completed, revealing executable code in external flash writable via the unauthenticated CPS protocol.

### Key Findings

| # | Finding | Severity |
|---|---------|----------|
| 1 | CPS password bypass — radio enforces nothing | Critical |
| 2 | AES-256 keys stored plaintext at 0x00C000 | Critical |
| 3 | Full codeplug extractable in 60s, no auth | Critical |
| 4 | No rate limiting on UART interface | High |
| 5 | Unauthenticated OTA remote control (stun/kill) | Critical |
| 6 | Remote Monitor = silent eavesdropping | Critical |
| 7 | Handler table out-of-bounds read | Critical |
| 8 | Proprietary block cipher for key derivation | High |
| 9 | OTA stack overflow via snprintf(0xFFFFFFFF) | Critical |
| 10 | No firmware code signing or integrity checks | Critical |
| 11 | Unrestricted 16 MB EEPROM read, no boundary checks | High |
| 12 | Executable CK803S code in external EEPROM (writable) | High |
| 13 | RF calibration data exposed and writable | High |

## Repository Structure

```
├── tools/                    # PoC and research tools
│   ├── dm32_reader.py        # EEPROM reader: dump, read, keys, radio ID
│   ├── dm32_ymodem_flash.py  # YMODEM-1K firmware flasher
│   ├── dm32_firmware_patcher.py  # Firmware parse/patch/diff/build
│   ├── dm32_poc.py           # Auth bypass PoC: extract keys + identity
│   ├── dm32_sniff2.py        # PTY serial sniffer for CPS via Wine
│   └── dm32_hidden_cmds2.py  # Hidden USB command tester
├── firmware/                 # Original firmware binary
│   ├── DM32_L01_048_20250821.bin
│   └── Firmware v1.01.048.txt
├── dumps/                    # Extracted data from radio
│   ├── dm32_eeprom_full.bin  # 16 MB EEPROM dump (SHA256: 44bf9b45...)
│   ├── codeplug_full.bin     # 561 KB codeplug extraction
│   ├── boot_icon_64x32.bmp  # Extracted boot icon (RGB565)
│   └── poc_output.json       # PoC tool output
├── captures/                 # Serial traffic captures (gzipped)
│   ├── dm32_fw_update_capture.log.gz   # Firmware update protocol
│   ├── dm32_cps_programming_capture.log.gz  # CPS programming session
│   ├── dm32_socat_capture.log.gz       # Early socat capture
│   └── eeprom_dump.log.gz             # EEPROM dump progress
├── docs/
│   ├── usage.md              # Detailed tool documentation
│   └── findings.html         # Full security findings report
├── reference/
│   └── Baofeng_DM-32UV_Firmware_Update_Guide.pdf
├── cps-software/             # Original CPS software (Windows)
└── archive/                  # Superseded intermediate scripts
```

## Quick Start

Requirements: Python 3, pyserial (`pip install pyserial`)

```bash
# Read radio info (radio must be powered on normally)
python3 tools/dm32_reader.py -p /dev/ttyUSB0 info

# Extract AES encryption keys
python3 tools/dm32_reader.py -p /dev/ttyUSB0 keys

# Dump full 16 MB EEPROM (~30 min)
python3 tools/dm32_reader.py -p /dev/ttyUSB0 dump 0x000000 0x1000000 dumps/eeprom.bin

# Read bootloader model (radio in bootloader: SK1+PTT during power-on)
python3 tools/dm32_ymodem_flash.py read-model --port /dev/ttyUSB0

# Verify firmware file integrity
python3 tools/dm32_ymodem_flash.py verify firmware/DM32_L01_048_20250821.bin
```

See [docs/usage.md](docs/usage.md) for full documentation.

## Protocols Decoded

**CPS Programming Protocol** (normal mode, 115200 8N1):
`PSEARCH` → `PASSSTA` → `PASWORD` → `SYSINFO` → V-frames → G-query → `PROGRAM` → READ/WRITE

**Firmware Flash Protocol** (bootloader mode, YMODEM-1K):
`R` polling → `M` model → `E` erase → YMODEM-1K transfer (840 blocks) → EOT

Both protocols decoded from live serial captures. Full protocol reference in the findings report.

## EEPROM Memory Map

```
0x000000-0x09FFFF  640 KB   Codeplug (settings, channels, AES keys, contacts)
0x0A7000           4 KB     RF calibration data (per-unit factory tuning)
0x0AC000           4 KB     Boot icon (RGB565, 64x32)
0x0BF000           4 KB     Boot strings ("WELCOME" / "DMR Radio")
0x0C3000           4 KB     Radio identity (DMR ID, callsign, owner)
0x0C5000           4 KB     CK803S executable code (EEPROM-resident)
0x0C8000-0x1FFFFF  1.2 MB   Font/glyph data + 1,636 CK803S functions
0x200000-0xE0BFFF  12 MB    DMR contact database (~200K records)
0xE0C000-0xFFEFFF  2 MB     Empty
```

## Legal

This research was conducted for educational and defensive security purposes under responsible disclosure principles. The tools are provided for authorized security testing only.
