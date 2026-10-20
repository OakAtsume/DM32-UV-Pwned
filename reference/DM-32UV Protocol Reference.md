# Baofeng DM-32UV / DP570UV

USB/UART Programming Protocol & Firmware Internals Reference

[Hardware](#hw) [Serial Config](#serial) [Handshake](#handshake) [V-Frames](#vframe) [Programming](#program) [Read/Write](#readwrite) [Memory Map](#memory) [Firmware Commands](#firmware-cmds) [Debug & Hidden](#debug) [Bootloader](#bootloader) [Passwords](#passwords) [Named Functions](#functions)

## Hardware Overview

### SoC & Architecture

| Main SoC | HR_C7000 (DMR Baseband) |
| --- | --- |
| CPU Core | C-SKY CK803S (32-bit RISC) |
| RF Chip | FD6818 |
| RTOS | uC/OS-III (Micrium) |
| Display | ILI9341 240x320 TFT |

### Firmware Binary

| File | DM32_L01_048_20250821.bin |
| --- | --- |
| Size | 860,416 bytes (0xD2100) |
| Header | 256 bytes ("BFUV32-V2") |
| Flash Base | 0x03000000 |
| Entry Point | 0x03000100 |
| Encryption | None (plain binary) |

## Serial Configuration

**115200 baud, 8N1, no flow control.**

The programming cable uses a K-Plug connector with an FTDI UART chip. On Linux the radio appears as `/dev/ttyACM0` or `/dev/ttyUSB0`.

| Timing | Value |
| --- | --- |
| Port open → flush → PSEARCH | 400ms wait, flush, 200ms wait |
| Post-PSEARCH read delay | 150ms |
| Inter-command delay | 10-50ms |
| Block read/write spacing | 150ms |
| Request timeout | 5000ms |
| Block payload timeout | 15000ms |

## Handshake Sequence

The CPS uses an ASCII command handshake before entering programming mode. Each command is sent as raw ASCII bytes (no framing, no length prefix, no checksum).

1

**PSEARCH** — Detect radio

```
TX: 50 53 45 41 52 43 48        "PSEARCH"
RX: 06 44 50 35 37 30 55 56   ACK + "DP570UV"
```

Response: `0x06` (ACK) followed by 7-byte ASCII model string. Match on ACK + prefix.

2

**PASSSTA** — Check password status

```
TX: 50 41 53 53 53 54 41        "PASSSTA"
RX: 50 00 00                    'P' + status bytes
```

First byte must be `0x50` ('P'). If radio has a CPS password set, the CPS would then send `PASWORD` with credentials.

3

**SYSINFO** — System info query

```
TX: 53 59 53 49 4E 46 4F        "SYSINFO"
RX: 06                          ACK
```

4

**V-Frame queries** — Metadata (see next section)

5

**Enter programming mode**

```
TX: FF FF FF FF 0C 50 52 4F 47 52 41 4D   preamble + "PROGRAM"
RX: 06                                      ACK
TX: 02
RX: FF FF FF FF FF FF FF FF                  8x 0xFF
TX: 06
RX: 06                                      ACK — now in programming mode
```

No exit command exists. Closing the serial port resets the radio.

## V-Frame Queries (0x56)

Metadata queries sent before or after entering programming mode. Format: `56 00 00 <len> <id>`

| ID | Purpose | Response | Status |
| --- | --- | --- | --- |
| 0x01 | Firmware version | ASCII e.g. "DM32.01.01.046" | Confirmed |
| 0x02 | Unknown | Binary, two 0xA415 words | Unknown |
| 0x03 | Build date | ASCII | Confirmed |
| 0x04 | DSP version | ASCII | Confirmed |
| 0x05 | Radio version | ASCII | Confirmed |
| 0x06 | Unknown range | 0x201000–0x264FFF | Unknown |
| 0x07 | Unknown range | 0x0C9000–0x149FFF | Unknown |
| 0x08 | Unknown range | 0x180000–0x200FFF | Unknown |
| 0x09 | Unknown range | 0x6DC000–0xFFFFFF | Unknown |
| 0x0A | Main config region | 0x001000–0x0C8FFF | Confirmed |
| 0x0B | Codeplug version | ASCII | Confirmed |
| 0x0C | Unknown | Never queried by CPS | Unknown |
| 0x0D | Unknown (64 bytes) | 56 0D 40 03 4E 2D 00 … | Hidden |
| 0x0E | Boot image region | 0x150000–0x175FFF | Derived |
| 0x0F | Contacts region | 0x278000–0x6DBFFF | Confirmed |
| 0x10 | Max contact count | uint24 LE (50,000) | Confirmed |

## Read / Write Protocol

After entering programming mode, the CPS reads and writes 4 KB pages using binary commands. **No checksums or CRC.**

### Read (0x52)

```
TX: 52 [addr_lo] [addr_mid] [addr_hi] [len_lo] [len_hi]
RX: 57 [addr:3] [len:2] [data...]

Example — read 4096 bytes from 0x0AA000:
TX: 52 00 A0 0A 00 10
RX: 57 00 A0 0A 00 10 [4096 bytes of data]
```

### Write (0x57)

```
TX: 57 [addr:3 LE] [00 10] [4096 bytes]    (4102 bytes total)
RX: 06                                       ACK

Block ID sits at payload offset 0xFFF (last byte of 4096).
Sentinel address 0xFFF001 used for unallocated slots.
```

### Undocumented: G-Query (0x47)

```
TX: 47 00 00 00 00 01
RX: 53 [echoed header] [256 bytes]
```

Sent once before PROGRAM. Purpose Unknown. Returns 256 bytes of unidentified data.

## Memory Map

16 MB address space. Main config uses logical block IDs at page+0xFFF. Addresses vary per radio.

| Address Range | Size | Contents |
| --- | --- | --- |
| 0x000000-0x000FFF | 4 KB | Unknown (no V-frame) |
| 0x001000-0x0C8FFF | 800 KB | **Main config** — 200 pages, logical-ID driven |
| 0x0C9000-0x149FFF | 516 KB | Unknown (V-frame 0x07) |
| 0x150000-0x175FFF | 152 KB | **Boot image** — 240x320 BGR565 raw pixels |
| 0x180000-0x200FFF | 516 KB | Unknown (V-frame 0x08) |
| 0x201000-0x264FFF | 400 KB | Unknown (V-frame 0x06) |
| 0x278000-0x6DBFFF | 4.4 MB | **DMR contact database** — 92-byte records, 50K max |
| 0x6DC000-0xFFFFFF | 9.1 MB | Unknown (V-frame 0x09) |

Main Config Block IDs (codeplug structure)

| ID | Contents | Status |
| --- | --- | --- |
| 0x02 | Calibration data (DO NOT WRITE) | Calib |
| 0x04 | Radio settings, names, embedded info (\~85 bytes mapped of 4096) | Confirmed |
| 0x06 | Analog config: DTMF codes, analog contacts, BDC table | Confirmed |
| 0x0A | Quick text messages (stride 129) | Confirmed |
| 0x0F | DMR RX groups (stride 109) | Confirmed |
| 0x10 | Digital/analog emergency + **encryption keys** (@0x300) | Partial |
| 0x11 | Scan lists (stride 57) | Confirmed |
| 0x12–0x41 | Channel banks (48 slots, 48-byte records) | Confirmed |
| 0x42–0x43 | TX contact index | Confirmed |
| 0x44–0x48 | Talk group banks (24-byte entries) | Confirmed |
| 0x50–0x5B | **12 allocated blocks — never touched by CPS** | Hidden |
| 0x5C–0x64 | Zone banks (stride 145) | Confirmed |
| 0x65–0x66 | Roaming zones/channels (not implemented) | Stub |
| 0x67 | DMR radio ID list (stride 16) | Confirmed |
| 0x69–0x6E | 6 allocated blocks — never touched by CPS | Hidden |

## Firmware Command Table

The firmware at 0x030A17B4 contains an 11-entry command string table (8 bytes each) with a handler function pointer table at 0x030A180C.

| # | Command | Handler Address | Purpose | Used by CPS? |
| --- | --- | --- | --- | --- |
| 0 | PROGRAM | 0x0302BC92 | Enter programming mode (multi-state) | Yes |
| 1 | PSEARCH | 0x0302B894 | Probe/detect radio | Yes |
| 2 | DP570UV | 0x0302B8BA | Model identification | Implicit |
| 3 | PASSSTA | 0x0302B8E0 | Password status check | Yes |
| 4 | PASWORD | 0x0302B930 | Password authentication | If locked |
| 5 | PCTESTM | 0x0302B980 | **PC Test Mode** — factory testing | No |
| 6 | RTCITEM | 0x030AD770\* | RTC item access | No |
| 7 | DEL-RCD | 0x030AD77C\* | Delete record | No |
| 8 | IDCHECK | No handler in pointer table | No |  |
| 9 | SYSINFO | No handler in pointer table | Yes |  |
| 10 | 588999 | No handler in pointer table | No |  |

\* Data pointer tables, not code addresses. Handler dispatch uses nested indirection.

All handlers use double-indexed table lookups (channel A/B + state) to select response data, then branch to `FUN_0302c04c` to transmit the response.

## Debug / Hidden Commands & Attack Surface

### Commands NOT used by CPS

These commands exist in firmware but the OEM CPS software never sends them. They are likely factory/debug commands left in production firmware.

| PCTESTM | **PC Test Mode.** Multi-state handler dispatches based on computed state value (cases 4, 5, 6 use channel A/B indexed lookups). Likely provides direct hardware diagnostic access — signal levels, frequency adjustment, power output testing. At 0x0302B980. |
| --- | --- |
| RTCITEM | **Real-Time Clock item access.** Handler at 0x030AD770 is a data pointer table with 8 entries pointing to functions in the 0x030BD4F8–0x030BD530 range. Could allow reading/setting RTC registers. |
| DEL-RCD | **Delete record.** Handler at 0x030AD77C is a data pointer table. Could allow deleting codeplug records remotely without full write cycle. |
| IDCHECK | **ID verification.** No handler in pointer table — may be handled inline by the dispatch logic or as a no-op. |
| 588999 | **Numeric unlock code.** No handler in pointer table. At the keypad level, the firmware has a code dispatch table at 0x030A2000 where digit sequences route to different UI modes. `588999` may unlock a hidden factory menu or enable additional CPS commands. |

### Undocumented Binary Commands

| 0x47 (G) | Sent once before PROGRAM. Returns `0x53` + header echo + 256 bytes. Purpose unknown — could be device serial number, factory calibration, or debug dump. |
| --- | --- |
| 0x56 0x0D | V-frame ID 0x0D with len=0x40 returns 64 bytes of unknown data. Normal query (len=0x00) returns nothing. Hidden behavior. |
| 0x56 0x0C | V-frame ID 0x0C — never queried by any known CPS. Unknown purpose. |

### Unexplored Memory Regions

Multiple large memory regions with unknown contents. Blocks 0x50–0x5B (12 blocks, \~48 KB) are allocated but never read or written by any CPS — likely factory data, test results, or alternate configuration.

V-frame regions 0x06–0x09 cover over 10 MB of address space with unknown purpose.

Block 0x10 contains encryption keys at offset 0x300 but 73% of the block (2,975 bytes) is unmapped.

Block 0x04 (radio settings) has 98% of its 4,096 bytes unmapped.

## Bootloader Protocol

**The bootloader supports arbitrary memory write and code execution at 115200 8N1.**

### Boot Sequence

```
Radio powers on, sends: 02 24 00 03
If no response within timeout → normal boot (sends 00 10 00 03 00)
Reply with: 02 14 00 03 → enters factory test mode
```

### Memory Write (cmd 0x18)

```
TX: 02 18 [checksum] 03
TX: [4-byte address, e.g. 00 01 00 00]
TX: [4-byte size, e.g. 00 00 00 40 = 64 bytes]
TX: [data block]
RX: 02 05 00 03              (third byte 00 = OK)
```

### Code Execution (cmd 0x1B)

```
TX: 02 1B [checksum] 03
TX: [4-byte jump address, e.g. 00 01 09 74]
RX: 02 05 00 03              (third byte 00 = OK)
→ CPU jumps to specified address
```

Combined: write a small program to RAM (e.g. IRAM at 0x00010000), then execute it. This enables full firmware dumping, custom code execution, and flash reprogramming from the bootloader level.

## Known Passwords & Codes

| Code | Purpose | Location |
| --- | --- | --- |
| 66660501 | Adjust/calibration mode (UI password) | Firmware at 0x030A2040 |
| 374612 | Embedded info access (UI password) | Not in firmware flash (likely in codeplug/EEPROM) |
| 588999 | Unknown — in CPS command table | Command string at 0x030A1804 |

## Named Functions in Ghidra

Total functions renamed across analysis sessions: **\~70+**

uC/OS-III RTOS (25 functions)

| Address | Name |
| --- | --- |
| 0x030B4640 | OSTaskCreate |
| 0x030B32C0 | OSSemPend |
| 0x030B3944 | OSSemPost |
| 0x030B219C | OSSched |
| 0x030B1FB0 | OSTaskStkInit |
| 0x030B2B30 | OS_SchedRoundRobin |
| 0x030B248C | OS_PendListRemove |
| 0x030B2C90 | OS_TaskRdy |
| 0x030B2E6C | OS_IntQPost |
| 0x030B3134 | OS_QInit |
| 0x030B50DC | OS_TickTaskInit |
| 0x030B3254 | OS_PrioGetHighest |
| 0x030B327C | OS_PrioInsert |
| 0x030B52B0 | OS_TickListRemove |
| 0x030B22BC | OS_IdleTaskInit |
| 0x030B43EC | OS_TCBInit |
| 0x030B25AC | OS_PrioInit |

Crypto & DMR (14 functions)

| Address | Name |
| --- | --- |
| 0x030B5F00 | rc4_key_schedule |
| 0x030B5FA4 | rc4_crypt |
| 0x030B6014 | rc4_keystream_gen |
| 0x030C0890 | block_cipher_encrypt |
| 0x030C0E18 | eeprom_init_crypto_keys |
| 0x030B60C8 | dmr_lfsr_step |
| 0x030B61D4 | dmr_encrypt_permute |
| 0x030B6C80 | crc4_compute |
| 0x030B73D8 | dmr_cach_encode |
| 0x030CFC58 | bytes_to_bits |
| 0x030CFCFC | bits_to_bytes |
| 0x030B83C8 | prng_next |

Hardware / Peripherals (9 functions)

| Address | Name |
| --- | --- |
| 0x030B5A74 | gpio_i2c_read_byte |
| 0x030B5B6C | gpio_i2c_write_byte |
| 0x030B5C8C | i2c_write |
| 0x030B5D64 | i2c_read |
| 0x0305EDF8 | register_irq_handler |
| 0x030CF7E8 | delay_us |
| 0x030CF940 | delay_ms |
| 0x030B8338 | hw_load_calibration_data |

USB/CPS Protocol Handlers (8 functions)

| Address | Name |
| --- | --- |
| 0x0302BC92 | usb_cmd_dispatch (PROGRAM handler) |
| 0x0302B894 | usb_cmd_psearch |
| 0x0302B8BA | usb_cmd_dp570uv |
| 0x0302B8E0 | usb_cmd_passsta |
| 0x0302B930 | usb_cmd_password |
| 0x0302B980 | usb_cmd_pctestm |
| 0x0302C04C | usb_response_send (common response handler) |
| 0x03000100 | firmware_entry |

C Library & Application (12 functions)

| Address | Name |
| --- | --- |
| 0x030D08D4 | memcpy |
| 0x030D08EC | memset |
| 0x030BACE4 | memcpy_16 |
| 0x030BACFC | memset_16 |
| 0x03062F28 | abs |
| 0x03050008 | radio_load_settings |
| 0x030501D4 | channel_parse_config |
| 0x030509C8 | radio_reset_state |
| 0x030624D8 | strncmp |
| 0x03062584 | snprintf |

RTOS Tasks Discovered (19 tasks)

task init, CclTraffic, cpchanscan, SlotTimer, task psint, task SqlCheck, task gps, task ShutDown, task cds, task sound, **task usb**, task CallDisp, task CodeSw, Atask menu, task ScanDisp, task InputAlter, Idle Task, ISR Queue, Tick Task

## Next Steps

**With the radio on `/dev/ttyACM0`, we can:**

1. Send `PCTESTM` and observe the response — factory test mode access
2. Send `588999` and check if it enables additional commands or changes radio state
3. Send `RTCITEM` and `DEL-RCD` to map their protocols
4. Read V-frame `0x0C` and `0x0D` (len=0x40) for undocumented metadata
5. Query the `0x47` (G) command to identify its 256-byte payload
6. Read the 12 hidden blocks (`0x50–0x5B`) to discover factory data
7. Read calibration block `0x02` to understand hardware tuning parameters
8. Use the bootloader memory write + execute to dump full IRAM contents
9. Attempt to read the unknown V-frame regions (0x06–0x09)

Protocol spec sourced from [infamy/DM32-Protocol-Spec](https://github.com/infamy/DM32-Protocol-Spec). Firmware analysis performed on v1.01.048 (2025-08-21) using Ghidra with C-SKY V2 processor module.