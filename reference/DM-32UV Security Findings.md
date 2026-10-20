# Baofeng DM-32UV Security Assessment

Firmware reverse engineering & vulnerability research\
CR1KK7ISG · 801 Labs · 2026-10-20

Target

Baofeng DM-32UV (DP570UV)

Firmware

DM32.01.L01.048 (2022-06-27)

Platform

HR_C7000 DMR SoC, C-SKY CK803S, uC/OS-III RTOS

Interface

USB-UART (CH340, 115200 8N1)

Tools

Ghidra, Python 3 + pyserial, custom serial sniffers

## 1. Confirmed Vulnerabilities

Critical CPS Password Bypass — No Authentication Enforced

The CPS programming password is enforced exclusively by the Windows CPS software. The radio firmware accepts all programming commands without any authentication.

Skipping the `PASSSTA`/`PASWORD` handshake steps entirely still allows:

- Full `PROGRAM` mode entry
- Complete codeplug read (137 pages, 561 KB)
- All data identical to authenticated dumps (byte-for-byte verified)

```
# Normal protocol:  PSEARCH → PASSSTA → PASWORD → (password check) → SYSINFO → ...
# Bypass:           PSEARCH → SYSINFO → V-frames → PROGRAM → full access
```

**PoC:** `dm32_poc.py` — extracts radio identity, AES keys, channels, and contacts without authentication in 3.3 seconds.

Critical AES-256 Encryption Keys Stored in Plaintext

DMR encryption key names and full 32-byte key values are stored unencrypted in the codeplug at radio address `0x00C000` (block type `0x10`). Combined with the password bypass, any AES-256 key can be extracted over USB in seconds.

```
Radio page 0x00C000, offset 0x2FC:
  01 45 6E 63 72 79 70 74 20 31 00  "Encrypt 1"
  ... 04 41 42 43 44 45 46 47 48  (32 bytes: full AES-256 key)
        4A 4B 4C 4D 4E 4F 50 51
        52 53 54 55 56 57 58 59
        5A 31 32 33 34 35 36 37
```

Key structure: count byte, name (null-terminated), slot text, type byte (`0x04` = AES-256), then 32 raw key bytes.

Critical Handler Table Out-of-Bounds Read

The USB command string table at `0x030a17b4` contains 11 entries, but the corresponding handler pointer table at `0x030a180c` has only 8 entries. Commands indexed 8–10 read past the table into adjacent string data.

| Index | Command | Handler Ptr | Target | Status |
| --- | --- | --- | --- | --- |
| 0 | PROGRAM | `0x0302bc92` | Valid code | OK |
| 1 | PSEARCH | `0x0302b894` | Valid code | OK |
| 2 | DP570UV | `0x0302b8ba` | Valid code | OK |
| 3 | PASSSTA | `0x0302b8e0` | Valid code | OK |
| 4 | PASWORD | `0x0302b930` | Valid code | OK |
| 5 | PCTESTM | `0x0302b980` | Valid code | OK |
| 6 | RTCITEM | `0x030ad770` | DATA region | Crash |
| 7 | DEL-RCD | `0x030ad77c` | DATA region | Crash |
| 8 | IDCHECK | `0x6b736174` | "task" → unmapped | OOB |
| 9 | SYSINFO | `0x6c614320` | " Cal" → unmapped | IRAM bypass |
| 10 | 588999 | `0x7369446c` | "lDis" → unmapped | OOB |

**SYSINFO** works despite its OOB entry because the IRAM-based dispatch code (`0x00040D9C`) handles it directly, never consulting the flash table. The flash table is dead code — but reachable if execution is redirected through it.

```
Handler table at 0x030a180c:                     Memory past table:

 [0] 0302bc92  PROGRAM   ─┐                      030a182c: 74 61 73 6b  "task CallDisp..."
 [1] 0302b894  PSEARCH    │ valid                 030a1830: 20 43 61 6c
 [2] 0302b8ba  DP570UV    │ handler               030a1834: 6c 44 69 73
 [3] 0302b8e0  PASSSTA    │ pointers              ▲  ▲  ▲
 [4] 0302b930  PASWORD    │                       │  │  └─ 588999 reads here
 [5] 0302b980  PCTESTM   ─┘                      │  └─── SYSINFO reads here
 [6] 030ad770  RTCITEM ──── points to DATA        └───── IDCHECK reads here
 [7] 030ad77c  DEL-RCD ──── points to DATA
```

High Proprietary Block Cipher for Key Derivation

The function `eeprom_init_crypto_keys` at `0x030c0e18` generates EEPROM encryption material using a custom block cipher instead of a vetted algorithm.

- 8-byte blocks, 32 rounds of bit rotation (shift-3/shift-5)
- 5 different permutation sub-functions selected by key-schedule bits
- I2C EEPROM at address `0x7A`, offset `0x30`
- Hardcoded interleaving constants: `00 16 FA B1 ED 9F 25 15`
- Key source material stored in IRAM (loaded at runtime, not in firmware binary)

Deterministic key generation with static constants means all radios sharing the same firmware produce predictable key material.

High No Rate Limiting on UART Interface

The USB-UART interface processes commands at wire speed with no brute-force protection, lockout, or throttling. Combined with the password bypass, this is moot for authentication — but it also means codeplug writes are unrestricted.

Critical Unauthenticated Remote Radio Control (Stun / Kill / Monitor)

The DM-32UV implements DMR Tier 2 supplementary services for remote radio control, accessible via **Contact → Radio Actions**:

| Feature | String Address | Impact |
| --- | --- | --- |
| Radio Check | `0x030af8d4` | Probe if target radio is active |
| Call Alert | `0x030af8e0` | Page / alert the target radio |
| Remote Mon. | `0x030af8ec` | Silently open target mic — eavesdrop |
| Radio Disable | `0x030af8f8` | Persistently disable target TX/RX |
| Radio Enable | `0x030af908` | Re-enable a disabled radio |
| Radio Stun | `0x030b1494` | Temporarily inhibit target radio |

### Zero Authentication

Firmware analysis reveals **no authentication mechanism whatsoever** for incoming remote control commands:

- No “Auth”, “Verify”, or password-related strings found in firmware context
- The ISR frame handler at `0x0301cad4` processes incoming CSBK opcodes (`0x04`, `0x1D`, `0x1F`, `0x24`, `0x27`) and auto-responds via `FUN_03017894` with **no source ID validation**
- DMR Tier 2 (ETSI TS 102 361-2) does not define authentication for CSBK supplementary services
- Some commercial DMR vendors add a proprietary “Remote Kill Password” — Baofeng adds none

### Protocol Flow (RX side)

```
Attacker SDR / DMR Radio
  │
  │  CSBK opcode 0x24 (Ahoy) + target DMR ID
  ▼
isr_frame_handler @ 0x0301cad4
  │  Checks: state==0x04 AND opcode in {0x04,0x1D,0x1F,0x24,0x27}
  │  For 0x24: also checks byte[7] MSB clear (Protect Flag)
  │  NO source ID check. NO password check. NO user prompt.
  ▼
FUN_03017894 @ 0x03017894
  │  Auto-constructs response CSBK (opcode 0x87)
  │  Extracts source/target IDs from received frame
  │  Sends immediate ACK — radio complies silently
  ▼
Radio executes command:
  • Radio Check  → responds with ACK
  • Remote Monitor → opens mic, transmits audio
  • Radio Disable → disables TX/RX persistently
  • Radio Stun → inhibits radio temporarily
```

### TX side

`radio_send_command(8)` at `0x030235f8` queues CSBK commands through the DMR TX pipeline. The command byte encodes the action type. Target DMR ID is encoded as BCD in `FUN_03023860`.

### Attack Requirements

- **Target DMR ID:** Broadcast in every voice/data transmission (easily captured with any DMR receiver or SDR)
- **Frequency:** Public repeater databases list frequencies and talkgroups
- **Equipment:** Any DMR radio with “Radio Actions” enabled, or an SDR capable of DMR TX (HackRF One, \~$300)
- **Only protection:** Per-channel “decode” flag in codeplug — if disabled, radio ignores the command. Likely *enabled* by default.

**Impact:** Any radio on the same frequency can stun, disable, or eavesdrop on any DM-32UV without authentication. Remote Monitor enables silent surveillance — the target radio opens its microphone with no on-screen indication. Mass denial-of-service is possible by iterating over known DMR IDs.

Critical No Firmware Code Signing or Integrity Verification

The DM-32UV firmware binary has **no cryptographic signature, no checksum, and no encryption**. The bootloader accepts any binary with the correct 9-byte magic header.

### Firmware Format (fully decoded)

```
Offset    Content
────────  ───────────────────────────────────
0x000000  42 46 55 56 33 32 2D 56 32  "BFUV32-V2" (magic)
0x000009  FF FF FF FF ... (padding)
0x0000FD  45 4E 44                    "END" (header terminator)
0x000100  Raw flash image begins     → maps to 0x03000000
  ...     [536 KB main code/data]
  ...     [84 KB IRAM code (copied to 0x00010000 at boot)]
  ...     [4 KB sparse data]
0x0D20FF  00 00 00 00 ...             Zero padding (no checksum/sig)
```

### Bootloader Entry

- **Entry method:** Hold **SK1 + PTT** while powering on → green LED
- **Interface:** Same USB-UART (CH340, 115200 8N1)
- **CPS menu:** Tool → Firmware (accepts `*.bin` and `*.enc` files)
- **Pre-requisite:** "Allow Reset" must be enabled in CPS Optional Features
- **Post-update:** Factory reset required (SK1 + SK2 during power-on)

### Missing Security Controls

| Control | Status |
| --- | --- |
| Code signing (RSA/ECDSA) | None |
| CRC/checksum at file tail | None — last 256 bytes are 0x00 |
| Firmware encryption | None — 12.3% null bytes confirms plaintext |
| Secure Boot chain | None — bootloader has no verification step |
| Anti-rollback (version fuse) | None — any version flashable |
| Hardware write-protect | None — no JTAG/SWD lock observed |

**PoC:** `dm32_firmware_patcher.py` — can parse, patch, diff, and build minimal valid firmware files. `dm32_bootloader_probe.py` — probes bootloader protocol when radio is in update mode.

**Impact:** Anyone with USB access can flash arbitrary firmware. Combined with the OTA stack overflow (V7), an attacker could achieve **persistent remote compromise**: OTA exploit → shellcode writes modified firmware to flash → backdoor survives reboot.

## 2. Hidden / Debug Command Analysis

The firmware contains 11 USB command strings, but only 6 are reachable through the active IRAM dispatch. The remaining 5 are dead code in flash.

| Command | Handler | Purpose | Reachable? |
| --- | --- | --- | --- |
| PCTESTM | `0x0302b980` | Factory LCD/signal test. Branches on param values 4, 5, 6 to render VFO signal info. References "Opt Signal" display string. No USB response — display only. | Dead code |
| RTCITEM | `0x030ad770` | Handler points to data region (pointer table: `0x030bd4f8`, `0x030bd500`, ...). Execution would fault on undefined instructions. | Crash trigger |
| DEL-RCD | `0x030ad77c` | Same as RTCITEM — handler points into data. Likely record deletion that was neutered by pointing the handler at data instead of removing the string. | Crash trigger |
| IDCHECK | OOB | Index 8 in an 8-entry table. Reads `0x6b736174` ("task") as function pointer. Jump to unmapped memory → hard fault. | Crash trigger |
| 588999 | OOB | Index 10. Reads `0x7369446c` ("lDis") as function pointer. Same unmapped crash. | Crash trigger |

### Why they're unreachable

The active USB command dispatch runs from **IRAM** (`0x00040D9C`), not from the flash command table. The IRAM code has hardcoded handlers for the 6 CPS commands (PSEARCH, PASSSTA, PASWORD, SYSINFO, PROGRAM, DP570UV) and ignores the flash table entirely. Evidence: SYSINFO works despite being OOB (index 9) in the flash table — proving it's routed by IRAM logic, not the table.

### Command validation functions

Three `usb_cmd_compare_*` functions validate incoming data against codeplug-stored command lists:

| Function | Address | Source | Record Size | Compare Length |
| --- | --- | --- | --- | --- |
| compare_a | `0x030229b4` | Codeplug section 0x11 | 57 bytes | 11 bytes |
| compare_b | `0x03049498` | Dynamic (via `FUN_030483ac`) | Variable | 16 bytes |
| compare_d | `0x03058184` | Codeplug section 0x65 | 33 bytes | 16 bytes |

## 3. Protocol Architecture

```
┌──────────────┐     USB-UART      ┌──────────────────────────────────┐
│   Attacker   │ ◄──── CH340 ────► │        DM-32UV Radio             │
│  (Python)    │   115200 8N1      │                                  │
└──────────────┘                   │  ┌───────────────────────────┐   │
                                   │  │  IRAM Dispatch (0x40D9C)  │   │
   CPS Protocol:                   │  │  ├─ PSEARCH handler       │   │
   ┌─ PSEARCH ──► model ID         │  │  ├─ SYSINFO handler       │   │
   ├─ PASSSTA ──► password?        │  │  ├─ PROGRAM handler       │   │
   ├─ PASWORD ──► check pw         │  │  ├─ PASSSTA handler       │   │
   ├─ SYSINFO ──► ACK              │  │  ├─ PASWORD handler       │   │
   ├─ V-frames ─► device info      │  │  └─ DP570UV handler       │   │
   ├─ G-query ──► config data      │  └───────────────────────────┘   │
   ├─ PROGRAM ──► enter prog       │                                  │
   ├─ 02/FF/06 ─► mode active      │  ┌───────────────────────────┐   │
   ├─ READ ─────► codeplug         │  │  Flash Table (dead code)  │   │
   ├─ WRITE ────► codeplug         │  │  ├─ PCTESTM  → LCD test   │   │
   └─ END ──────► exit             │  │  ├─ RTCITEM  → DATA crash │   │
                                   │  │  ├─ DEL-RCD  → DATA crash │   │
   Bypass:                         │  │  ├─ IDCHECK  → OOB crash  │   │
   Skip PASSSTA/PASWORD            │  │  └─ 588999   → OOB crash  │   │
   entirely → full access          │  └───────────────────────────┘   │
                                   └──────────────────────────────────┘
```

## 4. Attack Scenarios

Scenario Encryption Key Theft

An attacker with brief physical access to a radio's USB port can extract all AES-256 encryption keys in under 4 seconds. This compromises the confidentiality of all DMR encrypted communications using those keys, across every radio sharing the same keys.

0.0s

Connect USB cable

0.8s

PSEARCH → model ID

1.0s

SYSINFO (skip password)

1.5s

V-frames + PROGRAM mode

2.8s

Read page 0x00C000

3.3s

AES-256 keys extracted

Scenario Identity Cloning

DMR ID, callsign, radio name, and owner name are all readable at `0x0C3000`. An attacker can clone a radio's identity to impersonate its operator on DMR networks.

Scenario Channel / Contact Enumeration

Full channel list (frequencies, modes, names) and DMR contact database (talkgroup IDs, private call IDs) can be extracted to map an organization's communications infrastructure.

Scenario Over-the-Air Remote Surveillance

An attacker with an SDR and the target's DMR ID (captured from any overheard transmission) sends a CSBK Remote Monitor command. The target radio silently opens its microphone and transmits ambient audio back to the attacker. No physical access required. No on-screen alert on the target.

passive

Monitor DMR traffic, capture target DMR ID

0.0s

Craft CSBK Ahoy (0x24) with Remote Monitor service kind

0.1s

Target ISR auto-responds with ACK

0.2s

Target mic opens — audio TX begins

30s+

Eavesdropping active for “Measure Period” duration

Scenario Mass Radio Denial of Service

An attacker iterates over known DMR IDs on a talkgroup, sending Radio Disable CSBK commands. Each target radio is persistently disabled (TX and RX cease). Recovery requires a Radio Enable command from another radio or physical CPS reprogramming. A single attacker can disable an entire fleet in minutes.

Scenario Persistent Remote Compromise (OTA → Flash)

Combining the OTA stack overflow (V7) with the absence of firmware signing (V9), an attacker can achieve **persistent remote code execution** that survives power cycles:

passive

Capture target DMR ID from any overheard transmission

0.0s

Transmit crafted DMR data packet with oversized text field

0.1s

Stack overflow in `dmr_message_display_renderer`

0.1s

Return address overwritten → shellcode executes in IRAM

0.2s

Shellcode calls flash erase/write via SoC peripheral registers

0.5s

Modified firmware written to flash (no signature check)

reboot

Backdoored firmware loads — persistent compromise

**Key enablers:** No NX bit (shellcode runs from stack), no firmware signing (flash accepts arbitrary writes), no secure boot (modified firmware loads without verification). The CK803S has a flat address space with all memory executable.

## 5. RF Data Path Analysis (SMS / APRS)

Systematic analysis of the firmware's RF data receive path identified architectural concerns regarding buffer safety in message handling. While exploitable overflow could not be confirmed through static analysis alone (key receive functions are in IRAM, not the flash image), the structural risk is high.

Critical Over-the-Air Stack Buffer Overflow via snprintf(0xFFFFFFFF)

The firmware’s string formatting wrapper uses `snprintf` with a **4 GB size limit**, making every call site an effectively unbounded `sprintf`:

```
sprintf_wrapper_varargs @ 0x03061bb8
  ↓
sprintf_wrapper_unbounded @ 0x03061bd4
  ↓
snprintf(dest, 0xFFFFFFFF, fmt, args)  ← 4 GB “limit”
```

This wrapper is called from the **DMR message display renderer** (`0x0301ea6c`) with an **\~8-byte stack buffer** (`local_38`) as the destination, formatting data from incoming DMR packets:

- Caller DMR ID (24-bit, from received OTA frame)
- Contact name / talker alias (variable length, OTA-sourced)
- Message counters and slot indicators

Multiple call sites in `dmr_message_display_renderer`:

```
sprintf_wrapper_varargs(&local_38, PTR_DAT_..., *(DAT_... + 0x10));  // caller ID
sprintf_wrapper_varargs(&local_38, PTR_PTR_..., *(DAT_... + 0x10));  // with alias
sprintf_wrapper_varargs(&local_38, PTR_PTR_..., uVar5);              // slot ID
```

### Exploitation Conditions (all met)

| Mitigation | Status |
| --- | --- |
| Stack canaries | None |
| ASLR | None — flat address space, fixed load addresses |
| NX / W^X | None — all memory executable on CK803S |
| Input validation | None before format |

**Impact:** A crafted DMR data packet with an oversized contact name or caller ID field overflows the 8-byte stack buffer, overwrites the return address, and achieves **arbitrary code execution over the air** with no user interaction. This is a textbook stack-based buffer overflow on a platform with zero mitigations.

High Unbounded String Functions on OTA Data Paths

The firmware links unbounded C string functions that operate on data derived from over-the-air (OTA) sources:

| Function | Address | Risk |
| --- | --- | --- |
| `strcpy` | `0x030623cc` | No length bound — copies until NUL |
| `strcat` | `0x0306239c` | Appends until NUL, no dest bound |
| `memcpy` | `0x0306227c` | Safe if size is validated |
| `snprintf` | `0x03062584` | Called with size=0xFFFFFFFF via wrapper — **unbounded** |

Both `strcpy` and `strcat` are used in a firmware that processes variable-length text from untrusted sources: DMR SMS messages (UTF-16, up to \~280 chars), APRS information fields (up to 256 bytes), and contact names. A malicious OTA packet with an oversized or un-terminated string field could overflow a stack or heap buffer.

Critical Firmware-Wide sprintf Equivalent via snprintf(dest, 0xFFFFFFFF, fmt, ...)

The firmware's primary string formatting wrapper (`FUN_03061bb8` → `FUN_03061bd4`) calls `snprintf` with a size parameter of `0xFFFFFFFF`, effectively converting every call site into an unbounded `sprintf`:

```
// FUN_03061bd4 @ 0x03061bd4 — decompiled
void format_string(char *dest, char *fmt, va_list args) {
    snprintf(dest, 0xFFFFFFFF, fmt, args);  // 4 GB “limit” = no limit
}
```

This wrapper is called from the **DMR message display renderer** (`FUN_0301ea6c`) with stack-local buffers as destinations:

```
// FUN_0301ea6c — message display (decompiled, simplified)
char local_38[8];  // stack buffer, ~56 bytes from frame base
...
FUN_03061bb8(&local_38, format_ptr, source_dmr_id);  // unbounded write!
FUN_0300be38(0x28, 10, &local_38, color, 0);         // render to LCD
```

**Attack vector:** A crafted DMR data packet with an oversized contact name or source ID string would trigger `FUN_03061bb8` to write past the end of the 8-byte `local_38` stack buffer. On CK803S (no stack canaries, no ASLR, no NX), this directly overwrites the return address on the stack — a classic stack-based buffer overflow leading to arbitrary code execution.

**Impact:** Remote code execution via over-the-air DMR packet. No physical access required. No user interaction — the radio processes the packet automatically on receive.

**Scope:** `FUN_03061bb8` is called from at least 16 format-string sites across the firmware (menu rendering, contact display, channel info, APRS info). Every call site that formats OTA-sourced data into a fixed-size stack buffer is potentially exploitable.

### DMR Frame Dispatch Architecture

Incoming DMR data flows through a multi-stage dispatcher:

```
RF Baseband (HR_C7000)
  │
  ▼
isr_frame_handler @ 0x0301cad4
  │  dispatches frame types 0x04, 0x1D, 0x1F, 0x24, 0x27
  ▼
FUN_0301c978 — Main frame type dispatcher
  │  58-entry jump table (type byte - 4 = index)
  │  Allocates 24-byte buffers via FUN_0301c564
  ▼
FUN_0301a78c — RX frame filter/router
  │  Extracts source/dest IDs from headers
  │  Filters by radio's own ID, group membership
  │  param_1: 1=CSBK, 2=data header, 3=voice, 6=data
  ▼
FUN_03018eac — Sub-dispatcher (16 entries)
  │  Dispatches on data header subtype byte
  ▼
FUN_0301ea6c — Message display renderer (← OVERFLOW HERE)
  │  Calls FUN_03061bb8(stack_buf, fmt, ota_data)
  │  snprintf(dest, 0xFFFFFFFF, fmt, ...) — unbounded!
  ▼
LCD output / message storage
```

**Key observation:** Frame buffers are fixed at 24 bytes (matching DMR data block size). Standard-compliant packets fit. However, a malformed data header with a crafted block size or count field could cause the `FUN_030191c4` data block assembler to write beyond buffer boundaries.

### APRS TX/RX Chain

APRS uses AX.25 framing over 1200 baud AFSK, processed by these identified functions:

| Address | Function | Role |
| --- | --- | --- |
| `0x030593a4` | `nrzi_encode_bytes` | NRZI encoding for AX.25 TX |
| `0x030594b4` | bit_reversal | LSB↔MSB conversion (APRS is LSB-first) |
| `0x03059524` | CRC-CCITT | AX.25 FCS (polynomial 0x1021) |
| `0x030599d8` | NRZI decode + deinterleave | 112-bit block deinterleave (16×7 matrix) |
| `0x03059aa0` | APRS frame builder | AX.25 header + CRC + interleave + NRZI |
| `0x03059b88` | APRS RF transmit | Writes to hardware registers for TX |

The **APRS deinterleaver** (`FUN_030599d8`) uses a 112-byte stack buffer for bit matrix transposition. The function operates on 14-byte input blocks. A malformed APRS frame with unexpected length could reach this function before AX.25 length validation occurs.

### SMS / Message Storage

SMS-related UI strings confirm full messaging support:

- `"Msg Received"` @ `0x030afdd4`
- `"Message Sent"` @ `0x030afe7c`
- `"Inbox %d/%d"` @ `0x030a32e4` — format string with counters
- `"SMS Prompt"` @ `0x030ae848`
- `"SMS Format"` @ `0x030aed90`
- `"Quick Text %d/%d"` @ `0x030a3280` — format string with counters
- `"APRS Receive"` @ `0x030af1e8`
- `"APRS Info %d/%d"` @ `0x030a954c` — format string with counters
- `"GPS Info Send"` @ `0x030afdb8`

The `%d/%d` format strings suggest message indexing. If either counter originates from OTA data (e.g., a DMR packet advertising "message 3 of 5"), and the values aren't validated, integer overflow or unexpected array indexing could occur.

### IP/UDP Transport Layer

DMR SMS uses IP/UDP encapsulation. `FUN_03018cc0` builds IP headers (starting with `0x45` = IPv4, IHL=5) and UDP headers with one's-complement checksums. The payload length field at `param_1 + 0x36c` directly controls copy sizes in the data block assembler, making it a high-value target for malformed packet injection.

## 6. Codeplug Data Map

| Address | Block | Content | Record Format |
| --- | --- | --- | --- |
| `0x00C000` | 0x10 | Encryption keys | Name (null-term) + type (0x04=AES-256) + 32-byte key |
| `0x00D000` | — | Channel data (zone 1) | 48B records: name(16) + BCD freq(4+4) + mode flags |
| `0x00E000` | — | Channel data (zone 2) | Same format as zone 1 |
| `0x05F000` | — | DMR contacts | 24B records: name(16) + rsv(1) + ID(3 LE) + type(1) + flags(3) |
| `0x0C3000` | — | Radio identity | DMR ID at +0x10 (3B LE), name +0x13, callsign +0x20, owner +0x33 |

Full codeplug: 137 non-empty 4KB pages (561 KB). Extractable in \~60 seconds unauthenticated.

## 7. Firmware Binary Structure

Complete mapping of the firmware file `DM32_L01_048_20250821.bin` (860,416 bytes):

```
File Offset   Flash Address    Size     Content
───────────   ─────────────    ──────   ─────────────────────────────
0x000000      —                256 B    Header: "BFUV32-V2" + 0xFF pad + "END"
0x000100      0x03000000       536 KB   Main firmware (code + rodata)
0x083100      0x03083000       20 KB    Sparse data / padding
0x088100      0x03088000       295 KB   Data tables + IRAM source image
  └ 0x0BD868  0x030BD768       82 KB    IRAM code (→ 0x00010000 at boot)
0x0D0100      0x030D0000       8 KB     Sparse data + zero padding
```

### Memory Map (Runtime)

```
Address Range           Size     Content
──────────────────────  ───────  ──────────────────────────────
0x00000000-0x0000FFFF   64 KB   Boot ROM / vectors (not in FW binary)
0x00010000-0x00057FFF   288 KB  IRAM — .text+.data copied from flash at boot
  └ 0x00010000-0x0002F098        .text/.data (from flash 0x030BD768)
  └ 0x0004A7B0+0x783C           .bss (zeroed at boot)
  └ 0x00040D9C                  USB command dispatcher (active)
0x03000000-0x030D20FF   840 KB  Flash — main firmware image
  └ 0x0301cad4                  ISR frame handler (DMR RX)
  └ 0x0301ea6c                  Message display renderer (OVERFLOW)
  └ 0x03061bb8                  sprintf wrapper (snprintf 0xFFFFFFFF)
  └ 0x030A17B4                  USB command string table
  └ 0x030ADF54                  Menu item table (GB2312)
  └ 0x030AEE24                  Codeplug section jump table
0xC0000000-0xC00FFFFF   1 MB    Peripheral registers (SoC hardware)
  └ 0xC001xxxx                  Flash controller, UART, SPI, I2C
  └ 0xC004xxxx                  DMR baseband, RF control
  └ 0xC008xxxx                  GPIO, timers, DMA
```

### Boot Sequence

```
Power On
  │
  ├─ [SK1+PTT held?] ─── YES ──► Bootloader mode (green LED)
  │                              Accept firmware over USB-UART
  │                              No signature verification
  │                              Write directly to flash
  │
  └─ [Normal boot]
     │
     ▼
  Boot ROM (0x00000000)
     │  Initialize clocks, peripherals
     │  Copy IRAM .text from flash 0x030BD768 → IRAM 0x00010000
     │  Zero IRAM .bss at 0x0004A7B0 (0x783C bytes)
     ▼
  Main firmware entry (0x03000100)
     │  uC/OS-III RTOS init
     │  Peripheral setup (RF, LCD, keypad, USB-UART)
     │  Start task scheduler
     ▼
  Normal operation (DMR radio)
```

## 8. Firmware Update Protocol (CPS → Radio)

Firmware update protocol decoded from **live serial capture** of CPS ↔ radio traffic (2026-10-20). The actual protocol is YMODEM-1K with a custom pre-handshake—completely separate from the CPS codeplug read/write protocol. No password required; the CPS UI gates are cosmetic only.

**Note:** CPS function `FUN_0041d280` appears to implement an older W-command write protocol not used by the current CPS. The live capture reveals standard YMODEM-1K.

### Full Handshake Sequence (from capture)

```
Phase  TX (CPS → Radio)                     RX (Radio → CPS)
─────  ─────────────────────────────────     ──────────────────────────────
 1     52 ('R') — poll, retry until ACK      00 (not ready) or 06 (ACK)

 2     4D 00 00 00 01 ('M' model query)       4D 01 09 (9 bytes follow)
       06 (ACK)                               "BFUV32-V2" (9 bytes)

 3     45 00 00 00 00 ('E' erase/prepare)     06 (ACK — flash erased)

 4     31 ('1' — YMODEM CRC-16 request)     43 ('C' — CRC mode active)

 5     01 (SOH — 128B block)                 43 ('C')
       132B metadata packet:                  06 43 (ACK + ready)
         [00][FF] block 0 + complement
         [128B] filename\0 + size_ascii\0
         [2B] CRC-16/XMODEM

 6     Repeat 840×:                           [Data transfer loop]
         02 (STX — 1024B block)               43 ('C')
         1028B data packet:                   06 (ACK)
           [blk_num][0xFF-blk_num]
           [1024B firmware data]
           [2B] CRC-16/XMODEM

 7     04 (EOT — end of transmission)        48 12 (done)
```

### YMODEM-1K Data Block Format

```
Byte:   0        1          2..1025             1026..1027
       ┌────────┬──────────┬───────────────────┬────────────┐
       │blk_num │ ~blk_num │   1024B payload   │  CRC-16    │
       │ (1,2..)│(FE,FD..) │  firmware data    │  XMODEM    │
       └────────┴──────────┴───────────────────┴────────────┘

  blk_num  = sequential counter (1..255, wraps at 256)
  ~blk_num = one's complement (0xFF - blk_num)
  CRC-16   = XMODEM CRC (poly 0x1021, init 0x0000) over 1024B payload
  Preceded by STX (0x02); radio responds 'C' (0x43) then ACK (0x06)

  Firmware .bin: 256B header (BFUV32-V2 + 0xFF pad) stripped before transfer
  Flash payload: 860,160 bytes = 840 blocks × 1024B ≈ 5 min @ 115200 baud
```

### Hardcoded Factory Passwords

| Password | Purpose | CPS Address |
| --- | --- | --- |
| `374612` | Factory test mode (LCD/signal) | `0x004e6174` |
| `bfcps` | CPS configuration password | `0x004e617c` |
| `66660501` | Firmware flash authorization | `0x004e616c` |

All three passwords are hardcoded as plaintext strings in `CPS.exe` at `firmware_flash_handler` (`0x0042F7D0`). The firmware flash password `"66660501"` is model-specific (matches the radio's device info response). These passwords gate CPS UI access only—the **radio firmware accepts the PROGRAM handshake with no password verification** (see V1: CPS Password Bypass).

### Attack Scenario: Over-the-Air Persistent Compromise

```
Attacker Radio / SDR              Target DM-32UV
        │                                │
  1.    │── DMR data packet ──────────►  │  Malformed contact name
        │   (oversized field)            │  triggers stack overflow
        │                                │  (V9: snprintf 0xFFFFFFFF)
        │                                │
  2.    │                                │◄ ROP chain / shellcode executes
        │                                │  on CK803S (no NX, no ASLR)
        │                                │
  3.    │                                │◄ Shellcode writes to flash via
        │                                │  flash controller @ 0xC001xxxx
        │                                │  No signing = permanent implant
        │                                │
  4.    │                                │◄ Modified firmware persists
        │                                │  across power cycles, factory
        │                                │  resets, and CPS reprogramming
        │                                │
  5.    │◄── Exfil via DMR data ────────│  Encryption keys, GPS, audio
        │    or remote monitor ──────── │  sent back to attacker
```

**PoC tools created:**

- `dm32_reader.py` — **EEPROM reader**: full 16MB dump, key extraction, radio ID, arbitrary address read (normal mode)
- `dm32_ymodem_flash.py` — **YMODEM-1K firmware flasher** (decoded from live capture, verified CRC match)
- `dm32_sniff2.py` — PTY serial proxy/sniffer for capturing CPS ↔ radio traffic via Wine
- `dm32_firmware_patcher.py` — Firmware parse/patch/diff/build (header manipulation, IRAM extraction)

## 9. Full EEPROM Dump & Memory Map

Complete 16 MB dump of the external SPI flash/EEPROM via the CPS READ command (24-bit addressing, no boundary checks). **16,777,216 bytes**, zero read errors, 1757 seconds at 9.3 KB/s. SHA-256: `44bf9b45...df2f444e`.

**PoC:** `dm32_reader.py dump 0x000000 0x1000000 dm32_eeprom_full.bin` — reads the entire address space using the trivial `"123"` password. No authentication enforced (see V1).

### Memory Map

```
Address Range          Size       Content
──────────────────     ─────────  ──────────────────────────────────
0x000000-0x09FFFF      640 KB     Codeplug (settings, channels, zones, keys, contacts)
  └ 0x00C000                     AES-256 encryption keys (plaintext)
  └ 0x00D000-0x06A000            Channel data + local DMR contacts
  └ 0x082000-0x09FFFF            Extended config (DTMF, scan lists, zones)

0x0A0000-0x0C7FFF      160 KB     Post-codeplug system data
  └ 0x0A3000           4 KB      Configuration flags
  └ 0x0A7000           4 KB      RF calibration data (power/RSSI tables)
  └ 0x0AC000           4 KB      Boot icon (RGB565, 64×32 amber pixels)
  └ 0x0AE000-0x0B1FFF  16 KB     Reserved (zeroed — boot image slot?)
  └ 0x0BC000           4 KB      DMR config records (structured, 16B entries)
  └ 0x0BF000           4 KB      Boot strings ("WELCOME" / "DMR Radio")
  └ 0x0C3000           4 KB      Radio identity (DMR ID, callsign, owner name)
  └ 0x0C5000           4 KB      CK803S executable code (EEPROM-resident)

0x0C8000-0x1FFFFF      1.22 MB    Font/glyph bitmaps + executable code
  └ 0x0C8000-0x0C8013             Sequential index (00-13 lookup table)
  └ 0x0C8014+                     Mixed CK803S machine code & data
  └ 1,636 function prologues detected (CK803S push instructions)
  └ Entropy: 5.34 bits/byte (consistent with compiled code)

0x200000-0xE0BFFF      12.05 MB   DMR contact database (~200K records)
  └ 0x201000           Index table (16-byte entries: ID + offset + flags)
  └ 0x300000+          Contact name records (name, callsign, city, state, country)
  └ 0x400000-0xE0BFFF  Bulk name data (3 major regions at 4MB boundaries)

0xE0C000-0xFFEFFF      2.0 MB     Empty (0xFF)
0xFFF000-0xFFFFFF      4 KB       Flash end sentinel (FF 00 00 00...)
```

### Flash Usage

```
MB   0   1   2   3   4   5   6   7   8   9  10  11  12  13  14  15
    [###|###|###|###|###|###|###|###|###|###|###|###|###|###|...|...]
     ▲codeplug ▲fonts/code        ▲contact database             ▲empty
    87.5% utilized (14 / 16 MB)
```

### Key Findings

High RF Calibration Data Readable & Writable

Per-unit RF calibration data at `0x0A7000` contains power level DAC values, RSSI offset tables, and frequency compensation curves. This data is unique per radio (factory-tuned) and accessible via the same unauthenticated READ/WRITE commands as the codeplug.

- **Read risk:** Calibration values reveal hardware characteristics, manufacturing date codes, and RF fingerprinting data
- **Write risk:** Corrupting calibration data can cause out-of-spec TX power (regulatory violation), incorrect frequency offsets, or total radio malfunction requiring factory recalibration

```
0x0A7040: 144 138 135 138 138 193 182 173 160 174 235 221 250 218 210  (power DAC)
0x0A7050: 113 110 104 101 103  23  23  23  24  24  95  93  85  84  86  (RSSI offsets)
0x0A7080:  61  61  61  61  61  71  71  71  71  71                      (band markers)
```

High Executable Code in External EEPROM

**1,636 CK803S function prologues** (push register-save instructions) detected in the 0x0C5000 and 0x0C8000-0x1FFFFF regions. Entropy analysis (5.34 bits/byte) is consistent with compiled machine code, not font bitmaps.

- This code resides in the **external SPI EEPROM**, accessible via the same unauthenticated READ/WRITE commands
- If the CPU executes code from this region (XIP or copy-to-RAM), an attacker could **inject arbitrary code by writing to EEPROM addresses** using the CPS protocol
- Unlike firmware flash (write-only via YMODEM bootloader), EEPROM code is **readable and writable** in normal operating mode
- No integrity checks observed on EEPROM code regions

**Impact:** If this code is executed at runtime, persistent backdoors can be installed via USB without entering bootloader mode—just normal CPS programming mode with no password. The code persists across power cycles and firmware updates (YMODEM only reflashes internal flash, not external EEPROM).

Info Boot Image Storage Identified

The boot display configuration is at `0x0BF000`:

```
0x0BF001: "WELCOME"        Boot line 1 (UTF-8, 13 bytes max)
0x0BF00F: "DMR Radio"       Boot line 2 (UTF-8, 13 bytes max)
0x0BF01D: 01               Boot display mode (0=text, 1=image?)
```

A 64×32 RGB565 boot icon at `0x0AC000` uses an amber-on-dark palette (background `0x18C2` = RGB 24,24,16; foreground `0xE3C2` = RGB 230,121,16). The 16 KB zeroed region at `0x0AE000-0x0B1FFF` appears reserved for a larger boot image (the CPS "PowerOnPicture" tool likely writes here).

Info Complete DMR Contact Database Extracted

The 12 MB contact database (0x200000-0xE0BFFF) contains approximately 200,000 DMR user records with full PII:

- DMR ID (24-bit, little-endian)
- Callsign (up to 8 chars)
- Full name (first + last)
- City, state/province, country

```
0x300000: Philip E  (name)   KE8DRK (callsign)   Columbus, Ohio, United States
0x300060: Bennie C  (name)   KC8DEO (callsign)   Doylestown, Ohio, United States
```

This is a mirror of the public RadioID.net database, pre-loaded into every radio. Extractable in \~30 minutes via unauthenticated USB read.

### AES Key Storage Layout (confirmed from dump)

```
Address     Content
──────────  ──────────────────────────────────────────
0x00C000    Key name slot 0: "Sys 1" (32 bytes, null-padded)
0x00C020    Key name slot 1: (empty)
  ...
0x00C300    Key value record 0:
              01 4F 61 6B 4B 65 79 00          "OakKey"
              20 31 00 04 00 00 ...             slot "1", type 0x04 (AES-256)
              (key bytes: all 0x00 — empty)
0x00C320    Key value record 1:
              02 45 6E 63 72 79 70 74 20 31  "Encrypt 1"
              00 04                             type 0x04 (AES-256)
              41 42 43 44 45 46 47 48         ABCDEFGH
              4A 4B 4C 4D 4E 4F 50 51         JKLMNOPQ
              52 53 54 55 56 57 58 59         RSTUVWXY
              5A 31 32 33 34 35 36 37         Z1234567
```

## 10. Scope & Responsible Disclosure

These findings affect the **HR_C7000 DMR baseband platform** (Hualai / HYTERA OEM). The password bypass and plaintext key storage are likely architectural to the platform, not specific to the DM-32UV model. Other HR_C7000-based radios (DP570UV variants, OEM rebrands) should be assumed vulnerable until tested.

Firmware version tested: `DM32.01.L01.048` (2022-06-27). Protocol interface: USB-UART via CH340 (VID:PID `1a86:7523`).