# Rutgers University — eCTF 2026 Hardware Security Module

Bare-metal C firmware for the Texas Instruments MSPM0L2228 (ARM Cortex-M0+) implementing a secure Hardware Security Module (HSM) for the 2026 MITRE eCTF. Provides authenticated file storage, access control, and cryptographically verified peer-to-peer device transfers.

---

## Architecture Overview

```text
Host (UART0) ──► Framing Engine ──► [PIN Auth | Commands (L/R/W) | Peer Xfer (UART1)]
                                          │
                                          ▼
                               Authenticated Storage
                            (256B AES-256-GCM Chunks)
                                          │
                                          ▼
                                 Atomic Commit Order
                       (Chunks ──► Tags ──► Header ──► FAT)
```

### Security Architecture
- **Zero-Heap Cryptography**: RFC 5869 HKDF, SHA-256, and HMAC-SHA-256 implemented with bounded stack usage and zero dynamic heap allocations.
- **Microsecond Symmetric Auth**: Replaces unaccelerated P-256 curves with HMAC-derived tokens, eliminating timing side-channels and denial-of-service delays.
- **Power-Loss Atomic Commits**: Write operations commit in forward dependency order ($\text{Chunks} \to \text{Tags} \to \text{Header} \to \text{FAT}$). Power interruption leaves previous slot state intact; incomplete writes are discarded on boot.
- **Flash & Hardware Hardening**:
  - **8-Byte Flash ECC Boundary Isolation**: Isolates dynamic failure counters from static credentials across 64-bit ECC programming words.
  - **Constant-Time PIN Verification**: Multi-byte PIN hash comparison uses bitwise XOR accumulation.
  - **Hardware TRNG Recovery**: Bare-metal driver handles APBC bus disconnect recovery after MCU reset.
- **Peer Transfer Security (UART1)**: 3-way challenge-response handshake with fresh nonces, 8-entry bounded replay cache, and proof-gated directory disclosure.

---

## Memory Map

| Address Range | Size | Allocation / Description |
| :--- | :--- | :--- |
| `0x0000_0000 – 0x0000_5FFF` | 24 KiB | eCTF Secure Bootloader |
| `0x0000_6000 – 0x0003_9FFF` | 208 KiB | Application Firmware (`APP1`) |
| `0x0003_A000 – 0x0003_A3FF` | 1 KiB | 24-Byte Bootloader FAT Table |
| `0x0003_A400 – 0x0003_A7FF` | 1 KiB | Slot Metadata & Group IDs |
| `0x0003_A800 – 0x0003_ABFF` | 1 KiB | PIN Hash & ECC Failure Counters |
| `0x0003_AC00 – 0x0003_DFFF` | 96 KiB | Encrypted Data Slots (8 × 12 KiB) |
| `0x2020_0000 – 0x2020_7FFF` | 32 KiB | SRAM (Stack expanded to 4096B) |

---

## Wire Protocol (UART0)

Framed as `['%' (1B) | Opcode (1B) | Length (2B, LE) | Payload (N B)]`:

| Opcode | Command | Payload | Action |
| :---: | :--- | :--- | :--- |
| **`L`** | List | `pin[6]` | Returns metadata for occupied slots |
| **`R`** | Read | `pin[6] \| slot[1]` | Decrypts and streams file to host |
| **`W`** | Write | `pin[6] \| slot[1] \| group[2] \| name[8] \| uuid[16] \| len[2] \| data[...]` | Encrypts in chunks; atomic flash commit |
| **`N`** | Listen | *(None)* | Awaits incoming UART1 peer transfer |
| **`I`** | Interrogate | `pin[6]` | Queries peer directory via HMAC proof |
| **`C`** | Receive | `pin[6] \| read_slot[1] \| write_slot[1]` | Pulls peer file over UART1 after challenge |

*Note: Diagnostic opcodes and debug prints are compiled out of release builds via `#ifdef DEBUG_BUILD`.*

---

## Build & Flash

### 1. Build Secret Tool & Generate Secrets
```bash
uv pip install -e ./ectf26_design
uv run secrets ./global.secrets 0x1234 0x4321
```

### 2. Build Application Firmware
```bash
docker build -t build-hsm ./firmware

mkdir -p build
docker run --rm \
  -e HSM_PIN=123abc \
  -e PERMISSIONS='1234=RWC:4321=R--' \
  -v "$PWD/firmware:/hsm" \
  -v "$PWD/global.secrets:/secrets/global.secrets:ro" \
  -v "$PWD/build:/out" \
  build-hsm /out
```

### 3. Flash Target Device
```bash
uvx ectf hw --port /dev/ttyACM0 reflash ./build/hsm.bin -n hsm
```

---

## Repository Structure

```text
.
├── ectf26_design/              # Host secrets generation package
├── firmware/
│   ├── Dockerfile              # TI-Clang & wolfSSL build environment
│   ├── Makefile                # Firmware compilation rules
│   ├── firmware.ld             # Linker script (0x6000 origin, 4096B stack)
│   ├── inc/                    # Headers (crypto, flash, storage, protocol)
│   └── src/                    # Source files (drivers, AES-GCM, HSM core)
├── Rutgers_eCTF_Design_Document.pdf
├── Makefile
├── LICENSE.txt
└── README.md
```
