#!/usr/bin/env bash
set -euo pipefail

PORT="${PORT:-/dev/cu.usbmodemML2200011}"
VALID_PIN="${VALID_PIN:-123abc}"
INVALID_PIN="${INVALID_PIN:-ffffff}"

GROUP_FULL="${GROUP_FULL:-0x4321}"
GROUP_ALT="${GROUP_ALT:-0x1111}"

ROOT_DIR="${ROOT_DIR:-$HOME/dev/ess_main/ess_baseline}"
ART_DIR="${ART_DIR:-$ROOT_DIR/.checkpoint_artifacts}"
PAYLOAD_DIR="$ART_DIR/payloads"
READBACK_DIR="$ART_DIR/readback"
LOG_DIR="$ART_DIR/logs"

FLASH_BASELINE_FRESH_CMD="${FLASH_BASELINE_FRESH_CMD:-cd $ROOT_DIR && make flash}"
FLASH_R_ONLY_FRESH_CMD="${FLASH_R_ONLY_FRESH_CMD:-}"
FLASH_W_ONLY_FRESH_CMD="${FLASH_W_ONLY_FRESH_CMD:-}"
FLASH_C_ONLY_FRESH_CMD="${FLASH_C_ONLY_FRESH_CMD:-}"
FLASH_RWC_FRESH_CMD="${FLASH_RWC_FRESH_CMD:-}"
FLASH_W_ONLY_KEEP_CMD="${FLASH_W_ONLY_KEEP_CMD:-}"
RESET_CMD="${RESET_CMD:-}"

TAMPER_CIPHERTEXT_CMD="${TAMPER_CIPHERTEXT_CMD:-}"
TAMPER_METADATA_CMD="${TAMPER_METADATA_CMD:-}"
TAMPER_SIGNATURE_CMD="${TAMPER_SIGNATURE_CMD:-}"
PARTIAL_WRITE_CMD="${PARTIAL_WRITE_CMD:-}"

mkdir -p "$PAYLOAD_DIR" "$READBACK_DIR" "$LOG_DIR"

tool() {
  uvx ectf tools "$PORT" "$@"
}

fresh_flash_baseline() {
  bash -lc "$FLASH_BASELINE_FRESH_CMD"
  sleep 2
}

fresh_flash_r_only() {
  [[ -n "$FLASH_R_ONLY_FRESH_CMD" ]] || { echo "FLASH_R_ONLY_FRESH_CMD not set"; return 1; }
  bash -lc "$FLASH_R_ONLY_FRESH_CMD"
  sleep 2
}

fresh_flash_w_only() {
  [[ -n "$FLASH_W_ONLY_FRESH_CMD" ]] || { echo "FLASH_W_ONLY_FRESH_CMD not set"; return 1; }
  bash -lc "$FLASH_W_ONLY_FRESH_CMD"
  sleep 2
}

fresh_flash_c_only() {
  [[ -n "$FLASH_C_ONLY_FRESH_CMD" ]] || { echo "FLASH_C_ONLY_FRESH_CMD not set"; return 1; }
  bash -lc "$FLASH_C_ONLY_FRESH_CMD"
  sleep 2
}

fresh_flash_rwc() {
  [[ -n "$FLASH_RWC_FRESH_CMD" ]] || { echo "FLASH_RWC_FRESH_CMD not set"; return 1; }
  bash -lc "$FLASH_RWC_FRESH_CMD"
  sleep 2
}

keep_flash_w_only() {
  [[ -n "$FLASH_W_ONLY_KEEP_CMD" ]] || { echo "FLASH_W_ONLY_KEEP_CMD not set"; return 1; }
  bash -lc "$FLASH_W_ONLY_KEEP_CMD"
  sleep 2
}

mk_payloads() {
  printf 'hello baseline\n' > "$PAYLOAD_DIR/somefile.txt"
  printf 'overwrite-a\n' > "$PAYLOAD_DIR/overwrite_a.txt"
  printf 'overwrite-b-new-contents\n' > "$PAYLOAD_DIR/overwrite_b.txt"
  : > "$PAYLOAD_DIR/empty.bin"

  python3 - <<'PY'
from pathlib import Path
root = Path("'$PAYLOAD_DIR'")
(root / "ascii_0_127.bin").write_bytes(bytes(range(128)))
(root / "max_8192.bin").write_bytes(bytes([i % 251 for i in range(8192)]))
(root / ("a" * 31)).write_text("max name 31 bytes\n", encoding="utf-8")
PY
}

clean_readback() {
  rm -rf "$READBACK_DIR"
  mkdir -p "$READBACK_DIR"
}

cmp_file() {
  local src="$1"
  local dst_dir="$2"
  cmp -s "$src" "$dst_dir/$(basename "$src")"
}

measure_elapsed() {
  python3 - "$@" <<'PY'
import subprocess, sys, time
cmd = sys.argv[1:]
t0 = time.monotonic()
p = subprocess.run(cmd)
dt = time.monotonic() - t0
print(f"{p.returncode} {dt:.3f}")
PY
}
