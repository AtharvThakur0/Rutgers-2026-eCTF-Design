#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/test_env.sh"

mk_payloads
clean_readback

echo "[A] valid secure roundtrip"
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
tool read --force "$VALID_PIN" 0 "$READBACK_DIR/good"
cmp_file "$PAYLOAD_DIR/somefile.txt" "$READBACK_DIR/good"

echo "[B] tampered ciphertext rejected"
[[ -n "$TAMPER_CIPHERTEXT_CMD" ]] || { echo "TAMPER_CIPHERTEXT_CMD not set"; exit 1; }
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
bash -lc "$TAMPER_CIPHERTEXT_CMD"
if tool read --force "$VALID_PIN" 0 "$READBACK_DIR/tamper_cipher"; then
  echo "FAIL: tampered ciphertext read succeeded"
  exit 1
fi

echo "[C] tampered metadata rejected"
[[ -n "$TAMPER_METADATA_CMD" ]] || { echo "TAMPER_METADATA_CMD not set"; exit 1; }
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
bash -lc "$TAMPER_METADATA_CMD"
if tool read --force "$VALID_PIN" 0 "$READBACK_DIR/tamper_meta"; then
  echo "FAIL: tampered metadata read succeeded"
  exit 1
fi

echo "[D] bad signature rejected"
[[ -n "$TAMPER_SIGNATURE_CMD" ]] || { echo "TAMPER_SIGNATURE_CMD not set"; exit 1; }
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
bash -lc "$TAMPER_SIGNATURE_CMD"
if tool read --force "$VALID_PIN" 0 "$READBACK_DIR/tamper_sig"; then
  echo "FAIL: tampered signature read succeeded"
  exit 1
fi

echo "[E] partial write recovery"
[[ -n "$PARTIAL_WRITE_CMD" ]] || { echo "PARTIAL_WRITE_CMD not set"; exit 1; }
[[ -n "$RESET_CMD" ]] || { echo "RESET_CMD not set"; exit 1; }
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
bash -lc "$PARTIAL_WRITE_CMD"
bash -lc "$RESET_CMD"
sleep 2
tool read --force "$VALID_PIN" 0 "$READBACK_DIR/recovery"
cmp_file "$PAYLOAD_DIR/somefile.txt" "$READBACK_DIR/recovery"

echo "PASS: checkpoint_secure_storage"
