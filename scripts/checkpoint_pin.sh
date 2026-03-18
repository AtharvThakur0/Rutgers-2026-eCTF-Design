#!/usr/bin/env bash
set -euo pipefail
source "$(dirname "$0")/test_env.sh"

mk_payloads
clean_readback

echo "[A] valid baseline roundtrip"
fresh_flash_baseline
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
tool read --force "$VALID_PIN" 0 "$READBACK_DIR"
cmp_file "$PAYLOAD_DIR/somefile.txt" "$READBACK_DIR"

echo "[B] invalid PIN timing"
read -r rc elapsed < <(measure_elapsed uvx ectf tools "$PORT" list "$INVALID_PIN")
echo "invalid PIN rc=$rc elapsed=${elapsed}s"
python3 - "$rc" "$elapsed" <<'PY'
import sys
rc = int(sys.argv[1])
elapsed = float(sys.argv[2])
if rc == 0 or elapsed < 4.8:
    raise SystemExit(1)
PY

echo "[C] no-W write denied"
fresh_flash_r_only
if tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"; then
  echo "FAIL: write unexpectedly succeeded without W"
  exit 1
fi

echo "[D] no-R read denied"
fresh_flash_rwc
tool write "$VALID_PIN" 0 "$GROUP_FULL" "$PAYLOAD_DIR/somefile.txt"
keep_flash_w_only
if tool read --force "$VALID_PIN" 0 "$READBACK_DIR/no_r"; then
  echo "FAIL: read unexpectedly succeeded without R"
  exit 1
fi

echo "PASS: checkpoint_pin"
