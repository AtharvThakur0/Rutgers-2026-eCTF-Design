#!/usr/bin/env bash
set -euo pipefail

TEST_DIR="$(cd "$(dirname "$0")" && pwd)"
REGRESSION_NAME="${REGRESSION_NAME:-permission_matrix}"
# shellcheck source=scripts/regression_common.sh
source "$TEST_DIR/../scripts/regression_common.sh"

printf -v TARGET_GROUP_TEXT '%04x' "$((GID))"
MATRIX_ROOT_DIR="$LOG_DIR"
RWC_PAYLOAD_TEXT="${RWC_PAYLOAD_TEXT:-permission matrix rwc payload}"
W_ONLY_PAYLOAD_TEXT="${W_ONLY_PAYLOAD_TEXT:-permission matrix w-only payload}"

set_case_context() {
  local case_name="$1"

  LOG_DIR="$MATRIX_ROOT_DIR/$case_name"
  READBACK_DIR="$LOG_DIR/readback"
  mkdir -p "$LOG_DIR" "$READBACK_DIR"
}

assert_log_contains() {
  local stage="$1"
  local pattern="$2"
  local logfile="$LOG_DIR/${stage}.log"

  if ! python3 - "$logfile" "$pattern" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_bytes().decode("utf-8", "replace")
normalized_text = " ".join(text.split())
normalized_pattern = " ".join(sys.argv[2].split())
sys.exit(0 if normalized_pattern in normalized_text else 1)
PY
  then
    echo "ASSERT FAIL: $stage missing pattern: $pattern"
    fail_now "$stage"
  fi

  echo "ASSERT PASS: $stage contains $pattern"
}

assert_log_not_contains() {
  local stage="$1"
  local pattern="$2"
  local logfile="$LOG_DIR/${stage}.log"

  if python3 - "$logfile" "$pattern" <<'PY'
from pathlib import Path
import sys

text = Path(sys.argv[1]).read_bytes().decode("utf-8", "replace")
normalized_text = " ".join(text.split())
normalized_pattern = " ".join(sys.argv[2].split())
sys.exit(0 if normalized_pattern in normalized_text else 1)
PY
  then
    echo "ASSERT FAIL: $stage unexpectedly contained pattern: $pattern"
    fail_now "$stage"
  fi

  echo "ASSERT PASS: $stage omits $pattern"
}

expect_failure() {
  local stage="$1"
  shift

  if run_cmd_timeout "$stage" "$HOST_TIMEOUT" "$@"; then
    echo "ASSERT FAIL: $stage unexpectedly succeeded"
    fail_now "$stage"
  fi

  echo "PASS: $stage failed as expected"
}

run_rwc_case() {
  set_case_context 01_rwc
  GROUP_ARGS=(0x4321)
  PERMISSIONS="4321=RWC"
  GID="0x4321"
  PAYLOAD_TEXT="$RWC_PAYLOAD_TEXT"

  prepare_payload_file
  build_firmware
  flash_firmware
  run_list_ready
  assert_log_contains list_ready "Group ${TARGET_GROUP_TEXT}"
  run_write_test
  run_list_after
  assert_log_contains list_after "Group ${TARGET_GROUP_TEXT}"
  run_read_test
  compare_readback
}

run_r_only_case() {
  set_case_context 02_r_only
  GROUP_ARGS=(0x4321)
  PERMISSIONS="4321=R--"
  GID="0x4321"
  PAYLOAD_TEXT="$RWC_PAYLOAD_TEXT"

  prepare_payload_file
  build_firmware
  flash_firmware

  run_cmd_timeout list_r_only "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || fail_now list_r_only
  assert_log_contains list_r_only "Group ${TARGET_GROUP_TEXT}"

  run_cmd_timeout read_r_only "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" read --force "$PIN" "$SLOT" "$READBACK_DIR" || fail_now read_r_only
  compare_readback

  expect_failure write_r_only_denied \
    uvx ectf tools "$PORT" write "$PIN" "$SLOT" "$GID" "$PAYLOAD_FILE"
  assert_log_contains write_r_only_denied "Invalid permission"
}

run_w_only_case() {
  set_case_context 03_w_only
  GROUP_ARGS=(0x4321)
  PERMISSIONS="4321=-W-"
  GID="0x4321"
  PAYLOAD_TEXT="$W_ONLY_PAYLOAD_TEXT"

  prepare_payload_file
  build_firmware
  flash_firmware

  run_cmd_timeout list_w_only_hidden "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || fail_now list_w_only_hidden
  assert_log_not_contains list_w_only_hidden "Group ${TARGET_GROUP_TEXT}"

  run_cmd_timeout write_w_only "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" write "$PIN" "$SLOT" "$GID" "$PAYLOAD_FILE" || fail_now write_w_only

  expect_failure read_w_only_denied \
    uvx ectf tools "$PORT" read --force "$PIN" "$SLOT" "$READBACK_DIR"
  assert_log_contains read_w_only_denied "Invalid permission"

  run_cmd_timeout list_w_only_after "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || fail_now list_w_only_after
  assert_log_not_contains list_w_only_after "Group ${TARGET_GROUP_TEXT}"
}

run_c_only_case() {
  set_case_context 04_c_only
  GROUP_ARGS=(0x4321)
  PERMISSIONS="4321=--C"
  GID="0x4321"
  PAYLOAD_TEXT="$W_ONLY_PAYLOAD_TEXT"

  prepare_payload_file
  build_firmware
  flash_firmware

  run_cmd_timeout list_c_only_hidden "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || fail_now list_c_only_hidden
  assert_log_not_contains list_c_only_hidden "Group ${TARGET_GROUP_TEXT}"

  expect_failure write_c_only_denied \
    uvx ectf tools "$PORT" write "$PIN" "$SLOT" "$GID" "$PAYLOAD_FILE"
  assert_log_contains write_c_only_denied "Invalid permission"

  expect_failure read_c_only_denied \
    uvx ectf tools "$PORT" read --force "$PIN" "$SLOT" "$READBACK_DIR"
  assert_log_contains read_c_only_denied "Invalid permission"
}

require_port
require_openocd_scripts
print_context

run_rwc_case
run_r_only_case
run_w_only_case
run_c_only_case

echo
echo "Permission matrix regression completed. Logs: $MATRIX_ROOT_DIR"
