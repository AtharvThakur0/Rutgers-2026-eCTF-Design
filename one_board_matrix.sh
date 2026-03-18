#!/usr/bin/env bash
set -uo pipefail

# ============================================================
# One-board test matrix for MSPM0L2228 eCTF firmware
#
# Save as: scripts/one_board_matrix.sh
# Run with: chmod +x scripts/one_board_matrix.sh
#           ./scripts/one_board_matrix.sh
#
# You MUST set the flash commands below for your repo.
# Fresh flash commands should erase/reinitialize storage.
# Keep-data flash commands should update firmware WITHOUT wiping file storage.
#
# Required minimum:
#   FLASH_BASELINE_FRESH_CMD
#
# Strongly recommended:
#   FLASH_R_ONLY_FRESH_CMD
#   FLASH_W_ONLY_FRESH_CMD
#   FLASH_C_ONLY_FRESH_CMD
#   FLASH_RWC_FRESH_CMD
#   FLASH_W_ONLY_KEEP_CMD or FLASH_C_ONLY_KEEP_CMD
#   RESET_CMD
#
# Optional smoke hooks:
#   LISTEN_CMD
#   INTERROGATE_NO_NEIGHBOR_CMD
#   RECEIVE_NO_NEIGHBOR_CMD
#
# Optional secure-design tamper hooks:
#   TAMPER_CIPHERTEXT_CMD
#   TAMPER_METADATA_CMD
#   TAMPER_SIGNATURE_CMD
#   PARTIAL_WRITE_CMD
#
# Example env setup:
#
# export PORT=/dev/cu.usbmodemML2200011
# export VALID_PIN=123abc
# export INVALID_PIN=ffffff
#
# export FLASH_BASELINE_FRESH_CMD='cd ~/dev/ess_main/ess_baseline && make flash'
# export FLASH_RWC_FRESH_CMD='cd ~/dev/ess_main/ess_rwc && make flash'
# export FLASH_R_ONLY_FRESH_CMD='cd ~/dev/ess_main/ess_r_only && make flash'
# export FLASH_W_ONLY_FRESH_CMD='cd ~/dev/ess_main/ess_w_only && make flash'
# export FLASH_C_ONLY_FRESH_CMD='cd ~/dev/ess_main/ess_c_only && make flash'
#
# # Non-destructive reflash used for "read without R" after data already exists
# export FLASH_W_ONLY_KEEP_CMD='cd ~/dev/ess_main/ess_w_only && make flash_no_erase'
#
# # Optional board reset without erasing file storage
# export RESET_CMD='openocd -f interface/xds110.cfg -f target/ti/mspm0.cfg -c "init; reset run; shutdown"'
#
# # Optional one-board smoke hooks
# export LISTEN_CMD='uvx ectf tools /dev/cu.usbmodemML2200011 listen 123abc'
# export INTERROGATE_NO_NEIGHBOR_CMD='uvx ectf tools /dev/cu.usbmodemML2200011 interrogate 123abc'
# export RECEIVE_NO_NEIGHBOR_CMD='uvx ectf tools /dev/cu.usbmodemML2200011 receive 123abc 0'
#
# # Optional tamper hooks
# export TAMPER_CIPHERTEXT_CMD='cd ~/dev/ess_main/ess_secure && ./scripts/tamper_blob.sh ciphertext'
# export TAMPER_METADATA_CMD='cd ~/dev/ess_main/ess_secure && ./scripts/tamper_blob.sh metadata'
# export TAMPER_SIGNATURE_CMD='cd ~/dev/ess_main/ess_secure && ./scripts/tamper_blob.sh signature'
# export PARTIAL_WRITE_CMD='cd ~/dev/ess_main/ess_secure && ./scripts/sim_partial_write.sh'
# ============================================================

PORT="${PORT:-/dev/cu.usbmodemML2200011}"
VALID_PIN="${VALID_PIN:-123abc}"
INVALID_PIN="${INVALID_PIN:-ffffff}"

READY_WAIT_SEC="${READY_WAIT_SEC:-2}"
LISTEN_TIMEOUT_SEC="${LISTEN_TIMEOUT_SEC:-4}"
NO_NEIGHBOR_TIMEOUT_SEC="${NO_NEIGHBOR_TIMEOUT_SEC:-5}"
INVALID_PIN_MIN_SEC="${INVALID_PIN_MIN_SEC:-4.8}"

# Group IDs used by the tests
GROUP_FULL="${GROUP_FULL:-0x4321}"
GROUP_ALT="${GROUP_ALT:-0x1111}"

# For read-without-R tests, flash to this profile after data already exists
NO_R_PROFILE="${NO_R_PROFILE:-w_only}"

# Slot used by partial-write hook if you simulate an incomplete object there
PARTIAL_SLOT="${PARTIAL_SLOT:-1}"

ARTIFACT_DIR="${ARTIFACT_DIR:-$(pwd)/.one_board_test_artifacts}"
PAYLOAD_DIR="${ARTIFACT_DIR}/payloads"
READBACK_DIR="${ARTIFACT_DIR}/readbacks"
LOG_DIR="${ARTIFACT_DIR}/logs"

mkdir -p "$PAYLOAD_DIR" "$READBACK_DIR" "$LOG_DIR"

declare -A RESULT_STATUS
declare -A RESULT_NOTE
RESULT_ORDER=()
FAILED=0

log()  { printf '[INFO] %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
err()  { printf '[ERR ] %s\n' "$*" >&2; }

record_result() {
  local name="$1" status="$2" note="${3:-}"
  RESULT_ORDER+=("$name")
  RESULT_STATUS["$name"]="$status"
  RESULT_NOTE["$name"]="$note"
  [[ "$status" == "FAIL" ]] && FAILED=1
}

pass() { record_result "$1" "PASS" "${2:-}"; }
fail() { record_result "$1" "FAIL" "${2:-}"; }
skip() { record_result "$1" "SKIP" "${2:-}"; }

tool() {
  uvx ectf tools "$PORT" "$@"
}

run_capture() {
  local log_file="$1"
  shift
  "$@" >"$log_file" 2>&1
}

run_shell_capture() {
  local log_file="$1"
  local cmd="$2"
  bash -lc "$cmd" >"$log_file" 2>&1
}

run_shell_timeout() {
  local timeout_sec="$1"
  local log_file="$2"
  local cmd="$3"
  python3 - "$timeout_sec" "$log_file" "$cmd" <<'PY'
import subprocess, sys
timeout_sec = float(sys.argv[1])
log_file = sys.argv[2]
cmd = sys.argv[3]
try:
    cp = subprocess.run(["bash", "-lc", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=timeout_sec)
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(cp.stdout)
    sys.exit(cp.returncode)
except subprocess.TimeoutExpired as e:
    out = e.stdout or ""
    if isinstance(out, bytes):
        out = out.decode()
    with open(log_file, "w", encoding="utf-8") as f:
        f.write(out)
        f.write(f"\n[TIMEOUT after {timeout_sec:.1f}s]\n")
    sys.exit(124)
PY
}

measure_cmd_elapsed() {
  local log_file="$1"
  shift
  local t0 t1 rc elapsed
  t0="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
  "$@" >"$log_file" 2>&1
  rc=$?
  t1="$(python3 - <<'PY'
import time
print(time.monotonic())
PY
)"
  elapsed="$(python3 - "$t0" "$t1" <<'PY'
import sys
print(f"{float(sys.argv[2]) - float(sys.argv[1]):.3f}")
PY
)"
  printf '%s %s\n' "$rc" "$elapsed"
}

float_ge() {
  python3 - "$1" "$2" <<'PY'
import sys
x = float(sys.argv[1]); y = float(sys.argv[2])
sys.exit(0 if x >= y else 1)
PY
}

payload_path() {
  printf '%s/%s\n' "$PAYLOAD_DIR" "$1"
}

readback_path() {
  printf '%s/%s\n' "$READBACK_DIR" "$1"
}

ensure_payloads() {
  log "Generating payload files under $PAYLOAD_DIR"

  printf 'hello baseline\n' > "$(payload_path somefile.txt)"
  printf 'overwrite-a\n' > "$(payload_path overwrite_a.txt)"
  printf 'overwrite-b-new-contents\n' > "$(payload_path overwrite_b.txt)"
  : > "$(payload_path empty.bin)"

  python3 - "$(payload_path ascii_0_127.bin)" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_bytes(bytes(range(128)))
PY

  python3 - "$(payload_path max_8192.bin)" <<'PY'
import sys, pathlib
p = pathlib.Path(sys.argv[1])
p.write_bytes(bytes([i % 251 for i in range(8192)]))
PY

  local i
  for i in 0 1 2 3 4 5 6 7; do
    printf 'slot-%s-payload\n' "$i" > "$(payload_path "slot_${i}.txt")"
  done

  mkdir -p "$(payload_path dup_a_dir)" "$(payload_path dup_b_dir)"
  printf 'duplicate-name-a\n' > "$(payload_path dup_a_dir/dup.txt)"
  printf 'duplicate-name-b\n' > "$(payload_path dup_b_dir/dup.txt)"

  python3 - "$PAYLOAD_DIR" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
name31 = "a" * 31
(root / name31).write_text("max name 31 bytes\n", encoding="utf-8")
PY
}

profile_cmd_var_name() {
  local profile="$1"
  local mode="$2"
  local upper_profile="${profile^^}"
  local upper_mode="${mode^^}"
  printf 'FLASH_%s_%s_CMD' "$upper_profile" "$upper_mode"
}

profile_cmd_exists() {
  local var_name
  var_name="$(profile_cmd_var_name "$1" "$2")"
  [[ -n "${!var_name:-}" ]]
}

flash_profile() {
  local profile="$1"
  local mode="$2"
  local var_name cmd log_file
  var_name="$(profile_cmd_var_name "$profile" "$mode")"
  cmd="${!var_name:-}"
  log_file="${LOG_DIR}/flash_${profile}_${mode}.log"

  if [[ -z "$cmd" ]]; then
    err "Missing ${var_name}"
    return 2
  fi

  log "Flashing profile=${profile} mode=${mode}"
  if ! run_shell_capture "$log_file" "$cmd"; then
    err "Flash failed: $profile $mode. See $log_file"
    return 1
  fi

  sleep "$READY_WAIT_SEC"
  return 0
}

cmp_readback() {
  local original="$1"
  local read_dir="$2"
  local expected_file="${read_dir}/$(basename "$original")"
  cmp -s "$original" "$expected_file"
}

roundtrip_slot() {
  local tag="$1"
  local slot="$2"
  local gid="$3"
  local src="$4"

  local rdir
  rdir="$(readback_path "$tag")"
  rm -rf "$rdir"
  mkdir -p "$rdir"

  run_capture "${LOG_DIR}/${tag}_write.log" tool write "$VALID_PIN" "$slot" "$gid" "$src" || return 1
  run_capture "${LOG_DIR}/${tag}_list.log"  tool list "$VALID_PIN" || return 1
  run_capture "${LOG_DIR}/${tag}_read.log"  tool read --force "$VALID_PIN" "$slot" "$rdir" || return 1
  cmp_readback "$src" "$rdir"
}

expect_write_fail() {
  local tag="$1"
  local slot="$2"
  local gid="$3"
  local src="$4"
  local log_file="${LOG_DIR}/${tag}.log"
  tool write "$VALID_PIN" "$slot" "$gid" "$src" >"$log_file" 2>&1
  local rc=$?
  [[ $rc -ne 0 ]]
}

expect_read_fail() {
  local tag="$1"
  local slot="$2"
  local outdir
  outdir="$(readback_path "$tag")"
  rm -rf "$outdir"
  mkdir -p "$outdir"
  local log_file="${LOG_DIR}/${tag}.log"
  tool read --force "$VALID_PIN" "$slot" "$outdir" >"$log_file" 2>&1
  local rc=$?
  [[ $rc -ne 0 ]]
}

test_00_list_empty() {
  local name="00_list_empty"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if run_capture "${LOG_DIR}/${name}.log" tool list "$VALID_PIN"; then
    pass "$name" "list succeeded on fresh device"
  else
    fail "$name" "list failed on fresh device"
  fi
}

test_01_small_roundtrip() {
  local name="01_small_roundtrip"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if roundtrip_slot "$name" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    pass "$name" "small file write/read matched"
  else
    fail "$name" "small roundtrip failed"
  fi
}

test_02_overwrite_same_slot() {
  local name="02_overwrite_same_slot"
  local rdir
  rdir="$(readback_path "$name")"
  rm -rf "$rdir"
  mkdir -p "$rdir"

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write_a.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path overwrite_a.txt)"; then
    fail "$name" "initial write failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write_b.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path overwrite_b.txt)"; then
    fail "$name" "overwrite write failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_read.log" tool read --force "$VALID_PIN" 0 "$rdir"; then
    fail "$name" "read after overwrite failed"
    return
  fi

  if cmp_readback "$(payload_path overwrite_b.txt)" "$rdir"; then
    pass "$name" "overwrite preserved newest contents"
  else
    fail "$name" "readback did not match overwrite payload"
  fi
}

test_03_fill_all_8_slots() {
  local name="03_fill_all_8_slots"
  local i rdir

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  for i in 0 1 2 3 4 5 6 7; do
    if ! run_capture "${LOG_DIR}/${name}_write_${i}.log" tool write "$VALID_PIN" "$i" "$GROUP_FULL" "$(payload_path "slot_${i}.txt")"; then
      fail "$name" "write failed at slot $i"
      return
    fi
  done

  if ! run_capture "${LOG_DIR}/${name}_list.log" tool list "$VALID_PIN"; then
    fail "$name" "list failed after filling slots"
    return
  fi

  for i in 0 1 2 3 4 5 6 7; do
    rdir="$(readback_path "${name}_slot_${i}")"
    rm -rf "$rdir"
    mkdir -p "$rdir"
    if ! run_capture "${LOG_DIR}/${name}_read_${i}.log" tool read --force "$VALID_PIN" "$i" "$rdir"; then
      fail "$name" "read failed at slot $i"
      return
    fi
    if ! cmp_readback "$(payload_path "slot_${i}.txt")" "$rdir"; then
      fail "$name" "content mismatch at slot $i"
      return
    fi
  done

  pass "$name" "all 8 slots wrote and read correctly"
}

test_04_max_filename_31() {
  local name="04_max_filename_31"
  local f
  f="${PAYLOAD_DIR}/$(python3 - <<'PY'
print("a" * 31)
PY
)"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if roundtrip_slot "$name" 0 "$GROUP_FULL" "$f"; then
    pass "$name" "31-byte filename roundtrip passed"
  else
    fail "$name" "31-byte filename roundtrip failed"
  fi
}

test_05_zero_byte_file() {
  local name="05_zero_byte_file"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if roundtrip_slot "$name" 0 "$GROUP_FULL" "$(payload_path empty.bin)"; then
    pass "$name" "zero-byte file roundtrip passed"
  else
    fail "$name" "zero-byte file roundtrip failed"
  fi
}

test_06_ascii_0_127() {
  local name="06_ascii_0_127"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if roundtrip_slot "$name" 0 "$GROUP_FULL" "$(payload_path ascii_0_127.bin)"; then
    pass "$name" "ASCII 0..127 roundtrip passed"
  else
    fail "$name" "ASCII 0..127 roundtrip failed"
  fi
}

test_07_max_size_8192() {
  local name="07_max_size_8192"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if roundtrip_slot "$name" 0 "$GROUP_FULL" "$(payload_path max_8192.bin)"; then
    pass "$name" "8192-byte roundtrip passed"
  else
    fail "$name" "8192-byte roundtrip failed"
  fi
}

test_08_invalid_slot_rejected() {
  local name="08_invalid_slot_rejected"
  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  local log_file="${LOG_DIR}/${name}.log"
  tool write "$VALID_PIN" 8 "$GROUP_FULL" "$(payload_path somefile.txt)" >"$log_file" 2>&1
  local rc=$?
  if [[ $rc -ne 0 ]]; then
    pass "$name" "slot 8 correctly rejected"
  else
    fail "$name" "slot 8 unexpectedly accepted"
  fi
}

test_09_duplicate_filename_different_slots() {
  local name="09_duplicate_filename_different_slots"
  local rdir0 rdir1

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write_0.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path dup_a_dir/dup.txt)"; then
    fail "$name" "write slot 0 failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write_1.log" tool write "$VALID_PIN" 1 "$GROUP_FULL" "$(payload_path dup_b_dir/dup.txt)"; then
    fail "$name" "write slot 1 failed"
    return
  fi

  rdir0="$(readback_path "${name}_0")"
  rdir1="$(readback_path "${name}_1")"
  rm -rf "$rdir0" "$rdir1"
  mkdir -p "$rdir0" "$rdir1"

  if ! run_capture "${LOG_DIR}/${name}_read_0.log" tool read --force "$VALID_PIN" 0 "$rdir0"; then
    fail "$name" "read slot 0 failed"
    return
  fi
  if ! run_capture "${LOG_DIR}/${name}_read_1.log" tool read --force "$VALID_PIN" 1 "$rdir1"; then
    fail "$name" "read slot 1 failed"
    return
  fi

  if cmp_readback "$(payload_path dup_a_dir/dup.txt)" "$rdir0" && cmp_readback "$(payload_path dup_b_dir/dup.txt)" "$rdir1"; then
    pass "$name" "duplicate basenames across slots handled"
  else
    fail "$name" "duplicate basename roundtrip mismatch"
  fi
}

test_10_invalid_pin_timing() {
  local name="10_invalid_pin_timing"
  local rc elapsed note

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  # Create valid content so invalid read has a real slot target.
  if ! run_capture "${LOG_DIR}/${name}_prep_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep write failed"
    return
  fi

  read -r rc elapsed < <(measure_cmd_elapsed "${LOG_DIR}/${name}_list.log" uvx ectf tools "$PORT" list "$INVALID_PIN")
  if [[ $rc -eq 0 ]] || ! float_ge "$elapsed" "$INVALID_PIN_MIN_SEC"; then
    fail "$name" "invalid list PIN rc=$rc elapsed=${elapsed}s"
    return
  fi

  read -r rc elapsed < <(measure_cmd_elapsed "${LOG_DIR}/${name}_read.log" uvx ectf tools "$PORT" read --force "$INVALID_PIN" 0 "$(readback_path "${name}_invalid_read")")
  if [[ $rc -eq 0 ]] || ! float_ge "$elapsed" "$INVALID_PIN_MIN_SEC"; then
    fail "$name" "invalid read PIN rc=$rc elapsed=${elapsed}s"
    return
  fi

  read -r rc elapsed < <(measure_cmd_elapsed "${LOG_DIR}/${name}_write.log" uvx ectf tools "$PORT" write "$INVALID_PIN" 1 "$GROUP_FULL" "$(payload_path somefile.txt)")
  if [[ $rc -eq 0 ]] || ! float_ge "$elapsed" "$INVALID_PIN_MIN_SEC"; then
    fail "$name" "invalid write PIN rc=$rc elapsed=${elapsed}s"
    return
  fi

  note="invalid list/read/write all failed with >= ${INVALID_PIN_MIN_SEC}s path"
  pass "$name" "$note"
}

test_11_read_without_R() {
  local name="11_read_without_R"
  local keep_mode="keep"

  if ! profile_cmd_exists rwc fresh; then
    skip "$name" "FLASH_RWC_FRESH_CMD not set"
    return
  fi

  if ! profile_cmd_exists "$NO_R_PROFILE" "$keep_mode"; then
    skip "$name" "FLASH_${NO_R_PROFILE^^}_KEEP_CMD not set"
    return
  fi

  if ! flash_profile rwc fresh; then
    fail "$name" "RWC fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_prep_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep write under RWC failed"
    return
  fi

  if ! flash_profile "$NO_R_PROFILE" keep; then
    fail "$name" "keep-data flash to ${NO_R_PROFILE} failed"
    return
  fi

  if expect_read_fail "$name" 0; then
    pass "$name" "read denied without R permission"
  else
    fail "$name" "read unexpectedly succeeded without R permission"
  fi
}

test_12_write_without_W() {
  local name="12_write_without_W"

  if ! profile_cmd_exists r_only fresh; then
    skip "$name" "FLASH_R_ONLY_FRESH_CMD not set"
    return
  fi

  if ! flash_profile r_only fresh; then
    fail "$name" "R-only fresh flash failed"
    return
  fi

  if expect_write_fail "$name" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    pass "$name" "write denied without W permission"
  else
    fail "$name" "write unexpectedly succeeded without W permission"
  fi
}

test_13_c_only_local_gate() {
  local name="13_c_only_local_gate"

  if ! profile_cmd_exists c_only fresh; then
    skip "$name" "FLASH_C_ONLY_FRESH_CMD not set"
    return
  fi

  if ! flash_profile c_only fresh; then
    fail "$name" "C-only fresh flash failed"
    return
  fi

  if ! expect_write_fail "${name}_write" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "write unexpectedly succeeded under C-only profile"
    return
  fi

  if ! expect_read_fail "${name}_read" 0; then
    fail "$name" "read unexpectedly succeeded under C-only profile"
    return
  fi

  pass "$name" "C-only profile correctly blocks local read/write"
}

test_14_cold_boot_persistence() {
  local name="14_cold_boot_persistence"
  local rdir

  if [[ -z "${RESET_CMD:-}" ]]; then
    skip "$name" "RESET_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "write before reset failed"
    return
  fi

  if ! run_shell_capture "${LOG_DIR}/${name}_reset.log" "$RESET_CMD"; then
    fail "$name" "reset command failed"
    return
  fi

  sleep "$READY_WAIT_SEC"

  if ! run_capture "${LOG_DIR}/${name}_list.log" tool list "$VALID_PIN"; then
    fail "$name" "list failed after reset"
    return
  fi

  rdir="$(readback_path "$name")"
  rm -rf "$rdir"
  mkdir -p "$rdir"

  if ! run_capture "${LOG_DIR}/${name}_read.log" tool read --force "$VALID_PIN" 0 "$rdir"; then
    fail "$name" "read failed after reset"
    return
  fi

  if cmp_readback "$(payload_path somefile.txt)" "$rdir"; then
    pass "$name" "data persisted across reset"
  else
    fail "$name" "readback mismatch after reset"
  fi
}

test_15_listen_smoke() {
  local name="15_listen_smoke"
  local rc

  if [[ -z "${LISTEN_CMD:-}" ]]; then
    skip "$name" "LISTEN_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  run_shell_timeout "$LISTEN_TIMEOUT_SEC" "${LOG_DIR}/${name}.log" "$LISTEN_CMD"
  rc=$?

  # On one board, a clean return or a clean timeout is acceptable as smoke.
  if [[ $rc -eq 0 || $rc -eq 124 ]]; then
    pass "$name" "listen smoke completed with rc=$rc"
  else
    fail "$name" "listen smoke failed rc=$rc"
  fi
}

test_16_interrogate_no_neighbor() {
  local name="16_interrogate_no_neighbor"
  local rc

  if [[ -z "${INTERROGATE_NO_NEIGHBOR_CMD:-}" ]]; then
    skip "$name" "INTERROGATE_NO_NEIGHBOR_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  run_shell_timeout "$NO_NEIGHBOR_TIMEOUT_SEC" "${LOG_DIR}/${name}.log" "$INTERROGATE_NO_NEIGHBOR_CMD"
  rc=$?

  # This should not succeed with one board. Failure or timeout is acceptable.
  if [[ $rc -ne 0 ]]; then
    pass "$name" "interrogate failed cleanly without neighbor rc=$rc"
  else
    fail "$name" "interrogate unexpectedly succeeded without neighbor"
  fi
}

test_17_receive_no_neighbor() {
  local name="17_receive_no_neighbor"
  local rc

  if [[ -z "${RECEIVE_NO_NEIGHBOR_CMD:-}" ]]; then
    skip "$name" "RECEIVE_NO_NEIGHBOR_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  run_shell_timeout "$NO_NEIGHBOR_TIMEOUT_SEC" "${LOG_DIR}/${name}.log" "$RECEIVE_NO_NEIGHBOR_CMD"
  rc=$?

  if [[ $rc -ne 0 ]]; then
    pass "$name" "receive failed cleanly without neighbor rc=$rc"
  else
    fail "$name" "receive unexpectedly succeeded without neighbor"
  fi
}

test_18_tamper_ciphertext() {
  local name="18_tamper_ciphertext"
  if [[ -z "${TAMPER_CIPHERTEXT_CMD:-}" ]]; then
    skip "$name" "TAMPER_CIPHERTEXT_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep write failed"
    return
  fi

  if ! run_shell_capture "${LOG_DIR}/${name}_tamper.log" "$TAMPER_CIPHERTEXT_CMD"; then
    fail "$name" "ciphertext tamper hook failed"
    return
  fi

  if expect_read_fail "$name" 0; then
    pass "$name" "tampered ciphertext correctly rejected"
  else
    fail "$name" "tampered ciphertext unexpectedly read successfully"
  fi
}

test_19_tamper_metadata() {
  local name="19_tamper_metadata"
  if [[ -z "${TAMPER_METADATA_CMD:-}" ]]; then
    skip "$name" "TAMPER_METADATA_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep write failed"
    return
  fi

  if ! run_shell_capture "${LOG_DIR}/${name}_tamper.log" "$TAMPER_METADATA_CMD"; then
    fail "$name" "metadata tamper hook failed"
    return
  fi

  if expect_read_fail "$name" 0; then
    pass "$name" "tampered metadata correctly rejected"
  else
    fail "$name" "tampered metadata unexpectedly read successfully"
  fi
}

test_20_tamper_signature() {
  local name="20_tamper_signature"
  if [[ -z "${TAMPER_SIGNATURE_CMD:-}" ]]; then
    skip "$name" "TAMPER_SIGNATURE_CMD not set"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  if ! run_capture "${LOG_DIR}/${name}_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep write failed"
    return
  fi

  if ! run_shell_capture "${LOG_DIR}/${name}_tamper.log" "$TAMPER_SIGNATURE_CMD"; then
    fail "$name" "signature tamper hook failed"
    return
  fi

  if expect_read_fail "$name" 0; then
    pass "$name" "bad signature correctly rejected"
  else
    fail "$name" "bad signature unexpectedly read successfully"
  fi
}

test_21_partial_write_recovery() {
  local name="21_partial_write_recovery"
  local rdir

  if [[ -z "${PARTIAL_WRITE_CMD:-}" ]]; then
    skip "$name" "PARTIAL_WRITE_CMD not set"
    return
  fi

  if [[ -z "${RESET_CMD:-}" ]]; then
    skip "$name" "RESET_CMD not set for partial-write recovery"
    return
  fi

  if ! flash_profile baseline fresh; then
    fail "$name" "baseline fresh flash failed"
    return
  fi

  # Keep one known-good file alive at slot 0.
  if ! run_capture "${LOG_DIR}/${name}_good_write.log" tool write "$VALID_PIN" 0 "$GROUP_FULL" "$(payload_path somefile.txt)"; then
    fail "$name" "prep good write failed"
    return
  fi

  # Hook should simulate an incomplete object for PARTIAL_SLOT.
  if ! run_shell_capture "${LOG_DIR}/${name}_partial_hook.log" "$PARTIAL_WRITE_CMD"; then
    fail "$name" "partial-write hook failed"
    return
  fi

  if ! run_shell_capture "${LOG_DIR}/${name}_reset.log" "$RESET_CMD"; then
    fail "$name" "reset command failed"
    return
  fi

  sleep "$READY_WAIT_SEC"

  # Known-good file must still be readable.
  rdir="$(readback_path "${name}_slot0")"
  rm -rf "$rdir"
  mkdir -p "$rdir"

  if ! run_capture "${LOG_DIR}/${name}_read_good.log" tool read --force "$VALID_PIN" 0 "$rdir"; then
    fail "$name" "known-good file unreadable after recovery"
    return
  fi

  if ! cmp_readback "$(payload_path somefile.txt)" "$rdir"; then
    fail "$name" "known-good file corrupted after recovery"
    return
  fi

  # Optional: incomplete object slot should fail to read.
  if expect_read_fail "${name}_partial_slot" "$PARTIAL_SLOT"; then
    pass "$name" "partial write ignored; good data survived"
  else
    fail "$name" "partial slot unexpectedly readable"
  fi
}

print_summary() {
  printf '\n============================================================\n'
  printf 'ONE-BOARD TEST SUMMARY\n'
  printf '============================================================\n'
  printf '%-32s %-6s %s\n' "TEST" "STATUS" "NOTE"
  printf '%-32s %-6s %s\n' "----" "------" "----"

  local name
  for name in "${RESULT_ORDER[@]}"; do
    printf '%-32s %-6s %s\n' \
      "$name" \
      "${RESULT_STATUS[$name]}" \
      "${RESULT_NOTE[$name]}"
  done

  printf '\nLogs:      %s\n' "$LOG_DIR"
  printf 'Payloads:  %s\n' "$PAYLOAD_DIR"
  printf 'Readbacks: %s\n' "$READBACK_DIR"
  printf '\n'

  if [[ $FAILED -ne 0 ]]; then
    printf 'FINAL: FAIL\n'
    return 1
  else
    printf 'FINAL: PASS/SKIP ONLY\n'
    return 0
  fi
}

main() {
  if [[ -z "${FLASH_BASELINE_FRESH_CMD:-}" ]]; then
    err "FLASH_BASELINE_FRESH_CMD is required"
    exit 2
  fi

  ensure_payloads

  test_00_list_empty
  test_01_small_roundtrip
  test_02_overwrite_same_slot
  test_03_fill_all_8_slots
  test_04_max_filename_31
  test_05_zero_byte_file
  test_06_ascii_0_127
  test_07_max_size_8192
  test_08_invalid_slot_rejected
  test_09_duplicate_filename_different_slots
  test_10_invalid_pin_timing
  test_11_read_without_R
  test_12_write_without_W
  test_13_c_only_local_gate
  test_14_cold_boot_persistence
  test_15_listen_smoke
  test_16_interrogate_no_neighbor
  test_17_receive_no_neighbor
  test_18_tamper_ciphertext
  test_19_tamper_metadata
  test_20_tamper_signature
  test_21_partial_write_recovery

  print_summary
}

main "$@"
