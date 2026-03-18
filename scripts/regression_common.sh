#!/usr/bin/env bash
set -euo pipefail

REGRESSION_COMMON_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BASE_DIR="$(cd "$REGRESSION_COMMON_DIR/.." && pwd)"
ROOT_DIR="${ROOT_DIR:-$(cd "$BASE_DIR/.." && pwd)}"
FIRMWARE_DIR="$BASE_DIR/firmware"
BUILD_DIR="$BASE_DIR/build"
LOG_PARENT="$BASE_DIR/logs"
STAMP="${STAMP:-$(date +%Y%m%d-%H%M%S)}"
SECRETS_FILE="$BASE_DIR/global.secrets"
BUILD_IMAGE="${BUILD_IMAGE:-build-hsm-baseline}"
PIN="${PIN:-123abc}"
PERMISSIONS="${PERMISSIONS:-1234=R--:4321=RWC}"
GROUP_ARGS=(${GROUP_ARGS:-0x1234 0x4321})
SLOT="${SLOT:-0}"
GID="${GID:-0x4321}"
PAYLOAD_FILE="${PAYLOAD_FILE:-$BASE_DIR/tiny_baseline.txt}"
PAYLOAD_TEXT="${PAYLOAD_TEXT:-baseline tiny payload}"
INVALID_PIN="${INVALID_PIN:-654321}"
INVALID_PIN_MIN_SECONDS="${INVALID_PIN_MIN_SECONDS:-4.8}"
LEDGER_ADDR="${LEDGER_ADDR:-0x20206fa0}"
OPENOCD="${OPENOCD:-openocd}"
OPENOCD_PREFIX="${OPENOCD_PREFIX:-$(brew --prefix open-ocd 2>/dev/null || true)}"
OPENOCD_SCRIPTS="${OPENOCD_SCRIPTS:-$OPENOCD_PREFIX/share/openocd/scripts}"
FLASH_TIMEOUT="${FLASH_TIMEOUT:-300}"
HOST_TIMEOUT="${HOST_TIMEOUT:-40}"
PORT_WAIT_TIMEOUT="${PORT_WAIT_TIMEOUT:-20}"
PORT_WAIT_DELAY="${PORT_WAIT_DELAY:-1}"
REGRESSION_NAME="${REGRESSION_NAME:-regression}"
LOG_DIR="${LOG_DIR:-$LOG_PARENT/$STAMP-$REGRESSION_NAME}"
READBACK_DIR="${READBACK_DIR:-$LOG_DIR/readback}"
LOCAL_ECTF_DESIGN_DIR="$BASE_DIR/ectf26_design"
PARENT_ECTF_DESIGN_SCRIPT="$ROOT_DIR/ectf26_design/src/gen_secrets.py"

detect_port() {
  local first
  first="$(ls /dev/cu.usbmodem* 2>/dev/null | head -n 1 || true)"
  printf '%s' "$first"
}

PORT="${PORT:-$(detect_port)}"
HW_PORT="${HW_PORT:-${PORT/\/dev\/cu./\/dev\/tty.}}"

mkdir -p "$BUILD_DIR" "$LOG_DIR" "$READBACK_DIR"

run_cmd() {
  local stage="$1"
  shift
  local logfile="$LOG_DIR/${stage}.log"

  echo
  echo "==> [$stage]"
  printf 'CMD:'
  printf ' %q' "$@"
  printf '\n'

  {
    printf 'CMD:'
    printf ' %q' "$@"
    printf '\n'
    "$@"
  } > >(tee "$logfile") 2>&1
  local rc=$?

  echo "RC: $rc"
  echo "$rc" > "$LOG_DIR/${stage}.rc"
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $stage"
  else
    echo "FAIL: $stage"
  fi

  return "$rc"
}

run_cmd_timeout() {
  local stage="$1"
  local timeout_s="$2"
  shift 2
  local logfile="$LOG_DIR/${stage}.log"
  local cmd_pid=""
  local timer_pid=""
  local rc=0

  echo
  echo "==> [$stage]"
  printf 'CMD:'
  printf ' %q' "$@"
  printf '\n'
  echo "TIMEOUT: ${timeout_s}s"

  (
    printf 'CMD:'
    printf ' %q' "$@"
    printf '\n'
    echo "TIMEOUT: ${timeout_s}s"
    "$@" &
    cmd_pid=$!
    (
      sleep "$timeout_s"
      if kill -0 "$cmd_pid" 2>/dev/null; then
        echo "TIMEOUT after ${timeout_s}s"
        kill "$cmd_pid" 2>/dev/null || true
      fi
    ) &
    timer_pid=$!
    wait "$cmd_pid"
    rc=$?
    kill "$timer_pid" 2>/dev/null || true
    wait "$timer_pid" 2>/dev/null || true
    exit "$rc"
  ) > >(tee "$logfile") 2>&1
  rc=$?

  echo "RC: $rc"
  echo "$rc" > "$LOG_DIR/${stage}.rc"
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $stage"
  elif [[ $rc -eq 143 || $rc -eq 124 ]]; then
    echo "FAIL: $stage timed out"
  else
    echo "FAIL: $stage"
  fi

  return "$rc"
}

dump_port_owners() {
  local logfile="$LOG_DIR/port_owners.log"
  {
    echo "PORT=$PORT"
    echo "HW_PORT=$HW_PORT"
    lsof "$PORT" "$HW_PORT" 2>&1 || true
  } | tee "$logfile"
}

dump_ledger() {
  local logfile="$LOG_DIR/ledger_dump.log"
  "$OPENOCD" \
    -s "$OPENOCD_SCRIPTS" \
    -f interface/xds110.cfg \
    -f target/ti/mspm0.cfg \
    -c "init; halt; mdw $LEDGER_ADDR 21; reg pc; reg lr; reg sp; shutdown" \
    >"$logfile" 2>&1 || true
  echo "Ledger dump saved to $logfile"
}

fail_now() {
  local stage="$1"
  echo "ABORT: $stage"
  dump_port_owners
  exit 1
}

require_port() {
  if [[ -z "$PORT" ]]; then
    echo "No /dev/cu.usbmodem* control port found."
    exit 1
  fi
}

require_openocd_scripts() {
  if [[ -z "$OPENOCD_SCRIPTS" || ! -d "$OPENOCD_SCRIPTS" ]]; then
    echo "OpenOCD scripts not found. Set OPENOCD_SCRIPTS=/path/to/openocd/scripts"
    exit 1
  fi
}

print_context() {
  echo "BASE_DIR=$BASE_DIR"
  echo "ROOT_DIR=$ROOT_DIR"
  echo "PORT=$PORT"
  echo "HW_PORT=$HW_PORT"
  echo "LOG_DIR=$LOG_DIR"
}

prepare_payload_file() {
  printf '%s\n' "$PAYLOAD_TEXT" > "$PAYLOAD_FILE"
}

wait_for_port_ready() {
  local stage="${1:-wait_for_device_ready}"
  local timeout_s="${2:-$PORT_WAIT_TIMEOUT}"
  local deadline=$((SECONDS + timeout_s))
  local logfile="$LOG_DIR/${stage}.log"
  local rc=0

  echo
  echo "==> [$stage]"
  echo "Waiting up to ${timeout_s}s for $PORT"
  (
    echo "PORT=$PORT"
    echo "HW_PORT=$HW_PORT"
    echo "timeout=${timeout_s}s"
    while (( SECONDS < deadline )); do
      if [[ -e "$PORT" ]]; then
        echo "port_ready=yes"
        exit 0
      fi
      sleep "$PORT_WAIT_DELAY"
    done
    echo "port_ready=no"
    exit 1
  ) > >(tee "$logfile") 2>&1
  rc=$?

  echo "RC: $rc"
  echo "$rc" > "$LOG_DIR/${stage}.rc"
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $stage"
  else
    echo "FAIL: $stage"
  fi

  return "$rc"
}

build_firmware() {
  if [[ -d "$LOCAL_ECTF_DESIGN_DIR" ]]; then
    run_cmd gen_secrets \
      uvx --with-editable "$LOCAL_ECTF_DESIGN_DIR" --from ectf26_design \
      secrets --force "$SECRETS_FILE" \
      "${GROUP_ARGS[@]}" || fail_now gen_secrets
  elif [[ -x "$ROOT_DIR/.venv/bin/python" && -f "$PARENT_ECTF_DESIGN_SCRIPT" ]]; then
    run_cmd gen_secrets \
      "$ROOT_DIR/.venv/bin/python" \
      "$PARENT_ECTF_DESIGN_SCRIPT" \
      -f "$SECRETS_FILE" \
      "${GROUP_ARGS[@]}" || fail_now gen_secrets
  else
    echo "No usable secrets generator found."
    fail_now gen_secrets
  fi

  run_cmd docker_build \
    docker build -t "$BUILD_IMAGE" "$FIRMWARE_DIR" || fail_now docker_build

  run_cmd firmware_build \
    docker run --rm \
    -v "$FIRMWARE_DIR:/hsm" \
    -v "$SECRETS_FILE:/secrets/global.secrets:ro" \
    -v "$BUILD_DIR:/out" \
    -e "HSM_PIN=$PIN" \
    -e "PERMISSIONS=$PERMISSIONS" \
    "$BUILD_IMAGE" || fail_now firmware_build
}

flash_firmware() {
  run_cmd_timeout flash "$FLASH_TIMEOUT" \
    "$OPENOCD" \
    -s "$OPENOCD_SCRIPTS" \
    -f interface/xds110.cfg \
    -f target/ti/mspm0.cfg \
    -c "init; reset halt; program $BUILD_DIR/hsm.elf verify reset exit" || fail_now flash

  wait_for_port_ready wait_for_device_ready "$PORT_WAIT_TIMEOUT" || fail_now wait_for_device_ready
}

run_list_ready() {
  run_cmd_timeout list_ready "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || {
      dump_ledger
      fail_now list_ready
    }
}

run_write_test() {
  run_cmd_timeout write "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" write "$PIN" "$SLOT" "$GID" "$PAYLOAD_FILE" || {
      dump_ledger
      fail_now write
    }
}

run_list_after() {
  run_cmd_timeout list_after "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" list "$PIN" || {
      dump_ledger
      fail_now list_after
    }
}

run_read_test() {
  run_cmd_timeout read "$HOST_TIMEOUT" \
    uvx ectf tools "$PORT" read --force "$PIN" "$SLOT" "$READBACK_DIR" || {
      dump_ledger
      fail_now read
    }
}

compare_readback() {
  run_cmd compare \
    bash -lc "cmp \"$PAYLOAD_FILE\" \"$READBACK_DIR\"/*" || fail_now compare
}

measure_invalid_pin_timing() {
  local stage="${1:-invalid_pin_list}"
  local logfile="$LOG_DIR/${stage}.log"
  local result_file="$LOG_DIR/${stage}.txt"

  echo
  echo "==> [$stage]"
  echo "Measuring invalid PIN latency for uvx ectf tools $PORT list $INVALID_PIN"

  python3 - "$HOST_TIMEOUT" "$PORT" "$INVALID_PIN" "$logfile" "$result_file" "$INVALID_PIN_MIN_SECONDS" <<'PY'
import json
import subprocess
import sys
import time
from pathlib import Path

timeout_s = int(sys.argv[1])
port = sys.argv[2]
pin = sys.argv[3]
log_path = Path(sys.argv[4])
result_path = Path(sys.argv[5])
min_seconds = float(sys.argv[6])
cmd = ["uvx", "ectf", "tools", port, "list", pin]
start = time.monotonic()
timed_out = False

try:
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_s)
    rc = proc.returncode
    stdout = proc.stdout or ""
    stderr = proc.stderr or ""
except subprocess.TimeoutExpired as exc:
    timed_out = True
    rc = 124
    stdout = exc.stdout or ""
    stderr = exc.stderr or ""

elapsed = time.monotonic() - start
result = {
    "command": cmd,
    "elapsed_seconds": round(elapsed, 6),
    "min_seconds": min_seconds,
    "returncode": rc,
    "timed_out": timed_out,
    "meets_min_seconds": elapsed >= min_seconds,
}

log_lines = [
    "CMD: " + " ".join(cmd),
    f"elapsed_seconds={elapsed:.6f}",
    f"returncode={rc}",
    f"timed_out={str(timed_out).lower()}",
    "--- stdout ---",
    stdout,
    "--- stderr ---",
    stderr,
]
log_path.write_text("\n".join(log_lines) + "\n")
result_path.write_text(json.dumps(result, indent=2) + "\n")
print(f"elapsed_seconds={elapsed:.3f}")
print(f"min_seconds={min_seconds:.3f}")
print(f"returncode={rc}")
print(f"timed_out={str(timed_out).lower()}")
if rc == 0:
    sys.exit(1)
if elapsed < min_seconds:
    sys.exit(2)
sys.exit(0)
PY
  local rc=$?

  echo "$rc" > "$LOG_DIR/${stage}.rc"
  if [[ $rc -eq 0 ]]; then
    echo "PASS: $stage"
  else
    echo "FAIL: $stage"
  fi

  return "$rc"
}
