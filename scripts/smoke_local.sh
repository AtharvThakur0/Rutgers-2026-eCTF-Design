#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REGRESSION_NAME="${REGRESSION_NAME:-smoke_local}"
# shellcheck source=scripts/regression_common.sh
source "$SCRIPT_DIR/regression_common.sh"

require_port
require_openocd_scripts
print_context
prepare_payload_file
build_firmware
flash_firmware
run_list_ready
run_write_test
run_list_after
run_read_test
compare_readback

echo
echo "Smoke regression completed. Logs: $LOG_DIR"
