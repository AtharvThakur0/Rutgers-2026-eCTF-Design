#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REGRESSION_NAME="${REGRESSION_NAME:-invalid_pin_timing}"
# shellcheck source=scripts/regression_common.sh
source "$SCRIPT_DIR/regression_common.sh"

require_port
print_context
wait_for_port_ready wait_for_device_ready "$PORT_WAIT_TIMEOUT" || fail_now wait_for_device_ready
run_list_ready
measure_invalid_pin_timing

echo
echo "Invalid PIN timing captured. Logs: $LOG_DIR"
