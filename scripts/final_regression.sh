#!/usr/bin/env bash
set -euo pipefail

"$(dirname "$0")/smoke_local.sh"
"$(dirname "$0")/checkpoint_pin.sh"
"$(dirname "$0")/checkpoint_secure_storage.sh"

echo "final_regression: local checkpoints passed"
echo "Run two-board UART1 tests separately"
