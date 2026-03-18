#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

cc -Wall -Wextra -Werror -std=c11 \
  -I"/Applications/ti/mspm0_sdk_2_09_00_01/source" \
  -I"$BASE_DIR/firmware/inc" \
  "$BASE_DIR/tests/secure_blob_store_test.c" \
  "$BASE_DIR/tests/stubs.c" \
  "$BASE_DIR/firmware/src/secure_design.c" \
  "$BASE_DIR/firmware/src/secure_blob_store.c" \
  -o /tmp/secure_blob_store_test

/tmp/secure_blob_store_test
