#!/usr/bin/env bash
set -euo pipefail

BASE_DIR="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_IMAGE="${BUILD_IMAGE:-build-hsm-baseline}"

docker run --rm \
  --entrypoint bash \
  -v "$BASE_DIR:/workspace" \
  "$BUILD_IMAGE" \
  -lc '
set -euo pipefail
cc -Wall -Wextra -Werror -std=c11 \
  -Wno-error=cpp \
  -D_GNU_SOURCE \
  -I/workspace/firmware/inc \
  -I/workspace/firmware \
  -I/workspace/tests \
  -I/opt/wolfssl \
  -include strings.h \
  -DWOLFSSL_USER_SETTINGS \
  -DXMALLOC_USER \
  -DNO_WOLFSSL_DIR \
  /workspace/tests/secure_crypto_test.c \
  /workspace/firmware/src/secure_design.c \
  /workspace/firmware/src/secure_crypto.c \
  /opt/wolfssl/wolfcrypt/src/aes.c \
  /opt/wolfssl/wolfcrypt/src/asn.c \
  /opt/wolfssl/wolfcrypt/src/ecc.c \
  /opt/wolfssl/wolfcrypt/src/hash.c \
  /opt/wolfssl/wolfcrypt/src/hmac.c \
  /opt/wolfssl/wolfcrypt/src/integer.c \
  /opt/wolfssl/wolfcrypt/src/memory.c \
  /opt/wolfssl/wolfcrypt/src/misc.c \
  /opt/wolfssl/wolfcrypt/src/random.c \
  /opt/wolfssl/wolfcrypt/src/sha256.c \
  /opt/wolfssl/wolfcrypt/src/sp_int.c \
  /opt/wolfssl/wolfcrypt/src/wolfmath.c \
  -o /tmp/secure_crypto_test
/tmp/secure_crypto_test
'
