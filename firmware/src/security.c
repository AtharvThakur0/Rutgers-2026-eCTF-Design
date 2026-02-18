/**
 * @file security.c
 * @brief PIN-based access control for the eCTF 2026 HSM.
 *
 * Flash layout (one 1024-byte page at PIN_STATE_FLASH_ADDR = 0x3A800):
 *
 *   Offset   Size  Field
 *   ------   ----  -----
 *      0      32   pin_hash  — HMAC-SHA256(K_pin, PIN_bytes)
 *     32       4   fail_count — consecutive failures (LE32)
 *     36       4   _reserved — completes the 8-byte ECC word at offset 32
 *     40    984   (unused, erased = 0xFF)
 *
 * fail_count lives at offset 32, which is ECC word 4 (bytes 32–39).
 * pin_hash occupies ECC words 0–3 (bytes 0–31).  The two fields are
 * never in the same 8-byte ECC word, satisfying the ECC-write constraint.
 *
 * Lockout: none — fail_count is tracked but never triggers a lockout.
 */

#include "security.h"
#include "host_messaging.h"
#include "secrets.h"
#include "secure_crypto.h"
#include "secure_design.h"
#include "simple_flash.h"

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

/* =========================================================================
 * Constants
 * ========================================================================= */

/* Flash address of the PIN-state page (within the APP2 region 0x3A400–0x3FFFF).
 */
#define PIN_STATE_FLASH_ADDR 0x3A800u

/* Byte offsets within the PIN-state page. */
#define PIN_HASH_OFFSET 0u
#define FAIL_COUNT_OFFSET                                                      \
  32u /* 8-byte aligned; separate ECC word from pin_hash */

#define PIN_STATE_PAGE_SIZE 1024u

/* Minimum PIN length; maximum is PIN_MAX_LEN from security.h. */
#define PIN_MIN_LEN PIN_LENGTH /* 6 */

/* =========================================================================
 * RAM state
 * ========================================================================= */

static uint8_t g_pin_hash[32];
static uint32_t g_fail_count;
static bool g_initialized = false;

/* =========================================================================
 * Helpers
 * ========================================================================= */

/*
 * Mandatory delay after every failed PIN attempt.
 *
 * Calibrated to ≈ 5 s on MSPM0 running at 32 MHz.  Each loop iteration
 * touches a volatile variable which forces a load + store + branch.
 * Empirically measured at ~21 cycles/iter on this build → 7 700 000 × 21
 * / 32 000 000 ≈ 5.05 s.
 */
static void fail_delay(void) {
  for (volatile uint32_t i = 0u; i < 12500000UL; i++) {
#if !defined(HOST_TEST) && (defined(__MSPM0_HAS_WWDT__) || defined(WWDT0))
    if (i % 1000000u == 0u) {
      DL_WWDT_restart(WWDT0);
    }
#endif
  }
}

/*
 * Derive K_pin from the root secret, then compute
 *   HMAC-SHA256(K_pin, pin_bytes) → out_hash[32]
 */
static bool compute_pin_hash(const uint8_t *pin, size_t pin_len,
                             uint8_t out_hash[32]) {
  secure_crypto_root_secret_t root;
  uint8_t k_pin[SECURE_CRYPTO_DERIVED_KEY_SIZE];
  bool ok;

  if (!security_get_root_secret(&root)) {
    return false;
  }
  ok = secure_crypto_derive_pin_mac_key(&root, k_pin, sizeof(k_pin));
  memset(&root, 0, sizeof(root));
  if (!ok) {
    memset(k_pin, 0, sizeof(k_pin));
    return false;
  }

  ok = secure_crypto_hmac_sha256(k_pin, sizeof(k_pin), pin, pin_len, out_hash,
                                 32u);
  memset(k_pin, 0, sizeof(k_pin));
  return ok;
}

/* Flush g_pin_hash and g_fail_count to flash. */
static int write_pin_state(void) {
  uint8_t page[PIN_STATE_PAGE_SIZE];
  memset(page, 0xFF, sizeof(page));

  memcpy(page + PIN_HASH_OFFSET, g_pin_hash, 32u);

  page[FAIL_COUNT_OFFSET + 0u] = (uint8_t)(g_fail_count & 0xFFu);
  page[FAIL_COUNT_OFFSET + 1u] = (uint8_t)((g_fail_count >> 8) & 0xFFu);
  page[FAIL_COUNT_OFFSET + 2u] = (uint8_t)((g_fail_count >> 16) & 0xFFu);
  page[FAIL_COUNT_OFFSET + 3u] = (uint8_t)((g_fail_count >> 24) & 0xFFu);

  if (flash_simple_erase_page(PIN_STATE_FLASH_ADDR) != 0) {
    return -1;
  }
  if (flash_simple_write(PIN_STATE_FLASH_ADDR, page, PIN_STATE_PAGE_SIZE) !=
      0) {
    return -1;
  }
  return 0;
}

/* Populate g_pin_hash and g_fail_count from flash. */
static void load_pin_state(void) {
  uint8_t page[PIN_STATE_PAGE_SIZE];
  flash_simple_read(PIN_STATE_FLASH_ADDR, page, PIN_STATE_PAGE_SIZE);

  memcpy(g_pin_hash, page + PIN_HASH_OFFSET, 32u);

  g_fail_count = (uint32_t)page[FAIL_COUNT_OFFSET + 0u] |
                 ((uint32_t)page[FAIL_COUNT_OFFSET + 1u] << 8) |
                 ((uint32_t)page[FAIL_COUNT_OFFSET + 2u] << 16) |
                 ((uint32_t)page[FAIL_COUNT_OFFSET + 3u] << 24);

  /* Erased flash reads as 0xFFFFFFFF — treat as zero failures. */
  if (g_fail_count == 0xFFFFFFFFu) {
    g_fail_count = 0u;
  }
}

/* True when the PIN-state page has never been written (all 0xFF). */
static bool pin_hash_is_blank(void) {
  for (size_t i = 0u; i < 32u; i++) {
    if (g_pin_hash[i] != 0xFFu) {
      return false;
    }
  }
  return true;
}

/* =========================================================================
 * Public API
 * ========================================================================= */

int pin_init(void) {
  load_pin_state();

  if (pin_hash_is_blank()) {
    /*
     * First boot after reflash: provision the PIN hash from the
     * compile-time HSM_PIN constant baked into secrets.h.
     */
    const uint8_t *provisioned = (const uint8_t *)HSM_PIN;
    /* strnlen is absent from the TI ARM runtime; scan manually. */
    size_t plen = 0u;
    while (plen < (size_t)PIN_MAX_LEN && provisioned[plen] != 0u) {
      plen++;
    }
    if (plen < (size_t)PIN_MIN_LEN) {
      return -1; /* Provisioning error: HSM_PIN too short */
    }
    if (!compute_pin_hash(provisioned, plen, g_pin_hash)) {
      return -1;
    }
    g_fail_count = 0u;
    if (write_pin_state() != 0) {
      return -1;
    }
  }

  g_initialized = true;
  return 0;
}

bool pin_is_locked(void) { return false; }

bool check_pin(unsigned char *pin) {
  uint8_t candidate_hash[32];
  uint8_t diff = 0u;

  if (!g_initialized || pin == NULL) {
    return false;
  }

  if (!compute_pin_hash(pin, PIN_LENGTH, candidate_hash)) {
    return false;
  }

  /*
   * Constant-time comparison: accumulate XOR differences into a single
   * byte.  A branch-based early-exit (memcmp) would create a timing
   * oracle proportional to the number of matching leading bytes.
   */
  for (size_t i = 0u; i < 32u; i++) {
    diff |= candidate_hash[i] ^ g_pin_hash[i];
  }
  memset(candidate_hash, 0, sizeof(candidate_hash));

  if (diff == 0u) {
    /* Correct PIN — clear failure counter. */
    if (g_fail_count != 0u) {
      g_fail_count = 0u;
      write_pin_state();
    }
    return true;
  }

  /* Wrong PIN — record failure, enforce delay, then return. */
  g_fail_count++;
  write_pin_state();
  fail_delay();
  return false;
}

int pin_change(const uint8_t *old_pin, size_t old_len, const uint8_t *new_pin,
               size_t new_len) {
  uint8_t candidate_hash[32];
  uint8_t diff = 0u;

  if (!g_initialized || old_pin == NULL || new_pin == NULL) {
    return -1;
  }
  if (old_len < (size_t)PIN_MIN_LEN || old_len > (size_t)PIN_MAX_LEN) {
    return -1;
  }
  if (new_len < (size_t)PIN_MIN_LEN || new_len > (size_t)PIN_MAX_LEN) {
    return -1;
  }
  if (!compute_pin_hash(old_pin, old_len, candidate_hash)) {
    return -1;
  }

  for (size_t i = 0u; i < 32u; i++) {
    diff |= candidate_hash[i] ^ g_pin_hash[i];
  }
  memset(candidate_hash, 0, sizeof(candidate_hash));

  if (diff != 0u) {
    g_fail_count++;
    write_pin_state();
    fail_delay();
    return -1;
  }

  /* Old PIN verified — derive and store the new hash. */
  if (!compute_pin_hash(new_pin, new_len, g_pin_hash)) {
    return -1;
  }
  g_fail_count = 0u;
  return write_pin_state();
}

bool get_pin_hash(const uint8_t *pin, size_t pin_len, uint8_t out_hash[32]) {
  if (pin == NULL || out_hash == NULL) return false;
  if (pin_len < (size_t)PIN_MIN_LEN || pin_len > (size_t)PIN_MAX_LEN) return false;
  return compute_pin_hash(pin, pin_len, out_hash);
}

bool validate_permission(uint16_t group_id, permission_enum_t perm) {
  char output_buf[128] = {0};

  sprintf(output_buf, "Checking %c permissions for group: %hx\n", perm,
          group_id);
  print_debug(output_buf);

  // TODO: the reference design doesn't implement *ANY* security.
  // This function currently does nothing. Your team should add the
  // appropriate security checks here to implement the security
  // requirements.
  return true;
}
