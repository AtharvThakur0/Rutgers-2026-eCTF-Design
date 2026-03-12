/**
 * @file security.h
 * @author Samuel Meyers
 * @brief Stub file to hold security checks
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */
#ifndef __SECURITY_H__
#define __SECURITY_H__

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>

#define MAX_PERMS  8
#define PIN_LENGTH 6
#define PIN_MAX_LEN 20

typedef enum {
    PERM_READ = 'R',
    PERM_WRITE = 'W',
    PERM_RECEIVE = 'C',
} permission_enum_t;

typedef struct {
    uint16_t group_id;
    bool read;
    bool write;
    bool receive;
} group_permission_t;

/**
 * @brief Load pin_hash and fail_count from flash.  Provisions the initial
 *        hash from HSM_PIN (secrets.h) if the page is blank (first boot).
 *        Must be called once from init() before any check_pin() call.
 *
 * @return 0 on success, -1 on error.
 */
int pin_init(void);

/** @brief Return true if the HSM is permanently locked (≥5 failed attempts). */
bool pin_is_locked(void);

/** @brief Validate a pin against the HSM's pin.
 *
 *  Constant-time comparison.  Increments the failure counter and runs a
 *  mandatory fail_delay() on every wrong attempt.  Returns false immediately
 *  (no delay) when pin_is_locked() is already true.
 *
 *  @param pin Pointer to PIN_LENGTH bytes from the command packet.
 *  @return True if the pin is correct and the HSM is not locked.
 */
bool check_pin(unsigned char *pin);

/**
 * @brief Change the stored PIN.  Verifies old_pin first (constant-time).
 *        Increments the failure counter (with delay) on a wrong old_pin.
 *        Resets the counter and writes the new hash on success.
 *
 * @param old_pin  Current PIN bytes.
 * @param old_len  Length of old_pin (PIN_LENGTH ≤ len ≤ PIN_MAX_LEN).
 * @param new_pin  New PIN bytes.
 * @param new_len  Length of new_pin (PIN_LENGTH ≤ len ≤ PIN_MAX_LEN).
 * @return 0 on success, -1 on failure.
 */
int pin_change(const uint8_t *old_pin, size_t old_len,
               const uint8_t *new_pin, size_t new_len);

/**
 * @brief Compute HMAC-SHA-256(K_pin, pin_bytes) into out_hash[32].
 *
 * Used by command handlers that need to bind an encrypted blob to the
 * current PIN without exposing the internal g_pin_hash buffer.
 *
 * @param pin     PIN bytes.
 * @param pin_len Length of pin (PIN_LENGTH ≤ len ≤ PIN_MAX_LEN).
 * @param out_hash Output buffer, must be 32 bytes.
 * @return true on success.
 */
bool get_pin_hash(const uint8_t *pin, size_t pin_len, uint8_t out_hash[32]);

/** @brief Ensure the HSM has the requested permission
 *
 *  @param group_id Group ID.
 *  @param perm Permission type.
 *
 *  @return True if the HSM has the correct permission. False if not.
*/
bool validate_permission(uint16_t group_id, permission_enum_t perm);

#endif  // __SECURITY_H__
