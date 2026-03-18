/*
 * stubs.c — host-build test stubs only.
 *
 * These are minimal no-op replacements for functions that belong to the
 * hardware-dependent security and crypto layers (security.c, secure_crypto.c).
 * They exist solely so that the blob-store unit tests can be compiled and
 * linked on a host machine without pulling in wolfSSL, TI SDK headers, or any
 * other embedded-only dependency.
 *
 * None of these stubs are exercised by the blob-store test suite; they satisfy
 * the linker only.  Do NOT use this file in production firmware builds.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_crypto.h"

/* --------------------------------------------------------------------------
 * security.h stubs
 * -------------------------------------------------------------------------- */

bool security_get_root_secret(secure_crypto_root_secret_t *out) {
    (void)out;
    return false;
}

bool security_generate_nonce(uint8_t *out, size_t out_len) {
    (void)out;
    (void)out_len;
    return false;
}

void security_prepare_local_file_crypto_pool(size_t transfer_live_prefix_len) {
    (void)transfer_live_prefix_len;
}

void security_secure_uart_clear_replay_cache(void) {
}

bool security_secure_uart_check_and_update_replay(
    uint32_t Nr,
    uint32_t Nt,
    uint16_t group_id,
    uint8_t op
) {
    (void)Nr;
    (void)Nt;
    (void)group_id;
    (void)op;
    return false;
}

/* --------------------------------------------------------------------------
 * secure_crypto.h stubs
 *
 * secure_design.c's wired-up stub bodies reference these functions.  The
 * bodies are never reached during blob-store tests, but the linker needs the
 * symbols present.
 * -------------------------------------------------------------------------- */

bool secure_crypto_derive_file_enc_key(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    uint8_t *out,
    size_t out_len
) {
    (void)root; (void)group_id; (void)out; (void)out_len;
    return false;
}

bool secure_crypto_derive_xfer_root_key(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    uint8_t *out,
    size_t out_len
) {
    (void)root; (void)group_id; (void)out; (void)out_len;
    return false;
}

bool secure_crypto_derive_pin_mac_key(
    const secure_crypto_root_secret_t *root,
    uint8_t *out,
    size_t out_len
) {
    (void)root; (void)out; (void)out_len;
    return false;
}

bool secure_crypto_derive_writer_seed(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    uint8_t *out,
    size_t out_len
) {
    (void)root; (void)group_id; (void)out; (void)out_len;
    return false;
}

bool secure_crypto_derive_recv_seed(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    uint8_t *out,
    size_t out_len
) {
    (void)root; (void)group_id; (void)out; (void)out_len;
    return false;
}

bool secure_crypto_sha256(
    const uint8_t *message,
    size_t message_len,
    uint8_t *digest_out,
    size_t digest_len
) {
    (void)message; (void)message_len; (void)digest_out; (void)digest_len;
    return false;
}

bool secure_crypto_aes_gcm_encrypt(
    const uint8_t *key,
    size_t key_len,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *aad,
    size_t aad_len,
    const uint8_t *plaintext,
    size_t plaintext_len,
    uint8_t *ciphertext_out,
    uint8_t *tag_out,
    size_t tag_len
) {
    (void)key; (void)key_len; (void)nonce; (void)nonce_len;
    (void)aad; (void)aad_len; (void)plaintext; (void)plaintext_len;
    (void)ciphertext_out; (void)tag_out; (void)tag_len;
    return false;
}

bool secure_crypto_writer_sign(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    const uint8_t *message,
    size_t message_len,
    uint8_t *signature,
    size_t *signature_len
) {
    (void)root; (void)group_id; (void)message; (void)message_len;
    (void)signature; (void)signature_len;
    return false;
}

bool secure_crypto_writer_verify(
    const secure_crypto_root_secret_t *root,
    uint16_t group_id,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *signature,
    size_t signature_len
) {
    (void)root; (void)group_id; (void)message; (void)message_len;
    (void)signature; (void)signature_len;
    return false;
}
