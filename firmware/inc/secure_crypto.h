/**
 * @file secure_crypto.h
 * @brief Secure cryptographic interface for the eCTF 2026 HSM.
 * @date 2026
 *
 * All SHA-256 and HMAC operations use sha256_raw.h (no dynamic allocation).
 * wolfSSL is used only for AES-256-GCM.
 * No ECDSA — signing uses HMAC-SHA-256 with a derived symmetric key.
 *
 * KEY HIERARCHY
 * ─────────────
 *   GLOBAL_SECRETS → K_master (32 bytes)
 *   K_group[g]   = HKDF(ikm=K_master, salt=group_id LE16, info="group_root")
 *   K_file_enc   = HKDF-Expand(K_group, "file_enc_v1")
 *   K_xfer       = HKDF-Expand(K_group, "xfer_root_v1")
 *   K_pin        = HMAC(K_master, "pin_mac_v1")
 *   seed_writer  = HKDF-Expand(K_group, "writer_sign_seed_v1")
 *   seed_recv    = HKDF-Expand(K_group, "recv_sign_seed_v1")
 */

#ifndef SECURE_CRYPTO_H
#define SECURE_CRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Constants
 * ========================================================================= */

/** Size of any HKDF-derived symmetric key (AES-256). */
#define SECURE_CRYPTO_DERIVED_KEY_SIZE       32u

/** AES-GCM authentication tag length in bytes. */
#define SECURE_CRYPTO_AES_GCM_TAG_SIZE       16u

/** AES-GCM nonce (IV) length in bytes. */
#define SECURE_CRYPTO_AES_GCM_NONCE_SIZE     12u

/** SHA-256 digest length in bytes. */
#define SECURE_CRYPTO_SHA256_DIGEST_SIZE     32u

/**
 * Maximum signature size.  With HMAC-SHA-256 replacing ECDSA the
 * signature is always 32 bytes, but we keep this constant at 72 to
 * remain ABI-compatible with callers that size buffers with it.
 */
#define SECURE_CRYPTO_ECC_SIGNATURE_MAX_SIZE 72u

/** HMAC-SHA-256 output length in bytes. */
#define SECURE_CRYPTO_HMAC_SIZE              32u

/* =========================================================================
 * Core data types
 * ========================================================================= */

/**
 * @brief Root secret derived from GLOBAL_SECRETS.
 *
 * Holds K_master (32 bytes).  Zero this struct with memset immediately
 * after use.
 */
typedef struct {
    uint8_t k_master[SECURE_CRYPTO_DERIVED_KEY_SIZE];
} secure_crypto_root_secret_t;

/**
 * @brief Container for an HMAC signing key (replaces ECC keypair).
 *
 * sign_key holds the 32-byte symmetric key used by both sign and verify.
 * Zero this struct with memset when done.
 */
typedef struct {
    uint8_t sign_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
} secure_crypto_ecc_material_t;

/* =========================================================================
 * Initialisation / key extraction
 * ========================================================================= */

/**
 * @brief Extract K_master from the raw GLOBAL_SECRETS blob.
 *
 * Binary layout produced by gen_secrets:
 *   [  0.. 64] ECC public key  (65 bytes, uncompressed P-256)
 *   [ 65.. 96] ECC private key (32 bytes)
 *   [ 97..128] K_master        (32 bytes)
 *   [129..]    group list
 */
bool secure_crypto_root_secret_from_global_secrets(
    const uint8_t *global_secrets, size_t len,
    secure_crypto_root_secret_t *out);

/* =========================================================================
 * Per-group key derivation
 * ========================================================================= */

bool secure_crypto_derive_file_enc_key(const secure_crypto_root_secret_t *root,
                                       uint16_t group_id,
                                       uint8_t *out, size_t out_len);

bool secure_crypto_derive_xfer_root_key(const secure_crypto_root_secret_t *root,
                                        uint16_t group_id,
                                        uint8_t *out, size_t out_len);

bool secure_crypto_derive_pin_mac_key(const secure_crypto_root_secret_t *root,
                                      uint8_t *out, size_t out_len);

bool secure_crypto_derive_writer_seed(const secure_crypto_root_secret_t *root,
                                      uint16_t group_id,
                                      uint8_t *out, size_t out_len);

bool secure_crypto_derive_recv_seed(const secure_crypto_root_secret_t *root,
                                    uint16_t group_id,
                                    uint8_t *out, size_t out_len);

/* =========================================================================
 * Keypair derivation (HMAC-based, symmetric)
 * ========================================================================= */

bool secure_crypto_derive_writer_keypair(
    const secure_crypto_root_secret_t *root, uint16_t group_id,
    secure_crypto_ecc_material_t *material_out);

bool secure_crypto_derive_recv_keypair(
    const secure_crypto_root_secret_t *root, uint16_t group_id,
    secure_crypto_ecc_material_t *material_out);

/* =========================================================================
 * Hash / MAC primitives
 * ========================================================================= */

bool secure_crypto_sha256(const uint8_t *message, size_t len,
                          uint8_t *digest_out, size_t digest_len);

bool secure_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                               const uint8_t *message, size_t msg_len,
                               uint8_t *mac_out, size_t mac_len);

/* =========================================================================
 * AES-256-GCM
 * ========================================================================= */

bool secure_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *ciphertext_out, uint8_t *tag_out,
                                   size_t tag_len);

bool secure_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   const uint8_t *tag, size_t tag_len,
                                   uint8_t *plaintext_out, size_t pt_out_len);

/* =========================================================================
 * Sign / verify (HMAC-SHA-256 replacing ECDSA)
 *
 * Signatures are 32-byte HMAC outputs.  sig_len_ptr is set to 32 on success.
 * sig buffers are sized with SECURE_CRYPTO_ECC_SIGNATURE_MAX_SIZE (72 bytes)
 * for compatibility; only the first 32 bytes are populated/checked.
 * ========================================================================= */

bool secure_crypto_writer_sign(const secure_crypto_root_secret_t *root,
                               uint16_t group_id,
                               const uint8_t *message, size_t msg_len,
                               uint8_t *signature, size_t *sig_len_ptr);

bool secure_crypto_writer_verify(const secure_crypto_root_secret_t *root,
                                 uint16_t group_id,
                                 const uint8_t *message, size_t msg_len,
                                 const uint8_t *signature, size_t sig_len);

bool secure_crypto_receive_proof_sign(const secure_crypto_root_secret_t *root,
                                      uint16_t group_id,
                                      const uint8_t *message, size_t msg_len,
                                      uint8_t *signature, size_t *sig_len_ptr);

bool secure_crypto_receive_proof_verify(const secure_crypto_root_secret_t *root,
                                        uint16_t group_id,
                                        const uint8_t *message, size_t msg_len,
                                        const uint8_t *signature, size_t sig_len);

#ifdef __cplusplus
}
#endif

#endif /* SECURE_CRYPTO_H */
