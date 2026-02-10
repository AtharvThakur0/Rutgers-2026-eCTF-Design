/**
 * @file sha256_raw.h
 * @date 2026
 *
 * No dynamic allocation.  All state lives in caller-supplied structs or
 * in local stack variables.  Safe on Cortex-M0+ with no heap.
 */

#ifndef SHA256_RAW_H
#define SHA256_RAW_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* =========================================================================
 * Constants
 * ========================================================================= */

#define SHA256_RAW_DIGEST_SIZE  32u   /**< SHA-256 output length in bytes. */
#define HMAC_SHA256_RAW_SIZE    32u   /**< HMAC-SHA-256 output length in bytes. */

/* =========================================================================
 * Context types
 * ========================================================================= */

/**
 * @brief SHA-256 streaming context.  All fields are internal.
 *
 * Stack cost: 108 bytes.
 */
typedef struct {
    uint32_t state[8];   /**< Running hash state (H0..H7). */
    uint64_t length;     /**< Total bits processed in complete 512-bit blocks. */
    uint32_t curlen;     /**< Bytes buffered in @p buf (0–63). */
    uint8_t  buf[64];    /**< Partial block buffer. */
} sha256_raw_ctx_t;

/**
 * @brief HMAC-SHA-256 streaming context.
 *
 * Holds the pre-initialized inner and outer SHA-256 contexts.
 * Stack cost: 216 bytes.
 */
typedef struct {
    sha256_raw_ctx_t inner; /**< Inner hash: H(ipad || message). */
    sha256_raw_ctx_t outer; /**< Outer hash: H(opad || inner_hash). */
} hmac_sha256_raw_ctx_t;

/* =========================================================================
 * SHA-256 streaming API
 * ========================================================================= */

/** @brief Initialise a SHA-256 context. */
void sha256_raw_ctx_init(sha256_raw_ctx_t *ctx);

/** @brief Feed @p len bytes of @p data into an open SHA-256 context. */
void sha256_raw_ctx_update(sha256_raw_ctx_t *ctx, const uint8_t *data, size_t len);

/**
 * @brief Finalise the SHA-256 hash and write 32 bytes to @p digest.
 *
 * The context is invalid after this call; re-initialise before reuse.
 */
void sha256_raw_ctx_final(sha256_raw_ctx_t *ctx, uint8_t digest[SHA256_RAW_DIGEST_SIZE]);

/* =========================================================================
 * HMAC-SHA-256 streaming API
 * ========================================================================= */

/**
 * @brief Initialise an HMAC-SHA-256 context with the given key.
 *
 * @param key      HMAC key.  If @p key_len > 64, the key is pre-hashed.
 * @param key_len  Key length in bytes.
 */
void hmac_sha256_raw_init(hmac_sha256_raw_ctx_t *ctx,
                          const uint8_t *key, size_t key_len);

/** @brief Feed @p len bytes of @p data into an open HMAC-SHA-256 context. */
void hmac_sha256_raw_update(hmac_sha256_raw_ctx_t *ctx,
                             const uint8_t *data, size_t len);

/**
 * @brief Finalise HMAC-SHA-256 and write 32 bytes to @p mac.
 *
 * The context is invalid after this call; re-initialise before reuse.
 */
void hmac_sha256_raw_final(hmac_sha256_raw_ctx_t *ctx,
                            uint8_t mac[HMAC_SHA256_RAW_SIZE]);

/* =========================================================================
 * One-shot helpers
 * ========================================================================= */

/**
 * @brief One-shot SHA-256 hash.
 *
 * @param msg    Input data.
 * @param len    Input length in bytes.
 * @param digest Output buffer (32 bytes).
 */
void sha256_raw(const uint8_t *msg, size_t len,
                uint8_t digest[SHA256_RAW_DIGEST_SIZE]);

/**
 * @brief One-shot HMAC-SHA-256.
 *
 * @param key      HMAC key.
 * @param key_len  Key length in bytes.
 * @param msg      Message to authenticate.
 * @param msg_len  Message length in bytes.
 * @param mac      Output buffer (32 bytes).
 */
void hmac_sha256_raw(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t mac[HMAC_SHA256_RAW_SIZE]);

/* =========================================================================
 * ========================================================================= */

/**
 *
 * @param salt      Salt value (may be NULL if @p salt_len == 0, in which
 *                  case a 32-byte zero salt is used per RFC 5869).
 * @param salt_len  Length of @p salt in bytes.
 * @param ikm       Input key material.
 * @param ikm_len   Length of @p ikm in bytes.
 * @param prk       Output pseudorandom key (32 bytes).
 */
                          const uint8_t *ikm,  size_t ikm_len,
                          uint8_t prk[SHA256_RAW_DIGEST_SIZE]);

/**
 *
 * @p out_len must be ≤ 255 * SHA256_RAW_DIGEST_SIZE (8160 bytes).
 *
 * @param prk_len   Length of @p prk in bytes (typically 32).
 * @param info      Context/application-specific string.
 * @param info_len  Length of @p info in bytes.
 * @param out       Output buffer.
 * @param out_len   Requested output length in bytes.
 */
                         const uint8_t *info, size_t info_len,
                         uint8_t *out, size_t out_len);

#ifdef __cplusplus
}
#endif

#endif /* SHA256_RAW_H */
