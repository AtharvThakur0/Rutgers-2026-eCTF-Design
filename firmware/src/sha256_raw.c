/**
 * @file sha256_raw.c
 * @brief Self-contained SHA-256, HMAC-SHA-256, and HKDF (RFC 5869).
 * @date 2026
 *
 * No dynamic allocation.  The one-shot helpers and HKDF implementation use
 * fixed static scratch buffers so callers do not pay large stack costs on
 * Cortex-M0+.  This implementation is therefore not re-entrant.
 * Implements FIPS 180-4 SHA-256 and RFC 2104 HMAC and RFC 5869 HKDF.
 */

#include "sha256_raw.h"
#include <string.h>



#define ROTR32(x, n) (((uint32_t)(x) >> (n)) | ((uint32_t)(x) << (32u - (n))))

/* Internal static scratch storage for one-shot and HKDF paths. */
static uint32_t g_sha256_schedule[64];
static uint8_t g_hmac_pad[64];
static uint8_t g_hmac_inner_hash[SHA256_RAW_DIGEST_SIZE];
static uint8_t g_hkdf_block[SHA256_RAW_DIGEST_SIZE];
static sha256_raw_ctx_t g_sha256_oneshot_ctx;
static sha256_raw_ctx_t g_hmac_keyhash_ctx;
static hmac_sha256_raw_ctx_t g_hmac_oneshot_ctx;
static hmac_sha256_raw_ctx_t g_hkdf_ctx;

/* Initial hash values (FIPS 180-4 Section 5.3.3) */
static const uint32_t sha256_H0[8] = {
    0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au,
    0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u,
};

/* Round constants (FIPS 180-4 Section 4.2.2) */
static const uint32_t sha256_K[64] = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u,
    0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u,
    0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu,
    0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u,
    0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u,
    0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u,
    0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u,
    0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u,
    0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
};

/* Load big-endian 32-bit word from 4 bytes */
static uint32_t be32_load(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) |
           ((uint32_t)b[2] <<  8) | ((uint32_t)b[3]);
}

/* SHA-256 block compression (processes one 64-byte block) */

static void sha256_compress(sha256_raw_ctx_t *ctx, const uint8_t *block) {
    uint32_t *W = g_sha256_schedule;
    uint32_t a, b, c, d, e, f, g, h;
    uint32_t t1, t2, s0, s1;
    int i;

    /* Message schedule */
    for (i = 0; i < 16; i++) {
        W[i] = be32_load(block + 4 * i);
    }
    for (i = 16; i < 64; i++) {
        s0 = ROTR32(W[i - 15], 7)  ^ ROTR32(W[i - 15], 18) ^ (W[i - 15] >> 3);
        s1 = ROTR32(W[i - 2],  17) ^ ROTR32(W[i - 2],  19) ^ (W[i - 2]  >> 10);
        W[i] = W[i - 16] + s0 + W[i - 7] + s1;
    }

    a = ctx->state[0]; b = ctx->state[1];
    c = ctx->state[2]; d = ctx->state[3];
    e = ctx->state[4]; f = ctx->state[5];
    g = ctx->state[6]; h = ctx->state[7];

    for (i = 0; i < 64; i++) {
        s1 = ROTR32(e, 6) ^ ROTR32(e, 11) ^ ROTR32(e, 25);
        t1 = h + s1 + ((e & f) ^ (~e & g)) + sha256_K[i] + W[i];
        s0 = ROTR32(a, 2) ^ ROTR32(a, 13) ^ ROTR32(a, 22);
        t2 = s0 + ((a & b) ^ (a & c) ^ (b & c));
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    ctx->state[0] += a; ctx->state[1] += b;
    ctx->state[2] += c; ctx->state[3] += d;
    ctx->state[4] += e; ctx->state[5] += f;
    ctx->state[6] += g; ctx->state[7] += h;
    memset(W, 0, sizeof(g_sha256_schedule));
}



void sha256_raw_ctx_init(sha256_raw_ctx_t *ctx) {
    int i;
    for (i = 0; i < 8; i++) {
        ctx->state[i] = sha256_H0[i];
    }
    ctx->length = 0u;
    ctx->curlen = 0u;
}

void sha256_raw_ctx_update(sha256_raw_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t n;

    while (len > 0u) {
        if (ctx->curlen == 0u && len >= 64u) {
            /* Process a full block directly from the input buffer */
            sha256_compress(ctx, data);
            ctx->length += 512u;
            data += 64u;
            len  -= 64u;
        } else {
            /* Copy into partial block buffer */
            n = 64u - ctx->curlen;
            if (n > len) { n = len; }
            memcpy(ctx->buf + ctx->curlen, data, n);
            ctx->curlen += (uint32_t)n;
            data += n;
            len  -= n;
            if (ctx->curlen == 64u) {
                sha256_compress(ctx, ctx->buf);
                ctx->length += 512u;
                ctx->curlen = 0u;
            }
        }
    }
}

void sha256_raw_ctx_final(sha256_raw_ctx_t *ctx, uint8_t digest[SHA256_RAW_DIGEST_SIZE]) {
    int i;

    /* Account for the partial block's bit-length */
    ctx->length += (uint64_t)ctx->curlen * 8u;

    /* Append the mandatory 1-bit (0x80 byte) */
    ctx->buf[ctx->curlen++] = 0x80u;

    /* If not enough room for the 8-byte length field, compress and start fresh */
    if (ctx->curlen > 56u) {
        while (ctx->curlen < 64u) { ctx->buf[ctx->curlen++] = 0x00u; }
        sha256_compress(ctx, ctx->buf);
        ctx->curlen = 0u;
    }

    /* Pad to byte 56 */
    while (ctx->curlen < 56u) { ctx->buf[ctx->curlen++] = 0x00u; }

    /* Append 64-bit big-endian bit-length */
    ctx->buf[56] = (uint8_t)(ctx->length >> 56);
    ctx->buf[57] = (uint8_t)(ctx->length >> 48);
    ctx->buf[58] = (uint8_t)(ctx->length >> 40);
    ctx->buf[59] = (uint8_t)(ctx->length >> 32);
    ctx->buf[60] = (uint8_t)(ctx->length >> 24);
    ctx->buf[61] = (uint8_t)(ctx->length >> 16);
    ctx->buf[62] = (uint8_t)(ctx->length >>  8);
    ctx->buf[63] = (uint8_t)(ctx->length);

    sha256_compress(ctx, ctx->buf);

    /* Write digest in big-endian byte order */
    for (i = 0; i < 8; i++) {
        digest[4 * i]     = (uint8_t)(ctx->state[i] >> 24);
        digest[4 * i + 1] = (uint8_t)(ctx->state[i] >> 16);
        digest[4 * i + 2] = (uint8_t)(ctx->state[i] >>  8);
        digest[4 * i + 3] = (uint8_t)(ctx->state[i]);
    }

    memset(ctx, 0, sizeof(*ctx));
}



void hmac_sha256_raw_init(hmac_sha256_raw_ctx_t *ctx,
                          const uint8_t *key, size_t key_len) {
    int i;

    /* Normalise key: hash it if longer than 64 bytes */
    memset(g_hmac_pad, 0, sizeof(g_hmac_pad));
    if (key_len > 64u) {
        sha256_raw_ctx_init(&g_hmac_keyhash_ctx);
        sha256_raw_ctx_update(&g_hmac_keyhash_ctx, key, key_len);
        sha256_raw_ctx_final(&g_hmac_keyhash_ctx, g_hmac_pad);
        memset(&g_hmac_keyhash_ctx, 0, sizeof(g_hmac_keyhash_ctx));
        /* g_hmac_pad[32..63] already zeroed above. */
    } else if (key_len > 0u) {
        memcpy(g_hmac_pad, key, key_len);
    }

    /* Prime inner context with ipad = k_pad XOR 0x36. */
    for (i = 0; i < 64; i++) {
        g_hmac_pad[i] ^= 0x36u;
    }
    sha256_raw_ctx_init(&ctx->inner);
    sha256_raw_ctx_update(&ctx->inner, g_hmac_pad, sizeof(g_hmac_pad));

    /* Transform ipad into opad in place: 0x36 ^ 0x5c == 0x6a. */
    for (i = 0; i < 64; i++) {
        g_hmac_pad[i] ^= 0x6au;
    }
    sha256_raw_ctx_init(&ctx->outer);
    sha256_raw_ctx_update(&ctx->outer, g_hmac_pad, sizeof(g_hmac_pad));

    /* Zero sensitive key material */
    memset(g_hmac_pad, 0, sizeof(g_hmac_pad));
}

void hmac_sha256_raw_update(hmac_sha256_raw_ctx_t *ctx,
                             const uint8_t *data, size_t len) {
    sha256_raw_ctx_update(&ctx->inner, data, len);
}

void hmac_sha256_raw_final(hmac_sha256_raw_ctx_t *ctx,
                            uint8_t mac[HMAC_SHA256_RAW_SIZE]) {
    /* Finalise inner: H(ipad || message) */
    sha256_raw_ctx_final(&ctx->inner, g_hmac_inner_hash);

    /* Feed inner digest into outer: H(opad || inner_hash) */
    sha256_raw_ctx_update(&ctx->outer, g_hmac_inner_hash, SHA256_RAW_DIGEST_SIZE);
    sha256_raw_ctx_final(&ctx->outer, mac);

    memset(g_hmac_inner_hash, 0, sizeof(g_hmac_inner_hash));
    memset(ctx, 0, sizeof(*ctx));
}



void sha256_raw(const uint8_t *msg, size_t len,
                uint8_t digest[SHA256_RAW_DIGEST_SIZE]) {
    sha256_raw_ctx_init(&g_sha256_oneshot_ctx);
    sha256_raw_ctx_update(&g_sha256_oneshot_ctx, msg, len);
    sha256_raw_ctx_final(&g_sha256_oneshot_ctx, digest);
    memset(&g_sha256_oneshot_ctx, 0, sizeof(g_sha256_oneshot_ctx));
}

void hmac_sha256_raw(const uint8_t *key, size_t key_len,
                     const uint8_t *msg, size_t msg_len,
                     uint8_t mac[HMAC_SHA256_RAW_SIZE]) {
    hmac_sha256_raw_init(&g_hmac_oneshot_ctx, key, key_len);
    hmac_sha256_raw_update(&g_hmac_oneshot_ctx, msg, msg_len);
    hmac_sha256_raw_final(&g_hmac_oneshot_ctx, mac);
    memset(&g_hmac_oneshot_ctx, 0, sizeof(g_hmac_oneshot_ctx));
}

/* HKDF (RFC 5869) */

void hkdf_extract_sha256(const uint8_t *salt, size_t salt_len,
                          const uint8_t *ikm,  size_t ikm_len,
                          uint8_t prk[SHA256_RAW_DIGEST_SIZE]) {
    /* If salt is absent, use a string of HashLen zeros per RFC 5869 Section 2.2 */
    static const uint8_t zero_salt[SHA256_RAW_DIGEST_SIZE] = {0};
    if (salt == NULL || salt_len == 0u) {
        salt     = zero_salt;
        salt_len = SHA256_RAW_DIGEST_SIZE;
    }
    hmac_sha256_raw(salt, salt_len, ikm, ikm_len, prk);
}

void hkdf_expand_sha256(const uint8_t *prk,  size_t prk_len,
                         const uint8_t *info, size_t info_len,
                         uint8_t *out, size_t out_len) {
    size_t done = 0u;
    uint8_t counter = 0u;

    memset(g_hkdf_block, 0, sizeof(g_hkdf_block));

    while (done < out_len) {
        size_t take;

        counter++;

        /* T(i) = HMAC(PRK, T(i-1) || info || i) */
        hmac_sha256_raw_init(&g_hkdf_ctx, prk, prk_len);
        if (counter > 1u) {
            /* T(0) is the empty string; skip on the first iteration */
            hmac_sha256_raw_update(&g_hkdf_ctx, g_hkdf_block, SHA256_RAW_DIGEST_SIZE);
        }
        if (info_len > 0u) {
            hmac_sha256_raw_update(&g_hkdf_ctx, info, info_len);
        }
        hmac_sha256_raw_update(&g_hkdf_ctx, &counter, 1u);
        hmac_sha256_raw_final(&g_hkdf_ctx, g_hkdf_block);
        memset(&g_hkdf_ctx, 0, sizeof(g_hkdf_ctx));

        take = out_len - done;
        if (take > SHA256_RAW_DIGEST_SIZE) { take = SHA256_RAW_DIGEST_SIZE; }
        memcpy(out + done, g_hkdf_block, take);
        done += take;
    }

    memset(g_hkdf_block, 0, sizeof(g_hkdf_block));
}
