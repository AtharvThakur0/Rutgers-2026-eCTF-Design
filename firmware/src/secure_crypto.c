/**
 * @file secure_crypto.c
 * @brief Secure crypto implementation for the eCTF 2026 HSM.
 * @date 2026
 *
 * SHA-256 / HMAC-SHA-256 / HKDF use sha256_raw.c only.
 * AES-256-GCM uses wolfSSL only for wc_AesGcm*.
 * All large scratch/state is static to keep stack usage bounded on M0+.
 */

#include "secure_crypto.h"
#include "sha256_raw.h"

#include <string.h>

#ifdef WOLFSSL_USER_SETTINGS
#include "user_settings.h"
#endif
#include "wolfssl/wolfcrypt/aes.h"

/* GLOBAL_SECRETS binary layout
 *   [  0.. 64] ECC public key  (65 bytes)
 *   [ 65.. 96] ECC private key (32 bytes)
 *   [ 97..128] K_master        (32 bytes)
 *   [129..]    group list */
#define GS_AES_KEY_OFFSET 97u
#define GS_MIN_LEN        129u

/* HKDF / HMAC labels */
static const char LABEL_GROUP_ROOT[]  = "group_root";
static const char LABEL_FILE_ENC[]    = "file_enc_v1";
static const char LABEL_XFER_ROOT[]   = "xfer_root_v1";
static const char LABEL_PIN_MAC[]     = "pin_mac_v1";
static const char LABEL_WRITER_SEED[] = "writer_sign_seed_v1";
static const char LABEL_RECV_SEED[]   = "recv_sign_seed_v1";

/* Module scratch storage. This implementation is intentionally not re-entrant. */
static uint8_t g_group_salt[2];
static uint8_t g_hkdf_prk[SHA256_RAW_DIGEST_SIZE];
static uint8_t g_group_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
static uint8_t g_digest[SECURE_CRYPTO_SHA256_DIGEST_SIZE];
static uint8_t g_expected_mac[SECURE_CRYPTO_HMAC_SIZE];
static secure_crypto_ecc_material_t g_material;
static Aes g_aes_ctx;



static bool derive_key(const uint8_t master[SECURE_CRYPTO_DERIVED_KEY_SIZE],
                       const char *label,
                       uint8_t *out, size_t out_len) {
    if (!master || !label || !out || out_len == 0u) {
        return false;
    }

    hkdf_extract_sha256(NULL, 0u,
                        master, SECURE_CRYPTO_DERIVED_KEY_SIZE,
                        g_hkdf_prk);
    hkdf_expand_sha256(g_hkdf_prk, sizeof(g_hkdf_prk),
                       (const uint8_t *)label, strlen(label),
                       out, out_len);
    memset(g_hkdf_prk, 0, sizeof(g_hkdf_prk));
    return true;
}

static bool hmac_sha256(const uint8_t *key, size_t key_len,
                        const uint8_t *msg, size_t msg_len,
                        uint8_t out[SECURE_CRYPTO_HMAC_SIZE]) {
    if (!key || !out || (msg_len > 0u && !msg)) {
        return false;
    }

    hmac_sha256_raw(key, key_len, msg, msg_len, out);
    return true;
}

static bool derive_group_key(const secure_crypto_root_secret_t *root,
                             uint16_t group_id,
                             uint8_t out[SECURE_CRYPTO_DERIVED_KEY_SIZE]) {
    if (!root || !out) {
        return false;
    }

    g_group_salt[0] = (uint8_t)(group_id & 0xFFu);
    g_group_salt[1] = (uint8_t)((group_id >> 8) & 0xFFu);

    hkdf_extract_sha256(g_group_salt, sizeof(g_group_salt),
                        root->k_master, sizeof(root->k_master),
                        g_hkdf_prk);
    hkdf_expand_sha256(g_hkdf_prk, sizeof(g_hkdf_prk),
                       (const uint8_t *)LABEL_GROUP_ROOT,
                       sizeof(LABEL_GROUP_ROOT) - 1u,
                       out, SECURE_CRYPTO_DERIVED_KEY_SIZE);

    memset(g_group_salt, 0, sizeof(g_group_salt));
    memset(g_hkdf_prk, 0, sizeof(g_hkdf_prk));
    return true;
}

static bool derive_group_subkey(const secure_crypto_root_secret_t *root,
                                uint16_t group_id, const char *label,
                                uint8_t *out, size_t out_len) {
    bool ok;

    if (!label || !out || out_len == 0u) {
        return false;
    }

    ok = derive_group_key(root, group_id, g_group_key);
    if (ok) {
        ok = derive_key(g_group_key, label, out, out_len);
    }

    memset(g_group_key, 0, sizeof(g_group_key));
    return ok;
}

static bool aes_gcm_encrypt(const uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE],
                            const uint8_t iv[SECURE_CRYPTO_AES_GCM_NONCE_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *pt, size_t pt_len,
                            uint8_t *ct,
                            uint8_t tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE]) {
    int ret;

    memset(&g_aes_ctx, 0, sizeof(g_aes_ctx));
    ret = wc_AesGcmSetKey(&g_aes_ctx, key, SECURE_CRYPTO_DERIVED_KEY_SIZE);
    if (ret == 0) {
        ret = wc_AesGcmEncrypt(&g_aes_ctx,
                               ct, pt, (word32)pt_len,
                               iv, SECURE_CRYPTO_AES_GCM_NONCE_SIZE,
                               tag, SECURE_CRYPTO_AES_GCM_TAG_SIZE,
                               aad, (word32)aad_len);
    }
    memset(&g_aes_ctx, 0, sizeof(g_aes_ctx));
    return ret == 0;
}

static bool aes_gcm_decrypt(const uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE],
                            const uint8_t iv[SECURE_CRYPTO_AES_GCM_NONCE_SIZE],
                            const uint8_t *aad, size_t aad_len,
                            const uint8_t *ct, size_t ct_len,
                            const uint8_t tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE],
                            uint8_t *pt) {
    int ret;

    memset(&g_aes_ctx, 0, sizeof(g_aes_ctx));
    ret = wc_AesGcmSetKey(&g_aes_ctx, key, SECURE_CRYPTO_DERIVED_KEY_SIZE);
    if (ret == 0) {
        ret = wc_AesGcmDecrypt(&g_aes_ctx,
                               pt, ct, (word32)ct_len,
                               iv, SECURE_CRYPTO_AES_GCM_NONCE_SIZE,
                               tag, SECURE_CRYPTO_AES_GCM_TAG_SIZE,
                               aad, (word32)aad_len);
    }
    memset(&g_aes_ctx, 0, sizeof(g_aes_ctx));

    if (ret != 0 && pt && ct_len > 0u) {
        memset(pt, 0, ct_len);
    }
    return ret == 0;
}

static bool hmac_sign_digest(const secure_crypto_ecc_material_t *material,
                             const uint8_t digest[SECURE_CRYPTO_SHA256_DIGEST_SIZE],
                             uint8_t *signature, size_t *sig_len_ptr) {
    if (!material || !digest || !signature || !sig_len_ptr ||
        *sig_len_ptr < SECURE_CRYPTO_SHA256_DIGEST_SIZE) {
        return false;
    }

    if (!hmac_sha256(material->sign_key, sizeof(material->sign_key),
                     digest, SECURE_CRYPTO_SHA256_DIGEST_SIZE,
                     signature)) {
        return false;
    }

    *sig_len_ptr = SECURE_CRYPTO_SHA256_DIGEST_SIZE;
    return true;
}

static bool hmac_verify_digest(const secure_crypto_ecc_material_t *material,
                               const uint8_t digest[SECURE_CRYPTO_SHA256_DIGEST_SIZE],
                               const uint8_t *signature, size_t sig_len) {
    uint8_t diff = 0u;
    size_t i;

    if (!material || !digest || !signature ||
        sig_len != SECURE_CRYPTO_SHA256_DIGEST_SIZE) {
        return false;
    }

    if (!hmac_sha256(material->sign_key, sizeof(material->sign_key),
                     digest, SECURE_CRYPTO_SHA256_DIGEST_SIZE,
                     g_expected_mac)) {
        return false;
    }

    for (i = 0u; i < SECURE_CRYPTO_SHA256_DIGEST_SIZE; ++i) {
        diff |= (uint8_t)(g_expected_mac[i] ^ signature[i]);
    }

    memset(g_expected_mac, 0, sizeof(g_expected_mac));
    return diff == 0u;
}



bool secure_crypto_root_secret_from_global_secrets(
    const uint8_t *global_secrets, size_t len,
    secure_crypto_root_secret_t *out) {
    if (!global_secrets || !out || len < GS_MIN_LEN) {
        return false;
    }

    memcpy(out->k_master, global_secrets + GS_AES_KEY_OFFSET,
           SECURE_CRYPTO_DERIVED_KEY_SIZE);
    return true;
}

/* Per-group symmetric key derivation */

bool secure_crypto_derive_file_enc_key(const secure_crypto_root_secret_t *root,
                                       uint16_t group_id,
                                       uint8_t *out, size_t out_len) {
    if (!root || !out || out_len == 0u) {
        return false;
    }

    return derive_group_subkey(root, group_id, LABEL_FILE_ENC, out, out_len);
}

bool secure_crypto_derive_xfer_root_key(const secure_crypto_root_secret_t *root,
                                        uint16_t group_id,
                                        uint8_t *out, size_t out_len) {
    if (!root || !out || out_len == 0u) {
        return false;
    }

    return derive_group_subkey(root, group_id, LABEL_XFER_ROOT, out, out_len);
}

bool secure_crypto_derive_pin_mac_key(const secure_crypto_root_secret_t *root,
                                      uint8_t *out, size_t out_len) {
    if (!root || !out || out_len != SECURE_CRYPTO_HMAC_SIZE) {
        return false;
    }

    return hmac_sha256(root->k_master, sizeof(root->k_master),
                       (const uint8_t *)LABEL_PIN_MAC,
                       sizeof(LABEL_PIN_MAC) - 1u,
                       out);
}

bool secure_crypto_derive_writer_seed(const secure_crypto_root_secret_t *root,
                                      uint16_t group_id,
                                      uint8_t *out, size_t out_len) {
    if (!root || !out || out_len == 0u) {
        return false;
    }

    return derive_group_subkey(root, group_id, LABEL_WRITER_SEED, out, out_len);
}

bool secure_crypto_derive_recv_seed(const secure_crypto_root_secret_t *root,
                                    uint16_t group_id,
                                    uint8_t *out, size_t out_len) {
    if (!root || !out || out_len == 0u) {
        return false;
    }

    return derive_group_subkey(root, group_id, LABEL_RECV_SEED, out, out_len);
}

/* Keypair derivation (HMAC-based, symmetric) */

bool secure_crypto_derive_writer_keypair(
    const secure_crypto_root_secret_t *root, uint16_t group_id,
    secure_crypto_ecc_material_t *material_out) {
    if (!root || !material_out) {
        return false;
    }

    memset(material_out, 0, sizeof(*material_out));
    return secure_crypto_derive_writer_seed(root, group_id,
                                            material_out->sign_key,
                                            sizeof(material_out->sign_key));
}

bool secure_crypto_derive_recv_keypair(
    const secure_crypto_root_secret_t *root, uint16_t group_id,
    secure_crypto_ecc_material_t *material_out) {
    if (!root || !material_out) {
        return false;
    }

    memset(material_out, 0, sizeof(*material_out));
    return secure_crypto_derive_recv_seed(root, group_id,
                                          material_out->sign_key,
                                          sizeof(material_out->sign_key));
}



bool secure_crypto_sha256(const uint8_t *message, size_t len,
                          uint8_t *digest_out, size_t digest_len) {
    if (!digest_out || digest_len != SECURE_CRYPTO_SHA256_DIGEST_SIZE ||
        (len > 0u && !message)) {
        return false;
    }

    sha256_raw(message, len, digest_out);
    return true;
}

bool secure_crypto_hmac_sha256(const uint8_t *key, size_t key_len,
                               const uint8_t *message, size_t msg_len,
                               uint8_t *mac_out, size_t mac_len) {
    if (mac_len != SECURE_CRYPTO_HMAC_SIZE) {
        return false;
    }

    return hmac_sha256(key, key_len, message, msg_len, mac_out);
}

bool secure_crypto_derive_chunk_key(const uint8_t *master_key, size_t master_len,
                                    uint32_t chunk_idx, uint8_t *out,
                                    size_t out_len) {
    if (!master_key || !out || out_len == 0u) {
        return false;
    }

    uint8_t info[17];
    const char *label = "blob_chunk_v1";
    size_t label_len = strlen(label);
    memcpy(info, label, label_len);
    info[label_len + 0] = (uint8_t)(chunk_idx & 0xFFu);
    info[label_len + 1] = (uint8_t)((chunk_idx >> 8) & 0xFFu);
    info[label_len + 2] = (uint8_t)((chunk_idx >> 16) & 0xFFu);
    info[label_len + 3] = (uint8_t)((chunk_idx >> 24) & 0xFFu);

    hkdf_expand_sha256(master_key, master_len, info, label_len + 4,
                       out, out_len);
    return true;
}

bool secure_crypto_aes_gcm_encrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *plaintext, size_t pt_len,
                                   uint8_t *ciphertext_out, uint8_t *tag_out,
                                   size_t tag_len) {
    if (!key || key_len != SECURE_CRYPTO_DERIVED_KEY_SIZE ||
        !nonce || nonce_len != SECURE_CRYPTO_AES_GCM_NONCE_SIZE ||
        !tag_out || tag_len != SECURE_CRYPTO_AES_GCM_TAG_SIZE ||
        (pt_len > 0u && (!plaintext || !ciphertext_out))) {
        return false;
    }

    return aes_gcm_encrypt(key, nonce, aad, aad_len,
                           plaintext, pt_len,
                           ciphertext_out, tag_out);
}

bool secure_crypto_aes_gcm_decrypt(const uint8_t *key, size_t key_len,
                                   const uint8_t *nonce, size_t nonce_len,
                                   const uint8_t *aad, size_t aad_len,
                                   const uint8_t *ciphertext, size_t ct_len,
                                   const uint8_t *tag, size_t tag_len,
                                   uint8_t *plaintext_out, size_t pt_out_len) {
    if (!key || key_len != SECURE_CRYPTO_DERIVED_KEY_SIZE ||
        !nonce || nonce_len != SECURE_CRYPTO_AES_GCM_NONCE_SIZE ||
        !tag || tag_len != SECURE_CRYPTO_AES_GCM_TAG_SIZE ||
        pt_out_len < ct_len ||
        (ct_len > 0u && (!ciphertext || !plaintext_out))) {
        return false;
    }

    return aes_gcm_decrypt(key, nonce, aad, aad_len,
                           ciphertext, ct_len, tag,
                           plaintext_out);
}

/* Public sign / verify API - writer keypair */

bool secure_crypto_writer_sign(const secure_crypto_root_secret_t *root,
                               uint16_t group_id,
                               const uint8_t *message, size_t msg_len,
                               uint8_t *signature, size_t *sig_len_ptr) {
    bool ok;

    if (!root || !signature || !sig_len_ptr || (msg_len > 0u && !message)) {
        return false;
    }

    sha256_raw(message, msg_len, g_digest);
    ok = secure_crypto_derive_writer_keypair(root, group_id, &g_material);
    if (ok) {
        ok = hmac_sign_digest(&g_material, g_digest, signature, sig_len_ptr);
    }

    memset(g_digest, 0, sizeof(g_digest));
    memset(&g_material, 0, sizeof(g_material));
    return ok;
}

bool secure_crypto_writer_verify(const secure_crypto_root_secret_t *root,
                                 uint16_t group_id,
                                 const uint8_t *message, size_t msg_len,
                                 const uint8_t *signature, size_t sig_len) {
    bool ok;

    if (!root || !signature || (msg_len > 0u && !message)) {
        return false;
    }

    sha256_raw(message, msg_len, g_digest);
    ok = secure_crypto_derive_writer_keypair(root, group_id, &g_material);
    if (ok) {
        ok = hmac_verify_digest(&g_material, g_digest, signature, sig_len);
    }

    memset(g_digest, 0, sizeof(g_digest));
    memset(&g_material, 0, sizeof(g_material));
    return ok;
}

/* Receive-proof keypair */

bool secure_crypto_receive_proof_sign(const secure_crypto_root_secret_t *root,
                                      uint16_t group_id,
                                      const uint8_t *message, size_t msg_len,
                                      uint8_t *signature, size_t *sig_len_ptr) {
    bool ok;

    if (!root || !signature || !sig_len_ptr || (msg_len > 0u && !message)) {
        return false;
    }

    sha256_raw(message, msg_len, g_digest);
    ok = secure_crypto_derive_recv_keypair(root, group_id, &g_material);
    if (ok) {
        ok = hmac_sign_digest(&g_material, g_digest, signature, sig_len_ptr);
    }

    memset(g_digest, 0, sizeof(g_digest));
    memset(&g_material, 0, sizeof(g_material));
    return ok;
}

bool secure_crypto_receive_proof_verify(const secure_crypto_root_secret_t *root,
                                        uint16_t group_id,
                                        const uint8_t *message, size_t msg_len,
                                        const uint8_t *signature, size_t sig_len) {
    bool ok;

    if (!root || !signature || (msg_len > 0u && !message)) {
        return false;
    }

    sha256_raw(message, msg_len, g_digest);
    ok = secure_crypto_derive_recv_keypair(root, group_id, &g_material);
    if (ok) {
        ok = hmac_verify_digest(&g_material, g_digest, signature, sig_len);
    }

    memset(g_digest, 0, sizeof(g_digest));
    memset(&g_material, 0, sizeof(g_material));
    return ok;
}
