#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secure_crypto.h"

void *XMALLOC(size_t n, void *heap, int type) {
    (void)heap;
    (void)type;
    return malloc(n);
}

void XFREE(void *p, void *heap, int type) {
    (void)heap;
    (void)type;
    free(p);
}

void *XREALLOC(void *p, size_t n, void *heap, int type) {
    (void)heap;
    (void)type;
    return realloc(p, n);
}

static void fill_test_global_secrets(uint8_t *buffer, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        buffer[i] = (uint8_t)((i * 37U + 11U) & 0xffU);
    }
}

static int test_same_inputs_same_keys(void) {
    uint8_t global_secrets[133];
    secure_crypto_root_secret_t root_a;
    secure_crypto_root_secret_t root_b;
    uint8_t key_a[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t key_b[SECURE_CRYPTO_DERIVED_KEY_SIZE];

    fill_test_global_secrets(global_secrets, sizeof(global_secrets));
    if (!secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root_a) ||
        !secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root_b)) {
        return 1;
    }
    if (!secure_crypto_derive_file_enc_key(&root_a, 0x1234, key_a, sizeof(key_a)) ||
        !secure_crypto_derive_file_enc_key(&root_b, 0x1234, key_b, sizeof(key_b))) {
        return 1;
    }
    return memcmp(key_a, key_b, sizeof(key_a)) == 0 ? 0 : 1;
}

static int test_different_labels_different_keys(void) {
    uint8_t global_secrets[133];
    secure_crypto_root_secret_t root;
    uint8_t file_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t xfer_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];

    fill_test_global_secrets(global_secrets, sizeof(global_secrets));
    if (!secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root)) {
        return 1;
    }
    if (!secure_crypto_derive_file_enc_key(&root, 0x1234, file_key, sizeof(file_key)) ||
        !secure_crypto_derive_xfer_root_key(&root, 0x1234, xfer_key, sizeof(xfer_key))) {
        return 1;
    }
    return memcmp(file_key, xfer_key, sizeof(file_key)) != 0 ? 0 : 1;
}

static int test_different_groups_different_keys(void) {
    uint8_t global_secrets[133];
    secure_crypto_root_secret_t root;
    uint8_t key_a[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t key_b[SECURE_CRYPTO_DERIVED_KEY_SIZE];

    fill_test_global_secrets(global_secrets, sizeof(global_secrets));
    if (!secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root)) {
        return 1;
    }
    if (!secure_crypto_derive_writer_seed(&root, 0x1234, key_a, sizeof(key_a)) ||
        !secure_crypto_derive_writer_seed(&root, 0x4321, key_b, sizeof(key_b))) {
        return 1;
    }
    return memcmp(key_a, key_b, sizeof(key_a)) != 0 ? 0 : 1;
}

static int test_aes_gcm_round_trip(void) {
    uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t nonce[12];
    const uint8_t aad[] = {0x01, 0x02, 0x03};
    const uint8_t plaintext[] = "secure round trip";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    uint8_t tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE];

    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)i;
    }
    for (size_t i = 0; i < sizeof(nonce); ++i) {
        nonce[i] = (uint8_t)(0xa0U + i);
    }

    if (!secure_crypto_aes_gcm_encrypt(
            key,
            sizeof(key),
            nonce,
            sizeof(nonce),
            aad,
            sizeof(aad),
            plaintext,
            sizeof(plaintext),
            ciphertext,
            tag,
            sizeof(tag))) {
        return 1;
    }

    if (!secure_crypto_aes_gcm_decrypt(
            key,
            sizeof(key),
            nonce,
            sizeof(nonce),
            aad,
            sizeof(aad),
            ciphertext,
            sizeof(ciphertext),
            tag,
            sizeof(tag),
            decrypted,
            sizeof(decrypted))) {
        return 1;
    }

    return memcmp(plaintext, decrypted, sizeof(plaintext)) == 0 ? 0 : 1;
}

static int test_aes_gcm_tamper_failure(void) {
    uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t nonce[12];
    const uint8_t plaintext[] = "tamper me";
    uint8_t ciphertext[sizeof(plaintext)];
    uint8_t decrypted[sizeof(plaintext)];
    uint8_t tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE];

    for (size_t i = 0; i < sizeof(key); ++i) {
        key[i] = (uint8_t)(0x55U + i);
    }
    memset(nonce, 0x22, sizeof(nonce));

    if (!secure_crypto_aes_gcm_encrypt(
            key,
            sizeof(key),
            nonce,
            sizeof(nonce),
            NULL,
            0,
            plaintext,
            sizeof(plaintext),
            ciphertext,
            tag,
            sizeof(tag))) {
        return 1;
    }

    ciphertext[0] ^= 0x80U;
    return secure_crypto_aes_gcm_decrypt(
               key,
               sizeof(key),
               nonce,
               sizeof(nonce),
               NULL,
               0,
               ciphertext,
               sizeof(ciphertext),
               tag,
               sizeof(tag),
               decrypted,
               sizeof(decrypted))
           ? 1 : 0;
}

static int test_sign_verify_success(void) {
    uint8_t global_secrets[133];
    secure_crypto_root_secret_t root;
    secure_crypto_ecc_material_t material;
    const uint8_t message[] = "writer signature";
    uint8_t signature[SECURE_CRYPTO_ECC_SIGNATURE_MAX_SIZE];
    size_t signature_len = sizeof(signature);

    fill_test_global_secrets(global_secrets, sizeof(global_secrets));
    if (!secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root)) {
        fprintf(stderr, "root_secret_from_global_secrets failed\n");
        return 1;
    }
    if (!secure_crypto_derive_writer_keypair(&root, 0x1234, &material)) {
        fprintf(stderr, "derive_writer_keypair failed\n");
        return 1;
    }
    if (!secure_crypto_writer_sign(&root, 0x1234, message, sizeof(message), signature, &signature_len)) {
        fprintf(stderr, "writer_sign failed\n");
        return 1;
    }
    if (!secure_crypto_writer_verify(&root, 0x1234, message, sizeof(message), signature, signature_len)) {
        fprintf(stderr, "writer_verify failed signature_len=%zu\n", signature_len);
        return 1;
    }
    return 0;
}

static int test_verify_failure_modified_message(void) {
    uint8_t global_secrets[133];
    secure_crypto_root_secret_t root;
    const uint8_t message[] = "receive proof";
    uint8_t tampered[sizeof(message)];
    uint8_t signature[SECURE_CRYPTO_ECC_SIGNATURE_MAX_SIZE];
    size_t signature_len = sizeof(signature);

    fill_test_global_secrets(global_secrets, sizeof(global_secrets));
    memcpy(tampered, message, sizeof(message));
    tampered[0] ^= 0x01U;

    if (!secure_crypto_root_secret_from_global_secrets(global_secrets, sizeof(global_secrets), &root)) {
        return 1;
    }
    if (!secure_crypto_receive_proof_sign(&root, 0x4321, message, sizeof(message), signature, &signature_len)) {
        return 1;
    }
    return secure_crypto_receive_proof_verify(
               &root,
               0x4321,
               tampered,
               sizeof(tampered),
               signature,
               signature_len)
           ? 1 : 0;
}

struct test_case {
    const char *name;
    int (*fn)(void);
};

int main(void) {
    const struct test_case tests[] = {
        {"same_inputs_same_keys", test_same_inputs_same_keys},
        {"different_labels_different_keys", test_different_labels_different_keys},
        {"different_groups_different_keys", test_different_groups_different_keys},
        {"aes_gcm_round_trip", test_aes_gcm_round_trip},
        {"aes_gcm_tamper_failure", test_aes_gcm_tamper_failure},
        {"sign_verify_success", test_sign_verify_success},
        {"verify_failure_modified_message", test_verify_failure_modified_message},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        if (tests[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }

    return 0;
}
