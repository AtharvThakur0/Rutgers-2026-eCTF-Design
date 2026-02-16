/**
 * @file "simple_crypto.c"
 * @author Ben Janis
 * @brief Simplified Crypto API Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#if CRYPTO_EXAMPLE

#include "simple_crypto.h"
#include "security.h"
#include <stdint.h>
#include <string.h>


/******************************** FUNCTION PROTOTYPES ********************************/
/** @brief Encrypts plaintext using a symmetric cipher
 *
 * @param plaintext A pointer to a buffer of length len containing the
 *          plaintext to encrypt
 * @param len The length of the plaintext to encrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for encryption
 * @param ciphertext A pointer to a buffer of length len where the resulting
 *          ciphertext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int encrypt_sym(uint8_t *plaintext, size_t len, uint8_t *key, uint8_t *ciphertext) {
    Aes ctx; // Context for encryption
    int result; // Library result
    int result2;
    byte iv[16];
    byte authTag[32];
    byte authIn[16];
    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for encryption
    result = wc_AesGcmSetKey(&ctx, key, 32, NULL, AES_ENCRYPTION);
    if (result != 0)
        return result; // Report error


    // Encrypt each block
    for (int i = 0; i < len; i += BLOCK_SIZE) {
        result2 = wc_AesGcmEncrypt(&ctx, ciphertext + i, plaintext + i, sizeof(ciphertext), iv, sizeof(iv)), authTag, sizeof(authTag), authIn, sizeof(authIn);
        if (result != 0)
            return result2; // Report error
    }
    return 0;
}

int HKDF(int type, const byte * inKey, word32 inKeySz, const byte * salt, word32 saltSz, const byte * info, word32 infoSz, byte * out, word32 outSz){

    int ret;
    int ret2;
    byte key[]; // initialize with key ;
    byte salt[];  // initialize with salt ;
    byte derivedKey[MAX_DIGEST_SIZE];

    int ret = wc_HKDF_Extract(WC_SHA512, salt, sizeof(salt), key, sizeof(key), derivedKey);
    if ( ret != 0 ) {
        return ret;// error generating derived key
    }
    
    int ret2 = wc_HKDF_Expand(WC_SHA512, key, sizeof(key), NULL, 0,
    derivedKey, sizeof(derivedKey));
    if ( ret2 != 0 ) {
        return ret2;// error generating derived key
    }

}   

/** @brief Decrypts ciphertext using a symmetric cipher
 *
 * @param ciphertext A pointer to a buffer of length len containing the
 *          ciphertext to decrypt
 * @param len The length of the ciphertext to decrypt. Must be a multiple of
 *          BLOCK_SIZE (16 bytes)
 * @param key A pointer to a buffer of length KEY_SIZE (16 bytes) containing
 *          the key to use for decryption
 * @param plaintext A pointer to a buffer of length len where the resulting
 *          plaintext will be written to
 *
 * @return 0 on success, -1 on bad length, other non-zero for other error
 */
int decrypt_sym(uint8_t *ciphertext, size_t len, uint8_t *key, uint8_t *plaintext) {
    Aes ctx; // Context for decryption
    int result; // Library result
    int result2;
    byte iv[16];
    byte authTag[32];
    byte authIn[16];

    // Ensure valid length
    if (len <= 0 || len % BLOCK_SIZE)
        return -1;

    // Set the key for decryption
    result = wc_AesGcmSetKey(&ctx, key, 16, NULL, AES_DECRYPTION);
    if (result != 0)
        return result; // Report error

    // Decrypt each block
    for (int i = 0; i < len - 1; i += BLOCK_SIZE) {
        result2 = wc_AesGcmDecrypt(&ctx, ciphertext + i, plaintext + i, sizeof(ciphertext), iv, sizeof(iv), authTag, sizeof(authTag), authIn, sizeof(authIn));
        if (result2 != 0)
            return result2; // Report error
    }
    return 0;
}

/** @brief Hashes arbitrary-length data
 *
 * @param data A pointer to a buffer of length len containing the data
 *          to be hashed
 * @param len The length of the plaintext to hash
 * @param hash_out A pointer to a buffer of length HASH_SIZE (16 bytes) where the resulting
 *          hash output will be written to
 *
 * @return 0 on success, non-zero for other error
 */
int hash(void *data, size_t len, uint8_t *hash_out) {
    // Pass values to hash
    return wc_Md5Hash((uint8_t *)data, len, hash_out);
}

#endif
