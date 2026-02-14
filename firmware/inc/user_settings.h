/**
 * @file user_settings.h
 * @brief wolfSSL build configuration for the eCTF 2026 HSM.
 *
 * Enabled features:
 *   - AES-256-GCM  (HAVE_AESGCM)
 *   - HKDF         (HAVE_HKDF) — available but secure_crypto.c uses sha256_raw
 *   - HMAC/SHA-256 (HAVE_HMAC, WOLFSSL_SHA256) — compiled, not used for crypto
 *
 * Explicitly disabled to reduce code size on M0+:
 *   - RSA, DSA, DH, ECC (no asymmetric)
 *   - MD5, SHA-1, SHA-512, SHA-3
 *   - DES3, RC4, PKCS12/8/10, Sessions, Certs
 *
 * WOLFSSL_SMALL_STACK is NOT set here: with SMALL_STACK, wc_InitSha256 and
 * wc_HmacSetKey route through XMALLOC, which returns NULL on bare-metal with
 * no heap.  secure_crypto.c uses sha256_raw.c for all SHA-256/HMAC to avoid
 * this; wolfSSL is used only for AES-GCM where no dynamic allocation occurs.
 */

#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_INLINE
#define WC_NO_HARDEN

#define HAVE_AESGCM
#define HAVE_HKDF
#define HAVE_HMAC
#define WOLFSSL_SHA256
#define HAVE_SHA256

#define WOLFSSL_AES_DIRECT

/* Disable all unused algorithms */
#define NO_RSA
#define NO_DSA
#define NO_DH
#define NO_MD5
#define NO_SHA
#define NO_SHA512
#define NO_SHA3
#define NO_DES3
#define NO_RC4
#define NO_CERTS
#define NO_SESSION_CACHE
#define NO_PWDBASED
#define NO_PKCS12
#define NO_PKCS8
#define NO_CODING
#define NO_WRITEV
#define NO_FILESYSTEM
#define NO_MAIN_DRIVER
#define NO_DEV_RANDOM

/*
 * Entropy source: the MSPM0 hardware TRNG on the target.
 * Host test builds supply a PRNG substitute via tests/host_rand_seed.c.
 */
extern int trng_generate_seed(unsigned char *output, unsigned int sz);
#define CUSTOM_RAND_GENERATE_SEED  trng_generate_seed

#endif /* WOLFSSL_USER_SETTINGS_H */
