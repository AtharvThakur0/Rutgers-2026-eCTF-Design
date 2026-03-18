#ifndef WOLFSSL_USER_SETTINGS_H
#define WOLFSSL_USER_SETTINGS_H

#define WOLFCRYPT_ONLY
#define SINGLE_THREADED
#define NO_INLINE

#define HAVE_AESGCM
#define HAVE_HKDF
#define HAVE_ECC
#define HAVE_ECC_SIGN
#define HAVE_ECC_VERIFY

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

#define WOLFSSL_AES_DIRECT

#endif
