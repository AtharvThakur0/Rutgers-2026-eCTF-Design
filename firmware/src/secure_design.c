#include "secure_design.h"

#include <string.h>

#include "secrets.h"

#ifndef HOST_TEST
#include "trng.h"
#endif

bool security_get_root_secret(secure_crypto_root_secret_t *out)
{
    if (!out) {
        return false;
    }

    memset(out, 0, sizeof(*out));
    return secure_crypto_root_secret_from_global_secrets(
        GLOBAL_SECRETS, GLOBAL_SECRETS_LEN, out);
}

bool security_generate_nonce(uint8_t *out, size_t out_len)
{
    if (!out || out_len == 0u) {
        return false;
    }

#ifdef HOST_TEST
    extern int trng_generate_seed(unsigned char *output, unsigned int sz);
    static uint64_t g_host_nonce_counter = 1u;
    const uint64_t counter = g_host_nonce_counter++;

    if (out_len > (size_t)UINT32_MAX ||
        trng_generate_seed(out, (unsigned int)out_len) != 0) {
        return false;
    }

    for (size_t i = 0; i < out_len; ++i) {
        out[i] ^= (uint8_t)(counter >> ((i % sizeof(counter)) * 8u));
    }

    return true;
#else
    static bool g_trng_ready = false;

    if (!g_trng_ready) {
        trng_init();
        g_trng_ready = true;
    }

    trng_read_bytes(out, out_len);
    return true;
#endif
}

void security_prepare_local_file_crypto_pool(size_t transfer_live_prefix_len)
{
    (void)transfer_live_prefix_len;
}

void security_secure_uart_clear_replay_cache(void)
{
}

bool security_secure_uart_check_and_update_replay(uint32_t Nr,
                                                  uint32_t Nt,
                                                  uint16_t group_id,
                                                  uint8_t op)
{
    (void)Nr;
    (void)Nt;
    (void)group_id;
    (void)op;
    return true;
}
