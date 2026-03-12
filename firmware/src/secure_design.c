#include "secure_design.h"

#include <string.h>

#include "secrets.h"

#ifndef HOST_TEST
#include "trng.h"
#endif

#define SECURE_UART_REPLAY_CACHE_SIZE 8u

typedef struct {
    uint32_t nr;
    uint32_t nt;
    uint16_t group_id;
    uint8_t op;
    bool valid;
} replay_entry_t;

static replay_entry_t g_replay_cache[SECURE_UART_REPLAY_CACHE_SIZE];
static size_t g_replay_next;

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
    memset(g_replay_cache, 0, sizeof(g_replay_cache));
    g_replay_next = 0u;
}

bool security_secure_uart_check_and_update_replay(uint32_t Nr,
                                                  uint32_t Nt,
                                                  uint16_t group_id,
                                                  uint8_t op)
{
    /* Reject a tuple before inserting it.  The fixed-size ring is deliberate:
     * this target has no heap and only needs a short replay window for UART1. */
    for (size_t i = 0u; i < SECURE_UART_REPLAY_CACHE_SIZE; ++i) {
        const replay_entry_t *entry = &g_replay_cache[i];
        if (entry->valid && entry->nr == Nr && entry->nt == Nt &&
            entry->group_id == group_id && entry->op == op) {
            return false;
        }
    }

    g_replay_cache[g_replay_next].nr = Nr;
    g_replay_cache[g_replay_next].nt = Nt;
    g_replay_cache[g_replay_next].group_id = group_id;
    g_replay_cache[g_replay_next].op = op;
    g_replay_cache[g_replay_next].valid = true;
    g_replay_next = (g_replay_next + 1u) % SECURE_UART_REPLAY_CACHE_SIZE;
    return true;
}
