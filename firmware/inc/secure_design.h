#ifndef SECURE_DESIGN_H
#define SECURE_DESIGN_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "secure_crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

bool security_get_root_secret(secure_crypto_root_secret_t *out);
bool security_generate_nonce(uint8_t *out, size_t out_len);

void security_prepare_local_file_crypto_pool(size_t transfer_live_prefix_len);
void security_secure_uart_clear_replay_cache(void);
bool security_secure_uart_check_and_update_replay(uint32_t Nr,
                                                  uint32_t Nt,
                                                  uint16_t group_id,
                                                  uint8_t op);

#ifdef __cplusplus
}
#endif

#endif
