#ifndef SECURE_BLOB_STORE_H
#define SECURE_BLOB_STORE_H

#include <stddef.h>
#include <stdint.h>

#include "secure_crypto.h"

#ifdef HOST_TEST
#define SECURE_BLOB_STORE_PAGE_SIZE 1024u
#else
#include "simple_flash.h"
#define SECURE_BLOB_STORE_PAGE_SIZE FLASH_PAGE_SIZE
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define SECURE_BLOB_STORE_FLASH_BASE 0x6000u
#define SECURE_BLOB_STORE_FLASH_END  0x3A000u
#define SECURE_BLOB_STORE_FAT_ADDR   0x3A000u

#define SECURE_BLOB_STORE_MAX_SLOTS 16u
#define SECURE_BLOB_STORE_AUTO_SLOT 0xFFu

#define SECURE_BLOB_STORE_SLOT_SIZE \
    ((SECURE_BLOB_STORE_FLASH_END - SECURE_BLOB_STORE_FLASH_BASE) / \
     SECURE_BLOB_STORE_MAX_SLOTS)

#define SECURE_BLOB_STORE_PIN_HASH_SIZE SECURE_CRYPTO_SHA256_DIGEST_SIZE

typedef struct {
    uint32_t flash_addr;
    uint32_t record_len;
    uint32_t plaintext_len;
    uint32_t reserved;
} secure_blob_fat_entry_t;

typedef enum {
    SECURE_BLOB_STORE_OK = 0,
    SECURE_BLOB_STORE_INVALID_ARGUMENT = -1,
    SECURE_BLOB_STORE_INVALID_SLOT = -2,
    SECURE_BLOB_STORE_STORAGE_FULL = -3,
    SECURE_BLOB_STORE_NOT_FOUND = -4,
    SECURE_BLOB_STORE_PERMISSION_DENIED = -5,
    SECURE_BLOB_STORE_BUFFER_TOO_SMALL = -6,
    SECURE_BLOB_STORE_IO_ERROR = -7,
    SECURE_BLOB_STORE_CRYPTO_ERROR = -8,
    SECURE_BLOB_STORE_CORRUPT = -9,
} secure_blob_store_status_t;

extern secure_blob_fat_entry_t g_fat[SECURE_BLOB_STORE_MAX_SLOTS];

secure_blob_store_status_t blob_store_init(void);
secure_blob_store_status_t blob_write(uint8_t slot,
                                      const uint8_t *data,
                                      size_t len,
                                      const uint8_t owner_pin_hash
                                          [SECURE_BLOB_STORE_PIN_HASH_SIZE],
                                      uint32_t group_mask);
secure_blob_store_status_t blob_read(uint8_t slot,
                                     const uint8_t pin_hash
                                         [SECURE_BLOB_STORE_PIN_HASH_SIZE],
                                     uint32_t group_mask,
                                     uint8_t *out,
                                     size_t *out_len);
secure_blob_store_status_t blob_delete(uint8_t slot);

int init_blob_store(void);

#ifdef __cplusplus
}
#endif

#endif
