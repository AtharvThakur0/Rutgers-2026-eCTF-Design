#include "secure_blob_store.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>

#include "secure_design.h"

#ifdef HOST_TEST
int flash_simple_erase_page(uint32_t address);
void flash_simple_read(uint32_t address, void *buffer, uint32_t size);
int flash_simple_write(uint32_t address, void *buffer, uint32_t size);
#endif

#define SECURE_BLOB_MAGIC   0x53425331u
#define SECURE_BLOB_VERSION 1u
#define SECURE_BLOB_EMPTY_U32 UINT32_MAX

#define SECURE_BLOB_AAD_SIZE \
    (4u + 2u + 2u + 4u + 4u + SECURE_BLOB_STORE_PIN_HASH_SIZE + \
     SECURE_CRYPTO_AES_GCM_NONCE_SIZE)

typedef struct {
    uint32_t magic;
    uint16_t version;
    uint16_t slot;
    uint32_t plaintext_len;
    uint32_t group_mask;
    uint8_t owner_pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE];
    uint8_t nonce[SECURE_CRYPTO_AES_GCM_NONCE_SIZE];
    uint8_t tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE];
    uint8_t reserved[4];
} secure_blob_flash_header_t;

_Static_assert((SECURE_BLOB_STORE_SLOT_SIZE % SECURE_BLOB_STORE_PAGE_SIZE) == 0u,
               "secure blob slot size must be page aligned");
_Static_assert((SECURE_BLOB_STORE_SLOT_SIZE % 8u) == 0u,
               "secure blob slot size must preserve ECC word alignment");
_Static_assert((sizeof(secure_blob_fat_entry_t) * SECURE_BLOB_STORE_MAX_SLOTS) <=
                   SECURE_BLOB_STORE_PAGE_SIZE,
               "FAT must fit in the dedicated flash page");
_Static_assert((sizeof(secure_blob_fat_entry_t) % 8u) == 0u,
               "FAT entry must be ECC-word aligned");
_Static_assert((sizeof(secure_blob_flash_header_t) % 8u) == 0u,
               "Flash header must be ECC-word aligned");

secure_blob_fat_entry_t g_fat[SECURE_BLOB_STORE_MAX_SLOTS];

static uint8_t g_slot_buffer[SECURE_BLOB_STORE_SLOT_SIZE];
static uint8_t g_fat_page[SECURE_BLOB_STORE_PAGE_SIZE];
static uint8_t g_aad[SECURE_BLOB_AAD_SIZE];

static void write_u16_le(uint8_t *dst, uint16_t value)
{
    dst[0] = (uint8_t)(value & 0xFFu);
    dst[1] = (uint8_t)((value >> 8) & 0xFFu);
}

static void write_u32_le(uint8_t *dst, uint32_t value)
{
    dst[0] = (uint8_t)(value & 0xFFu);
    dst[1] = (uint8_t)((value >> 8) & 0xFFu);
    dst[2] = (uint8_t)((value >> 16) & 0xFFu);
    dst[3] = (uint8_t)((value >> 24) & 0xFFu);
}

static uint32_t blob_slot_base(uint8_t slot)
{
    return SECURE_BLOB_STORE_FLASH_BASE +
           ((uint32_t)slot * (uint32_t)SECURE_BLOB_STORE_SLOT_SIZE);
}

static bool slot_is_empty(uint8_t slot)
{
    return g_fat[slot].flash_addr == SECURE_BLOB_EMPTY_U32;
}

static bool slot_is_valid(uint8_t slot)
{
    return slot < SECURE_BLOB_STORE_MAX_SLOTS;
}

static secure_blob_store_status_t find_write_slot(uint8_t requested_slot,
                                                  uint8_t *resolved_slot)
{
    if (!resolved_slot) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    if (requested_slot != SECURE_BLOB_STORE_AUTO_SLOT) {
        if (!slot_is_valid(requested_slot)) {
            return SECURE_BLOB_STORE_INVALID_SLOT;
        }
        *resolved_slot = requested_slot;
        return SECURE_BLOB_STORE_OK;
    }

    for (uint8_t slot = 0u; slot < SECURE_BLOB_STORE_MAX_SLOTS; ++slot) {
        if (slot_is_empty(slot)) {
            *resolved_slot = slot;
            return SECURE_BLOB_STORE_OK;
        }
    }

    return SECURE_BLOB_STORE_STORAGE_FULL;
}

static void build_aad(const secure_blob_flash_header_t *header)
{
    uint8_t *dst = g_aad;

    write_u32_le(dst, header->magic);
    dst += 4;
    write_u16_le(dst, header->version);
    dst += 2;
    write_u16_le(dst, header->slot);
    dst += 2;
    write_u32_le(dst, header->plaintext_len);
    dst += 4;
    write_u32_le(dst, header->group_mask);
    dst += 4;
    memcpy(dst, header->owner_pin_hash, sizeof(header->owner_pin_hash));
    dst += sizeof(header->owner_pin_hash);
    memcpy(dst, header->nonce, sizeof(header->nonce));
}

static bool derive_slot_key(const secure_crypto_root_secret_t *root,
                            uint8_t slot,
                            uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE])
{
    static const uint8_t label[] = "blob_slot_key_v1";
    uint8_t info[sizeof(label) - 1u + 4u];

    if (!root || !key) {
        return false;
    }

    memcpy(info, label, sizeof(label) - 1u);
    write_u32_le(info + sizeof(label) - 1u, slot);
    return secure_crypto_hmac_sha256(root->k_master, sizeof(root->k_master),
                                     info, sizeof(info),
                                     key, SECURE_CRYPTO_DERIVED_KEY_SIZE);
}

static secure_blob_store_status_t erase_slot_pages(uint8_t slot)
{
    const uint32_t base = blob_slot_base(slot);

    for (uint32_t offset = 0u;
         offset < (uint32_t)SECURE_BLOB_STORE_SLOT_SIZE;
         offset += (uint32_t)SECURE_BLOB_STORE_PAGE_SIZE) {
        if (flash_simple_erase_page(base + offset) != 0) {
            return SECURE_BLOB_STORE_IO_ERROR;
        }
    }

    return SECURE_BLOB_STORE_OK;
}

static secure_blob_store_status_t commit_fat_entry(uint8_t slot,
                                                   const secure_blob_fat_entry_t *entry)
{
    if (!slot_is_valid(slot) || !entry) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    memset(g_fat_page, 0xFF, sizeof(g_fat_page));
    memcpy(g_fat_page, g_fat, sizeof(g_fat));
    memcpy(g_fat_page + ((size_t)slot * sizeof(*entry)), entry, sizeof(*entry));

    if (flash_simple_erase_page(SECURE_BLOB_STORE_FAT_ADDR) != 0) {
        return SECURE_BLOB_STORE_IO_ERROR;
    }
    if (flash_simple_write(SECURE_BLOB_STORE_FAT_ADDR,
                           g_fat_page,
                           (uint32_t)sizeof(g_fat_page)) != 0) {
        return SECURE_BLOB_STORE_IO_ERROR;
    }

    memcpy(&g_fat[slot], entry, sizeof(*entry));
    return SECURE_BLOB_STORE_OK;
}

static secure_blob_store_status_t load_header(uint8_t slot,
                                              secure_blob_flash_header_t *header)
{
    const secure_blob_fat_entry_t *entry;

    if (!slot_is_valid(slot) || !header) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    entry = &g_fat[slot];
    if (slot_is_empty(slot)) {
        return SECURE_BLOB_STORE_NOT_FOUND;
    }
    if (entry->flash_addr != blob_slot_base(slot) ||
        entry->record_len < sizeof(*header) ||
        entry->record_len > SECURE_BLOB_STORE_SLOT_SIZE ||
        entry->plaintext_len > (SECURE_BLOB_STORE_SLOT_SIZE - sizeof(*header))) {
        return SECURE_BLOB_STORE_CORRUPT;
    }

    flash_simple_read(entry->flash_addr, header, (uint32_t)sizeof(*header));

    if (header->magic != SECURE_BLOB_MAGIC ||
        header->version != SECURE_BLOB_VERSION ||
        header->slot != slot ||
        header->plaintext_len != entry->plaintext_len ||
        entry->record_len != (sizeof(*header) + header->plaintext_len)) {
        return SECURE_BLOB_STORE_CORRUPT;
    }

    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_store_init(void)
{
    flash_simple_read(SECURE_BLOB_STORE_FAT_ADDR, g_fat, sizeof(g_fat));
    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_write(
    uint8_t slot,
    const uint8_t *data,
    size_t len,
    const uint8_t owner_pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE],
    uint32_t group_mask)
{
    secure_blob_flash_header_t *header =
        (secure_blob_flash_header_t *)(void *)g_slot_buffer;
    secure_blob_fat_entry_t entry;
    secure_crypto_root_secret_t root;
    uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    secure_blob_store_status_t rc;
    uint8_t resolved_slot = 0u;

    if (!owner_pin_hash || (len > 0u && !data)) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }
    if (len > (SECURE_BLOB_STORE_SLOT_SIZE - sizeof(*header)) ||
        len > (size_t)UINT32_MAX) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    rc = find_write_slot(slot, &resolved_slot);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if (!security_get_root_secret(&root)) {
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    if (!derive_slot_key(&root, resolved_slot, key)) {
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    memset(g_slot_buffer, 0xFF, sizeof(*header));
    if (!security_generate_nonce(header->nonce, sizeof(header->nonce))) {
        memset(key, 0, sizeof(key));
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    header->magic = SECURE_BLOB_MAGIC;
    header->version = SECURE_BLOB_VERSION;
    header->slot = resolved_slot;
    header->plaintext_len = (uint32_t)len;
    header->group_mask = group_mask;
    memcpy(header->owner_pin_hash, owner_pin_hash, sizeof(header->owner_pin_hash));
    build_aad(header);

    if (len > 0u) {
        if (!secure_crypto_aes_gcm_encrypt(
                key, sizeof(key),
                header->nonce, sizeof(header->nonce),
                g_aad, sizeof(g_aad),
                data, len,
                g_slot_buffer + sizeof(*header),
                header->tag, sizeof(header->tag))) {
            memset(key, 0, sizeof(key));
            memset(&root, 0, sizeof(root));
            return SECURE_BLOB_STORE_CRYPTO_ERROR;
        }
    } else {
        if (!secure_crypto_aes_gcm_encrypt(
                key, sizeof(key),
                header->nonce, sizeof(header->nonce),
                g_aad, sizeof(g_aad),
                NULL, 0u,
                NULL,
                header->tag, sizeof(header->tag))) {
            memset(key, 0, sizeof(key));
            memset(&root, 0, sizeof(root));
            return SECURE_BLOB_STORE_CRYPTO_ERROR;
        }
    }

    memset(key, 0, sizeof(key));
    memset(&root, 0, sizeof(root));

    rc = erase_slot_pages(resolved_slot);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if (flash_simple_write(blob_slot_base(resolved_slot),
                           g_slot_buffer,
                           (uint32_t)(sizeof(*header) + len)) != 0) {
        return SECURE_BLOB_STORE_IO_ERROR;
    }

    entry.flash_addr = blob_slot_base(resolved_slot);
    entry.record_len = (uint32_t)(sizeof(*header) + len);
    entry.plaintext_len = (uint32_t)len;
    entry.reserved = 0u;

    return commit_fat_entry(resolved_slot, &entry);
}

secure_blob_store_status_t blob_read(
    uint8_t slot,
    const uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE],
    uint32_t group_mask,
    uint8_t *out,
    size_t *out_len)
{
    secure_blob_flash_header_t header;
    secure_crypto_root_secret_t root;
    uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    secure_blob_store_status_t rc;

    if (!slot_is_valid(slot) || !pin_hash || !out_len) {
        return !slot_is_valid(slot) ? SECURE_BLOB_STORE_INVALID_SLOT
                                    : SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    rc = load_header(slot, &header);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if (memcmp(pin_hash, header.owner_pin_hash, sizeof(header.owner_pin_hash)) != 0 ||
        (group_mask & header.group_mask) == 0u) {
        return SECURE_BLOB_STORE_PERMISSION_DENIED;
    }

    if (*out_len < header.plaintext_len) {
        *out_len = header.plaintext_len;
        return SECURE_BLOB_STORE_BUFFER_TOO_SMALL;
    }
    if (header.plaintext_len > 0u && !out) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    if (!security_get_root_secret(&root)) {
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    if (!derive_slot_key(&root, slot, key)) {
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    build_aad(&header);
    if (header.plaintext_len > 0u) {
        flash_simple_read(blob_slot_base(slot) + (uint32_t)sizeof(header),
                          g_slot_buffer,
                          header.plaintext_len);
    }

    if (!secure_crypto_aes_gcm_decrypt(
            key, sizeof(key),
            header.nonce, sizeof(header.nonce),
            g_aad, sizeof(g_aad),
            header.plaintext_len > 0u ? g_slot_buffer : NULL,
            header.plaintext_len,
            header.tag, sizeof(header.tag),
            out, *out_len)) {
        memset(key, 0, sizeof(key));
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    memset(key, 0, sizeof(key));
    memset(&root, 0, sizeof(root));
    *out_len = header.plaintext_len;
    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_delete(uint8_t slot)
{
    secure_blob_fat_entry_t erased_entry;
    secure_blob_store_status_t rc;

    if (!slot_is_valid(slot)) {
        return SECURE_BLOB_STORE_INVALID_SLOT;
    }
    if (slot_is_empty(slot)) {
        return SECURE_BLOB_STORE_NOT_FOUND;
    }

    rc = erase_slot_pages(slot);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    memset(&erased_entry, 0xFF, sizeof(erased_entry));
    return commit_fat_entry(slot, &erased_entry);
}

int init_blob_store(void)
{
    return blob_store_init() == SECURE_BLOB_STORE_OK ? 0 : -1;
}
