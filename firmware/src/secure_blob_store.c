#include "secure_blob_store.h"

#include <limits.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "secure_design.h"
#include "sha256_raw.h"
#include "host_messaging.h"

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
    uint8_t blob_tag[SECURE_CRYPTO_HMAC_SIZE];
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

#define SECURE_BLOB_CHUNK_SIZE 256u

secure_blob_fat_entry_t g_fat[SECURE_BLOB_STORE_MAX_SLOTS];

static uint8_t g_scratch_page[SECURE_BLOB_STORE_PAGE_SIZE];
static uint8_t g_chunk_buffer[SECURE_BLOB_CHUNK_SIZE];
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
    char dbg[128];
    if (!slot_is_valid(slot) || !entry) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    sprintf(dbg, "DBG cf: slot=%u addr=0x%lx rec=%lu pt=%lu\n",
            (unsigned)slot, (unsigned long)entry->flash_addr,
            (unsigned long)entry->record_len, (unsigned long)entry->plaintext_len);
    print_debug(dbg);

    memset(g_scratch_page, 0xFF, sizeof(g_scratch_page));
    memcpy(g_scratch_page, g_fat, sizeof(g_fat));
    memcpy(g_scratch_page + ((size_t)slot * sizeof(*entry)), entry, sizeof(*entry));

    if (flash_simple_erase_page(SECURE_BLOB_STORE_FAT_ADDR) != 0) {
        return SECURE_BLOB_STORE_IO_ERROR;
    }
    if (flash_simple_write(SECURE_BLOB_STORE_FAT_ADDR,
                           g_scratch_page,
                           (uint32_t)sizeof(g_scratch_page)) != 0) {
        return SECURE_BLOB_STORE_IO_ERROR;
    }

    memcpy(&g_fat[slot], entry, sizeof(*entry));
    return SECURE_BLOB_STORE_OK;
}

static secure_blob_store_status_t load_header(uint8_t slot,
                                              secure_blob_flash_header_t *header)
{
    const secure_blob_fat_entry_t *entry;
    char dbg[128];

    if (!slot_is_valid(slot) || !header) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    entry = &g_fat[slot];
    if (slot_is_empty(slot)) {
        return SECURE_BLOB_STORE_NOT_FOUND;
    }

    sprintf(dbg, "DBG lh: slot=%u fat_addr=0x%lx rec_len=%lu pt_len=%lu\n",
            (unsigned)slot, (unsigned long)entry->flash_addr, 
            (unsigned long)entry->record_len, (unsigned long)entry->plaintext_len);
    print_debug(dbg);

    if (entry->flash_addr != blob_slot_base(slot) ||
        entry->record_len < sizeof(*header) ||
        entry->record_len > SECURE_BLOB_STORE_SLOT_SIZE ||
        entry->plaintext_len > (SECURE_BLOB_STORE_SLOT_SIZE - sizeof(*header))) {
        print_debug("DBG lh: FAT bounds check FAIL\n");
        return SECURE_BLOB_STORE_CORRUPT;
    }

    flash_simple_read(entry->flash_addr, header, (uint32_t)sizeof(*header));

    sprintf(dbg, "DBG lh: hdr magic=0x%lx ver=%u h_slot=%u h_pt_len=%lu\n",
            (unsigned long)header->magic, (unsigned)header->version,
            (unsigned)header->slot, (unsigned long)header->plaintext_len);
    print_debug(dbg);

    if (header->magic != SECURE_BLOB_MAGIC ||
        header->version != SECURE_BLOB_VERSION ||
        header->slot != slot ||
        header->plaintext_len != entry->plaintext_len ||
        entry->record_len != (sizeof(*header) + header->plaintext_len)) {
        print_debug("DBG lh: header content FAIL\n");
        if (header->magic != SECURE_BLOB_MAGIC) print_debug("  - magic mismatch\n");
        if (header->version != SECURE_BLOB_VERSION) print_debug("  - version mismatch\n");
        if (header->slot != slot) print_debug("  - slot mismatch\n");
        if (header->plaintext_len != entry->plaintext_len) print_debug("  - pt_len mismatch\n");
        if (entry->record_len != (sizeof(*header) + header->plaintext_len)) {
            sprintf(dbg, "  - record_len mismatch: rec=%lu vs exp=%lu\n",
                    (unsigned long)entry->record_len, 
                    (unsigned long)(sizeof(*header) + header->plaintext_len));
            print_debug(dbg);
        }
        return SECURE_BLOB_STORE_CORRUPT;
    }

    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_store_init(void)
{
    static bool s_initialized = false;
    if (s_initialized) {
        return SECURE_BLOB_STORE_OK;
    }
    flash_simple_read(SECURE_BLOB_STORE_FAT_ADDR, g_fat, sizeof(g_fat));
    s_initialized = true;
    return SECURE_BLOB_STORE_OK;
}

#define SECURE_BLOB_MAX_TAGS_SIZE 512u
#define SECURE_BLOB_TAGS_OFFSET (SECURE_BLOB_STORE_SLOT_SIZE - SECURE_BLOB_MAX_TAGS_SIZE)

secure_blob_store_status_t blob_write(
    uint8_t slot,
    const uint8_t *data,
    size_t len,
    const uint8_t owner_pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE],
    uint32_t group_mask)
{
    secure_blob_flash_header_t header;
    secure_blob_fat_entry_t entry;
    secure_crypto_root_secret_t root;
    uint8_t master_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t chunk_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t chunk_tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE];
    uint8_t tags_digest[SECURE_CRYPTO_SHA256_DIGEST_SIZE];
    sha256_raw_ctx_t sha_ctx;
    secure_blob_store_status_t rc;
    uint8_t resolved_slot = 0u;
    uint32_t flash_addr;

    if (!owner_pin_hash || (len > 0u && !data)) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }
    if (len > (SECURE_BLOB_TAGS_OFFSET - sizeof(header)) ||
        len > (size_t)UINT32_MAX) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    rc = find_write_slot(slot, &resolved_slot);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    char _dbg[128];
    sprintf(_dbg, "DBG bw: slot=%u len=%u\n", (unsigned)resolved_slot, (unsigned)len);
    print_debug(_dbg);

    if (!security_get_root_secret(&root)) {
        print_debug("DBG bw: root_secret FAIL\n");
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    if (!derive_slot_key(&root, resolved_slot, master_key)) {
        print_debug("DBG bw: derive_key FAIL\n");
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    memset(&header, 0xFF, sizeof(header));
    if (!security_generate_nonce(header.nonce, sizeof(header.nonce))) {
        print_debug("DBG bw: nonce FAIL\n");
        memset(master_key, 0, sizeof(master_key));
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    header.magic = SECURE_BLOB_MAGIC;
    header.version = SECURE_BLOB_VERSION;
    header.slot = resolved_slot;
    header.plaintext_len = (uint32_t)len;
    header.group_mask = group_mask;
    memcpy(header.owner_pin_hash, owner_pin_hash, sizeof(header.owner_pin_hash));
    build_aad(&header);

    sprintf(_dbg, "DBG bw: writing hdr magic=0x%lx pt_len=%lu sz=%u\n",
            (unsigned long)header.magic, (unsigned long)header.plaintext_len,
            (unsigned)sizeof(header));
    print_debug(_dbg);

    rc = erase_slot_pages(resolved_slot);
    if (rc != SECURE_BLOB_STORE_OK) {
        print_debug("DBG bw: erase FAIL\n");
        memset(master_key, 0, sizeof(master_key));
        memset(&root, 0, sizeof(root));
        return rc;
    }

    sha256_raw_ctx_init(&sha_ctx);

    flash_addr = blob_slot_base(resolved_slot);

    /* Only enter the encryption loop when there is actual plaintext.
     * Calling wc_AesGcmEncrypt with zero-length input is implementation-
     * defined; skip the loop entirely for zero-byte blobs.              */
    if (len > 0u) {
        size_t processed = 0;
        uint32_t chunk_idx = 0;

        while (processed < len) {
            size_t to_proc = len - processed;
            if (to_proc > SECURE_BLOB_CHUNK_SIZE) to_proc = SECURE_BLOB_CHUNK_SIZE;

            secure_crypto_derive_chunk_key(master_key, sizeof(master_key), chunk_idx, chunk_key, sizeof(chunk_key));

            if (!secure_crypto_aes_gcm_encrypt(chunk_key, sizeof(chunk_key), header.nonce, sizeof(header.nonce),
                                               g_aad, sizeof(g_aad), data + processed, to_proc,
                                               g_chunk_buffer, chunk_tag, sizeof(chunk_tag))) {
                print_debug("DBG bw: aes_gcm FAIL\n");
                memset(master_key, 0, sizeof(master_key));
                memset(&root, 0, sizeof(root));
                return SECURE_BLOB_STORE_CRYPTO_ERROR;
            }

            sha256_raw_ctx_update(&sha_ctx, chunk_tag, sizeof(chunk_tag));

            /* Store the chunk ciphertext. */
            if (flash_simple_write(flash_addr + (uint32_t)sizeof(header) + (uint32_t)processed,
                                   g_chunk_buffer, (uint32_t)to_proc) != 0) {
                print_debug("DBG bw: flash_ct FAIL\n");
                memset(master_key, 0, sizeof(master_key));
                memset(&root, 0, sizeof(root));
                return SECURE_BLOB_STORE_IO_ERROR;
            }

            /* Store the chunk tag at the end of the slot. */
            if (flash_simple_write(flash_addr + SECURE_BLOB_TAGS_OFFSET + (chunk_idx * SECURE_CRYPTO_AES_GCM_TAG_SIZE),
                                   chunk_tag, sizeof(chunk_tag)) != 0) {
                print_debug("DBG bw: flash_tag FAIL\n");
                memset(master_key, 0, sizeof(master_key));
                memset(&root, 0, sizeof(root));
                return SECURE_BLOB_STORE_IO_ERROR;
            }

            processed += to_proc;
            chunk_idx++;
        }
    }

    sha256_raw_ctx_final(&sha_ctx, tags_digest);

    /* Use the master_key to HMAC the tags digest into the final blob_tag. */
    if (!secure_crypto_hmac_sha256(master_key, sizeof(master_key),
                                   tags_digest, sizeof(tags_digest),
                                   header.blob_tag, sizeof(header.blob_tag))) {
        print_debug("DBG bw: hmac_tag FAIL\n");
        memset(master_key, 0, sizeof(master_key));
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    memset(master_key, 0, sizeof(master_key));
    memset(&root, 0, sizeof(root));

    if (flash_simple_write(flash_addr, &header, sizeof(header)) != 0) {
        print_debug("DBG bw: flash_hdr FAIL\n");
        return SECURE_BLOB_STORE_IO_ERROR;
    }

    entry.flash_addr = flash_addr;
    entry.record_len = (uint32_t)(sizeof(header) + len);
    entry.plaintext_len = (uint32_t)len;
    entry.reserved = 0u;

    sprintf(_dbg, "DBG bw: entry pt_len=%lu rec_len=%lu len_var=%lu\n",
            (unsigned long)entry.plaintext_len, (unsigned long)entry.record_len,
            (unsigned long)len);
    print_debug(_dbg);

    print_debug("DBG bw: committing FAT\n");
    return commit_fat_entry(resolved_slot, &entry);
}

/* Streaming read state */
static struct {
    uint32_t flash_addr;
    size_t processed;
    size_t total_len;
    uint8_t nonce[SECURE_CRYPTO_AES_GCM_NONCE_SIZE];
    uint8_t master_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
    uint8_t expected_blob_tag[SECURE_CRYPTO_HMAC_SIZE];
    sha256_raw_ctx_t sha_ctx;
} g_read_state;

static secure_blob_store_status_t blob_read_init_internal(
    uint8_t slot,
    const uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE],
    bool require_pin_hash,
    uint32_t group_mask,
    size_t *plaintext_len_out)
{
    secure_blob_flash_header_t header;
    secure_crypto_root_secret_t root;
    secure_blob_store_status_t rc;

    if (!slot_is_valid(slot) || !plaintext_len_out ||
        (require_pin_hash && !pin_hash)) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    rc = load_header(slot, &header);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if ((group_mask & header.group_mask) == 0u) {
        return SECURE_BLOB_STORE_PERMISSION_DENIED;
    }

    if (require_pin_hash &&
        memcmp(pin_hash, header.owner_pin_hash, sizeof(header.owner_pin_hash)) != 0) {
        return SECURE_BLOB_STORE_PERMISSION_DENIED;
    }

    if (!security_get_root_secret(&root)) {
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    if (!derive_slot_key(&root, slot, g_read_state.master_key)) {
        memset(&root, 0, sizeof(root));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }
    memset(&root, 0, sizeof(root));

    build_aad(&header);
    /* g_aad is used in blob_read_chunk. */

    g_read_state.flash_addr = blob_slot_base(slot) + (uint32_t)sizeof(header);
    g_read_state.processed = 0;
    g_read_state.total_len = header.plaintext_len;
    memcpy(g_read_state.nonce, header.nonce, sizeof(header.nonce));
    memcpy(g_read_state.expected_blob_tag, header.blob_tag, sizeof(header.blob_tag));

    sha256_raw_ctx_init(&g_read_state.sha_ctx);

    *plaintext_len_out = header.plaintext_len;
    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_read_init(uint8_t slot,
                                          const uint8_t pin_hash
                                              [SECURE_BLOB_STORE_PIN_HASH_SIZE],
                                          uint32_t group_mask,
                                          size_t *plaintext_len_out)
{
    return blob_read_init_internal(slot, pin_hash, true, group_mask,
                                   plaintext_len_out);
}

secure_blob_store_status_t blob_read_chunk(uint8_t *out, size_t chunk_len)
{
    if (!out || (g_read_state.processed + chunk_len) > g_read_state.total_len) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    size_t chunk_processed = 0;
    while (chunk_processed < chunk_len) {
        size_t to_proc = chunk_len - chunk_processed;
        if (to_proc > SECURE_BLOB_CHUNK_SIZE) to_proc = SECURE_BLOB_CHUNK_SIZE;

        uint32_t chunk_idx = (uint32_t)(g_read_state.processed / SECURE_BLOB_CHUNK_SIZE);
        uint8_t chunk_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
        uint8_t chunk_tag[SECURE_CRYPTO_AES_GCM_TAG_SIZE];

        secure_crypto_derive_chunk_key(g_read_state.master_key, sizeof(g_read_state.master_key),
                                        chunk_idx, chunk_key, sizeof(chunk_key));

        /* Read ciphertext chunk from flash. */
        flash_simple_read(g_read_state.flash_addr + (uint32_t)g_read_state.processed,
                          g_chunk_buffer, (uint32_t)to_proc);

        /* Read the corresponding chunk tag from the end of the slot. */
        uint8_t slot_idx = (uint8_t)((g_read_state.flash_addr - SECURE_BLOB_STORE_FLASH_BASE) /
                                     SECURE_BLOB_STORE_SLOT_SIZE);
        flash_simple_read(blob_slot_base(slot_idx) +
                              SECURE_BLOB_TAGS_OFFSET + (chunk_idx * SECURE_CRYPTO_AES_GCM_TAG_SIZE),
                          chunk_tag, sizeof(chunk_tag));

        /* Accumulate the chunk tag into the tags digest. */
        sha256_raw_ctx_update(&g_read_state.sha_ctx, chunk_tag, sizeof(chunk_tag));

        /* Decrypt the chunk. */
        if (!secure_crypto_aes_gcm_decrypt(chunk_key, sizeof(chunk_key),
                                           g_read_state.nonce, sizeof(g_read_state.nonce),
                                           g_aad, sizeof(g_aad),
                                           g_chunk_buffer, to_proc,
                                           chunk_tag, sizeof(chunk_tag),
                                           out + chunk_processed, to_proc)) {
            return SECURE_BLOB_STORE_CRYPTO_ERROR;
        }

        g_read_state.processed += to_proc;
        chunk_processed += to_proc;
    }

    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_read_finish(void)
{
    uint8_t tags_digest[SECURE_CRYPTO_SHA256_DIGEST_SIZE];
    uint8_t actual_blob_tag[SECURE_CRYPTO_HMAC_SIZE];

    sha256_raw_ctx_final(&g_read_state.sha_ctx, tags_digest);

    if (!secure_crypto_hmac_sha256(g_read_state.master_key, sizeof(g_read_state.master_key),
                                   tags_digest, sizeof(tags_digest),
                                   actual_blob_tag, sizeof(actual_blob_tag))) {
        memset(g_read_state.master_key, 0, sizeof(g_read_state.master_key));
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    memset(g_read_state.master_key, 0, sizeof(g_read_state.master_key));

    if (memcmp(actual_blob_tag, g_read_state.expected_blob_tag, SECURE_CRYPTO_HMAC_SIZE) != 0) {
        return SECURE_BLOB_STORE_CRYPTO_ERROR;
    }

    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_read_all(
    uint8_t slot,
    const uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE],
    uint32_t group_mask,
    uint8_t *out,
    size_t *out_len)
{
    secure_blob_store_status_t rc;
    size_t pt_len;

    rc = blob_read_init(slot, pin_hash, group_mask, &pt_len);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if (*out_len < pt_len) {
        *out_len = pt_len;
        return SECURE_BLOB_STORE_BAD_LEN;
    }

    if (pt_len > 0u) {
        rc = blob_read_chunk(out, pt_len);
        if (rc != SECURE_BLOB_STORE_OK) {
            return rc;
        }
    }

    rc = blob_read_finish();
    if (rc != SECURE_BLOB_STORE_OK) {
        if (out && pt_len > 0u) {
            memset(out, 0, pt_len);
        }
        return rc;
    }

    *out_len = pt_len;
    return SECURE_BLOB_STORE_OK;
}

secure_blob_store_status_t blob_read_all_group_mask(
    uint8_t slot,
    uint32_t group_mask,
    uint8_t *out,
    size_t *out_len)
{
    secure_blob_store_status_t rc;
    size_t pt_len;

    if (!out_len) {
        return SECURE_BLOB_STORE_INVALID_ARGUMENT;
    }

    rc = blob_read_init_internal(slot, NULL, false, group_mask, &pt_len);
    if (rc != SECURE_BLOB_STORE_OK) {
        return rc;
    }

    if (*out_len < pt_len) {
        *out_len = pt_len;
        return SECURE_BLOB_STORE_BAD_LEN;
    }

    if (pt_len > 0u) {
        rc = blob_read_chunk(out, pt_len);
        if (rc != SECURE_BLOB_STORE_OK) {
            return rc;
        }
    }

    rc = blob_read_finish();
    if (rc != SECURE_BLOB_STORE_OK) {
        if (out && pt_len > 0u) {
            memset(out, 0, pt_len);
        }
        return rc;
    }

    *out_len = pt_len;
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
