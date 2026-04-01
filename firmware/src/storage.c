/* Defines the FAT data structure fat_entry_t
 * and the FAT security extension data structure fat_ext_t
 */

#include "secure_crypto.h"
#include "secure_design.h"
#include "security.h"
#include "simple_crypto.h"
#include "simple_flash.h"
#include <stdint.h>
#include <string.h>

typedef struct __attribute__((packed)) {
  // __attribute__((packed)) tells the compiler to remove padding
  uint8_t uuid[16];
  uint16_t length;
  uint16_t padding;
  uint32_t addr;
} fat_entry_t;

typedef struct __attribute__((packed)) {
  uint32_t file_addr;
  uint16_t group_id;
  group_permission_t perm;
  uint32_t counter;
  uint8_t metadata_HMAC[32];
  // HMAC(GroupKey, UUID + GroupID + Permissions + Counter)
} fat_ext_t;

#define FAT_BASE_ADDRESS 0x3A000
#define MAX_FAT_ENTRIES 8
// #define FLASH_PAGE_SIZE    1024

#define APP2_BASE_ADDRESS 0x3A400

/*
 * Magic stamped at FAT_PAGE_MAGIC_OFFSET inside every valid FAT page.
 * If the page is blank (all-0xFF after a power-loss-during-erase) the magic
 * is absent; storage_init() detects this and re-initialises the FAT to an
 * empty state so the device stays operational rather than reading garbage.
 */
#define FAT_PAGE_MAGIC 0xCAFEF00Du
#define FAT_PAGE_MAGIC_OFFSET                                                  \
  ((uint32_t)(MAX_FAT_ENTRIES * sizeof(fat_entry_t)))

const fat_entry_t *flash_fat = (const fat_entry_t *)FAT_BASE_ADDRESS;
const fat_ext_t *flash_ext = (const fat_ext_t *)APP2_BASE_ADDRESS;

/*
 * HMAC message: UUID(16) | group_id LE16(2) | read(1) | write(1) | receive(1) |
 * counter LE32(4) = 27 bytes total.  Fields are serialised explicitly so the
 * layout is independent of struct padding or endianness of the host.
 */
#define METADATA_HMAC_MSG_LEN 27u

static void build_hmac_msg(const uint8_t uuid[16], const fat_ext_t *ext,
                           uint8_t out[METADATA_HMAC_MSG_LEN]) {
  uint8_t *p = out;

  memcpy(p, uuid, 16);
  p += 16;

  p[0] = (uint8_t)(ext->group_id & 0xFFu);
  p[1] = (uint8_t)((ext->group_id >> 8) & 0xFFu);
  p += 2;

  p[0] = ext->perm.read ? 1u : 0u;
  p[1] = ext->perm.write ? 1u : 0u;
  p[2] = ext->perm.receive ? 1u : 0u;
  p += 3;

  p[0] = (uint8_t)(ext->counter & 0xFFu);
  p[1] = (uint8_t)((ext->counter >> 8) & 0xFFu);
  p[2] = (uint8_t)((ext->counter >> 16) & 0xFFu);
  p[3] = (uint8_t)((ext->counter >> 24) & 0xFFu);
}

/*
 * Derive the per-group metadata authentication key.
 * Uses xfer_root_key (distinct from the file encryption key) so that the
 * auth key and the enc key are never the same material.
 */
static bool derive_group_auth_key(const secure_crypto_root_secret_t *root,
                                  uint16_t group_id,
                                  uint8_t key[SECURE_CRYPTO_DERIVED_KEY_SIZE]) {
  return secure_crypto_derive_xfer_root_key(root, group_id, key,
                                            SECURE_CRYPTO_DERIVED_KEY_SIZE);
}

static int fat_page_is_valid(void) {
  uint32_t magic;
  memcpy(&magic, (const uint8_t *)FAT_BASE_ADDRESS + FAT_PAGE_MAGIC_OFFSET,
         sizeof(magic));
  return (magic == FAT_PAGE_MAGIC) ? 1 : 0;
}

/*
 * Must be called once at boot before any other storage function.
 *
 * Handles the power-loss-after-erase case: if the FAT page was erased but
 * not yet rewritten (magic absent) the device would otherwise read garbage
 * entries on every subsequent access.  We detect the blank page via the
 * missing magic and write a clean, all-empty FAT so the device stays
 * functional.
 *
 * Returns  0 if the FAT was intact.
 * Returns -1 if the FAT was corrupt/blank and had to be reset (all files lost).
 */
int storage_init(void) {
  if (fat_page_is_valid()) {
    return 0;
  }

  uint8_t page_buffer[FLASH_PAGE_SIZE];
  memset(page_buffer, 0xFF, FLASH_PAGE_SIZE);
  *(uint32_t *)(page_buffer + FAT_PAGE_MAGIC_OFFSET) = FAT_PAGE_MAGIC;

  flash_simple_erase_page((uint32_t)flash_fat);
  flash_simple_write((uint32_t)FAT_BASE_ADDRESS, page_buffer, FLASH_PAGE_SIZE);
  return -1;
}

void get_fat_entry(int index, fat_entry_t *out_fat_entry) {
  if (index >= MAX_FAT_ENTRIES) {
    return;
  }
  memcpy(out_fat_entry, &flash_fat[index], sizeof(fat_entry_t));
}

int update_fat_entry(int index, fat_entry_t *in_fat_entry) {
  if (index >= MAX_FAT_ENTRIES) {
    return -1;
  }

  uint8_t page_buffer[FLASH_PAGE_SIZE];

  memcpy(page_buffer, (void *)FAT_BASE_ADDRESS, FLASH_PAGE_SIZE);
  memcpy(&page_buffer[index * sizeof(fat_entry_t)], in_fat_entry,
         sizeof(fat_entry_t));

  /* Stamp the magic so storage_init() recognises a completed write after reset.
   * Power-loss between the erase below and the write completing will leave the
   * page blank (no magic); storage_init() will detect and recover gracefully.
   */
  *(uint32_t *)(page_buffer + FAT_PAGE_MAGIC_OFFSET) = FAT_PAGE_MAGIC;

  flash_simple_erase_page((uint32_t)flash_fat);
  flash_simple_write((uint32_t)FAT_BASE_ADDRESS, (uint8_t *)page_buffer,
                     FLASH_PAGE_SIZE);

  return 0;
}

int counter(int index) {
  if (index < 0 || index >= MAX_FAT_ENTRIES) {
    return -1;
  }

  uint8_t page_buffer[FLASH_PAGE_SIZE];
  fat_ext_t *entries = (fat_ext_t *)page_buffer;

  memcpy(page_buffer, (void *)APP2_BASE_ADDRESS, FLASH_PAGE_SIZE);
  entries[index].counter++;

  /* Recalculate HMAC over UUID + GroupID + Permissions + Counter */
  fat_entry_t fat_entry;
  get_fat_entry(index, &fat_entry);

  secure_crypto_root_secret_t root;
  uint8_t group_key[SECURE_CRYPTO_DERIVED_KEY_SIZE];
  uint8_t hmac_msg[METADATA_HMAC_MSG_LEN];

  if (!security_get_root_secret(&root)) {
    return -1;
  }
  if (!derive_group_auth_key(&root, entries[index].group_id, group_key)) {
    memset(&root, 0, sizeof(root));
    return -1;
  }

  build_hmac_msg(fat_entry.uuid, &entries[index], hmac_msg);

  bool hmac_ok = secure_crypto_hmac_sha256(
      group_key, sizeof(group_key), hmac_msg, sizeof(hmac_msg),
      entries[index].metadata_HMAC, sizeof(entries[index].metadata_HMAC));

  memset(&root, 0, sizeof(root));
  memset(group_key, 0, sizeof(group_key));
  memset(hmac_msg, 0, sizeof(hmac_msg));

  if (!hmac_ok) {
    return -1;
  }

  flash_simple_erase_page((uint32_t)flash_ext);
  flash_simple_write((uint32_t)APP2_BASE_ADDRESS, (uint8_t *)page_buffer,
                     FLASH_PAGE_SIZE);

  return 0;
}

int verify_file_metadata(int index, fat_entry_t *fat_entry,
                         uint8_t *group_key) {
  fat_ext_t current_metadata;
  uint8_t expected_hmac[32];
  uint8_t hmac_msg[METADATA_HMAC_MSG_LEN];

  if (index < 0 || index >= MAX_FAT_ENTRIES) {
    return -1;
  }

  memcpy(&current_metadata, &flash_ext[index], sizeof(fat_ext_t));

  if (current_metadata.file_addr != fat_entry->addr) {
    return -1;
  }

  /* Recompute the HMAC and compare against the stored value */
  build_hmac_msg(fat_entry->uuid, &current_metadata, hmac_msg);

  if (!secure_crypto_hmac_sha256(group_key, SECURE_CRYPTO_DERIVED_KEY_SIZE,
                                 hmac_msg, sizeof(hmac_msg), expected_hmac,
                                 sizeof(expected_hmac))) {
    return -1;
  }

  if (memcmp(expected_hmac, current_metadata.metadata_HMAC,
             sizeof(expected_hmac)) != 0) {
    return -1;
  }

  return 0;
}
