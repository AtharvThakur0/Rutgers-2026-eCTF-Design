/**
 * @file commands.c
 * @author Samuel Meyers
 * @brief eCTF command handlers — crypto + blob-store + PIN wired together
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF
 * (eCTF). This code is being provided only for educational purposes for the
 * 2026 MITRE eCTF competition, and may not meet MITRE standards for quality.
 * Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 *
 * Flash layout for command-layer state (separate from the blob-data slots):
 *
 *   0x3A000  secure blob FAT  (secure_blob_store.c, 1024 B = 1 page)
 *   0x3A400  name/group table (this file,           1024 B = 1 page)
 *   0x3A800  PIN state        (security.c,          1024 B = 1 page)
 */

#include "commands.h"
#include "filesystem.h"
#include "host_messaging.h"
#include "secure_blob_store.h"
#include "secure_crypto.h"
#include "secure_design.h"
#include "simple_flash.h"
#include <limits.h>
#include <string.h>

/* =========================================================================
 * Name / group metadata table
 *
 * One 1024-byte flash page at 0x3A400 holds one 64-byte entry per blob
 * slot. Stores the file name and owning group_id unencrypted so that
 * LIST_FILES can enumerate files without decrypting blobs.
 * ========================================================================= */

#define BLOB_NAME_TABLE_ADDR 0x3A400u

/* 64 bytes per entry: 32 (name) + 2 (group_id) + 1 (in_use) + 29 (pad).
 * 64 is a multiple of 8, satisfying the MSPM0 ECC-word constraint.
 * 16 × 64 = 1024 bytes fits exactly in one flash page.              */
#define NAME_ENTRY_SIZE 64u
#define NAME_IN_USE_TAG 0x01u

#pragma pack(push, 1)
typedef struct {
  char name[MAX_NAME_SIZE]; /* 32 bytes */
  uint16_t group_id;        /*  2 bytes */
  uint8_t in_use;           /*  1 byte  */
  uint8_t reserved[29];     /* 29 bytes */
} blob_name_entry_t;        /* 64 bytes */
#pragma pack(pop)

_Static_assert(sizeof(blob_name_entry_t) == NAME_ENTRY_SIZE,
               "blob_name_entry_t must be exactly 64 bytes");
_Static_assert((NAME_ENTRY_SIZE % 8u) == 0u,
               "name entry must be ECC-word aligned");
_Static_assert(sizeof(blob_name_entry_t) * SECURE_BLOB_STORE_MAX_SLOTS <=
                   FLASH_PAGE_SIZE,
               "name table must fit in one flash page");

/* RAM shadow of the name table. */
static blob_name_entry_t g_name_table[SECURE_BLOB_STORE_MAX_SLOTS];

/* Scratch page for erase-rewrite of the name table. */
static uint8_t g_name_page[FLASH_PAGE_SIZE];

/* =========================================================================
 * Name table helpers
 * ========================================================================= */

static void load_name_table(void) {
  flash_simple_read(BLOB_NAME_TABLE_ADDR, g_name_table, sizeof(g_name_table));
}

/* Flush the whole name table page to flash. */
static int flush_name_table(void) {
  memset(g_name_page, 0xFF, sizeof(g_name_page));
  memcpy(g_name_page, g_name_table, sizeof(g_name_table));

  if (flash_simple_erase_page(BLOB_NAME_TABLE_ADDR) != 0)
    return -1;
  if (flash_simple_write(BLOB_NAME_TABLE_ADDR, g_name_page,
                         (uint32_t)sizeof(g_name_page)) != 0)
    return -1;
  return 0;
}

/* Write or update a name entry for a slot. */
static int save_name_entry(uint8_t slot, const char *name, uint16_t group_id) {
  if (slot >= SECURE_BLOB_STORE_MAX_SLOTS || name == NULL)
    return -1;

  memset(&g_name_table[slot], 0xFF, sizeof(g_name_table[slot]));
  memcpy(g_name_table[slot].name, name, MAX_NAME_SIZE);
  g_name_table[slot].name[MAX_NAME_SIZE - 1] = '\0'; /* ensure NUL */
  g_name_table[slot].group_id = group_id;
  g_name_table[slot].in_use = NAME_IN_USE_TAG;
  memset(g_name_table[slot].reserved, 0xFF,
         sizeof(g_name_table[slot].reserved));

  return flush_name_table();
}

/* Mark a name entry as deleted. */
static int clear_name_entry(uint8_t slot) {
  if (slot >= SECURE_BLOB_STORE_MAX_SLOTS)
    return -1;

  memset(&g_name_table[slot], 0xFF, sizeof(g_name_table[slot]));
  return flush_name_table();
}

/* True when slot is occupied in both the blob FAT and the name table. */
static bool slot_occupied(uint8_t slot) {
  if (slot >= SECURE_BLOB_STORE_MAX_SLOTS)
    return false;
  if (g_name_table[slot].in_use != NAME_IN_USE_TAG)
    return false;
  /* Cross-check with the blob FAT: flash_addr == UINT32_MAX means empty. */
  return g_fat[slot].flash_addr != UINT32_MAX;
}

/* =========================================================================
 * Public initialisation
 * ========================================================================= */

int init_commands(void) {
  /* Load the blob-store FAT into g_fat (secure_blob_store.c). */
  if (blob_store_init() != SECURE_BLOB_STORE_OK)
    return -1;

  /* Load our name/group shadow from flash. */
  load_name_table();
  return 0;
}

/* =========================================================================
 * pin_gate — centralised PIN check used by every command handler.
 *
 * Returns  0 if the PIN is valid and the HSM is not locked.
 * Returns -1 and sends an appropriate ERROR packet otherwise.
 * ========================================================================= */
static int pin_gate(unsigned char *pin) {
  if (pin_is_locked()) {
    print_error("HSM locked\n");
    return -1;
  }
  if (!check_pin(pin)) {
    if (pin_is_locked()) {
      print_error("HSM locked\n");
    } else {
      print_error("Invalid pin\n");
    }
    return -1;
  }
  return 0;
}

/* =========================================================================
 * Shared static buffers (avoid large stack allocations on Cortex-M0+)
 * ========================================================================= */

/* Scratch buffer for smaller messages. */
static uint8_t g_scratch_buf[512];

typedef union {
  uint8_t read_buf[MAX_NAME_SIZE + MAX_CONTENTS_SIZE];
  receive_response_t receive_resp;
} large_response_buf_t;

/* Shared large buffer for read/interrogate/receive/listen paths. */
static large_response_buf_t g_large_buf;
static interrogate_proof_t g_interrogate_proof;

static int store_received_blob(uint8_t slot, const uint8_t uuid[UUID_SIZE],
                               const file_t *file,
                               const uint8_t *pin) {
  uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE];
  secure_blob_store_status_t rc;

  if (uuid == NULL || file == NULL || pin == NULL) {
    print_error("Transfer payload invalid\n");
    return -1;
  }

  if (file->contents_len > MAX_CONTENTS_SIZE) {
    print_error("Transfer payload too large\n");
    return -1;
  }

  if (!validate_permission(file->group_id, PERM_RECEIVE)) {
    print_error("Invalid permission\n");
    return -1;
  }

  if (!get_pin_hash(pin, PIN_LENGTH, pin_hash)) {
    print_error("Crypto error\n");
    return -1;
  }

  if (save_name_entry(slot, file->name, file->group_id) != 0) {
    memset(pin_hash, 0, sizeof(pin_hash));
    print_error("Name store failed\n");
    return -1;
  }

  /* Pass NULL for zero-byte files to avoid any undefined behaviour with
   * zero-length GCM; blob_write tolerates (NULL, 0). */
  const uint8_t *contents_ptr =
      (file->contents_len == 0) ? NULL : file->contents;
  rc = blob_write(slot, contents_ptr, file->contents_len, uuid, pin_hash,
                  (uint32_t)file->group_id);
  memset(pin_hash, 0, sizeof(pin_hash));

  if (rc != SECURE_BLOB_STORE_OK) {
    clear_name_entry(slot);
    print_error("Store failed\n");
    return -1;
  }

  return 0;
}

/* =========================================================================
 * Helper: enumerate files into a list_response_t from the blob FAT +
 *         name table (used by both list() and listen/interrogate path).
 * ========================================================================= */
void generate_list_files(list_response_t *file_list) {
  file_list->n_files = 0;
  for (uint8_t i = 0;
       i < SECURE_BLOB_STORE_MAX_SLOTS && file_list->n_files < MAX_FILE_COUNT;
       i++) {
    if (slot_occupied(i)) {
      uint32_t idx = file_list->n_files;
      file_list->metadata[idx].slot = i;
      file_list->metadata[idx].group_id = g_name_table[i].group_id;
      memcpy(file_list->metadata[idx].name, g_name_table[i].name,
             MAX_NAME_SIZE);
      file_list->n_files++;
    }
  }
}

/* Minimum write packet: everything except the variable-length contents. */
#define WRITE_CMD_MIN_LEN \
  ((uint16_t)(sizeof(write_command_t) - MAX_CONTENTS_SIZE))

/* =========================================================================
 * STORE_FILE  (opcode 'W')
 *
 * Flow: PIN check → permission check → compute owner_pin_hash →
 *       save name entry → blob_write (AES-256-GCM) → ACK
 * ========================================================================= */
int write(uint16_t pkt_len, uint8_t *buf) {
  write_command_t *cmd = (write_command_t *)buf;
  uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE];
  secure_blob_store_status_t rc;

  /* Reject truncated packets — must have at least the fixed header fields. */
  if (pkt_len < WRITE_CMD_MIN_LEN) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(cmd->pin) != 0)
    return -1;

  if (!validate_permission(cmd->group_id, PERM_WRITE)) {
    print_error("Invalid permission\n");
    return -1;
  }

  /* Validate contents_len against the bytes actually received. */
  if (cmd->contents_len > (uint16_t)(pkt_len - WRITE_CMD_MIN_LEN)) {
    print_error("Packet too short for contents\n");
    return -1;
  }

  /* Zero-byte write: legal, skip all crypto, write an empty blob. */
  if (cmd->contents_len == 0) {
    print_debug("Zero-byte write: skipping crypto\n");

    uint8_t dummy_pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE] = {0};
    if (!get_pin_hash(cmd->pin, PIN_LENGTH, dummy_pin_hash)) {
      print_error("Crypto error\n");
      return -1;
    }
    if (save_name_entry(cmd->slot, cmd->name, cmd->group_id) != 0) {
      memset(dummy_pin_hash, 0, sizeof(dummy_pin_hash));
      print_error("Name store failed\n");
      return -1;
    }
    /* Pass NULL contents and 0 length; blob_write tolerates this. */
    rc = blob_write(cmd->slot, NULL, 0, cmd->uuid, dummy_pin_hash,
                    (uint32_t)cmd->group_id);
    memset(dummy_pin_hash, 0, sizeof(dummy_pin_hash));
    if (rc != SECURE_BLOB_STORE_OK) {
      clear_name_entry(cmd->slot);
      print_error("Store failed\n");
      return -1;
    }
    write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
    return 0;
  }

  /* Bind the encrypted blob to this PIN. */
  if (!get_pin_hash(cmd->pin, PIN_LENGTH, pin_hash)) {
    print_debug("DBG: get_pin_hash FAILED\n");
    print_error("Crypto error\n");
    return -1;
  }
  print_debug("DBG: pin_hash ok\n");

  /* Persist the file name and group unencrypted for LIST_FILES. */
  if (save_name_entry(cmd->slot, cmd->name, cmd->group_id) != 0) {
    memset(pin_hash, 0, sizeof(pin_hash));
    print_debug("DBG: save_name_entry FAILED\n");
    print_error("Name store failed\n");
    return -1;
  }
  print_debug("DBG: name entry saved\n");

  /* Encrypt and write the blob; group_id stored as the access mask. */
  rc = blob_write(cmd->slot, cmd->contents, cmd->contents_len, cmd->uuid, pin_hash,
                  (uint32_t)cmd->group_id);
  memset(pin_hash, 0, sizeof(pin_hash));

  if (rc != SECURE_BLOB_STORE_OK) {
    /* Undo the name entry so the FAT stays consistent. */
    clear_name_entry(cmd->slot);
    print_debug("DBG: blob_write FAILED\n");
    print_error("Store failed\n");
    return -1;
  }
  print_debug("DBG: blob written\n");

  write_packet(CONTROL_INTERFACE, WRITE_MSG, NULL, 0);
  return 0;
}

/* =========================================================================
 * RETRIEVE_FILE  (opcode 'R')
 *
 * Flow: PIN check → group permission check → compute pin_hash →
 *       blob_read (AES-256-GCM decrypt) → stream body with per-chunk ACK
 *
 * Per-chunk ACK is handled transparently by write_packet() / write_bytes().
 * ========================================================================= */
int read(uint16_t pkt_len, uint8_t *buf) {
  read_command_t *cmd = (read_command_t *)buf;
  uint8_t pin_hash[SECURE_BLOB_STORE_PIN_HASH_SIZE];
  size_t out_len = MAX_CONTENTS_SIZE;
  secure_blob_store_status_t rc;

  if (pkt_len < (uint16_t)sizeof(read_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(cmd->pin) != 0)
    return -1;

  if (!slot_occupied(cmd->slot)) {
    print_error("File not found\n");
    return -1;
  }

  if (!validate_permission(g_name_table[cmd->slot].group_id, PERM_READ)) {
    print_error("Invalid permission\n");
    return -1;
  }

  if (!get_pin_hash(cmd->pin, PIN_LENGTH, pin_hash)) {
    print_error("Crypto error\n");
    return -1;
  }

  /* Consolidate name + plaintext into ONE contiguous buffer. */
  memcpy(g_large_buf.read_buf, g_name_table[cmd->slot].name, MAX_NAME_SIZE);

  /* Decrypt directly into the rest of the buffer. */
  rc = blob_read_all(cmd->slot, pin_hash, 0xFFFFFFFFu,
                     g_large_buf.read_buf + MAX_NAME_SIZE, &out_len);
  memset(pin_hash, 0, sizeof(pin_hash));

  if (rc != SECURE_BLOB_STORE_OK) {
    char dbg[64];
    sprintf(dbg, "Read failed with rc=%d\n", (int)rc);
    print_debug(dbg);
    print_error("Read failed\n");
    return -1;
  }

  char dbg_buf[64];
  sprintf(dbg_buf, "Read success: %u bytes\n", (unsigned)out_len);
  print_debug(dbg_buf);

  return write_packet(CONTROL_INTERFACE, READ_MSG,
                      g_large_buf.read_buf, (uint16_t)(MAX_NAME_SIZE + out_len));
}

/* =========================================================================
 * LIST_FILES  (opcode 'L')
 *
 * Returns FAT metadata (slot, group_id, name) for every occupied slot.
 * PIN is still verified (required by the existing ectf host tools).
 * ========================================================================= */
int list(uint16_t pkt_len, uint8_t *buf) {
  list_command_t *cmd = (list_command_t *)buf;
  list_response_t *resp = (list_response_t *)g_scratch_buf;

  if (pkt_len < (uint16_t)sizeof(list_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(cmd->pin) != 0)
    return -1;

  memset(resp, 0, sizeof(*resp));
  generate_list_files(resp);

  pkt_len_t length = LIST_PKT_LEN(resp->n_files);
  write_packet(CONTROL_INTERFACE, LIST_MSG, resp, length);
  return 0;
}

/* =========================================================================
 * DELETE_FILE  (opcode 'X')
 *
 * Flow: PIN check (owner only) → blob_delete (erase flash + update FAT)
 *       → clear name entry → ACK
 * ========================================================================= */
int delete_file(uint16_t pkt_len, uint8_t *buf) {
  delete_file_command_t *cmd = (delete_file_command_t *)buf;
  secure_blob_store_status_t rc;

  if (pkt_len < (uint16_t)sizeof(delete_file_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(cmd->pin) != 0)
    return -1;

  if (!slot_occupied(cmd->slot)) {
    print_error("File not found\n");
    return -1;
  }

  rc = blob_delete(cmd->slot);
  if (rc != SECURE_BLOB_STORE_OK) {
    print_error("Delete failed\n");
    return -1;
  }

  if (clear_name_entry(cmd->slot) != 0) {
    /* FAT already erased; best effort on name table. */
    print_error("Name clear failed\n");
    return -1;
  }

  write_packet(CONTROL_INTERFACE, DELETE_FILE_MSG, NULL, 0);
  return 0;
}

/* =========================================================================
 * CHANGE_PIN  (opcode 'P')
 *
 * Flow: old PIN check (inside pin_change) → derive new hash →
 *       write flash → ACK
 * ========================================================================= */
int change_pin(uint16_t pkt_len, uint8_t *buf) {
  change_pin_command_t *cmd = (change_pin_command_t *)buf;

  if (pkt_len < (uint16_t)sizeof(change_pin_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_is_locked()) {
    print_error("HSM locked\n");
    return -1;
  }

  if (pin_change(cmd->old_pin, PIN_LENGTH, cmd->new_pin, PIN_LENGTH) != 0) {
    if (pin_is_locked()) {
      print_error("HSM locked\n");
    } else {
      print_error("Invalid pin\n");
    }
    return -1;
  }

  write_packet(CONTROL_INTERFACE, CHANGE_PIN_MSG, NULL, 0);
  return 0;
}

/* =========================================================================
 * BOOT_FLAG  (opcode 'G')
 *
 * Returns 32 bytes of HMAC-SHA-256(K_master, "ectf_boot_flag_v1").
 * This value is unique per deployment (K_master is random) and proves
 * the HSM was correctly provisioned with the expected global secrets.
 * No PIN required.
 * ========================================================================= */
int boot_flag(uint16_t pkt_len, uint8_t *buf) {
  static const uint8_t label[] = "ectf_boot_flag_v1";
  static uint8_t s_flag[SECURE_CRYPTO_HMAC_SIZE];
  secure_crypto_root_secret_t root;

  (void)pkt_len;
  (void)buf;

  if (!security_get_root_secret(&root)) {
    print_error("Crypto error\n");
    return -1;
  }

  bool ok =
      secure_crypto_hmac_sha256(root.k_master, sizeof(root.k_master), label,
                                sizeof(label) - 1u, s_flag, sizeof(s_flag));
  memset(&root, 0, sizeof(root));

  if (!ok) {
    print_error("Crypto error\n");
    return -1;
  }

  write_packet(CONTROL_INTERFACE, BOOT_FLAG_MSG, s_flag, sizeof(s_flag));
  return 0;
}

/* =========================================================================
 * DIGEST  (opcode 'H')
 *
 * Request body: 1 byte slot number (defaults to 0 if body is empty).
 * Response: device_id[16] || file_id[16] = 32 bytes.
 *   device_id = HMAC-SHA-256(K_master, "ectf_boot_flag_v1")[:16]
 *   file_id   = SHA-256(slot plaintext)[:16]
 *
 * No PIN required.  Uses group-mask auth via blob_read_all_group_mask().
 * ========================================================================= */
int digest(uint16_t pkt_len, uint8_t *buf) {
  static const uint8_t boot_label[] = "ectf_boot_flag_v1";
  secure_crypto_root_secret_t root;
  uint8_t full_hmac[SECURE_CRYPTO_HMAC_SIZE];
  uint8_t sha256_out[SECURE_CRYPTO_SHA256_DIGEST_SIZE];
  uint8_t response[32]; /* device_id[16] + file_id[16] */
  secure_blob_store_status_t rc;
  size_t plaintext_len = MAX_CONTENTS_SIZE;
  uint8_t slot;
  bool ok;

  slot = (pkt_len >= 1u) ? buf[0] : 0u;

  if (slot >= SECURE_BLOB_STORE_MAX_SLOTS || !slot_occupied(slot)) {
    print_error("File not found\n");
    return -1;
  }

  /* device_id = first 16 bytes of HMAC-SHA-256(K_master, boot_label) */
  if (!security_get_root_secret(&root)) {
    print_error("Crypto error\n");
    return -1;
  }
  ok = secure_crypto_hmac_sha256(root.k_master, sizeof(root.k_master),
                                 boot_label, sizeof(boot_label) - 1u,
                                 full_hmac, sizeof(full_hmac));
  memset(&root, 0, sizeof(root));
  if (!ok) {
    print_error("Crypto error\n");
    return -1;
  }
  memcpy(response, full_hmac, 16u);

  /* Decrypt slot contents (group-mask auth, no PIN required) */
  rc = blob_read_all_group_mask(slot,
                                (uint32_t)g_name_table[slot].group_id,
                                g_large_buf.read_buf,
                                &plaintext_len);
  if (rc != SECURE_BLOB_STORE_OK) {
    print_error("Read failed\n");
    return -1;
  }

  /* file_id = SHA-256(plaintext)[:16] */
  ok = secure_crypto_sha256(g_large_buf.read_buf, plaintext_len,
                            sha256_out, sizeof(sha256_out));
  if (plaintext_len > 0u) {
    memset(g_large_buf.read_buf, 0, plaintext_len);
  }
  if (!ok) {
    print_error("Crypto error\n");
    return -1;
  }
  memcpy(response + 16u, sha256_out, 16u);

  return write_packet(CONTROL_INTERFACE, DIGEST_MSG, response, sizeof(response));
}

/* =========================================================================
 * ECHO  (opcode 0xEE)  — test only, remove before production
 * ========================================================================= */
int echo(uint16_t pkt_len, uint8_t *buf) {
  write_packet(CONTROL_INTERFACE, ECHO_MSG, buf, pkt_len);
  return 0;
}

/* =========================================================================
 * RECEIVE  (opcode 'C')
 * =========================================================================
 *
 * Inter-HSM file transfer. Source-side listen() reads plaintext from the
 * encrypted blob store, and the destination re-encrypts into its own blob slot.
 * ========================================================================= */
int receive(uint16_t pkt_len, uint8_t *buf) {
  receive_command_t *command = (receive_command_t *)buf;
  receive_request_t request;
  receive_challenge_t challenge;
  receive_proof_t proof;
  secure_crypto_root_secret_t root;
  msg_type_t cmd;
  uint16_t len_recv_msg;
  int rc;
  slot_t write_slot;
  pin_t pin;

  if (pkt_len < (uint16_t)sizeof(receive_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(command->pin) != 0)
    return -1;

  write_slot = command->write_slot;
  memcpy(pin, command->pin, sizeof(pin));

  memset(&g_large_buf.receive_resp, 0, sizeof(g_large_buf.receive_resp));
  memset(&request, 0, sizeof(request));

  request.slot = command->read_slot;
  if (!security_generate_nonce((uint8_t *)&request.requester_nonce,
                               sizeof(request.requester_nonce))) {
    print_error("Nonce generation failed\n");
    return -1;
  }

  rc = write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, (void *)&request,
                    sizeof(receive_request_t));
  if (rc != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }

  memset(&challenge, 0, sizeof(challenge));
  len_recv_msg = sizeof(challenge);
  rc = read_packet_timeout(TRANSFER_INTERFACE, &cmd, &challenge,
                           &len_recv_msg, UART_XFER_TIMEOUT_MS);
  if (rc != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }
  if (cmd == ERROR_MSG) {
    /* Target explicitly denied the transfer; relay a useful message. */
    print_error("Could not import file\n");
    return -1;
  }
  if (cmd != RECEIVE_MSG || len_recv_msg != sizeof(challenge) ||
      challenge.slot != request.slot ||
      challenge.requester_nonce != request.requester_nonce) {
    print_error("Opcode mismatch\n");
    return -1;
  }

  if (!validate_permission(challenge.group_id, PERM_RECEIVE)) {
    print_error("Invalid permission\n");
    return -1;
  }

  memset(&proof, 0, sizeof(proof));
  proof.slot = challenge.slot;
  proof.group_id = challenge.group_id;
  proof.requester_nonce = challenge.requester_nonce;
  proof.target_nonce = challenge.target_nonce;
  if (!security_get_root_secret(&root)) {
    print_error("Crypto error\n");
    return -1;
  }
  size_t proof_len = sizeof(proof.proof);
  bool proof_ok = secure_crypto_receive_proof_sign(
      &root, proof.group_id, (const uint8_t *)&challenge, sizeof(challenge),
      proof.proof, &proof_len);
  memset(&root, 0, sizeof(root));
  if (!proof_ok || proof_len != sizeof(proof.proof)) {
    memset(&proof, 0, sizeof(proof));
    print_error("Crypto error\n");
    return -1;
  }

  rc = write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &proof, sizeof(proof));
  if (rc != MSG_OK) {
    memset(&proof, 0, sizeof(proof));
    print_error("No response from target HSM\n");
    return -1;
  }
  memset(&proof, 0, sizeof(proof));

  len_recv_msg = sizeof(g_large_buf.receive_resp);
  rc = read_packet_timeout(TRANSFER_INTERFACE, &cmd, &g_large_buf.receive_resp,
                           &len_recv_msg, UART_XFER_TIMEOUT_MS);
  if (rc != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }
  if (cmd == ERROR_MSG) {
    print_error("Could not import file\n");
    return -1;
  }
  if (cmd != RECEIVE_MSG || len_recv_msg != sizeof(g_large_buf.receive_resp)) {
    print_error("Opcode mismatch\n");
    return -1;
  }

  if (store_received_blob(write_slot, g_large_buf.receive_resp.uuid,
                          &g_large_buf.receive_resp.file, pin) != 0) {
    return -1;
  }

  write_packet(CONTROL_INTERFACE, RECEIVE_MSG, NULL, 0);
  return 0;
}

/* =========================================================================
 * INTERROGATE  (opcode 'I')
 * ========================================================================= */
int interrogate(uint16_t pkt_len, uint8_t *buf) {
  interrogate_command_t *command = (interrogate_command_t *)buf;
  interrogate_request_t request;
  interrogate_challenge_t challenge;
  secure_crypto_root_secret_t root;
  msg_type_t cmd;
  uint16_t len_recv_msg;
  uint8_t proof_message[sizeof(challenge) + sizeof(group_id_t)];
  int rc;

  if (pkt_len < (uint16_t)sizeof(interrogate_command_t)) {
    print_error("Packet too short\n");
    return -1;
  }

  if (pin_gate(command->pin) != 0)
    return -1;

  /* Bug 3 fix: Use static scratch buffer to avoid stack overflow. */
  list_response_t *p_list = (list_response_t *)g_large_buf.read_buf;

  memset(&request, 0, sizeof(request));
  if (!security_generate_nonce((uint8_t *)&request.requester_nonce,
                               sizeof(request.requester_nonce))) {
    print_error("Nonce generation failed\n");
    return -1;
  }

  /* Request a fresh challenge before disclosing which groups this device can
   * receive.  A captured proof cannot be replayed against a new challenge. */
  rc = write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &request,
                    sizeof(request));
  if (rc != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }

  memset(&challenge, 0, sizeof(challenge));
  len_recv_msg = sizeof(challenge);
  if (read_packet_timeout(TRANSFER_INTERFACE, &cmd, &challenge, &len_recv_msg,
                          UART_XFER_TIMEOUT_MS) != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }

  if (cmd != INTERROGATE_MSG || len_recv_msg != sizeof(challenge) ||
      challenge.requester_nonce != request.requester_nonce) {
    print_error("Opcode mismatch\n");
    return -1;
  }

  memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
  g_interrogate_proof.requester_nonce = challenge.requester_nonce;
  g_interrogate_proof.target_nonce = challenge.target_nonce;
  if (!security_get_root_secret(&root)) {
    print_error("Crypto error\n");
    return -1;
  }
  for (size_t i = 0u; i < MAX_PERMS; ++i) {
    size_t sig_len;
    if (!global_permissions[i].receive) {
      continue;
    }
    if (g_interrogate_proof.proof_count >= MAX_PERMS) {
      break;
    }
    interrogate_group_proof_t *entry =
        &g_interrogate_proof.proofs[g_interrogate_proof.proof_count];
    entry->group_id = global_permissions[i].group_id;
    memcpy(proof_message, &challenge, sizeof(challenge));
    memcpy(proof_message + sizeof(challenge), &entry->group_id,
           sizeof(entry->group_id));
    sig_len = sizeof(entry->proof);
    if (!secure_crypto_receive_proof_sign(
            &root, entry->group_id, proof_message, sizeof(proof_message),
            entry->proof, &sig_len) || sig_len != sizeof(entry->proof)) {
      memset(&root, 0, sizeof(root));
      memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
      print_error("Crypto error\n");
      return -1;
    }
    g_interrogate_proof.proof_count++;
  }
  memset(&root, 0, sizeof(root));
  memset(proof_message, 0, sizeof(proof_message));

  if (write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG,
                   &g_interrogate_proof, sizeof(g_interrogate_proof)) != MSG_OK) {
    memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
    print_error("No response from target HSM\n");
    return -1;
  }
  memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));

  /* Read the filtered metadata response from the other HSM. */
  len_recv_msg = sizeof(list_response_t);
  if (read_packet_timeout(TRANSFER_INTERFACE, &cmd, p_list, &len_recv_msg,
                          UART_XFER_TIMEOUT_MS) != MSG_OK) {
    print_error("No response from target HSM\n");
    return -1;
  }
  if (cmd != INTERROGATE_MSG || len_recv_msg > sizeof(list_response_t)) {
    print_error("Opcode mismatch\n");
    return -1;
  }

  /* Forward the exact number of bytes received from the peer back to the host. */
  return write_packet(CONTROL_INTERFACE, INTERROGATE_MSG, p_list, len_recv_msg);
}

/* =========================================================================
 * LISTEN  (opcode 'N')
 * ========================================================================= */
int listen(uint16_t pkt_len, uint8_t *buf) {
  uint8_t uart_buf[sizeof(interrogate_proof_t)];
  msg_type_t cmd;
  pkt_len_t write_length, read_length;
  list_response_t file_list;
  receive_request_t *command;
  receive_challenge_t challenge;
  receive_proof_t proof;
  interrogate_request_t interrogate_request;
  interrogate_challenge_t interrogate_challenge;
  uint8_t interrogate_proof_message[sizeof(interrogate_challenge) + sizeof(group_id_t)];
  bool group_authorized[MAX_PERMS];
  secure_crypto_root_secret_t root;
  size_t plaintext_len;
  bool proof_valid;
  int rc;

  read_length = sizeof(uart_buf);

  memset(uart_buf, 0, sizeof(uart_buf));
  rc = read_packet_timeout(TRANSFER_INTERFACE, &cmd, uart_buf, &read_length,
                           UART_XFER_TIMEOUT_MS);
  if (rc != MSG_OK) {
    print_error("No request on transfer UART\n");
    return -1;
  }

  switch (cmd) {
  case INTERROGATE_MSG:
    if (read_length != sizeof(interrogate_request_t)) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Interrogate denied", 18);
      return -1;
    }
    memcpy(&interrogate_request, uart_buf, sizeof(interrogate_request));
    memset(&interrogate_challenge, 0, sizeof(interrogate_challenge));
    interrogate_challenge.requester_nonce = interrogate_request.requester_nonce;
    if (!security_generate_nonce((uint8_t *)&interrogate_challenge.target_nonce,
                                 sizeof(interrogate_challenge.target_nonce))) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Interrogate denied", 18);
      return -1;
    }
    if (write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &interrogate_challenge,
                     sizeof(interrogate_challenge)) != MSG_OK) {
      return -1;
    }
    read_length = sizeof(g_interrogate_proof);
    if (read_packet_timeout(TRANSFER_INTERFACE, &cmd, &g_interrogate_proof,
                            &read_length, UART_XFER_TIMEOUT_MS) != MSG_OK ||
        cmd != INTERROGATE_MSG || read_length != sizeof(g_interrogate_proof) ||
        g_interrogate_proof.proof_count > MAX_PERMS ||
        g_interrogate_proof.requester_nonce != interrogate_challenge.requester_nonce ||
        g_interrogate_proof.target_nonce != interrogate_challenge.target_nonce ||
        !security_get_root_secret(&root)) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Interrogate denied", 18);
      return -1;
    }
    memset(group_authorized, 0, sizeof(group_authorized));
    for (size_t i = 0u; i < g_interrogate_proof.proof_count; ++i) {
      const interrogate_group_proof_t *entry = &g_interrogate_proof.proofs[i];
      memcpy(interrogate_proof_message, &interrogate_challenge,
             sizeof(interrogate_challenge));
      memcpy(interrogate_proof_message + sizeof(interrogate_challenge),
             &entry->group_id, sizeof(entry->group_id));
      if (!secure_crypto_receive_proof_verify(
              &root, entry->group_id, interrogate_proof_message,
              sizeof(interrogate_proof_message), entry->proof,
              sizeof(entry->proof))) {
        memset(&root, 0, sizeof(root));
        memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
        write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Interrogate denied", 18);
        return -1;
      }
      group_authorized[i] = true;
    }
    memset(&root, 0, sizeof(root));
    memset(interrogate_proof_message, 0, sizeof(interrogate_proof_message));
    if (!security_secure_uart_check_and_update_replay(
            interrogate_challenge.requester_nonce,
            interrogate_challenge.target_nonce, 0u, INTERROGATE_MSG)) {
      memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Interrogate denied", 18);
      return -1;
    }

    memset(&file_list, 0, sizeof(file_list));
    for (uint8_t slot = 0u; slot < SECURE_BLOB_STORE_MAX_SLOTS; ++slot) {
      if (!slot_occupied(slot) || file_list.n_files >= MAX_FILE_COUNT) {
        continue;
      }
      for (size_t i = 0u; i < g_interrogate_proof.proof_count; ++i) {
        if (group_authorized[i] &&
            g_interrogate_proof.proofs[i].group_id == g_name_table[slot].group_id) {
          file_metadata_t *metadata = &file_list.metadata[file_list.n_files++];
          metadata->slot = slot;
          metadata->group_id = g_name_table[slot].group_id;
          memcpy(metadata->name, g_name_table[slot].name, MAX_NAME_SIZE);
          break;
        }
      }
    }
    memset(&g_interrogate_proof, 0, sizeof(g_interrogate_proof));
    write_length = LIST_PKT_LEN(file_list.n_files);
    if (write_packet(TRANSFER_INTERFACE, INTERROGATE_MSG, &file_list,
                     write_length) != MSG_OK) {
      print_error("Transfer write failed\n");
      return -1;
    }
    break;

  case RECEIVE_MSG:
    command = (receive_request_t *)uart_buf;
    if (read_length != sizeof(*command)) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Could not import file", 21);
      return -1;
    }
    if (!slot_occupied(command->slot)) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG,
                   "Could not import file", 21);
      print_error("File not found\n");
      return -1;
    }
    memset(&challenge, 0, sizeof(challenge));
    challenge.slot = command->slot;
    challenge.group_id = g_name_table[command->slot].group_id;
    challenge.requester_nonce = command->requester_nonce;
    if (!security_generate_nonce((uint8_t *)&challenge.target_nonce,
                                 sizeof(challenge.target_nonce))) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG,
                   "Could not import file", 21);
      return -1;
    }

    if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &challenge,
                     sizeof(challenge)) != MSG_OK) {
      print_error("Transfer write failed\n");
      return -1;
    }

    read_length = sizeof(proof);
    if (read_packet_timeout(TRANSFER_INTERFACE, &cmd, &proof, &read_length,
                            UART_XFER_TIMEOUT_MS) != MSG_OK ||
        cmd != RECEIVE_MSG || read_length != sizeof(proof) ||
        proof.slot != challenge.slot || proof.group_id != challenge.group_id ||
        proof.requester_nonce != challenge.requester_nonce ||
        proof.target_nonce != challenge.target_nonce) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Could not import file", 21);
      return -1;
    }
    proof_valid = security_get_root_secret(&root) &&
                  secure_crypto_receive_proof_verify(
                      &root, proof.group_id, (const uint8_t *)&challenge,
                      sizeof(challenge), proof.proof, sizeof(proof.proof));
    memset(&root, 0, sizeof(root));
    if (!proof_valid || !security_secure_uart_check_and_update_replay(
                            proof.requester_nonce, proof.target_nonce,
                            proof.group_id, RECEIVE_MSG)) {
      memset(&proof, 0, sizeof(proof));
      write_packet(TRANSFER_INTERFACE, ERROR_MSG, "Could not import file", 21);
      return -1;
    }
    memset(&proof, 0, sizeof(proof));

    memset(&g_large_buf.receive_resp, 0, sizeof(g_large_buf.receive_resp));
    memcpy(g_large_buf.receive_resp.uuid, g_fat[command->slot].uuid,
           UUID_SIZE);
    g_large_buf.receive_resp.file.in_use = FILE_IN_USE;
    g_large_buf.receive_resp.file.group_id = g_name_table[command->slot].group_id;
    memcpy(g_large_buf.receive_resp.file.name, g_name_table[command->slot].name,
           MAX_NAME_SIZE);
    g_large_buf.receive_resp.file.name[MAX_NAME_SIZE - 1] = '\0';

    plaintext_len = MAX_CONTENTS_SIZE;
    if (blob_read_all_group_mask(command->slot,
                                 (uint32_t)g_name_table[command->slot].group_id,
                                 g_large_buf.receive_resp.file.contents,
                                 &plaintext_len) != SECURE_BLOB_STORE_OK) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG,
                   "Could not import file", 21);
      print_error("Failed to read file\n");
      return -1;
    }

    if (plaintext_len > MAX_CONTENTS_SIZE) {
      write_packet(TRANSFER_INTERFACE, ERROR_MSG,
                   "Could not import file", 21);
      print_error("Transfer payload too large\n");
      return -1;
    }
    g_large_buf.receive_resp.file.contents_len = (uint16_t)plaintext_len;

    write_length = sizeof(g_large_buf.receive_resp);
    if (write_packet(TRANSFER_INTERFACE, RECEIVE_MSG, &g_large_buf.receive_resp,
                     write_length) != MSG_OK) {
      print_error("Transfer write failed\n");
      return -1;
    }
    break;

  default:
    print_error("Bad message type");
    return -1;
  }

  write_packet(CONTROL_INTERFACE, LISTEN_MSG, NULL, 0);
  return 0;
}
