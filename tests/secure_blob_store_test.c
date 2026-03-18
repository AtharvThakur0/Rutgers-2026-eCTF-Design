#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "secure_design.h"
#include "secure_blob_store.h"

typedef struct {
    uint8_t flash[SECURE_BLOB_STORE_APP2_END];
    secure_blob_fat_entry_t fat[SECURE_BLOB_STORE_MAX_SLOTS];
    int erase_calls;
    int write_calls;
    int commit_calls;
    int fail_write_call;
    uint32_t partial_write_len;
} fake_flash_t;

static void fake_flash_init(fake_flash_t *fake) {
    memset(fake, 0, sizeof(*fake));
    memset(fake->flash, 0xff, sizeof(fake->flash));
    memset(fake->fat, 0xff, sizeof(fake->fat));
}

static int fake_erase_page(void *ctx, uint32_t address) {
    fake_flash_t *fake = (fake_flash_t *)ctx;

    if (address % SECURE_BLOB_STORE_PAGE_SIZE != 0U ||
        address + SECURE_BLOB_STORE_PAGE_SIZE > sizeof(fake->flash)) {
        return -1;
    }

    ++fake->erase_calls;
    memset(fake->flash + address, 0xff, SECURE_BLOB_STORE_PAGE_SIZE);
    return 0;
}

static int fake_write(void *ctx, uint32_t address, const void *src, uint32_t len) {
    fake_flash_t *fake = (fake_flash_t *)ctx;
    const uint8_t *bytes = (const uint8_t *)src;
    uint32_t write_len = len;
    int rc = 0;

    if (address + len > sizeof(fake->flash)) {
        return -1;
    }

    ++fake->write_calls;
    if (fake->fail_write_call == fake->write_calls) {
        write_len = fake->partial_write_len;
        if (write_len == 0U || write_len > len) {
            write_len = len > 16U ? 16U : len;
        }
        rc = -1;
    }

    for (uint32_t i = 0; i < write_len; ++i) {
        fake->flash[address + i] &= bytes[i];
    }

    return rc;
}

static void fake_read(void *ctx, uint32_t address, void *dest, uint32_t len) {
    fake_flash_t *fake = (fake_flash_t *)ctx;

    memcpy(dest, fake->flash + address, len);
}

static int fake_commit_fat(void *ctx, const secure_blob_fat_entry_t *fat, size_t fat_count) {
    fake_flash_t *fake = (fake_flash_t *)ctx;

    (void)fat;
    (void)fat_count;
    ++fake->commit_calls;
    return 0;
}

static secure_blob_store_t make_store(fake_flash_t *fake) {
    secure_blob_store_t store;

    memset(&store, 0, sizeof(store));
    store.io.ctx = fake;
    store.io.erase_page = fake_erase_page;
    store.io.write = fake_write;
    store.io.read = fake_read;
    store.io.commit_fat = fake_commit_fat;
    store.fat = fake->fat;
    store.fat_count = SECURE_BLOB_STORE_MAX_SLOTS;
    store.page_size = SECURE_BLOB_STORE_PAGE_SIZE;
    store.app1_base = SECURE_BLOB_STORE_APP1_BASE;
    store.app1_end = SECURE_BLOB_STORE_APP1_END;
    store.app2_base = SECURE_BLOB_STORE_APP2_BASE;
    store.app2_end = SECURE_BLOB_STORE_APP2_END;

    return store;
}

static secure_blob_record_t sample_record(uint8_t state, uint32_t plaintext_len) {
    secure_blob_record_t record;

    memset(&record, 0, sizeof(record));
    record.state = state;
    record.group_id = 0x4321;
    memcpy(record.file_name, "secure.txt", sizeof("secure.txt"));
    for (size_t i = 0; i < sizeof(record.uuid); ++i) {
        record.uuid[i] = (uint8_t)(0x10U + i);
    }
    record.plaintext_len = plaintext_len;
    for (size_t i = 0; i < sizeof(record.content_nonce); ++i) {
        record.content_nonce[i] = (uint8_t)(0x20U + i);
    }
    for (size_t i = 0; i < sizeof(record.content_tag); ++i) {
        record.content_tag[i] = (uint8_t)(0x30U + i);
    }
    for (size_t i = 0; i < sizeof(record.content_hash); ++i) {
        record.content_hash[i] = (uint8_t)(0x40U + i);
    }
    record.writer_signature_len = 64U;
    for (size_t i = 0; i < record.writer_signature_len; ++i) {
        record.writer_signature[i] = (uint8_t)(0x50U + i);
    }

    return record;
}

static void fill_ciphertext(uint8_t *ciphertext, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        ciphertext[i] = (uint8_t)(0xa0U + i);
    }
}

static int records_equal(const secure_blob_record_t *lhs, const secure_blob_record_t *rhs) {
    if (lhs->state != rhs->state ||
        lhs->group_id != rhs->group_id ||
        lhs->plaintext_len != rhs->plaintext_len ||
        lhs->writer_signature_len != rhs->writer_signature_len) {
        return 0;
    }

    return memcmp(lhs->file_name, rhs->file_name, sizeof(lhs->file_name)) == 0 &&
           memcmp(lhs->uuid, rhs->uuid, sizeof(lhs->uuid)) == 0 &&
           memcmp(lhs->content_nonce, rhs->content_nonce, sizeof(lhs->content_nonce)) == 0 &&
           memcmp(lhs->content_tag, rhs->content_tag, sizeof(lhs->content_tag)) == 0 &&
           memcmp(lhs->content_hash, rhs->content_hash, sizeof(lhs->content_hash)) == 0 &&
           memcmp(lhs->writer_signature, rhs->writer_signature, lhs->writer_signature_len) == 0;
}

static int test_serialize_round_trip(void) {
    secure_blob_record_t record = sample_record(SECURE_DESIGN_BLOB_STATE_VALID, 19U);
    uint8_t ciphertext[19];
    uint8_t buffer[SECURE_BLOB_STORE_PREFIX_SIZE + sizeof(ciphertext)];
    secure_blob_record_t parsed;
    const uint8_t *ciphertext_ptr = NULL;
    size_t written = 0;
    size_t ciphertext_len = 0;

    fill_ciphertext(ciphertext, sizeof(ciphertext));
    if (!secure_blob_serialize(
            &record,
            ciphertext,
            sizeof(ciphertext),
            buffer,
            sizeof(buffer),
            &written)) {
        return 1;
    }
    if (written != sizeof(buffer) || !secure_blob_is_valid(buffer, written)) {
        return 1;
    }
    if (!secure_blob_deserialize(buffer, written, &parsed, &ciphertext_ptr, &ciphertext_len)) {
        return 1;
    }

    return records_equal(&record, &parsed) &&
                   ciphertext_len == sizeof(ciphertext) &&
                   memcmp(ciphertext, ciphertext_ptr, sizeof(ciphertext)) == 0
               ? 0 : 1;
}

static int test_incomplete_blob_ignored(void) {
    fake_flash_t fake;
    secure_blob_store_t store;
    secure_blob_record_t record = sample_record(SECURE_DESIGN_BLOB_STATE_WRITING, 8U);
    uint8_t ciphertext[8];
    uint8_t buffer[SECURE_BLOB_STORE_PREFIX_SIZE + sizeof(ciphertext)];
    secure_blob_slot_info_t info;

    fake_flash_init(&fake);
    store = make_store(&fake);
    fill_ciphertext(ciphertext, sizeof(ciphertext));
    if (!secure_blob_serialize(
            &record,
            ciphertext,
            sizeof(ciphertext),
            buffer,
            sizeof(buffer),
            NULL)) {
        return 1;
    }

    memcpy(fake.flash + SECURE_BLOB_STORE_APP1_BASE, buffer, sizeof(buffer));
    memcpy(fake.fat[0].uuid, record.uuid, sizeof(record.uuid));
    fake.fat[0].length = (uint16_t)sizeof(buffer);
    fake.fat[0].padding = 0xffffU;
    fake.fat[0].flash_addr = SECURE_BLOB_STORE_APP1_BASE;

    if (secure_blob_scan_slot(&store, 0U, &info) != SECURE_BLOB_SCAN_WRITING) {
        return 1;
    }

    return secure_blob_load(&store, 0U, &record, ciphertext, sizeof(ciphertext), NULL) == 0 ? 1 : 0;
}

static int test_fat_update_after_complete_blob_write(void) {
    fake_flash_t fake;
    secure_blob_store_t store;
    secure_blob_record_t record = sample_record(SECURE_DESIGN_BLOB_STATE_VALID, 64U);
    uint8_t ciphertext[64];
    uint8_t scratch[SECURE_BLOB_STORE_PREFIX_SIZE + sizeof(ciphertext)];

    fake_flash_init(&fake);
    store = make_store(&fake);
    fill_ciphertext(ciphertext, sizeof(ciphertext));
    fake.fail_write_call = 1;

    if (secure_blob_write(
            &store,
            0U,
            &record,
            ciphertext,
            sizeof(ciphertext),
            scratch,
            sizeof(scratch),
            false,
            NULL) == 0) {
        return 1;
    }

    return fake.commit_calls == 0 && fake.fat[0].flash_addr == UINT32_MAX ? 0 : 1;
}

static int test_recovery_after_partial_write(void) {
    fake_flash_t fake;
    secure_blob_store_t store;
    secure_blob_record_t record = sample_record(SECURE_DESIGN_BLOB_STATE_VALID, 96U);
    uint8_t ciphertext[96];
    uint8_t scratch[SECURE_BLOB_STORE_PREFIX_SIZE + sizeof(ciphertext)];

    fake_flash_init(&fake);
    store = make_store(&fake);
    fill_ciphertext(ciphertext, sizeof(ciphertext));
    fake.fail_write_call = 2;
    fake.partial_write_len = 64U;

    if (secure_blob_write(
            &store,
            1U,
            &record,
            ciphertext,
            sizeof(ciphertext),
            scratch,
            sizeof(scratch),
            false,
            NULL) == 0) {
        return 1;
    }

    if (fake.commit_calls != 1 ||
        secure_blob_scan_slot(&store, 1U, NULL) == SECURE_BLOB_SCAN_VALID) {
        return 1;
    }

    if (secure_blob_recover_fat(&store) != 0) {
        return 1;
    }

    return fake.fat[1].flash_addr == UINT32_MAX &&
                   secure_blob_scan_slot(&store, 1U, NULL) == SECURE_BLOB_SCAN_EMPTY
               ? 0 : 1;
}

static int test_write_and_load_round_trip(void) {
    fake_flash_t fake;
    secure_blob_store_t store;
    secure_blob_record_t record = sample_record(SECURE_DESIGN_BLOB_STATE_VALID, 40U);
    secure_blob_record_t loaded;
    secure_blob_slot_info_t info;
    uint8_t ciphertext[40];
    uint8_t loaded_ciphertext[40];
    uint8_t scratch[SECURE_BLOB_STORE_PREFIX_SIZE + sizeof(ciphertext)];
    size_t loaded_len = 0;
    uint32_t flash_addr = 0;

    fake_flash_init(&fake);
    store = make_store(&fake);
    fill_ciphertext(ciphertext, sizeof(ciphertext));

    if (secure_blob_write(
            &store,
            0U,
            &record,
            ciphertext,
            sizeof(ciphertext),
            scratch,
            sizeof(scratch),
            true,
            &flash_addr) != 0) {
        return 1;
    }
    if (flash_addr != SECURE_BLOB_STORE_APP1_BASE ||
        secure_blob_scan_slot(&store, 0U, &info) != SECURE_BLOB_SCAN_VALID) {
        return 1;
    }
    if (secure_blob_load(
            &store,
            0U,
            &loaded,
            loaded_ciphertext,
            sizeof(loaded_ciphertext),
            &loaded_len) != 0) {
        return 1;
    }

    return records_equal(&record, &loaded) &&
                   loaded_len == sizeof(ciphertext) &&
                   memcmp(ciphertext, loaded_ciphertext, sizeof(ciphertext)) == 0
               ? 0 : 1;
}

struct test_case {
    const char *name;
    int (*fn)(void);
};

int main(void) {
    const struct test_case tests[] = {
        {"serialize_round_trip", test_serialize_round_trip},
        {"incomplete_blob_ignored", test_incomplete_blob_ignored},
        {"fat_update_after_complete_blob_write", test_fat_update_after_complete_blob_write},
        {"recovery_after_partial_write", test_recovery_after_partial_write},
        {"write_and_load_round_trip", test_write_and_load_round_trip},
    };

    for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); ++i) {
        if (tests[i].fn() != 0) {
            fprintf(stderr, "FAIL %s\n", tests[i].name);
            return 1;
        }
        printf("PASS %s\n", tests[i].name);
    }

    return 0;
}
