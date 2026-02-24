/**
 * @file host_messaging.c
 * @author Samuel Meyers
 * @brief eCTF Host Messaging Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>

#define MAGIC '%'
#define NONCE_SIZE 16
#define TAG_SIZE   16

size_t build_packet(uint8_t opcode, uint8_t *nonce, uint8_t *ciphertext, uint16_t cipher_len, uint8_t *tag, uint8_t *message)
{
    size_t offset = 0;

    message[offset] = MAGIC;
    offset += 1;

    message[offset] = opcode;
    offset += 1;

    uint16_t body_len = NONCE_SIZE + cipher_len + TAG_SIZE;

    message[offset]     = body_len & 0xFF;
    message[offset + 1] = (body_len >> 8) & 0xFF;
    offset += 2;

    memcpy(message + offset, nonce, NONCE_SIZE);
    offset += NONCE_SIZE;

    memcpy(message + offset, ciphertext, cipher_len);
    offset += cipher_len;

    memcpy(message + offset, tag, TAG_SIZE);
    offset += TAG_SIZE;

    return offset;
}
