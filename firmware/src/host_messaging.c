/**
 * @file host_messaging.c
 * @author Samuel Meyers
 * @brief eCTF Host Messaging Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF
 * competition, and may not meet MITRE standards for quality. Use this code at your
 * own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include <stdint.h>
#include <string.h>
#include "host_messaging.h"
#include "simple_uart.h"

#define NONCE_SIZE 16
#define TAG_SIZE   16

static uint32_t uart_frame_timeout_ms(int uart_id)
{
    return (uart_id == CONTROL_INTERFACE) ? UART_RX_TIMEOUT_MS
                                          : UART_XFER_TIMEOUT_MS;
}

size_t build_packet(uint8_t opcode, uint8_t *nonce, uint8_t *ciphertext,
                    uint16_t cipher_len, uint8_t *tag, uint8_t *message)
{
    size_t offset = 0;

    message[offset] = MSG_MAGIC;
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

/* Receive a 4-byte raw ACK packet ('%' 'A' 0x00 0x00) from the peer.
 * Used inside write_packet/write_bytes to avoid re-entering write_packet. */
static int await_ack(int uart_id)
{
    uint32_t timeout_ms = uart_frame_timeout_ms(uart_id);
    int b = uart_readbyte_timeout(uart_id, timeout_ms);

    if (b < 0) return MSG_TIMEOUT;
    if ((uint8_t)b != (uint8_t)MSG_MAGIC) return MSG_NO_ACK;

    b = uart_readbyte_timeout(uart_id, timeout_ms);
    if (b < 0) return MSG_TIMEOUT;
    if ((uint8_t)b != (uint8_t)ACK_MSG) return MSG_NO_ACK;

    if (uart_readbyte_timeout(uart_id, timeout_ms) < 0) return MSG_TIMEOUT;
    if (uart_readbyte_timeout(uart_id, timeout_ms) < 0) return MSG_TIMEOUT;
    return MSG_OK;
}

/* The ectf_tools host protocol (hsm_interface.py):
 *
 *  SENDING (host -> HSM, send_msg):
 *    - Yields header as chunk 0, then body in 256-byte chunks.
 *    - Calls get_ack() after EVERY chunk (including the header).
 *    - Therefore read_packet() must write_ack() after the header AND after
 *      each 256-byte body block.
 *
 *  RECEIVING (host <- HSM, get_raw_msg):
 *    - For opcodes other than ACK and DEBUG ("NACK_MSGS"):
 *      sends send_ack() after the header AND after each 256-byte body block.
 *    - For ACK and DEBUG opcodes: never sends ACKs.
 *    - Therefore write_packet() must await_ack() after the header and after
 *      each 256-byte body block, ONLY for non-ACK/non-DEBUG opcodes.
 */

int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack)
{
    const uint8_t *p = (const uint8_t *)buf;
    uint16_t offset = 0;

    while (offset < len) {
        /* Determine block size: up to 256 bytes. */
        uint16_t block = (uint16_t)(len - offset);
        if (block > 256) block = 256;

        for (uint16_t i = 0; i < block; i++) {
            uart_writebyte(uart_id, p[offset + i]);
        }

        if (should_ack) {
            int ack_rc = await_ack(uart_id);
            if (ack_rc != MSG_OK) return ack_rc;
        }

        offset += block;
    }

    return MSG_OK;
}

int write_header(int uart_id, msg_type_t type, uint16_t len)
{
    msg_header_t hdr;
    hdr.magic = MSG_MAGIC;
    hdr.cmd   = (char)type;
    hdr.len   = len;

    /* Send the 4-byte header. */
    const uint8_t *hp = (const uint8_t *)&hdr;
    for (size_t i = 0; i < MSG_HEADER_SIZE; i++) {
        uart_writebyte(uart_id, hp[i]);
    }

    /* The host ACKs every chunk (header + each 256-byte body block) for all
     * opcodes EXCEPT ACK, DEBUG, and ERROR ("NACK_MSGS" in hsm_interface.py).
     * Await the header ACK before sending the body. */
    bool needs_ack = (type != ACK_MSG && type != DEBUG_MSG && type != ERROR_MSG);

    if (needs_ack) {
        int ack_rc = await_ack(uart_id);
        if (ack_rc != MSG_OK) return ack_rc;
    }

    return MSG_OK;
}

int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len)
{
    int rc = write_header(uart_id, type, len);
    if (rc != MSG_OK) return rc;

    if (len > 0 && buf != NULL) {
        bool needs_ack = (type != ACK_MSG && type != DEBUG_MSG && type != ERROR_MSG);
        return write_bytes(uart_id, buf, len, needs_ack);
    }

    return MSG_OK;
}

int read_packet(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len)
{
    if (cmd == NULL) return MSG_BAD_PTR;

    int b;
    uint32_t timeout_ms = uart_frame_timeout_ms(uart_id);

    /* Drain bytes until we see the magic byte. */
    do {
        b = uart_readbyte_timeout(uart_id, timeout_ms);
        if (b < 0) return MSG_TIMEOUT;
    } while ((uint8_t)b != (uint8_t)MSG_MAGIC);

    /* Read the command byte. */
    b = uart_readbyte_timeout(uart_id, timeout_ms);
    if (b < 0) return MSG_TIMEOUT;
    *cmd = (msg_type_t)b;

    /* Read the 2-byte little-endian payload length. */
    int lo = uart_readbyte_timeout(uart_id, timeout_ms);
    int hi = uart_readbyte_timeout(uart_id, timeout_ms);
    if (lo < 0 || hi < 0) return MSG_TIMEOUT;
    uint16_t pkt_len = (uint16_t)lo | ((uint16_t)hi << 8);

    /* ACK the header chunk - the host is blocked in get_ack() waiting for
     * this before it will send the first body chunk. */
    write_ack(uart_id);

    /* Enforce caller buffer size limit if non-zero. */
    if (len != NULL && *len != 0 && pkt_len > *len) {
        return MSG_BAD_LEN;
    }
    if (len != NULL) {
        *len = pkt_len;
    }

    /* Read body in 256-byte blocks, ACK-ing after each block.
     * The host writes one block then blocks in get_ack() waiting for our ACK
     * before writing the next block. */
    if (pkt_len > 0 && buf != NULL) {
        uint8_t *p = (uint8_t *)buf;
        uint16_t remaining = pkt_len;
        uint16_t offset    = 0;

        while (remaining > 0) {
            uint16_t block = remaining < 256 ? remaining : 256;

            for (uint16_t i = 0; i < block; i++) {
                b = uart_readbyte_timeout(uart_id, timeout_ms);
                if (b < 0) return MSG_TIMEOUT;
                p[offset + i] = (uint8_t)b;
            }

            write_ack(uart_id);
            offset    += block;
            remaining -= block;
        }
    }

    return MSG_OK;
}

int read_packet_timeout(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len,
                        uint32_t timeout_ms)
{
    if (cmd == NULL) return MSG_BAD_PTR;

    int b;
    uint32_t sync_timeout_ms = uart_frame_timeout_ms(uart_id);

    do {
        b = uart_readbyte_timeout(uart_id, timeout_ms);
        if (b < 0) return MSG_TIMEOUT;
    } while ((uint8_t)b != (uint8_t)MSG_MAGIC);

    b = uart_readbyte_timeout(uart_id, sync_timeout_ms);
    if (b < 0) return MSG_TIMEOUT;
    *cmd = (msg_type_t)b;

    int lo = uart_readbyte_timeout(uart_id, sync_timeout_ms);
    int hi = uart_readbyte_timeout(uart_id, sync_timeout_ms);
    if (lo < 0 || hi < 0) return MSG_TIMEOUT;
    uint16_t pkt_len = (uint16_t)lo | ((uint16_t)hi << 8);

    write_ack(uart_id);

    if (len != NULL && *len != 0 && pkt_len > *len) return MSG_BAD_LEN;
    if (len != NULL) *len = pkt_len;

    if (pkt_len > 0 && buf != NULL) {
        uint8_t *p = (uint8_t *)buf;
        uint16_t remaining = pkt_len;
        uint16_t offset    = 0;

        while (remaining > 0) {
            uint16_t block = remaining < 256 ? remaining : 256;

            for (uint16_t i = 0; i < block; i++) {
                b = uart_readbyte_timeout(uart_id, sync_timeout_ms);
                if (b < 0) return MSG_TIMEOUT;
                p[offset + i] = (uint8_t)b;
            }

            write_ack(uart_id);
            offset    += block;
            remaining -= block;
        }
    }

    return MSG_OK;
}

int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len)
{
    static const char hex_chars[] = "0123456789abcdef";
    const uint8_t *p = (const uint8_t *)buf;

    if (len > 0x7FFFu) return -1; /* len*2 must fit in uint16_t */
    uint16_t hex_len = (uint16_t)(len * 2);

    /* Send the framing header manually (stream nibbles without a temp buffer). */
    msg_header_t hdr;
    hdr.magic = MSG_MAGIC;
    hdr.cmd   = (char)type;
    hdr.len   = hex_len;

    const uint8_t *hp = (const uint8_t *)&hdr;
    for (size_t i = 0; i < MSG_HEADER_SIZE; i++) {
        uart_writebyte(uart_id, hp[i]);
    }

    bool needs_ack = (type != ACK_MSG && type != DEBUG_MSG && type != ERROR_MSG);

    if (needs_ack) {
        int ack_rc = await_ack(uart_id);
        if (ack_rc != MSG_OK) return ack_rc;
    }

    /* Stream hex nibbles in 256-byte blocks; ACK after each complete block. */
    uint16_t block_pos = 0;
    for (size_t i = 0; i < len; i++) {
        uart_writebyte(uart_id, (uint8_t)hex_chars[(p[i] >> 4) & 0xF]);
        uart_writebyte(uart_id, (uint8_t)hex_chars[p[i] & 0xF]);
        block_pos += 2;
        if (block_pos == 256) {
            if (needs_ack) {
                int ack_rc = await_ack(uart_id);
                if (ack_rc != MSG_OK) return ack_rc;
            }
            block_pos = 0;
        }
    }

    return MSG_OK;
}
