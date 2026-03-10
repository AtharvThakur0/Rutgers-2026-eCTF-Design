/**
 * @file host_messaging.h
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

#ifndef __HOST_MESSAGING__
#define __HOST_MESSAGING__

#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include "simple_uart.h"

#define CMD_TYPE_LEN sizeof(char)
#define CMD_LEN_LEN sizeof(uint16_t)
#define MSG_MAGIC '%'       // '%' - 0x25

typedef enum {
    LIST_MSG = 'L',         // 'L' - 0x4c
    READ_MSG = 'R',         // 'R' - 0x52
    WRITE_MSG = 'W',        // 'W' - 0x57
    RECEIVE_MSG = 'C',      // 'C' - 0x43
    INTERROGATE_MSG = 'I',  // 'I' - 0x49
    LISTEN_MSG = 'N',       // 'N' - 0x4e
    ACK_MSG = 'A',          // 'A' - 0x41
    DEBUG_MSG = 'D',        // 'D' - 0x44
    ERROR_MSG = 'E',        // 'E' - 0x45
    ECHO_MSG = 0xEE,        // 0xEE - test echo (not a final command)
    DELETE_FILE_MSG = 'X',  // 'X' - 0x58 - delete encrypted blob
    CHANGE_PIN_MSG  = 'P',  // 'P' - 0x50 - change stored PIN
    BOOT_FLAG_MSG   = 'G',  // 'G' - 0x47 - return provisioned boot flag
    DIGEST_MSG      = 'H',  // 'H' - 0x48 - return device_id + file digest
} msg_type_t;

#pragma pack(push, 1) // Tells the compiler not to pad the struct members
typedef struct {
    char magic;    // Should be MSG_MAGIC
    char cmd;      // msg_type_t
    uint16_t len;
} msg_header_t;
#pragma pack(pop) // Tells the compiler to resume padding struct members

typedef enum {
    MSG_OK = 0,
    MSG_BAD_PTR = 1,
    MSG_TIMEOUT = -2,
    MSG_NO_ACK = 2,
    MSG_BAD_LEN = 3,
    // <0 is UART error
} msg_status_t;

#define MSG_HEADER_SIZE sizeof(msg_header_t)

int write_bytes(int uart_id, const void *buf, uint16_t len, bool should_ack);

/** @brief Write len bytes to UART in hex. 2 bytes will be printed for every byte.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type Message type.
 *  @param buf Pointer to the bytes that will be printed.
 *  @param len The number of bytes to print.
 *
 *  @return 0 on success. A negative value on error.
*/
int write_hex(int uart_id, msg_type_t type, const void *buf, size_t len);

/** @brief Send only the message header.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type Message type.
 *  @param len Total length of the payload that will follow.
 *
 *  @return 0 on success. A negative value on error.
 */
int write_header(int uart_id, msg_type_t type, uint16_t len);

/** @brief Send a message to the host, expecting an ack after every 256 bytes.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param type The type of message to send.
 *  @param buf Pointer to a buffer containing the outgoing packet.
 *  @param len The size of the outgoing packet in bytes.
 *
 *  @return 0 on success. A negative value on failure.
*/
int write_packet(int uart_id, msg_type_t type, const void *buf, uint16_t len);

/** @brief Reads a packet from console UART.
 *
 *  @param uart_id The id of the uart where the message is to be sent
 *  @param cmd A pointer to the resulting opcode of the packet. Must not be null.
 *  @param buf A pointer to a buffer to store the incoming packet. Can be null.
 *  @param len A pointer to the resulting length of the packet. Can be null.
 *
 *  @return 0 on success, a negative number on failure
*/
int read_packet(int uart_id, msg_type_t* cmd, void *buf, uint16_t *len);

/** @brief Like read_packet() but returns MSG_TIMEOUT if no magic byte arrives
 *  within @p timeout_ms milliseconds.
 *
 *  @param uart_id       UART to read from.
 *  @param cmd           Receives the opcode.
 *  @param buf           Receives the payload (may be NULL).
 *  @param len           In: buffer capacity (0 = unchecked). Out: actual payload length.
 *  @param timeout_ms    Maximum wait for the first magic byte.
 *
 *  @return MSG_OK on success, MSG_TIMEOUT if no packet arrived, other MSG_* on error.
*/
int read_packet_timeout(int uart_id, msg_type_t *cmd, void *buf, uint16_t *len,
                        uint32_t timeout_ms);

// Macro definitions to print the specified format for error messages
#define print_error(msg) write_packet(CONTROL_INTERFACE, ERROR_MSG, msg, strlen(msg))

/*
 * Debug traffic is useful while bringing up UART and the bootloader, but it
 * must never become a release-side information oracle.  Keep the call sites
 * in place for diagnostics and compile them out unless the build explicitly
 * opts in with -DDEBUG_BUILD.
 */
#ifdef DEBUG_BUILD
#define print_debug(msg) write_packet(CONTROL_INTERFACE, DEBUG_MSG, msg, strlen(msg))
#define print_hex_debug(msg, len) write_hex(CONTROL_INTERFACE, DEBUG_MSG, msg, len)
#else
#define print_debug(msg) ((void)0)
#define print_hex_debug(msg, len) ((void)0)
#endif

// Macro definitions to write ack message
#define write_ack(uart_id) write_packet(uart_id, ACK_MSG, NULL, 0)

#endif
