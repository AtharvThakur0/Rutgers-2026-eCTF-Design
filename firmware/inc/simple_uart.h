/**
 * @file "simple_uart.h"
 * @author Samuel Meyers
 * @brief Simple UART Interface Header
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */


#ifndef __SIMPLE_UART__
#define __SIMPLE_UART__

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include <ti/devices/msp/msp.h>
#include <ti/driverlib/dl_gpio.h>
#include "ti_msp_dl_config.h"

/******************************** MACRO DEFINITIONS ********************************/
#define UART_BAUD 115200
#define CONTROL_INTERFACE 0
#define TRANSFER_INTERFACE 1

#define CONFIG_UART_COUNT 2
#define UART_RX_TIMEOUT_MS        UINT32_MAX
#define UART_XFER_TIMEOUT_MS      2000u
#define UART_TIMEOUT_LOOPS_PER_MS 4000u

/******************************** FUNCTION PROTOTYPES ******************************/

/** @brief Reads the next available character from UART.
 *
 *  @param uart_id The index of UART to use
 *  @return The character read.  Otherwise see MAX78000 Error Codes for
 *      a list of return codes.
*/
int uart_readbyte(int uart_id);

/** @brief Try to read a byte from UART without blocking.
 *
 *  @param uart_id The index of UART to use.
 *  @return The received byte, or -1 if no byte is currently available.
*/
int uart_try_readbyte(int uart_id);

/** @brief Poll for a byte on UART for up to @p timeout_ms milliseconds.
 *
 *  Use @ref UART_RX_TIMEOUT_MS for an effectively unbounded wait.
 *
 *  @param uart_id The index of UART to use.
 *  @param timeout_ms Maximum time to wait before returning -1.
 *  @return The received byte, or -1 if no byte arrived before timeout.
*/
int uart_readbyte_timeout(int uart_id, uint32_t timeout_ms);

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use
 *  @param data The byte to be written.
*/
void uart_writebyte(int uart_id, uint8_t data);

/** @brief Drain pending bytes from the UART RX FIFO.
 *
 *  Reads and discards bytes until no byte arrives within a short timeout.
 *
 *  @param uart_id The index of UART to drain.
*/
void uart_drain_rx(int uart_id);

#endif // __SIMPLE_UART__
