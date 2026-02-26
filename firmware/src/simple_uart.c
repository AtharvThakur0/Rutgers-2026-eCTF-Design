/**
 * @file "simple_uart.c"
 * @author Samuel Meyers
 * @brief UART Interrupt Handler Implementation
 * @date 2026
 *
 * This source file is part of an example system for MITRE's 2026 Embedded CTF (eCTF).
 * This code is being provided only for educational purposes for the 2026 MITRE eCTF competition,
 * and may not meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

#include "simple_uart.h"

#define OPEN_CONNECTION 1
#define UART_DRAIN_TIMEOUT_MS 5u
/**********************************************************
 *************** HARDWARE ABSTRACTIONS ********************
 **********************************************************/


void ecdh(void) {
    
}

// This holds the two UART configurations necessary for communication
UART_Regs *uart_inst[] = {UART_0_INST, UART_1_INST};

UART_Regs *get_uart_handle(int uart_id) {
    if (uart_id < 0 || uart_id >= CONFIG_UART_COUNT) {
        // Default on bad input is 0
        return uart_inst[0];
    }
    else {
        return uart_inst[uart_id];
    }
}

/** @brief Reads the next available character from UART.
 *
 *  @param uart_id The index of UART to use
 *  @return The character read.
*/
int uart_readbyte(int uart_id){
    uint8_t data = DL_UART_receiveDataBlocking(get_uart_handle(uart_id));
    return data;
}

int uart_try_readbyte(int uart_id)
{
    UART_Regs *uart = get_uart_handle(uart_id);

    if (DL_UART_isRXFIFOEmpty(uart)) {
        return -1;
    }

    return (int)(uint8_t)DL_UART_receiveData(uart);
}

int uart_readbyte_timeout(int uart_id, uint32_t timeout_ms)
{
    if (timeout_ms == UART_RX_TIMEOUT_MS) {
        for (;;) {
            int b = uart_try_readbyte(uart_id);
            if (b >= 0) {
                return b;
            }
            __asm volatile("nop");
        }
    }

    uint64_t loops64 = (uint64_t)timeout_ms * (uint64_t)UART_TIMEOUT_LOOPS_PER_MS;
    uint32_t loops = (loops64 > UINT32_MAX) ? UINT32_MAX : (uint32_t)loops64;

    while (loops > 0u) {
        int b = uart_try_readbyte(uart_id);
        if (b >= 0) {
            return b;
        }
        loops--;
        __asm volatile("nop");
    }

    return -1;
}

/** @brief Writes a byte to UART.
 *
 *  @param uart_id The index of UART to use
 *  @param data The byte to be written.
*/
void uart_writebyte(int uart_id, uint8_t data) {
    DL_UART_transmitDataBlocking(get_uart_handle(uart_id), data);
}

void uart_drain_rx(int uart_id)
{
    while (uart_readbyte_timeout(uart_id, UART_DRAIN_TIMEOUT_MS) >= 0) {
        /* discard */
    }
}
