/**
 * @file    HSM.c
 * @author  Samuel Meyers
 * @brief   Boot code and main function for the HSM
 * @date    2026
 *
 * This source file is part of an example system for MITRE's 2026
 * Embedded CTF (eCTF). This code is being provided only for
 * educational purposes for the 2026 MITRE eCTF competition, and may not
 * meet MITRE standards for quality. Use this code at your own risk!
 *
 * @copyright Copyright (c) 2026 The MITRE Corporation
 */

/*********************** INCLUDES *************************/
#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "simple_flash.h"
#include "host_messaging.h"
#include "commands.h"
#include "filesystem.h"
#include "security.h"
#include "ti_msp_dl_config.h"
#include "status_led.h"
#include "simple_uart.h"
#include "trng.h"

/* Code between this #ifdef and the subsequent #endif will
*  be ignored by the compiler if CRYPTO_EXAMPLE is not set in
*  the Makefile. */
#ifdef CRYPTO_EXAMPLE
/* The simple crypto example included with the reference design is
*  intended to be an example of how you *may* use cryptography in your
*  design. You are not limited nor required to use this interface in
*  your design. It is recommended for newer teams to start by only using
*  the simple crypto library until they have a working design. */
#include "simple_crypto.h"
#endif  //CRYPTO_EXAMPLE

/**********************************************************
 ************************ GLOBALS *************************
 **********************************************************/

static unsigned char uart_buf[MAX_MSG_SIZE];

/**********************************************************
 ******************** HELPER FUNCTIONS ********************
 **********************************************************/




/**********************************************************
 ********************* CORE FUNCTIONS *********************
 **********************************************************/


static void init_runtime_watchdog(void) {
#if !defined(HOST_TEST) && (defined(__MSPM0_HAS_WWDT__) || defined(WWDT0))
    DL_WWDT_reset(WWDT0);
    DL_WWDT_enablePower(WWDT0);
    delay_cycles(POWER_STARTUP_DELAY);
    DL_WWDT_setCoreHaltBehavior(WWDT0, DL_WWDT_CORE_HALT_STOP);
    DL_WWDT_initWatchdogMode(WWDT0,
                             DL_WWDT_CLOCK_DIVIDE_8,
                             DL_WWDT_TIMER_PERIOD_15_BITS,
                             DL_WWDT_RUN_IN_SLEEP,
                             DL_WWDT_WINDOW_PERIOD_0,
                             DL_WWDT_WINDOW_PERIOD_0);
    DL_WWDT_restart(WWDT0);
#endif
}

static void platform_watchdog_kick(void) {
#if !defined(HOST_TEST) && (defined(__MSPM0_HAS_WWDT__) || defined(WWDT0))
    DL_WWDT_restart(WWDT0);
#endif
}

/** @brief Initializes peripherals for system boot.
*/
void init() {
    // Initialize all of the hardware components
    SYSCFG_DL_init();

    // Initialize the hardware TRNG (must follow SYSCFG_DL_init so clocks are up)
    trng_init();

    init_fs();

    // Load pin_hash and fail_count from flash.  On first boot after reflash
    // this provisions the initial hash from HSM_PIN (secrets.h).
    if (pin_init() != 0) {
        print_error("PIN init failed\n");
    }

    // Initialise the encrypted blob store FAT and name/group metadata table.
    if (init_commands() != 0) {
        print_error("Blob store init failed\n");
    }

    init_runtime_watchdog();
}

/**********************************************************
 *********************** MAIN LOOP ************************
 **********************************************************/

int main(void) {
    char output_buf[128] = {0};
    msg_type_t cmd;
    int result;
    uint16_t pkt_len;

    // initialize the device
    init();

    // TRNG startup self-test: two independent 8-byte samples must be
    // non-zero and must differ from each other.
    uint8_t rng_a[8], rng_b[8];
    trng_read_bytes(rng_a, sizeof(rng_a));
    trng_read_bytes(rng_b, sizeof(rng_b));

    bool rng_a_nonzero = false;
    for (int i = 0; i < 8; i++) {
        if (rng_a[i] != 0) { rng_a_nonzero = true; break; }
    }
    bool rng_different = (memcmp(rng_a, rng_b, sizeof(rng_a)) != 0);

    if (rng_a_nonzero && rng_different) {
#ifdef DEBUG_BUILD
        print_debug("TRNG OK\n");
        print_hex_debug(rng_a, sizeof(rng_a));
        print_hex_debug(rng_b, sizeof(rng_b));
#endif
    } else {
        print_error("TRNG FAIL\n");
    }

#ifdef DEBUG_BUILD
    print_debug("BOOT OK\n");
#endif

    // process commands forever
    while (1) {
        platform_watchdog_kick();
#ifdef DEBUG_BUILD
        print_debug("Ready\n");
#endif

        STATUS_LED_ON();

        pkt_len = 0;
        result = read_packet(CONTROL_INTERFACE, &cmd, uart_buf, &pkt_len);
        platform_watchdog_kick();

        if (result != MSG_OK) {
            STATUS_LED_OFF();
            switch (result)
            {
            case MSG_BAD_PTR:
                print_error("Bad cmd pointer\n");
                break;
            case MSG_NO_ACK:
                print_error("Failed to receive ACK from host\n");
                break;
            case MSG_BAD_LEN:
                print_error("Received bad length\n");
                break;
            case MSG_TIMEOUT:
                print_error("UART frame timeout\n");
                break;
            default:
                print_error("Failed to receive cmd from host\n");
                break;
            }
            continue;
        }

        // Handle the requested command
        switch (cmd) {

        // Handle list command
        case LIST_MSG:


            STATUS_LED_OFF();
            list(pkt_len, uart_buf);
            break;

        // Handle read command
        case READ_MSG:
            STATUS_LED_OFF();
            read(pkt_len, uart_buf);
            break;

        // Handle write command
        case WRITE_MSG:
            STATUS_LED_OFF();
            write(pkt_len, uart_buf);
            break;

        // Handle receive command
        case RECEIVE_MSG:
            STATUS_LED_OFF();
            receive(pkt_len, uart_buf);
            break;

        // Handle interrogate command
        case INTERROGATE_MSG:
            STATUS_LED_OFF();
            interrogate(pkt_len, uart_buf);
            break;

        // Handle listen command
        case LISTEN_MSG:
            STATUS_LED_OFF();
            listen(pkt_len, uart_buf);
            break;

        /*
         * These bring-up and diagnostic commands are deliberately absent
         * from release firmware.  The eCTF host interface consists only of
         * L/R/W/N/I/C; leaving extra handlers reachable expands the attack
         * surface and can accidentally expose plaintext or key-derived data.
         */
#ifdef DEBUG_BUILD
        // Handle delete file command (opcode 'X')
        case DELETE_FILE_MSG:
            STATUS_LED_OFF();
            delete_file(pkt_len, uart_buf);
            break;

        // Handle change PIN command (opcode 'P')
        case CHANGE_PIN_MSG:
            STATUS_LED_OFF();
            change_pin(pkt_len, uart_buf);
            break;

        // Handle boot flag command (opcode 'G')
        case BOOT_FLAG_MSG:
            STATUS_LED_OFF();
            boot_flag(pkt_len, uart_buf);
            break;

        // Handle digest command (opcode 'H')
        case DIGEST_MSG:
            STATUS_LED_OFF();
            digest(pkt_len, uart_buf);
            break;

        // Test-only echo command (opcode 0xEE) — remove before production
        case ECHO_MSG:
            STATUS_LED_OFF();
            echo(pkt_len, uart_buf);
            break;
#endif

        // Handle bad command
        default:
            STATUS_LED_OFF();
            sprintf(output_buf, "Invalid Command: %c\n", cmd);
            print_error(output_buf);
            break;
        }
    }
}
