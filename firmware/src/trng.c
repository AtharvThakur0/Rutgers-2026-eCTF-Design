/**
 * @file trng.c
 * @brief MSPM0L2228 hardware TRNG implementation (DriverLib-based).
 * @date 2026
 *
 * API reference: ti/driverlib/dl_trng.h (SDK 2.06 / 2.09)
 *
 * Functions that DO exist as __STATIC_INLINE in dl_trng.h:
 *   DL_TRNG_enablePower, DL_TRNG_isPowerEnabled, DL_TRNG_reset,
 *   DL_TRNG_setClockDivider, DL_TRNG_setDecimationRate,
 *   DL_TRNG_sendCommand (+ DL_TRNG_CMD_NORM_FUNC enum value),
 *   DL_TRNG_isCaptureReady, DL_TRNG_isCommandFail,
 *   DL_TRNG_getCapture, DL_TRNG_clearInterruptStatus.
 *
 * Functions that DO NOT exist (removed):
 *   DL_TRNG_enable()   — use DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC)
 *   DL_TRNG_getData()  — use DL_TRNG_getCapture(TRNG)
 */

#include "trng.h"
#include <stdbool.h>

/* Generous poll limit — at 32 MHz and CLKDIV_2, one 32-bit capture takes
 * roughly 2 048 ring-oscillator cycles.  1 000 000 iterations is > 10 ms
 * of margin; if we time out something is badly wrong with the peripheral. */
#define TRNG_POLL_LIMIT  1000000u

void trng_init(void)
{
    /* Step 1: Enable power so the peripheral bus is accessible. */
    DL_TRNG_enablePower(TRNG);

    /* Wait for the power domain to report ready. */
    uint32_t timeout = TRNG_POLL_LIMIT;
    while (!DL_TRNG_isPowerEnabled(TRNG)) {
        if (--timeout == 0u) { return; }
    }

    /* Step 2: Issue a reset to put the peripheral into a known state. */
    DL_TRNG_reset(TRNG);

    /* delay_cycles is not long enough for the GPRCM reset to propagate;
     * spin on a short NOP loop (~32 cycles) instead. */
    delay_cycles(32);

    /* Step 3: Re-enable power AFTER reset.
     * DL_TRNG_reset() disconnects the peripheral bus — register writes are
     * silently dropped until enablePower is called a second time. */
    DL_TRNG_enablePower(TRNG);

    timeout = TRNG_POLL_LIMIT;
    while (!DL_TRNG_isPowerEnabled(TRNG)) {
        if (--timeout == 0u) { return; }
    }

    /* Step 4: Clock and decimation setup.
     * Clock divider /2 → 16 MHz TRNG clock from a 32 MHz MCLK.
     * Decimation rate 4 → one output bit per 4 ring-oscillator samples;
     * slower than RATE_2 but provides more mixing of raw entropy. */
    DL_TRNG_setClockDivider(TRNG, DL_TRNG_CLOCK_DIVIDE_2);
    DL_TRNG_setDecimationRate(TRNG, DL_TRNG_DECIMATION_RATE_4);

    /* Step 5: Clear any stale interrupt flags left from reset. */
    DL_TRNG_clearInterruptStatus(TRNG,
        DL_TRNG_INTERRUPT_CMD_DONE_EVENT    |
        DL_TRNG_INTERRUPT_CMD_FAIL_EVENT    |
        DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
}

void trng_read_bytes(uint8_t *buf, size_t len)
{
    size_t written = 0;

    while (written < len) {
        /* Clear stale flags before issuing the next command. */
        DL_TRNG_clearInterruptStatus(TRNG,
            DL_TRNG_INTERRUPT_CMD_DONE_EVENT    |
            DL_TRNG_INTERRUPT_CMD_FAIL_EVENT    |
            DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

        /* Issue the NORM_FUNC command — this is the correct way to start
         * a single 32-bit capture.  There is no DL_TRNG_enable() in the SDK;
         * DL_TRNG_sendCommand is the only way to drive the TRNG state machine. */
        DL_TRNG_sendCommand(TRNG, DL_TRNG_CMD_NORM_FUNC);

        /* Poll until the capture is ready, bailing on failure or timeout. */
        uint32_t timeout = TRNG_POLL_LIMIT;
        while (!DL_TRNG_isCaptureReady(TRNG)) {
            if (DL_TRNG_isCommandFail(TRNG)) {
                /* Health-test or analogue failure — clear and retry. */
                DL_TRNG_clearInterruptStatus(TRNG,
                    DL_TRNG_INTERRUPT_CMD_DONE_EVENT    |
                    DL_TRNG_INTERRUPT_CMD_FAIL_EVENT    |
                    DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);
                goto next_word;
            }
            if (--timeout == 0u) {
                goto next_word;
            }
        }

        {
            /* Read the captured 32-bit word.  DL_TRNG_getData() does not exist
             * in the SDK; DL_TRNG_getCapture() is the correct function. */
            uint32_t word = DL_TRNG_getCapture(TRNG);

            DL_TRNG_clearInterruptStatus(TRNG,
                DL_TRNG_INTERRUPT_CMD_DONE_EVENT    |
                DL_TRNG_INTERRUPT_CAPTURE_RDY_EVENT);

            /* Copy 1–4 bytes depending on how many still need to be written. */
            size_t take = len - written;
            if (take > sizeof(uint32_t)) {
                take = sizeof(uint32_t);
            }
            for (size_t i = 0; i < take; i++) {
                buf[written++] = (uint8_t)(word >> (8u * i));
            }
        }

        next_word:;
    }
}
