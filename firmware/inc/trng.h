/**
 * @file trng.h
 * @brief MSPM0L2228 hardware TRNG interface (DriverLib-based).
 * @date 2026
 */

#ifndef __TRNG_H__
#define __TRNG_H__

#include <stdint.h>
#include <stddef.h>
#include "ti_msp_dl_config.h"   /* pulls in msp.h + driverlib.h → dl_trng.h */

/**
 * @brief Initialize the hardware TRNG.
 *
 * Must be called once before any call to trng_read_bytes().
 * Sequence: reset → enablePower → 32-cycle delay → setDecimationRate → enable.
 * DL_TRNG_enablePower() MUST follow DL_TRNG_reset(); reversing the order
 * leaves the peripheral bus disconnected and all reads return 0.
 */
void trng_init(void);

/**
 * @brief Fill a buffer with hardware random bytes.
 *
 * Polls DL_TRNG_isCaptureReady() for each 32-bit word and copies bytes into
 * buf.  Triggers a new capture (DL_TRNG_enable) before every poll so the
 * function is safe to call repeatedly without re-running trng_init().
 *
 * @param buf  Destination buffer.
 * @param len  Number of random bytes to write.
 */
void trng_read_bytes(uint8_t *buf, size_t len);

#endif /* __TRNG_H__ */
