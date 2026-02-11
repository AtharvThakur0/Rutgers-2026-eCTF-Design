#include "ti/devices/msp/peripherals/hw_trng.h"

#define TRNG_BASE_ADDR 0x40444000
#define TRNG_HW ((volatile TRNG_Regs *)TRNG_BASE_ADDR)

/*
 * @brief Generates a 32 bit random number using the hardware True Random Number
 * Generator.
 * @param error Pointer to an integer to store error codes.
 * @return 32 bit random number.
 */

uint32_t trng_32(int *error);
