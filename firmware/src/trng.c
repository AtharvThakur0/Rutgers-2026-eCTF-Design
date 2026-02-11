#include "trng.h"

uint32_t trng_32(int *error) {
  if (error)
    *error = 0;
  TRNG_HW->GPRCM.PWREN = (0x26 << 24) | 0x1;
  while (!(TRNG_HW->GPRCM.STAT & 0x1))
    ; // gprcm status in the lower bits

  TRNG_HW->CLKDIVIDE = TRNG_CLKDIVIDE_RATIO_DIV_BY_2;

  TRNG_HW->CTL = 0x3;
  while (!(TRNG_HW->STAT & TRNG_IIDX_STAT_IRQ_CMD_DONE))
    ;

  if (TRNG_HW->STAT & TRNG_IIDX_STAT_IRQ_CMD_FAIL) {
    *error = -1;
    return 0;
  }

  return TRNG_HW->DATA_CAPTURE;
}
