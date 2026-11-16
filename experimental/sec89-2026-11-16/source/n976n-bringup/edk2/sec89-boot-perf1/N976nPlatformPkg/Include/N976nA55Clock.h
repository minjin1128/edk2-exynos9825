/* SPDX-License-Identifier: MIT
 * Passive CPUCL0 clock observation. No MMIO, frequency or voltage writes.
 */
#ifndef N976N_A55_CLOCK_H
#define N976N_A55_CLOCK_H

#include <Base.h>

#define N976N_A55_CLOCK_CMU_BASE       0x1D020000ULL
#define N976N_A55_CLOCK_CMU_BYTES      0x8000U
#define N976N_A55_CLOCK_APLL_OFFSET    0x100U
#define N976N_A55_CLOCK_PLL_OFFSET     0x160U
#define N976N_A55_CLOCK_PATH_OFFSET    0x1000U
#define N976N_A55_CLOCK_PARENT_OFFSET  0x1008U
#define N976N_A55_CLOCK_REFERENCE_HZ   26000000ULL
#define N976N_A55_CLOCK_DT_MIN_HZ      442000000ULL
#define N976N_A55_CLOCK_DT_MAX_HZ      1950000000ULL

typedef struct {
  UINT32 Mux1000Before;
  UINT32 Mux1008Before;
  UINT32 Apll100Before;
  UINT32 Pll160Before;
  UINT32 Mux1000After;
  UINT32 Mux1008After;
  UINT32 Apll100After;
  UINT32 Pll160After;
} N976N_A55_CLOCK_SAMPLE;

typedef enum {
  N976nA55ClockNotSampled = 0,
  N976nA55ClockPll = 1,
  N976nA55ClockOscillator = 2,
  N976nA55ClockSharedPath = 3,
  N976nA55ClockTransient = 4,
  N976nA55ClockUnreadable = 5,
  N976nA55ClockDisabled = 6,
  N976nA55ClockInvalidPms = 7
} N976N_A55_CLOCK_REASON;

typedef enum {
  N976nA55ClockSourceUnknown = 0,
  N976nA55ClockSourcePll160 = 1,
  N976nA55ClockSourceApll100 = 2,
  N976nA55ClockSourceShared = 3
} N976N_A55_CLOCK_SOURCE;

typedef struct {
  UINT32 Reason;
  UINT32 Source;
  UINT64 Hertz;
  UINT32 M;
  UINT32 P;
  UINT32 S;
  /* A diagnostic comparison only. Neither this flag nor a decoded rate grants
   * permission to change DVFS, proves an OPP, or validates voltage/temperature. */
  UINT32 WithinDtPolicy;
} N976N_A55_CLOCK_RESULT;

/* The caller owns readable CMU mapping and must gather both observations.
 * Matching observations reject visible transitions; they are not an atomic
 * hardware snapshot or a continuous frequency measurement. Missing samples
 * must not be supplied as zero: a stable zero CON0 denotes oscillator bypass.
 * The unselected PLL is not required to be enabled, readable, or unchanged.
 * Hertz is nonzero only for decoded local PLL or confirmed local bypass. */
N976N_A55_CLOCK_RESULT
N976nA55ClockDecode (CONST N976N_A55_CLOCK_SAMPLE *Sample);

#endif
