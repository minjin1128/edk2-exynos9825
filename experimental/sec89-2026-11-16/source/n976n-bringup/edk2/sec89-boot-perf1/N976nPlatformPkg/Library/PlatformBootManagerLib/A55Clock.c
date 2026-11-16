/* SPDX-License-Identifier: MIT
 * Actual N976N Samsung Kernel.tar.gz, drivers/soc/samsung/cal-if/:
 * exynos9820/cmucal-sfr.c:2773-2783,3064-3072 defines CON0 P[13:8],
 * M[25:16], S[2:0], enable31, stable29; each external mux select0/busy16.
 * exynos9820/cmucal-node.c:140-141,564-575 defines the local parents:
 * MUX_CLK_CPUCL0_PLL=0 -> MUX_PLL_CPUCL0 (0=PLL,1=APLL); =1 -> shared path.
 * Both local PLLs have OSCCLK_CPUCL0 as parent, independently of CMUREF.
 * ra.h:33-42 defines internal PLL mux select4/busy7 and FIN_HZ_26M.
 * ra.c:105-117,343-383 establishes bypass and integer PMS calculation.
 * cmucal-node.c:1392 gives DIV_CLK_CPUCL0_CPU no ratio field: do not invent
 * a divisor from the unrelated BUSY/autogating bits at CMU+0x1818.
 * The 442MHz..1.95GHz DT bounds are policy metadata, not a rate-setting API.
 */
#include <N976nA55Clock.h>

#define A55_MUX_SELECT  0x00000001U
#define A55_MUX_BUSY    0x00010000U
#define A55_PLL_SELECT  0x00000010U
#define A55_PLL_BUSY    0x00000080U
#define A55_PLL_STABLE  0x20000000U
#define A55_PLL_ENABLE  0x80000000U

N976N_A55_CLOCK_RESULT
N976nA55ClockDecode (CONST N976N_A55_CLOCK_SAMPLE *Sample)
{
  N976N_A55_CLOCK_RESULT Result = { 0 };
  UINT32 Before;
  UINT32 After;

  if (Sample == NULL) {
    return Result;
  }

  if ((Sample->Mux1000Before == 0xFFFFFFFFU) ||
      (Sample->Mux1000After == 0xFFFFFFFFU)) {
    Result.Reason = N976nA55ClockUnreadable;
    return Result;
  }
  if ((Sample->Mux1000Before != Sample->Mux1000After) ||
      ((Sample->Mux1000Before | Sample->Mux1000After) & A55_MUX_BUSY)) {
    Result.Reason = N976nA55ClockTransient;
    return Result;
  }
  if (Sample->Mux1000Before & A55_MUX_SELECT) {
    /* The switch user's shared-CMU ancestry was not sampled. No guessed Hz. */
    Result.Reason = N976nA55ClockSharedPath;
    Result.Source = N976nA55ClockSourceShared;
    return Result;
  }

  if ((Sample->Mux1008Before == 0xFFFFFFFFU) ||
      (Sample->Mux1008After == 0xFFFFFFFFU)) {
    Result.Reason = N976nA55ClockUnreadable;
    return Result;
  }
  if ((Sample->Mux1008Before != Sample->Mux1008After) ||
      ((Sample->Mux1008Before | Sample->Mux1008After) & A55_MUX_BUSY)) {
    Result.Reason = N976nA55ClockTransient;
    return Result;
  }

  if (Sample->Mux1008Before & A55_MUX_SELECT) {
    Result.Source = N976nA55ClockSourceApll100;
    Before = Sample->Apll100Before;
    After = Sample->Apll100After;
  } else {
    Result.Source = N976nA55ClockSourcePll160;
    Before = Sample->Pll160Before;
    After = Sample->Pll160After;
  }
  if ((Before == 0xFFFFFFFFU) || (After == 0xFFFFFFFFU)) {
    Result.Reason = N976nA55ClockUnreadable;
    return Result;
  }
  if ((Before != After) || ((Before | After) & A55_PLL_BUSY)) {
    Result.Reason = N976nA55ClockTransient;
    return Result;
  }
  if (!(Before & A55_PLL_SELECT)) {
    /* Internal mux selects the documented reference even if PLL is enabled.
     * Samsung disables by selecting this path before changing PLL_ENABLE. */
    Result.Reason = N976nA55ClockOscillator;
    Result.Hertz = N976N_A55_CLOCK_REFERENCE_HZ;
    return Result;
  }
  if (!(Before & A55_PLL_ENABLE)) {
    /* PLL output selected but disabled: do not represent unknown as 0Hz. */
    Result.Reason = N976nA55ClockDisabled;
    return Result;
  }
  if (!(Before & A55_PLL_STABLE)) {
    Result.Reason = N976nA55ClockTransient;
    return Result;
  }

  Result.M = (Before >> 16) & 0x3FFU;
  Result.P = (Before >> 8) & 0x3FU;
  Result.S = Before & 0x7U;
  if ((Result.M == 0) || (Result.P == 0)) {
    Result.Reason = N976nA55ClockInvalidPms;
    return Result;
  }
  Result.Reason = N976nA55ClockPll;
  Result.Hertz = (N976N_A55_CLOCK_REFERENCE_HZ * Result.M) /
                ((UINT64)Result.P << Result.S);
  Result.WithinDtPolicy =
    (Result.Hertz >= N976N_A55_CLOCK_DT_MIN_HZ) &&
    (Result.Hertz <= N976N_A55_CLOCK_DT_MAX_HZ);
  return Result;
}
