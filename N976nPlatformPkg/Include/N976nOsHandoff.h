/* SPDX-License-Identifier: MIT */
#ifndef N976N_OS_HANDOFF_H_
#define N976N_OS_HANDOFF_H_
#include <Uefi.h>

#define N976N_OS_HANDOFF_MAGIC 0x383646464F444E48ULL
/* Phase 1 prepared, 2 checking, 3 BeforeEBS ready, 4 map-key retry,
 * 8 ExitBootServices notification, E0 refused. Phase 8 is not proof of the
 * original ExitBootServices return or kernel execution.
 * Checks: prepared 1, filesystem frozen 2, memory 4, DMA stopped 8,
 * physical firmware timer disabled 10, final cached state consistent 20.
 */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, Profile;
  UINT64 BeforeCount, FailedCount, ExitCount, TimerControl, TimerChecks, Counter;
  UINT64 Reserved[2];
} N976N_OS_HANDOFF_REPORT;
STATIC_ASSERT (sizeof (N976N_OS_HANDOFF_REPORT) == 128, "SEC68 OS handoff ABI");
extern volatile N976N_OS_HANDOFF_REPORT mN976nOsHandoffReport;

EFI_STATUS N976nPrepareOsHandoff (UINT64 Profile);
EFI_STATUS N976nBeginOsHandoff (VOID);
EFI_STATUS N976nFailedOsHandoff (VOID);
EFI_STATUS N976nObserveExitBootServices (VOID);
BOOLEAN N976nOsHandoffAttempted (VOID);
#endif
