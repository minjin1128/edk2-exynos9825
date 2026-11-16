/* SPDX-License-Identifier: MIT */
#ifndef N976N_RUNTIME_POWER_H_
#define N976N_RUNTIME_POWER_H_
#include <N976nPowerOff.h>
#define N976N_RUNTIME_POWER_MAGIC 0x315257505452394EULL
#define N976N_RUNTIME_POWER_PAGES 5U
#define N976N_RUNTIME_POWER_MASK 0x1FULL
#define N976N_RUNTIME_POWER_HCI 0x13D60000ULL
#define N976N_RUNTIME_POWER_RESET (N976N_POWER_PMU+0x3A00ULL)
/* Ordered, disjoint pages. Only the two named PMU registers can be written. */
STATIC CONST UINT64 mN976nRuntimePowerPages[N976N_RUNTIME_POWER_PAGES] = {
  N976N_POWER_PMU, N976N_POWER_PMU+0x3000, N976N_POWER_PMU+0x8000,
  N976N_POWER_GPIO, N976N_RUNTIME_POWER_HCI
};
typedef struct {
  UINT64 Magic, Version, Ready, MapMask;
} N976N_RUNTIME_POWER_READY;
extern EFI_GUID gN976nRuntimePowerReadyGuid;
/* Boot-only readiness protocol. Do not retain or call it after EBS. */
STATIC inline BOOLEAN N976nRuntimePowerReadyValid(CONST N976N_RUNTIME_POWER_READY *P) {
  return P && P->Magic==N976N_RUNTIME_POWER_MAGIC && P->Version==1 &&
    P->Ready==1 && P->MapMask==N976N_RUNTIME_POWER_MASK;
}
#endif
