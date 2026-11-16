/* SPDX-License-Identifier: MIT */
#ifndef N976N_POWER_OFF_H_
#define N976N_POWER_OFF_H_
#include <N976nPlatform.h>
#define N976N_POWER_ADMISSION_MAGIC 0x3236444152574F50ULL
#define N976N_POWER_REPORT_MAGIC 0x3236545052574F50ULL
#define N976N_POWER_PMU 0x15860000ULL
#define N976N_POWER_GPIO 0x15850000ULL
#define N976N_POWER_HOLD (N976N_POWER_PMU + 0x030CULL)
#define N976N_POWER_CLEAR (N976N_POWER_PMU + 0x830CULL)
typedef struct {
  UINT64 Magic, Version, Size, Admitted, Reason, PmuBase, GpioBase;
  UINT64 PowerPin, DownPin, PowerPhandle, DownPhandle, Checks;
} N976N_POWER_ADMISSION;
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Reason, Profile, Checks;
  UINT64 Seconds, Trigger, PsciReturn, PsHoldBefore, PsHoldAfter;
  UINT64 KeyRaw, MmuChecks, Attempts;
} N976N_POWER_REPORT;
STATIC_ASSERT(sizeof(N976N_POWER_ADMISSION)==96, "SEC62 power admission ABI");
STATIC_ASSERT(sizeof(N976N_POWER_REPORT)==128, "SEC62 power report ABI");
extern EFI_GUID gN976nPowerAdmissionGuid;
extern volatile N976N_POWER_REPORT mN976nPowerReport;
BOOLEAN EFIAPI N976nAdmitPower (CONST VOID *Dtb, UINT64 Bytes, N976N_POWER_ADMISSION *Out);
EFI_STATUS N976nPreparePowerOff (CONST N976N_PLATFORM_HANDOFF *Handoff, BOOLEAN StorageClosed);
VOID N976nPowerOffWait (CONST N976N_PLATFORM_HANDOFF *Handoff, BOOLEAN StorageClosed,
  EFI_STATUS (*Black)(VOID), VOID (*Refresh)(VOID));
VOID EFIAPI N976nPowerReadyCheckpoint (VOID);
#endif
