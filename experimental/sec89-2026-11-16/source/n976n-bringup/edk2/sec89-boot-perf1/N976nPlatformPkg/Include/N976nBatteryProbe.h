/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_PROBE_H_
#define N976N_BATTERY_PROBE_H_
#include <N976nBatteryTypes.h>
#include <N976nBattery.h>
/* Boot-time sequential observations only. No runtime battery, charging or
 * thermal protection interface is published to Windows by this candidate. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Reason;
  UINT64 Factor, FactorStatus, CounterHz, CounterStart, CounterEnd;
  UINT64 SafeToContinue, Attempted;
  N976N_BATTERY_RAW Raw;
  N976N_BATTERY_VALUES Values;
} N976N_BATTERY_PROBE_REPORT;
extern volatile N976N_BATTERY_PROBE_REPORT mN976nBatteryReport;
EFI_STATUS N976nObserveBattery (UINT64 Profile);
#endif
