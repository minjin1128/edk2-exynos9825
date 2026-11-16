/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_LIVE_H_
#define N976N_BATTERY_LIVE_H_
#include <N976nBatteryTypes.h>
#include <Lease.h>
typedef struct {
 UINT64 Phase,Status,Reason,Address,Bytes,Published,PreExitChecked,Released;
 UINT64 Gic114,ProducerRetired,ProducerRestored,UnexpectedWrite,ProducerKind;
 N976N_BAT_BUS_REPORT Capture;
 /* Firmware-only frozen evidence; does not change the Windows lease ABI. */
 UINT64 UartRestoreChecked,CompareKind,CompareIndex,CompareExpected,CompareActual;
} N976N_BATTERY_LIVE_REPORT;
extern volatile N976N_BATTERY_LIVE_REPORT mN976nBatteryLiveReport;
EFI_STATUS N976nBatteryLivePublish(UINT64 Profile);
EFI_STATUS N976nBatteryLiveCheck(VOID);
EFI_STATUS N976nBatteryLiveBeforeExit(VOID);
EFI_STATUS N976nBatteryLiveRelease(VOID);
UINT64 N976nBatteryLiveAddress(VOID);
typedef struct {
 UINT64 Phase,Status,Reason,AcquireStatus,ReleaseStatus,Count,Complete,Restored,Quarantine;
 UINT64 Begin[3],End[3],GaugeStatus[3],ChargeStatus[3];
 N976N_BATTERY_RAW Gauge[3];
 N976N_BATTERY_VALUES Values[3];
 N976N_POWER_RAW Charger[3];
 N976N_BAT_BUS_REPORT Acquire,Last,FirstFailure;
} N976N_POWER_DIAG_REPORT;
extern volatile UINT64 mN976nBatteryDiagReached,mN976nBatteryDiagStatus;
extern volatile N976N_POWER_DIAG_REPORT mN976nPowerDiagReport;
EFI_STATUS N976nBatteryDiagnosticStop(EFI_STATUS Status);
#endif
