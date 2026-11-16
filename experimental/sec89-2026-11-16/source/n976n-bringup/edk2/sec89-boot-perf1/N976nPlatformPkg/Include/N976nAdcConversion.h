/* SPDX-License-Identifier: MIT */
#ifndef N976N_ADC_CONVERSION_H
#define N976N_ADC_CONVERSION_H
#include <N976nPlatform.h>
/* Fixed single-channel development observation, no thermal/charge permission. */
typedef struct {
 UINT64 Reached,Status,Reason,Phase,Channel,Hz,Start,End,IrqTick,Polls;
 UINT64 Old[3],After[3];
 UINT64 Registered,Enabled,Disabled,Unregistered,Initialized,Issued;
 UINT64 Irqs,Unexpected,DataRaw,Data12,Ack,Eoi,EoiStatus,Done;
 UINT64 Cleanup,Retired,Restored,Quarantine,ClockDrift,Pending,Active;
 UINT64 Stalled,MaxStalled,InitStep,IrqDisableStatus;
} N976N_ADC_CONVERSION_REPORT;
STATIC_ASSERT(sizeof(N976N_ADC_CONVERSION_REPORT)==41*8,"ADC2 report ABI");
extern volatile N976N_ADC_CONVERSION_REPORT mN976nAdcConversionReport;
EFI_STATUS N976nConvertAdcOnce(UINT64 Profile);
/* No Boot Services/console/IRQ restoration: fixed raw screen then terminal. */
__attribute__((noreturn)) VOID N976nAdcIrqUnsafeStop(EFI_STATUS Status);
#endif
