/* SPDX-License-Identifier: MIT */
#ifndef N976N_ADC_PREFLIGHT_H
#define N976N_ADC_PREFLIGHT_H
#include <N976nPlatform.h>
#define N976N_ADC_ADMISSION_MAGIC 0x314144434647504EULL
#define N976N_ADC_PREFLIGHT_WORDS 20U
/* Identity only: no permission to access ADC peripheral or change clocks/IRQ. */
typedef struct {
 UINT64 Magic,Version,Size,Profile,Admitted,Reason,Checks;
 UINT64 Adc,AdcBytes,Cmu,Irq,Clock,ReadPlan;
} N976N_ADC_ADMISSION;
STATIC_ASSERT(sizeof(N976N_ADC_ADMISSION)==104,"ADC identity HOB ABI");
extern EFI_GUID gN976nAdcPreflightGuid;
BOOLEAN EFIAPI N976nAdmitAdcPreflight(CONST VOID *,UINT64,UINT64,N976N_ADC_ADMISSION *);
typedef struct {
 UINT64 Reached,Status,Reason,IrqEnabled,Hz,Begin,End,Valid;
 UINT32 Raw[N976N_ADC_PREFLIGHT_WORDS];
} N976N_ADC_PREFLIGHT_REPORT;
STATIC_ASSERT(sizeof(N976N_ADC_PREFLIGHT_REPORT)==144,"ADC preflight report");
extern volatile N976N_ADC_PREFLIGHT_REPORT mN976nAdcPreflightReport;
VOID N976nObserveAdcPreflight(UINT64 Profile);
#endif
