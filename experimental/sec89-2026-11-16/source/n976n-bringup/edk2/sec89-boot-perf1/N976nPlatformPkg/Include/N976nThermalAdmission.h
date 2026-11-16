/* SPDX-License-Identifier: MIT */
#ifndef N976N_THERMAL_ADMISSION_H
#define N976N_THERMAL_ADMISSION_H
#include <N976nAdcPreflight.h>
#include <ThermalContract.h>
#define N976N_THERMAL_ADMISSION_MAGIC 0x314D524548544E4EULL
typedef struct {
 UINT64 Magic,Version,Size,Profile,Admitted,Reason,Checks;
 NCA_THERMAL_CONTRACT Contract;
} N976N_THERMAL_ADMISSION;
STATIC_ASSERT(sizeof(N976N_THERMAL_ADMISSION)==688,"Thermal admission ABI");
extern EFI_GUID gN976nThermalAdmissionGuid;
/* Identity must be the successful ADC admission from this same unchanged DT.
 * The SEC caller owns the DT; this function is not a userspace admission API. */
BOOLEAN EFIAPI N976nAdmitThermal(CONST VOID *,UINT64,UINT64,
 CONST N976N_ADC_ADMISSION *,N976N_THERMAL_ADMISSION *);
#endif
