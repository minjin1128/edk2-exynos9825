/* SPDX-License-Identifier: MIT */
#ifndef N976N_CHARGE_OBSERVATION_H
#define N976N_CHARGE_OBSERVATION_H
#include <N976nPlatform.h>
#define N976N_CHARGE_ADMISSION_MAGIC 0x3153424F4748434EULL
#define N976N_CHARGE_ADMISSION_CHECKS 7ULL
#define N976N_CHARGE_OBS_FIELDS 19U
/* Pure runtime-DT authority for a fixed read plan, never a live-owner lease
 * or charging capability. Existing battery/Windows lease ABIs are unchanged. */
typedef struct {
 UINT64 Magic,Version,Size,Profile,Admitted,Reason,Checks;
 UINT64 Hsi,Mfd,Ccic,Pca,ReadPlan;
} N976N_CHARGE_ADMISSION;
STATIC_ASSERT(sizeof(N976N_CHARGE_ADMISSION)==96,"observation admission ABI");
extern EFI_GUID gN976nChargeObservationGuid;
BOOLEAN EFIAPI N976nAdmitChargeObservation(CONST VOID *,UINT64,UINT64,N976N_CHARGE_ADMISSION *);
typedef struct {
 UINT64 Reached,Admitted,AdmissionReason,Count,Complete;
 UINT64 Valid[3],Begin[3],End[3];
 UINT8 Raw[3][N976N_CHARGE_OBS_FIELDS];
} N976N_CHARGE_OBSERVATION;
extern volatile N976N_CHARGE_OBSERVATION mN976nChargeObservation;
#endif
