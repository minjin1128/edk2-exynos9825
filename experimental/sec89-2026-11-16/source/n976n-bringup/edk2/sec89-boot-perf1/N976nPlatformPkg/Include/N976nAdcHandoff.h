/* SPDX-License-Identifier: MIT */
#ifndef N976N_ADC_HANDOFF_H
#define N976N_ADC_HANDOFF_H
#include <Base.h>
#include <AdcLease.h>
EFI_STATUS N976nPrepareAdcHandoff(UINT64 Profile);
BOOLEAN N976nCaptureAdcHandoff(UINT64 Profile,UINT64 Generation,NCA_LEASE_BINDING *Binding);
BOOLEAN N976nCheckAdcHandoff(CONST NCA_LEASE_BINDING *Binding);
#endif
