/* SPDX-License-Identifier: MIT
 * Shared, pointer-free firmware/Windows ADC ownership record. No sample in this
 * record is a live temperature, input contract, or permission to charge.
 */
#ifndef N976N_ADC_LEASE_H
#define N976N_ADC_LEASE_H
#include "ThermalContract.h"
typedef struct {
 NCA_U64 Generation;
 NCA_U32 Original[3],Clocks[9];
 NCA_U32 FirmwareRetired,FirmwareRestored,FirmwareIrqDetached,Reserved;
 unsigned char AdmissionDigest[32];
 NCA_THERMAL_CONTRACT Thermal;
} NCA_LEASE_BINDING;
typedef char NcaLeaseAbi[(sizeof(NCA_LEASE_BINDING)==736)?1:-1];
static inline int NcaLeaseValid(const NCA_LEASE_BINDING *a)
{
 unsigned i;unsigned char nonzero=0;
 if(!a||!a->Generation||a->Reserved||a->FirmwareRetired!=1||
   a->FirmwareRestored!=1||a->FirmwareIrqDetached!=1||
   (a->Original[0]&~2U)||(a->Original[1]&~0x7FU)||a->Original[2]||
   !NcaThermalContractValid(&a->Thermal))return 0;
 for(i=0;i<9;i++)if(a->Clocks[i]==0xFFFFFFFFU)return 0;
 if(a->Clocks[1]||!(a->Clocks[4]&(1U<<21))||!(a->Clocks[5]&(1U<<21))||
   (a->Clocks[7]&3)!=2||(a->Clocks[8]&3)!=2)return 0;
 /* The digest binds the admitted normalized contract. Its nonzero value is
  * not an admission check: the entire canonical contract is checked above. */
 for(i=0;i<32;i++)nonzero|=a->AdmissionDigest[i];
 return nonzero!=0;
}
#endif
