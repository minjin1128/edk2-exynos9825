/* SPDX-License-Identifier: MIT
 * Publish the admitted, restored ADC/thermal contract. No inherited temperature
 * or successful conversion grants a charger capability. No MMIO writes here.
 * Accepted ExitBootServices uses the battery lease's cached RAM-only path.
 */
#ifndef N976N_ADC_HANDOFF_TEST
#include <PiDxe.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#endif
#include <N976nAdcHandoff.h>
#include <N976nAdcConversion.h>
#include <N976nThermalAdmission.h>
#include <N976nSystemVolume.h>

STATIC CONST UINTN mAdcHandoffClocks[9]={0x15C00100,0x15C01000,0x15C01800,
 0x15C01804,0x15C02004,0x15C02008,0x15C03000,0x15C03008,0x15C0300C};
STATIC CONST UINTN mAdcHandoffConfig[3]={0x15C40000,0x15C40004,0x15C40010};
STATIC CONST VOID *AdcUniqueHob(CONST EFI_GUID *Guid,UINTN Bytes)
{
 VOID *H=GetFirstGuidHob(Guid);
 if(!H||GET_GUID_HOB_DATA_SIZE(H)!=Bytes||GetNextGuidHob(Guid,GET_NEXT_HOB(H)))return NULL;
 return GET_GUID_HOB_DATA(H);
}
STATIC BOOLEAN AdcRetirementValid(VOID)
{
 CONST volatile N976N_ADC_CONVERSION_REPORT *R=&mN976nAdcConversionReport;
 return R->Reached==1&&!R->Status&&!R->Reason&&R->Phase==8&&R->Channel==4&&
 R->Hz==26000000&&R->Registered==1&&R->Enabled==1&&R->Disabled==1&&
 R->Unregistered==1&&R->Initialized==1&&R->Issued==1&&R->Irqs==1&&
 !R->Unexpected&&R->Ack==1&&R->Eoi==1&&!R->EoiStatus&&R->Done==1&&
 R->Cleanup==1&&R->Retired==1&&R->Restored==1&&!R->Quarantine&&
 !R->ClockDrift&&!R->Pending&&!R->Active&&!R->IrqDisableStatus;
}
BOOLEAN N976nCheckAdcHandoff(CONST NCA_LEASE_BINDING *B)
{
 if(!NcaLeaseValid(B)||!AdcRetirementValid())return FALSE;
 for(UINTN I=0;I<3;I++)if(mN976nAdcConversionReport.Old[I]!=B->Original[I]||
   mN976nAdcConversionReport.After[I]!=B->Original[I]||
   MmioRead32(mAdcHandoffConfig[I])!=B->Original[I])return FALSE;
 for(UINTN I=0;I<9;I++)if(MmioRead32(mAdcHandoffClocks[I])!=B->Clocks[I])return FALSE;
 /* SPI84 => INTID116. All three reads are live; zero is necessary but is
  * not standalone ownership proof. Report/DT/lease proofs are required too. */
 for(UINTN I=0;I<3;I++){
   UINT32 V=MmioRead32(0x1010110C+I*0x100);
   if(V==MAX_UINT32||(V&BIT20))return FALSE;
 }
 return TRUE;
}
BOOLEAN N976nCaptureAdcHandoff(UINT64 Profile,UINT64 Generation,NCA_LEASE_BINDING *B)
{
 struct {N976N_ADC_ADMISSION Adc;N976N_THERMAL_ADMISSION Thermal;} Pair;
 CONST N976N_ADC_ADMISSION *A;CONST N976N_THERMAL_ADMISSION *T;
 if(!B)return FALSE;
 ZeroMem(B,sizeof(*B));ZeroMem(&Pair,sizeof(Pair));
 if(Profile!=0||!Generation||!AdcRetirementValid())return FALSE;
 A=AdcUniqueHob(&gN976nAdcPreflightGuid,sizeof(*A));
 T=AdcUniqueHob(&gN976nThermalAdmissionGuid,sizeof(*T));
 if(!A||!T)return FALSE;
 CopyMem(&Pair.Adc,A,sizeof(*A));CopyMem(&Pair.Thermal,T,sizeof(*T));A=&Pair.Adc;T=&Pair.Thermal;
 if(A->Magic!=N976N_ADC_ADMISSION_MAGIC||A->Version!=1||A->Size!=sizeof(*A)||
 A->Profile!=Profile||A->Admitted!=1||A->Reason||A->Checks!=7||
 A->Adc!=0x15C40000||A->AdcBytes!=0x100||A->Cmu!=0x15C00000||
 A->Irq!=116||A->Clock!=110||A->ReadPlan!=1||
 T->Magic!=N976N_THERMAL_ADMISSION_MAGIC||T->Version!=1||T->Size!=sizeof(*T)||
 T->Profile!=Profile||T->Admitted!=1||T->Reason||T->Checks!=0x1F||
 !NcaThermalContractValid(&T->Contract)||T->Contract.AdcAddress!=A->Adc||
 T->Contract.AdcBytes!=A->AdcBytes||T->Contract.Irq!=A->Irq||T->Contract.Clock!=A->Clock)return FALSE;
 if(mN976nAdcPreflightReport.Reached!=1||mN976nAdcPreflightReport.Status||
 mN976nAdcPreflightReport.Reason||mN976nAdcPreflightReport.Hz!=26000000||
 mN976nAdcPreflightReport.Valid!=0xFFFFF)return FALSE;
 B->Generation=Generation;
 for(UINTN I=0;I<3;I++){
   if(mN976nAdcConversionReport.Old[I]>MAX_UINT32)return FALSE;
   B->Original[I]=(UINT32)mN976nAdcConversionReport.Old[I];
 }
 for(UINTN I=0;I<9;I++)B->Clocks[I]=mN976nAdcPreflightReport.Raw[I];
 B->FirmwareRetired=B->FirmwareRestored=B->FirmwareIrqDetached=1;
 CopyMem(&B->Thermal,&T->Contract,sizeof(B->Thermal));
 /* Digest binds normalized admitted HOB payloads, not a whole-DTB hash. */
 if(!N976nSystemSha256(&Pair,sizeof(Pair),B->AdmissionDigest))return FALSE;
 return N976nCheckAdcHandoff(B);
}
EFI_STATUS N976nPrepareAdcHandoff(UINT64 Profile)
{
 N976nObserveAdcPreflight(Profile);
 if(Profile==1){(VOID)N976nConvertAdcOnce(Profile);return EFI_SUCCESS;}
 if(Profile!=0)return EFI_UNSUPPORTED;
 if(EFI_ERROR(mN976nAdcPreflightReport.Status))return (EFI_STATUS)mN976nAdcPreflightReport.Status;
 return N976nConvertAdcOnce(Profile);
}
