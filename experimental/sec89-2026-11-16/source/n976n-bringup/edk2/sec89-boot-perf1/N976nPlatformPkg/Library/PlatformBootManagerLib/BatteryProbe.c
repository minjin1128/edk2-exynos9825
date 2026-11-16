/* SPDX-License-Identifier: MIT
 * First read-only battery observation. Called at TPL_APPLICATION before the
 * existing UART mux preparation, after platform DT/mapping admission. HSI45
 * stays private to this synchronous sample until restore or quarantine.
 */
#include <PiDxe.h>
#include <N976nPlatform.h>
#include <N976nBatteryAdmission.h>
#include <N976nBatteryProbe.h>
#include <N976nUartMux.h>
#include <N976nChargeObservation.h>
#include <Library/IoLib.h>
#include "BatteryBus.h"
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

volatile N976N_BATTERY_PROBE_REPORT mN976nBatteryReport;
volatile N976N_CHARGE_OBSERVATION mN976nChargeObservation;
STATIC BOOLEAN mAttempted;

STATIC VOID Show (CONST N976N_BATTERY_PROBE_REPORT *R)
{
  CONST N976N_BATTERY_VALUES *V=&R->Values;
  Print(L"\nSEC89 CHARGE ADC2: before UART / NO charger setting writes\n");
  Print(L"BAT phase %lu status %lx reason %lx | valid %x\n",
    R->Phase,R->Status,R->Reason,V->ValueValidMask);
  if (V->ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_SOCREP))
    Print(L"SOC %u.%u%% (gauge) ",V->SocPermille/10,V->SocPermille%10);
  else Print(L"SOC unknown ");
  if (V->ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_VCELL))
    Print(L"/ voltage %u mV\n",V->VoltageMv);
  else Print(L"/ voltage unknown\n");
  if (V->ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT))
    Print(L"Current %d mA ",V->CurrentMa);
  else Print(L"Current unknown ");
  Print(L"/ DT factor %lu (status %lu)\n",R->Factor,R->FactorStatus);
  if (V->ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_INPUT))
    Print(L"Input wired/wireless %u/%u ",V->WiredInput,V->WirelessInput);
  else Print(L"Input unknown ");
  Print(L"/ charge state %u (0=unknown,1=charging,2=full,3=idle,4=discharge)\n",V->ChargeState);
  Print(L"Bus restored %lu retired %lu quarantine %lu / safe %lu\n",
    mN976nBatteryBusReport.Restored,mN976nBatteryBusReport.Retired,
    mN976nBatteryBusReport.Quarantine,R->SafeToContinue);
  Print(L"RAW status/SOC/VCELL/current/avg/rem/full/input/detail:\n");
  for (UINTN I=0;I<N976N_BAT_FIELD_COUNT;I++) Print(L"%04x ",R->Raw.Raw[I]);
  Print(L"\nAdmission %lu reason %lx / samples %lu complete %lu\n",
   mN976nChargeObservation.Admitted,mN976nChargeObservation.AdmissionReason,
   mN976nChargeObservation.Count,mN976nChargeObservation.Complete);
  Print(L"ORDER CHG@69: B2 B3 B4 B7 B8 B9 BA BB BD C0 C3\n");
  Print(L"ORDER CCIC@25: 06 08 0A 0B 0C 0D / PCA@57: 05 22\n");
  for(UINTN J=0;J<3;J++){
   Print(L"Sample %u valid %lx ticks %lx..%lx\n",(UINT32)J+1,
    mN976nChargeObservation.Valid[J],mN976nChargeObservation.Begin[J],mN976nChargeObservation.End[J]);
   for(UINTN I=0;I<N976N_CHARGE_OBS_FIELDS;I++){
    if(mN976nChargeObservation.Valid[J]&(1ULL<<I))Print(L"%02x ",mN976nChargeObservation.Raw[J][I]);
    else Print(L"-- ");
   }
   Print(L"\n");
  }
  Print(L"Bus why/phase %lx/%lu field %lx addr/reg %lx/%lx\n",
   mN976nBatteryBusReport.Reason,mN976nBatteryBusReport.FailurePhase,
   mN976nBatteryBusReport.Field,mN976nBatteryBusReport.Address,mN976nBatteryBusReport.Register);
  Print(L"First compare addr/expected/actual %lx/%lx/%lx\n",
   mN976nBatteryBusReport.FirstAddress,mN976nBatteryBusReport.FirstExpected,mN976nBatteryBusReport.FirstActual);
  Print(L"General USB is allowed. No UART switch, Windows or media writes.\n");
  Print(L"Raw samples are sequential, not a current contract or charging protection.\n");
  Print(L"Unplug USB/charger before shutdown; 120s / VolumeDown hold2s then release.\n");
}

EFI_STATUS N976nObserveBattery (UINT64 Profile)
{
  N976N_BATTERY_PROBE_REPORT R;
  CONST N976N_BATTERY_ADMISSION *A;
  CONST N976N_CHARGE_ADMISSION *C;
  N976N_CHARGE_OBSERVATION *O=(VOID *)&mN976nChargeObservation;
  VOID *Hob;
  EFI_STATUS Status;
  if (mAttempted) return mN976nBatteryReport.SafeToContinue ? EFI_SUCCESS : EFI_NOT_READY;
  mAttempted=TRUE;O->Reached=1;
  ZeroMem(&R,sizeof(R));
  R.Magic=0x315442415438384EULL; R.Version=1; R.Size=sizeof(R); R.Phase=1;
  R.Status=EFI_NOT_READY;
  if (Profile==N976N_PLATFORM_PROFILE_QEMU) {
    R.Status=EFI_UNSUPPORTED; R.Reason=1; R.SafeToContinue=1;
    goto Done;
  }
  if (Profile!=N976N_PLATFORM_PROFILE_PHONE || EfiGetCurrentTpl()!=TPL_APPLICATION ||
      mN976nUartMuxReport.Phase!=0) { R.Reason=2; goto Done; }
  Hob=GetFirstGuidHob(&gN976nBatteryAdmissionGuid);
  if (Hob==NULL || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(*A) ||
      GetNextGuidHob(&gN976nBatteryAdmissionGuid,GET_NEXT_HOB(Hob))!=NULL) {
    R.Reason=3; R.SafeToContinue=1; goto Done;
  }
  A=GET_GUID_HOB_DATA(Hob);
  if (A->Magic!=N976N_BATTERY_ADMISSION_MAGIC || A->Version!=1 ||
      A->Size!=sizeof(*A) || A->Profile!=Profile || A->Admitted!=1 ||
      A->Reason!=0 || A->Checks!=N976N_BATTERY_ADMISSION_CHECKS ||
      !((A->FactorStatus==1 && (A->Factor==2 || A->Factor==5)) ||
        (A->FactorStatus>=2 && A->FactorStatus<=6 && A->Factor==0))) {
    R.Reason=4; R.SafeToContinue=1; goto Done;
  }
  Hob=GetFirstGuidHob(&gN976nChargeObservationGuid);
  O->AdmissionReason=1;
  if(!Hob||GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(*C)||
    GetNextGuidHob(&gN976nChargeObservationGuid,GET_NEXT_HOB(Hob))){R.Reason=0xC101;R.SafeToContinue=1;goto Done;}
  C=GET_GUID_HOB_DATA(Hob);O->AdmissionReason=C->Reason;
  if(C->Magic!=N976N_CHARGE_ADMISSION_MAGIC||C->Version!=1||C->Size!=sizeof(*C)||
    C->Profile!=Profile||C->Admitted!=1||C->Reason||C->Checks!=N976N_CHARGE_ADMISSION_CHECKS||
    C->Hsi!=0x15D60000||C->Mfd!=0x66||C->Ccic!=0x25||C->Pca!=0x57||C->ReadPlan!=1){
    R.Reason=0xC102;R.SafeToContinue=1;goto Done;}
  O->Admitted=1;
  /* GIC SPI82/INTID114 must remain masked for this private polling owner. */
  UINT32 Irq=MmioRead32(0x1010110C);
  if(Irq==MAX_UINT32||(Irq&BIT18)){R.Reason=0xC103;R.SafeToContinue=1;goto Done;}
  R.Factor=A->Factor; R.FactorStatus=A->FactorStatus;
  R.CounterHz=GetPerformanceCounterProperties(NULL,NULL);
  R.CounterStart=GetPerformanceCounter(); R.Phase=2; R.Attempted=1;
  Status=N976nBatteryBusObserve(1,&R.Raw,O);
  R.CounterEnd=GetPerformanceCounter(); R.Status=Status;
  R.Reason=mN976nBatteryBusReport.Reason;
  if (!N976nBatteryDecode(&R.Raw,(UINT32)R.Factor,&R.Values)) {
    R.Status=EFI_COMPROMISED_DATA; R.Reason=5;
  }
  /* A failed or missing gauge never pretends to be a zero-percent battery.
   * It may be skipped only when no MMIO write happened or exact restoration
   * succeeded. Uncertain ownership prevents the following UART and OS handoff. */
  R.SafeToContinue=mN976nBatteryBusReport.Quarantine==0 &&
    (mN976nBatteryBusReport.NoMutation==1 || mN976nBatteryBusReport.Restored==1);
  /* Preserve the raw record for diagnosis, but do not present derived battery
   * values when the bus ownership/restore result is uncertain. */
  if (!R.SafeToContinue) ZeroMem(&R.Values,sizeof(R.Values));
  R.Phase=EFI_ERROR((EFI_STATUS)R.Status)?6:8;
Done:
  CopyMem((VOID *)&mN976nBatteryReport,&R,sizeof(R));
  if (Profile==N976N_PLATFORM_PROFILE_PHONE && EfiGetCurrentTpl()==TPL_APPLICATION) {
    Show(&R);

  }
  return R.SafeToContinue ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
