/* SPDX-License-Identifier: MIT
 * SEC89 CONTROL1: final HSI45/ADC contract follows the read-only gauge producer retirement.
 * Publication performs read-only binding checks; ADC conversion retires beforehand.
 * Capture/Validate use the exact Windows portable core, with a write callback
 * that only records a contract violation. GIC SPI82 => INTID114 remains masked.
 * Physical accessibility of inherited post-gauge registers is a hardware test;
 * a readable but unsupported state leaves BAT0 absent rather than inventing it.
 */
#ifndef N976N_BATTERY_LIVE_TEST
#include <PiDxe.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/MemoryAttribute.h>
#endif
#include <N976nBatteryLive.h>
#include <N976nBatteryProbe.h>
#include "BatteryBus.h"
#include <N976nAdcHandoff.h>
#include <N976nWindowsConnection.h>
#include <N976nUartKd.h>
#include <N976nUartMux.h>

STATIC N976N_BAT_LEASE *mBatteryLease;
STATIC N976N_BAT_LEASE mBatteryExpected;
STATIC N976N_BAT_BUS_CONTEXT mBatteryBindingContext;
STATIC UINT64 mBatteryProfile=MAX_UINT64;
STATIC BOOLEAN mBatteryReleased,mBatteryPreExit;
volatile N976N_BATTERY_LIVE_REPORT mN976nBatteryLiveReport;
STATIC_ASSERT(sizeof(N976N_BAT_LEASE)==1392,"exact OS lease ABI");
STATIC_ASSERT(OFFSET_OF(N976N_BAT_LEASE,ClaimState)==1384,"immutable bound");
STATIC_ASSERT(OFFSET_OF(N976N_BAT_LEASE,Crc32)==36,"CRC field bound");
STATIC_ASSERT(sizeof(N976N_BAT_LEASE)<4088,"guard outside record");

STATIC UINT32 BatteryRead(VOID *Context,UINT64 Address)
{ (VOID)Context; return MmioRead32((UINTN)Address); }
STATIC VOID BatteryNoWrite(VOID *Context,UINT64 Address,UINT32 Value)
{ (VOID)Context; (VOID)Address; (VOID)Value; mN976nBatteryLiveReport.UnexpectedWrite=1; }
STATIC VOID BatteryBarrier(VOID *Context)
{ (VOID)Context; MemoryFence(); }
STATIC UINT64 BatteryCounter(VOID *Context)
{ (VOID)Context; return GetPerformanceCounter(); }
STATIC VOID BatteryNoStall(VOID *Context,UINT32 Us)
{ (VOID)Context; (VOID)Us; mN976nBatteryLiveReport.UnexpectedWrite=1; }
STATIC int BatteryNotCancelled(VOID *Context)
{ (VOID)Context; return 0; }
STATIC CONST N976N_BAT_BUS_OPS mBatteryOps={BatteryRead,BatteryNoWrite,
 BatteryBarrier,BatteryCounter,BatteryNoStall,BatteryNotCancelled};
STATIC EFI_STATUS BatteryRefuse(UINT64 Reason,EFI_STATUS Status)
{
 mN976nBatteryLiveReport.Phase=0xE0;
 mN976nBatteryLiveReport.Reason=Reason;mN976nBatteryLiveReport.Status=Status;
 MemoryFence();return Status;
}
STATIC EFI_STATUS BatteryAbsent(UINT64 Reason)
{
 mN976nBatteryLiveReport.Phase=2;mN976nBatteryLiveReport.Reason=Reason;
 mN976nBatteryLiveReport.Status=EFI_UNSUPPORTED;
 Print(L"BAT LIVE absent: reason %lx; no live battery device published.\n",Reason);
 return EFI_SUCCESS;
}
STATIC EFI_STATUS BatteryCompareRefuse(UINT64 Kind,UINT64 Index,UINT64 Expected,UINT64 Actual)
{
 mN976nBatteryLiveReport.CompareKind=Kind;
 mN976nBatteryLiveReport.CompareIndex=Index;
 mN976nBatteryLiveReport.CompareExpected=Expected;
 mN976nBatteryLiveReport.CompareActual=Actual;
 return BatteryRefuse(18,EFI_SECURITY_VIOLATION);
}
STATIC BOOLEAN BatteryCachedValid(VOID)
{
 return mBatteryLease && !CompareMem(mBatteryLease,&mBatteryExpected,sizeof(mBatteryExpected)) && N976nBatLeaseValid(mBatteryLease,N976N_BAT_LEASE_PREPARED) &&
   mBatteryLease->ClaimState==N976N_BAT_CLAIM_READY &&
   *(volatile UINT64 *)((UINT8 *)mBatteryLease+4088)==N976N_BAT_LEASE_GUARD &&
   !mN976nBatteryLiveReport.UnexpectedWrite;
}
STATIC BOOLEAN BatteryIrqMasked(VOID)
{
 /* GICD_ISENABLER[114/32] at base+0x100+3*4, bit114%32=18. */
 UINT32 V=MmioRead32(0x1010110C);
 mN976nBatteryLiveReport.Gic114=V;
 return V!=MAX_UINT32 && !(V&BIT18);
}
UINT64 N976nBatteryLiveAddress(VOID){return (UINTN)mBatteryLease;}
EFI_STATUS N976nBatteryLivePublish(UINT64 Profile)
{
 N976N_BAT_LEASE L;N976N_BAT_BUS_REPORT Capture;
 UINT32 UartSelected[16];
 EFI_PHYSICAL_ADDRESS Page=N976N_BAT_LEASE_END-N976N_BAT_LEASE_PAGE;
 EFI_MEMORY_ATTRIBUTE_PROTOCOL *Attributes=NULL;UINT64 Value=0;
 EFI_STATUS Status;
 if(mBatteryProfile!=MAX_UINT64||Profile>1)return EFI_ACCESS_DENIED;
 mBatteryProfile=Profile;mN976nBatteryLiveReport.Phase=1;
 if(Profile==1)return BatteryAbsent(1); /* QEMU: no phone MMIO/fake lease */
 /* A skipped, non-mutating probe may omit BAT0 without blocking Windows.
  * This is never evidence of retirement and can never publish a lease. */
 if(!mN976nBatteryReport.SafeToContinue || mN976nBatteryBusReport.Quarantine)
   return BatteryRefuse(2,EFI_SECURITY_VIOLATION);
 if(!mN976nBatteryReport.Attempted ||
    !((mN976nBatteryReport.FactorStatus==1 &&
       (mN976nBatteryReport.Factor==2||mN976nBatteryReport.Factor==5)) ||
      (mN976nBatteryReport.FactorStatus>=2&&mN976nBatteryReport.FactorStatus<=6&&
       mN976nBatteryReport.Factor==0))) return BatteryAbsent(3);
 if(mN976nBatteryBusReport.Retired!=1 || mN976nBatteryBusReport.Restored!=1 ||
    mN976nBatteryBusReport.Phase!=8 || mN976nBatteryBusReport.Status ||
    mN976nBatteryBusReport.Reason)
   return BatteryRefuse(2,EFI_SECURITY_VIOLATION);
 mN976nBatteryLiveReport.ProducerKind=N976N_BAT_PRODUCER_GAUGE_USB;
 mN976nBatteryLiveReport.ProducerRetired=1;mN976nBatteryLiveReport.ProducerRestored=1;
 /* Keep the v4 gauge producer identity accepted by CONTROL3 .605. UART is
  * a subsequent bus owner: it must independently retire and return the exact
  * same selected view before that gauge contract can be published. */
 if(!N976nUartKdReady() || !N976nUartMuxReady() ||
    mN976nUartMuxReport.Phase!=8 || mN976nUartMuxReport.Status ||
    mN976nUartMuxReport.Reason || mN976nUartMuxReport.Quarantine ||
    mN976nUartMuxReport.Retired!=1 || mN976nUartMuxReport.Restored!=1 ||
    !N976nUartMuxGetRestoredSelectedConfig(UartSelected))
   return BatteryRefuse(17,EFI_SECURITY_VIOLATION);
 ZeroMem(&L,sizeof(L));ZeroMem(&Capture,sizeof(Capture));
 L.CounterHz=GetPerformanceCounterProperties(NULL,NULL);
 if(L.CounterHz!=26000000 || !BatteryIrqMasked())return BatteryAbsent(4);
 if(!N976nBatBusCaptureBinding(&mBatteryOps,NULL,L.CounterHz,&L.Binding,&Capture)) {
   CopyMem((VOID *)&mN976nBatteryLiveReport.Capture,&Capture,sizeof(Capture));
   if(mN976nBatteryLiveReport.UnexpectedWrite)return BatteryRefuse(5,EFI_SECURITY_VIOLATION);
   return BatteryAbsent(6);
 }
 CopyMem((VOID *)&mN976nBatteryLiveReport.Capture,&Capture,sizeof(Capture));
 if(!N976nBatteryBusGetRestoredSelectedConfig(L.SelectedConfig)||
    !N976nBatBusSelectedValid(L.SelectedConfig)||
    L.Binding.Mode!=mN976nBatteryBusReport.InheritedMode||
    L.Binding.Qch!=mN976nBatteryBusReport.InheritedQch)return BatteryRefuse(15,EFI_SECURITY_VIOLATION);
 for(UINTN I=0;I<6;I++)
   if((L.Binding.Gpio[I]&15)!=(mN976nBatteryBusReport.InheritedPin[I]&15))
     return BatteryRefuse(15,EFI_SECURITY_VIOLATION);
 /* PRE MODE0 and selected MODE4 views may differ. Compare the two owners'
  * saved selected views, never Binding.Config against SelectedConfig. */
 for(UINTN I=0;I<16;I++)
   if(L.SelectedConfig[I]!=UartSelected[I])
     return BatteryCompareRefuse(1,I,L.SelectedConfig[I],UartSelected[I]);
 if(L.Binding.Mode!=mN976nUartMuxReport.InheritedMode)
   return BatteryCompareRefuse(2,0,L.Binding.Mode,mN976nUartMuxReport.InheritedMode);
 if(L.Binding.Qch!=mN976nUartMuxReport.InheritedQch)
   return BatteryCompareRefuse(3,0,L.Binding.Qch,mN976nUartMuxReport.InheritedQch);
 for(UINTN I=0;I<6;I++)
   if((L.Binding.Gpio[I]&15)!=(mN976nUartMuxReport.InheritedPin[I]&15))
     return BatteryCompareRefuse(4,I,L.Binding.Gpio[I]&15,mN976nUartMuxReport.InheritedPin[I]&15);
 mN976nBatteryLiveReport.UartRestoreChecked=1;
 L.Magic=N976N_BAT_LEASE_MAGIC;L.Version=N976N_BAT_LEASE_VERSION;L.Bytes=sizeof(L);
 L.ImmutableBytes=N976N_BAT_LEASE_IMMUTABLE_BYTES;
 L.BootCounter=GetPerformanceCounter();L.ProducerStage=N976N_BAT_LEASE_PREPARED;
 if(!N976nCaptureAdcHandoff(Profile,L.BootCounter,&L.Adc))return BatteryRefuse(16,EFI_SECURITY_VIOLATION);
 L.Factor=(UINT32)mN976nBatteryReport.Factor;
 L.FactorStatus=(UINT32)mN976nBatteryReport.FactorStatus;
 L.Gic114Masked=1;L.ProducerRetired=1;L.ProducerRestored=1;L.ProducerKind=N976N_BAT_PRODUCER_GAUGE_USB;L.Guard=N976N_BAT_LEASE_GUARD;
 L.Crc32=N976nBatLeaseCrc(&L);
 if(!N976nBatLeaseValid(&L,N976N_BAT_LEASE_PREPARED)||
    !N976nBatBusInit(&mBatteryBindingContext,&mBatteryOps,NULL,&L.Binding))
   return BatteryRefuse(7,EFI_SECURITY_VIOLATION);
 Status=gBS->AllocatePages(AllocateMaxAddress,EfiACPIMemoryNVS,1,&Page);
 if(EFI_ERROR(Status))return BatteryRefuse(8,Status);
 if(Page<N976N_BAT_LEASE_LOW || Page>=N976N_BAT_LEASE_END || (Page&4095)) {
   gBS->FreePages(Page,1);return BatteryRefuse(9,EFI_SECURITY_VIOLATION);
 }
 Status=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&Attributes);
 if(EFI_ERROR(Status)||!Attributes||!Attributes->SetMemoryAttributes||!Attributes->GetMemoryAttributes) {
   gBS->FreePages(Page,1);return BatteryRefuse(10,EFI_UNSUPPORTED);
 }
 Status=Attributes->SetMemoryAttributes(Attributes,Page,4096,EFI_MEMORY_XP);
 if(EFI_ERROR(Status)||EFI_ERROR(Attributes->GetMemoryAttributes(Attributes,Page,4096,&Value))||Value!=EFI_MEMORY_XP) {
   gBS->FreePages(Page,1);return BatteryRefuse(11,EFI_SECURITY_VIOLATION);
 }
 CopyMem(&mBatteryExpected,&L,sizeof(L));
 mBatteryLease=(VOID *)(UINTN)Page;ZeroMem(mBatteryLease,4096);CopyMem(mBatteryLease,&L,sizeof(L));
 *(UINT64 *)((UINT8 *)mBatteryLease+4088)=N976N_BAT_LEASE_GUARD;MemoryFence();
 Status=N976nBatteryLiveCheck();
 if(EFI_ERROR(Status))return Status; /* allocation retained on uncertain contract */
 mN976nBatteryLiveReport.Address=Page;mN976nBatteryLiveReport.Bytes=4096;
 mN976nBatteryLiveReport.Published=1;mN976nBatteryLiveReport.Phase=8;
 Print(L"BAT LIVE prepared: gauge + UART bus restored, %lu Hz, NVS %lx.\n",L.Binding.InputHz,Page);
 return EFI_SUCCESS;
}
EFI_STATUS N976nBatteryLiveCheck(VOID)
{
 if(mBatteryReleased)return EFI_ACCESS_DENIED;
 if(mBatteryProfile==1)return mBatteryLease?EFI_SECURITY_VIOLATION:EFI_SUCCESS;
 if(mBatteryProfile!=0)return EFI_NOT_READY;
 if(!mBatteryLease)return mN976nBatteryLiveReport.Phase==2?EFI_SUCCESS:EFI_NOT_READY;
 if(!BatteryCachedValid() || !BatteryIrqMasked() ||
    !N976nCheckAdcHandoff(&mBatteryExpected.Adc) ||
    !N976nBatBusValidateBinding(&mBatteryBindingContext) ||
    mN976nBatteryLiveReport.UnexpectedWrite)
   return BatteryRefuse(12,EFI_SECURITY_VIOLATION);
 return EFI_SUCCESS;
}
EFI_STATUS N976nBatteryLiveBeforeExit(VOID)
{
 EFI_STATUS Status=N976nBatteryLiveCheck();
 if(EFI_ERROR(Status))return Status;
 mBatteryPreExit=TRUE;mN976nBatteryLiveReport.PreExitChecked=1;return EFI_SUCCESS;
}
EFI_STATUS N976nBatteryLiveRelease(VOID)
{
 /* Accepted-EBS event: cached RAM only. No MMIO, BootServices, bus callback,
  * timer/clock read or physical transfer is permitted in this function. */
 if(mBatteryReleased||!mBatteryPreExit)return EFI_ACCESS_DENIED;
 if(mBatteryLease) {
   if(!BatteryCachedValid())return BatteryRefuse(13,EFI_SECURITY_VIOLATION);
   mBatteryLease->ProducerStage=N976N_BAT_LEASE_RELEASED;
   mBatteryLease->Crc32=N976nBatLeaseCrc(mBatteryLease);MemoryFence();
 }
 mBatteryReleased=TRUE;mN976nBatteryLiveReport.Released=1;return EFI_SUCCESS;
}

/* First SEC89 hardware observation: use the actual Windows portable transport,
 * retain ownership for three bounded samples, retire and restore, then STOP.
 * Charger access remains fixed pointer+RX only. No charge-control payload API. */
volatile UINT64 mN976nBatteryDiagReached,mN976nBatteryDiagStatus;
volatile N976N_POWER_DIAG_REPORT mN976nPowerDiagReport;
STATIC N976N_BAT_BUS_CONTEXT mPowerDiagBus;
STATIC VOID PowerWrite(VOID *Context,UINT64 Address,UINT32 Value)
{
 BOOLEAN Allowed=FALSE;(VOID)Context;
 if(Address==0x15C22030||Address==0x15C0304C||
    Address==0x15C30180||Address==0x15C30188||Address==0x15C3018C||
    Address==0x15C301A0||Address==0x15C301A8||Address==0x15C301AC)Allowed=TRUE;
 if(Address>=0x15D60000&&Address<=0x15D600C8)switch((UINT32)(Address-0x15D60000)) {
   case 0:case 4:case 8:case 0x20:case 0x24:case 0x34:case 0x40:case 0x44:
   case 0x48:case 0x54:case 0x58:case 0x5C:case 0x60:case 0x64:case 0x68:
   case 0x70:case 0xC4:case 0xC8:Allowed=TRUE;break;
 }
 if(!Allowed){mN976nBatteryLiveReport.UnexpectedWrite=1;return;}
 MmioWrite32((UINTN)Address,Value);
}
STATIC VOID PowerStall(VOID *Context,UINT32 Us)
{ (VOID)Context;MicroSecondDelay(Us); }
STATIC CONST N976N_BAT_BUS_OPS mPowerOps={BatteryRead,PowerWrite,BatteryBarrier,
 BatteryCounter,PowerStall,BatteryNotCancelled};
EFI_STATUS N976nBatteryDiagnosticStop(EFI_STATUS Status)
{
 N976N_POWER_DIAG_REPORT *D=(VOID *)&mN976nPowerDiagReport;
 N976N_BAT_BUS_CONTEXT *C=&mPowerDiagBus;
 if(mN976nBatteryDiagReached)return EFI_ACCESS_DENIED;
 mN976nBatteryDiagReached=1;mN976nBatteryDiagStatus=Status;
 ZeroMem(D,sizeof(*D));D->Phase=1;D->Status=Status;
 D->AcquireStatus=D->ReleaseStatus=EFI_NOT_STARTED;
 for(UINTN I=0;I<3;I++)D->GaugeStatus[I]=D->ChargeStatus[I]=EFI_NOT_STARTED;
 if(EFI_ERROR(Status)){D->Reason=1;goto Done;}
 if(mBatteryProfile==1){D->Phase=2;D->Reason=2;goto Done;} /* no phone MMIO */
 if(mBatteryProfile!=0||!mN976nBatteryLiveReport.Published||!BatteryCachedValid()||
    EFI_ERROR(N976nBatteryLiveCheck())){D->Status=EFI_NOT_READY;D->Reason=3;goto Done;}
 if(!N976nBatBusInit(C,&mPowerOps,NULL,&mBatteryExpected.Binding)||
    !N976nBatBusBindSelected(C,mBatteryExpected.SelectedConfig)) {
   D->Status=EFI_SECURITY_VIOLATION;D->Reason=4;goto Done;
 }
 D->Phase=3;D->AcquireStatus=N976nBatBusAcquireD0(C);D->Acquire=C->AcquireReport;
 if(D->AcquireStatus){D->Status=D->AcquireStatus;D->Reason=5;goto Retire;}
 for(UINTN I=0;I<3;I++) {
   D->Phase=4;D->Count=I+1;D->Begin[I]=GetPerformanceCounter();
   D->GaugeStatus[I]=N976nBatBusReadActive(C,I+1,&D->Gauge[I]);
   if(D->GaugeStatus[I]){D->Status=D->GaugeStatus[I];D->Reason=6;D->End[I]=GetPerformanceCounter();break;}
   N976nBatteryDecode(&D->Gauge[I],mBatteryExpected.Factor,&D->Values[I]);
   D->Phase=5;D->ChargeStatus[I]=N976nBatBusReadChargeActive(C,I+1,&D->Charger[I]);
   D->End[I]=GetPerformanceCounter();
   if(D->ChargeStatus[I]){D->Status=D->ChargeStatus[I];D->Reason=7;break;}
   D->Complete++;if(I<2)MicroSecondDelay(500000);
 }
Retire:
 D->Phase=6;
 if(C->D0Active&&!C->Quarantined)D->ReleaseStatus=N976nBatBusReleaseD0(C);
 D->Last=C->Report;D->FirstFailure=C->FirstFailure;
 D->Restored=C->Report.Restored;D->Quarantine=C->Quarantined;
 if(!D->Status&&(D->ReleaseStatus||D->Quarantine||!D->Restored)) {
   D->Status=D->ReleaseStatus?D->ReleaseStatus:EFI_DEVICE_ERROR;D->Reason=8;
 }
 if(!D->Status&&EFI_ERROR(N976nBatteryLiveCheck())){D->Status=EFI_SECURITY_VIOLATION;D->Reason=9;}
 if(!D->Status&&D->Complete==3)D->Phase=8;
Done:
 MemoryFence();
 /* Even successful observations never reach ACPI installation/Windows load. */
 return EFI_ERROR(D->Status)?D->Status:EFI_ABORTED;
}
