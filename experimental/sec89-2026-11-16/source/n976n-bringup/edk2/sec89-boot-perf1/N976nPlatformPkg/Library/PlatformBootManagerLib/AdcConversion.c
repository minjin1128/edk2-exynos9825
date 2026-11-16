/* SPDX-License-Identifier: MIT
 * Samsung N976N exynos_adc v3: one channel4 conversion, clock unchanged.
 * EDK2 GICv2 calls a registered handler without EOI; every entry must EOI.
 * No charger commands, no DMA, no Windows handoff, no timeout retry.
 */
#include <PiDxe.h>
#include <N976nAdcPreflight.h>
#include <N976nAdcConversion.h>
#include <Protocol/HardwareInterrupt.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>

#define ADC_BASE 0x15C40000U
#define ADC_CON1 (ADC_BASE+0)
#define ADC_CON2 (ADC_BASE+4)
#define ADC_DATA (ADC_BASE+8)
#define ADC_INT_EN (ADC_BASE+0x10)
#define ADC_INT_ST (ADC_BASE+0x14)
#define ADC_IRQ 116U
#define IRQ_BIT (1U<<20)
#define GIC_ENABLE 0x1010110CU
#define GIC_PENDING 0x1010120CU
#define GIC_ACTIVE 0x1010130CU
#define WAIT_TICKS 2600000ULL
#define FROZEN_POLLS 20000U
#define MAX_POLLS 1000000U

volatile N976N_ADC_CONVERSION_REPORT mN976nAdcConversionReport;
STATIC EFI_HARDWARE_INTERRUPT_PROTOCOL *mAdcInterrupt;
STATIC CONST UINTN mAdcClockAddresses[9]={
 0x15C00100,0x15C01000,0x15C01800,0x15C01804,0x15C02004,
 0x15C02008,0x15C03000,0x15C03008,0x15C0300C
};

STATIC BOOLEAN AdcClockUnchanged(VOID)
{
 BOOLEAN Good=TRUE;
 for(UINTN I=0;I<9;I++){
  if(MmioRead32(mAdcClockAddresses[I])!=mN976nAdcPreflightReport.Raw[I]){
   mN976nAdcConversionReport.ClockDrift|=1ULL<<I;Good=FALSE;
  }
 }
 return Good;
}

STATIC BOOLEAN AdcSourceState(BOOLEAN Want);

STATIC VOID AdcUnsafeStop(VOID)
{
 volatile N976N_ADC_CONVERSION_REPORT *R=&mN976nAdcConversionReport;
 DisableInterrupts();
 R->Status=EFI_DEVICE_ERROR;R->Reason=14;R->Quarantine=1;R->Restored=0;R->Phase=8;
 MemoryFence();N976nAdcIrqUnsafeStop(EFI_DEVICE_ERROR);
}

STATIC VOID EFIAPI AdcInterrupt(HARDWARE_INTERRUPT_SOURCE Source,EFI_SYSTEM_CONTEXT Context)
{
 volatile N976N_ADC_CONVERSION_REPORT *R=&mN976nAdcConversionReport;
 (VOID)Context;
 R->Irqs++;
 /* Mask this source immediately. The context and this code remain resident. */
 R->IrqDisableStatus=mAdcInterrupt->DisableInterruptSource(mAdcInterrupt,ADC_IRQ);
 BOOLEAN Masked=!EFI_ERROR(R->IrqDisableStatus)&&AdcSourceState(FALSE);
 if(!Masked||Source!=ADC_IRQ||R->Phase!=5||R->Issued!=1||R->Irqs!=1){
  R->Unexpected++;
 }else{
  R->IrqTick=GetPerformanceCounter();
  R->DataRaw=MmioRead32(ADC_DATA);R->Data12=R->DataRaw&0xFFF;
  MmioWrite32(ADC_INT_ST,1);MemoryFence();R->Ack++;
 }
 /* Dispatcher already read IAR. EOI exactly once, including unexpected IRQ. */
 R->EoiStatus=mAdcInterrupt->EndOfInterrupt(mAdcInterrupt,Source);R->Eoi++;
 MemoryFence();R->Done=1;
 /* EOI precedes the non-returning path; never return to an unmasked level IRQ. */
 if(!Masked)AdcUnsafeStop();
}

STATIC BOOLEAN AdcSourceState(BOOLEAN Want)
{
 BOOLEAN Enabled=FALSE;
 EFI_STATUS S=mAdcInterrupt->GetInterruptSourceState(mAdcInterrupt,ADC_IRQ,&Enabled);
 return !EFI_ERROR(S)&&Enabled==Want&&((MmioRead32(GIC_ENABLE)&IRQ_BIT)!=0)==Want;
}

EFI_STATUS N976nConvertAdcOnce(UINT64 Profile)
{
 volatile N976N_ADC_CONVERSION_REPORT *R=&mN976nAdcConversionReport;
 volatile N976N_ADC_PREFLIGHT_REPORT *P=&mN976nAdcPreflightReport;
 EFI_TPL OldTpl;EFI_STATUS S;UINT64 Now,Previous;BOOLEAN Good=FALSE;
 if(R->Reached)return (EFI_STATUS)R->Status;
 R->Reached=1;R->Status=EFI_NOT_READY;R->Channel=4;
 if(Profile==N976N_PLATFORM_PROFILE_QEMU){R->Status=EFI_UNSUPPORTED;R->Reason=1;return EFI_UNSUPPORTED;}
 /* EfiGetCurrentTpl can enable interrupts: never call it from IRQ-off entry. */
 if(Profile!=N976N_PLATFORM_PROFILE_PHONE||!GetInterruptState()){
  R->Reason=2;return EFI_NOT_READY;
 }
 if(EfiGetCurrentTpl()!=TPL_APPLICATION){R->Reason=2;return EFI_NOT_READY;}
 R->Phase=1;R->Reason=3;
 if(P->Reached!=1||P->Status||P->Reason||P->Valid!=0xFFFFF||!P->IrqEnabled||P->Hz!=26000000)goto Show;
 R->Hz=GetPerformanceCounterProperties(NULL,NULL);
 if(R->Hz!=26000000)goto Show;
 /* Observed OSCCLK parent, gates asserted, QCH manual REQ=1. No clock writes. */
 if(P->Raw[1]!=0||!(P->Raw[4]&(1U<<21))||!(P->Raw[5]&(1U<<21))||
    (P->Raw[7]&3)!=2||(P->Raw[8]&3)!=2||!AdcClockUnchanged())goto Show;
 R->Reason=4;
 if(!(MmioRead32(0x10101000)&1)||!(MmioRead32(0x10102000)&1)||
   ((MmioRead32(0x10101004)&31)+1)*32<=ADC_IRQ||
   (MmioRead32(0x10101C1C)&(1U<<9))||
   (MmioRead32(0x10101874)&0xFF)!=1||
   (MmioRead32(0x10101474)&0xFF)>=(MmioRead32(0x10102004)&0xFF)||
   (MmioRead32(GIC_ENABLE)&IRQ_BIT)||(MmioRead32(GIC_PENDING)&IRQ_BIT)||
   (MmioRead32(GIC_ACTIVE)&IRQ_BIT))goto Show;
 S=gBS->LocateProtocol(&gHardwareInterruptProtocolGuid,NULL,(VOID**)&mAdcInterrupt);
 if(EFI_ERROR(S)||!mAdcInterrupt){R->Reason=5;goto Show;}
 R->Phase=2;R->Reason=6;
 R->Old[0]=MmioRead32(ADC_CON1);R->Old[1]=MmioRead32(ADC_CON2);R->Old[2]=MmioRead32(ADC_INT_EN);
 /* Never replay START/SOFT_RESET or another consumer's live interrupt state. */
 if((R->Old[0]&~2ULL)||(R->Old[1]&~0x7FULL)||R->Old[2])goto Show;
 R->Phase=3;R->Reason=7;
 OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 S=mAdcInterrupt->RegisterInterruptSource(mAdcInterrupt,ADC_IRQ,AdcInterrupt);
 if(!EFI_ERROR(S)){
  R->Registered=1;
  /* A real enable=1 observation is required; read-zero alone may be secure RAZ. */
  R->Enabled=AdcSourceState(TRUE)?1:0;
 }
 gBS->RestoreTPL(OldTpl);
 if(EFI_ERROR(S)){R->Status=S;goto Show;}
 if(!R->Enabled||R->Unexpected)goto Cleanup;
 R->Phase=4;R->Reason=8;R->Initialized=1;
 R->InitStep=1;MmioWrite32(ADC_CON1,4);MemoryFence();
 R->InitStep=2;MmioWrite32(ADC_CON1,2);MemoryFence();
 R->InitStep=3;MmioWrite32(ADC_CON2,0x60);
 R->InitStep=4;MmioWrite32(ADC_INT_EN,1);MemoryFence();
 if(R->Unexpected||MmioRead32(ADC_CON1)!=2||MmioRead32(ADC_CON2)!=0x60||MmioRead32(ADC_INT_EN)!=1)goto Cleanup;
 R->InitStep=5;MmioWrite32(ADC_CON2,(MmioRead32(ADC_CON2)&~15U)|4);MemoryFence();
 /* Pending check, state publication and START are atomic wrt this BSP's ISR. */
 OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
 if(R->Unexpected||!AdcClockUnchanged()||(MmioRead32(GIC_PENDING)&IRQ_BIT)||
    (MmioRead32(GIC_ACTIVE)&IRQ_BIT)||MmioRead32(ADC_CON1)!=2||MmioRead32(ADC_CON2)!=0x64){
  gBS->RestoreTPL(OldTpl);goto Cleanup;
 }
 R->Start=GetPerformanceCounter();R->Phase=5;R->Issued=1;MemoryFence();
 R->InitStep=6;MmioWrite32(ADC_CON1,3);MemoryFence();
 gBS->RestoreTPL(OldTpl);
 Previous=R->Start;R->Reason=9;R->Status=EFI_TIMEOUT;
 for(R->Polls=0;R->Polls<MAX_POLLS;R->Polls++){
  /* Decide ISR-vs-timeout under the same short IRQ exclusion as START. */
  OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);
  if(R->Done){
   Good=R->Irqs==1&&!R->Unexpected&&R->Ack==1&&R->Eoi==1&&
     !EFI_ERROR(R->EoiStatus)&&!EFI_ERROR(R->IrqDisableStatus)&&R->DataRaw!=MAX_UINT32&&
     R->IrqTick>=R->Start&&R->IrqTick-R->Start<=WAIT_TICKS;
   if(Good){R->Status=EFI_SUCCESS;R->Reason=0;R->Retired=1;}
   else{R->Status=EFI_DEVICE_ERROR;R->Reason=10;}
   R->Phase=6;gBS->RestoreTPL(OldTpl);break;
  }
  Now=GetPerformanceCounter();
  if(Now<Previous){R->Reason=11;R->Phase=6;gBS->RestoreTPL(OldTpl);break;}
  R->Stalled=Now==Previous?R->Stalled+1:0;
  if(R->Stalled>R->MaxStalled)R->MaxStalled=R->Stalled;
  if(Now-R->Start>=WAIT_TICKS||R->Stalled>=FROZEN_POLLS||R->Polls+1==MAX_POLLS){
   R->Reason=R->Stalled>=FROZEN_POLLS?12:(R->Polls+1==MAX_POLLS?13:9);
   R->Phase=6;gBS->RestoreTPL(OldTpl);break;
  }
  Previous=Now;gBS->RestoreTPL(OldTpl);CpuPause();
 }
Cleanup:
 OldTpl=gBS->RaiseTPL(TPL_HIGH_LEVEL);R->Phase=6;R->Cleanup=1;
 if(R->Initialized){
  /* Samsung exit does not prove an in-flight conversion was aborted. */
  MmioWrite32(ADC_CON2,MmioRead32(ADC_CON2)&~0x70U);
  MmioWrite32(ADC_INT_EN,0);MemoryFence();
 }
 S=mAdcInterrupt->DisableInterruptSource(mAdcInterrupt,ADC_IRQ);
 R->Disabled=!EFI_ERROR(S)&&AdcSourceState(FALSE);
 if(R->Disabled){
  S=mAdcInterrupt->RegisterInterruptSource(mAdcInterrupt,ADC_IRQ,NULL);
  R->Unregistered=!EFI_ERROR(S);
 }
 /* Only a proven new completion permits restoring original configuration.
  * A pre-START refusal may restore its settings; it did not retire a conversion. */
 if(R->Disabled&&R->Unregistered&&(!R->Issued||Good)&&!R->Unexpected){
  if(R->Initialized){
   MmioWrite32(ADC_CON2,(UINT32)R->Old[1]);
   MmioWrite32(ADC_CON1,(UINT32)R->Old[0]);MemoryFence();
  }
  R->After[0]=MmioRead32(ADC_CON1);R->After[1]=MmioRead32(ADC_CON2);R->After[2]=MmioRead32(ADC_INT_EN);
  R->Restored=R->After[0]==R->Old[0]&&R->After[1]==R->Old[1]&&R->After[2]==R->Old[2];
 }
 R->Pending=MmioRead32(GIC_PENDING)&IRQ_BIT;R->Active=MmioRead32(GIC_ACTIVE)&IRQ_BIT;
 if(!AdcClockUnchanged()||!R->Disabled||!R->Unregistered||!R->Restored||
    R->Pending||R->Active||R->Unexpected||(R->Issued&&!R->Retired)){
  R->Quarantine=1;R->Restored=0;
  if(!R->Reason){R->Reason=14;R->Status=EFI_DEVICE_ERROR;}
 }
 R->End=GetPerformanceCounter();R->Phase=8;
 if(!R->Disabled)AdcUnsafeStop();
 gBS->RestoreTPL(OldTpl);
Show:
 Print(L"\nSEC89 CONTROL1: channel4 handoff check; no charging commands\n");
 Print(L"ADC status %lx reason %lu phase %lu / init step %lu\n",R->Status,R->Reason,R->Phase,R->InitStep);
 Print(L"IRQ reg/en/dis/unreg %lu/%lu/%lu/%lu / issued %lu count %lu unexpected %lu\n",R->Registered,R->Enabled,R->Disabled,R->Unregistered,R->Issued,R->Irqs,R->Unexpected);
 Print(L"DAT raw %08lx sample %lu / ACK/EOI %lu/%lu EOI status %lx\n",R->DataRaw,R->Data12,R->Ack,R->Eoi,R->EoiStatus);
 Print(L"OLD C1/C2/IE %lx/%lx/%lx AFTER %lx/%lx/%lx\n",R->Old[0],R->Old[1],R->Old[2],R->After[0],R->After[1],R->After[2]);
 Print(L"Ticks start/IRQ/end %lx/%lx/%lx / Hz %lu polls %lu stalled %lu\n",R->Start,R->IrqTick,R->End,R->Hz,R->Polls,R->MaxStalled);
 Print(L"Cleanup/retired/restored/quarantine %lu/%lu/%lu/%lu\n",R->Cleanup,R->Retired,R->Restored,R->Quarantine);
 Print(L"Clock drift %lx pending %lx active %lx / ISR disable %lx\n",R->ClockDrift,R->Pending,R->Active,R->IrqDisableStatus);
 Print(L"Windows must acquire new three-sensor samples after the ADC handoff.\n");
 return (EFI_STATUS)R->Status;
}
