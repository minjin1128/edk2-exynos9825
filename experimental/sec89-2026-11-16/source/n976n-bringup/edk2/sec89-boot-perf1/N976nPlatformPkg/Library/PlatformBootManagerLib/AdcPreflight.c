/* SPDX-License-Identifier: MIT
 * Read-only fixed CMGP/GIC snapshot. No ADC peripheral access, IRQ claim,
 * conversion, clock mutation, input contract or charging permission.
 */
#include <PiDxe.h>
#include <N976nAdcPreflight.h>
#include <N976nUartAdmission.h>
#include <N976nAcpiPlatform.h>
#include <Library/BaseLib.h>
#include <Library/IoLib.h>
#include <Library/HobLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiLib.h>

volatile N976N_ADC_PREFLIGHT_REPORT mN976nAdcPreflightReport;
STATIC CONST UINTN mAdcPreflightAddresses[N976N_ADC_PREFLIGHT_WORDS]={
 0x15C00100,0x15C01000,0x15C01800,0x15C01804,0x15C02004,
 0x15C02008,0x15C03000,0x15C03008,0x15C0300C,
 0x10101000,0x10101004,0x10101008,0x1010110C,0x1010120C,
 0x1010130C,0x10101474,0x10101874,0x10101C1C,0x10102000,0x10102004
};
STATIC CONST VOID *AdcHob(CONST EFI_GUID *Guid,UINTN Bytes)
{
 VOID *H=GetFirstGuidHob(Guid);
 if(!H||GET_GUID_HOB_DATA_SIZE(H)!=Bytes||GetNextGuidHob(Guid,GET_NEXT_HOB(H)))return NULL;
 return GET_GUID_HOB_DATA(H);
}
VOID N976nObserveAdcPreflight(UINT64 Profile)
{
 volatile N976N_ADC_PREFLIGHT_REPORT *R=&mN976nAdcPreflightReport;
 CONST N976N_ADC_ADMISSION *A;CONST N976N_UART_ADMISSION *U;
 CONST N976N_ACPI_ADMISSION *G;
 if(R->Reached)return;
 R->Reached=1;R->Status=EFI_NOT_READY;
 if(Profile==N976N_PLATFORM_PROFILE_QEMU){R->Status=EFI_UNSUPPORTED;R->Reason=1;return;}
 /* Observe IRQ state BEFORE EfiGetCurrentTpl: its Raise/Restore may enable IRQ. */
 R->IrqEnabled=GetInterruptState();
 if(Profile!=N976N_PLATFORM_PROFILE_PHONE||!R->IrqEnabled){R->Reason=2;return;}
 if(EfiGetCurrentTpl()!=TPL_APPLICATION){R->Reason=2;return;}
 R->Reason=3;A=AdcHob(&gN976nAdcPreflightGuid,sizeof(*A));
 if(!A||A->Magic!=N976N_ADC_ADMISSION_MAGIC||A->Version!=1||A->Size!=sizeof(*A)||
   A->Profile!=Profile||A->Admitted!=1||A->Reason||A->Checks!=7||
   A->Adc!=0x15C40000||A->AdcBytes!=0x100||A->Cmu!=0x15C00000||
   A->Irq!=116||A->Clock!=110||A->ReadPlan!=1)goto Show;
 R->Reason=4;U=AdcHob(&gN976nUartAdmissionGuid,sizeof(*U));
 if(!U||U->Magic!=N976N_UART_ADMISSION_MAGIC||U->Version!=1||U->Size!=sizeof(*U)||
   U->Profile!=Profile||U->Admitted!=1||U->Reason||U->Checks!=N976N_UART_ADMISSION_CHECKS||
   U->CmuCmgp!=0x15C00000||U->CmuCmgpBytes!=0x8000)goto Show;
 /* PhoneSec maps only first 0x4000 CMGP bytes after touch ownership succeeds.
  * All selected addresses are within that Device-XN range, not ADC's page. */
 R->Reason=5;G=AdcHob(&gN976nAcpiAdmissionGuid,sizeof(*G));
 if(!N976nValidateAcpiAdmission(G,Profile))goto Show;
 R->Hz=GetPerformanceCounterProperties(NULL,NULL);
 if(R->Hz!=G->CounterFrequency){R->Reason=6;goto Show;}
 R->Begin=GetPerformanceCounter();
 for(UINTN I=0;I<N976N_ADC_PREFLIGHT_WORDS;I++){
   UINT32 V=MmioRead32(mAdcPreflightAddresses[I]);R->Raw[I]=V;
   if(V!=MAX_UINT32)R->Valid|=1ULL<<I;
 }
 R->End=GetPerformanceCounter();
 R->Reason=R->Valid==0xFFFFF?0:7;
 R->Status=R->Reason?EFI_DEVICE_ERROR:EFI_SUCCESS;
Show:
 Print(L"\nSEC89 ADC PREFLIGHT: fixed read-only snapshot, ADC NOT accessed\n");
 Print(L"ADC snapshot status %lx reason %lx valid %lx IRQ-on %lu Hz %lu\n",
   R->Status,R->Reason,R->Valid,R->IrqEnabled,R->Hz);
 Print(L"Expected ADC 15C40000 / GSIV116 / gate110; NOT ownership\n");
 for(UINTN I=0;I<N976N_ADC_PREFLIGHT_WORDS;I++){
   if(R->Valid&(1ULL<<I))Print(L"%08x:%08x ",(UINT32)mAdcPreflightAddresses[I],R->Raw[I]);
   else Print(L"%08x:-------- ",(UINT32)mAdcPreflightAddresses[I]);
   if(I%3==2||I+1==N976N_ADC_PREFLIGHT_WORDS)Print(L"\n");
 }
 Print(L"Zero GIC bits are not IRQ ownership. No ADC/clock/IRQ writes.\n");
}
