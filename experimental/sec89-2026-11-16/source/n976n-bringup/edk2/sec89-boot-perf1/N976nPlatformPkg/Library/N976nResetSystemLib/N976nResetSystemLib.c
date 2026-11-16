/* SPDX-License-Identifier: MIT
 * Samsung N976N final reset/power-off, reached through upstream ResetSystemDxe.
 * No Boot Services, HOB, allocation, log or OS pointer is used in Reset*.
 * Windows must finish its normal storage shutdown before calling ResetSystem.
 * Idle doorbells are an additional device check, NOT a cache-flush guarantee.
 */
#ifndef N976N_RUNTIME_POWER_HOST_TEST
#include <PiDxe.h>
#include <N976nRuntimePower.h>
#include <N976nUfs.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Library/ResetSystemLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiRuntimeLib.h>
#endif

STATIC UINTN mPages[N976N_RUNTIME_POWER_PAGES];
STATIC UINT64 mFrequency;
STATIC BOOLEAN mReady, mVirtualReady, mConversionFailed;
STATIC EFI_EVENT mVirtualEvent;
STATIC N976N_RUNTIME_POWER_READY mReadyProtocol = {N976N_RUNTIME_POWER_MAGIC,1,0,0};
/* Small runtime record readable through the matching firmware symbols in KD.
 * Reason: 1=not ready, 2=conversion, 3=HCI invalid, 4=busy, 5=clock stuck,
 * 6=power key held, 7=PS_HOLD invalid, 8=write returned. Never report success
 * merely because the final MMIO write returned. */
volatile struct { UINT64 Calls, Type, Reason, Polls, Hce, Hcs, Dbr, TmDbr, Key, Hold; }
  mN976nRuntimePowerReport;

STATIC BOOLEAN AdmissionValid(CONST N976N_POWER_ADMISSION *A) {
  return A->Magic==N976N_POWER_ADMISSION_MAGIC && A->Version==1 &&
    A->Size==sizeof(*A) && A->Admitted==1 && A->Reason==0 && A->Checks==0xFF &&
    A->PmuBase==N976N_POWER_PMU && A->GpioBase==N976N_POWER_GPIO &&
    A->PowerPin==4 && A->DownPin==4 && A->PowerPhandle &&
    A->PowerPhandle!=MAX_UINT32 && A->DownPhandle &&
    A->DownPhandle!=MAX_UINT32 && A->PowerPhandle!=A->DownPhandle;
}

STATIC VOID EFIAPI VirtualAddressChange(EFI_EVENT Event, VOID *Context) {
  UINTN Converted[N976N_RUNTIME_POWER_PAGES];
  /* Commit all pointers together. A failed conversion permanently blocks MMIO. */
  if(mVirtualReady || mConversionFailed) {mConversionFailed=TRUE;return;}
  mVirtualReady=FALSE;
  for(UINTN I=0;I<N976N_RUNTIME_POWER_PAGES;++I) {
    VOID *P=(VOID *)mPages[I];
    if(EFI_ERROR(EfiConvertPointer(0,&P)) || !P || ((UINTN)P&EFI_PAGE_MASK)) {
      mConversionFailed=TRUE;return;
    }
    Converted[I]=(UINTN)P;
  }
  for(UINTN I=0;I<N976N_RUNTIME_POWER_PAGES;++I)mPages[I]=Converted[I];
  mVirtualReady=TRUE;
}

STATIC EFI_STATUS MarkRuntime(UINT64 Address) {
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR D;
  EFI_STATUS S=gDS->GetMemorySpaceDescriptor(Address,&D);
  UINT64 A=EFI_MEMORY_UC|EFI_MEMORY_XP|EFI_MEMORY_RUNTIME;
  if(EFI_ERROR(S))return S;
  if(D.BaseAddress>Address || D.Length<EFI_PAGE_SIZE ||
     Address-D.BaseAddress>D.Length-EFI_PAGE_SIZE)return EFI_COMPROMISED_DATA;
  if(D.GcdMemoryType==EfiGcdMemoryTypeNonExistent) {
    S=gDS->AddMemorySpace(EfiGcdMemoryTypeMemoryMappedIo,Address,EFI_PAGE_SIZE,A);
    if(EFI_ERROR(S))return S;
  } else {
    if(D.GcdMemoryType!=EfiGcdMemoryTypeMemoryMappedIo ||
       (D.Attributes && D.Attributes!=EFI_MEMORY_UC && D.Attributes!=A))
      return EFI_ACCESS_DENIED;
    S=gDS->SetMemorySpaceCapabilities(Address,EFI_PAGE_SIZE,D.Capabilities|A);
    if(EFI_ERROR(S))return S;
  }
  S=gDS->SetMemorySpaceAttributes(Address,EFI_PAGE_SIZE,A);
  if(EFI_ERROR(S))return S;
  S=gDS->GetMemorySpaceDescriptor(Address,&D);
  return !EFI_ERROR(S) && D.GcdMemoryType==EfiGcdMemoryTypeMemoryMappedIo &&
    D.BaseAddress==Address && D.Length==EFI_PAGE_SIZE && D.Attributes==A ?
    EFI_SUCCESS:EFI_SECURITY_VIOLATION;
}

EFI_STATUS EFIAPI N976nResetSystemLibConstructor(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable) {
  N976N_POWER_ADMISSION A;
  UINT64 Start,End;
  EFI_STATUS S;
  VOID *Hob=GetFirstGuidHob(&gN976nPowerAdmissionGuid);
  if(PcdGet32(PcdN976nPlatformProfile)!=N976N_PLATFORM_PROFILE_PHONE || !Hob ||
     GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(A) ||
     GetNextGuidHob(&gN976nPowerAdmissionGuid,GET_NEXT_HOB(Hob)))return EFI_UNSUPPORTED;
  CopyMem(&A,GET_GUID_HOB_DATA(Hob),sizeof(A));
  if(!AdmissionValid(&A))return EFI_SECURITY_VIOLATION;
  Hob=GetFirstGuidHob(&gN976nPlatformHandoffGuid);
  if(!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_PLATFORM_HANDOFF) ||
     GetNextGuidHob(&gN976nPlatformHandoffGuid,GET_NEXT_HOB(Hob)))return EFI_COMPROMISED_DATA;
  CONST N976N_PLATFORM_HANDOFF *H=GET_GUID_HOB_DATA(Hob);
  if(H->Magic!=N976N_PLATFORM_HANDOFF_MAGIC || H->Version!=N976N_PLATFORM_ABI_VERSION ||
     H->Size!=sizeof(*H) || H->Profile!=N976N_PLATFORM_PROFILE_PHONE || H->Reserved)
    return EFI_SECURITY_VIOLATION;
  Hob=GetFirstGuidHob(&gN976nUfsAdmissionGuid);
  if(!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_UFS_ADMISSION) ||
     GetNextGuidHob(&gN976nUfsAdmissionGuid,GET_NEXT_HOB(Hob)))return EFI_COMPROMISED_DATA;
  CONST N976N_UFS_ADMISSION *U=GET_GUID_HOB_DATA(Hob);
  if(U->Magic!=N976N_UFS_ADMISSION_MAGIC || U->Version!=N976N_UFS_ADMISSION_VERSION ||
     U->Size!=sizeof(*U) || U->Admitted!=1 || U->Reason ||
     U->Hci!=N976N_RUNTIME_POWER_HCI || U->Vendor!=0x13D61100 || U->Coherency!=0x13C10700)
    return EFI_SECURITY_VIOLATION;
  mFrequency=GetPerformanceCounterProperties(&Start,&End);
  if(mFrequency<1000 || mFrequency>1000000000ULL || Start || End!=MAX_UINT64)
    return EFI_UNSUPPORTED;
  for(UINTN I=0;I<N976N_RUNTIME_POWER_PAGES;++I) {
    mPages[I]=(UINTN)mN976nRuntimePowerPages[I];
    S=MarkRuntime(mPages[I]);if(EFI_ERROR(S))return S;
    mReadyProtocol.MapMask|=1ULL<<I;
  }
  S=gBS->CreateEvent(EVT_SIGNAL_VIRTUAL_ADDRESS_CHANGE,TPL_NOTIFY,
      VirtualAddressChange,NULL,&mVirtualEvent);
  if(EFI_ERROR(S))return S;
  mReadyProtocol.Ready=1;
  S=gBS->InstallProtocolInterface(&ImageHandle,&gN976nRuntimePowerReadyGuid,
      EFI_NATIVE_INTERFACE,&mReadyProtocol);
  if(EFI_ERROR(S)) {mReadyProtocol.Ready=0;gBS->CloseEvent(mVirtualEvent);return S;}
  mReady=TRUE;return EFI_SUCCESS;
}

STATIC BOOLEAN ReadyForCut(BOOLEAN Shutdown) {
  if(!mReady || !mFrequency) {mN976nRuntimePowerReport.Reason=1;return FALSE;}
  if(mConversionFailed || (EfiGoneVirtual()&&!mVirtualReady)) {
    mN976nRuntimePowerReport.Reason=2;return FALSE;
  }
  UINT64 Begin=GetPerformanceCounter(),Previous=Begin,Same=0;
  /* One second max for hardware idle/key release, with an independent stopped
   * counter watchdog. No stalls depending on an advancing timer. */
  for(;;) {
    UINT32 Hce=MmioRead32(mPages[4]+0x34),Hcs=MmioRead32(mPages[4]+0x30);
    UINT32 Dbr=MmioRead32(mPages[4]+0x58),Tm=MmioRead32(mPages[4]+0x78);
    UINT32 Key=Shutdown?MmioRead32(mPages[3]+0x44):BIT4;
    mN976nRuntimePowerReport.Hce=Hce;mN976nRuntimePowerReport.Hcs=Hcs;
    mN976nRuntimePowerReport.Dbr=Dbr;mN976nRuntimePowerReport.TmDbr=Tm;
    mN976nRuntimePowerReport.Key=Key;++mN976nRuntimePowerReport.Polls;
    /* HCE=0 is a valid OS-stopped controller only with no pending doorbells.
     * HCE=1 requires DevicePresent. Other/reserved HCE bits are unsupported. */
    if(Hce>1 || Hcs==MAX_UINT32 || Key==MAX_UINT32 || (Hce==1 && !(Hcs&BIT0))) {
      mN976nRuntimePowerReport.Reason=3;return FALSE;
    }
    if(Dbr==0 && Tm==0 && (Key&BIT4))break;
    UINT64 Now=GetPerformanceCounter();
    Same=Now==Previous?Same+1:0;Previous=Now;
    if(Same>=200000) {mN976nRuntimePowerReport.Reason=5;return FALSE;}
    if(Now-Begin>=mFrequency) {
      mN976nRuntimePowerReport.Reason=(Dbr||Tm)?4:6;return FALSE;
    }
  }
  UINT32 Hold=MmioRead32(mPages[0]+0x30C);
  mN976nRuntimePowerReport.Hold=Hold;
  if(Hold==MAX_UINT32 || !(Hold&BIT8)) {mN976nRuntimePowerReport.Reason=7;return FALSE;}
  return TRUE;
}

STATIC VOID FinalReset(BOOLEAN Shutdown) {
  ++mN976nRuntimePowerReport.Calls;
  mN976nRuntimePowerReport.Type=Shutdown?2:0;
  mN976nRuntimePowerReport.Reason=0;mN976nRuntimePowerReport.Polls=0;
  if(!ReadyForCut(Shutdown))return;
  /* Samsung exynos9820/9825: atomic alias takes a BIT INDEX, not a bitmask.
   * All OS/device persistence work precedes this endpoint. No storage writes. */
  MemoryFence();
  if(Shutdown)MmioWrite32(mPages[2]+0x30C,8);
  else MmioWrite32(mPages[1]+0xA00,2);
  MemoryFence();
  /* Give the asynchronous PMU request time to complete before the OS regards
   * a returned ResetSystem as failure. Both a wall limit and a stopped-clock
   * limit apply. No further MMIO is touched after the request. */
  UINT64 Begin=GetPerformanceCounter(),Previous=Begin,Same=0;
  for(;;) {
    UINT64 Now=GetPerformanceCounter();
    Same=Now==Previous?Same+1:0;Previous=Now;
    if(Now-Begin>=mFrequency/10 || Same>=200000)break;
  }
  mN976nRuntimePowerReport.Reason=8;
}
VOID EFIAPI ResetCold(VOID) {FinalReset(FALSE);}
VOID EFIAPI ResetWarm(VOID) {FinalReset(FALSE);}
VOID EFIAPI ResetShutdown(VOID) {FinalReset(TRUE);}
VOID EFIAPI ResetPlatformSpecific(UINTN DataSize, VOID *ResetData) {ResetCold();}
