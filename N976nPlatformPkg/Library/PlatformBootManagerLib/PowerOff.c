/* SPDX-License-Identifier: MIT
 * SEC62 terminal diagnostic shutdown, not an OS/runtime reset service.
 * Samsung N976N exynos-pmu.c uses atomic clear alias +0x8000 with bit INDEX.
 * Do not copy 9810 +0x330C/RMW. ACPM shared queues and charging/reboot policy
 * are intentionally not owned here: this is a bounded physical experiment.
 */
#include <PiDxe.h>
#include <N976nPowerOff.h>
#include <AArch64/AArch64Mmu.h>
#include <IndustryStandard/ArmStdSmc.h>
#include <Library/ArmLib.h>
#include <Library/ArmMonitorLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Library/TimerLib.h>

volatile N976N_POWER_REPORT mN976nPowerReport;
STATIC N976N_POWER_ADMISSION mPowerAdmission;
STATIC CONST N976N_PLATFORM_HANDOFF *mPowerHandoff;
STATIC N976N_PLATFORM_HANDOFF mPowerHandoffCopy;
STATIC BOOLEAN mPowerPrepared;
STATIC UINT64 mPowerFrequency;
typedef struct { UINT64 El, Sctlr, Tcr, Root, Mair; } POWER_CPU;
STATIC POWER_CPU mPowerCpu;
#ifdef N976N_POWER_HOST_TEST
STATIC VOID PowerReadCpu (POWER_CPU *Cpu);
#else
STATIC VOID PowerReadCpu (POWER_CPU *Cpu) {
  ZeroMem(Cpu,sizeof(*Cpu));
  __asm__ volatile("mrs %0, CurrentEL":"=r"(Cpu->El));
  if(Cpu->El!=4)return;
  __asm__ volatile("mrs %0, sctlr_el1":"=r"(Cpu->Sctlr));
  __asm__ volatile("mrs %0, tcr_el1":"=r"(Cpu->Tcr));
  __asm__ volatile("mrs %0, ttbr0_el1":"=r"(Cpu->Root));
  __asm__ volatile("mrs %0, mair_el1":"=r"(Cpu->Mair));
}
#endif
STATIC BOOLEAN Within (UINT64 Base, UINT64 Bytes, UINT64 Address, UINT64 Size) {
  return Bytes && Size && Base<=MAX_UINT64-Bytes && Address>=Base && Address<Base+Bytes && Size<=Base+Bytes-Address;
}
/* Three exact admitted pages, EL1 identity Device-nGnRnE/RW/XN. Follow only
   low firmware-owned table pages; reject block mappings and table controls. */
STATIC BOOLEAN PowerMapping (CONST N976N_PLATFORM_HANDOFF *H, CONST POWER_CPU *Cpu) {
  STATIC CONST UINT64 Pages[]={N976N_POWER_PMU,N976N_POWER_PMU+0x8000,N976N_POWER_GPIO};
  UINTN T0=Cpu->Tcr&63;
  if(!H || !H->HeapSize || ((H->HeapBase|H->HeapSize)&4095) ||
      H->HeapSize>MAX_UINT64-H->HeapBase || Cpu->El!=4 ||
      (Cpu->Sctlr&(BIT0|BIT2))!=(BIT0|BIT2) || (Cpu->Sctlr&BIT25) ||
      T0<16 || T0>39 || (Cpu->Tcr&(BIT7|BIT14|BIT15|BIT37|BIT39|BIT40|BIT59)) ||
      ((Cpu->Tcr>>32)&7)>5 || (Cpu->Root&0xFFE))return FALSE;
  for(UINTN P=0;P<ARRAY_SIZE(Pages);P++) {
    UINT64 Table=Cpu->Root&TT_ADDRESS_MASK_DESCRIPTION_TABLE, Entry=0;
    if(Pages[P]+4096>(1ULL<<(64-T0)))return FALSE;
    for(UINTN L=(T0-16)/9;L<=3;L++) {
      if(!Within(H->HeapBase,H->HeapSize,Table,4096))return FALSE;
      Entry=((volatile UINT64 *)(UINTN)Table)[(Pages[P]>>(12+(3-L)*9))&511];
      if((Entry&3)!=3)return FALSE;
      if(L<3) {
        if(Entry&(BIT59|BIT60|BIT61|BIT62|BIT63))return FALSE;
        Table=Entry&TT_ADDRESS_MASK_DESCRIPTION_TABLE;
      }
    }
    if((Entry&TT_ADDRESS_MASK_BLOCK_ENTRY)!=Pages[P] || !(Entry&TT_AF) ||
       (Entry&TT_AP_MASK)!=TT_AP_NO_RW ||
       (Entry&(TT_PXN_MASK|TT_UXN_MASK))!=(TT_PXN_MASK|TT_UXN_MASK) ||
       (Entry&TT_SH_MASK)!=0 || ((Cpu->Mair>>(((Entry>>2)&7)*8))&255)!=0)return FALSE;
  }
  return TRUE;
}
STATIC BOOLEAN AdmissionValid (CONST N976N_POWER_ADMISSION *A) {
  return A->Magic==N976N_POWER_ADMISSION_MAGIC && A->Version==1 && A->Size==sizeof(*A) &&
    A->Admitted==1 && A->Reason==0 && A->Checks==0xFF && A->PmuBase==N976N_POWER_PMU &&
    A->GpioBase==N976N_POWER_GPIO && A->PowerPin==4 && A->DownPin==4 &&
    A->PowerPhandle && A->PowerPhandle!=MAX_UINT32 && A->DownPhandle &&
    A->DownPhandle!=MAX_UINT32 && A->PowerPhandle!=A->DownPhandle;
}
STATIC BOOLEAN FreshMapping (VOID) {
  POWER_CPU Cpu;PowerReadCpu(&Cpu);
  return mPowerHandoff && CompareMem(mPowerHandoff,&mPowerHandoffCopy,sizeof(mPowerHandoffCopy))==0 &&
    mPowerHandoffCopy.Profile==N976N_PLATFORM_PROFILE_PHONE &&
    PcdGet32(PcdN976nPlatformProfile)==N976N_PLATFORM_PROFILE_PHONE &&
    CompareMem(&Cpu,&mPowerCpu,sizeof(Cpu))==0 && PowerMapping(&mPowerHandoffCopy,&Cpu);
}
STATIC EFI_STATUS Deny (UINT64 Reason) {
  mN976nPowerReport.Phase=1;mN976nPowerReport.Reason=Reason;
  mN976nPowerReport.Status=EFI_ACCESS_DENIED;return EFI_ACCESS_DENIED;
}
EFI_STATUS N976nPreparePowerOff (CONST N976N_PLATFORM_HANDOFF *H, BOOLEAN StorageClosed) {
  UINT64 Start,End; VOID *Hob;
  ZeroMem((VOID *)&mN976nPowerReport,sizeof(mN976nPowerReport));
  ZeroMem(&mPowerAdmission,sizeof(mPowerAdmission));ZeroMem(&mPowerCpu,sizeof(mPowerCpu));
  mPowerHandoff=H;mPowerPrepared=TRUE;mPowerFrequency=0;
  mN976nPowerReport.Magic=N976N_POWER_REPORT_MAGIC;mN976nPowerReport.Version=1;
  mN976nPowerReport.Size=sizeof(mN976nPowerReport);mN976nPowerReport.Phase=1;
  mN976nPowerReport.Status=EFI_NOT_READY;mN976nPowerReport.PsciReturn=MAX_UINT64;
  mN976nPowerReport.Seconds=120;
  if(!H || H->Magic!=N976N_PLATFORM_HANDOFF_MAGIC || H->Version!=N976N_PLATFORM_ABI_VERSION ||
      H->Size!=sizeof(*H) || H->Reserved || H->Profile>1 ||
      H->Profile!=PcdGet32(PcdN976nPlatformProfile))return Deny(1);
  CopyMem(&mPowerHandoffCopy,H,sizeof(*H));
  mN976nPowerReport.Profile=H->Profile;
  if(!StorageClosed)return Deny(2);
  mN976nPowerReport.Checks=3;
  mPowerFrequency=GetPerformanceCounterProperties(&Start,&End);
  if(mPowerFrequency<1000 || mPowerFrequency>1000000000ULL || Start!=0 || End!=MAX_UINT64)return Deny(3);
  mN976nPowerReport.Checks|=BIT4;
  if(H->Profile==N976N_PLATFORM_PROFILE_QEMU) {
    mN976nPowerReport.Seconds=3;mN976nPowerReport.Phase=2;return EFI_SUCCESS;
  }
  Hob=GetFirstGuidHob(&gN976nPowerAdmissionGuid);
  if(!Hob || !Within(H->HeapBase,H->HeapSize,(UINTN)Hob,sizeof(EFI_HOB_GUID_TYPE)) ||
      GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(mPowerAdmission) ||
      !Within(H->HeapBase,H->HeapSize,(UINTN)GET_GUID_HOB_DATA(Hob),sizeof(mPowerAdmission)))return Deny(4);
  CopyMem(&mPowerAdmission,GET_GUID_HOB_DATA(Hob),sizeof(mPowerAdmission));
  if(!AdmissionValid(&mPowerAdmission))return Deny(5);
  mN976nPowerReport.Checks|=BIT2;
  PowerReadCpu(&mPowerCpu);
  if(!PowerMapping(H,&mPowerCpu))return Deny(6);
  mN976nPowerReport.MmuChecks=7;mN976nPowerReport.Checks|=BIT3;
  mN976nPowerReport.PsHoldBefore=MmioRead32(N976N_POWER_HOLD);
  if(mN976nPowerReport.PsHoldBefore==MAX_UINT32 || !(mN976nPowerReport.PsHoldBefore&BIT8))return Deny(7);
  mN976nPowerReport.Checks|=BIT5;mN976nPowerReport.Phase=2;return EFI_SUCCESS;
}
__attribute__((noinline)) VOID EFIAPI N976nPowerReadyCheckpoint (VOID) { MemoryFence(); }
STATIC BOOLEAN PowerKeys (BOOLEAN *Down, BOOLEAN *Power) {
  UINT32 D,P;
  if(!FreshMapping())return FALSE;
  D=MmioRead32(N976N_POWER_GPIO+4);P=MmioRead32(N976N_POWER_GPIO+0x44);
  mN976nPowerReport.KeyRaw=((UINT64)P<<32)|D;
  if(D==MAX_UINT32 || P==MAX_UINT32)return FALSE;
  *Down=(D&BIT4)==0;*Power=(P&BIT4)==0;return TRUE;
}
/* counter is architected increasing, modulo arithmetic handles its wrap */
STATIC UINT64 Milliseconds (UINT64 Begin) {
  UINT64 Delta=GetPerformanceCounter()-Begin;
  return Delta/mPowerFrequency*1000 + (Delta%mPowerFrequency)*1000/mPowerFrequency;
}
STATIC VOID Park (VOID) {
  DisableInterrupts();for(;;)ArmCallWFI();
}
VOID N976nPowerOffWait (CONST N976N_PLATFORM_HANDOFF *H, BOOLEAN StorageClosed,
  EFI_STATUS (*Black)(VOID), VOID (*Refresh)(VOID)) {
  UINT64 Begin,HoldStart=0,ReleaseStart=0;BOOLEAN Held=FALSE,Qualified=FALSE,Released=FALSE,Down=FALSE,Power=FALSE;
  BOOLEAN Ready;ARM_MONITOR_ARGS Args;
  if(!mPowerPrepared || H!=mPowerHandoff)N976nPreparePowerOff(H,StorageClosed);
  if(!StorageClosed)Deny(2);
  Ready=mN976nPowerReport.Phase==2;
  if(Refresh)Refresh();N976nPowerReadyCheckpoint();
  if(!mPowerFrequency || mPowerFrequency<1000) {
    if(Black)Black();Park();return;
  }
  Begin=GetPerformanceCounter();
  /* A failed admission retains the photo interval, but never touches MMIO. */
  while(Milliseconds(Begin)<mN976nPowerReport.Seconds*1000) {
    if(Ready && H->Profile==N976N_PLATFORM_PROFILE_PHONE) {
      if(!PowerKeys(&Down,&Power)){Deny(8);Ready=FALSE;}
      else if(Down) {
        if(!Held){HoldStart=GetPerformanceCounter();Held=TRUE;Qualified=FALSE;}
        if(Milliseconds(HoldStart)>=2000)Qualified=TRUE;
        Released=FALSE;
      }
      else if(Held) {
        if(Qualified && !Power) {
          if(!Released){ReleaseStart=GetPerformanceCounter();Released=TRUE;}
          if(Milliseconds(ReleaseStart)>=100){mN976nPowerReport.Trigger=2;break;}
        } else {Held=FALSE;Qualified=FALSE;Released=FALSE;}
      }
    }
    MicroSecondDelay(50000);
  }
  if(!mN976nPowerReport.Trigger)mN976nPowerReport.Trigger=1;
  if(Ready && H->Profile==N976N_PLATFORM_PROFILE_PHONE) {
    Begin=GetPerformanceCounter();Released=FALSE;
    do {
      if(!PowerKeys(&Down,&Power)){Deny(8);Ready=FALSE;break;}
      if(!Power && !Down) {
        if(!Released){ReleaseStart=GetPerformanceCounter();Released=TRUE;}
        if(Milliseconds(ReleaseStart)>=100)break;
      } else Released=FALSE;
      MicroSecondDelay(50000);
    } while(Milliseconds(Begin)<10000);
    if(!Released || Milliseconds(ReleaseStart)<100){Deny(9);Ready=FALSE;}
    if(Ready && (!FreshMapping() || !AdmissionValid(&mPowerAdmission) ||
       MmioRead32(N976N_POWER_HOLD)!=mN976nPowerReport.PsHoldBefore)){Deny(10);Ready=FALSE;}
  }
  /* Black callback is validated GOP/Blt owned by the terminal caller. */
  if(!Black || EFI_ERROR(Black())) {Deny(11);Park();return;}
  if(!Ready){Park();return;}
  DisableInterrupts();mN976nPowerReport.Phase=4;mN976nPowerReport.Checks|=BIT6;
  ZeroMem(&Args,sizeof(Args));Args.Arg0=ARM_SMC_ID_PSCI_SYSTEM_OFF;
  mN976nPowerReport.Attempts=1;MemoryFence();ArmMonitorCall(&Args);
  mN976nPowerReport.PsciReturn=Args.Arg0;
  if(H->Profile==N976N_PLATFORM_PROFILE_PHONE) {
    /* Recheck actual CPU/PTE and key after monitor return. A changed world
       gets no fallback. Exact Samsung atomic clear; no ACPM/PMIC/inform writes. */
    if(!PowerKeys(&Down,&Power) || Down || Power ||
       MmioRead32(N976N_POWER_HOLD)!=mN976nPowerReport.PsHoldBefore){Deny(12);Park();return;}
    mN976nPowerReport.Checks|=BIT7;mN976nPowerReport.Attempts=2;
    MmioWrite32(N976N_POWER_CLEAR,8);ArmDataSynchronizationBarrier();
    ArmInstructionSynchronizationBarrier();MicroSecondDelay(100000);
    mN976nPowerReport.PsHoldAfter=MmioRead32(N976N_POWER_HOLD);
  }
  mN976nPowerReport.Phase=5;mN976nPowerReport.Status=EFI_DEVICE_ERROR;
  mN976nPowerReport.Reason=13;MemoryFence();Park();
}
