/* SPDX-License-Identifier: MIT
 * SEC88 SMP2: observed A55 identity plus standard GICv2 OS parking.
 * Samsung N976N DT's legacy arm,psci CPU_ON is SMC 0xC4000003. Linux passes
 * DT reg target, physical secondary_entry, context zero. DT targets are not
 * architectural MPIDR affinities on the observed N976N entry path.
 * Do not use the 9810 demo's
 * CPU_ON return alone as evidence of a live AP or publish extra MADT CPUs.
 */
#include <PiDxe.h>
#include <N976nA55Probe.h>
#include <N976nAcpiPlatform.h>
#include <AArch64/AArch64Mmu.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/ArmMonitorLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>

#define PAGE 4096U
#define AP_GUARD 0x314452473535414EULL
#define MPIDR_AFFINITY 0xFF00FFFFFFULL
#define CLOCK_STALL_LIMIT 200000U
volatile N976N_A55_PROBE_REPORT mN976nA55ProbeReport;
STATIC BOOLEAN mAttempted;
STATIC UINT64 mProfile=MAX_UINT64;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mAttributes;
typedef struct {UINT64 CpuOnTarget,ExpectedAffinity;} A55_IDENTITY;
STATIC CONST A55_IDENTITY mA55Identity[3]={
  {N976N_A55_TARGET1,N976N_A55_AFFINITY1}, /* observed AP1 */
  {N976N_A55_TARGET2,N976N_A55_AFFINITY2}, /* observed IMG_0404 */
  {N976N_A55_TARGET3,N976N_A55_AFFINITY3}  /* observed IMG_0404 */
};
typedef struct {UINT64 El,Sctlr,Tcr,Root,Mair,Mpidr,Midr;} A55_CPU;
#ifdef N976N_A55_HOST_TEST
STATIC VOID A55ReadCpu(A55_CPU *C);
#else
STATIC VOID A55ReadCpu(A55_CPU *C) {
  ZeroMem(C,sizeof(*C));
  __asm__ volatile("mrs %0, CurrentEL":"=r"(C->El));
  if(C->El!=4)return;
  __asm__ volatile("mrs %0, sctlr_el1":"=r"(C->Sctlr));
  __asm__ volatile("mrs %0, tcr_el1":"=r"(C->Tcr));
  __asm__ volatile("mrs %0, ttbr0_el1":"=r"(C->Root));
  __asm__ volatile("mrs %0, mair_el1":"=r"(C->Mair));
  __asm__ volatile("mrs %0, mpidr_el1":"=r"(C->Mpidr));
  __asm__ volatile("mrs %0, midr_el1":"=r"(C->Midr));
}
#endif

/* Actual identity leaves; follow only firmware-owned low table pages. Code
 * is Normal WB/RO/X (AP permissions forbid EL0), every other arena page
 * Device/RW/PXN/UXN. Match the existing EDK2 executable-page contract.
 * A table attribute or block mapping cannot silently widen the contract. */
STATIC BOOLEAN A55Page(UINT64 Address,CONST A55_CPU *C,BOOLEAN Code) {
  UINTN T0=C->Tcr&63;
  if((Address&4095) || C->El!=4 || (C->Sctlr&5)!=5 || (C->Sctlr&BIT25) ||
     T0<16 || T0>39 || (C->Tcr&(BIT7|BIT14|BIT15|BIT37|BIT39|BIT40|BIT59)) ||
     ((C->Tcr>>32)&7)>5 || (C->Root&0xFFE) || Address>MAX_UINT64-PAGE ||
     Address+PAGE>(1ULL<<(64-T0)))return FALSE;
  UINT64 Table=C->Root&TT_ADDRESS_MASK_DESCRIPTION_TABLE,Entry=0;
  for(UINTN L=(T0-16)/9;L<=3;++L) {
    if(Table<N976N_BOOTSTRAP_HEAP_BASE || Table>N976N_BOOTSTRAP_HEAP_END-PAGE)return FALSE;
    Entry=((volatile UINT64 *)(UINTN)Table)[(Address>>(12+(3-L)*9))&511];
    if((Entry&3)!=3)return FALSE;
    if(L<3) {
      if(Entry&(BIT59|BIT60|BIT61|BIT62|BIT63))return FALSE;
      Table=Entry&TT_ADDRESS_MASK_DESCRIPTION_TABLE;
    }
  }
  if((Entry&TT_ADDRESS_MASK_BLOCK_ENTRY)!=Address || !(Entry&TT_AF))return FALSE;
  UINT64 Mair=(C->Mair>>(((Entry>>2)&7)*8))&255;
  if(Code)return (Entry&TT_AP_MASK)==TT_AP_NO_RO && !(Entry&(TT_PXN_MASK|TT_UXN_MASK)) &&
    (Entry&TT_SH_MASK)==TT_SH_INNER_SHAREABLE && Mair==255;
  return (Entry&TT_AP_MASK)==TT_AP_NO_RW &&
    (Entry&(TT_PXN_MASK|TT_UXN_MASK))==(TT_PXN_MASK|TT_UXN_MASK) &&
    (Entry&TT_SH_MASK)==0 && Mair==0;
}

STATIC BOOLEAN A55ArenaBounds(UINT64 A) {
  return !(A&(PAGE-1)) && A>=N976N_BOOTSTRAP_HEAP_BASE &&
    A<=N976N_BOOTSTRAP_HEAP_END-N976N_A55_PROBE_ARENA_BYTES;
}

STATIC BOOLEAN A55Owned(UINT64 A) {
  UINTN Bytes=0,Key=0,Stride=0;UINT32 Version=0;
  EFI_STATUS S=gBS->GetMemoryMap(&Bytes,NULL,&Key,&Stride,&Version);
  if(S!=EFI_BUFFER_TOO_SMALL || Stride<sizeof(EFI_MEMORY_DESCRIPTOR) ||
     Bytes>MAX_UINTN-8*Stride)return FALSE;
  Bytes+=8*Stride;
  EFI_MEMORY_DESCRIPTOR *Map=AllocatePool(Bytes);
  if(!Map)return FALSE;
  S=gBS->GetMemoryMap(&Bytes,Map,&Key,&Stride,&Version);
  UINT64 Covered=0;BOOLEAN Ok=!EFI_ERROR(S) && Stride>=sizeof(*Map) && Bytes && !(Bytes%Stride);
  for(UINTN I=0;Ok && I<Bytes;I+=Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D=(CONST VOID *)((CONST UINT8 *)Map+I);
    if((D->PhysicalStart&(PAGE-1)) || !D->NumberOfPages || D->NumberOfPages>MAX_UINT64/PAGE ||
       D->PhysicalStart>MAX_UINT64-D->NumberOfPages*PAGE){Ok=FALSE;break;}
    UINT64 End=D->PhysicalStart+D->NumberOfPages*PAGE;
    if(End<=A || D->PhysicalStart>=A+N976N_A55_PROBE_ARENA_BYTES)continue;
    if(D->Type!=EfiReservedMemoryType || (D->Attribute&EFI_MEMORY_RUNTIME)){Ok=FALSE;break;}
    for(UINTN P=0;P<8;++P)if(D->PhysicalStart<=A+P*PAGE && End>=A+(P+1)*PAGE) {
      if(Covered&(1ULL<<P)){Ok=FALSE;break;}
      Covered|=1ULL<<P;
    }
  }
  FreePool(Map);
  return Ok && Covered==255;
}

STATIC BOOLEAN A55Maps(UINT64 A) {
  if(!A55ArenaBounds(A) || !mAttributes || !A55Owned(A))return FALSE;
  A55_CPU C;A55ReadCpu(&C);
  for(UINTN I=0;I<8;++I) {
    UINT64 P=A+I*PAGE,Attr=0,Want=I==1?EFI_MEMORY_RO:EFI_MEMORY_XP;
    EFI_GCD_MEMORY_SPACE_DESCRIPTOR G;
    if(!A55Page(P,&C,I==1) || EFI_ERROR(gDS->GetMemorySpaceDescriptor(P,&G)) ||
       G.GcdMemoryType!=EfiGcdMemoryTypeSystemMemory || G.BaseAddress>P ||
       G.Length<PAGE || P-G.BaseAddress>G.Length-PAGE ||
       G.Attributes!=(Want|(I==1?EFI_MEMORY_WB:EFI_MEMORY_UC)) ||
       EFI_ERROR(mAttributes->GetMemoryAttributes(mAttributes,P,PAGE,&Attr)) || Attr!=Want)return FALSE;
  }
  return TRUE;
}

STATIC BOOLEAN A55StubBounds(UINTN *Bytes,UINTN *Config) {
  UINTN Start=(UINTN)N976nA55EntryStart,End=(UINTN)N976nA55EntryEnd,C=(UINTN)N976nA55EntryConfig;
  if(End<=Start || End-Start>PAGE || C<Start || C>End || End-C<sizeof(N976N_A55_ENTRY_CONFIG) ||
     ((Start|C)&7))return FALSE;
  *Bytes=End-Start;*Config=C-Start;return TRUE;
}

/* Guard words surround both pages; only the exact committed witness is mutable.
 * Code/config bytes are compared to the original image and exact patched config. */
/* WitnessMode: 0=not started, 1=must match the saved committed observation,
 * 2=incomplete/failed attempt, potentially writing: check only its exterior. */
STATIC BOOLEAN A55Contents(UINTN Index,UINTN WitnessMode) {
  UINT64 A=mN976nA55ProbeReport.Ap[Index].Arena;
  UINTN Bytes,Offset;if(!A55ArenaBounds(A) || !A55StubBounds(&Bytes,&Offset))return FALSE;
  N976N_A55_ENTRY_CONFIG Config={N976N_A55_ENTRY_CONFIG_MAGIC,A+2*PAGE,
    mA55Identity[Index].ExpectedAffinity,mA55Identity[Index].CpuOnTarget,
    A+4*PAGE,0x10101000,0x10102000};
  CONST volatile UINT8 *C=(CONST VOID *)(UINTN)(A+PAGE);
  for(UINTN I=0;I<Bytes;++I) {
    UINT8 Expected=(I>=Offset && I<Offset+sizeof(Config))?((UINT8 *)&Config)[I-Offset]:N976nA55EntryStart[I];
    if(C[I]!=Expected)return FALSE;
  }
  for(UINTN P=0;P<8;++P) {
    CONST volatile UINT64 *G=(CONST VOID *)(UINTN)(A+P*PAGE);
    for(UINTN I=0;I<PAGE/8;++I) {
      if(P==1 && I*8<ALIGN_VALUE(Bytes,8))continue;
      if(P==4) { if(G[I]!=(I==0?MAX_UINT32:0))return FALSE; continue; }
      if(P==2 && I<sizeof(N976N_A55_ENTRY_WITNESS)/8) {
        if(!WitnessMode && G[I])return FALSE;
        if(WitnessMode==1 && G[I]!=((CONST volatile UINT64 *)&mN976nA55ProbeReport.Ap[Index].Entry)[I])return FALSE;
      } else if(G[I]!=(AP_GUARD^((UINT64)Index<<32)^((UINT64)P<<16)^I))return FALSE;
    }
  }
  return TRUE;
}

STATIC EFI_STATUS A55Prepare(UINTN I) {
  UINTN Bytes,Offset;if(!A55StubBounds(&Bytes,&Offset))return EFI_COMPROMISED_DATA;
  EFI_PHYSICAL_ADDRESS A=N976N_BOOTSTRAP_HEAP_END-1;
  EFI_STATUS S=gBS->AllocatePages(AllocateMaxAddress,EfiReservedMemoryType,8,&A);
  if(EFI_ERROR(S))return S;
  mN976nA55ProbeReport.Ap[I].Arena=A; /* Retain even on a partial failure. */
  if(!A55ArenaBounds(A))return EFI_SECURITY_VIOLATION;
  for(UINTN J=0;J<I;++J) {
    UINT64 B=mN976nA55ProbeReport.Ap[J].Arena;
    if(A<B+N976N_A55_PROBE_ARENA_BYTES && B<A+N976N_A55_PROBE_ARENA_BYTES)return EFI_SECURITY_VIOLATION;
  }
  S=gDS->SetMemorySpaceAttributes(A,N976N_A55_PROBE_ARENA_BYTES,EFI_MEMORY_WB|EFI_MEMORY_XP);
  if(EFI_ERROR(S))return S;
  for(UINTN P=0;P<8;++P) {
    UINT64 *G=(VOID *)(UINTN)(A+P*PAGE);
    for(UINTN W=0;W<PAGE/8;++W)G[W]=AP_GUARD^((UINT64)I<<32)^((UINT64)P<<16)^W;
  }
  CopyMem((VOID *)(UINTN)(A+PAGE),N976nA55EntryStart,Bytes);
  N976N_A55_ENTRY_CONFIG Config={N976N_A55_ENTRY_CONFIG_MAGIC,A+2*PAGE,
    mA55Identity[I].ExpectedAffinity,mA55Identity[I].CpuOnTarget,
    A+4*PAGE,0x10101000,0x10102000};
  CopyMem((VOID *)(UINTN)(A+PAGE+Offset),&Config,sizeof(Config));
  ZeroMem((VOID *)(UINTN)(A+2*PAGE),sizeof(N976N_A55_ENTRY_WITNESS));
  ZeroMem((VOID *)(UINTN)(A+4*PAGE),PAGE);
  *(UINT32 *)(UINTN)(A+4*PAGE)=MAX_UINT32;
  WriteBackInvalidateDataCacheRange((VOID *)(UINTN)A,N976N_A55_PROBE_ARENA_BYTES);
  S=gDS->SetMemorySpaceAttributes(A,N976N_A55_PROBE_ARENA_BYTES,EFI_MEMORY_UC|EFI_MEMORY_XP);
  if(EFI_ERROR(S))return S;
  S=gDS->SetMemorySpaceAttributes(A+PAGE,PAGE,EFI_MEMORY_WB|EFI_MEMORY_RO);
  if(EFI_ERROR(S))return S;
  InvalidateInstructionCacheRange((VOID *)(UINTN)(A+PAGE),PAGE);
  MemoryFence();
  mN976nA55ProbeReport.Ap[I].Code=A+PAGE;mN976nA55ProbeReport.Ap[I].Witness=A+2*PAGE;
  return A55Maps(A) && A55Contents(I,FALSE)?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
}

STATIC BOOLEAN A55WitnessValid(CONST N976N_A55_ENTRY_WITNESS *W,UINTN I) {
  if(I>=3)return FALSE;
  if(W->GicInterface>=8 || W->GicInterface==mN976nA55ProbeReport.BspInterface ||
     W->GicTarget!=(1ULL<<W->GicInterface))return FALSE;
  for(UINTN J=0;J<I;++J)
    if(W->GicInterface==mN976nA55ProbeReport.Ap[J].Entry.GicInterface)return FALSE;
  UINT64 Affinity=W->Mpidr&MPIDR_AFFINITY;
  if(Affinity==(mN976nA55ProbeReport.BspMpidr&MPIDR_AFFINITY))return FALSE;
  for(UINTN J=0;J<I;++J)
    if(Affinity==(mN976nA55ProbeReport.Ap[J].Entry.Mpidr&MPIDR_AFFINITY))return FALSE;
  return W->Magic==N976N_A55_ENTRY_MAGIC && W->Version==N976N_A55_ENTRY_VERSION && W->Bytes==sizeof(*W) &&
    W->CpuOnTarget==mA55Identity[I].CpuOnTarget &&
    W->ExpectedAffinity==mA55Identity[I].ExpectedAffinity &&
    Affinity==mA55Identity[I].ExpectedAffinity &&
    (W->Mpidr&BIT24) && ((W->Mpidr^mN976nA55ProbeReport.BspMpidr)&BIT24)==0 &&
    ((W->Midr>>24)&255)==0x41 && ((W->Midr>>4)&4095)==0xD05 &&
    W->CurrentEl==4 && !(W->Sctlr&(BIT0|BIT2|BIT12|BIT25)) &&
    W->GicCtlr==1 && W->GicPmr>0x80 && W->GicPmr<=0xFF &&
    !(W->TimerControl&1) && (W->ReadyDaif&0x3C0)==0x3C0 &&
    W->Cntfrq==mN976nA55ProbeReport.Frequency && W->Status==0 &&
    W->Reserved1==0 && W->Parked==N976N_A55_ENTRY_PARKED;
}

STATIC EFI_STATUS A55Wait(UINTN I) {
  UINT64 Start=GetPerformanceCounter(),Previous=Start,Stall=0;
  CONST volatile N976N_A55_ENTRY_WITNESS *W=(CONST VOID *)(UINTN)mN976nA55ProbeReport.Ap[I].Witness;
  for(;;) {
    if(W->Parked==N976N_A55_ENTRY_PARKED) {
      MemoryFence();
      /* Aligned word reads from the Device mapping, never an unaligned memcpy. */
      UINT64 *D=(VOID *)&mN976nA55ProbeReport.Ap[I].Entry;
      CONST volatile UINT64 *P=(CONST VOID *)W;
      for(UINTN J=0;J<sizeof(*W)/8;++J)D[J]=P[J];
      if(!A55WitnessValid((CONST VOID *)&mN976nA55ProbeReport.Ap[I].Entry,I))return EFI_COMPROMISED_DATA;
      return EFI_SUCCESS;
    }
    UINT64 Now=GetPerformanceCounter();
    if(Now<Previous)return EFI_DEVICE_ERROR;
    Stall=Now==Previous?Stall+1:0;Previous=Now;
    UINT64 Ticks=Now-Start;
    mN976nA55ProbeReport.Ap[I].WaitUs=Ticks/(mN976nA55ProbeReport.Frequency/1000000ULL);
    if(Ticks>=mN976nA55ProbeReport.Frequency/2)return EFI_TIMEOUT;
    if(Stall>=CLOCK_STALL_LIMIT)return EFI_DEVICE_ERROR;
    CpuPause();
  }
}

STATIC VOID A55ClockSample(VOID) {
  N976N_A55_CLOCK_SAMPLE S;
  S.Mux1000Before=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x1000);
  S.Mux1008Before=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x1008);
  S.Apll100Before=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x100);
  S.Pll160Before=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x160);
  MemoryFence();
  S.Mux1000After=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x1000);
  S.Mux1008After=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x1008);
  S.Apll100After=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x100);
  S.Pll160After=MmioRead32(N976N_A55_CLOCK_CMU_BASE+0x160);
  mN976nA55ProbeReport.ClockRaw=S;mN976nA55ProbeReport.Clock=N976nA55ClockDecode(&S);
}

STATIC EFI_STATUS A55Fail(EFI_STATUS S,UINT64 Reason) {
  mN976nA55ProbeReport.Status=S;mN976nA55ProbeReport.Reason=Reason;return S;
}

EFI_STATUS N976nA55Probe(UINT64 Profile,VOID (*Progress)(VOID)) {
  if(mAttempted)return EFI_ALREADY_STARTED;
  mAttempted=TRUE;mProfile=Profile;ZeroMem((VOID *)&mN976nA55ProbeReport,sizeof(mN976nA55ProbeReport));
  mN976nA55ProbeReport.Magic=N976N_A55_PROBE_MAGIC;mN976nA55ProbeReport.Phase=1;
  for(UINTN I=0;I<3;++I)mN976nA55ProbeReport.Ap[I].SmcReturn=MAX_UINT64;
  if(Profile==N976N_PLATFORM_PROFILE_QEMU) {
    mN976nA55ProbeReport.Phase=8;return A55Fail(EFI_UNSUPPORTED,1);
  }
  VOID *Hob=GetFirstGuidHob(&gN976nAcpiAdmissionGuid);
  if(Profile!=N976N_PLATFORM_PROFILE_PHONE || !Hob ||
     GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_ACPI_ADMISSION))return A55Fail(EFI_ACCESS_DENIED,2);
  N976N_ACPI_ADMISSION A;CopyMem(&A,GET_GUID_HOB_DATA(Hob),sizeof(A));
  A55_CPU C;A55ReadCpu(&C);
  mN976nA55ProbeReport.BspEl=C.El;mN976nA55ProbeReport.BspMpidr=C.Mpidr;mN976nA55ProbeReport.BspMidr=C.Midr;
  if(!N976nValidateAcpiAdmission(&A,Profile) || A.PsciUseHvc || A.BspMpidr || A.CpuCount<4 ||
     C.El!=4 || (C.Mpidr&MPIDR_AFFINITY) || !(C.Mpidr&BIT24) ||
     ((C.Midr>>24)&255)!=0x41 || ((C.Midr>>4)&4095)!=0xD05)
    return A55Fail(EFI_ACCESS_DENIED,3);
  for(UINTN I=0;I<4;++I)if(A.CpuMpidr[I]!=I)return A55Fail(EFI_ACCESS_DENIED,4);
  UINT64 Start,End,F=GetPerformanceCounterProperties(&Start,&End);
  if(F!=26000000 || F!=A.CounterFrequency || Start || End!=MAX_UINT64)return A55Fail(EFI_UNSUPPORTED,5);
  mN976nA55ProbeReport.Frequency=F;
  if(!A55Page(N976N_A55_CLOCK_CMU_BASE,&C,FALSE) ||
     !A55Page(N976N_A55_CLOCK_CMU_BASE+PAGE,&C,FALSE))return A55Fail(EFI_SECURITY_VIOLATION,6);
  if(!A55Page(A.GicBase[N976N_ACPI_GICD],&C,FALSE) ||
     !A55Page(A.GicBase[N976N_ACPI_GICC],&C,FALSE))return A55Fail(EFI_SECURITY_VIOLATION,8);
  mN976nA55ProbeReport.BspInterface=A.BspInterfaceNumber;
  A55ClockSample();
  EFI_STATUS S=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&mAttributes);
  if(EFI_ERROR(S) || !mAttributes)return A55Fail(EFI_ERROR(S)?S:EFI_NOT_FOUND,7);
  mN976nA55ProbeReport.Phase=2;
  for(UINTN I=0;I<3;++I) {
    S=A55Prepare(I);if(EFI_ERROR(S))return A55Fail(S,0x10+I);
    mN976nA55ProbeReport.MapMask|=1ULL<<I;mN976nA55ProbeReport.GuardMask|=1ULL<<I;
  }
  for(UINTN I=0;I<3;++I) {
    if(!A55Maps(mN976nA55ProbeReport.Ap[I].Arena) || !A55Contents(I,FALSE))return A55Fail(EFI_SECURITY_VIOLATION,0x20+I);
    mN976nA55ProbeReport.Phase=3+I;mN976nA55ProbeReport.AttemptedMask|=1ULL<<I;
    if(Progress)Progress(); /* Persist visible identity before a possibly nonreturning SMC. */
    ARM_MONITOR_ARGS Args;ZeroMem(&Args,sizeof(Args));
    Args.Arg0=0xC4000003;Args.Arg1=mA55Identity[I].CpuOnTarget;
    Args.Arg2=(UINTN)mN976nA55ProbeReport.Ap[I].Code;
    MemoryFence();
    ArmMonitorCall(&Args); /* Existing phone profile binds the SMC conduit. */
    UINTN Return=Args.Arg0;
    mN976nA55ProbeReport.Ap[I].SmcReturn=Return;
    S=Return?EFI_DEVICE_ERROR:A55Wait(I);
    if(!EFI_ERROR(S))mN976nA55ProbeReport.ParkedMask|=1ULL<<I;
    /* Earlier APs have no remaining writes after their commit. Check all
     * arenas, not only the new AP's, before admitting the next target. */
    for(UINTN J=0;J<3;++J) {
      if(!A55Maps(mN976nA55ProbeReport.Ap[J].Arena)) {
        mN976nA55ProbeReport.MapMask&=~(1ULL<<J);return A55Fail(EFI_SECURITY_VIOLATION,0x50+J);
      }
      if(!A55Contents(J,J<I?1:(J==I?(EFI_ERROR(S)?2:1):0))) {
        mN976nA55ProbeReport.GuardMask&=~(1ULL<<J);return A55Fail(EFI_SECURITY_VIOLATION,0x60+J);
      }
    }
    if(EFI_ERROR(S))return A55Fail(S,(Return?0x30:0x40)+I);
  }
  mN976nA55ProbeReport.Phase=8;return A55Fail(EFI_SUCCESS,0);
}

/* Publish only after all observed identities and banked GIC interfaces pass. */
EFI_STATUS N976nA55PublishAcpi(UINT64 Profile,VOID *Table) {
  N976N_ACPI_MADT *M=Table;
  if(!M)return EFI_INVALID_PARAMETER;
  if(Profile==N976N_PLATFORM_PROFILE_QEMU)return EFI_SUCCESS;
  CONST volatile N976N_A55_PROBE_REPORT *R=&mN976nA55ProbeReport;
  if(Profile!=N976N_PLATFORM_PROFILE_PHONE || R->Phase!=8 || EFI_ERROR(R->Status) ||
     R->Reason || R->AttemptedMask!=7 || R->ParkedMask!=7 || R->MapMask!=7 || R->GuardMask!=7 ||
     M->Gicc.CPUInterfaceNumber!=R->BspInterface)return EFI_NOT_READY;
  for(UINTN I=0;I<3;++I) {
    if(!A55Maps(R->Ap[I].Arena) || !A55Contents(I,1) ||
       !A55WitnessValid((CONST VOID *)&R->Ap[I].Entry,I))return EFI_SECURITY_VIOLATION;
    M->GiccAp[I]=M->Gicc;
    M->GiccAp[I].CPUInterfaceNumber=(UINT32)R->Ap[I].Entry.GicInterface;
    M->GiccAp[I].AcpiProcessorUid=(UINT32)I+1;
    M->GiccAp[I].MPIDR=R->Ap[I].Entry.Mpidr&MPIDR_AFFINITY;
    M->GiccAp[I].ParkedAddress=R->Ap[I].Arena+4*PAGE;
    M->GiccAp[I].ParkingProtocolVersion=1;
  }
  M->Header.Header.Checksum=0;
  M->Header.Header.Checksum=CalculateCheckSum8((UINT8 *)M,sizeof(*M));
  return EFI_SUCCESS;
}

/* Recheck exact reserved ownership using the already captured EBS map.
 * No allocation, no DMA and no AP state change. Mailboxes are still firmware
 * initialized here; Windows cannot start APs until after EBS returns. */
BOOLEAN N976nA55OsMap(CONST EFI_MEMORY_DESCRIPTOR *Map,UINTN Bytes,UINTN Stride) {
  if(mProfile==N976N_PLATFORM_PROFILE_QEMU)return TRUE;
  if(mProfile!=N976N_PLATFORM_PROFILE_PHONE || !Map || Stride<sizeof(*Map) ||
     !Bytes || Bytes%Stride || mN976nA55ProbeReport.ParkedMask!=7)return FALSE;
  A55_CPU C;A55ReadCpu(&C);
  for(UINTN A=0;A<3;++A) {
    UINT64 Base=mN976nA55ProbeReport.Ap[A].Arena,Covered=0;
    if(!A55ArenaBounds(Base) || !A55Contents(A,1))return FALSE;
    for(UINTN P=0;P<8;++P)if(!A55Page(Base+P*PAGE,&C,P==1))return FALSE;
    for(UINTN I=0;I<Bytes;I+=Stride) {
      CONST EFI_MEMORY_DESCRIPTOR *D=(CONST VOID *)((CONST UINT8 *)Map+I);
      if(!D->NumberOfPages || D->NumberOfPages>MAX_UINT64/PAGE ||
         (D->PhysicalStart&(PAGE-1)) || D->PhysicalStart>MAX_UINT64-D->NumberOfPages*PAGE)return FALSE;
      UINT64 End=D->PhysicalStart+D->NumberOfPages*PAGE;
      if(End<=Base || D->PhysicalStart>=Base+N976N_A55_PROBE_ARENA_BYTES)continue;
      if(D->Type!=EfiReservedMemoryType || (D->Attribute&EFI_MEMORY_RUNTIME))return FALSE;
      for(UINTN P=0;P<8;++P)if(D->PhysicalStart<=Base+P*PAGE && End>=Base+(P+1)*PAGE) {
        if(Covered&(1ULL<<P))return FALSE;Covered|=1ULL<<P;
      }
    }
    if(Covered!=255)return FALSE;
  }
  return TRUE;
}
