/* SPDX-License-Identifier: MIT
 * SEC78: one read-only Windows ownership handoff, no controller configuration.
 * The established firmware WB DMA is retained. A distinct UC/NX DMA allocation
 * avoids a WB/NC alias or an unsupported Windows cache-maintenance substitute.
 * All pages are NVS and remain reserved even on failure/return/quarantine.
 */
#include <PiDxe.h>
#include <N976nUfsWindowsLease.h>
#include <N976nSec78DiagnosticMode.h>
#include <N976nUfsDiag.h>
#include <N976nAcpiPlatform.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/IoLib.h>
#include <Library/HobLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>
#include "UfsDmaMapping.h"

STATIC N976N_UFS_HANDOFF *mWinLease;
STATIC CONST N976N_PLATFORM_HANDOFF *mWinPlatform;
STATIC UINT64 mWinProfile=MAX_UINT64;
STATIC BOOLEAN mWinReleased;
CONST UINT32 N976nSec78DiagnosticMode = N976N_SEC78_DIAG_MODE;
STATIC UINT64 mLegacyDma;
STATIC BOOLEAN mLegacyStopped;
STATIC BOOLEAN mWinIrqAdmitted;
STATIC UINT64 mWinIrqFailure;
STATIC_ASSERT(sizeof(N976N_UFS_HANDOFF)==336,"Windows UFS handoff size");
STATIC_ASSERT(OFFSET_OF(N976N_UFS_HANDOFF,ClaimState)==320,"atomic claim ABI");
STATIC_ASSERT(OFFSET_OF(N976N_UFS_HANDOFF,PowerRaw)==252,"power proof ABI");
#define LEASE_BYTES N976N_UFS_HANDOFF_LEASE_BYTES
#define DMA_BYTES N976N_UFS_HANDOFF_DMA_BYTES
#define FW_DMA_BYTES N976N_UFS_FIRMWARE_DMA_BYTES
#define UFS_CACHE_MASK (EFI_MEMORY_UC|EFI_MEMORY_WC|EFI_MEMORY_WT|EFI_MEMORY_WB|EFI_MEMORY_UCE)
#define FATAL_IS ((1U<<7)|(1U<<11)|(1U<<12)|(1U<<16)|(1U<<17)|(1U<<18))

STATIC UINT32 LeaseCrc(CONST N976N_UFS_HANDOFF *L) {
  UINT32 Crc=MAX_UINT32;
  for(UINTN I=0;I<N976N_UFS_HANDOFF_IMMUTABLE_BYTES;I++) {
    UINT8 B=(I>=20&&I<24)?0:((CONST UINT8 *)L)[I]; Crc^=B;
    for(UINTN J=0;J<8;J++) Crc=(Crc>>1)^((Crc&1)?0xEDB88320U:0);
  }
  return ~Crc;
}
STATIC BOOLEAN Zeros(CONST UINT8 *P,UINTN N) {
  for(UINTN I=0;I<N;I++) if(P[I]) return FALSE;
  return TRUE;
}
STATIC BOOLEAN Low(UINT64 A,UINT64 N) {
  return mWinPlatform&&N&&!(A&4095)&&!(N&4095)&&A<=MAX_UINT32-N&&
    A>=mWinPlatform->HeapBase&&A-mWinPlatform->HeapBase<mWinPlatform->HeapSize&&
    N<=mWinPlatform->HeapSize-(A-mWinPlatform->HeapBase);
}
STATIC BOOLEAN LegacyShape(VOID) {
  return N976N_SEC78_DIAG_MODE==3 && mWinProfile==0 && !mWinReleased &&
    mWinLease==NULL && mWinPlatform &&
    mWinPlatform->Magic==N976N_PLATFORM_HANDOFF_MAGIC &&
    mWinPlatform->Version==N976N_PLATFORM_ABI_VERSION &&
    mWinPlatform->Size==sizeof(*mWinPlatform) && !mWinPlatform->Reserved &&
    mWinPlatform->Profile==0 && Low(mLegacyDma,FW_DMA_BYTES);
}
STATIC BOOLEAN Overlap(UINT64 A,UINT64 N,UINT64 B,UINT64 M) {
  return A<B+M&&B<A+N; /* Low() precedes every call. */
}
STATIC UINT32 R(UINT32 O) { return MmioRead32(0x13D60000U+O); }
STATIC UINT32 V(UINT32 O) { return MmioRead32(0x13D61100U+O); }
STATIC EFI_STATUS IrqRefuse(UINT64 Reason) {
  if (!mWinIrqFailure) {
    mWinIrqFailure=Reason;
    mN976nAcpiReport.Reason=Reason;
  }
  return EFI_SECURITY_VIOLATION;
}
STATIC EFI_STATUS IrqQuiet(VOID) {
  /* PhoneSec already maps this exact, DT-admitted GIC page Device-XN.
   * No new mapping, register write, pending clear or IRQ enable is performed.
   * The Windows miniport keeps HCI IE0 and polls; its registered ISR is inert.
   * Nonsecure readback is bounded evidence, not proof about secure GIC state. */
  if (!mWinIrqAdmitted) return IrqRefuse(0x7801);
  if (R(0x24)!=0) return IrqRefuse(0x7802);
  UINT32 Typer=MmioRead32(0x10101004);
  if (Typer==MAX_UINT32 || 32U*((Typer&31U)+1U)<=281U) return IrqRefuse(0x7806);
  UINT32 Pending=MmioRead32(0x10101220),Active=MmioRead32(0x10101320);
  UINT32 Config=MmioRead32(0x10101C44);
  if (Pending & (1U<<25)) return IrqRefuse(0x7803);
  if (Active & (1U<<25)) return IrqRefuse(0x7804);
  if (Config & (1U<<19)) return IrqRefuse(0x7805);
  return EFI_SUCCESS;
}
STATIC EFI_STATUS AdmitIrq(VOID) {
  VOID *Hob=GetFirstGuidHob(&gN976nAcpiAdmissionGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_ACPI_ADMISSION) ||
      GetNextGuidHob(&gN976nAcpiAdmissionGuid,GET_NEXT_HOB(Hob))!=NULL)
    return IrqRefuse(0x7801);
  N976N_ACPI_ADMISSION A;
  CopyMem(&A,GET_GUID_HOB_DATA(Hob),sizeof(A));
  /* This independent parser binds the inherited interrupt-parent to the
   * exact GICv2 identity and range. UFS admission proves <SPI,249,0>. */
  if (!N976nValidateAcpiAdmission(&A,0) || A.GicBase[N976N_ACPI_GICD]!=0x10101000 ||
      A.GicBytes[N976N_ACPI_GICD]!=0x1000) return IrqRefuse(0x7801);
  mWinIrqAdmitted=TRUE;
  return IrqQuiet();
}
STATIC BOOLEAN Shape(VOID) {
  N976N_UFS_HANDOFF *L=mWinLease;
  if(!L||mWinProfile||mWinReleased||L->Magic!=N976N_UFS_HANDOFF_MAGIC||
    L->Version!=N976N_UFS_HANDOFF_VERSION||L->Bytes!=sizeof(*L)||L->ImmutableBytes!=320||L->Profile||
    (L->ProducerStage!=1&&L->ProducerStage!=2)||L->ClaimState||
    L->Guard!=N976N_UFS_HANDOFF_GUARD||L->LeaseBase!=(UINTN)L||L->LeaseBytes!=LEASE_BYTES||
    L->DmaBytes!=DMA_BYTES||L->FirmwareDmaBytes!=FW_DMA_BYTES||
    !Low(L->LeaseBase,LEASE_BYTES)||!Low(L->DmaBase,DMA_BYTES)||!Low(L->FirmwareDmaBase,FW_DMA_BYTES)||
    Overlap(L->LeaseBase,LEASE_BYTES,L->DmaBase,DMA_BYTES)||
    Overlap(L->LeaseBase,LEASE_BYTES,L->FirmwareDmaBase,FW_DMA_BYTES)||
    Overlap(L->DmaBase,DMA_BYTES,L->FirmwareDmaBase,FW_DMA_BYTES)||
    !L->BootCounter||!L->CounterHz||L->CounterHz>1000000000ULL||
    L->HciBase!=0x13D60000||L->HciBytes!=0x2000||L->VendorOffset!=0x1100||
    L->CoherencyBase!=0x13C10000||L->CoherencyBytes!=0x1000||L->CoherencyOffset!=0x700||
    L->BaselineOffset!=4096||L->BaselineBytes!=4096||L->Lun!=0||
    !L->LastLba||L->LastLba>=MAX_UINT32||L->BlockBytes!=4096||L->Flags!=7||L->PowerRaw!=0x11||
    L->ProducerChecks!=(L->ProducerStage==1?0x1F:0x3F)||!Zeros(L->Reserved,sizeof(L->Reserved))||
    !Zeros((UINT8 *)L+sizeof(*L),4088-sizeof(*L))||
    *(UINT64 *)((UINT8 *)L+4088)!=N976N_UFS_HANDOFF_GUARD||L->Crc32!=LeaseCrc(L)||
    L->BaselineCrc32!=CalculateCrc32((UINT8 *)L+4096,4096)) return FALSE;
  return TRUE;
}
STATIC BOOLEAN Mappings(VOID) {
  UFS_DMA_CPU_STATE Cpu; UfsDmaReadCpuState(&Cpu);
  return UfsDmaMappingSnapshotCacheValid(mWinPlatform,(UINTN)mWinLease,LEASE_BYTES,&Cpu,255,TT_SH_INNER_SHAREABLE)&&
    UfsDmaMappingSnapshotCacheValid(mWinPlatform,mWinLease->DmaBase,DMA_BYTES,&Cpu,0,0)&&
    UfsDmaMappingValid(mWinPlatform,mWinLease->FirmwareDmaBase,FW_DMA_BYTES);
}
UINT64 N976nUfsWindowsLeaseAddress(VOID) { return (UINTN)mWinLease; }
UINT64 N976nUfsWindowsDmaAddress(VOID) { return mWinLease?mWinLease->DmaBase:0; }

EFI_STATUS N976nUfsWindowsLeasePrepare(CONST N976N_PLATFORM_HANDOFF *H,
 CONST N976N_UFS_ADMISSION *A,CONST N976N_UFS_REPORT *Report,CONST UINT8 *Baseline) {
  if(mWinProfile!=MAX_UINT64||!H||H->Profile>1) return EFI_ACCESS_DENIED;
  mWinProfile=H->Profile;
  if(H->Profile==1) return EFI_SUCCESS;
  if(H->Magic!=N976N_PLATFORM_HANDOFF_MAGIC||H->Version!=N976N_PLATFORM_ABI_VERSION||
    H->Size!=sizeof(*H)||H->Reserved||!A||A->Magic!=N976N_UFS_ADMISSION_MAGIC||
    A->Version!=1||A->Size!=sizeof(*A)||A->Admitted!=1||A->Reason||
    A->Hci!=0x13D60000||A->Vendor!=0x13D61100||A->Coherency!=0x13C10700||
    !Report||Report->Magic!=N976N_UFS_REPORT_MAGIC||Report->Version!=1||Report->Size!=sizeof(*Report)||
    Report->Quarantined||Report->Restore||Report->Lun||Report->BlockBytes!=4096||
    !Report->LastLba||Report->LastLba>=MAX_UINT32||Report->BufferBytes!=FW_DMA_BYTES||!Baseline)
    return EFI_SECURITY_VIOLATION;
  mWinPlatform=H;
  if(!Low(Report->Buffer,FW_DMA_BYTES)) return EFI_SECURITY_VIOLATION;
  if(N976N_SEC78_DIAG_MODE==3) {
    mLegacyDma=Report->Buffer;
    return LegacyShape()&&UfsDmaMappingValid(H,mLegacyDma,FW_DMA_BYTES)?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
  }
  if(N976N_SEC78_DIAG_MODE==1 && EFI_ERROR(AdmitIrq())) return EFI_SECURITY_VIOLATION;
  EFI_PHYSICAL_ADDRESS Lease=H->HeapBase+H->HeapSize-1,Dma=Lease;
  EFI_STATUS S=gBS->AllocatePages(AllocateMaxAddress,EfiACPIMemoryNVS,2,&Lease);
  if(EFI_ERROR(S)) return S;
  S=gBS->AllocatePages(AllocateMaxAddress,EfiACPIMemoryNVS,DMA_BYTES/4096,&Dma);
  if(EFI_ERROR(S)) return S; /* bounded reserved leak, never unsafe reuse */
  if(!Low(Lease,LEASE_BYTES)||!Low(Dma,DMA_BYTES)||Overlap(Lease,LEASE_BYTES,Dma,DMA_BYTES)||
    Overlap(Lease,LEASE_BYTES,Report->Buffer,FW_DMA_BYTES)||Overlap(Dma,DMA_BYTES,Report->Buffer,FW_DMA_BYTES))
    return EFI_SECURITY_VIOLATION;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *M=NULL;
  S=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&M);
  if(EFI_ERROR(S)||!M||!M->SetMemoryAttributes||!M->GetMemoryAttributes) return EFI_UNSUPPORTED;
  S=M->SetMemoryAttributes(M,Lease,LEASE_BYTES,EFI_MEMORY_XP);
  if(EFI_ERROR(S)) return S;
  S=M->SetMemoryAttributes(M,Dma,DMA_BYTES,EFI_MEMORY_XP);
  if(EFI_ERROR(S)) return S;
  ZeroMem((VOID *)(UINTN)Dma,DMA_BYTES);
  const UINTN GuardPages[4]={0,2,4,21};
  for(UINTN I=0;I<4;I++) SetMem((UINT8 *)(UINTN)Dma+GuardPages[I]*4096,4096,0xA5);
  /* There must be no dirty cached lines when the new identity mapping becomes
   * Device-UC. This range has never been submitted to the controller. */
  WriteBackInvalidateDataCacheRange((VOID *)(UINTN)Dma,DMA_BYTES); MemoryFence();
  S=gDS->SetMemorySpaceAttributes(Dma,DMA_BYTES,EFI_MEMORY_UC|EFI_MEMORY_XP);
  if(EFI_ERROR(S)) return S;
  /* Upstream GetMemoryMap publishes GCD capabilities for ordinary memory.
   * Constrain this privately owned NVS extent to UC so Windows cannot select
   * WB for its later mapping merely because the original bank supports WB. */
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Space;
  S=gDS->GetMemorySpaceDescriptor(Dma,&Space);
  if(EFI_ERROR(S)||Space.GcdMemoryType!=EfiGcdMemoryTypeSystemMemory||
    Space.BaseAddress>Dma||Space.Length<Dma-Space.BaseAddress||
    DMA_BYTES>Space.Length-(Dma-Space.BaseAddress)) return EFI_SECURITY_VIOLATION;
  S=gDS->SetMemorySpaceCapabilities(Dma,DMA_BYTES,
    (Space.Capabilities&~UFS_CACHE_MASK)|EFI_MEMORY_UC);
  if(EFI_ERROR(S)) return S;
  ZeroMem((VOID *)(UINTN)Lease,LEASE_BYTES); mWinLease=(VOID *)(UINTN)Lease;
  N976N_UFS_HANDOFF *L=mWinLease;
  L->Magic=N976N_UFS_HANDOFF_MAGIC;L->Version=N976N_UFS_HANDOFF_VERSION;L->Bytes=sizeof(*L);L->ImmutableBytes=320;
  L->ProducerStage=1;L->BootCounter=GetPerformanceCounter();L->CounterHz=Report->Frequency;
  L->LeaseBase=Lease;L->LeaseBytes=LEASE_BYTES;L->DmaBase=Dma;L->DmaBytes=DMA_BYTES;
  L->FirmwareDmaBase=Report->Buffer;L->FirmwareDmaBytes=FW_DMA_BYTES;
  L->HciBase=A->Hci;L->HciBytes=0x2000;L->VendorOffset=0x1100;
  L->CoherencyBase=0x13C10000;L->CoherencyBytes=0x1000;L->CoherencyOffset=0x700;
  L->BaselineOffset=4096;L->BaselineBytes=4096;
  CopyMem((UINT8 *)L+4096,Baseline,4096);L->BaselineCrc32=CalculateCrc32((UINT8 *)L+4096,4096);
  L->Lun=(UINT32)Report->Lun;L->LastLba=Report->LastLba;L->BlockBytes=(UINT32)Report->BlockBytes;
  L->Flags=7;L->PowerRaw=0x11;L->ProducerChecks=0x1F;L->Guard=N976N_UFS_HANDOFF_GUARD;
  *(UINT64 *)((UINT8 *)L+4088)=N976N_UFS_HANDOFF_GUARD;L->Crc32=LeaseCrc(L);MemoryFence();
  return Shape()&&Mappings()?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
}
EFI_STATUS N976nUfsWindowsLeaseCheck(VOID) {
  if(mWinProfile==1) return (mWinLease||mLegacyDma)?EFI_SECURITY_VIOLATION:EFI_SUCCESS;
  if(N976N_SEC78_DIAG_MODE==3)
    return LegacyShape()&&UfsDmaMappingValid(mWinPlatform,mLegacyDma,FW_DMA_BYTES)?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
  return Shape()&&Mappings()?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
}

EFI_STATUS N976nUfsWindowsLeaseStopped(VOID) {
  if(EFI_ERROR(N976nUfsWindowsLeaseCheck())||!N976nUfsExitQuiesced()) return EFI_SECURITY_VIOLATION;
  if(mWinProfile==1) return EFI_SUCCESS;
  if(N976N_SEC78_DIAG_MODE==3) {
    if(mLegacyStopped) return EFI_ACCESS_DENIED;
    mLegacyStopped=TRUE;return EFI_SUCCESS;
  }
  if(N976N_SEC78_DIAG_MODE==1 && EFI_ERROR(IrqQuiet())) return EFI_SECURITY_VIOLATION;
  N976N_UFS_HANDOFF *L=mWinLease;
  if(L->ProducerStage!=1||mN976nUfsDiag.PowerFinal!=0x11||
    (mN976nUfsDiag.Prepare&0x30)!=0x30||(mN976nUfsDiag.PowerRestore&6)||
    mN976nUfsReport.Restore) return EFI_ACCESS_DENIED;
  L->HciCap=R(0);L->HciVersion=R(8);L->Hce=R(0x34);L->Hcs=R(0x30);
  L->Ie=R(0x24);L->Ahit=R(0x18);L->Is=R(0x20);L->Iacr=R(0x4C);
  L->TrlBase=R(0x50);L->TrlBaseHi=R(0x54);L->TmBase=R(0x70);L->TmBaseHi=R(0x74);
  L->TrlRun=R(0x60);L->TmRun=R(0x80);L->TrlDoorbell=R(0x58);L->TmDoorbell=R(0x78);
  L->TxPrdt=V(0);L->RxPrdt=V(4);L->Reorder=V(0x60);L->Nexus=V(0x40);L->Axi=V(0x6C);
  L->Coherency=MmioRead32(0x13C10700);
  if(L->Hce!=1||(L->Hcs&0xB)!=0xB||L->HciCap==MAX_UINT32||L->HciVersion==MAX_UINT32||
    L->Ie||L->Ahit||(L->Is&(FATAL_IS|1))||L->Iacr||
    L->TrlBase!=L->FirmwareDmaBase+4096||L->TrlBaseHi||L->TrlRun||L->TmRun||L->TrlDoorbell||L->TmDoorbell||
    L->TxPrdt!=0xC||L->RxPrdt!=0xC||L->Reorder!=0xA||L->Coherency!=0x11)
    return EFI_DEVICE_ERROR;
  L->ProducerStage=2;L->ProducerChecks=0x3F;L->Crc32=LeaseCrc(L);MemoryFence();
  return EFI_SUCCESS;
}
EFI_STATUS N976nUfsWindowsLeaseRelease(VOID) {
  /* Accepted-EBS notification: cached checks only, no services/MMIO/table walk. */
  if(mWinProfile==1) { if(mWinReleased||mWinLease||mLegacyDma) return EFI_SECURITY_VIOLATION;mWinReleased=TRUE;return EFI_SUCCESS; }
  if(N976N_SEC78_DIAG_MODE==3) {
    if(!LegacyShape()||!mLegacyStopped||!N976nUfsExitQuiesced()) return EFI_SECURITY_VIOLATION;
    MemoryFence();mWinReleased=TRUE;return EFI_SUCCESS;
  }
  if(!Shape()||mWinLease->ProducerStage!=2||!N976nUfsExitQuiesced()) return EFI_SECURITY_VIOLATION;
  mWinLease->ProducerStage=3;mWinLease->ProducerChecks=0x7F;mWinLease->Crc32=LeaseCrc(mWinLease);
  MemoryFence();mWinReleased=TRUE;return EFI_SUCCESS;
}
BOOLEAN N976nUfsWindowsLeaseMap(CONST EFI_MEMORY_DESCRIPTOR *Map,UINTN Bytes,UINTN Stride) {
  if(mWinProfile==1) return mWinLease==NULL && !mLegacyDma;
  BOOLEAN Legacy=N976N_SEC78_DIAG_MODE==3;
  if(!(Legacy?LegacyShape():Shape())||!Map||Stride<sizeof(*Map)||Stride%8||!Bytes||Bytes%Stride) return FALSE;
  UINT64 Bases[3],Lengths[3]={LEASE_BYTES,DMA_BYTES,FW_DMA_BYTES};
  UINT64 Cache[3]={EFI_MEMORY_WB,EFI_MEMORY_UC,EFI_MEMORY_WB};
  UINTN Count=Legacy?1:3;
  if(Legacy) {Bases[0]=mLegacyDma;Lengths[0]=FW_DMA_BYTES;}
  else {Bases[0]=mWinLease->LeaseBase;Bases[1]=mWinLease->DmaBase;Bases[2]=mWinLease->FirmwareDmaBase;}
  for(UINTN I=0;I<Count;I++) {
    UINT64 At=Bases[I],End=At+Lengths[I];
    while(At<End) {
      CONST EFI_MEMORY_DESCRIPTOR *Found=NULL;
      for(UINTN Off=0;Off<Bytes;Off+=Stride) {
        CONST EFI_MEMORY_DESCRIPTOR *D=(CONST VOID *)((CONST UINT8 *)Map+Off);
        if(!D->NumberOfPages||D->NumberOfPages>MAX_UINT64/4096||
          D->PhysicalStart>MAX_UINT64-D->NumberOfPages*4096) return FALSE;
        if(At>=D->PhysicalStart&&At-D->PhysicalStart<D->NumberOfPages*4096) {
          if(Found) return FALSE;Found=D;
        }
      }
      if(!Found||Found->Type!=(Legacy?EfiBootServicesData:EfiACPIMemoryNVS)||(Found->Attribute&EFI_MEMORY_RUNTIME)||
        ((I==1&&(Found->Attribute&UFS_CACHE_MASK)!=Cache[I]) ||
         (I!=1&&!(Found->Attribute&Cache[I])))) return FALSE;
      UINT64 Next=Found->PhysicalStart+Found->NumberOfPages*4096;
      At=Next<End?Next:End;
    }
  }
  return TRUE;
}
