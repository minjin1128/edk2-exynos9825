/* SPDX-License-Identifier: MIT
 * SEC66: standard GCD publication and bounded allocation/protection exercise.
 * Publication is a commit; never revoke mapped system memory afterward.
 */
#include <PiDxe.h>
#include <N976nHighRam.h>
#include <Library/ArmLib.h>
#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/N976nBootstrapPolicy.h>
#include <AArch64/AArch64Mmu.h>

#define HR_PAGE 4096ULL
#define HR_CHUNK 0x200000ULL
#define HR_END (N976N_HIGH_RAM_BASE+N976N_HIGH_RAM_BYTES)
#define HR_GUARD 0x3935475541524448ULL
/* Screen 9..32: phase,status,checks,reason,base,bytes,L3 tables,publication,
 * alloc count,free count,RO,RP,address,expected,observed,guards,map,PA bits,
 * TCR,SCTLR,first allocation base/pages,admission,conventional high bytes. */
volatile UINT64 mN976nHighRamReport[24];
typedef struct { UINT64 El,Sctlr,Tcr,Root,Mair,PaBits,Line,Granule; } HR_CPU;
STATIC HR_CPU mHrCpu;
STATIC N976N_PLATFORM_HANDOFF mHrHandoff;
STATIC N976N_HIGH_RAM_ADMISSION mHrAdmission;
STATIC UINT64 mHrMap[2048];
STATIC EFI_PHYSICAL_ADDRESS mHrAlloc[2];
STATIC CONST UINTN mHrPages[2]={5,64};
STATIC BOOLEAN mHrOwned[2],mHrStarted,mHrCommitAttempted,mHrPublished;
STATIC UINT64 mHrFailureAddress;
STATIC UINT64 mHrBorrowMap[2048];
STATIC BOOLEAN mHrReady,mHrBorrowBusy;
#ifdef N976N_HIGH_RAM_HOST_TEST
/* Explicit architectural/physical-memory seams. The component harness still
 * executes the admission, table walk, patterns, guards and cleanup below. */
STATIC VOID HrReadCpu (HR_CPU *Cpu);
STATIC volatile UINT64 *HrPage (UINT64 Address);
STATIC volatile UINT64 *HrLowPage (UINT64 Address);
STATIC UINT64 HrTranslation (UINT64 Address, BOOLEAN Write);
#else
STATIC VOID HrReadCpu (HR_CPU *C)
{
  ZeroMem (C, sizeof (*C));
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (C->El));
  if (C->El != 4) return;
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (C->Sctlr));
  __asm__ volatile ("mrs %0, tcr_el1" : "=r" (C->Tcr));
  __asm__ volatile ("mrs %0, ttbr0_el1" : "=r" (C->Root));
  __asm__ volatile ("mrs %0, mair_el1" : "=r" (C->Mair));
  C->PaBits = ArmGetPhysicalAddressBits ();
  C->Line = ArmDataCacheLineLength ();
  C->Granule = ArmCacheWritebackGranule ();
}
STATIC volatile UINT64 *HrPage (UINT64 Address)
{ return (volatile UINT64 *)(UINTN)Address; }
STATIC volatile UINT64 *HrLowPage (UINT64 Address)
{ return (volatile UINT64 *)(UINTN)Address; }
STATIC UINT64 HrTranslation (UINT64 Address, BOOLEAN Write)
{
  UINT64 Par;
  if (Write) {
    __asm__ volatile ("dsb sy\n\tat s1e1w, %1\n\tisb\n\tmrs %0, par_el1" : "=r" (Par) : "r" (Address) : "memory");
  } else {
    __asm__ volatile ("dsb sy\n\tat s1e1r, %1\n\tisb\n\tmrs %0, par_el1" : "=r" (Par) : "r" (Address) : "memory");
  }
  return Par;
}
#endif

#define CHECKPOINT(Name,Nops) __attribute__((noinline)) VOID Name (VOID) { MemoryFence(); __asm__ volatile (Nops ::: "memory"); }
CHECKPOINT(N976nHighRamCheckpoint, "")
CHECKPOINT(N976nHighRamMappedCheckpoint, "nop")
CHECKPOINT(N976nHighRamPublishedCheckpoint, "nop\n\tnop")
CHECKPOINT(N976nHighRamAllocatedCheckpoint, "nop\n\tnop\n\tnop")
CHECKPOINT(N976nHighRamProtectedCheckpoint, "nop\n\tnop\n\tnop\n\tnop")
CHECKPOINT(N976nHighRamFreedCheckpoint, "nop\n\tnop\n\tnop\n\tnop\n\tnop")
STATIC VOID HrMark (UINT64 Phase,UINT64 Address)
{
 BOOLEAN Changed=mN976nHighRamReport[0]!=Phase;
 mN976nHighRamReport[0]=Phase; mN976nHighRamReport[12]=Address;
 if (Changed) N976nHighRamScreen();
 N976nHighRamCheckpoint();
}
STATIC EFI_STATUS HrFail (UINT64 Reason, EFI_STATUS Status)
{
  if (mN976nHighRamReport[3] == 0) {
    mN976nHighRamReport[3] = Reason; mN976nHighRamReport[1] = Status;
    mHrFailureAddress = mN976nHighRamReport[12]; N976nHighRamScreen ();
  }
  return Status;
}
STATIC BOOLEAN HrSpan (UINT64 A, UINT64 N, UINT64 Base, UINT64 Size)
{ return N && Size && Size <= MAX_UINT64 - Base && A >= Base && A-Base < Size && N <= Size-(A-Base); }
STATIC BOOLEAN HrOverlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{
  if (!N || !M) return FALSE;
  return N > MAX_UINT64-A || M > MAX_UINT64-B || (A < B+M && B < A+N);
}
STATIC BOOLEAN HrLow (UINT64 A, UINT64 N)
{ return HrSpan (A, N, mHrHandoff.HeapBase, mHrHandoff.HeapSize); }
STATIC BOOLEAN HrGranule (UINT64 N)
{ return N && N <= HR_PAGE && !(N & (N-1)); }
STATIC BOOLEAN HrCpuValid (CONST HR_CPU *C)
{
  STATIC CONST UINT8 Bits[] = {32,36,40,42,44,48};
  UINTN T0 = C->Tcr & 63, Ips = (C->Tcr >> 32) & 7;
  UINT64 End = N976N_HIGH_RAM_BASE + N976N_HIGH_RAM_BYTES;
  return C->El == 4 && (C->Sctlr & (BIT0|BIT2)) == (BIT0|BIT2) && !(C->Sctlr & BIT25) &&
    T0 >= 16 && T0 <= 39 && !(C->Tcr & (BIT7|BIT14|BIT15|BIT37|BIT39|BIT40|BIT59)) &&
    Ips < ARRAY_SIZE (Bits) && C->PaBits >= 36 && C->PaBits <= 48 && Bits[Ips] <= C->PaBits &&
    End <= (1ULL << Bits[Ips]) && End <= (1ULL << (64-T0)) && !(C->Root & 0xFFE) &&
    HrGranule (C->Line) && HrGranule (C->Granule);
}
STATIC BOOLEAN HrCpuStable (VOID)
{ HR_CPU C; HrReadCpu (&C); return HrCpuValid (&C) && CompareMem (&C, &mHrCpu, sizeof (C)) == 0; }
STATIC BOOLEAN HrTableOwned (UINT64 Table)
{
 if ((Table&4095)||!HrLow(Table,HR_PAGE)) return FALSE;
#define PRIVATE(X) if(HrOverlap(Table,HR_PAGE,(UINTN)&(X),sizeof(X)))return FALSE
 PRIVATE(mHrCpu);PRIVATE(mHrHandoff);PRIVATE(mHrAdmission);PRIVATE(mHrMap);
 PRIVATE(mN976nHighRamReport);PRIVATE(mHrAlloc);PRIVATE(mHrPages);PRIVATE(mHrOwned);
 PRIVATE(mHrBorrowMap);PRIVATE(mHrReady);PRIVATE(mHrBorrowBusy);
 PRIVATE(mHrStarted);PRIVATE(mHrCommitAttempted);PRIVATE(mHrPublished);PRIVATE(mHrFailureAddress);
#undef PRIVATE
 return TRUE;
}
/* Want 0: RW-XN/WB, 1: RO-XN/WB, 2: inaccessible RO-XN/WB (AF clear).
 * All high mappings must be exact 4KiB identity pages, with low-owned tables. */
STATIC BOOLEAN HrLeaf (UINT64 Address,UINT64 E,UINTN Want)
{
 if ((E&3)!=3 || (E&TT_ADDRESS_MASK_BLOCK_ENTRY)!=Address ||
     (E&TT_AP_MASK)!=(Want?TT_AP_NO_RO:TT_AP_NO_RW) ||
     (E&(TT_PXN_MASK|TT_UXN_MASK))!=(TT_PXN_MASK|TT_UXN_MASK) ||
     (E&TT_SH_MASK)!=TT_SH_INNER_SHAREABLE ||
     ((mHrCpu.Mair>>(((E>>2)&7)*8))&255)!=255 ||
     ((E&TT_AF)!=(Want==2?0:TT_AF)))return FALSE;
 return TRUE;
}
STATIC BOOLEAN HrMapping (UINT64 Address,UINTN Want)
{
 UINT64 Table=mHrCpu.Root&TT_ADDRESS_MASK_DESCRIPTION_TABLE,E=0;
 for(UINTN Level=((mHrCpu.Tcr&63)-16)/9;Level<=3;++Level){
  if(!HrTableOwned(Table))return FALSE;
  E=HrLowPage(Table)[(Address>>(12+(3-Level)*9))&511];
  if(Level==3)break;
  if((E&3)!=3 || (E&(BIT59|BIT60|BIT61|BIT62|BIT63)))return FALSE;
  Table=E&TT_ADDRESS_MASK_DESCRIPTION_TABLE;
 }
 if(!HrLeaf(Address,E,Want))return FALSE;
 UINT64 R=HrTranslation(Address,FALSE),W=HrTranslation(Address,TRUE);
 if(Want==2)return (R&1)&&(W&1);
 return !(R&1)&&(R&TT_ADDRESS_MASK_DESCRIPTION_TABLE)==Address &&
   (Want==1 ? (W&1)!=0 : !(W&1)&&(W&TT_ADDRESS_MASK_DESCRIPTION_TABLE)==Address);
}
STATIC BOOLEAN HrAuditTable(UINT64 Table,UINTN Level,UINT64 Lo,UINT64 End,
                            BOOLEAN Absent,UINT64 Protected,UINTN Permission,
                            UINTN *Budget,UINTN *Leaves,UINTN *Tables)
{
 if(Level>3||!HrTableOwned(Table))return FALSE;
 if(Level==3)++*Tables;
 UINTN Shift=12+(3-Level)*9;UINT64 Mask=(1ULL<<Shift)-1;
 while(Lo<End){
  if(!*Budget)return FALSE;--*Budget;
  UINT64 Next=MIN(End,(Lo|Mask)+1),E=HrLowPage(Table)[(Lo>>Shift)&511];
  if(!(E&1)){if(!Absent)return FALSE;}
  else if(Level<3){
   if((E&3)!=3||(E&(BIT59|BIT60|BIT61|BIT62|BIT63))||
      !HrAuditTable(E&TT_ADDRESS_MASK_DESCRIPTION_TABLE,Level+1,Lo,Next,
                   Absent,Protected,Permission,Budget,Leaves,Tables))return FALSE;
  }else{
   if(Absent||Next-Lo!=HR_PAGE||!HrLeaf(Lo,E,Lo==Protected?Permission:0))return FALSE;
   ++*Leaves;
  }
  Lo=Next;
 }
 return TRUE;
}
STATIC BOOLEAN HrAudit(BOOLEAN Absent,UINT64 Protected,UINTN Permission)
{
 UINTN Budget=0x81000,Leaves=0,Tables=0;
 if(!HrCpuStable()||!HrAuditTable(mHrCpu.Root&TT_ADDRESS_MASK_DESCRIPTION_TABLE,
    ((mHrCpu.Tcr&63)-16)/9,N976N_HIGH_RAM_BASE,HR_END,Absent,Protected,Permission,
    &Budget,&Leaves,&Tables))return FALSE;
 if(!Absent){
  if(Leaves!=N976N_HIGH_RAM_BYTES/HR_PAGE||Tables!=N976N_HIGH_RAM_BYTES/HR_CHUNK)return FALSE;
  mN976nHighRamReport[6]=Tables;
 }
 return HrCpuStable();
}
/* A fixed low buffer avoids new allocation while inspecting allocator state.
 * High bookkeeping allocations are allowed as BootServicesData; ownership of
 * our test windows is established separately by exact coverage, not by status. */
STATIC BOOLEAN HrMapSnapshot(BOOLEAN Published)
{
 UINTN Bytes=sizeof(mHrMap),Key=0,Stride=0;UINT32 Version=0;
 UINT64 Covered=0,Free=0;
 if(EFI_ERROR(gBS->GetMemoryMap(&Bytes,(VOID*)mHrMap,&Key,&Stride,&Version))||
    !Bytes||Bytes>sizeof(mHrMap)||Stride<sizeof(EFI_MEMORY_DESCRIPTOR)||
    Bytes%Stride||Version!=1)return FALSE;
 for(UINTN O=0;O<Bytes;O+=Stride){
  EFI_MEMORY_DESCRIPTOR *D=(VOID*)((UINT8*)mHrMap+O);
  if(!D->NumberOfPages||D->NumberOfPages>MAX_UINT64/HR_PAGE)return FALSE;
  UINT64 N=D->NumberOfPages*HR_PAGE;
  if((D->PhysicalStart&4095)||N>MAX_UINT64-D->PhysicalStart)return FALSE;
  for(UINTN P=0;P<O;P+=Stride){EFI_MEMORY_DESCRIPTOR *E=(VOID*)((UINT8*)mHrMap+P);
   if(HrOverlap(D->PhysicalStart,N,E->PhysicalStart,E->NumberOfPages*HR_PAGE))return FALSE;}
  if(HrOverlap(D->PhysicalStart,N,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)){
   if(!Published||!HrSpan(D->PhysicalStart,N,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
      (D->Type!=EfiConventionalMemory&&D->Type!=EfiBootServicesData&&D->Type!=EfiBootServicesCode)||
      !(D->Attribute&EFI_MEMORY_WB)||(D->Attribute&EFI_MEMORY_RUNTIME))return FALSE;
   if(N>N976N_HIGH_RAM_BYTES-Covered)return FALSE;Covered+=N;
   if(D->Type==EfiConventionalMemory)Free+=N;
  }
 }
 if(Covered!=(Published?N976N_HIGH_RAM_BYTES:0))return FALSE;
 UINT64 Cursor=N976N_HIGH_RAM_BASE;
 for(UINTN I=0;Cursor<HR_END&&I<128;++I){
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR D;
  if(EFI_ERROR(gDS->GetMemorySpaceDescriptor(Cursor,&D))||!D.Length||
     D.Length>MAX_UINT64-D.BaseAddress||D.BaseAddress>Cursor||D.BaseAddress+D.Length<=Cursor)return FALSE;
  if(Published){
   if(D.GcdMemoryType!=EfiGcdMemoryTypeSystemMemory||!D.ImageHandle||
      !HrSpan(D.BaseAddress,D.Length,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
      (D.Attributes&(EFI_MEMORY_CACHETYPE_MASK|EFI_MEMORY_XP|EFI_MEMORY_RO|EFI_MEMORY_RP|EFI_MEMORY_RUNTIME))!=(EFI_MEMORY_WB|EFI_MEMORY_XP)||
      (D.Capabilities&(EFI_MEMORY_WB|EFI_MEMORY_RO|EFI_MEMORY_RP|EFI_MEMORY_XP))!=
       (EFI_MEMORY_WB|EFI_MEMORY_RO|EFI_MEMORY_RP|EFI_MEMORY_XP))return FALSE;
  }else if(D.GcdMemoryType!=EfiGcdMemoryTypeNonExistent||D.ImageHandle)return FALSE;
  Cursor=MIN(HR_END,D.BaseAddress+D.Length);
 }
 if(Cursor!=HR_END)return FALSE;
 mN976nHighRamReport[23]=Free;return TRUE;
}
STATIC BOOLEAN HrRangeType(UINT64 Base,UINT64 Pages,EFI_MEMORY_TYPE Type)
{
 UINTN Bytes=sizeof(mHrMap),Key=0,Stride=0;UINT32 Version=0;UINT64 Covered=0,Need=Pages*HR_PAGE;
 if(!Pages||Pages>N976N_HIGH_RAM_BYTES/HR_PAGE||!HrSpan(Base,Need,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
    EFI_ERROR(gBS->GetMemoryMap(&Bytes,(VOID*)mHrMap,&Key,&Stride,&Version))||
    Bytes>sizeof(mHrMap)||!Bytes||Stride<sizeof(EFI_MEMORY_DESCRIPTOR)||Bytes%Stride||Version!=1)return FALSE;
 for(UINTN O=0;O<Bytes;O+=Stride){EFI_MEMORY_DESCRIPTOR *D=(VOID*)((UINT8*)mHrMap+O);
  if(!D->NumberOfPages||D->NumberOfPages>MAX_UINT64/HR_PAGE)return FALSE;
  UINT64 N=D->NumberOfPages*HR_PAGE;
  if((D->PhysicalStart&4095)||N>MAX_UINT64-D->PhysicalStart)return FALSE;
  for(UINTN P=0;P<O;P+=Stride){EFI_MEMORY_DESCRIPTOR *E=(VOID*)((UINT8*)mHrMap+P);
   if(HrOverlap(D->PhysicalStart,N,E->PhysicalStart,E->NumberOfPages*HR_PAGE))return FALSE;}
  if(HrOverlap(Base,Need,D->PhysicalStart,N)){
   if(D->Type!=(UINT32)Type)return FALSE;
   UINT64 Lo=MAX(Base,D->PhysicalStart),Hi=MIN(Base+Need,D->PhysicalStart+N);
   if(Hi-Lo>Need-Covered)return FALSE;Covered+=Hi-Lo;
  }
 }
 return Covered==Need;
}
STATIC BOOLEAN HrAdmit (CONST N976N_PLATFORM_HANDOFF *H)
{
  if (!H || H->Magic != N976N_PLATFORM_HANDOFF_MAGIC || H->Version != N976N_PLATFORM_ABI_VERSION ||
      H->Size != sizeof (*H) || H->Reserved || H->Profile > 1 ||
      H->HeapBase != N976N_BOOTSTRAP_HEAP_BASE || H->HeapSize != N976N_BOOTSTRAP_HEAP_END-N976N_BOOTSTRAP_HEAP_BASE)
    return FALSE;
  CopyMem (&mHrHandoff,H,sizeof (*H));
  VOID *Hob = GetFirstGuidHob (&gN976nHighRamAdmissionGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (mHrAdmission)) return FALSE;
  CopyMem (&mHrAdmission,GET_GUID_HOB_DATA (Hob),sizeof (mHrAdmission));
  CONST N976N_HIGH_RAM_ADMISSION *A = &mHrAdmission;
  mN976nHighRamReport[22] = A->Checks;
  if (A->Magic != N976N_HIGH_RAM_MAGIC || A->Version != 1 || A->Size != sizeof (*A) ||
      A->Base != N976N_HIGH_RAM_BASE || A->Bytes != N976N_HIGH_RAM_BYTES ||
      A->Checks != N976N_HIGH_RAM_ADMISSION_ALL || A->Reason || A->Admitted != 1 ||
      A->DynamicMask != 7 || A->Reserved || A->ImageBase != H->ImageBase || A->ImageBytes != H->ImageSize ||
      !A->Dtb || A->DtbBytes < 40 || A->DtbBytes > 0x200000 ||
      !A->InitrdBase || !A->InitrdBytes || !A->ImageBase || !A->ImageBytes) return FALSE;
  const UINT64 Live[][2] = {{H->HeapBase,H->HeapSize},{H->ImageBase,H->ImageSize},
    {H->FirmwareBase,H->FirmwareSize},{H->StackBase,H->StackSize},
    {A->Dtb,A->DtbBytes},{A->InitrdBase,A->InitrdBytes},{0xCA000000ULL,0x010B3000ULL}};
  for (UINTN I=0; I<ARRAY_SIZE (Live); ++I)
    if (!Live[I][0] || !Live[I][1] || Live[I][1] > MAX_UINT64-Live[I][0] ||
        HrOverlap (A->Base,A->Bytes,Live[I][0],Live[I][1])) return FALSE;
  return TRUE;
}
STATIC UINT64 HrPattern(UINT64 Address,UINTN Pass)
{ return Address^(Pass==1?0x59A5C39E76012D4BULL:0xA65A3C6189FED2B4ULL); }
STATIC BOOLEAN HrCompare(UINT64 Address,UINT64 Expected,UINT64 Actual)
{
 if(Expected==Actual)return TRUE;
 if(!mN976nHighRamReport[3]){mN976nHighRamReport[12]=Address;mN976nHighRamReport[13]=Expected;mN976nHighRamReport[14]=Actual;}
 return FALSE;
}
STATIC BOOLEAN HrOwned(UINTN I)
{
 if(I>=2||!mHrOwned[I]||!HrCpuStable()||
    !HrSpan(mHrAlloc[I],mHrPages[I]*HR_PAGE,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
    !HrRangeType(mHrAlloc[I],mHrPages[I],I?EfiBootServicesCode:EfiBootServicesData))return FALSE;
 for(UINTN P=0;P<mHrPages[I];++P)if(!HrMapping(mHrAlloc[I]+P*HR_PAGE,0))return FALSE;
 return TRUE;
}
STATIC BOOLEAN HrGuards(BOOLEAN Initialize)
{
 if(!HrOwned(0))return FALSE;
 for(UINTN End=0;End<2;++End){
  UINT64 A=mHrAlloc[0]+(End?mHrPages[0]-1:0)*HR_PAGE;volatile UINT64 *P=HrPage(A);
  for(UINTN W=0;W<HR_PAGE/8;++W){UINT64 V=HR_GUARD^A^W;if(Initialize)P[W]=V;else if(!HrCompare(A+W*8,V,P[W]))return FALSE;}
  if(Initialize)WriteBackInvalidateDataCacheRange((VOID*)(UINTN)A,HR_PAGE);
 }
 return TRUE;
}
STATIC BOOLEAN HrPatterns(VOID)
{
 for(UINTN Pass=1;Pass<=2;++Pass){
  for(UINTN I=0;I<2;++I){
   if(!HrOwned(I))return FALSE;
   for(UINTN P=I?0:1;P<mHrPages[I]-(I?0:1);++P){
    UINT64 A=mHrAlloc[I]+P*HR_PAGE;volatile UINT64 *V=HrPage(A);
    for(UINTN W=0;W<HR_PAGE/8;++W)V[W]=HrPattern(A+W*8,Pass);
    WriteBackInvalidateDataCacheRange((VOID*)(UINTN)A,HR_PAGE);
   }
  }
  MemoryFence();
  for(UINTN I=0;I<2;++I){
   if(!HrOwned(I))return FALSE;
   for(UINTN P=I?0:1;P<mHrPages[I]-(I?0:1);++P){
    UINT64 A=mHrAlloc[I]+P*HR_PAGE;
    InvalidateDataCacheRange((VOID*)(UINTN)A,HR_PAGE);MemoryFence();
    volatile UINT64 *V=HrPage(A);
    for(UINTN W=0;W<HR_PAGE/8;++W)if(!HrCompare(A+W*8,HrPattern(A+W*8,Pass),V[W]))return FALSE;
   }
  }
  if(!HrGuards(FALSE))return FALSE;
 }
 return TRUE;
}
STATIC BOOLEAN HrAllocate(UINTN I,EFI_ALLOCATE_TYPE Type,UINT64 Requested)
{
 EFI_PHYSICAL_ADDRESS Address=Requested;
 EFI_STATUS S=gBS->AllocatePages(Type,I?EfiBootServicesCode:EfiBootServicesData,mHrPages[I],&Address);
 if(EFI_ERROR(S))return FALSE;
 mHrAlloc[I]=Address;mHrOwned[I]=TRUE;++mN976nHighRamReport[8];
 if((Address&4095)||(Type==AllocateAddress&&Address!=Requested)||
    !HrSpan(Address,mHrPages[I]*HR_PAGE,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
    (I&&mHrOwned[0]&&HrOverlap(Address,mHrPages[I]*HR_PAGE,mHrAlloc[0],mHrPages[0]*HR_PAGE)))return FALSE;
 return HrOwned(I);
}
STATIC BOOLEAN HrFree(UINTN I)
{
 if(!HrOwned(I))return FALSE;
 EFI_STATUS S=gBS->FreePages(mHrAlloc[I],mHrPages[I]);
 if(EFI_ERROR(S)||!HrRangeType(mHrAlloc[I],mHrPages[I],EfiConventionalMemory))return FALSE;
 for(UINTN P=0;P<mHrPages[I];++P)if(!HrMapping(mHrAlloc[I]+P*HR_PAGE,0))return FALSE;
 mHrOwned[I]=FALSE;++mN976nHighRamReport[9];return TRUE;
}
__attribute__((noinline)) EFI_STATUS N976nHighRamProbeDone(EFI_STATUS Status)
{
 if(!EFI_ERROR(Status)){mN976nHighRamReport[0]=8;mHrReady=TRUE;}
 mN976nHighRamReport[1]=Status;
 if(mN976nHighRamReport[3])mN976nHighRamReport[12]=mHrFailureAddress;
 N976nHighRamScreen();N976nHighRamCheckpoint();return Status;
}
EFI_STATUS N976nRunHighRamProbe(CONST N976N_PLATFORM_HANDOFF *H)
{
 EFI_STATUS Status=EFI_SUCCESS;UINT64 Address=0;
 if(mHrStarted)return EFI_ALREADY_STARTED;mHrStarted=TRUE;
 ZeroMem((VOID*)mN976nHighRamReport,sizeof(mN976nHighRamReport));
 mN976nHighRamReport[1]=EFI_NOT_READY;mN976nHighRamReport[4]=N976N_HIGH_RAM_BASE;
 mN976nHighRamReport[5]=N976N_HIGH_RAM_BYTES;HrMark(1,0);
#define NEED(C,R,S) do{if(!(C)){Status=HrFail(R,S);goto Done;}}while(0)
 NEED((FixedPcdGet32(PcdN976nUfsQueryExperiment)==9||FixedPcdGet32(PcdN976nUfsQueryExperiment)==12||FixedPcdGet32(PcdN976nUfsQueryExperiment)==13)&&
      EfiGetCurrentTpl()==TPL_APPLICATION&&HrAdmit(H),1,EFI_ACCESS_DENIED);
 mN976nHighRamReport[2]|=1;
 HrReadCpu(&mHrCpu);mN976nHighRamReport[17]=mHrCpu.PaBits;mN976nHighRamReport[18]=mHrCpu.Tcr;mN976nHighRamReport[19]=mHrCpu.Sctlr;
 NEED(HrCpuValid(&mHrCpu),2,EFI_UNSUPPORTED);
 NEED(HrAudit(TRUE,0,0)&&HrMapSnapshot(FALSE),3,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[2]|=2;mN976nHighRamReport[16]=1;
 HrMark(2,N976N_HIGH_RAM_BASE);
 /* Force 4KiB tables before publication. The pinned upstream mapper retains
    existing table branches when the rest of the bank is subsequently filled. */
 for(Address=N976N_HIGH_RAM_BASE;Address<HR_END;Address+=HR_CHUNK){
  mN976nHighRamReport[12]=Address;
  NEED(!EFI_ERROR(ArmSetMemoryAttributes(Address,HR_PAGE,EFI_MEMORY_WB|EFI_MEMORY_XP,0))&&
       HrCpuStable()&&HrMapping(Address,0),4,EFI_SECURITY_VIOLATION);
 }
 NEED(!EFI_ERROR(ArmSetMemoryAttributes(N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES,EFI_MEMORY_WB|EFI_MEMORY_XP,0))&&
      HrAudit(FALSE,0,0)&&HrMapSnapshot(FALSE),5,EFI_SECURITY_VIOLATION);
 /* All admitted addresses may be used by DXE immediately inside AddMemorySpace.
    Initialize their inherited cache state before publication, range-only. This
    is not a full-bank data-pattern test and performs no storage/DMA operation. */
 HrMark(3,N976N_HIGH_RAM_BASE);
 InvalidateDataCacheRange((VOID*)(UINTN)N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES);MemoryFence();
 NEED(HrCpuStable()&&HrMapping(N976N_HIGH_RAM_BASE,0)&&HrMapping(HR_END-HR_PAGE,0)&&HrMapSnapshot(FALSE),6,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[2]|=4;N976nHighRamMappedCheckpoint();
 HrMark(4,N976N_HIGH_RAM_BASE);
 /* Commit boundary: Add can partially publish and allocate bookkeeping even
    if it returns an error. Never remove/unmap/revoke the bank after this call. */
 mHrCommitAttempted=TRUE;
 Status=gDS->AddMemorySpace(EfiGcdMemoryTypeSystemMemory,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES,
                            EFI_MEMORY_WB|EFI_MEMORY_XP|EFI_MEMORY_RO|EFI_MEMORY_RP);
 NEED(!EFI_ERROR(Status),7,Status);mHrPublished=TRUE;mN976nHighRamReport[7]=1;
 Status=gDS->SetMemorySpaceAttributes(N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES,EFI_MEMORY_WB|EFI_MEMORY_XP);
 NEED(!EFI_ERROR(Status),8,Status);mN976nHighRamReport[7]|=2;
 NEED(HrMapSnapshot(TRUE)&&HrAudit(FALSE,0,0),9,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[7]|=4;mN976nHighRamReport[2]|=8;mN976nHighRamReport[16]|=2;
 N976nHighRamPublishedCheckpoint();
 HrMark(5,N976N_HIGH_RAM_BASE+HR_CHUNK);
 NEED(HrAllocate(0,AllocateAddress,N976N_HIGH_RAM_BASE+HR_CHUNK),10,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[20]=mHrAlloc[0];mN976nHighRamReport[21]=mHrPages[0];
 NEED(HrAllocate(1,AllocateMaxAddress,HR_END-1),11,EFI_SECURITY_VIOLATION);
 /* Refusal tests target an owned duplicate and addresses outside all admitted
    allocatable memory. Never free or access an unowned address. */
 Address=mHrAlloc[0];Status=gBS->AllocatePages(AllocateAddress,EfiBootServicesData,1,&Address);
 NEED(Status==EFI_NOT_FOUND,12,EFI_SECURITY_VIOLATION);
 Address=mHrAlloc[0]+1;Status=gBS->AllocatePages(AllocateAddress,EfiBootServicesData,1,&Address);
 NEED(Status==EFI_NOT_FOUND,12,EFI_SECURITY_VIOLATION);
 Address=HR_END-HR_PAGE;Status=gBS->AllocatePages(AllocateAddress,EfiBootServicesData,2,&Address);
 NEED(Status==EFI_NOT_FOUND,12,EFI_SECURITY_VIOLATION);
 Address=HR_END;Status=gBS->AllocatePages(AllocateAddress,EfiBootServicesData,1,&Address);
 NEED(Status==EFI_NOT_FOUND,12,EFI_SECURITY_VIOLATION);
 NEED(HrMapSnapshot(TRUE)&&HrGuards(TRUE)&&HrPatterns(),13,EFI_COMPROMISED_DATA);
 mN976nHighRamReport[15]=1;mN976nHighRamReport[2]|=16;
 N976nHighRamAllocatedCheckpoint();
 HrMark(6,mHrAlloc[0]+HR_PAGE);Address=mHrAlloc[0]+HR_PAGE;
 NEED(!EFI_ERROR(gDS->SetMemorySpaceAttributes(Address,HR_PAGE,EFI_MEMORY_WB|EFI_MEMORY_XP|EFI_MEMORY_RO))&&
      HrCpuStable()&&HrMapping(Address,1),14,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[10]=1;
 /* Read proof while RO, followed by actual page-table/AT write rejection. */
 for(UINTN W=0;W<HR_PAGE/8;++W)NEED(HrCompare(Address+W*8,HrPattern(Address+W*8,2),HrPage(Address)[W]),14,EFI_COMPROMISED_DATA);
 NEED(HrAudit(FALSE,Address,1),14,EFI_SECURITY_VIOLATION);mN976nHighRamReport[10]|=2;
 NEED(!EFI_ERROR(gDS->SetMemorySpaceAttributes(Address,HR_PAGE,EFI_MEMORY_WB|EFI_MEMORY_XP|EFI_MEMORY_RO|EFI_MEMORY_RP))&&
      HrCpuStable()&&HrMapping(Address,2),15,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[11]=1;
 NEED(HrAudit(FALSE,Address,2),15,EFI_SECURITY_VIOLATION);mN976nHighRamReport[11]|=2;
 N976nHighRamProtectedCheckpoint();
 /* Do not call FreePages on RP/RO: pinned upstream may return SUCCESS while
    leaking it. First restore exact RW-XN, then check the resulting type. */
 NEED(!EFI_ERROR(gDS->SetMemorySpaceAttributes(Address,HR_PAGE,EFI_MEMORY_WB|EFI_MEMORY_XP))&&
      HrMapping(Address,0)&&HrGuards(FALSE)&&HrOwned(1),16,EFI_SECURITY_VIOLATION);
 InvalidateDataCacheRange((VOID*)(UINTN)Address,HR_PAGE);MemoryFence();
 for(UINTN W=0;W<HR_PAGE/8;++W)NEED(HrCompare(Address+W*8,HrPattern(Address+W*8,2),HrPage(Address)[W]),16,EFI_COMPROMISED_DATA);
 mN976nHighRamReport[15]|=2;mN976nHighRamReport[2]|=32;
 HrMark(7,mHrAlloc[0]);
 NEED(HrFree(1)&&HrFree(0),17,EFI_SECURITY_VIOLATION);
 NEED(HrAllocate(0,AllocateAddress,N976N_HIGH_RAM_BASE+HR_CHUNK)&&HrGuards(TRUE)&&HrGuards(FALSE)&&HrFree(0),18,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[2]|=64;
 NEED(!mHrOwned[0]&&!mHrOwned[1]&&mN976nHighRamReport[8]==3&&mN976nHighRamReport[9]==3&&
      HrMapSnapshot(TRUE)&&HrAudit(FALSE,0,0),19,EFI_SECURITY_VIOLATION);
 mN976nHighRamReport[16]|=4;mN976nHighRamReport[2]|=128;N976nHighRamFreedCheckpoint();
 Status=EFI_SUCCESS;
Done:
 /* Failures are sticky. Retain all mappings and owned allocations for
    diagnosis; after commit this is necessary to protect live DXE metadata. */
 if(mN976nHighRamReport[3])Status=mN976nHighRamReport[1];
 return N976nHighRamProbeDone(Status);
#undef NEED
}

/* Publication success is distinct from merely attempting AddMemorySpace. The
 * report is the pre-Windows snapshot; live clients must request fresh ownership
 * and permission checks below, never infer free bytes from this old snapshot. */
BOOLEAN N976nHighRamPublished(VOID)
{
 return mHrReady&&mHrCommitAttempted&&mHrPublished&&!mHrOwned[0]&&!mHrOwned[1]&&
   mN976nHighRamReport[0]==8&&mN976nHighRamReport[1]==EFI_SUCCESS&&
   mN976nHighRamReport[2]==255&&mN976nHighRamReport[3]==0&&
   mN976nHighRamReport[7]==7&&mN976nHighRamReport[16]==7;
}
/* Exact synchronous CPU-only borrow. This does not grant DMA ownership or
 * admit FAT/firmware control allocations. The caller specifies allocated data
 * types; LoaderCode is accepted only when its actual mapping remains RW-XN. */
STATIC BOOLEAN HrLiveCpuRange(CONST VOID *Buffer,UINTN Bytes,UINT32 TypeMask,BOOLEAN Freed)
{
 CONST UINT32 Allowed=Freed?(1U<<EfiConventionalMemory):
   (1U<<EfiLoaderCode)|(1U<<EfiLoaderData)|(1U<<EfiBootServicesData);
 UINT64 Address=(UINTN)Buffer,Covered=0;
 UINTN MapBytes=sizeof(mHrBorrowMap),Key=0,Stride=0;UINT32 Version=0;
 BOOLEAN Valid=FALSE;EFI_TPL Old;
 if(!N976nHighRamPublished()||mHrBorrowBusy||!TypeMask||(TypeMask&~Allowed)||
    EfiGetCurrentTpl()>TPL_CALLBACK||!Buffer||!Bytes||Bytes>0x400000||
    !HrSpan(Address,Bytes,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||!HrCpuStable())return FALSE;
 /* The bounded request limit exceeds the current read-only FAT medium plus
    its generated MBR. SEC66 uses this unchanged bounded CPU check for each
    slice of a separately owned full-file allocation; it never grants DMA. */
#define PRIVATE(X) if(HrOverlap(Address,Bytes,(UINTN)&(X),sizeof(X)))return FALSE
 PRIVATE(mHrBorrowMap);PRIVATE(mHrMap);PRIVATE(mHrCpu);PRIVATE(mHrAdmission);
 PRIVATE(mHrHandoff);PRIVATE(mN976nHighRamReport);PRIVATE(mHrAlloc);PRIVATE(mHrPages);
 PRIVATE(mHrOwned);PRIVATE(mHrReady);PRIVATE(mHrBorrowBusy);
#undef PRIVATE
 Old=gBS->RaiseTPL(TPL_CALLBACK);
 if(mHrBorrowBusy){gBS->RestoreTPL(Old);return FALSE;}mHrBorrowBusy=TRUE;
 if(EFI_ERROR(gBS->GetMemoryMap(&MapBytes,(VOID*)mHrBorrowMap,&Key,&Stride,&Version))||
    !MapBytes||MapBytes>sizeof(mHrBorrowMap)||Stride<sizeof(EFI_MEMORY_DESCRIPTOR)||
    MapBytes%Stride||Version!=EFI_MEMORY_DESCRIPTOR_VERSION)goto Done;
 for(UINTN O=0;O<MapBytes;O+=Stride){
  EFI_MEMORY_DESCRIPTOR *D=(VOID*)((UINT8*)mHrBorrowMap+O);
  if(!D->NumberOfPages||D->NumberOfPages>MAX_UINT64/HR_PAGE)goto Done;
  UINT64 N=D->NumberOfPages*HR_PAGE;
  if((D->PhysicalStart&4095)||N>MAX_UINT64-D->PhysicalStart)goto Done;
  for(UINTN P=0;P<O;P+=Stride){EFI_MEMORY_DESCRIPTOR *E=(VOID*)((UINT8*)mHrBorrowMap+P);
   if(HrOverlap(D->PhysicalStart,N,E->PhysicalStart,E->NumberOfPages*HR_PAGE))goto Done;}
  if(HrOverlap(Address,Bytes,D->PhysicalStart,N)){
   if(D->Type>=32||!(TypeMask&(1U<<D->Type))||!(D->Attribute&EFI_MEMORY_WB)||
      (D->Attribute&EFI_MEMORY_RUNTIME)||!HrSpan(D->PhysicalStart,N,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES))goto Done;
   UINT64 Lo=MAX(Address,D->PhysicalStart),Hi=MIN(Address+Bytes,D->PhysicalStart+N);
   if(Hi-Lo>Bytes-Covered)goto Done;Covered+=Hi-Lo;
  }
 }
 if(Covered!=Bytes)goto Done;
 for(UINT64 P=Address&~4095ULL;P<=((Address+Bytes-1)&~4095ULL);P+=HR_PAGE)
  if(!HrMapping(P,0))goto Done;
 /* GCD remains an independent resource owner and cache-attribute authority. */
 UINT64 Cursor=Address,End=Address+Bytes;
 for(UINTN I=0;Cursor<End&&I<128;++I){EFI_GCD_MEMORY_SPACE_DESCRIPTOR D;
  if(EFI_ERROR(gDS->GetMemorySpaceDescriptor(Cursor,&D))||!D.Length||
     D.Length>MAX_UINT64-D.BaseAddress||D.BaseAddress>Cursor||D.BaseAddress+D.Length<=Cursor||
     !HrSpan(D.BaseAddress,D.Length,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)||
     D.GcdMemoryType!=EfiGcdMemoryTypeSystemMemory||!D.ImageHandle||
     (D.Attributes&(EFI_MEMORY_CACHETYPE_MASK|EFI_MEMORY_XP|EFI_MEMORY_RO|EFI_MEMORY_RP|EFI_MEMORY_RUNTIME))!=(EFI_MEMORY_WB|EFI_MEMORY_XP))goto Done;
  Cursor=MIN(End,D.BaseAddress+D.Length);
 }
 Valid=Cursor==End&&HrCpuStable();
Done:
 mHrBorrowBusy=FALSE;gBS->RestoreTPL(Old);return Valid;
}

BOOLEAN N976nHighRamOwnedCpuRange(CONST VOID *Buffer,UINTN Bytes,UINT32 TypeMask)
{ return HrLiveCpuRange(Buffer,Bytes,TypeMask,FALSE); }
/* Retirement proof, never a data-access grant. A failed ownership check is
   not proof of free memory; require exact ConventionalMemory plus the same
   CPU/PTE/GCD checks as a live data borrow. */
BOOLEAN N976nHighRamFreedCpuRange(CONST VOID *Buffer,UINTN Bytes)
{ return HrLiveCpuRange(Buffer,Bytes,1U<<EfiConventionalMemory,TRUE); }
