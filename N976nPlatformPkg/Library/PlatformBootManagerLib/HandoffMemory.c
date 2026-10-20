/* SPDX-License-Identifier: MIT
 * SEC68: preallocated, read-only memory contract at the UEFI handoff boundary.
 * Reuses upstream GetMemoryMap/MemoryAttribute and the existing sealed catalog.
 * No map-key substitution, memory-type conversion, PTE write or cache operation.
 */
#include <PiDxe.h>
#include <N976nHandoffMemory.h>
#include <N976nPlatform.h>
#include <N976nHighRam.h>
#include <N976nAcpiPlatform.h>
#include <N976nWindowsBoot.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/ArmLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/MemoryAttribute.h>
#include <IndustryStandard/PeImage.h>
#include "AcpiBspDsdt.h"

#define HM_PAGE 4096ULL
#define HM_PAGES (N976N_HANDOFF_MAP_BYTES / HM_PAGE + 2)
#define HM_GUARD 0x3836445241554748ULL
#define HM_SECTIONS 12U
#define HM_ACPI_COUNT 6U
#define HM_ACPI_MAX 512U
#define HM_RT_ALIGN 0x10000ULL
#define HM_EXEC 0x20000000U
#define HM_READ 0x40000000U
#define HM_WRITE 0x80000000U

typedef struct {
  UINT64 Address, Bytes;
  UINT8 Data[HM_ACPI_MAX];
} HM_ACPI;
typedef struct {
  UINT32 Rva, Bytes, Raw, RawBytes, Flags;
} HM_SECTION;
typedef struct {
  CONST UINT8 *Source;
  UINTN Bytes, Headers, ImageBytes, Count;
  UINT32 RelocRva, RelocBytes;
  HM_SECTION Sections[HM_SECTIONS];
} HM_PE;
typedef struct {
  UINT64 Allocation, FvBase, FvBytes;
  EFI_MEMORY_DESCRIPTOR *Map;
  UINTN MapBytes, Stride;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Attributes;
  BOOLEAN Prepared, Begun;
  UINTN RuntimeCount;
  N976N_BOOTSTRAP_IMAGE Runtime[N976N_BOOTSTRAP_IMAGE_LIMIT];
  HM_ACPI Acpi[HM_ACPI_COUNT];
} HM_STATE;

STATIC HM_STATE mHm;
STATIC CONST EFI_GUID mHmPolicyGuid = N976N_BOOTSTRAP_POLICY_HOB_GUID;
volatile N976N_HANDOFF_MEMORY_REPORT mN976nHandoffMemoryReport;

STATIC BOOLEAN HmSpan (UINT64 A, UINT64 N, UINT64 Base, UINT64 Bytes)
{ return N && A >= Base && A-Base < Bytes && N <= Bytes-(A-Base); }
STATIC BOOLEAN HmLow (UINT64 A, UINT64 N)
{ return HmSpan (A, N, N976N_BOOTSTRAP_HEAP_BASE,
    N976N_BOOTSTRAP_HEAP_END-N976N_BOOTSTRAP_HEAP_BASE); }
STATIC UINT16 Hm16 (CONST UINT8 *P)
{ return (UINT16)(P[0] | ((UINT16)P[1]<<8)); }
STATIC UINT32 Hm32 (CONST UINT8 *P)
{ return (UINT32)Hm16(P) | ((UINT32)Hm16(P+2)<<16); }
STATIC BOOLEAN HmOverlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return A < B+M && B < A+N; } /* Callers have already bounded both ends. */

STATIC EFI_STATUS HmFail (UINT64 Reason, UINT64 Detail, EFI_STATUS Status)
{
  mN976nHandoffMemoryReport.Phase=0xE0;
  mN976nHandoffMemoryReport.Reason=Reason;
  mN976nHandoffMemoryReport.Detail=Detail;
  mN976nHandoffMemoryReport.Status=Status;
  return Status;
}

STATIC BOOLEAN HmAttributes (UINT64 Address, UINT64 Bytes, UINT64 Expected)
{
  UINT64 Attributes=0;
  if (!Bytes || Address > MAX_UINT64-Bytes ||
      Address+Bytes > MAX_UINT64-(HM_PAGE-1) || !mHm.Attributes ||
      !mHm.Attributes->GetMemoryAttributes) return FALSE;
  UINT64 Base=Address & ~(HM_PAGE-1);
  UINT64 End=ALIGN_VALUE(Address+Bytes,HM_PAGE);
  return !EFI_ERROR(mHm.Attributes->GetMemoryAttributes(mHm.Attributes,Base,End-Base,&Attributes)) &&
    Attributes==Expected;
}

STATIC BOOLEAN HmGuards (VOID)
{
  if (!HmLow(mHm.Allocation,HM_PAGES*HM_PAGE) ||
      !HmAttributes(mHm.Allocation,HM_PAGES*HM_PAGE,EFI_MEMORY_XP)) return FALSE;
  for (UINTN Side=0; Side<2; ++Side) {
    UINT64 Address=mHm.Allocation+(Side ? HM_PAGE+N976N_HANDOFF_MAP_BYTES : 0);
    CONST UINT64 *P=(CONST VOID *)(UINTN)Address;
    for (UINTN I=0; I<HM_PAGE/sizeof(UINT64); ++I)
      if (P[I] != (HM_GUARD ^ Address ^ I)) return FALSE;
  }
  return TRUE;
}

STATIC CONST EFI_MEMORY_DESCRIPTOR *HmDescriptor (UINTN Index)
{ return (CONST VOID *)((CONST UINT8 *)mHm.Map+Index*mHm.Stride); }

STATIC BOOLEAN HmMapValid (VOID)
{
  if (!mHm.MapBytes || mHm.MapBytes>N976N_HANDOFF_MAP_BYTES ||
      mHm.Stride<sizeof(EFI_MEMORY_DESCRIPTOR) || mHm.Stride%8 ||
      mHm.MapBytes%mHm.Stride) return FALSE;
  UINTN Count=mHm.MapBytes/mHm.Stride;
  UINT64 High=0, Runtime=0;
  for (UINTN I=0; I<Count; ++I) {
    CONST EFI_MEMORY_DESCRIPTOR *D=HmDescriptor(I);
    if (!D->NumberOfPages || D->NumberOfPages>MAX_UINT64/HM_PAGE ||
        (D->PhysicalStart&(HM_PAGE-1)) ||
        (D->Type>=EfiMaxMemoryType && D->Type<MEMORY_TYPE_OEM_RESERVED_MIN) ||
        D->PhysicalStart>MAX_UINT64-D->NumberOfPages*HM_PAGE) return FALSE;
    UINT64 Bytes=D->NumberOfPages*HM_PAGE, End=D->PhysicalStart+Bytes;
    for (UINTN J=0; J<I; ++J) {
      CONST EFI_MEMORY_DESCRIPTOR *E=HmDescriptor(J);
      if (HmOverlap(D->PhysicalStart,Bytes,E->PhysicalStart,E->NumberOfPages*HM_PAGE)) return FALSE;
    }
    BOOLEAN Rt=D->Type==EfiRuntimeServicesCode || D->Type==EfiRuntimeServicesData;
    if (Rt) {
      if (!(D->Attribute&EFI_MEMORY_RUNTIME) ||
          !(D->Attribute&EFI_MEMORY_WB) ||
          (D->PhysicalStart&(HM_RT_ALIGN-1)) || (End&(HM_RT_ALIGN-1)) ||
          !HmLow(D->PhysicalStart,Bytes)) return FALSE;
      ++Runtime;
    } else if (D->Attribute&EFI_MEMORY_RUNTIME) {
      /* This platform has no admitted runtime MMIO/provider outside its six
       * runtime images and low runtime data. A new provider needs admission. */
      return FALSE;
    }
    if (HmOverlap(D->PhysicalStart,Bytes,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)) {
      if (!HmSpan(D->PhysicalStart,Bytes,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES) ||
          !(D->Type==EfiConventionalMemory || D->Type==EfiLoaderCode ||
            D->Type==EfiLoaderData || D->Type==EfiBootServicesCode ||
            D->Type==EfiBootServicesData || D->Type>=MEMORY_TYPE_OS_RESERVED_MIN) ||
          !(D->Attribute&EFI_MEMORY_WB) ||
          Bytes>N976N_HIGH_RAM_BYTES-High) return FALSE;
      High+=Bytes;
    }
  }
  mN976nHandoffMemoryReport.DescriptorCount=Count;
  mN976nHandoffMemoryReport.RuntimeDescriptors=Runtime;
  mN976nHandoffMemoryReport.HighBytes=High;
  return Runtime && High==N976N_HIGH_RAM_BYTES;
}

STATIC BOOLEAN HmOwned (UINT64 Address, UINT64 Bytes, UINT32 Type, BOOLEAN Runtime)
{
  if (!HmLow(Address,Bytes)) return FALSE;
  UINT64 Covered=0;
  for (UINTN I=0; I<mHm.MapBytes/mHm.Stride; ++I) {
    CONST EFI_MEMORY_DESCRIPTOR *D=HmDescriptor(I);
    UINT64 End=D->PhysicalStart+D->NumberOfPages*HM_PAGE;
    if (D->PhysicalStart>=Address+Bytes || End<=Address) continue;
    if (D->Type!=Type || !!(D->Attribute&EFI_MEMORY_RUNTIME)!=Runtime ||
        !(D->Attribute&EFI_MEMORY_WB)) return FALSE;
    UINT64 Part=MIN(End,Address+Bytes)-MAX(D->PhysicalStart,Address);
    if (Part>Bytes-Covered) return FALSE;
    Covered+=Part;
  }
  return Covered==Bytes;
}

STATIC CONST UINT8 *HmRva (CONST HM_PE *V, UINT32 Rva, UINT32 Bytes)
{
  for (UINTN I=0; I<V->Count; ++I) {
    CONST HM_SECTION *S=&V->Sections[I];
    if (HmSpan(Rva,Bytes,S->Rva,MIN(S->Bytes,S->RawBytes)))
      return V->Source+S->Raw+Rva-S->Rva;
  }
  return NULL;
}

STATIC BOOLEAN HmPe (CONST N976N_BOOTSTRAP_IMAGE *Image, HM_PE *V)
{
  ZeroMem(V,sizeof(*V));
  if (!HmSpan(Image->SourceOffset,Image->SourceBytes,0,mHm.FvBytes) ||
      Image->SourceBytes<64 || Image->Subsystem!=12 || Image->FileType!=7 ||
      !HmLow(Image->LoadedBase,Image->LoadedBytes) ||
      ((Image->LoadedBase|Image->LoadedBytes)&(HM_PAGE-1))) return FALSE;
  CONST UINT8 *P=(CONST VOID *)(UINTN)(mHm.FvBase+Image->SourceOffset);
  UINTN N=Image->SourceBytes, Pe=Hm32(P+60);
  if (Hm16(P)!=0x5A4D || !HmSpan(Pe,24,0,N) || Hm32(P+Pe)!=0x4550 ||
      Hm16(P+Pe+4)!=0xAA64 || Hm16(P+Pe+20)<112+6*8) return FALSE;
  UINTN Optional=Pe+24, OptionalBytes=Hm16(P+Pe+20);
  if (!HmSpan(Optional,OptionalBytes,0,N) || Hm16(P+Optional)!=0x20B ||
      Hm16(P+Optional+68)!=12 || Hm32(P+Optional+32)!=HM_PAGE ||
      Hm32(P+Optional+56)!=Image->LoadedBytes ||
      Hm32(P+Optional+108)<6) return FALSE;
  V->Source=P; V->Bytes=N; V->Headers=Hm32(P+Optional+60);
  V->ImageBytes=Image->LoadedBytes; V->Count=Hm16(P+Pe+6);
  V->RelocRva=Hm32(P+Optional+112+5*8);
  V->RelocBytes=Hm32(P+Optional+116+5*8);
  if (!V->Count || V->Count>HM_SECTIONS || !V->Headers ||
      V->Headers>V->ImageBytes || V->Headers>N ||
      !HmSpan(Optional+OptionalBytes,V->Count*40,0,V->Headers)) return FALSE;
  UINT64 End=ALIGN_VALUE(V->Headers,HM_PAGE);
  for (UINTN I=0; I<V->Count; ++I) {
    CONST UINT8 *S=P+Optional+OptionalBytes+I*40;
    HM_SECTION *T=&V->Sections[I];
    T->Bytes=Hm32(S+8); T->Rva=Hm32(S+12);
    T->RawBytes=Hm32(S+16); T->Raw=Hm32(S+20); T->Flags=Hm32(S+36);
    UINT64 Span=ALIGN_VALUE(MAX((UINT64)T->Bytes,T->RawBytes),HM_PAGE);
    if (!T->Bytes || !(T->Flags&HM_READ) || (T->Rva&(HM_PAGE-1)) ||
        (T->Flags&(HM_WRITE|HM_EXEC))==(HM_WRITE|HM_EXEC) ||
        !HmSpan(T->Rva,Span,End,V->ImageBytes-End) ||
        (T->RawBytes && !HmSpan(T->Raw,T->RawBytes,V->Headers,N-V->Headers))) return FALSE;
    End=T->Rva+Span;
  }
  return !V->RelocBytes || HmRva(V,V->RelocRva,V->RelocBytes)!=NULL;
}

STATIC BOOLEAN HmRuntimeImage (CONST N976N_BOOTSTRAP_IMAGE *Image)
{
  HM_PE V;
  if (!HmOwned(Image->LoadedBase,Image->LoadedBytes,EfiRuntimeServicesCode,TRUE) ||
      !HmPe(Image,&V) ||
      !HmAttributes(Image->LoadedBase,ALIGN_VALUE(V.Headers,HM_PAGE),EFI_MEMORY_RO|EFI_MEMORY_XP))
    return FALSE;
  UINT64 End=ALIGN_VALUE(V.Headers,HM_PAGE);
  for (UINTN I=0; I<V.Count; ++I) {
    CONST HM_SECTION *S=&V.Sections[I];
    if (S->Rva>End && !HmAttributes(Image->LoadedBase+End,S->Rva-End,EFI_MEMORY_RO|EFI_MEMORY_XP))
      return FALSE;
    UINT64 Attr=(S->Flags&HM_EXEC) ? EFI_MEMORY_RO :
      EFI_MEMORY_XP | ((S->Flags&HM_WRITE) ? 0 : EFI_MEMORY_RO);
    UINT64 Bytes=ALIGN_VALUE(MAX((UINT64)S->Bytes,S->RawBytes),HM_PAGE);
    if (!HmAttributes(Image->LoadedBase+S->Rva,Bytes,Attr)) return FALSE;
    End=S->Rva+Bytes;
  }
  if (End<V.ImageBytes && !HmAttributes(Image->LoadedBase+End,V.ImageBytes-End,EFI_MEMORY_RO|EFI_MEMORY_XP))
    return FALSE;
  CONST UINT8 *Rel=HmRva(&V,V.RelocRva,V.RelocBytes);
  UINTN Offset=0; UINT64 Last=0; BOOLEAN Seen=FALSE;
  while (Offset<V.RelocBytes) {
    if (V.RelocBytes-Offset<8) return FALSE;
    UINT32 Page=Hm32(Rel+Offset), Bytes=Hm32(Rel+Offset+4);
    if ((Page&(HM_PAGE-1)) || Bytes<8 || (Bytes&3) || Bytes>V.RelocBytes-Offset) return FALSE;
    for (UINTN J=8; J<Bytes; J+=2) {
      UINT16 Entry=Hm16(Rel+Offset+J);
      if (!(Entry>>12)) continue;
      UINT64 Target=(UINT64)Page+(Entry&0xFFF); BOOLEAN Writable=FALSE;
      if ((Entry>>12)!=10 || (Target&7) || (Seen && Target<Last+8) ||
          Target>MAX_UINT32 || !HmRva(&V,(UINT32)Target,8)) return FALSE;
      for (UINTN K=0; K<V.Count; ++K) {
        CONST HM_SECTION *S=&V.Sections[K];
        if ((S->Flags&HM_WRITE) && !(S->Flags&HM_EXEC) &&
            HmSpan(Target,8,S->Rva,S->Bytes)) Writable=TRUE;
      }
      if (!Writable || !HmAttributes(Image->LoadedBase+Target,8,EFI_MEMORY_XP)) return FALSE;
      ++mN976nHandoffMemoryReport.RuntimeFixups; Last=Target; Seen=TRUE;
    }
    Offset+=Bytes;
  }
  ++mN976nHandoffMemoryReport.RuntimeImages;
  return Offset==V.RelocBytes;
}

STATIC BOOLEAN HmCatalog (VOID)
{
  VOID *Hob=GetFirstGuidHob(&gN976nPlatformHandoffGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_PLATFORM_HANDOFF) ||
      GetNextGuidHob(&gN976nPlatformHandoffGuid,GET_NEXT_HOB(Hob))) return FALSE;
  CONST N976N_PLATFORM_HANDOFF *H=GET_GUID_HOB_DATA(Hob);
  if (H->Magic!=N976N_PLATFORM_HANDOFF_MAGIC || H->Version!=N976N_PLATFORM_ABI_VERSION ||
      H->Size!=sizeof(*H) || H->Profile>1 || H->Reserved ||
      H->HeapBase!=N976N_BOOTSTRAP_HEAP_BASE ||
      H->HeapSize!=N976N_BOOTSTRAP_HEAP_END-N976N_BOOTSTRAP_HEAP_BASE ||
      H->FirmwareSize!=N976N_BOOTSTRAP_FV_BYTES || (H->FirmwareBase&(HM_PAGE-1)) ||
      !HmSpan(H->FirmwareBase,H->FirmwareSize,0x80002000,0x7FFFE000) ||
      !HmAttributes(H->FirmwareBase,H->FirmwareSize,EFI_MEMORY_RO|EFI_MEMORY_XP)) return FALSE;
  Hob=GetFirstGuidHob(&mHmPolicyGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_BOOTSTRAP_POLICY) ||
      GetNextGuidHob(&mHmPolicyGuid,GET_NEXT_HOB(Hob))) return FALSE;
  CONST N976N_BOOTSTRAP_POLICY *P=GET_GUID_HOB_DATA(Hob);
  if (P->Magic!=N976N_BOOTSTRAP_POLICY_MAGIC || P->Failure ||
      P->FvBase!=H->FirmwareBase || P->FvBytes!=H->FirmwareSize ||
      !P->SourceCount || P->SourceCount>N976N_BOOTSTRAP_IMAGE_LIMIT ||
      P->ActiveCount>P->SourceCount || P->PublishedCount<P->ActiveCount) return FALSE;
  mHm.FvBase=P->FvBase; mHm.FvBytes=P->FvBytes;
  for (UINTN I=0; I<P->SourceCount; ++I) {
    CONST N976N_BOOTSTRAP_IMAGE *R=&P->Images[I];
    if (R->Subsystem!=12) continue;
    if (!R->LoadedBase || !R->LoadedBytes || mHm.RuntimeCount>=N976N_BOOTSTRAP_IMAGE_LIMIT) return FALSE;
    HM_PE V;
    if (!HmPe(R,&V)) return FALSE;
    for (UINTN J=0; J<mHm.RuntimeCount; ++J)
      if (HmOverlap(R->LoadedBase,R->LoadedBytes,mHm.Runtime[J].LoadedBase,mHm.Runtime[J].LoadedBytes))
        return FALSE;
    mHm.Runtime[mHm.RuntimeCount++]=*R;
  }
  return mHm.RuntimeCount!=0;
}

STATIC BOOLEAN HmAcpi (BOOLEAN Capture)
{
  UINT64 Addresses[HM_ACPI_COUNT]={mN976nWindowsReport.Rsdp,mN976nWindowsReport.Xsdt,
    mN976nWindowsReport.Fadt,mN976nWindowsReport.Dsdt,mN976nAcpiReport.Madt,mN976nAcpiReport.Gtdt};
  UINT64 Sizes[HM_ACPI_COUNT]={sizeof(EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER),
    sizeof(EFI_ACPI_DESCRIPTION_HEADER)+3*sizeof(UINT64),
    sizeof(EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE),sizeof(mAcpiBspDsdt),sizeof(N976N_ACPI_MADT),
    sizeof(EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE)};
  if (mN976nAcpiReport.Phase!=8 || mN976nAcpiReport.Status || mN976nAcpiReport.Checks!=0xFF ||
      mN976nAcpiReport.Reason || mN976nAcpiReport.OwnershipChecks!=0x3F ||
      mN976nAcpiReport.AttributeChecks!=0x3F) return FALSE;
  for (UINTN I=0; I<HM_ACPI_COUNT; ++I) {
    if (Sizes[I]>HM_ACPI_MAX || !HmOwned(Addresses[I],Sizes[I],EfiACPIReclaimMemory,FALSE) ||
        !(HmAttributes(Addresses[I],Sizes[I],EFI_MEMORY_XP) ||
          HmAttributes(Addresses[I],Sizes[I],EFI_MEMORY_RO|EFI_MEMORY_XP))) return FALSE;
    for (UINTN J=0; J<I; ++J)
      if (HmOverlap(Addresses[I],Sizes[I],Addresses[J],Sizes[J])) return FALSE;
    CONST UINT8 *Data=(CONST VOID *)(UINTN)Addresses[I];
    if (CalculateSum8(Data,Sizes[I]) ||
        (I==0 && CalculateSum8(Data,20))) return FALSE;
    if (Capture) {
      mHm.Acpi[I].Address=Addresses[I]; mHm.Acpi[I].Bytes=Sizes[I];
      CopyMem(mHm.Acpi[I].Data,Data,Sizes[I]);
    } else if (mHm.Acpi[I].Address!=Addresses[I] || mHm.Acpi[I].Bytes!=Sizes[I] ||
               CompareMem(mHm.Acpi[I].Data,Data,Sizes[I])) return FALSE;
    mN976nHandoffMemoryReport.AcpiChecks|=1ULL<<I;
  }
  return TRUE;
}

STATIC EFI_STATUS HmCheck (BOOLEAN Begin)
{
  EFI_STATUS Status;
  UINTN Bytes=N976N_HANDOFF_MAP_BYTES, Key=0, Stride=0;
  UINT32 Version=0;
  mN976nHandoffMemoryReport.Phase=2;
  mN976nHandoffMemoryReport.Checks=0;
  mN976nHandoffMemoryReport.AcpiChecks=0;
  mN976nHandoffMemoryReport.RuntimeImages=0;
  mN976nHandoffMemoryReport.RuntimeFixups=0;
  mN976nHandoffMemoryReport.Guards=0;
  if (!mHm.Prepared || !HmGuards()) return HmFail(0x681,mHm.Allocation,EFI_SECURITY_VIOLATION);
  mN976nHandoffMemoryReport.Guards=1;
  mN976nHandoffMemoryReport.Checks|=1;
  Status=gBS->GetMemoryMap(&Bytes,mHm.Map,&Key,&Stride,&Version);
  mN976nHandoffMemoryReport.RequiredBytes=Bytes;
  if (EFI_ERROR(Status)) return HmFail(0x682,Bytes,Status);
  if (Bytes>N976N_HANDOFF_MAP_BYTES || Version!=EFI_MEMORY_DESCRIPTOR_VERSION)
    return HmFail(0x683,Version,EFI_COMPROMISED_DATA);
  mHm.MapBytes=Bytes; mHm.Stride=Stride;
  mN976nHandoffMemoryReport.MapBytes=Bytes;
  mN976nHandoffMemoryReport.DescriptorSize=Stride;
  mN976nHandoffMemoryReport.MapKey=Key;
  if (!HmMapValid()) return HmFail(0x684,0,EFI_COMPROMISED_DATA);
  mN976nHandoffMemoryReport.Checks|=2|4;
  if (!HmOwned(mHm.Allocation,HM_PAGES*HM_PAGE,EfiBootServicesData,FALSE) ||
      !HmAttributes(mHm.FvBase,mHm.FvBytes,EFI_MEMORY_RO|EFI_MEMORY_XP))
    return HmFail(0x685,mHm.Allocation,EFI_SECURITY_VIOLATION);
  for (UINTN I=0; I<mHm.RuntimeCount; ++I)
    if (!HmRuntimeImage(&mHm.Runtime[I]))
      return HmFail(0x686,mHm.Runtime[I].LoadedBase,EFI_SECURITY_VIOLATION);
  mN976nHandoffMemoryReport.Checks|=8|16;
  if (!HmAcpi(!Begin)) return HmFail(0x687,0,EFI_SECURITY_VIOLATION);
  mN976nHandoffMemoryReport.Checks|=32;
  if (!HmOwned((UINTN)gST,sizeof(*gST),EfiRuntimeServicesData,TRUE) ||
      !HmAttributes((UINTN)gST,sizeof(*gST),EFI_MEMORY_XP) ||
      !gST->RuntimeServices ||
      !HmOwned((UINTN)gST->RuntimeServices,sizeof(EFI_RUNTIME_SERVICES),EfiRuntimeServicesData,TRUE) ||
      !HmAttributes((UINTN)gST->RuntimeServices,sizeof(EFI_RUNTIME_SERVICES),EFI_MEMORY_XP))
    return HmFail(0x688,(UINTN)gST,EFI_SECURITY_VIOLATION);
  mN976nHandoffMemoryReport.Checks|=64;
  if (!HmGuards()) return HmFail(0x689,mHm.Allocation,EFI_SECURITY_VIOLATION);
  mN976nHandoffMemoryReport.Guards=3;
  mN976nHandoffMemoryReport.Checks|=128;
  mN976nHandoffMemoryReport.Phase=Begin ? 8 : 1;
  mN976nHandoffMemoryReport.Status=EFI_SUCCESS;
  mN976nHandoffMemoryReport.Reason=0;
  mN976nHandoffMemoryReport.Detail=0;
  return EFI_SUCCESS;
}

EFI_STATUS N976nPrepareHandoffMemory (VOID)
{
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS Address=N976N_BOOTSTRAP_HEAP_END-1;
  if (mHm.Prepared || mHm.Allocation || mHm.Begun) return EFI_ALREADY_STARTED;
  if (EfiGetCurrentTpl()!=TPL_APPLICATION) return EFI_UNSUPPORTED;
  ZeroMem(&mHm,sizeof(mHm));
  ZeroMem((VOID *)&mN976nHandoffMemoryReport,sizeof(mN976nHandoffMemoryReport));
  mN976nHandoffMemoryReport.Magic=N976N_HANDOFF_MEMORY_MAGIC;
  mN976nHandoffMemoryReport.Version=1;
  mN976nHandoffMemoryReport.Size=sizeof(mN976nHandoffMemoryReport);
  Status=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&mHm.Attributes);
  if (EFI_ERROR(Status) || !mHm.Attributes || !mHm.Attributes->GetMemoryAttributes)
    return HmFail(0x680,0,EFI_UNSUPPORTED);
  Status=gBS->AllocatePages(AllocateMaxAddress,EfiBootServicesData,HM_PAGES,&Address);
  if (EFI_ERROR(Status)) return HmFail(0x680,Address,Status);
  mHm.Allocation=Address;
  if (!HmLow(Address,HM_PAGES*HM_PAGE) || !HmAttributes(Address,HM_PAGES*HM_PAGE,EFI_MEMORY_XP))
    return HmFail(0x680,Address,EFI_SECURITY_VIOLATION); /* quarantine */
  for (UINTN Side=0; Side<2; ++Side) {
    UINT64 Guard=Address+(Side ? HM_PAGE+N976N_HANDOFF_MAP_BYTES : 0);
    UINT64 *P=(VOID *)(UINTN)Guard;
    for (UINTN I=0; I<HM_PAGE/sizeof(UINT64); ++I) P[I]=HM_GUARD ^ Guard ^ I;
  }
  mHm.Map=(VOID *)(UINTN)(Address+HM_PAGE);
  mN976nHandoffMemoryReport.WorkspaceBase=Address;
  mN976nHandoffMemoryReport.WorkspacePages=HM_PAGES;
  mN976nHandoffMemoryReport.MapAddress=(UINTN)mHm.Map;
  mN976nHandoffMemoryReport.MapCapacity=N976N_HANDOFF_MAP_BYTES;
  if (!HmCatalog()) return HmFail(0x680,0,EFI_COMPROMISED_DATA);
  mHm.Prepared=TRUE;
  return HmCheck(FALSE);
}

EFI_STATUS N976nCheckHandoffMemory (VOID)
{
  if (!mHm.Prepared || mHm.Begun) return EFI_NOT_READY;
  mHm.Begun=TRUE;
  ++mN976nHandoffMemoryReport.Attempts;
  return HmCheck(TRUE);
}

EFI_STATUS N976nReleaseHandoffMemory (VOID)
{
  if (mHm.Begun || EfiGetCurrentTpl()!=TPL_APPLICATION) return EFI_ACCESS_DENIED;
  if (!mHm.Allocation) return EFI_SUCCESS;
  if (!mHm.Prepared || !HmGuards()) return EFI_SECURITY_VIOLATION;
  EFI_STATUS Status=gBS->FreePages(mHm.Allocation,HM_PAGES);
  if (!EFI_ERROR(Status)) {
    ZeroMem(&mHm,sizeof(mHm));
    mN976nHandoffMemoryReport.Phase=9;
  }
  return Status;
}
