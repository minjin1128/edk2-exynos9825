/* SPDX-License-Identifier: MIT
 * N976N adapter into the NTDEV-style standard DXE/BDS platform. The retained
 * runtime-DT ownership gate is N976N-specific; SEC42's Core and image admission
 * are reused. No Windows call-sequence diagnostics or storage are introduced.
 */
#include <PiPei.h>
#include <IndustryStandard/PeImage.h>
#include <Library/ArmLib.h>
#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PrePiLib.h>
#include <Library/PrePiHobListPointerLib.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include <N976nPlatform.h>
#include <N976nPhone.h>
#include <N976nFramebuffer.h>
#include <N976nUfsAdmission.h>
#include <N976nHighRamAdmission.h>
#include <N976nPowerOff.h>
#include <N976nAcpiAdmission.h>
#include <LegacyMemory/MemoryPlan.h>

#define PAGE 4096ULL
#define WINDOW_BASE 0x92000000ULL
#define WINDOW_END  0x96000000ULL
#define HEAP_BASE   N976N_BOOTSTRAP_HEAP_BASE
#define HEAP_END    N976N_BOOTSTRAP_HEAP_END
extern VOID EFIAPI ProcessLibraryConstructorList (VOID);
STATIC N976N_PHONE_INPUT mInput;
STATIC MEMORY_PLAN mPlan;
STATIC SEC_PROBE_HANDOFF mLegacy;
STATIC N976N_PLATFORM_FB_REPORT mDisplay;
STATIC N976N_UFS_ADMISSION mUfsAdmission;
STATIC N976N_HIGH_RAM_ADMISSION mHighRamAdmission;
STATIC N976N_POWER_ADMISSION mPowerAdmission;
STATIC N976N_ACPI_ADMISSION mAcpiAdmission;
STATIC ARM_MEMORY_REGION_DESCRIPTOR mRegions[32];
STATIC UINTN mRegionCount;
STATIC volatile UINT64 *mReport;
STATIC N976N_PHONE_SCREEN mScreen;
STATIC EFI_IMAGE_NT_HEADERS64 *mPe;
STATIC EFI_IMAGE_SECTION_HEADER *mSections;
STATIC BOOLEAN mSerialReady;

STATIC BOOLEAN Inside (UINT64 A, UINT64 N, UINT64 B, UINT64 E)
{ return N && B <= E && A >= B && A < E && N <= E - A; }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return N && M && A < B + M && B < A + N; }
STATIC VOID Event (UINT64 E, UINT64 V) { if (mScreen) mScreen (E, V); }

__attribute__((noinline, noreturn)) VOID EFIAPI N976nPhoneSecStop (UINT64 Error)
{
  if (mReport) mReport[1] = Error;
  Event (2, Error);
  if (mSerialReady) DEBUG ((DEBUG_ERROR, "SEC49 PHONE SEC STOP error=%Lx\n", Error));
  ArmDisableInterrupts ();
  for (;;) CpuPause ();
}
STATIC VOID Need (BOOLEAN Good, UINT64 Error)
{ if (!Good) N976nPhoneSecStop (Error); }
STATIC VOID Stage (UINT64 Value)
{ mReport[2] = Value; Event (1, Value); }
STATIC VOID Region (UINT64 Base, UINT64 Size, ARM_MEMORY_REGION_ATTRIBUTES Attributes)
{
  Need (mRegionCount + 1 < ARRAY_SIZE (mRegions) && Size &&
        !((Base | Size) & (PAGE - 1)) && Base <= MAX_UINT64 - Size, 0x4301);
  mRegions[mRegionCount].PhysicalBase = Base;
  mRegions[mRegionCount].VirtualBase = Base;
  mRegions[mRegionCount].Length = Size;
  mRegions[mRegionCount++].Attributes = Attributes;
}

STATIC VOID AdmitAcpi (VOID)
{
  UINT64 Mpidr, Frequency;
  UINT32 TargetMask=0, Typer;
  __asm__ volatile ("mrs %0, mpidr_el1" : "=r" (Mpidr));
  __asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (Frequency));
  if (!N976nAdmitAcpi ((CONST VOID *)(UINTN)mInput.Dtb, mPlan.Info.DtbSize,
        FixedPcdGet32 (PcdN976nPlatformProfile), Mpidr, Frequency, &mAcpiAdmission)) return;
  /* MMU/caches remain off at this SEC phase. The exact profile controller
   * range was admitted above. These are read-only identity registers, not
   * interrupt acknowledge/EOI, reset, routing or CPU-start operations. */
  Typer = MmioRead32 ((UINTN)mAcpiAdmission.GicBase[0] + 4);
  for (UINTN Index=0; Index<8; Index++)
    TargetMask |= MmioRead32 ((UINTN)mAcpiAdmission.GicBase[0] + 0x800 + Index*4);
  TargetMask |= TargetMask >> 16;
  TargetMask |= TargetMask >> 8;
  N976nCompleteAcpiAdmission (&mAcpiAdmission, Typer, TargetMask & 255U);
}

STATIC VOID ValidateInput (CONST N976N_PHONE_INPUT *Input)
{
  UINT64 El, Sctlr, Daif, Stack;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, daif" : "=r" (Daif));
  __asm__ volatile ("mov %0, sp" : "=r" (Stack));
  Need (El == 4 && !(Sctlr & (BIT0 | BIT2 | BIT12 | BIT25)) &&
        (Daif & 0x3C0) == 0x3C0 && !((UINTN)Input & 7) &&
        Inside ((UINTN)Input, sizeof (*Input), 0x80002000, 0x87000000), 0x4310);
  CopyMem (&mInput, Input, sizeof (mInput));
  Need (mInput.Magic == N976N_PHONE_INPUT_MAGIC && mInput.Size == sizeof (mInput) &&
        mInput.ImageBase >= 0x80002000 && mInput.ImageEnd <= 0x87000000 &&
        mInput.ImageBase < mInput.WrapperCodeEnd &&
        mInput.WrapperCodeEnd == mInput.WritableBase &&
        mInput.WritableBase < mInput.WritableEnd && mInput.WritableEnd <= mInput.SecBase &&
        mInput.SecSize && mInput.SecSize <= 0x100000 &&
        Inside (mInput.SecBase, mInput.SecSize, mInput.WritableEnd, mInput.FvBase) &&
        mInput.FvSize == N976N_BOOTSTRAP_FV_BYTES &&
        Inside (mInput.FvBase, mInput.FvSize, mInput.SecBase + mInput.SecSize, mInput.ImageEnd) &&
        mInput.FvBase + mInput.FvSize == mInput.ImageEnd &&
        !((mInput.ImageBase | mInput.ImageEnd | mInput.WrapperCodeEnd | mInput.WritableBase |
           mInput.WritableEnd | mInput.SecBase | mInput.SecSize | mInput.FvBase |
           mInput.StackBase | mInput.StackSize) & (PAGE - 1)) &&
        mInput.StackSize == 0x10000 &&
        Inside (mInput.StackBase, mInput.StackSize, mInput.WritableBase, mInput.WritableEnd) &&
        Inside (Stack, 16, mInput.StackBase, mInput.StackBase + mInput.StackSize) &&
        Inside ((UINTN)Input, sizeof (*Input), mInput.WritableBase, mInput.WritableEnd) &&
        Inside (mInput.ReportAddress, N976N_PHONE_REPORT_BYTES, mInput.WritableBase, mInput.WritableEnd) &&
        !(mInput.ReportAddress & 7) && !(mInput.Screen & 3) &&
        Inside (mInput.Screen, 4, mInput.ImageBase, mInput.WrapperCodeEnd) &&
        !Overlap (mInput.ReportAddress, N976N_PHONE_REPORT_BYTES, (UINTN)Input, sizeof (*Input)) &&
        !Overlap (mInput.ReportAddress, N976N_PHONE_REPORT_BYTES, mInput.StackBase, mInput.StackSize) &&
        Inside ((UINTN)&ValidateInput, 4, mInput.SecBase, mInput.SecBase + mInput.SecSize), 0x4311);
  mReport = (VOID *)(UINTN)mInput.ReportAddress;
  mScreen = (N976N_PHONE_SCREEN)(UINTN)mInput.Screen;
  mReport[0] = N976N_PHONE_REPORT_MAGIC; mReport[1] = 0;
  Stage (1);
}

STATIC BOOLEAN SecData (UINT64 Rva, UINT64 Size, BOOLEAN Writable)
{
  for (UINTN I=0; I<mPe->FileHeader.NumberOfSections; I++) {
    EFI_IMAGE_SECTION_HEADER *S = &mSections[I];
    if (!(S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) &&
        (!Writable || (S->Characteristics & EFI_IMAGE_SCN_MEM_WRITE)) &&
        Inside (Rva, Size, S->VirtualAddress, S->VirtualAddress + S->Misc.VirtualSize)) return TRUE;
  }
  return FALSE;
}

STATIC VOID ValidateSec (VOID)
{
  EFI_IMAGE_DOS_HEADER *Dos = (VOID *)(UINTN)mInput.SecBase;
  Need (Dos->e_magic == EFI_IMAGE_DOS_SIGNATURE && Dos->e_lfanew >= sizeof (*Dos) &&
        Dos->e_lfanew <= PAGE-sizeof (*mPe), 0x4312);
  mPe = (VOID *)(UINTN)(mInput.SecBase + Dos->e_lfanew);
  Need (mPe->Signature == EFI_IMAGE_NT_SIGNATURE && mPe->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 &&
        mPe->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        mPe->OptionalHeader.ImageBase == mInput.SecBase &&
        mPe->OptionalHeader.SizeOfImage == mInput.SecSize &&
        mPe->OptionalHeader.SectionAlignment == PAGE && mPe->OptionalHeader.FileAlignment == PAGE &&
        mPe->OptionalHeader.SizeOfHeaders == PAGE &&
        mPe->FileHeader.SizeOfOptionalHeader == sizeof (mPe->OptionalHeader) &&
        mPe->FileHeader.NumberOfSections > 0 && mPe->FileHeader.NumberOfSections <= 12 &&
        mPe->OptionalHeader.NumberOfRvaAndSizes > EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC &&
        mPe->OptionalHeader.NumberOfRvaAndSizes <= EFI_IMAGE_NUMBER_OF_DIRECTORY_ENTRIES, 0x4313);
  mSections = (VOID *)((UINT8 *)&mPe->OptionalHeader + sizeof (mPe->OptionalHeader));
  Need ((UINTN)(mSections + mPe->FileHeader.NumberOfSections) <= mInput.SecBase + PAGE, 0x4314);
  UINT64 Last = PAGE; BOOLEAN Entry = FALSE;
  for (UINTN I=0; I<mPe->FileHeader.NumberOfSections; I++) {
    EFI_IMAGE_SECTION_HEADER *S = &mSections[I];
    UINT64 Size = ALIGN_VALUE (MAX (S->Misc.VirtualSize, S->SizeOfRawData), PAGE);
    Need (Size && S->Misc.VirtualSize && !(S->VirtualAddress & (PAGE-1)) &&
          Inside (S->VirtualAddress, Size, Last, mInput.SecSize) &&
          (S->Characteristics & EFI_IMAGE_SCN_MEM_READ) &&
          !((S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) && (S->Characteristics & EFI_IMAGE_SCN_MEM_WRITE)), 0x4315);
    Last = S->VirtualAddress + Size;
    if ((S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) &&
        Inside (mPe->OptionalHeader.AddressOfEntryPoint, 4, S->VirtualAddress,
                S->VirtualAddress + S->Misc.VirtualSize)) Entry = TRUE;
  }
  Need (Entry, 0x4316);
  EFI_IMAGE_DATA_DIRECTORY *Rel = &mPe->OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_BASERELOC];
  Need (Rel->Size && SecData (Rel->VirtualAddress, Rel->Size, FALSE), 0x4317);
  UINT64 Offset = 0, Previous = 0; BOOLEAN Seen = FALSE;
  while (Offset < Rel->Size) {
    Need (Rel->Size - Offset >= 8, 0x4317);
    EFI_IMAGE_BASE_RELOCATION *Block = (VOID *)(UINTN)(mInput.SecBase + Rel->VirtualAddress + Offset);
    Need (!(Block->VirtualAddress & (PAGE-1)) && Block->SizeOfBlock >= 8 &&
          !(Block->SizeOfBlock & 3) && Block->SizeOfBlock <= Rel->Size - Offset, 0x4317);
    UINT16 *Fixups = (VOID *)(Block + 1);
    for (UINTN I=0; I<(Block->SizeOfBlock-8)/2; I++) {
      UINT64 Kind = Fixups[I] >> 12, Rva = (UINT64)Block->VirtualAddress + (Fixups[I] & 0xFFF);
      if (!Kind) continue;
      Need (Kind == EFI_IMAGE_REL_BASED_DIR64 && !(Rva & 7) &&
            (!Seen || Rva >= Previous+8) && SecData (Rva, 8, FALSE) &&
            !Overlap (Rva, 8, Rel->VirtualAddress, Rel->Size), 0x4318);
      UINT64 Value = *(CONST UINT64 *)(UINTN)(mInput.SecBase + Rva);
      Need (Inside (Value, 1, mInput.SecBase, mInput.SecBase + mInput.SecSize), 0x4318);
      Previous = Rva; Seen = TRUE;
    }
    Offset += Block->SizeOfBlock;
  }
  Need (Seen && Offset == Rel->Size, 0x4318);
  mReport[8] = mInput.SecSize;
}

/* Same owned-range IVAC contract as SEC29 FIX1/FIX5, before any cached access
 * or initialization in the admitted external window. Never global set/way. */
STATIC VOID InvalidateExternal (VOID)
{
  UINT64 Sctlr, Ctr;
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, ctr_el0" : "=r" (Ctr));
  UINT64 Line = 4ULL << ((Ctr >> 16) & 15);
  Need (!(Sctlr & (BIT0 | BIT2 | BIT12)) && Line >= 16 && Line <= 2048, 0x431C);
  __asm__ volatile ("dsb sy" ::: "memory");
  for (UINT64 P=WINDOW_BASE; P<WINDOW_END; P+=Line) __asm__ volatile ("dc ivac, %0" :: "r" (P) : "memory");
  __asm__ volatile ("dsb sy\n\tisb" ::: "memory");
}
STATIC VOID Guard (UINT64 Base)
{
  volatile UINT64 *P = (VOID *)(UINTN)Base;
  for (UINTN I=0; I<PAGE/8; I++) P[I] = N976N_PHONE_GUARD ^ Base;
}
STATIC VOID Resource (EFI_RESOURCE_TYPE Type, UINT64 Base, UINT64 Size)
{
  BuildResourceDescriptorHob (Type, EFI_RESOURCE_ATTRIBUTE_PRESENT |
    EFI_RESOURCE_ATTRIBUTE_INITIALIZED | EFI_RESOURCE_ATTRIBUTE_TESTED |
    EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE | EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE | EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE,
    Base, Size);
}
STATIC VOID Allocation (UINT64 Base, UINT64 End, EFI_MEMORY_TYPE Type)
{ if (End > Base) BuildMemoryAllocationHob (Base, End-Base, Type); }

/* Read-only observation boundary for the actual phone profile. Stopping here
 * proves admission and MMU construction, not physical GIC/DXE execution. */
__attribute__((noinline)) VOID EFIAPI N976nPhoneEnterCore (VOID *Hob, UINT64 Entry)
{ ((VOID (EFIAPI *)(VOID *))(UINTN)Entry)(Hob); }

VOID EFIAPI _ModuleEntryPoint (CONST N976N_PHONE_INPUT *Input)
{
  EFI_HOB_HANDOFF_INFO_TABLE *Hob; N976N_PLATFORM_HANDOFF Handoff;
  VOID *Tables, *Pe; UINTN TableBytes; EFI_PEI_FV_HANDLE Volume; EFI_PEI_FILE_HANDLE File;
  EFI_FV_FILE_INFO FileInfo; EFI_PHYSICAL_ADDRESS CoreBase; UINT64 CoreSize, CoreEntry;
  ValidateInput (Input); ValidateSec ();
  ZeroMem (&mLegacy, sizeof (mLegacy));
  mLegacy.ImageBase = mInput.ImageBase; mLegacy.ImageEnd = mInput.ImageEnd; mLegacy.Dtb = mInput.Dtb;
  mLegacy.BootInfo.ExternalBase = WINDOW_BASE; mLegacy.BootInfo.ExternalSize = WINDOW_END-WINDOW_BASE;
  mReport[11] = ParseRuntimeDtb (&mLegacy, &mPlan);
  Need (mReport[11] == 0, 0x4319);
  mReport[12] = BuildMemoryPlan (&mLegacy, &mPlan);
  Need (mReport[12] == 0, 0x4319);
  UINT64 PolicyChecks = 0;
  Need (ValidateExternalMemoryPolicy (&mLegacy, &mPlan, &PolicyChecks) && PolicyChecks == 0xFF, 0x431A);
  mReport[9] = PolicyChecks; Event (5, PolicyChecks); Stage (2);
  /* The existing DT parser has admitted this entire source span. A missing or
     different UFS node disables only the probe; no controller address is used. */
  N976nAdmitUfs ((CONST VOID *)(UINTN)mInput.Dtb, mPlan.Info.DtbSize, &mUfsAdmission);
  /* A separate software candidate gate, never a SystemMemory grant. The
     bounded BDS consumer independently checks CPU/PTE state before access. */
  N976nAdmitHighRam (&mLegacy, &mPlan, &mHighRamAdmission);
  N976nAdmitPower ((CONST VOID *)(UINTN)mInput.Dtb, mPlan.Info.DtbSize, &mPowerAdmission);
  AdmitAcpi ();
  EFI_STATUS DisplayStatus = N976nValidateDisplay (&mDisplay);
  mReport[13] = mDisplay.Raw[2];
  Need (!EFI_ERROR (DisplayStatus) && mDisplay.Raw[0] == 0xFF &&
        mDisplay.Raw[1] == 0 && mDisplay.Raw[2] == 0 && N976nFbInfoValid (&mDisplay.Info), 0x431B);
  mReport[10] = mDisplay.Raw[0]; Event (6, mDisplay.Raw[0]);
  InvalidateExternal (); Guard (WINDOW_BASE); Guard (HEAP_END);
  Hob = HobConstructor ((VOID *)(UINTN)HEAP_BASE, HEAP_END-HEAP_BASE,
                        (VOID *)(UINTN)HEAP_BASE, (VOID *)(UINTN)HEAP_END);
  Need (Hob == (VOID *)(UINTN)HEAP_BASE && !EFI_ERROR (PrePeiSetHobList (Hob)), 0x431D);
  Resource (EFI_RESOURCE_SYSTEM_MEMORY, HEAP_BASE, HEAP_END-HEAP_BASE);
  Resource (EFI_RESOURCE_MEMORY_RESERVED, WINDOW_BASE, PAGE);
  Resource (EFI_RESOURCE_MEMORY_RESERVED, HEAP_END, WINDOW_END-HEAP_END);
  Resource (EFI_RESOURCE_SYSTEM_MEMORY, mInput.ImageBase, mInput.ImageEnd-mInput.ImageBase);
  Resource (EFI_RESOURCE_MEMORY_RESERVED, FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE);
  Allocation (mInput.ImageBase, mInput.WrapperCodeEnd, EfiBootServicesCode);
  Allocation (mInput.WritableBase, mInput.StackBase, EfiBootServicesData);
  BuildStackHob (mInput.StackBase, mInput.StackSize);
  Allocation (mInput.StackBase+mInput.StackSize, mInput.WritableEnd, EfiBootServicesData);
  Allocation (mInput.WritableEnd, mInput.ImageEnd, EfiReservedMemoryType);
  BuildCpuHob (ArmGetPhysicalAddressBits (), 16); BuildFvHob (mInput.FvBase, mInput.FvSize);
  SetBootMode (BOOT_WITH_FULL_CONFIGURATION);
  ZeroMem (&Handoff, sizeof (Handoff));
  Handoff.Magic = N976N_PLATFORM_HANDOFF_MAGIC; Handoff.Version = N976N_PLATFORM_ABI_VERSION;
  Handoff.Size = sizeof (Handoff); Handoff.Profile = FixedPcdGet32 (PcdN976nPlatformProfile);
  Handoff.FirmwareBase = mInput.FvBase; Handoff.FirmwareSize = mInput.FvSize;
  Handoff.HeapBase = HEAP_BASE; Handoff.HeapSize = HEAP_END-HEAP_BASE;
  Handoff.StackBase = mInput.StackBase; Handoff.StackSize = mInput.StackSize;
  Handoff.ImageBase = mInput.ImageBase; Handoff.ImageSize = mInput.ImageEnd-mInput.ImageBase;
  Handoff.Screen = mInput.Screen; Handoff.ReportAddress = mInput.ReportAddress;
  Need (BuildGuidDataHob (&gN976nPlatformHandoffGuid, &Handoff, sizeof (Handoff)) != NULL &&
        BuildGuidDataHob (&gN976nFramebufferHobGuid, &mDisplay, sizeof (mDisplay)) != NULL &&
        BuildGuidDataHob (&gN976nUfsAdmissionGuid, &mUfsAdmission, sizeof (mUfsAdmission)) != NULL &&
        BuildGuidDataHob (&gN976nHighRamAdmissionGuid, &mHighRamAdmission, sizeof (mHighRamAdmission)) != NULL &&
        BuildGuidDataHob (&gN976nPowerAdmissionGuid, &mPowerAdmission, sizeof (mPowerAdmission)) != NULL &&
        BuildGuidDataHob (&gN976nAcpiAdmissionGuid, &mAcpiAdmission, sizeof (mAcpiAdmission)) != NULL, 0x431E);
  ProcessLibraryConstructorList ();
  Region (mInput.ImageBase, mInput.ImageEnd-mInput.ImageBase, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (mInput.ImageBase, mInput.WrapperCodeEnd-mInput.ImageBase, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_RO);
  for (UINTN I=0; I<mPe->FileHeader.NumberOfSections; I++) {
    EFI_IMAGE_SECTION_HEADER *S = &mSections[I];
    if (S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE)
      Region (mInput.SecBase+S->VirtualAddress, ALIGN_VALUE (MAX (S->Misc.VirtualSize, S->SizeOfRawData), PAGE), ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_RO);
  }
  Region (HEAP_BASE, HEAP_END-HEAP_BASE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  Region (0x19030000, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  if (mUfsAdmission.Admitted) {
    /* Exact DT-owned controller pages only, never a peripheral-wide mapping.
       QEMU may map these addresses for the page audit but never accesses them. */
    Region (mUfsAdmission.Hci, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
    Region (mUfsAdmission.Vendor & ~(PAGE-1), PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
    Region (mUfsAdmission.Coherency & ~(PAGE-1), PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  }
  if (mPowerAdmission.Admitted && Handoff.Profile == N976N_PLATFORM_PROFILE_PHONE) {
    /* Three exact DT-admitted Device-XN pages, no broad PMU/SRAM mapping. */
    Region (N976N_POWER_PMU, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
    Region (N976N_POWER_PMU + 0x8000, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
    Region (N976N_POWER_GPIO, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  }
  if (Handoff.Profile == N976N_PLATFORM_PROFILE_QEMU) {
    Region (0x08000000, 0x20000, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
    Region (0x09000000, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  } else {
    Need (Handoff.Profile == N976N_PLATFORM_PROFILE_PHONE, 0x431F);
    Region (0x10101000, 0x2000, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  }
  Stage (3);
  Need (!EFI_ERROR (ArmConfigureMmu (mRegions, &Tables, &TableBytes)), 0x4320);
  mReport[3] = (UINTN)Tables; mReport[4] = TableBytes;
  Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.SecBase, PAGE, EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
  for (UINTN I=0; I<mPe->FileHeader.NumberOfSections; I++) {
    EFI_IMAGE_SECTION_HEADER *S = &mSections[I];
    if (!(S->Characteristics & (EFI_IMAGE_SCN_MEM_WRITE | EFI_IMAGE_SCN_MEM_EXECUTE)))
      Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.SecBase+S->VirtualAddress,
        ALIGN_VALUE (MAX (S->Misc.VirtualSize, S->SizeOfRawData), PAGE), EFI_MEMORY_RO | EFI_MEMORY_XP,
        EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
  }
  UINT64 LastEnd = PAGE;
  for (UINTN I=0; I<mPe->FileHeader.NumberOfSections; I++) {
    EFI_IMAGE_SECTION_HEADER *S = &mSections[I];
    if (S->VirtualAddress > LastEnd)
      Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.SecBase+LastEnd, S->VirtualAddress-LastEnd,
        EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
    LastEnd = S->VirtualAddress + ALIGN_VALUE (MAX (S->Misc.VirtualSize, S->SizeOfRawData), PAGE);
  }
  if (mInput.FvBase > mInput.SecBase+LastEnd)
    Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.SecBase+LastEnd, mInput.FvBase-mInput.SecBase-LastEnd,
      EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
  if (mInput.SecBase > mInput.WritableEnd)
    Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.WritableEnd, mInput.SecBase-mInput.WritableEnd,
      EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
  Need (!EFI_ERROR (ArmSetMemoryAttributes (mInput.FvBase, mInput.FvSize,
    EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4321);
  UINT64 Sctlr; __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr)); Event (7, Sctlr);
  SerialPortInitialize ();
  mSerialReady = TRUE;
  DEBUG ((DEBUG_ERROR, "SEC49 PHONE SEC: standard DXE dispatch profile=%u\n", Handoff.Profile));
  Need (!EFI_ERROR (N976nBootstrapPolicyInitialize ()), 0x4322);
  Need (!EFI_ERROR (FfsFindNextVolume (0, &Volume)), 0x4323); File = NULL;
  Need (!EFI_ERROR (FfsFindNextFile (EFI_FV_FILETYPE_DXE_CORE, Volume, &File)), 0x4324);
  Need (!EFI_ERROR (FfsFindSectionDataWithHook (EFI_SECTION_PE32, NULL, File, &Pe, NULL)), 0x4325);
  Need (!EFI_ERROR (FfsGetFileInfo (File, &FileInfo)), 0x4326);
  Need (!EFI_ERROR (LoadPeCoffImage (Pe, &CoreBase, &CoreSize, &CoreEntry)), 0x4327);
  BuildModuleHob (&FileInfo.FileName, CoreBase, ALIGN_VALUE (CoreSize, PAGE), CoreEntry);
  BuildMemoryAllocationHob (HEAP_BASE,
    ALIGN_VALUE (Hob->EfiFreeMemoryBottom-HEAP_BASE+sizeof (EFI_HOB_MEMORY_ALLOCATION), PAGE), EfiBootServicesData);
  mReport[5] = CoreBase; mReport[6] = CoreSize; mReport[7] = CoreEntry; Stage (4);
  N976nPhoneEnterCore (Hob, CoreEntry);
  N976nPhoneSecStop (0x4328);
}
