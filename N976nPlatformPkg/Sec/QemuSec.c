/* SPDX-License-Identifier: MIT
 * Synthetic QEMU-only handoff into the real EDK2 DXE Core.
 * This deliberately does not stand in for the N976N DT/reservation/entry checks.
 * All allocations are in one guarded test RAM window; data starts nonexecuting.
 */
#include <PiPei.h>
#include <IndustryStandard/PeImage.h>
#include <Library/ArmLib.h>
#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PrePiLib.h>
#include <Library/PrePiHobListPointerLib.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/SerialPortLib.h>
#include <Library/PcdLib.h>
#include <N976nPlatform.h>

#define SEC_BASE 0x90000000ULL
#define SEC_LIMIT 0x90100000ULL
#define SHIM_BASE 0x90200000ULL
#define REPORT_BASE 0x90201000ULL
#define FV_BASE 0x90400000ULL
#define FV_SIZE 0x00900000ULL
#define HEAP_BASE 0x92001000ULL
#define HEAP_END 0x95FDE000ULL
#define STACK_BASE 0x95FDF000ULL
#define STACK_END 0x95FFF000ULL
#define GUARD 0x5345433432475541ULL
#define PAGE 4096ULL

extern VOID EFIAPI ProcessLibraryConstructorList (VOID);
STATIC ARM_MEMORY_REGION_DESCRIPTOR mRegions[24];
STATIC UINTN mRegionCount;
STATIC volatile UINT64 *CONST mReport = (VOID *)(UINTN)REPORT_BASE;

__attribute__((noinline)) VOID EFIAPI N976nQemuSecStop (UINT64 Error)
{
  mReport[1] = Error;
  DEBUG ((DEBUG_ERROR, "SEC49 SEC STOP error=%Lx\n", Error));
  ArmDisableInterrupts ();
  for (;;) { CpuPause (); }
}

STATIC VOID Need (BOOLEAN Condition, UINT64 Error)
{ if (!Condition) { N976nQemuSecStop (Error); } }

STATIC VOID Region (UINT64 Base, UINT64 Size, ARM_MEMORY_REGION_ATTRIBUTES Attr)
{
  Need (mRegionCount + 1 < ARRAY_SIZE (mRegions) && Size &&
        !((Base | Size) & (PAGE-1)) && Base <= MAX_UINT64-Size, 0x4201);
  mRegions[mRegionCount].PhysicalBase = Base;
  mRegions[mRegionCount].VirtualBase = Base;
  mRegions[mRegionCount].Length = Size;
  mRegions[mRegionCount++].Attributes = Attr;
}

STATIC VOID SystemRam (UINT64 Base, UINT64 Size)
{
  BuildResourceDescriptorHob (EFI_RESOURCE_SYSTEM_MEMORY,
    EFI_RESOURCE_ATTRIBUTE_PRESENT | EFI_RESOURCE_ATTRIBUTE_INITIALIZED |
    EFI_RESOURCE_ATTRIBUTE_TESTED | EFI_RESOURCE_ATTRIBUTE_UNCACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_COMBINEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_THROUGH_CACHEABLE |
    EFI_RESOURCE_ATTRIBUTE_WRITE_BACK_CACHEABLE, Base, Size);
}

STATIC VOID MapSec (VOID)
{
  EFI_IMAGE_DOS_HEADER *Dos = (VOID *)(UINTN)SEC_BASE;
  EFI_IMAGE_NT_HEADERS64 *Pe;
  EFI_IMAGE_SECTION_HEADER *Section;
  Need (Dos->e_magic == EFI_IMAGE_DOS_SIGNATURE && Dos->e_lfanew >= sizeof (*Dos) &&
        Dos->e_lfanew <= PAGE-sizeof (*Pe), 0x4202);
  Pe = (VOID *)(UINTN)(SEC_BASE + Dos->e_lfanew);
  Need (Pe->Signature == EFI_IMAGE_NT_SIGNATURE &&
        Pe->FileHeader.Machine == IMAGE_FILE_MACHINE_ARM64 &&
        Pe->OptionalHeader.Magic == EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC &&
        Pe->OptionalHeader.ImageBase == SEC_BASE &&
        Pe->OptionalHeader.SizeOfImage <= SEC_LIMIT-SEC_BASE &&
        Pe->OptionalHeader.SizeOfImage >= PAGE &&
        Pe->OptionalHeader.SectionAlignment == PAGE &&
        Pe->FileHeader.SizeOfOptionalHeader == sizeof (Pe->OptionalHeader) &&
        Pe->FileHeader.NumberOfSections > 0 && Pe->FileHeader.NumberOfSections <= 12,
        0x4203);
  Section = (VOID *)((UINT8 *)&Pe->OptionalHeader + Pe->FileHeader.SizeOfOptionalHeader);
  Need ((UINTN)(Section + Pe->FileHeader.NumberOfSections) <= SEC_BASE+PAGE, 0x4204);
  Region (SEC_BASE, SEC_LIMIT-SEC_BASE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  UINT64 LastEnd = PAGE;
  BOOLEAN EntryFound = FALSE;
  for (UINTN I=0; I<Pe->FileHeader.NumberOfSections; I++) {
    UINT64 Size = ALIGN_VALUE (MAX (Section[I].Misc.VirtualSize, Section[I].SizeOfRawData), PAGE);
    UINT64 Start = Section[I].VirtualAddress;
    Need (Size && Start >= LastEnd && !(Start & (PAGE-1)) &&
          Start <= Pe->OptionalHeader.SizeOfImage && Size <= Pe->OptionalHeader.SizeOfImage-Start,
          0x4205);
    LastEnd = Start + Size;
    if (Section[I].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) {
      Need (!(Section[I].Characteristics & EFI_IMAGE_SCN_MEM_WRITE), 0x4206);
      Region (SEC_BASE+Start, Size, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_RO);
      if (Pe->OptionalHeader.AddressOfEntryPoint >= Start &&
          Pe->OptionalHeader.AddressOfEntryPoint-Start < Section[I].Misc.VirtualSize) {
        EntryFound = TRUE;
      }
    }
  }
  Need (EntryFound, 0x4207);
  mReport[8] = Pe->OptionalHeader.SizeOfImage;
}

VOID EFIAPI _ModuleEntryPoint (VOID)
{
  EFI_HOB_HANDOFF_INFO_TABLE *Hob;
  EFI_PEI_FV_HANDLE Volume;
  EFI_PEI_FILE_HANDLE File;
  EFI_FV_FILE_INFO FileInfo;
  VOID *Pe, *Tables;
  UINTN TableBytes;
  EFI_PHYSICAL_ADDRESS CoreBase;
  UINT64 CoreSize, CoreEntry;
  EFI_STATUS Status;
  N976N_PLATFORM_HANDOFF Handoff;
  mReport[0] = 0x5345433432535444ULL;
  mReport[1] = 0;
  mReport[2] = 1;
  /* Build profile is also checked by the BDS self-check. A phone never enters
     this synthetic loader: no Android wrapper or flash package is generated. */
  Need (ArmReadCurrentEL () == 4 && !ArmMmuEnabled () &&
        FixedPcdGet32 (PcdN976nPlatformProfile) == N976N_PLATFORM_PROFILE_QEMU, 0x4210);
  Hob = HobConstructor ((VOID *)(UINTN)HEAP_BASE, HEAP_END-HEAP_BASE,
                        (VOID *)(UINTN)HEAP_BASE, (VOID *)(UINTN)HEAP_END);
  Need (Hob == (VOID *)(UINTN)HEAP_BASE && !EFI_ERROR (PrePeiSetHobList (Hob)), 0x4211);
  SystemRam (HEAP_BASE, STACK_END-HEAP_BASE);
  SystemRam (SEC_BASE, SEC_LIMIT-SEC_BASE);
  SystemRam (SHIM_BASE, 2*PAGE);
  SystemRam (FV_BASE, FV_SIZE);
  BuildMemoryAllocationHob (SEC_BASE, SEC_LIMIT-SEC_BASE, EfiReservedMemoryType);
  BuildMemoryAllocationHob (SHIM_BASE, PAGE, EfiBootServicesCode);
  BuildMemoryAllocationHob (REPORT_BASE, PAGE, EfiBootServicesData);
  /* Immutable source: the generic data NX pass must not remove its RO bit. */
  BuildMemoryAllocationHob (FV_BASE, FV_SIZE, EfiReservedMemoryType);
  BuildMemoryAllocationHob (HEAP_END, PAGE, EfiReservedMemoryType);
  BuildStackHob (STACK_BASE, STACK_END-STACK_BASE);
  BuildCpuHob (ArmGetPhysicalAddressBits (), 16);
  BuildFvHob (FV_BASE, FV_SIZE);
  SetBootMode (BOOT_WITH_FULL_CONFIGURATION);
  ZeroMem (&Handoff, sizeof (Handoff));
  Handoff.Magic = N976N_PLATFORM_HANDOFF_MAGIC;
  Handoff.Version = N976N_PLATFORM_ABI_VERSION;
  Handoff.Size = sizeof (Handoff);
  Handoff.Profile = 1;
  Handoff.FirmwareBase = FV_BASE; Handoff.FirmwareSize = FV_SIZE;
  Handoff.HeapBase = HEAP_BASE; Handoff.HeapSize = HEAP_END-HEAP_BASE;
  Handoff.StackBase = STACK_BASE; Handoff.StackSize = STACK_END-STACK_BASE;
  BuildGuidDataHob (&gN976nPlatformHandoffGuid, &Handoff, sizeof (Handoff));
  ProcessLibraryConstructorList ();
  mReport[2] = 2;
  MapSec ();
  Region (SHIM_BASE, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_RO);
  Region (REPORT_BASE, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (HEAP_BASE, HEAP_END-HEAP_BASE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (STACK_BASE, STACK_END-STACK_BASE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (FV_BASE, FV_SIZE, ARM_MEMORY_REGION_ATTRIBUTE_WRITE_BACK_XP);
  Region (0x08000000, 0x20000, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  Region (0x09000000, PAGE, ARM_MEMORY_REGION_ATTRIBUTE_DEVICE);
  Need (!EFI_ERROR (ArmConfigureMmu (mRegions, &Tables, &TableBytes)), 0x4212);
  Need (!EFI_ERROR (ArmSetMemoryAttributes (FV_BASE, FV_SIZE,
              EFI_MEMORY_RO | EFI_MEMORY_XP, EFI_MEMORY_RO | EFI_MEMORY_XP)), 0x4213);
  mReport[3] = (UINTN)Tables; mReport[4] = TableBytes;
  mReport[2] = 3;
  SerialPortInitialize ();
  SerialPortWrite ((UINT8 *)"SEC49 synthetic SEC: standard DXE dispatch\r\n", 43);
  Need (!EFI_ERROR (N976nBootstrapPolicyInitialize ()), 0x4214);
  Need (!EFI_ERROR (FfsFindNextVolume (0, &Volume)), 0x4215);
  File = NULL;
  Need (!EFI_ERROR (FfsFindNextFile (EFI_FV_FILETYPE_DXE_CORE, Volume, &File)), 0x4216);
  Need (!EFI_ERROR (FfsFindSectionDataWithHook (EFI_SECTION_PE32, NULL, File, &Pe, NULL)), 0x4217);
  Need (!EFI_ERROR (FfsGetFileInfo (File, &FileInfo)), 0x4218);
  Status = LoadPeCoffImage (Pe, &CoreBase, &CoreSize, &CoreEntry);
  Need (!EFI_ERROR (Status), 0x4219);
  BuildModuleHob (&FileInfo.FileName, CoreBase, ALIGN_VALUE (CoreSize, PAGE), CoreEntry);
  /* Retain the original HOB data as well as the Core's later copy. */
  BuildMemoryAllocationHob (HEAP_BASE,
    ALIGN_VALUE (Hob->EfiFreeMemoryBottom-HEAP_BASE + sizeof (EFI_HOB_MEMORY_ALLOCATION), PAGE),
    EfiBootServicesData);
  mReport[5] = CoreBase; mReport[6] = CoreSize; mReport[7] = CoreEntry;
  mReport[2] = 4;
  ((VOID (EFIAPI *)(VOID *))(UINTN)CoreEntry)(Hob);
  N976nQemuSecStop (0x421A);
}
