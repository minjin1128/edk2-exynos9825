/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC56: NTDEV/upstream SourceBuffer LoadImage, with an exact owned source and
 * standard filesystem DevicePath. Native StartImage uses the existing bounded
 * observation boundary; no loader hook or policy bypass.
 * Verified FAT chunks are copied here; this range is never a DMA destination.
 */
#include <N976nUfsImage.h>
#include <N976nBootMedia.h>
#include <N976nWindowsBoot.h>
#include <N976nHighRam.h>
#include <N976nUfs.h>
#include <IndustryStandard/PeImage.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/SimpleFileSystem.h>

#define IMAGE_PAGE 4096U
#define IMAGE_CHUNK 16384U
#define IMAGE_PATH_LIMIT 1024U
#define IMAGE_ATTRIBUTES (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)

volatile N976N_UFS_IMAGE_REPORT mN976nUfsImageReport;
STATIC CONST N976N_PLATFORM_HANDOFF *mImageHandoff;
STATIC CONST UINT8 *mImageExpected;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mImageMemory;
STATIC EFI_PHYSICAL_ADDRESS mImageAllocation;
STATIC UINTN mImagePages, mImageBytes;
STATIC UINT8 *mImageSource;
STATIC EFI_HANDLE mImageChild;
STATIC BOOLEAN mImageEntered, mImageScope, mImageFailed, mImageSealed;
STATIC BOOLEAN mImageLoadAttempted, mImageQuarantined;

__attribute__((noinline)) VOID EFIAPI N976nUfsImageLoadedCheckpoint (VOID) {
  MemoryFence ();
}

__attribute__((noinline)) VOID N976nHighRamWindowsReadyCheckpoint (VOID) {
  MemoryFence (); __asm__ volatile ("nop" ::: "memory");
}

STATIC EFI_STATUS ImageFail (EFI_STATUS Status, UINT64 Reason) {
  if (!mImageFailed) {
    mImageFailed = TRUE;
    mN976nUfsImageReport.Status = EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
    mN976nUfsImageReport.Reason = Reason;
  }
  mN976nUfsImageReport.Phase = 0xE;
  return mN976nUfsImageReport.Status;
}
STATIC BOOLEAN ImageSpan (UINT64 Base, UINT64 Bytes, UINT64 Begin, UINT64 Length) {
  return Bytes != 0 && Length <= MAX_UINT64 - Begin && Base >= Begin &&
    Base - Begin <= Length && Bytes <= Length - (Base - Begin);
}
STATIC BOOLEAN ImageOverlap (UINT64 A, UINT64 An, UINT64 B, UINT64 Bn) {
  return An > MAX_UINT64 - A || Bn > MAX_UINT64 - B || (A < B + Bn && B < A + An);
}
BOOLEAN N976nUfsImageSourceOverlaps (CONST VOID *Buffer, UINTN Bytes) {
  if (Buffer == NULL || Bytes == 0 || Bytes > MAX_UINT64 - (UINTN)Buffer) { return TRUE; }
  return mImageAllocation != 0 && ImageOverlap ((UINTN)Buffer, Bytes,
    mImageAllocation, mImagePages * IMAGE_PAGE);
}
STATIC BOOLEAN ImageHeap (UINT64 Base, UINT64 Bytes) {
  return mImageHandoff != NULL && ImageSpan (Base, Bytes,
    mImageHandoff->HeapBase, mImageHandoff->HeapSize);
}
STATIC BOOLEAN ImageAttributes (UINT64 Address, UINT64 Bytes, UINT64 Expected) {
  UINT64 Attributes;
  if (mImageMemory == NULL || Bytes == 0 || Address > MAX_UINT64 - Bytes) { return FALSE; }
  for (UINT64 Page = Address & ~(UINT64)(IMAGE_PAGE - 1);
       Page <= ((Address + Bytes - 1) & ~(UINT64)(IMAGE_PAGE - 1)); Page += IMAGE_PAGE) {
    if (EFI_ERROR (mImageMemory->GetMemoryAttributes (mImageMemory, Page, IMAGE_PAGE, &Attributes)) ||
        (Attributes & IMAGE_ATTRIBUTES) != Expected) { return FALSE; }
  }
  return TRUE;
}
STATIC BOOLEAN ImageStorage (BOOLEAN Contents) {
  if (mImageAllocation == 0 || mImagePages < 3 || mImagePages > 1026 ||
      mImageBytes != N976N_BOOT_WINDOWS_BYTES ||
      mImageSource != (UINT8 *)(UINTN)(mImageAllocation + IMAGE_PAGE) ||
      !ImageHeap (mImageAllocation, mImagePages * IMAGE_PAGE) ||
      !ImageAttributes (mImageAllocation, mImagePages * IMAGE_PAGE,
                       EFI_MEMORY_XP | (mImageSealed ? EFI_MEMORY_RO : 0))) { return FALSE; }
  CONST UINT8 *P = (VOID *)(UINTN)mImageAllocation;
  for (UINTN I = 0; I < IMAGE_PAGE; ++I) { if (P[I] != 0xA5) { return FALSE; } }
  for (UINTN I = IMAGE_PAGE + mImageBytes; I < mImagePages * IMAGE_PAGE; ++I) {
    if (P[I] != 0xA5) { return FALSE; }
  }
  return !Contents || (mImageExpected != NULL &&
    ImageAttributes ((UINTN)mImageExpected, mImageBytes, EFI_MEMORY_RO | EFI_MEMORY_XP) &&
    CompareMem (mImageSource, mImageExpected, mImageBytes) == 0);
}

VOID N976nResetUfsImage (VOID) {
  if (mImageEntered) { return; }
  ZeroMem ((VOID *)&mN976nUfsImageReport, sizeof (mN976nUfsImageReport));
  mN976nUfsImageReport.Magic = N976N_UFS_IMAGE_MAGIC;
  mN976nUfsImageReport.Version = 1;
  mN976nUfsImageReport.Size = sizeof (mN976nUfsImageReport);
  mN976nUfsImageReport.Status = EFI_NOT_READY;
  mN976nUfsImageReport.LoadStatus = EFI_NOT_STARTED;
  mN976nUfsImageReport.UnloadStatus = EFI_NOT_STARTED;
}
BOOLEAN N976nUfsImageClosed (VOID) {
  return !mImageScope && mImageAllocation == 0 && mImageChild == NULL && !mImageQuarantined;
}
EFI_STATUS N976nBeginUfsImage (CONST N976N_PLATFORM_HANDOFF *H, CONST UINT8 *Expected, UINTN Bytes) {
  EFI_STATUS Status; EFI_PHYSICAL_ADDRESS Allocation = 0;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (mImageEntered || !N976nUfsImageClosed ()) { return EFI_ALREADY_STARTED; }
  mImageEntered = TRUE; mImageScope = TRUE; mImageHandoff = H;
  mN976nUfsImageReport.Phase = 1;
  if (H == NULL || H->Magic != N976N_PLATFORM_HANDOFF_MAGIC || H->Version != N976N_PLATFORM_ABI_VERSION ||
      H->Size != sizeof (*H) || H->Reserved || H->Profile > 1 ||
      H->HeapSize == 0 || H->HeapSize > MAX_UINT64 - H->HeapBase ||
      H->FirmwareSize != 0x900000 || !ImageSpan (H->FirmwareBase, H->FirmwareSize, H->ImageBase, H->ImageSize) ||
      ImageOverlap (H->FirmwareBase, H->FirmwareSize, H->HeapBase, H->HeapSize) ||
      Expected == NULL || Bytes != N976N_BOOT_WINDOWS_BYTES ||
      !ImageSpan ((UINTN)Expected, Bytes, H->FirmwareBase, H->FirmwareSize)) {
    return ImageFail (EFI_COMPROMISED_DATA, 1);
  }
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mImageMemory);
  if (EFI_ERROR (Status) || mImageMemory == NULL || mImageMemory->GetMemoryAttributes == NULL ||
      mImageMemory->SetMemoryAttributes == NULL || mImageMemory->ClearMemoryAttributes == NULL) {
    return ImageFail (EFI_UNSUPPORTED, 2);
  }
  if (!ImageAttributes ((UINTN)Expected, Bytes, EFI_MEMORY_RO | EFI_MEMORY_XP)) {
    return ImageFail (EFI_SECURITY_VIOLATION, 3);
  }
  mImageExpected = Expected; mImageBytes = Bytes;
  mImagePages = EFI_SIZE_TO_PAGES (Bytes) + 2;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData, mImagePages, &Allocation);
  if (EFI_ERROR (Status)) { return ImageFail (Status, 4); }
  mImageAllocation = Allocation;
  mImageSource = (VOID *)(UINTN)(Allocation + IMAGE_PAGE);
  if ((Allocation & (IMAGE_PAGE - 1)) || !ImageHeap (Allocation, mImagePages * IMAGE_PAGE) ||
      !ImageAttributes (Allocation, mImagePages * IMAGE_PAGE, EFI_MEMORY_XP)) {
    mImageQuarantined = TRUE; return ImageFail (EFI_SECURITY_VIOLATION, 5);
  }
  SetMem ((VOID *)(UINTN)Allocation, mImagePages * IMAGE_PAGE, 0xA5);
  if (!ImageStorage (FALSE)) { return ImageFail (EFI_SECURITY_VIOLATION, 6); }
  mN976nUfsImageReport.SourceBytes = Bytes;
  mN976nUfsImageReport.SourceAttributes = EFI_MEMORY_XP;
  mN976nUfsImageReport.Checks = 1; mN976nUfsImageReport.Phase = 2;
  return EFI_SUCCESS;
}
EFI_STATUS N976nAppendUfsImage (UINTN Offset, CONST VOID *Verified, UINTN Bytes) {
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (mImageFailed) { return mN976nUfsImageReport.Status; }
  if (!mImageScope || mImageSealed || mImageLoadAttempted || Bytes == 0 || Bytes > IMAGE_CHUNK ||
      Offset != mN976nUfsImageReport.StagedBytes || Offset > mImageBytes || Bytes > mImageBytes - Offset ||
      Verified == NULL || !ImageHeap ((UINTN)Verified, Bytes) ||
      ImageOverlap ((UINTN)Verified, Bytes, mImageAllocation, mImagePages * IMAGE_PAGE) ||
      !ImageAttributes ((UINTN)Verified, Bytes, EFI_MEMORY_XP) || !ImageStorage (FALSE)) {
    return ImageFail (EFI_SECURITY_VIOLATION, 7);
  }
  if (CompareMem (Verified, mImageExpected + Offset, Bytes)) { return ImageFail (EFI_COMPROMISED_DATA, 8); }
  CopyMem (mImageSource + Offset, Verified, Bytes);
  if (!ImageStorage (FALSE) || CompareMem (mImageSource + Offset, mImageExpected + Offset, Bytes)) {
    return ImageFail (EFI_COMPROMISED_DATA, 9);
  }
  mN976nUfsImageReport.StagedBytes += Bytes;
  if (mN976nUfsImageReport.StagedBytes == mImageBytes) {
    mN976nUfsImageReport.Checks |= 2; mN976nUfsImageReport.Phase = 3;
  }
  return EFI_SUCCESS;
}

/* Bound every node before using a generic DevicePath helper. The exact volume
 * prefix must resolve to the supplied handle; the suffix is one canonical file. */
STATIC UINTN ImagePathBytes (CONST EFI_DEVICE_PATH_PROTOCOL *Path) {
  UINTN Total = 0;
  if (Path == NULL) { return 0; }
  while (Total < IMAGE_PATH_LIMIT) {
    CONST EFI_DEVICE_PATH_PROTOCOL *P = (CONST VOID *)((CONST UINT8 *)Path + Total);
    if (!ImageHeap ((UINTN)P, sizeof (*P)) || !ImageAttributes ((UINTN)P, sizeof (*P), EFI_MEMORY_XP)) { return 0; }
    UINTN N = DevicePathNodeLength (P);
    if (N < sizeof (*P) || N > IMAGE_PATH_LIMIT - Total ||
        !ImageHeap ((UINTN)P, N) || !ImageAttributes ((UINTN)P, N, EFI_MEMORY_XP)) { return 0; }
    if (IsDevicePathEnd (P)) { return N == sizeof (*P) ? Total + N : 0; }
    if (DevicePathType (P) == END_DEVICE_PATH_TYPE) { return 0; }
    Total += N;
  }
  return 0;
}
STATIC EFI_STATUS ImagePath (EFI_HANDLE Fs, EFI_DEVICE_PATH_PROTOCOL *Full,
  EFI_DEVICE_PATH_PROTOCOL **Suffix, UINTN *SuffixBytes) {
  EFI_HANDLE Found = NULL; EFI_DEVICE_PATH_PROTOCOL *Volume = NULL, *Remaining = Full;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;
  CONST CHAR16 Canonical[] = L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi";
  if (Fs == NULL || Full == NULL || ImagePathBytes (Full) == 0 ||
      EFI_ERROR (gBS->HandleProtocol (Fs, &gEfiDevicePathProtocolGuid, (VOID **)&Volume)) ||
      EFI_ERROR (gBS->HandleProtocol (Fs, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&FileSystem)) ||
      FileSystem == NULL || Volume == NULL) { return EFI_COMPROMISED_DATA; }
  UINTN V = ImagePathBytes (Volume), F = ImagePathBytes (Full);
  if (V <= sizeof (*Volume) || V >= F || CompareMem (Volume, Full, V - sizeof (*Volume))) {
    return EFI_COMPROMISED_DATA;
  }
  EFI_STATUS Status = gBS->LocateDevicePath (&gEfiDevicePathProtocolGuid, &Remaining, &Found);
  EFI_DEVICE_PATH_PROTOCOL *File = (VOID *)((UINT8 *)Full + V - sizeof (*Volume));
  if (EFI_ERROR (Status) || Found != Fs || Remaining != File ||
      DevicePathType (File) != MEDIA_DEVICE_PATH || DevicePathSubType (File) != MEDIA_FILEPATH_DP ||
      DevicePathNodeLength (File) != sizeof (*File) + sizeof (Canonical) ||
      CompareMem ((UINT8 *)File + sizeof (*File), Canonical, sizeof (Canonical)) ||
      F != V + sizeof (*File) + sizeof (Canonical)) { return EFI_COMPROMISED_DATA; }
  *Suffix = File; *SuffixBytes = F - (V - sizeof (*Volume));
  return EFI_SUCCESS;
}

STATIC EFI_STATUS ImageLoaded (EFI_HANDLE Parent, EFI_HANDLE Fs,
  EFI_DEVICE_PATH_PROTOCOL *Suffix, UINTN SuffixBytes) {
  EFI_LOADED_IMAGE_PROTOCOL *Loaded = NULL;
  EFI_STATUS Status = gBS->HandleProtocol (mImageChild, &gEfiLoadedImageProtocolGuid, (VOID **)&Loaded);
  if (EFI_ERROR (Status) || Loaded == NULL || !ImageHeap ((UINTN)Loaded, sizeof (*Loaded)) ||
      !ImageAttributes ((UINTN)Loaded, sizeof (*Loaded), EFI_MEMORY_XP)) { return EFI_COMPROMISED_DATA; }
  UINT64 Base = (UINTN)Loaded->ImageBase, Size = Loaded->ImageSize;
  if (!ImageHeap (Base, Size) || ((Base | Size) & (IMAGE_PAGE - 1)) ||
      ImageOverlap (Base, Size, mImageAllocation, mImagePages * IMAGE_PAGE) || Size < sizeof (EFI_IMAGE_DOS_HEADER)) {
    return EFI_SECURITY_VIOLATION;
  }
  /* Retain the independently bounded extent even when later identity checks
   * fail. Cleanup can then verify revocation; an unknown extent quarantines. */
  mN976nUfsImageReport.ImageBase = Base; mN976nUfsImageReport.ImageBytes = Size;
  if (Loaded->ParentHandle != Parent || Loaded->DeviceHandle != Fs || Loaded->SystemTable != gST ||
      Loaded->Revision != EFI_LOADED_IMAGE_PROTOCOL_REVISION ||
      Loaded->ImageCodeType != EfiLoaderCode || Loaded->ImageDataType != EfiLoaderData ||
      Loaded->LoadOptions != NULL || Loaded->LoadOptionsSize != 0 ||
      ImagePathBytes (Loaded->FilePath) != SuffixBytes || CompareMem (Loaded->FilePath, Suffix, SuffixBytes)) {
    return EFI_COMPROMISED_DATA;
  }
  if (!ImageAttributes (Base, IMAGE_PAGE, EFI_MEMORY_RO | EFI_MEMORY_XP)) { return EFI_SECURITY_VIOLATION; }
  CONST EFI_IMAGE_DOS_HEADER *Dos = (CONST VOID *)(UINTN)Base;
  UINTN Pe = Dos->e_lfanew;
  if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE || Pe > Size || sizeof (EFI_IMAGE_NT_HEADERS64) > Size - Pe ||
      !ImageAttributes (Base + Pe, sizeof (EFI_IMAGE_NT_HEADERS64), EFI_MEMORY_RO | EFI_MEMORY_XP)) {
    return EFI_COMPROMISED_DATA;
  }
  CONST EFI_IMAGE_NT_HEADERS64 *Nt = (CONST VOID *)(UINTN)(Base + Pe);
  if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE || Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 ||
      Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      Nt->OptionalHeader.Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ||
      Nt->OptionalHeader.SizeOfImage != Size || Nt->OptionalHeader.AddressOfEntryPoint >= Size ||
      Nt->FileHeader.SizeOfOptionalHeader < sizeof (EFI_IMAGE_OPTIONAL_HEADER64) ||
      Nt->FileHeader.NumberOfSections == 0 || Nt->FileHeader.NumberOfSections > 32) { return EFI_COMPROMISED_DATA; }
  UINTN Table = Pe + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Nt->FileHeader.SizeOfOptionalHeader;
  UINTN TableBytes = Nt->FileHeader.NumberOfSections * sizeof (EFI_IMAGE_SECTION_HEADER);
  if (Table > Size || TableBytes > Size - Table ||
      !ImageAttributes (Base + Table, TableBytes, EFI_MEMORY_RO | EFI_MEMORY_XP) ||
      !ImageAttributes (Base + Nt->OptionalHeader.AddressOfEntryPoint, 4, EFI_MEMORY_RO)) { return EFI_SECURITY_VIOLATION; }
  CONST EFI_IMAGE_SECTION_HEADER *Sections = (CONST VOID *)(UINTN)(Base + Table);
  BOOLEAN HaveCode = FALSE, HaveData = FALSE;
  for (UINTN I = 0; I < Nt->FileHeader.NumberOfSections; ++I) {
    CONST EFI_IMAGE_SECTION_HEADER *S = &Sections[I];
    UINTN Rva = S->VirtualAddress, N = S->Misc.VirtualSize;
    UINT64 Attr = EFI_MEMORY_RO | EFI_MEMORY_XP;
    if (!N || (Rva & (IMAGE_PAGE - 1)) || Rva >= Size || N > Size - Rva ||
        (S->Characteristics & EFI_IMAGE_SCN_MEM_READ) == 0 ||
        ((S->Characteristics & EFI_IMAGE_SCN_MEM_WRITE) && (S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE))) {
      return EFI_SECURITY_VIOLATION;
    }
    if (S->Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) { Attr = EFI_MEMORY_RO; HaveCode = TRUE; }
    else if (S->Characteristics & EFI_IMAGE_SCN_MEM_WRITE) { Attr = EFI_MEMORY_XP; HaveData = TRUE; }
    if (!ImageAttributes (Base + Rva, N, Attr)) { return EFI_SECURITY_VIOLATION; }
  }
  if (!HaveCode || !HaveData) { return EFI_SECURITY_VIOLATION; }
  mN976nUfsImageReport.ImageBase = Base; mN976nUfsImageReport.ImageBytes = Size;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS ImageLoad (EFI_HANDLE Parent, EFI_HANDLE Fs, EFI_DEVICE_PATH_PROTOCOL *FullPath, BOOLEAN Run) {
  EFI_STATUS Status; EFI_DEVICE_PATH_PROTOCOL *Suffix = NULL; UINTN SuffixBytes = 0;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (mImageFailed) { return mN976nUfsImageReport.Status; }
  if (!mImageScope || mImageLoadAttempted || Parent == NULL ||
      mN976nUfsImageReport.StagedBytes != mImageBytes || !ImageStorage (TRUE)) {
    return ImageFail (EFI_SECURITY_VIOLATION, 10);
  }
  if (Run) {
    Status = N976nPrepareUfsWindows (Fs, mImageHandoff->Profile);
    if (EFI_ERROR (Status)) { return ImageFail (Status, 26); }
  }
  /* SecurityStubDxe admits external application buffers only after the standard
   * trusted-driver completion/lock phase. Reuse the existing platform helper. */
  Status = N976nCompleteDxePhase ();
  if (EFI_ERROR (Status)) { return ImageFail (Status, 25); }
  Status = ImagePath (Fs, FullPath, &Suffix, &SuffixBytes);
  if (EFI_ERROR (Status)) { return ImageFail (Status, 11); }
  mN976nUfsImageReport.Checks |= 4;
  Status = mImageMemory->SetMemoryAttributes (mImageMemory, mImageAllocation,
    mImagePages * IMAGE_PAGE, EFI_MEMORY_RO | EFI_MEMORY_XP);
  /* A failed attribute call may have partially changed pages. Release restores
   * the exact owned allocation before freeing; it never assumes an atomic call. */
  mImageSealed = TRUE;
  if (EFI_ERROR (Status) || !ImageStorage (TRUE)) { return ImageFail (EFI_SECURITY_VIOLATION, 12); }
  mN976nUfsImageReport.SourceAttributes = EFI_MEMORY_RO | EFI_MEMORY_XP;
  mN976nUfsImageReport.Checks |= 8; mN976nUfsImageReport.Phase = 4;
  mImageLoadAttempted = TRUE;
  Status = gBS->LoadImage (FALSE, Parent, FullPath, mImageSource, mImageBytes, &mImageChild);
  mN976nUfsImageReport.LoadStatus = Status;
  if (EFI_ERROR (Status)) { ImageFail (Status, 13); }
  else if (mImageChild == NULL) { ImageFail (EFI_COMPROMISED_DATA, 13); }
  else { mN976nUfsImageReport.Checks |= 16; mN976nUfsImageReport.Phase = 5; }
  if (!ImageStorage (TRUE)) { ImageFail (EFI_COMPROMISED_DATA, 15); }
  if (mImageChild != NULL) {
    Status = ImageLoaded (Parent, Fs, Suffix, SuffixBytes);
    if (EFI_ERROR (Status)) { ImageFail (Status, 14); }
    else if (!mImageFailed) {
      mN976nUfsImageReport.Checks |= 32;
      N976nUfsImageLoadedCheckpoint ();
    }
  }
  BOOLEAN Started = FALSE;
  if (Run && !mImageFailed) {
    /* All source/child/FAT/ACPI/event setup is still low-owned. Publish only
       now, before the native loader application starts allocating data. */
    Status = N976nRunHighRamProbe (mImageHandoff);
    if (EFI_ERROR (Status) || !N976nHighRamPublished () || !N976nUfsWindowsDmaReady () || !ImageStorage (TRUE) ||
        EFI_ERROR (ImageLoaded (Parent, Fs, Suffix, SuffixBytes))) {
      mImageQuarantined = TRUE;
      Status = ImageFail (EFI_ERROR (Status) ? Status : EFI_SECURITY_VIOLATION, 30);
      /* Publication may be partial. Hold the source/child/service and mapped
         bank; do not attempt unmap, generic rollback or native StartImage. */
      N976nBdsStop (Status);
      return Status;
    }
    N976nHighRamWindowsReadyCheckpoint ();
    mN976nUfsImageReport.Phase = 7;
    Status = N976nStartUfsWindows (Parent, Fs, mImageChild);
    Started = mN976nWindowsReport.StartCount != 0;
    if (EFI_ERROR (Status)) { ImageFail (Status, 27); }
    if (!ImageStorage (TRUE)) { ImageFail (EFI_COMPROMISED_DATA, 28); }
  }
  if (mImageChild != NULL) {
    if (!Started) {
      Status = gBS->UnloadImage (mImageChild); mN976nUfsImageReport.UnloadStatus = Status;
      if (EFI_ERROR (Status)) { mImageQuarantined = TRUE; return ImageFail (Status, 16); }
    }
    /* A returned application is auto-unloaded by CoreStartImage. Never unload
     * a potentially stale handle again, nor free source storage on assumption. */
    VOID *Gone = NULL;
    Status = gBS->HandleProtocol (mImageChild, &gEfiLoadedImageProtocolGuid, &Gone);
    if (Started) { mN976nWindowsReport.AutoUnloadStatus = Status; }
    if (Status != EFI_INVALID_PARAMETER || Gone != NULL) {
      mImageQuarantined = TRUE; return ImageFail (EFI_COMPROMISED_DATA, 17);
    }
    if (Started) { mN976nUfsImageReport.UnloadStatus = EFI_SUCCESS; }
    mImageChild = NULL; mN976nUfsImageReport.CloseChecks |= 1;
    if (mN976nUfsImageReport.ImageBase == 0 || mN976nUfsImageReport.ImageBytes == 0 ||
        !ImageAttributes (mN976nUfsImageReport.ImageBase, mN976nUfsImageReport.ImageBytes, EFI_MEMORY_XP)) {
      mImageQuarantined = TRUE; return ImageFail (EFI_SECURITY_VIOLATION, 18);
    }
    mN976nUfsImageReport.FreedAttributes = EFI_MEMORY_XP;
    if (Started) {
      mN976nWindowsReport.FreedAttributes = EFI_MEMORY_XP;
      mN976nWindowsReport.Checks |= 128;
    }
    mN976nUfsImageReport.CloseChecks |= 2;
    mN976nUfsImageReport.Checks |= 64;
  }
  if (mImageFailed) { return mN976nUfsImageReport.Status; }
  mN976nUfsImageReport.Phase = 6;
  return EFI_SUCCESS;
}

EFI_STATUS N976nLoadAndUnloadUfsImage (EFI_HANDLE Parent, EFI_HANDLE Fs, EFI_DEVICE_PATH_PROTOCOL *FullPath) {
  return ImageLoad (Parent, Fs, FullPath, FALSE);
}
EFI_STATUS N976nRunUfsImage (EFI_HANDLE Parent, EFI_HANDLE Fs, EFI_DEVICE_PATH_PROTOCOL *FullPath) {
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  EFI_STATUS Status = ImageLoad (Parent, Fs, FullPath, TRUE);
  /* Non-returning observations never reach here. All event cleanup occurs at
   * application TPL, while the source/filesystem/service are still owned. */
  EFI_STATUS Cancel = N976nCancelUfsWindows ();
  if (EFI_ERROR (Cancel)) { ImageFail (Cancel, 29); }
  return EFI_ERROR (Status) ? Status : (EFI_ERROR (Cancel) ? mN976nUfsImageReport.Status : EFI_SUCCESS);
}

EFI_STATUS N976nReleaseUfsImage (VOID) {
  EFI_STATUS Status;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (!mImageEntered) { return EFI_NOT_STARTED; }
  if (mImageChild != NULL || mImageQuarantined) { return ImageFail (EFI_ACCESS_DENIED, 19); }
  if (!mImageScope) { return mImageFailed ? mN976nUfsImageReport.Status : EFI_ALREADY_STARTED; }
  if (mImageAllocation != 0) {
    if (!ImageHeap (mImageAllocation, mImagePages * IMAGE_PAGE) || (mImageAllocation & (IMAGE_PAGE - 1))) {
      mImageQuarantined = TRUE; return ImageFail (EFI_SECURITY_VIOLATION, 20);
    }
    Status = mImageMemory->SetMemoryAttributes (mImageMemory, mImageAllocation, mImagePages * IMAGE_PAGE, EFI_MEMORY_XP);
    if (!EFI_ERROR (Status)) {
      Status = mImageMemory->ClearMemoryAttributes (mImageMemory, mImageAllocation, mImagePages * IMAGE_PAGE, EFI_MEMORY_RO);
    }
    if (EFI_ERROR (Status) || !ImageAttributes (mImageAllocation, mImagePages * IMAGE_PAGE, EFI_MEMORY_XP)) {
      mImageQuarantined = TRUE; return ImageFail (EFI_SECURITY_VIOLATION, 21);
    }
    mImageSealed = FALSE;
    if (!ImageStorage (mN976nUfsImageReport.StagedBytes == mImageBytes)) { ImageFail (EFI_COMPROMISED_DATA, 22); }
    mN976nUfsImageReport.CloseChecks |= 4;
    Status = gBS->FreePages (mImageAllocation, mImagePages);
    if (EFI_ERROR (Status)) { mImageQuarantined = TRUE; return ImageFail (Status, 23); }
    mImageAllocation = 0; mImageSource = NULL; mImagePages = 0;
    mN976nUfsImageReport.CloseChecks |= 8;
  }
  mImageScope = FALSE;
  if (mImageFailed) { return mN976nUfsImageReport.Status; }
  if (mN976nUfsImageReport.Checks != 0x7F || mN976nUfsImageReport.CloseChecks != 0xF ||
      !N976nUfsImageClosed ()) { return ImageFail (EFI_COMPROMISED_DATA, 24); }
  mN976nUfsImageReport.Checks |= 128;
  mN976nUfsImageReport.Phase = 8; mN976nUfsImageReport.Status = EFI_SUCCESS;
  return EFI_SUCCESS;
}
