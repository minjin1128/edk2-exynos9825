/* SPDX-License-Identifier: MIT
 * Standard firmware-volume filesystem and native EFI application lifecycle.
 * No Boot Services replacement, source-buffer loader or per-call emulation.
 */
#include <Uefi.h>
#include <N976nBootFiles.h>
#include <IndustryStandard/PeImage.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/FirmwareVolume2.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/SimpleFileSystem.h>

volatile N976N_BOOT_FILES_REPORT mN976nBootFilesReport;
STATIC N976N_BOOT_RECEIPT mReceipt;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mAttributes;

__attribute__((noinline)) VOID EFIAPI N976nBootFilesCheckpoint (VOID)
{
  MemoryFence ();
}

STATIC EFI_STATUS ReadBootInfo (EFI_FILE_PROTOCOL *Root)
{
  CONST CHAR8 Expected[] = N976N_BOOT_INFO_CONTENT;
  CHAR8 Data[128];
  EFI_FILE_PROTOCOL *File = NULL, *Rejected = NULL;
  UINTN Bytes = sizeof (Data);
  UINT32 Crc;
  EFI_STATUS Status, Close;

  Status = Root->Open (Root, &File, N976N_BOOT_INFO_PATH, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { return Status; }
  Status = File->Read (File, &Bytes, Data);
  if (EFI_ERROR (Status) || Bytes != sizeof (Expected) - 1 ||
      CompareMem (Data, Expected, sizeof (Expected) - 1) != 0) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Status = gBS->CalculateCrc32 (Data, Bytes, &Crc);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.FileBytes = Bytes;
  mN976nBootFilesReport.FileCrc = Crc;
  mN976nBootFilesReport.Checks |= 2;

  Status = Root->Open (Root, &Rejected, L"\\N976nMissing.efi", EFI_FILE_MODE_READ, 0);
  mN976nBootFilesReport.MissingStatus = Status;
  if (Rejected != NULL) { Rejected->Close (Rejected); Rejected = NULL; }
  if (Status != EFI_NOT_FOUND) { Status = EFI_COMPROMISED_DATA; goto Done; }
  mN976nBootFilesReport.Checks |= 4;
  Status = Root->Open (Root, &Rejected, N976N_BOOT_INFO_PATH,
    EFI_FILE_MODE_READ | EFI_FILE_MODE_WRITE, 0);
  mN976nBootFilesReport.WriteOpenStatus = Status;
  if (Rejected != NULL) { Rejected->Close (Rejected); Rejected = NULL; }
  if (Status != EFI_WRITE_PROTECTED) { Status = EFI_COMPROMISED_DATA; goto Done; }
  mN976nBootFilesReport.Checks |= 8;
  Bytes = 1;
  Status = File->Write (File, &Bytes, Data);
  mN976nBootFilesReport.WriteStatus = Status;
  if (Status != EFI_WRITE_PROTECTED) { Status = EFI_COMPROMISED_DATA; goto Done; }
  mN976nBootFilesReport.Checks |= 16;
  /* Verify that rejected writes did not alter the supplied resource. */
  Status = File->SetPosition (File, 0);
  if (EFI_ERROR (Status)) { goto Done; }
  Bytes = sizeof (Data);
  Status = File->Read (File, &Bytes, Data);
  if (!EFI_ERROR (Status) && (Bytes != sizeof (Expected) - 1 ||
      CompareMem (Data, Expected, sizeof (Expected) - 1) != 0)) {
    Status = EFI_COMPROMISED_DATA;
  }
Done:
  Close = File->Close (File);
  return EFI_ERROR (Status) ? Status : Close;
}

/* The production policy validates every section and source byte. BDS records
 * independently observable representative header/code/data permissions too. */
STATIC EFI_STATUS CheckLoadedImage (EFI_HANDLE Handle, EFI_HANDLE Fs,
  EFI_LOADED_IMAGE_PROTOCOL **Loaded)
{
  EFI_LOADED_IMAGE_PROTOCOL *Image = NULL;
  EFI_IMAGE_DOS_HEADER *Dos;
  EFI_IMAGE_NT_HEADERS64 *Nt;
  EFI_IMAGE_SECTION_HEADER *Section;
  UINT64 Base, Size, PeOffset, TableOffset, HeaderAttr, CodeAttr, DataAttr = 0;
  BOOLEAN HaveData = FALSE;
  EFI_STATUS Status = gBS->HandleProtocol (Handle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
  if (EFI_ERROR (Status)) { return Status; }
  if (Image == NULL || Image->DeviceHandle != Fs || Image->ParentHandle == NULL ||
      Image->ImageCodeType != EfiLoaderCode || Image->ImageDataType != EfiLoaderData) {
    return EFI_COMPROMISED_DATA;
  }
  Base = (UINTN)Image->ImageBase;
  Size = Image->ImageSize;
  if (Base < 0x92001000ULL || Base >= 0x95FDE000ULL ||
      Size == 0 || Size > 0x95FDE000ULL - Base || ((Base | Size) & 4095) != 0) {
    return EFI_SECURITY_VIOLATION;
  }
  Dos = (VOID *)(UINTN)Base;
  if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE) { return EFI_COMPROMISED_DATA; }
  PeOffset = Dos->e_lfanew;
  if (PeOffset > Size || sizeof (*Nt) > Size - PeOffset) { return EFI_COMPROMISED_DATA; }
  Nt = (VOID *)(UINTN)(Base + PeOffset);
  if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE ||
      Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      Nt->OptionalHeader.Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ||
      Nt->OptionalHeader.AddressOfEntryPoint >= Size ||
      Nt->FileHeader.NumberOfSections == 0 || Nt->FileHeader.NumberOfSections > 32) {
    return EFI_COMPROMISED_DATA;
  }
  TableOffset = PeOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Nt->FileHeader.SizeOfOptionalHeader;
  if (TableOffset > Size || Nt->FileHeader.NumberOfSections * sizeof (*Section) > Size - TableOffset) {
    return EFI_COMPROMISED_DATA;
  }
  Section = (VOID *)(UINTN)(Base + TableOffset);
  Status = mAttributes->GetMemoryAttributes (mAttributes, Base, 4096, &HeaderAttr);
  if (EFI_ERROR (Status)) { return Status; }
  Status = mAttributes->GetMemoryAttributes (mAttributes,
    (Base + Nt->OptionalHeader.AddressOfEntryPoint) & ~4095ULL, 4096, &CodeAttr);
  if (EFI_ERROR (Status)) { return Status; }
  for (UINTN Index = 0; Index < Nt->FileHeader.NumberOfSections; Index++) {
    if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_WRITE) == 0) { continue; }
    if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0 ||
        Section[Index].VirtualAddress >= Size ||
        Section[Index].Misc.VirtualSize > Size - Section[Index].VirtualAddress) {
      return EFI_SECURITY_VIOLATION;
    }
    Status = mAttributes->GetMemoryAttributes (mAttributes,
      (Base + Section[Index].VirtualAddress) & ~4095ULL, 4096, &DataAttr);
    if (EFI_ERROR (Status)) { return Status; }
    HaveData = TRUE;
    break;
  }
  if (!HaveData ||
      (HeaderAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != (EFI_MEMORY_RO | EFI_MEMORY_XP) ||
      (CodeAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_RO ||
      (DataAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
    return EFI_SECURITY_VIOLATION;
  }
  mN976nBootFilesReport.HeaderAttributes = HeaderAttr;
  mN976nBootFilesReport.CodeAttributes = CodeAttr;
  mN976nBootFilesReport.DataAttributes = DataAttr;
  *Loaded = Image;
  return EFI_SUCCESS;
}

STATIC EFI_STATUS CheckFreed (UINT64 Base, UINT64 Bytes, UINT64 *Attributes)
{
  EFI_STATUS Status = mAttributes->GetMemoryAttributes (mAttributes, Base, Bytes, Attributes);
  if (!EFI_ERROR (Status) && (*Attributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
    return EFI_SECURITY_VIOLATION;
  }
  return Status;
}

EFI_STATUS RunBootFiles (EFI_HANDLE Parent)
{
  EFI_HANDLE *Handles = NULL, FsHandle, Child = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
  EFI_FILE_PROTOCOL *Root = NULL;
  EFI_DEVICE_PATH_PROTOCOL *Path = NULL;
  EFI_LOADED_IMAGE_PROTOCOL *Loaded = NULL;
  UINTN Count = 0, ExitBytes = 0;
  CHAR16 *ExitData = NULL;
  UINT64 Freed;
  EFI_STATUS Status;

  ZeroMem ((VOID *)&mN976nBootFilesReport, sizeof (mN976nBootFilesReport));
  mN976nBootFilesReport.Magic = N976N_BOOT_FILES_MAGIC;
  mN976nBootFilesReport.Version = 1;
  mN976nBootFilesReport.Size = sizeof (mN976nBootFilesReport);
  mN976nBootFilesReport.Stage = 1;
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mAttributes);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiFirmwareVolume2ProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { goto Done; }
  if (Count != 1) { Status = EFI_COMPROMISED_DATA; goto Done; }
  /* FvSimpleFileSystem installs its protocol on this firmware-volume handle.
     SEC49 also has a FAT filesystem, so select the owned FV, not an arbitrary
     member of the global filesystem list. */
  FsHandle = Handles[0];
  Status = gBS->ConnectController (FsHandle, NULL, NULL, TRUE);
  FreePool (Handles); Handles = NULL;
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.FsHandle = (UINTN)FsHandle;
  Status = gBS->HandleProtocol (FsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.Checks |= 1;
  mN976nBootFilesReport.Stage = 2;
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = ReadBootInfo (Root);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = Root->Close (Root); Root = NULL;
  if (EFI_ERROR (Status)) { goto Done; }

  mN976nBootFilesReport.Stage = 3;
  Path = FileDevicePath (FsHandle, N976N_BOOT_APP_PATH);
  if (Path == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = gBS->LoadImage (FALSE, Parent, Path, NULL, 0, &Child);
  mN976nBootFilesReport.LoadStatus = Status;
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.LoadCount++;
  mN976nBootFilesReport.Checks |= 32;
  mN976nBootFilesReport.Stage = 4;
  Status = CheckLoadedImage (Child, FsHandle, &Loaded);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.LoadedBase = (UINTN)Loaded->ImageBase;
  mN976nBootFilesReport.LoadedBytes = Loaded->ImageSize;
  mN976nBootFilesReport.Checks |= 64;
  ZeroMem (&mReceipt, sizeof (mReceipt));
  mReceipt.Magic = N976N_BOOT_RECEIPT_MAGIC;
  mReceipt.Version = 1;
  mReceipt.Size = sizeof (mReceipt);
  mReceipt.ImageBase = (UINTN)Loaded->ImageBase;
  mReceipt.ImageBytes = Loaded->ImageSize;
  Loaded->LoadOptions = &mReceipt;
  Loaded->LoadOptionsSize = sizeof (mReceipt);
  mN976nBootFilesReport.Stage = 5;
  N976nBootFilesCheckpoint ();
  mN976nBootFilesReport.StartCount++;
  Status = gBS->StartImage (Child, &ExitBytes, &ExitData);
  mN976nBootFilesReport.StartStatus = Status;
  if (EFI_ERROR (Status)) { Child = NULL; goto Done; }
  if (ExitBytes != 0 || ExitData != NULL) { Child = NULL; Status = EFI_COMPROMISED_DATA; goto Done; }
  mN976nBootFilesReport.Checks |= 128;
  mN976nBootFilesReport.Stage = 6;
  Loaded = NULL;
  Status = gBS->HandleProtocol (Child, &gEfiLoadedImageProtocolGuid, (VOID **)&Loaded);
  Child = NULL;
  mN976nBootFilesReport.AutoUnloadStatus = Status;
  if (Status != EFI_INVALID_PARAMETER || Loaded != NULL) { Status = EFI_COMPROMISED_DATA; goto Done; }
  Status = CheckFreed (mN976nBootFilesReport.LoadedBase, mN976nBootFilesReport.LoadedBytes, &Freed);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.FreedAttributes = Freed;
  mN976nBootFilesReport.AutoUnloadCount++;
  mN976nBootFilesReport.Checks |= 256;
  mN976nBootFilesReport.ReceiptChecks = mReceipt.Checks;
  mN976nBootFilesReport.ReceiptBytes = mReceipt.FileBytes;
  mN976nBootFilesReport.ReceiptCrc = mReceipt.FileCrc;
  if (mReceipt.Checks != N976N_BOOT_RECEIPT_CHECKS || mReceipt.Status != EFI_SUCCESS ||
      mReceipt.FileBytes != mN976nBootFilesReport.FileBytes ||
      mReceipt.FileCrc != mN976nBootFilesReport.FileCrc ||
      mReceipt.ImageBase != mN976nBootFilesReport.LoadedBase ||
      mReceipt.ImageBytes != mN976nBootFilesReport.LoadedBytes) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  mN976nBootFilesReport.Checks |= 1024;

  mN976nBootFilesReport.Stage = 7;
  Status = gBS->LoadImage (FALSE, Parent, Path, NULL, 0, &Child);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.LoadCount++;
  Status = CheckLoadedImage (Child, FsHandle, &Loaded);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.ExplicitLoadedBase = (UINTN)Loaded->ImageBase;
  mN976nBootFilesReport.ExplicitLoadedBytes = Loaded->ImageSize;
  Status = gBS->UnloadImage (Child);
  mN976nBootFilesReport.ExplicitUnloadStatus = Status;
  if (EFI_ERROR (Status)) { goto Done; }
  Child = NULL;
  Status = CheckFreed (mN976nBootFilesReport.ExplicitLoadedBase, mN976nBootFilesReport.ExplicitLoadedBytes, &Freed);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nBootFilesReport.ExplicitFreedAttributes = Freed;
  mN976nBootFilesReport.ExplicitUnloadCount++;
  mN976nBootFilesReport.Checks |= 512;
  if (mN976nBootFilesReport.Checks != N976N_BOOT_FILES_CHECKS) { Status = EFI_COMPROMISED_DATA; goto Done; }
  mN976nBootFilesReport.Stage = 8;
  Status = EFI_SUCCESS;
Done:
  if (ExitData != NULL) { FreePool (ExitData); }
  if (Path != NULL) { FreePool (Path); }
  if (Handles != NULL) { FreePool (Handles); }
  if (Root != NULL) { Root->Close (Root); }
  mN976nBootFilesReport.Status = Status;
  MemoryFence ();
  return Status;
}
