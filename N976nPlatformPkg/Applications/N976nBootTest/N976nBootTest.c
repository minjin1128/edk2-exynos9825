/* SPDX-License-Identifier: MIT
 * A bounded native EFI application, not a replacement loader. The ordinary
 * UefiApplicationEntryPoint library returns to DXE's StartImage/Exit path.
 */
#include <Uefi.h>
#include <N976nBootFiles.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/SimpleFileSystem.h>

STATIC volatile UINT64 mWritableMarker = N976N_BOOT_RECEIPT_MAGIC;

EFI_STATUS EFIAPI UefiMain (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_LOADED_IMAGE_PROTOCOL *Image = NULL;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
  EFI_FILE_PROTOCOL *Root = NULL, *File = NULL;
  N976N_BOOT_RECEIPT *Receipt;
  CONST CHAR8 Expected[] = N976N_BOOT_INFO_CONTENT;
  CHAR8 Contents[128];
  UINTN Bytes = sizeof (Contents);
  UINT32 Crc;
  UINT64 Attributes;
  EFI_STATUS Status;

  if (SystemTable != gST || SystemTable->BootServices != gBS) { return EFI_COMPROMISED_DATA; }
  Status = gBS->HandleProtocol (ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
  if (EFI_ERROR (Status) || Image == NULL || Image->DeviceHandle == NULL ||
      Image->LoadOptions == NULL || Image->LoadOptionsSize != sizeof (*Receipt)) {
    return EFI_COMPROMISED_DATA;
  }
  Receipt = Image->LoadOptions;
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&Memory);
  if (EFI_ERROR (Status) || Memory == NULL ||
      EFI_ERROR (Memory->GetMemoryAttributes (Memory, (UINTN)Receipt, sizeof (*Receipt), &Attributes)) ||
      (Attributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP ||
      Receipt->Magic != N976N_BOOT_RECEIPT_MAGIC || Receipt->Version != 1 ||
      Receipt->Size != sizeof (*Receipt) || Receipt->Reserved != 0 || Receipt->Checks != 0 ||
      Receipt->ImageBase != (UINTN)Image->ImageBase || Receipt->ImageBytes != Image->ImageSize) {
    return EFI_SECURITY_VIOLATION;
  }
  Receipt->Checks = 1 | 8;
  Status = gBS->HandleProtocol (Image->DeviceHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status)) { goto Done; }
  if (Fs == NULL) { Status = EFI_COMPROMISED_DATA; goto Done; }
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = Root->Open (Root, &File, N976N_BOOT_INFO_PATH, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = File->Read (File, &Bytes, Contents);
  if (EFI_ERROR (Status)) { goto Done; }
  if (Bytes != sizeof (Expected) - 1 || CompareMem (Contents, Expected, Bytes) != 0) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Status = gBS->CalculateCrc32 (Contents, Bytes, &Crc);
  if (EFI_ERROR (Status)) { goto Done; }
  Receipt->FileBytes = Bytes;
  Receipt->FileCrc = Crc;
  Receipt->Checks |= 2;

  Receipt->CodeAddress = (UINTN)UefiMain;
  Receipt->DataAddress = (UINTN)&mWritableMarker;
  Receipt->StackAddress = (UINTN)&Contents;
  if (EFI_ERROR (Memory->GetMemoryAttributes (Memory, (UINTN)UefiMain & ~4095ULL, 4096, &Receipt->CodeAttributes)) ||
      EFI_ERROR (Memory->GetMemoryAttributes (Memory, (UINTN)&mWritableMarker & ~4095ULL, 4096, &Receipt->DataAttributes)) ||
      EFI_ERROR (Memory->GetMemoryAttributes (Memory, (UINTN)&Contents & ~4095ULL, 4096, &Receipt->StackAttributes)) ||
      (Receipt->CodeAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_RO ||
      (Receipt->DataAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP ||
      (Receipt->StackAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP ||
      mWritableMarker != N976N_BOOT_RECEIPT_MAGIC) {
    Status = EFI_SECURITY_VIOLATION; goto Done;
  }
  Receipt->Checks |= 4;
  Status = gST->ConOut->OutputString (gST->ConOut,
    L"\r\nSEC67 EFI application PASS\r\nBootInfo.txt read from the loaded device\r\n");
  if (!EFI_ERROR (Status)) { Receipt->Checks |= 16; }

Done:
  if (File != NULL) {
    EFI_STATUS CloseStatus = File->Close (File);
    if (!EFI_ERROR (Status)) { Status = CloseStatus; }
  }
  if (Root != NULL) {
    EFI_STATUS CloseStatus = Root->Close (Root);
    if (!EFI_ERROR (Status)) { Status = CloseStatus; }
  }
  Receipt->Status = Status;
  return Status;
}
