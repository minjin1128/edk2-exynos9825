/** @file
  Bounded read-only RAM BlockIo adapter. Upstream DXE supplies DiskIo and FAT.
  The immutable FV resource is copied once into dedicated data pages, checked,
  made RO/XN, then exposed. No physical controller or storage write is involved.
  SPDX-License-Identifier: MIT
**/
#include <PiDxe.h>
#include <N976nBootMedia.h>
#include <N976nBootMediaManifest.h>
#include <N976nPlatform.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DxeServicesLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>
#include <Protocol/DevicePath.h>
#include <Protocol/MemoryAttribute.h>

#pragma pack (1)
typedef struct {
  MEMMAP_DEVICE_PATH Memory;
  EFI_DEVICE_PATH_PROTOCOL End;
} N976N_MEDIA_DEVICE_PATH;
#pragma pack ()

STATIC EFI_HANDLE mHandle;
STATIC EFI_BLOCK_IO_PROTOCOL mBlockIo;
STATIC EFI_BLOCK_IO_MEDIA mMedia = {
  0x4539, FALSE, TRUE, FALSE, TRUE, FALSE, 512, 1,
  N976N_BOOT_MEDIA_BYTES / 512 - 1, 0, 1, 1
};
STATIC N976N_MEDIA_DEVICE_PATH mDevicePath = {
  {{HARDWARE_DEVICE_PATH, HW_MEMMAP_DP, {sizeof (MEMMAP_DEVICE_PATH), 0}},
    EfiBootServicesData, 0, 0},
  {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE,
    {sizeof (EFI_DEVICE_PATH_PROTOCOL), 0}}
};
N976N_BOOT_MEDIA_PROTOCOL mN976nBootMedia = {
  N976N_BOOT_MEDIA_MAGIC, 1, sizeof (N976N_BOOT_MEDIA_PROTOCOL),
  0, N976N_BOOT_MEDIA_BYTES, 0, 0, 0
};

STATIC EFI_STATUS Request (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                          EFI_LBA Lba, UINTN Bytes, CONST VOID *Buffer)
{
  if (This != &mBlockIo || mN976nBootMedia.Checks != N976N_BOOT_MEDIA_CHECKS) {
    return EFI_INVALID_PARAMETER;
  }
  if (MediaId != mMedia.MediaId) { return EFI_MEDIA_CHANGED; }
  if (Bytes == 0) { return EFI_SUCCESS; }
  if ((Bytes & 511) != 0) { return EFI_BAD_BUFFER_SIZE; }
  if (Buffer == NULL || (UINTN)Buffer > MAX_UINTN - Bytes ||
      Lba > mMedia.LastBlock || Bytes / 512 > mMedia.LastBlock - Lba + 1) {
    return EFI_INVALID_PARAMETER;
  }
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI N976nMediaRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN BufferSize, VOID *Buffer)
{
  EFI_STATUS Status = Request (This, MediaId, Lba, BufferSize, Buffer);
  if (EFI_ERROR (Status) || BufferSize == 0) { return Status; }
  /* Reject writes through a read destination alias of the RO backing. */
  if ((UINTN)Buffer < mN976nBootMedia.Base + mN976nBootMedia.Bytes &&
      mN976nBootMedia.Base < (UINTN)Buffer + BufferSize) {
    return EFI_ACCESS_DENIED;
  }
  CopyMem (Buffer, (VOID *)(UINTN)(mN976nBootMedia.Base + Lba * 512), BufferSize);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI N976nMediaWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN BufferSize, VOID *Buffer)
{
  EFI_STATUS Status = Request (This, MediaId, Lba, BufferSize, Buffer);
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}

EFI_STATUS EFIAPI N976nMediaReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended)
{
  (VOID)Extended;
  return This == &mBlockIo && mN976nBootMedia.Checks == N976N_BOOT_MEDIA_CHECKS ?
    EFI_SUCCESS : EFI_INVALID_PARAMETER;
}

EFI_STATUS EFIAPI N976nMediaFlush (EFI_BLOCK_IO_PROTOCOL *This)
{
  return N976nMediaReset (This, FALSE);
}

EFI_STATUS EFIAPI N976nBootMediaEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory;
  EFI_PHYSICAL_ADDRESS Base = 0;
  VOID *Raw = NULL;
  UINTN Bytes = 0;
  UINT32 Crc;
  UINT64 Attributes;
  BOOLEAN Protected = FALSE;
  (VOID)ImageHandle; (VOID)SystemTable;
  if (mHandle != NULL) { return EFI_ALREADY_STARTED; }
  VOID *Hob = GetFirstGuidHob (&gN976nPlatformHandoffGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (N976N_PLATFORM_HANDOFF)) {
    return EFI_COMPROMISED_DATA;
  }
  CONST N976N_PLATFORM_HANDOFF *Handoff = GET_GUID_HOB_DATA (Hob);
  if (Handoff->Magic != N976N_PLATFORM_HANDOFF_MAGIC ||
      Handoff->Version != N976N_PLATFORM_ABI_VERSION || Handoff->Size != sizeof (*Handoff) ||
      Handoff->Reserved != 0 || Handoff->Profile > 1 ||
      Handoff->HeapBase != 0x92001000ULL || Handoff->HeapSize != 0x03FDD000ULL) {
    return EFI_COMPROMISED_DATA;
  }
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&Memory);
  if (EFI_ERROR (Status)) { return Status; }
  Status = GetSectionFromFv (&gN976nBootMediaFileGuid, EFI_SECTION_RAW, 0, &Raw, &Bytes);
  if (EFI_ERROR (Status)) { return Status; }
  if (Bytes != N976N_BOOT_MEDIA_BYTES || Raw == NULL) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Status = gBS->CalculateCrc32 (Raw, Bytes, &Crc);
  if (EFI_ERROR (Status) || Crc != N976N_BOOT_MEDIA_EXPECTED_CRC32) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  mN976nBootMedia.Checks = 1;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData,
                              EFI_SIZE_TO_PAGES (Bytes), &Base);
  if (EFI_ERROR (Status)) { goto Done; }
  if ((Base & EFI_PAGE_MASK) != 0 || Base < Handoff->HeapBase ||
      Base > Handoff->HeapBase + Handoff->HeapSize - Bytes) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Status = Memory->GetMemoryAttributes (Memory, Base, Bytes, &Attributes);
  if (EFI_ERROR (Status) || Attributes != EFI_MEMORY_XP) {
    Status = EFI_SECURITY_VIOLATION; goto Done;
  }
  CopyMem ((VOID *)(UINTN)Base, Raw, Bytes);
  if (CompareMem ((VOID *)(UINTN)Base, Raw, Bytes) != 0) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  mN976nBootMedia.Checks |= 2;
  /* Set the cleanup flag before the operation: failure may mean partial RO. */
  Protected = TRUE;
  Status = Memory->SetMemoryAttributes (Memory, Base, Bytes, EFI_MEMORY_RO | EFI_MEMORY_XP);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = Memory->GetMemoryAttributes (Memory, Base, Bytes, &Attributes);
  if (EFI_ERROR (Status) || Attributes != (EFI_MEMORY_RO | EFI_MEMORY_XP)) {
    Status = EFI_SECURITY_VIOLATION; goto Done;
  }
  mN976nBootMedia.Checks |= 4;
  mN976nBootMedia.Base = Base;
  mN976nBootMedia.Attributes = Attributes;
  mN976nBootMedia.Crc32 = Crc;
  /* Describe the admitted RAM disk using the standard hardware memory-map
   * node. The end is inclusive; the preceding owned-range check bounds it.
   * Bind addresses only after the backing has passed integrity and RO/XN. */
  mDevicePath.Memory.StartingAddress = Base;
  mDevicePath.Memory.EndingAddress = Base + Bytes - 1;
  mBlockIo.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3;
  mBlockIo.Media = &mMedia;
  mBlockIo.Reset = N976nMediaReset;
  mBlockIo.ReadBlocks = N976nMediaRead;
  mBlockIo.WriteBlocks = N976nMediaWrite;
  mBlockIo.FlushBlocks = N976nMediaFlush;
  /* Complete the state before protocol notifications can invoke BlockIo. */
  mN976nBootMedia.Checks |= 8;
  Status = gBS->InstallMultipleProtocolInterfaces (&mHandle,
             &gEfiDevicePathProtocolGuid, &mDevicePath,
             &gEfiBlockIoProtocolGuid, &mBlockIo,
             &gN976nBootMediaProtocolGuid, &mN976nBootMedia, NULL);
Done:
  if (Raw != NULL) { FreePool (Raw); }
  if (EFI_ERROR (Status)) {
    mN976nBootMedia.Checks = 0;
    mN976nBootMedia.Base = 0;
    mDevicePath.Memory.StartingAddress = 0;
    mDevicePath.Memory.EndingAddress = 0;
    if (Base != 0) {
      /* If an attribute rollback fails, retain unreachable NX pages rather
       * than giving the allocator pages that could still be read-only. */
      EFI_STATUS Rollback = Protected ?
        Memory->ClearMemoryAttributes (Memory, Base, Bytes, EFI_MEMORY_RO) : EFI_SUCCESS;
      if (!EFI_ERROR (Rollback)) {
        Rollback = Memory->GetMemoryAttributes (Memory, Base, Bytes, &Attributes);
        if (!EFI_ERROR (Rollback) && Attributes == EFI_MEMORY_XP) {
          gBS->FreePages (Base, EFI_SIZE_TO_PAGES (Bytes));
        }
      }
    }
  }
  return Status;
}
