/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC56: physical BOOT -> exact sealed FAT subextent -> upstream FAT -> bounded file streaming.
 * NTDEV 6e2cacf15f6b supplies the standard storage/filesystem composition.
 * UpstreamFat headers are unchanged EDK2 870158586f14dbf9d57e312ea6ea87141a1b0699.
 * They describe the cache owned by that exact, independently admitted driver;
 * no FAT algorithm is reimplemented and no arbitrary heap/DMA destination is
 * admitted. The existing RAM FAT is an integrity reference, never read fallback.
 */
#include <N976nUfsFileSystem.h>
#include <N976nUfsService.h>
#include <N976nUfsImage.h>
#include <N976nWindowsBoot.h>
#include <N976nHighRam.h>
#include <N976nUfs.h>
#include <Library/MemoryAllocationLib.h>
#include <N976nBootMedia.h>
#include <N976nBootMediaManifest.h>
#include <Library/DevicePathLib.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include "UpstreamFat/Fat.h"

#define FS_MEDIA_ID 0x533536U
#define FS_GUARD 64U
#define FS_CACHE_BYTES (8192U + 64U * 8192U)
#define FS_FILE_BYTES 16384U
#define FS_TAIL_BYTES 4093U
#define FS_MAX_REQUEST 16384U
#define FS_BLOCK_BYTES 512U

/* The transport owns every returned byte. This module only copies from it
 * after comparison with the immutable FV and independent CPU range checks. */
extern EFI_STATUS N976nReadUfsOwned (UINT64 Offset, UINTN Bytes, CONST UINT8 **Data);
extern UINTN N976nUfsOwnedBudget (VOID);
extern BOOLEAN N976nUfsOwnedRangeAllowed (UINT64 Offset, UINTN Bytes);
extern BOOLEAN N976nUfsCpuRangeAllowed (CONST VOID *Buffer, UINTN Bytes);

typedef struct {
  UINT8 Before[FS_GUARD];
  UINT8 File[FS_FILE_BYTES];
  UINT8 Between[FS_GUARD];
  UINT64 Info[32];
  UINT8 After[FS_GUARD];
} FS_STORAGE;

volatile N976N_FILE_SYSTEM_REPORT mN976nFileSystemReport;
STATIC FS_STORAGE mFsStorage;
STATIC EFI_HANDLE mFsHandle;
typedef struct {
  VENDOR_DEVICE_PATH Vendor;
  EFI_DEVICE_PATH_PROTOCOL End;
} FS_DEVICE_PATH;
STATIC CONST FS_DEVICE_PATH mFsExpectedPath = {
  {{HARDWARE_DEVICE_PATH, HW_VENDOR_DP, {sizeof (VENDOR_DEVICE_PATH), 0}},
   {0x2ed59155,0x9c71,0x4c25,{0x94,0x5a,0x97,0x6e,0x55,0x00,0x00,0x01}}},
  {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {END_DEVICE_PATH_LENGTH, 0}}
};
STATIC FS_DEVICE_PATH mFsPath;
/* A distinct mapped-controller identity, not a fabricated GPT partition or
 * RAM disk. The final standard UFS node identifies the physical LUN backing
 * this bounded byte-oriented logical view. Geometry is the exposed view. */
#pragma pack (1)
typedef struct {
  VENDOR_DEVICE_PATH Vendor;
  UINT64 BootStart, BootBlocks, FatOffset, FatBytes;
  UFS_DEVICE_PATH Ufs;
  EFI_DEVICE_PATH_PROTOCOL End;
} FS_PARENT_DEVICE_PATH;
typedef struct {
  VENDOR_DEVICE_PATH Vendor;
  UINT64 BootStart, BootBlocks, FatOffset, FatBytes;
  UFS_DEVICE_PATH Ufs;
  HARDDRIVE_DEVICE_PATH Hd;
  EFI_DEVICE_PATH_PROTOCOL End;
} FS_RUN_DEVICE_PATH;
#pragma pack ()
STATIC FS_RUN_DEVICE_PATH mFsRunPath, mFsRunExpectedPath;
STATIC FS_PARENT_DEVICE_PATH mFsParentPath, mFsParentExpectedPath;
STATIC EFI_HANDLE mFsParentHandle;
STATIC EFI_BLOCK_IO_PROTOCOL mFsParentBlock;
STATIC EFI_BLOCK_IO_MEDIA mFsParentMedia;
STATIC struct { UINT8 Before[64], Sector[512], After[64]; } mFsMbr;
STATIC UINT8 mFsMbrExpected[512];
STATIC BOOLEAN mFsParentBusy, mFsMbrReady;
STATIC UINT64 mFsParentReads, mFsParentMbrReads;
STATIC BOOLEAN mFsRunMode;
volatile N976N_FILE_RUN_REPORT mN976nFileRunReport;
volatile UINT64 mN976nHighRamUseReport[8];
STATIC UINT64 mFsMemoryMap[8192];
STATIC struct { CONST VOID *Buffer; UINTN Bytes; BOOLEAN Active; } mFsLease;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mFsMemory;

STATIC EFI_BLOCK_IO_PROTOCOL mFsBlock;
STATIC EFI_DISK_IO_PROTOCOL mFsDisk;
STATIC EFI_BLOCK_IO_MEDIA mFsMedia;
STATIC EFI_DRIVER_BINDING_PROTOCOL *mFsDriver;
STATIC CONST N976N_PLATFORM_HANDOFF *mFsHandoff;
STATIC CONST UINT8 *mFsSource;
STATIC FAT_VOLUME *mFsVolume;
STATIC UINT8 *mFsCache;
STATIC BOOLEAN mFsEntered, mFsScope, mFsGate, mFsBusy, mFsMount;
STATIC BOOLEAN mFsStorageReady, mFsMounted, mFsFailed;
STATIC EFI_GUID mFatFileGuid = {0x961578fe,0xb6b7,0x44c3,{0xaf,0x35,0x6b,0xc7,0x05,0xcd,0x2b,0x1f}};
STATIC EFI_GUID mFfs2Guid = {0x8c8ce578,0x8a3d,0x4f1c,{0x99,0x35,0x89,0x61,0x85,0xc3,0x2d,0xd3}};

STATIC UINT64 FsLe (CONST UINT8 *P, UINTN N) {
  UINT64 V = 0;
  for (UINTN I = 0; I < N; ++I) { V |= (UINT64)P[I] << (8 * I); }
  return V;
}
__attribute__((noinline)) VOID EFIAPI N976nHighRamReadCheckpoint (VOID) {
  MemoryFence ();
}
STATIC BOOLEAN FsSpan (UINT64 P, UINT64 N, UINT64 Base, UINT64 Bytes) {
  return N != 0 && Bytes <= MAX_UINT64 - Base && P >= Base &&
    P - Base <= Bytes && N <= Bytes - (P - Base);
}
STATIC BOOLEAN FsIn (CONST VOID *P, UINTN N, CONST VOID *Base, UINTN Bytes) {
  return P != NULL && FsSpan ((UINTN)P, N, (UINTN)Base, Bytes);
}
STATIC BOOLEAN FsOverlaps (CONST VOID *A, UINTN An, CONST VOID *B, UINTN Bn) {
  UINTN X = (UINTN)A, Y = (UINTN)B;
  return An > MAX_UINTN - X || Bn > MAX_UINTN - Y || (X < Y + Bn && Y < X + An);
}
STATIC BOOLEAN FsControlOverlap (CONST VOID *P, UINTN N) {
  return FsOverlaps (P, N, &mFsStorage, sizeof (mFsStorage)) ||
    FsOverlaps (P, N, &mFsBlock, sizeof (mFsBlock)) ||
    FsOverlaps (P, N, &mFsDisk, sizeof (mFsDisk)) ||
    FsOverlaps (P, N, &mFsMedia, sizeof (mFsMedia)) ||
    FsOverlaps (P, N, &mFsPath, sizeof (mFsPath)) ||
    FsOverlaps (P, N, &mFsRunPath, sizeof (mFsRunPath)) ||
    FsOverlaps (P, N, &mFsParentPath, sizeof (mFsParentPath)) ||
    FsOverlaps (P, N, &mFsParentExpectedPath, sizeof (mFsParentExpectedPath)) ||
    FsOverlaps (P, N, &mFsParentBlock, sizeof (mFsParentBlock)) ||
    FsOverlaps (P, N, &mFsParentMedia, sizeof (mFsParentMedia)) ||
    FsOverlaps (P, N, &mFsMbr, sizeof (mFsMbr)) ||
    FsOverlaps (P, N, &mFsMbrExpected, sizeof (mFsMbrExpected)) ||
    FsOverlaps (P, N, &mFsRunExpectedPath, sizeof (mFsRunExpectedPath)) ||
    FsOverlaps (P, N, &mFsLease, sizeof (mFsLease)) ||
    FsOverlaps (P, N, mFsMemoryMap, sizeof (mFsMemoryMap)) ||
    FsOverlaps (P, N, (CONST VOID *)&mN976nFileRunReport, sizeof (mN976nFileRunReport)) ||
    FsOverlaps (P, N, (CONST VOID *)mN976nHighRamUseReport, sizeof (mN976nHighRamUseReport)) ||
    FsOverlaps (P, N, (CONST VOID *)&mN976nFileSystemReport, sizeof (mN976nFileSystemReport)) ||
    (mFsHandoff != NULL && FsOverlaps (P, N, mFsHandoff, sizeof (*mFsHandoff))) ||
    (mFsDriver != NULL && FsOverlaps (P, N, mFsDriver, sizeof (*mFsDriver)));
}
STATIC VOID *FsPath (VOID) { return mFsRunMode ? (VOID *)&mFsRunPath : (VOID *)&mFsPath; }
STATIC UINTN FsPathBytes (VOID) { return mFsRunMode ? sizeof (mFsRunPath) : sizeof (mFsPath); }
STATIC BOOLEAN FsPathValid (VOID) {
  VOID *Path = NULL;
  return mFsHandle != NULL && N976nUfsCpuRangeAllowed (FsPath (), FsPathBytes ()) &&
    CompareMem (FsPath (), mFsRunMode ? (VOID *)&mFsRunExpectedPath : (VOID *)&mFsExpectedPath,
                FsPathBytes ()) == 0 &&
    !EFI_ERROR (gBS->HandleProtocol (mFsHandle, &gEfiDevicePathProtocolGuid, &Path)) &&
    Path == FsPath ();
}
STATIC BOOLEAN FsPrepareRunPath (VOID) {
  if (mN976nServiceReport.PartitionBlocks == 0 || mN976nUfsReport.Lun > 7 ||
      mN976nServiceReport.PartitionStart > MAX_UINT64 / 4096 ||
      mN976nServiceReport.PartitionBlocks > MAX_UINT64 / 4096 ||
      mN976nServiceReport.PartitionStart > MAX_UINT64 - mN976nServiceReport.PartitionBlocks ||
      !FsSpan (mN976nFileSystemReport.VolumeOffset, N976N_BOOT_MEDIA_BYTES, 0,
               mN976nServiceReport.PartitionBlocks * 4096)) { return FALSE; }
  if (!N976nUfsCpuRangeAllowed (&mFsRunPath, sizeof (mFsRunPath)) ||
      !N976nUfsCpuRangeAllowed (&mFsRunExpectedPath, sizeof (mFsRunExpectedPath)) ||
      !N976nUfsCpuRangeAllowed (&mFsParentPath, sizeof (mFsParentPath)) ||
      !N976nUfsCpuRangeAllowed (&mFsParentExpectedPath, sizeof (mFsParentExpectedPath)) ||
      !N976nUfsCpuRangeAllowed (&mFsParentBlock, sizeof (mFsParentBlock)) ||
      !N976nUfsCpuRangeAllowed (&mFsParentMedia, sizeof (mFsParentMedia)) ||
      !N976nUfsCpuRangeAllowed (&mFsMbr, sizeof (mFsMbr)) ||
      !N976nUfsCpuRangeAllowed (mFsMbrExpected, sizeof (mFsMbrExpected))) { return FALSE; }
  ZeroMem (&mFsRunExpectedPath, sizeof (mFsRunExpectedPath));
  mFsRunExpectedPath.Vendor.Header.Type = HARDWARE_DEVICE_PATH;
  mFsRunExpectedPath.Vendor.Header.SubType = HW_VENDOR_DP;
  mFsRunExpectedPath.Vendor.Header.Length[0] = sizeof (VENDOR_DEVICE_PATH) + 32;
  CONST EFI_GUID Guid = {0x2ed59156,0x9c71,0x4c25,{0x94,0x5a,0x97,0x6e,0x56,0x00,0x00,0x01}};
  CopyMem (&mFsRunExpectedPath.Vendor.Guid, &Guid, sizeof (Guid));
  mFsRunExpectedPath.BootStart = mN976nServiceReport.PartitionStart;
  mFsRunExpectedPath.BootBlocks = mN976nServiceReport.PartitionBlocks;
  mFsRunExpectedPath.FatOffset = mN976nFileSystemReport.VolumeOffset;
  mFsRunExpectedPath.FatBytes = N976N_BOOT_MEDIA_BYTES;
  mFsRunExpectedPath.Ufs.Header.Type = MESSAGING_DEVICE_PATH;
  mFsRunExpectedPath.Ufs.Header.SubType = MSG_UFS_DP;
  mFsRunExpectedPath.Ufs.Header.Length[0] = sizeof (UFS_DEVICE_PATH);
  mFsRunExpectedPath.Ufs.Lun = (UINT8)mN976nUfsReport.Lun;
  mFsRunExpectedPath.End.Type = END_DEVICE_PATH_TYPE;
  mFsRunExpectedPath.End.SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE;
  mFsRunExpectedPath.End.Length[0] = END_DEVICE_PATH_LENGTH;
  CopyMem (&mFsParentExpectedPath, &mFsRunExpectedPath, sizeof (mFsParentExpectedPath) - 4);
  CopyMem (&mFsParentExpectedPath.End, &mFsRunExpectedPath.End, 4);
  CopyMem (&mFsParentPath, &mFsParentExpectedPath, sizeof (mFsParentPath));
  UINT32 Signature = 0;
  if (EFI_ERROR (gBS->CalculateCrc32 (&mFsParentExpectedPath, sizeof (mFsParentExpectedPath) - 4,
                                     &Signature)) || Signature == 0) { return FALSE; }
  HARDDRIVE_DEVICE_PATH *Hd = &mFsRunExpectedPath.Hd;
  Hd->Header.Type = MEDIA_DEVICE_PATH; Hd->Header.SubType = MEDIA_HARDDRIVE_DP;
  Hd->Header.Length[0] = sizeof (*Hd); Hd->PartitionNumber = 1;
  Hd->PartitionStart = 1; Hd->PartitionSize = N976N_BOOT_MEDIA_BYTES / FS_BLOCK_BYTES;
  CopyMem (Hd->Signature, &Signature, sizeof (Signature));
  Hd->MBRType = 1; Hd->SignatureType = 1;
  CopyMem (&mFsRunPath, &mFsRunExpectedPath, sizeof (mFsRunPath));
  ZeroMem (mFsMbrExpected, sizeof (mFsMbrExpected));
  CopyMem (mFsMbrExpected + 0x1B8, &Signature, 4);
  mFsMbrExpected[0x1BE + 4] = 1; /* FAT12, no legacy executable boot code. */
  mFsMbrExpected[0x1BE + 8] = 1;
  UINT32 Sectors = N976N_BOOT_MEDIA_BYTES / FS_BLOCK_BYTES;
  CopyMem (mFsMbrExpected + 0x1BE + 12, &Sectors, 4);
  mFsMbrExpected[510] = 0x55; mFsMbrExpected[511] = 0xAA;
  SetMem (&mFsMbr, sizeof (mFsMbr), 0xA5);
  CopyMem (mFsMbr.Sector, mFsMbrExpected, sizeof (mFsMbr.Sector)); mFsMbrReady = TRUE;
  return TRUE;
}
STATIC BOOLEAN FsGuards (VOID) {
  if (!mFsStorageReady) { return FALSE; }
  if (mFsRunMode && (!mFsMbrReady || CompareMem (mFsMbr.Sector, mFsMbrExpected, 512))) { return FALSE; }
  for (UINTN I = 0; I < FS_GUARD; ++I) {
    if (mFsStorage.Before[I] != 0xA5 || mFsStorage.Between[I] != 0xA5 ||
        mFsStorage.After[I] != 0xA5 || (mFsRunMode &&
        (mFsMbr.Before[I] != 0xA5 || mFsMbr.After[I] != 0xA5))) { return FALSE; }
  }
  return TRUE;
}
STATIC EFI_STATUS FsFail (EFI_STATUS Status, UINT64 Reason) {
  if (!mFsFailed) {
    mFsFailed = TRUE; mN976nFileSystemReport.Status = Status;
    mN976nFileSystemReport.Reason = Reason;
  }
  return Status;
}
STATIC BOOLEAN FsHandoffValid (CONST N976N_PLATFORM_HANDOFF *H) {
  return H != NULL && H->Magic == N976N_PLATFORM_HANDOFF_MAGIC &&
    H->Version == N976N_PLATFORM_ABI_VERSION && H->Size == sizeof (*H) && !H->Reserved &&
    H->Profile <= 1 && H->FirmwareSize == 0x900000 && !(H->FirmwareBase & EFI_PAGE_MASK) &&
    H->ImageSize <= 0xC00000 && FsSpan (H->FirmwareBase, H->FirmwareSize, H->ImageBase, H->ImageSize) &&
    FsSpan (H->StackBase, H->StackSize, H->ImageBase, H->ImageSize) &&
    H->HeapSize != 0 && H->HeapSize <= MAX_UINT64 - H->HeapBase;
}

/* Reuses the sealed profile's bounded FFS/RAW layout from BootstrapImagePolicy.
 * Source media may occur only once. No byte-pattern scan or guessed offset. */
EFI_STATUS N976nLocateUfsReferenceMedia (CONST N976N_PLATFORM_HANDOFF *H, CONST UINT8 **Source) {
  CONST UINT8 *P;
  UINTN N, Header, O, Ext, Sum = 0, Total = 0, I;
  CONST UINT8 *Found = NULL;
  if (Source == NULL || !FsHandoffValid (H)) {
    return EFI_COMPROMISED_DATA;
  }
  P = (CONST VOID *)(UINTN)H->FirmwareBase; N = (UINTN)H->FirmwareSize;
  if (FsLe (P + 32, 8) != N || FsLe (P + 40, 4) != 0x4856465F || P[55] != 2 ||
      P[54] || CompareMem (P + 16, &mFfs2Guid, 16) || !(FsLe (P + 44, 4) & 0x800)) {
    return EFI_VOLUME_CORRUPTED;
  }
  Header = (UINTN)FsLe (P + 48, 2);
  if (Header < 72 || Header > N || (Header & 7)) { return EFI_VOLUME_CORRUPTED; }
  for (I = 0; I < Header; I += 2) { Sum += (UINTN)FsLe (P + I, 2); }
  if (Sum & 0xFFFF) { return EFI_VOLUME_CORRUPTED; }
  for (I = 56; I + 8 <= Header; I += 8) {
    UINTN Count = (UINTN)FsLe (P + I, 4), Size = (UINTN)FsLe (P + I + 4, 4);
    if (Count == 0 && Size == 0) { break; }
    if (!Count || !Size || Count > N / Size || Count * Size > N - Total) { return EFI_VOLUME_CORRUPTED; }
    Total += Count * Size;
  }
  if (I + 8 > Header || Total != N) { return EFI_VOLUME_CORRUPTED; }
  O = Header; Ext = (UINTN)FsLe (P + 52, 2);
  if (Ext) {
    if (!FsSpan (Ext, 20, 0, N)) { return EFI_VOLUME_CORRUPTED; }
    UINTN Size = (UINTN)FsLe (P + Ext + 16, 4);
    if (Size < 20 || !FsSpan (Ext, Size, 0, N) || Ext + Size < Header) { return EFI_VOLUME_CORRUPTED; }
    O = ALIGN_VALUE (Ext + Size, 8);
  }
  while (O < N) {
    if (N - O < 24 || (FsLe (P + O, 8) == MAX_UINT64 && FsLe (P + O + 8, 8) == MAX_UINT64 &&
                      FsLe (P + O + 16, 8) == MAX_UINT64)) {
      for (; O < N; ++O) { if (P[O] != 0xFF) { return EFI_VOLUME_CORRUPTED; } }
      break;
    }
    UINTN Size = (UINTN)FsLe (P + O + 20, 3);
    if (Size < 24 || Size == 0xFFFFFF || Size > N - O || ALIGN_VALUE (O + Size, 8) > N ||
        (P[O + 19] & 1) || ((~P[O + 23]) & 0xFF) != 7) { return EFI_VOLUME_CORRUPTED; }
    Sum = 0;
    for (I = 0; I < 24; ++I) { if (I != 17 && I != 23) { Sum += P[O + I]; } }
    if (Sum & 0xFF) { return EFI_VOLUME_CORRUPTED; }
    if (P[O + 19] & 0x40) {
      Sum = P[O + 17]; for (I = 24; I < Size; ++I) { Sum += P[O + I]; }
      if (Sum & 0xFF) { return EFI_VOLUME_CORRUPTED; }
    } else if (P[O + 17] != 0xAA) { return EFI_VOLUME_CORRUPTED; }
    if (CompareMem (P + O, &gN976nBootMediaFileGuid, sizeof (EFI_GUID)) == 0) {
      if (Found != NULL || P[O + 18] != 2) { return EFI_VOLUME_CORRUPTED; }
      for (UINTN S = O + 24; S < O + Size; ) {
        if (O + Size - S < 4) { return EFI_VOLUME_CORRUPTED; }
        UINTN Z = (UINTN)FsLe (P + S, 3);
        if (Z < 4 || Z == 0xFFFFFF || Z > O + Size - S) { return EFI_VOLUME_CORRUPTED; }
        if (P[S + 3] == 0x19) {
          if (Found != NULL || Z - 4 != N976N_BOOT_MEDIA_BYTES) { return EFI_VOLUME_CORRUPTED; }
          Found = P + S + 4;
        } else if (P[S + 3] != 0x15 && P[S + 3] != 0x14) { return EFI_UNSUPPORTED; }
        S = ALIGN_VALUE (S + Z, 4) > O + Size ? S + Z : ALIGN_VALUE (S + Z, 4);
      }
    }
    O = ALIGN_VALUE (O + Size, 8);
  }
  if (Found == NULL) { return EFI_NOT_FOUND; }
  *Source = Found; return EFI_SUCCESS;
}

STATIC BOOLEAN FsCacheValid (VOID) {
  FAT_VOLUME *V = mFsVolume;
  if (V == NULL || mFsCache == NULL || mFsHandoff == NULL ||
      !FsSpan ((UINTN)V, sizeof (*V), mFsHandoff->HeapBase, mFsHandoff->HeapSize) ||
      !FsSpan ((UINTN)mFsCache, FS_CACHE_BYTES, mFsHandoff->HeapBase, mFsHandoff->HeapSize) ||
      FsOverlaps (V, sizeof (*V), mFsCache, FS_CACHE_BYTES) ||
      FsControlOverlap (V, sizeof (*V)) || FsControlOverlap (mFsCache, FS_CACHE_BYTES) ||
      !N976nUfsCpuRangeAllowed (V, sizeof (*V)) ||
      V->Signature != FAT_VOLUME_SIGNATURE || V->Handle != mFsHandle || !V->Valid || V->DiskError ||
      V->BlockIo != &mFsBlock || V->DiskIo != &mFsDisk || V->DiskIo2 != NULL ||
      V->MediaId != FS_MEDIA_ID || !V->ReadOnly || V->FatType != Fat12 ||
      V->VolumeSize != N976N_BOOT_MEDIA_BYTES || V->CacheBuffer != mFsCache ||
      V->DiskCache[CacheFat].CacheBase != mFsCache || V->DiskCache[CacheData].CacheBase != mFsCache + 8192 ||
      V->DiskCache[CacheFat].PageAlignment != 13 || V->DiskCache[CacheData].PageAlignment != 13 ||
      V->DiskCache[CacheFat].GroupMask != 0 || V->DiskCache[CacheData].GroupMask != 63 ||
      V->DiskCache[CacheFat].BlockSize != FS_BLOCK_BYTES || V->DiskCache[CacheData].BlockSize != FS_BLOCK_BYTES ||
      V->FatDirty || V->DiskCache[CacheFat].Dirty || V->DiskCache[CacheData].Dirty) { return FALSE; }
  return N976nUfsCpuRangeAllowed (mFsCache, FS_CACHE_BYTES);
}
/* Runtime clients borrow exactly one synchronous CPU output span. A fresh
 * UEFI memory map must cover the entire span with allocated LoaderCode/Data.
 * A loader memory type does not grant execution: every borrowed page must
 * still be exactly RW-XN. Executable/RO pages, free memory, BootServicesData,
 * firmware, staging and all controls are refused.
 * These buffers are never passed to DMA. No allocation-wide heap allowlist. */
STATIC BOOLEAN FsBorrowAllowed (CONST VOID *Buffer, UINTN Bytes) {
  UINTN MapBytes = sizeof (mFsMemoryMap), Key = 0, DescriptorBytes = 0;
  UINT32 Version = 0; UINT64 Attributes = 0;
  BOOLEAN Low = mFsHandoff != NULL &&
    FsSpan ((UINTN)Buffer, Bytes, mFsHandoff->HeapBase, mFsHandoff->HeapSize);
  if (!mFsRunMode || !N976nUfsExecutionActive () || mFsHandoff == NULL ||
      Buffer == NULL || Bytes == 0 || Bytes > N976N_BOOT_MEDIA_BYTES + 512 ||
      FsControlOverlap (Buffer, Bytes) ||
      (mFsVolume && FsOverlaps (Buffer, Bytes, mFsVolume, sizeof (*mFsVolume))) ||
      (mFsCache && FsOverlaps (Buffer, Bytes, mFsCache, FS_CACHE_BYTES)) ||
      N976nUfsImageSourceOverlaps (Buffer, Bytes) || mFsMemory == NULL ||
      !(Low ? N976nUfsCpuRangeAllowed (Buffer, Bytes) :
        N976nHighRamOwnedCpuRange (Buffer, Bytes, (1U << EfiLoaderCode) | (1U << EfiLoaderData))) ||
      EFI_ERROR (mFsMemory->GetMemoryAttributes (mFsMemory, (UINTN)Buffer, Bytes, &Attributes)) ||
      Attributes != EFI_MEMORY_XP || gBS->GetMemoryMap == NULL ||
      !N976nUfsCpuRangeAllowed (mFsMemoryMap, sizeof (mFsMemoryMap)) ||
      EFI_ERROR (gBS->GetMemoryMap (&MapBytes, (VOID *)mFsMemoryMap, &Key, &DescriptorBytes, &Version)) ||
      DescriptorBytes < sizeof (EFI_MEMORY_DESCRIPTOR) || MapBytes > sizeof (mFsMemoryMap) ||
      MapBytes == 0 || MapBytes % DescriptorBytes || Version != EFI_MEMORY_DESCRIPTOR_VERSION) {
    return FALSE;
  }
  UINT64 At = (UINTN)Buffer, End = At + Bytes;
  while (At < End) {
    UINT64 Next = At, Boundary = End; UINTN Matches = 0;
    for (UINTN O = 0; O < MapBytes; O += DescriptorBytes) {
      EFI_MEMORY_DESCRIPTOR *D = (VOID *)((UINT8 *)mFsMemoryMap + O);
      if (D->NumberOfPages == 0 || D->NumberOfPages > MAX_UINT64 / EFI_PAGE_SIZE ||
          D->PhysicalStart > MAX_UINT64 - D->NumberOfPages * EFI_PAGE_SIZE) { return FALSE; }
      UINT64 Top = D->PhysicalStart + D->NumberOfPages * EFI_PAGE_SIZE;
      if (D->PhysicalStart > At && D->PhysicalStart < Boundary) { Boundary = D->PhysicalStart; }
      if (At >= D->PhysicalStart && At < Top) {
        if (D->Type != EfiLoaderData && D->Type != EfiLoaderCode) { return FALSE; }
        ++Matches; Next = MIN (Top, End);
      }
    }
    Next = MIN (Next, Boundary);
    if (Matches != 1 || Next <= At) { return FALSE; }
    At = Next;
  }
  return TRUE;
}
STATIC BOOLEAN FsStaticDestination (VOID *Buffer, UINTN Bytes, UINT64 Offset) {
  BOOLEAN Owned = FALSE;
  if (mFsMount) {
    Owned = Offset == 0 && Bytes == sizeof (FAT_BOOT_SECTOR) && mFsHandoff != NULL &&
      FsSpan ((UINTN)Buffer, Bytes, mFsHandoff->StackBase, mFsHandoff->StackSize);
  } else {
    Owned = FsIn (Buffer, Bytes, mFsStorage.File, sizeof (mFsStorage.File)) ||
      (FsCacheValid () && FsIn (Buffer, Bytes, mFsCache, FS_CACHE_BYTES));
  }
  return Owned && N976nUfsCpuRangeAllowed (Buffer, Bytes);
}
STATIC BOOLEAN FsDestination (VOID *Buffer, UINTN Bytes, UINT64 Offset) {
  return FsStaticDestination (Buffer, Bytes, Offset) ||
    (mFsLease.Active && FsIn (Buffer, Bytes, mFsLease.Buffer, mFsLease.Bytes) && FsBorrowAllowed (Buffer, Bytes));
}
STATIC UINT64 FsOverlapBytes (UINT64 Offset, UINTN Bytes, UINT64 Base, UINTN Length) {
  UINT64 Start = MAX (Offset, Base), End = MIN (Offset + Bytes, Base + Length);
  return End > Start ? End - Start : 0;
}
STATIC VOID FsRunReadObserved (UINT64 Offset, UINTN Bytes) {
  if (!mFsRunMode || !N976nUfsExecutionActive ()) { return; }
  mN976nFileRunReport.Phase = 2;
  if (mN976nFileRunReport.Reason == 0) { mN976nFileRunReport.Status = EFI_SUCCESS; }
  ++mN976nFileRunReport.Calls; ++mN976nFileRunReport.DiskCalls; mN976nFileRunReport.Bytes += Bytes;
  mN976nFileRunReport.LastOffset = Offset; mN976nFileRunReport.LastBytes = Bytes;
  mN976nFileRunReport.BcdBytes += FsOverlapBytes (Offset, Bytes, N976N_BOOT_BCD_OFFSET, N976N_BOOT_BCD_BYTES);
  mN976nFileRunReport.FontBytes +=
    FsOverlapBytes (Offset, Bytes, N976N_BOOT_FONT_OFFSET, N976N_BOOT_FONT_BYTES) +
    FsOverlapBytes (Offset, Bytes, N976N_BOOT_SEGOE_OFFSET, N976N_BOOT_SEGOE_BYTES) +
    FsOverlapBytes (Offset, Bytes, N976N_BOOT_SEGMONO_OFFSET, N976N_BOOT_SEGMONO_BYTES);
  mN976nFileRunReport.Checks |= 3;
  if (mN976nFileRunReport.BcdBytes) { mN976nFileRunReport.Checks |= 4; }
  if (mN976nFileRunReport.FontBytes) { mN976nFileRunReport.Checks |= 8; }
}
STATIC EFI_STATUS FsState (UINT32 MediaId) {
  if (!mFsGate || !mFsScope || !mFsMedia.MediaPresent) { return EFI_NO_MEDIA; }
  if (MediaId != FS_MEDIA_ID) { return EFI_MEDIA_CHANGED; }
  if (!FsGuards () || mFsBlock.Media != &mFsMedia || mFsMedia.MediaId != FS_MEDIA_ID ||
      !mFsMedia.ReadOnly || !mFsMedia.LogicalPartition || mFsMedia.RemovableMedia ||
      mFsMedia.WriteCaching || mFsMedia.BlockSize != FS_BLOCK_BYTES || mFsMedia.IoAlign != 1 ||
      mFsMedia.LastBlock != N976N_BOOT_MEDIA_BYTES / FS_BLOCK_BYTES - 1 || mFsSource == NULL) {
    mFsGate = FALSE; return FsFail (EFI_SECURITY_VIOLATION, 0x20);
  }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI FsDiskRead (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId,
  UINT64 Offset, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status; EFI_TPL Old; BOOLEAN Busy = FALSE, Borrowed = FALSE;
  BOOLEAN High = (UINTN)Buffer >= N976N_HIGH_RAM_BASE &&
    (UINTN)Buffer < N976N_HIGH_RAM_BASE + N976N_HIGH_RAM_BYTES;
  if (This != &mFsDisk) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  Old = gBS->RaiseTPL (TPL_CALLBACK);
  Status = FsState (MediaId);
  if (EFI_ERROR (Status)) { goto Done; }
  if (mFsBusy) { Status = EFI_NOT_READY; goto Done; }
  if (Bytes == 0) { Status = EFI_SUCCESS; goto Done; }
  if (Bytes > (mFsRunMode && N976nUfsExecutionActive () ? N976N_BOOT_MEDIA_BYTES : FS_MAX_REQUEST) ||
      !FsSpan (Offset, Bytes, 0, N976N_BOOT_MEDIA_BYTES)) { Status = EFI_INVALID_PARAMETER; goto Done; }
  if (!FsStaticDestination (Buffer, Bytes, Offset)) {
    if (mFsLease.Active || !FsBorrowAllowed (Buffer, Bytes)) { Status = EFI_INVALID_PARAMETER; goto Done; }
    mFsLease.Buffer = Buffer; mFsLease.Bytes = Bytes; mFsLease.Active = TRUE; Borrowed = TRUE;
  }
  /* Account for each bounded owned read, including a boundary page repeated
   * between chunks. This is conservative and keeps cleanup reservation intact. */
  UINTN Needed = 0;
  for (UINTN At = 0; At < Bytes; ) {
    UINTN N = MIN ((UINTN)8192, Bytes - At);
    Needed += (UINTN)(((mN976nFileSystemReport.VolumeOffset + Offset + At) & 4095) + N + 4095) / 4096;
    At += N;
  }
  if (Needed > N976nUfsOwnedBudget ()) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  mFsBusy = TRUE; Busy = TRUE;
  for (UINTN At = 0; At < Bytes; ) {
    CONST UINT8 *Data = NULL; UINTN N = MIN ((UINTN)8192, Bytes - At);
    Status = N976nReadUfsOwned (mN976nFileSystemReport.VolumeOffset + Offset + At, N, &Data);
    if (EFI_ERROR (Status)) { FsFail (Status, 0x21); goto Poison; }
    if (Data == NULL || CompareMem (Data, mFsSource + (UINTN)Offset + At, N) != 0 ||
        !FsGuards () || !FsDestination ((UINT8 *)Buffer + At, N, Offset + At)) {
      Status = FsFail (EFI_COMPROMISED_DATA, 0x22); goto Poison;
    }
    CopyMem ((UINT8 *)Buffer + At, Data, N);
    if (High) {
      /* Only the already borrowed CPU output is observed. The physical
       * transport still uses its private low DMA and low owned read buffer.
       * Recheck ownership before dereferencing the copied high destination. */
      if (!Borrowed || !mFsLease.Active ||
          !FsDestination ((UINT8 *)Buffer + At, N, Offset + At) ||
          !FsGuards () || CompareMem ((UINT8 *)Buffer + At, mFsSource + (UINTN)Offset + At, N) != 0 ||
          mN976nHighRamUseReport[0] == MAX_UINT64 ||
          mN976nHighRamUseReport[1] > MAX_UINT64 - N) {
        Status = FsFail (EFI_COMPROMISED_DATA, 0x24); goto Poison;
      }
      ++mN976nHighRamUseReport[0]; mN976nHighRamUseReport[1] += N;
      mN976nHighRamUseReport[2] = (UINTN)Buffer + At;
      mN976nHighRamUseReport[3] = N; mN976nHighRamUseReport[4] = Offset + At;
      mN976nHighRamUseReport[5] = 0x1F;
      if (mN976nHighRamUseReport[0] == 1) { N976nHighRamReadCheckpoint (); }
    }
    At += N;
  }
  if (!FsGuards ()) { Status = FsFail (EFI_SECURITY_VIOLATION, 0x23); goto Poison; }
  ++mN976nFileSystemReport.DiskCalls; mN976nFileSystemReport.ReadBytes += Bytes;
  FsRunReadObserved (Offset, Bytes);
  if (mFsMount) { mN976nFileSystemReport.OwnerChecks |= 2; }
  Status = EFI_SUCCESS; goto Done;
Poison:
  mFsGate = FALSE; mFsMedia.MediaPresent = FALSE;
Done:
  if (mFsRunMode && N976nUfsExecutionActive () && EFI_ERROR (Status)) {
    if (High && mN976nHighRamUseReport[6] != MAX_UINT64) { ++mN976nHighRamUseReport[6]; }
    ++mN976nFileRunReport.Rejected;
    if (mN976nFileRunReport.Reason == 0) {
      mN976nFileRunReport.Status = Status; mN976nFileRunReport.Reason = 1;
      mN976nFileRunReport.LastOffset = Offset; mN976nFileRunReport.LastBytes = Bytes;
    }
  }
  if (Borrowed) { ZeroMem (&mFsLease, sizeof (mFsLease)); }
  if (Busy) { mFsBusy = FALSE; }
  gBS->RestoreTPL (Old); return Status;
}
STATIC EFI_STATUS EFIAPI FsDiskWrite (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId,
  UINT64 Offset, UINTN Bytes, VOID *Buffer) {
  (VOID)Offset; (VOID)Bytes; (VOID)Buffer;
  if (This != &mFsDisk) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = FsState (MediaId);
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI FsBlockRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  if (This != &mFsBlock) { return EFI_INVALID_PARAMETER; }
  if (Bytes % FS_BLOCK_BYTES) { return EFI_BAD_BUFFER_SIZE; }
  if (Lba > N976N_BOOT_MEDIA_BYTES / FS_BLOCK_BYTES) { return EFI_INVALID_PARAMETER; }
  EFI_STATUS Status = FsDiskRead (&mFsDisk, MediaId, Lba * FS_BLOCK_BYTES, Bytes, Buffer);
  if (mFsRunMode && N976nUfsExecutionActive () && !EFI_ERROR (Status) && Bytes) {
    ++mN976nFileRunReport.BlockCalls; --mN976nFileRunReport.DiskCalls;
  }
  return Status;
}
STATIC EFI_STATUS EFIAPI FsBlockWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  if (This != &mFsBlock) { return EFI_INVALID_PARAMETER; }
  return FsDiskWrite (&mFsDisk, MediaId, Lba, Bytes, Buffer);
}
STATIC EFI_STATUS EFIAPI FsBlockReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
  (VOID)Extended;
  if (This != &mFsBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = FsState (FS_MEDIA_ID);
  return EFI_ERROR (Status) ? Status : EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI FsBlockFlush (EFI_BLOCK_IO_PROTOCOL *This) {
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  return This == &mFsBlock ? FsState (FS_MEDIA_ID) : EFI_INVALID_PARAMETER;
}

/* Temporary bounded embedded-FAT adapter, replaced by standard partition
 * binding when a real FAT/ESP medium is available. Sector zero is metadata;
 * every other byte is fetched from the same guarded physical FAT provider.
 * No raw physical disk geometry or on-media partition table is fabricated. */
STATIC BOOLEAN FsParentPathValid (VOID) {
  VOID *Path = NULL;
  return mFsParentHandle != NULL &&
    N976nUfsCpuRangeAllowed (&mFsParentPath, sizeof (mFsParentPath)) &&
    !CompareMem (&mFsParentPath, &mFsParentExpectedPath, sizeof (mFsParentPath)) &&
    !EFI_ERROR (gBS->HandleProtocol (mFsParentHandle, &gEfiDevicePathProtocolGuid, &Path)) &&
    Path == &mFsParentPath;
}
STATIC EFI_STATUS FsParentState (UINT32 MediaId) {
  EFI_STATUS Status = FsState (MediaId);
  if (EFI_ERROR (Status)) { return Status; }
  if (!mFsRunMode || mFsParentBlock.Media != &mFsParentMedia ||
      mFsParentMedia.MediaId != FS_MEDIA_ID || !mFsParentMedia.MediaPresent ||
      !mFsParentMedia.ReadOnly || mFsParentMedia.LogicalPartition || mFsParentMedia.RemovableMedia ||
      mFsParentMedia.WriteCaching || mFsParentMedia.BlockSize != 512 || mFsParentMedia.IoAlign != 1 ||
      mFsParentMedia.LastBlock != N976N_BOOT_MEDIA_BYTES / 512 || !FsParentPathValid ()) {
    mFsGate = FALSE; return FsFail (EFI_SECURITY_VIOLATION, 0x4A);
  }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI FsParentRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  if (This != &mFsParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_TPL Old = gBS->RaiseTPL (TPL_CALLBACK); BOOLEAN Busy = FALSE;
  EFI_STATUS Status = FsParentState (MediaId);
  if (EFI_ERROR (Status)) { goto Done; }
  if (mFsParentBusy || mFsBusy || mFsLease.Active) { Status = EFI_NOT_READY; goto Done; }
  if (Bytes == 0) { Status = EFI_SUCCESS; goto Done; }
  if (Bytes % 512) { Status = EFI_BAD_BUFFER_SIZE; goto Done; }
  if (Lba > N976N_BOOT_MEDIA_BYTES / 512 || Bytes / 512 > 1 + N976N_BOOT_MEDIA_BYTES / 512 - Lba ||
      !FsBorrowAllowed (Buffer, Bytes)) { Status = EFI_INVALID_PARAMETER; goto Done; }
  UINTN Prefix = Lba == 0 ? 512 : 0, PayloadBytes = Bytes - Prefix;
  UINT64 Offset = Lba == 0 ? 0 : (Lba - 1) * 512;
  UINTN Needed = 0;
  for (UINTN At = 0; At < PayloadBytes; ) {
    UINTN N = MIN ((UINTN)8192, PayloadBytes - At);
    Needed += (UINTN)(((mN976nFileSystemReport.VolumeOffset + Offset + At) & 4095) + N + 4095) / 4096;
    At += N;
  }
  if (Needed > N976nUfsOwnedBudget ()) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  mFsParentBusy = TRUE; Busy = TRUE;
  if (PayloadBytes) {
    Status = FsDiskRead (&mFsDisk, MediaId, Offset, PayloadBytes, (UINT8 *)Buffer + Prefix);
    if (EFI_ERROR (Status)) { goto Done; }
    ++mN976nFileRunReport.BlockCalls; --mN976nFileRunReport.DiskCalls;
  }
  /* Copy generated metadata last: payload or ownership failures cannot leave
   * an apparently successful MBR prefix before reporting the failed read. */
  if (Prefix) {
    if (!FsGuards () || !FsParentPathValid () || !FsBorrowAllowed (Buffer, 512)) {
      Status = FsFail (EFI_SECURITY_VIOLATION, 0x4B); mFsGate = FALSE; goto Done;
    }
    CopyMem (Buffer, mFsMbr.Sector, 512); ++mFsParentMbrReads;
  }
  ++mFsParentReads; Status = EFI_SUCCESS;
Done:
  if (Busy) { mFsParentBusy = FALSE; }
  gBS->RestoreTPL (Old); return Status;
}
STATIC EFI_STATUS EFIAPI FsParentWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  (VOID)Lba; (VOID)Bytes; (VOID)Buffer;
  if (This != &mFsParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = FsParentState (MediaId);
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI FsParentReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
  (VOID)Extended;
  if (This != &mFsParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = FsParentState (FS_MEDIA_ID);
  return EFI_ERROR (Status) ? Status : EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI FsParentFlush (EFI_BLOCK_IO_PROTOCOL *This) {
  if (This != &mFsParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  return FsParentState (FS_MEDIA_ID);
}

STATIC BOOLEAN FsFatImage (EFI_LOADED_IMAGE_PROTOCOL *Image) {
  if (Image == NULL || !N976nUfsCpuRangeAllowed (Image, sizeof (*Image)) || Image->FilePath == NULL) { return FALSE; }
  EFI_DEVICE_PATH_PROTOCOL *P = Image->FilePath;
  for (UINTN Total = 0; Total < 256; ) {
    if (!N976nUfsCpuRangeAllowed (P, sizeof (*P))) { return FALSE; }
    UINTN N = DevicePathNodeLength (P);
    if (N < sizeof (*P) || N > 256 - Total || !N976nUfsCpuRangeAllowed (P, N)) { return FALSE; }
    if (DevicePathType (P) == MEDIA_DEVICE_PATH && DevicePathSubType (P) == MEDIA_PIWG_FW_FILE_DP) {
      if (N != sizeof (MEDIA_FW_VOL_FILEPATH_DEVICE_PATH)) { return FALSE; }
      MEDIA_FW_VOL_FILEPATH_DEVICE_PATH *File = (VOID *)P;
      EFI_DEVICE_PATH_PROTOCOL *End = NextDevicePathNode (P);
      return CompareGuid (&File->FvFileName, &mFatFileGuid) &&
        N976nUfsCpuRangeAllowed (End, sizeof (*End)) && IsDevicePathEnd (End) &&
        DevicePathNodeLength (End) == sizeof (*End);
    }
    if (IsDevicePathEnd (P)) { return FALSE; }
    Total += N; P = NextDevicePathNode (P);
  }
  return FALSE;
}
STATIC EFI_STATUS FsFindDriver (VOID) {
  EFI_HANDLE *Handles = NULL; UINTN Count = 0;
  EFI_STATUS Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiDriverBindingProtocolGuid,
                                              NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { return Status; }
  UINTN Found = 0;
  for (UINTN I = 0; I < Count; ++I) {
    EFI_DRIVER_BINDING_PROTOCOL *Binding = NULL; EFI_LOADED_IMAGE_PROTOCOL *Image = NULL;
    Status = gBS->HandleProtocol (Handles[I], &gEfiDriverBindingProtocolGuid, (VOID **)&Binding);
    if (EFI_ERROR (Status) || !N976nUfsCpuRangeAllowed (Binding, sizeof (*Binding)) ||
        Binding->DriverBindingHandle != Handles[I] || Binding->Supported == NULL ||
        Binding->Start == NULL || Binding->Stop == NULL) { continue; }
    Status = gBS->HandleProtocol (Binding->ImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
    if (!EFI_ERROR (Status) && FsFatImage (Image)) { ++Found; mFsDriver = Binding; }
  }
  FreePool (Handles);
  return Found == 1 ? EFI_SUCCESS : EFI_NOT_FOUND;
}
STATIC EFI_STATUS FsBindCache (EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs) {
  if (Fs == NULL || (UINTN)Fs < OFFSET_OF (FAT_VOLUME, VolumeInterface)) { return EFI_COMPROMISED_DATA; }
  FAT_VOLUME *V = (VOID *)((UINT8 *)Fs - OFFSET_OF (FAT_VOLUME, VolumeInterface));
  if (!N976nUfsCpuRangeAllowed (V, sizeof (*V))) { return EFI_SECURITY_VIOLATION; }
  mFsVolume = V; mFsCache = V->CacheBuffer;
  if (!FsCacheValid ()) { mFsVolume = NULL; mFsCache = NULL; return EFI_SECURITY_VIOLATION; }
  mN976nFileSystemReport.OwnerChecks |= 4; return EFI_SUCCESS;
}

/* Validate each finite chunk before advancing the independently reported
 * progress. The same 16KiB CPU buffer is reused for the full file; the guarded
 * transport owns DMA and never receives this file-buffer pointer. */
STATIC EFI_STATUS FsReadFileChunk (EFI_FILE_PROTOCOL *File, UINT64 Position,
  UINT64 SourceOffset, UINTN Bytes) {
  UINTN ReadBytes = Bytes; UINT64 EndPosition = MAX_UINT64;
  if (Bytes == 0 || Bytes > sizeof (mFsStorage.File) || Position > MAX_UINT64 - Bytes ||
      !FsSpan (SourceOffset, Bytes, 0, N976N_BOOT_MEDIA_BYTES) || !FsGuards () ||
      !N976nUfsCpuRangeAllowed (mFsStorage.File, sizeof (mFsStorage.File))) {
    return FsFail (EFI_SECURITY_VIOLATION, 0x38);
  }
  EFI_STATUS Status = File->Read (File, &ReadBytes, mFsStorage.File);
  if (EFI_ERROR (Status)) { return FsFail (Status, 17); }
  if (ReadBytes != Bytes || !FsGuards () ||
      !N976nUfsCpuRangeAllowed (mFsStorage.File, sizeof (mFsStorage.File)) ||
      CompareMem (mFsStorage.File, mFsSource + (UINTN)SourceOffset, Bytes)) {
    return FsFail (EFI_COMPROMISED_DATA, 17);
  }
  Status = File->GetPosition (File, &EndPosition);
  if (EFI_ERROR (Status)) { return FsFail (Status, 0x40); }
  if (EndPosition != Position + Bytes || !FsGuards ()) {
    return FsFail (EFI_COMPROMISED_DATA, 0x40);
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS FsFileEof (EFI_FILE_PROTOCOL *File, UINT64 ExpectedPosition) {
  UINTN Bytes = 1; UINT64 Position = MAX_UINT64;
  if (!FsGuards () || !N976nUfsCpuRangeAllowed (mFsStorage.File, sizeof (mFsStorage.File))) {
    return FsFail (EFI_SECURITY_VIOLATION, 0x38);
  }
  /* EOF must not touch any part of the reused CPU buffer, including bytes
   * beyond the last short chunk. This also avoids a second staging buffer. */
  SetMem (mFsStorage.File, sizeof (mFsStorage.File), 0xA5);
  EFI_STATUS Status = File->Read (File, &Bytes, mFsStorage.File);
  if (EFI_ERROR (Status)) { return FsFail (Status, 19); }
  if (Bytes != 0 || !FsGuards () ||
      !N976nUfsCpuRangeAllowed (mFsStorage.File, sizeof (mFsStorage.File))) {
    return FsFail (EFI_COMPROMISED_DATA, 19);
  }
  for (UINTN I = 0; I < sizeof (mFsStorage.File); ++I) {
    if (mFsStorage.File[I] != 0xA5) { return FsFail (EFI_COMPROMISED_DATA, 19); }
  }
  Status = File->GetPosition (File, &Position);
  if (EFI_ERROR (Status)) { return FsFail (Status, 0x40); }
  if (Position != ExpectedPosition || !FsGuards ()) {
    return FsFail (EFI_COMPROMISED_DATA, 0x40);
  }
  return EFI_SUCCESS;
}

STATIC EFI_STATUS FsVerifyFile (EFI_FILE_PROTOCOL *File, BOOLEAN Stream) {
  CONST UINT64 ExpectedBytes = Stream ? N976N_BOOT_WINDOWS_BYTES : N976N_BOOT_BCD_BYTES;
  CONST UINT64 SourceOffset = Stream ? N976N_BOOT_WINDOWS_OFFSET : N976N_BOOT_BCD_OFFSET;
  UINTN Bytes = sizeof (mFsStorage.Info); UINT64 Position = MAX_UINT64;
  EFI_STATUS Status; UINT32 Crc = 0;
  if (File == NULL || File->GetInfo == NULL || File->Read == NULL || File->GetPosition == NULL ||
      (Stream && File->SetPosition == NULL) || mFsSource == NULL ||
      !FsSpan (SourceOffset, ExpectedBytes, 0, N976N_BOOT_MEDIA_BYTES) ||
      (!Stream && ExpectedBytes != FS_FILE_BYTES) || (Stream && ExpectedBytes <= FS_TAIL_BYTES)) {
    return FsFail (EFI_COMPROMISED_DATA, 16);
  }
  if (!FsGuards () || !N976nUfsCpuRangeAllowed (&mFsStorage, sizeof (mFsStorage))) {
    return FsFail (EFI_SECURITY_VIOLATION, 0x38);
  }
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Bytes, mFsStorage.Info);
  EFI_FILE_INFO *Info = (VOID *)mFsStorage.Info;
  if (EFI_ERROR (Status)) { return FsFail (Status, 16); }
  if (Bytes > sizeof (mFsStorage.Info) || Bytes < SIZE_OF_EFI_FILE_INFO + 8 ||
      Info->Size != Bytes || Info->FileSize != ExpectedBytes ||
      (Info->Attribute & EFI_FILE_DIRECTORY) || !FsGuards () ||
      !N976nUfsCpuRangeAllowed (&mFsStorage, sizeof (mFsStorage))) {
    return FsFail (EFI_COMPROMISED_DATA, 16);
  }
  Status = File->GetPosition (File, &Position);
  if (EFI_ERROR (Status)) { return FsFail (Status, 0x40); }
  if (Position != 0 || !FsGuards ()) { return FsFail (EFI_COMPROMISED_DATA, 0x40); }
  mN976nFileSystemReport.Checks |= 8;
  while (Position < ExpectedBytes) {
    Bytes = (UINTN)MIN ((UINT64)sizeof (mFsStorage.File), ExpectedBytes - Position);
    Status = FsReadFileChunk (File, Position, SourceOffset + Position, Bytes);
    if (EFI_ERROR (Status)) { return Status; }
    if (Stream) {
      Status = N976nAppendUfsImage ((UINTN)Position, mFsStorage.File, Bytes);
      if (EFI_ERROR (Status)) { return FsFail (Status, 0x45); }
    }
    Position += Bytes;
    mN976nFileSystemReport.FileBytes = Position;
    mN976nFileSystemReport.VerifiedBytes = Position;
  }
  if (!Stream) {
    /* Retain SEC53's format/CRC contract for the legacy BCD branch. */
    Status = gBS->CalculateCrc32 (mFsStorage.File, (UINTN)ExpectedBytes, &Crc);
    if (EFI_ERROR (Status) || Crc != N976N_BOOT_BCD_CRC32 || CompareMem (mFsStorage.File, "regf", 4)) {
      return FsFail (EFI_COMPROMISED_DATA, 18);
    }
  }
  Status = FsFileEof (File, ExpectedBytes);
  if (EFI_ERROR (Status)) { return Status; }
  if (Stream) {
    /* Exercise a non-sector-aligned backward seek and reread, without adding
     * duplicate bytes to the verified sequential-file progress counters. */
    Position = ExpectedBytes - FS_TAIL_BYTES;
    Status = File->SetPosition (File, Position);
    if (EFI_ERROR (Status)) { return FsFail (Status, 0x41); }
    UINT64 Actual = MAX_UINT64;
    Status = File->GetPosition (File, &Actual);
    if (EFI_ERROR (Status)) { return FsFail (Status, 0x41); }
    if (Actual != Position || !FsGuards ()) { return FsFail (EFI_COMPROMISED_DATA, 0x41); }
    Status = FsReadFileChunk (File, Position, SourceOffset + Position, FS_TAIL_BYTES);
    if (EFI_ERROR (Status)) { return Status; }
    Status = FsFileEof (File, ExpectedBytes);
    if (EFI_ERROR (Status)) { return Status; }
  }
  if (mN976nFileSystemReport.FileBytes != ExpectedBytes ||
      mN976nFileSystemReport.VerifiedBytes != ExpectedBytes) {
    return FsFail (EFI_COMPROMISED_DATA, 0x42);
  }
  mN976nFileSystemReport.Checks |= 0x10; mN976nFileSystemReport.Phase = 4;
  return EFI_SUCCESS;
}

VOID N976nResetUfsFileSystem (VOID) {
  if (mFsEntered || mFsHandle != NULL || mFsParentHandle != NULL || mFsScope || mFsBusy || mFsParentBusy) { return; }
  N976nResetUfsImage ();
  ZeroMem ((VOID *)mN976nHighRamUseReport, sizeof (mN976nHighRamUseReport));
  ZeroMem ((VOID *)&mN976nFileRunReport, sizeof (mN976nFileRunReport));
  mN976nFileRunReport.Magic = N976N_FILE_RUN_MAGIC;
  mN976nFileRunReport.Version = 1; mN976nFileRunReport.Size = sizeof (mN976nFileRunReport);
  mN976nFileRunReport.Status = EFI_NOT_READY;
  ZeroMem ((VOID *)&mN976nFileSystemReport, sizeof (mN976nFileSystemReport));
  mN976nFileSystemReport.Magic = N976N_FILE_SYSTEM_MAGIC;
  mN976nFileSystemReport.Version = 2; mN976nFileSystemReport.Size = sizeof (mN976nFileSystemReport);
  mN976nFileSystemReport.Status = EFI_NOT_READY;
}
BOOLEAN N976nUfsFileSystemClosed (VOID) { return !mFsGate && !mFsBusy && !mFsParentBusy && !mFsScope && N976nUfsImageClosed (); }

EFI_STATUS N976nConsumeUfsFileSystem (CONST N976N_PLATFORM_HANDOFF *Handoff, EFI_HANDLE Parent) {
  EFI_STATUS Status, Cleanup;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
  EFI_FILE_PROTOCOL *Root = NULL, *File = NULL, *Missing = NULL;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory = NULL;
  CONST UINT8 *Header = NULL;
  UINT64 Attributes = 0; UINT32 Crc = 0;
  BOOLEAN Published = FALSE, ParentPublished = FALSE, ImageBegun = FALSE;
  EFI_DEVICE_PATH_PROTOCOL *ImagePath = NULL;
  BOOLEAN Stream = PcdGet32 (PcdN976nUfsQueryExperiment) >= 8;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (mFsEntered || mFsHandle != NULL || mFsParentHandle != NULL) { return EFI_ALREADY_STARTED; }
  if (Stream && Parent == NULL) { return EFI_INVALID_PARAMETER; }
  mFsRunMode = PcdGet32 (PcdN976nUfsQueryExperiment) == 9;
  mFsEntered = TRUE; mFsScope = TRUE; mFsHandoff = Handoff;
  mN976nFileSystemReport.Phase = 1;
  if (!FsHandoffValid (Handoff)) { Status = FsFail (EFI_COMPROMISED_DATA, 1); goto Done; }
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&Memory);
  if (EFI_ERROR (Status)) { FsFail (Status, 2); goto Done; }
  mFsMemory = Memory;
  Status = Memory->GetMemoryAttributes (Memory, Handoff->FirmwareBase, Handoff->FirmwareSize, &Attributes);
  if (EFI_ERROR (Status) || Attributes != (EFI_MEMORY_RO | EFI_MEMORY_XP)) {
    Status = FsFail (EFI_SECURITY_VIOLATION, 3); goto Done;
  }
  Status = N976nLocateUfsReferenceMedia (Handoff, &mFsSource);
  if (EFI_ERROR (Status)) { FsFail (Status, 1); goto Done; }
  Status = gBS->CalculateCrc32 ((VOID *)mFsSource, N976N_BOOT_MEDIA_BYTES, &Crc);
  if (EFI_ERROR (Status) || Crc != N976N_BOOT_MEDIA_EXPECTED_CRC32) {
    Status = FsFail (EFI_COMPROMISED_DATA, 4); goto Done;
  }
  mN976nFileSystemReport.Checks |= 1;
  Status = N976nReadUfsOwned (0, 2048, &Header);
  if (EFI_ERROR (Status)) { FsFail (Status, 5); goto Done; }
  if (Header == NULL || CompareMem (Header, "ANDROID!", 8) || FsLe (Header + 8, 4) != Handoff->ImageSize ||
      FsLe (Header + 36, 4) != 2048 || !FsSpan ((UINTN)mFsSource, N976N_BOOT_MEDIA_BYTES,
                                            Handoff->ImageBase, Handoff->ImageSize)) {
    Status = FsFail (EFI_COMPROMISED_DATA, 6); goto Done;
  }
  mN976nFileSystemReport.VolumeOffset = 2048 + (UINTN)mFsSource - Handoff->ImageBase;
  mN976nFileSystemReport.VolumeBytes = N976N_BOOT_MEDIA_BYTES;
  if (!N976nUfsOwnedRangeAllowed (mN976nFileSystemReport.VolumeOffset, N976N_BOOT_MEDIA_BYTES)) {
    Status = FsFail (EFI_COMPROMISED_DATA, 0x39); goto Done;
  }
  mN976nFileSystemReport.Checks |= 2; mN976nFileSystemReport.OwnerChecks |= 1;
  if (!N976nUfsCpuRangeAllowed (&mFsStorage, sizeof (mFsStorage))) {
    Status = FsFail (EFI_SECURITY_VIOLATION, 7); goto Done;
  }
  SetMem (&mFsStorage, sizeof (mFsStorage), 0xA5); mFsStorageReady = TRUE;
  Status = FsFindDriver ();
  if (EFI_ERROR (Status)) { FsFail (Status, 8); goto Done; }
  ZeroMem (&mFsMedia, sizeof (mFsMedia));
  mFsMedia.MediaId = FS_MEDIA_ID; mFsMedia.MediaPresent = TRUE;
  mFsMedia.ReadOnly = TRUE; mFsMedia.LogicalPartition = TRUE;
  mFsMedia.BlockSize = FS_BLOCK_BYTES; mFsMedia.IoAlign = 1;
  mFsMedia.LastBlock = N976N_BOOT_MEDIA_BYTES / FS_BLOCK_BYTES - 1;
  /* This byte-offset subextent need not share the physical4KiB alignment. */
  mFsMedia.LogicalBlocksPerPhysicalBlock = 1; mFsMedia.OptimalTransferLengthGranularity = 1;
  mFsBlock.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3; mFsBlock.Media = &mFsMedia;
  mFsBlock.ReadBlocks = FsBlockRead; mFsBlock.WriteBlocks = FsBlockWrite;
  mFsBlock.Reset = FsBlockReset; mFsBlock.FlushBlocks = FsBlockFlush;
  mFsDisk.Revision = EFI_DISK_IO_PROTOCOL_REVISION;
  mFsDisk.ReadDisk = FsDiskRead; mFsDisk.WriteDisk = FsDiskWrite;
  /* Mode8 retains the exact prior load/unload identity. Mode9 publishes the
   * temporary readonly mapped-controller/UFS parent and virtual MBR child.
   * Only the identified FAT binding is invoked; no generic ConnectController,
   * synthetic GPT/ESP or memory-backed media identity. */
  if (Stream) {
    if ((mFsRunMode && !FsPrepareRunPath ()) || !N976nUfsCpuRangeAllowed (FsPath (), FsPathBytes ())) {
      Status = FsFail (EFI_SECURITY_VIOLATION, 0x43); goto Done;
    }
    if (!mFsRunMode) { CopyMem (&mFsPath, &mFsExpectedPath, sizeof (mFsPath)); }
    else {
      CopyMem (&mFsParentMedia, &mFsMedia, sizeof (mFsMedia));
      mFsParentMedia.LogicalPartition = FALSE; ++mFsParentMedia.LastBlock;
      mFsParentBlock.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3;
      mFsParentBlock.Media = &mFsParentMedia;
      mFsParentBlock.ReadBlocks = FsParentRead; mFsParentBlock.WriteBlocks = FsParentWrite;
      mFsParentBlock.Reset = FsParentReset; mFsParentBlock.FlushBlocks = FsParentFlush;
      Status = gBS->InstallMultipleProtocolInterfaces (&mFsParentHandle,
        &gEfiBlockIoProtocolGuid, &mFsParentBlock, &gEfiDevicePathProtocolGuid, &mFsParentPath, NULL);
      ParentPublished = mFsParentHandle != NULL;
      if (EFI_ERROR (Status)) { FsFail (Status, 0x4C); goto Done; }
      if (!FsParentPathValid ()) { Status = FsFail (EFI_COMPROMISED_DATA, 0x4C); goto Done; }
    }
    Status = gBS->InstallMultipleProtocolInterfaces (&mFsHandle,
      &gEfiBlockIoProtocolGuid, &mFsBlock, &gEfiDiskIoProtocolGuid, &mFsDisk,
      &gEfiDevicePathProtocolGuid, FsPath (), NULL);
  } else {
    Status = gBS->InstallMultipleProtocolInterfaces (&mFsHandle,
      &gEfiBlockIoProtocolGuid, &mFsBlock, &gEfiDiskIoProtocolGuid, &mFsDisk, NULL);
  }
  /* Preserve a failed installation's original status, but still attempt exact
   * retirement when firmware returned a partially constructed handle. */
  Published = mFsHandle != NULL;
  if (EFI_ERROR (Status)) { FsFail (Status, 9); goto Done; }
  if (!Published) { Status = FsFail (EFI_COMPROMISED_DATA, 9); goto Done; }
  if (Stream && !FsPathValid ()) { Status = FsFail (EFI_COMPROMISED_DATA, 0x43); goto Done; }
  mFsGate = TRUE; mN976nFileSystemReport.Phase = 2;
  Status = mFsDriver->Supported (mFsDriver, mFsHandle, NULL);
  if (EFI_ERROR (Status)) { FsFail (Status, 10); goto Done; }
  mFsMount = TRUE;
  Status = mFsDriver->Start (mFsDriver, mFsHandle, NULL);
  mFsMount = FALSE;
  if (EFI_ERROR (Status)) {
    /* A driver may report a later failure after publishing SFS. Retire any
     * observed publication, rather than inferring ownership from status only. */
    FsFail (Status, 11);
    Cleanup = gBS->HandleProtocol (mFsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
    if (!EFI_ERROR (Cleanup)) { mFsMounted = TRUE; }
    goto Done;
  }
  mFsMounted = TRUE;
  Status = gBS->HandleProtocol (mFsHandle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status)) { FsFail (Status, 12); goto Done; }
  Status = FsBindCache (Fs);
  if (EFI_ERROR (Status)) { FsFail (Status, 13); goto Done; }
  mN976nFileSystemReport.Checks |= 4; mN976nFileSystemReport.Phase = 3;
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { FsFail (Status, 14); goto Done; }
  Status = Root->Open (Root, &File, Stream ? L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi" :
                      L"\\EFI\\Microsoft\\Boot\\BCD", EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { FsFail (Status, 15); goto Done; }
  if (Stream) {
    ImageBegun = TRUE;
    Status = N976nBeginUfsImage (Handoff, mFsSource + N976N_BOOT_WINDOWS_OFFSET, N976N_BOOT_WINDOWS_BYTES);
    if (EFI_ERROR (Status)) { FsFail (Status, 0x44); goto Done; }
  }
  Status = FsVerifyFile (File, Stream);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = Root->Open (Root, &Missing, L"\\sources\\boot.wim", EFI_FILE_MODE_READ, 0);
  mN976nFileSystemReport.MissingWim = Status;
  if (Status != EFI_NOT_FOUND || Missing != NULL) { Status = FsFail (EFI_COMPROMISED_DATA, 20); goto Done; }
  mN976nFileSystemReport.Checks |= 0x20;
  /* Negative calls must leave transport counters unchanged. In particular,
   * invalid-pointer writes cannot reach upstream read-modify-write or DMA. */
  UINT64 Calls = mN976nFileSystemReport.DiskCalls, Reads = mN976nFileSystemReport.ReadBytes;
  if (FsDiskWrite (&mFsDisk, FS_MEDIA_ID, MAX_UINT64, 1, (VOID *)1) != EFI_WRITE_PROTECTED ||
      FsBlockWrite (&mFsBlock, FS_MEDIA_ID, MAX_UINT64, 1, (VOID *)1) != EFI_WRITE_PROTECTED ||
      FsDiskRead (&mFsDisk, FS_MEDIA_ID + 1, 0, 1, mFsStorage.File) != EFI_MEDIA_CHANGED ||
      FsDiskRead (&mFsDisk, FS_MEDIA_ID, 0, 1, (VOID *)1) != EFI_INVALID_PARAMETER ||
      FsDiskRead (&mFsDisk, FS_MEDIA_ID, N976N_BOOT_MEDIA_BYTES, 1, mFsStorage.File) != EFI_INVALID_PARAMETER ||
      Calls != mN976nFileSystemReport.DiskCalls || Reads != mN976nFileSystemReport.ReadBytes || !FsCacheValid ()) {
    Status = FsFail (EFI_SECURITY_VIOLATION, 21); goto Done;
  }
  mN976nFileSystemReport.OwnerChecks |= 8; mN976nFileSystemReport.Checks |= 0x40;
  if (Stream) {
    if (!FsPathValid ()) { Status = FsFail (EFI_COMPROMISED_DATA, 0x43); goto Done; }
    ImagePath = FileDevicePath (mFsHandle, L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi");
    if (ImagePath == NULL) { Status = FsFail (EFI_OUT_OF_RESOURCES, 0x46); goto Done; }
    if (mFsRunMode) { mN976nFileRunReport.Phase = 1; mN976nFileRunReport.Checks = 1; }
    Status = mFsRunMode ? N976nRunUfsImage (Parent, mFsHandle, ImagePath) :
                         N976nLoadAndUnloadUfsImage (Parent, mFsHandle, ImagePath);
    if (EFI_ERROR (Status)) { FsFail (Status, 0x47); goto Done; }
    if (!FsPathValid ()) { Status = FsFail (EFI_COMPROMISED_DATA, 0x43); goto Done; }
  }
  Status = EFI_SUCCESS;
Done:
  if (ImageBegun) {
    Cleanup = N976nReleaseUfsImage ();
    if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x48); }
    if (!N976nUfsImageClosed ()) {
      /* A live/uncertain child retains its device handle and source. Revoke
       * callbacks, but keep those objects and DMA quarantined for diagnosis. */
      mFsGate = FALSE; mFsMedia.MediaPresent = FALSE; mFsScope = FALSE;
      FsFail (EFI_SECURITY_VIOLATION, 0x49);
      mN976nFileSystemReport.Phase = 0xE;
      return mN976nFileSystemReport.Status;
    }
  }
  if (ImagePath != NULL) { FreePool (ImagePath); ImagePath = NULL; }
  if (Missing != NULL) { Cleanup = Missing->Close (Missing); if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x30); } }
  if (File != NULL) {
    Cleanup = File->Close (File); if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x31); }
    else { mN976nFileSystemReport.CloseChecks |= 1; }
  }
  if (Root != NULL) {
    Cleanup = Root->Close (Root); if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x32); }
    else { mN976nFileSystemReport.CloseChecks |= 2; }
  }
  mFsMount = FALSE;
  /* Revoke callbacks before removing the filesystem, so failure paths cannot
   * retain an active controller through an upstream cache or saved callback. */
  mFsGate = FALSE; mFsMedia.MediaPresent = FALSE; mFsParentMedia.MediaPresent = FALSE;
  if (mFsMounted) {
    Cleanup = mFsDriver->Stop (mFsDriver, mFsHandle, 0, NULL);
    if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x33); }
    else {
      VOID *Gone = NULL;
      Cleanup = gBS->HandleProtocol (mFsHandle, &gEfiSimpleFileSystemProtocolGuid, &Gone);
      if (Cleanup != EFI_UNSUPPORTED || Gone != NULL) { FsFail (EFI_COMPROMISED_DATA, 0x34); }
      else { mN976nFileSystemReport.CloseChecks |= 4; mFsMounted = FALSE; }
    }
  }
  mFsVolume = NULL; mFsCache = NULL;
  if (Published) {
    if (Stream) {
      if (!FsPathValid ()) { FsFail (EFI_COMPROMISED_DATA, 0x43); }
      Cleanup = gBS->UninstallMultipleProtocolInterfaces (mFsHandle,
        &gEfiBlockIoProtocolGuid, &mFsBlock, &gEfiDiskIoProtocolGuid, &mFsDisk,
        &gEfiDevicePathProtocolGuid, FsPath (), NULL);
    } else {
      Cleanup = gBS->UninstallMultipleProtocolInterfaces (mFsHandle,
        &gEfiBlockIoProtocolGuid, &mFsBlock, &gEfiDiskIoProtocolGuid, &mFsDisk, NULL);
    }
    if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x35); }
    else {
      mFsHandle = NULL;
      if (FsDiskRead (&mFsDisk, FS_MEDIA_ID, 0, 1, (VOID *)1) != EFI_NO_MEDIA ||
          FsBlockRead (&mFsBlock, FS_MEDIA_ID, 0, 512, (VOID *)1) != EFI_NO_MEDIA) {
        FsFail (EFI_SECURITY_VIOLATION, 0x36);
      } else { mN976nFileSystemReport.CloseChecks |= 8; }
    }
  }
  if (ParentPublished && mFsHandle == NULL) {
    if (!FsParentPathValid ()) { FsFail (EFI_COMPROMISED_DATA, 0x4D); }
    Cleanup = gBS->UninstallMultipleProtocolInterfaces (mFsParentHandle,
      &gEfiBlockIoProtocolGuid, &mFsParentBlock, &gEfiDevicePathProtocolGuid, &mFsParentPath, NULL);
    if (EFI_ERROR (Cleanup)) { FsFail (Cleanup, 0x4D); }
    else { mFsParentHandle = NULL; }
  } else if (ParentPublished) { FsFail (EFI_SECURITY_VIOLATION, 0x4E); }
  mFsScope = FALSE;
  if (mFsRunMode && mN976nFileRunReport.Phase != 0) { mN976nFileRunReport.Phase = 3; }
  if (!mFsFailed && Stream && (mN976nUfsImageReport.Phase != 8 ||
      mN976nUfsImageReport.Status != EFI_SUCCESS || mN976nUfsImageReport.Checks != 0xFF ||
      mN976nUfsImageReport.SourceBytes != N976N_BOOT_WINDOWS_BYTES ||
      mN976nUfsImageReport.StagedBytes != N976N_BOOT_WINDOWS_BYTES ||
      mN976nUfsImageReport.LoadStatus != EFI_SUCCESS || mN976nUfsImageReport.UnloadStatus != EFI_SUCCESS ||
      mN976nUfsImageReport.CloseChecks != 0xF || !N976nUfsImageClosed ())) {
    FsFail (EFI_SECURITY_VIOLATION, 0x48);
  }
  if (!mFsFailed && (!FsGuards () || !N976nUfsFileSystemClosed () ||
      mN976nFileSystemReport.Checks != 0x7F || mN976nFileSystemReport.OwnerChecks != 0xF ||
      mN976nFileSystemReport.CloseChecks != 0xF)) { FsFail (EFI_SECURITY_VIOLATION, 0x37); }
  if (mFsFailed) { mN976nFileSystemReport.Phase = 0xE; return mN976nFileSystemReport.Status; }
  mN976nFileSystemReport.Checks |= 0x80; mN976nFileSystemReport.Phase = 8;
  mN976nFileSystemReport.Status = EFI_SUCCESS; return EFI_SUCCESS;
}
