/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC66 bounded read-only SYSTEM FAT to high-RAM staging. Pinned upstream EnhancedFatDxe
 * owns parsing/cache; this adapter authenticates all physical bytes before
 * exposing them. Each128KiB SHA256 chunk is fetched through the existing
 * private4KiB DMA and exact pending CPU destinations. Windows CPU outputs never enter the private DMA boundary.
 */
#include <N976nSystemVolume.h>
#include <N976nUfs.h>
#include <N976nHighRam.h>
#include <SystemRuntimeFiles.h>
#include <N976nUfsImage.h>
#include <N976nUfsFileSystem.h>
#include <N976nWindowsBoot.h>
#include <N976nBootMedia.h>
#include <N976nBootMediaManifest.h>
#include <SystemVolumeSeal.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Library/TimerLib.h>
#include <Protocol/DriverBinding.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include "UpstreamFat/Fat.h"
#include <SystemVolumeSealData.inc>
#define SV_MEDIA_ID 0x533633U
#define SV_GUARD 64U
#define SV_CACHE_FAT_BYTES (16U * 32768U)
#define SV_CACHE_BYTES (SV_CACHE_FAT_BYTES + 64U * 65536U)
#define SV_FILE_BYTES 16384U
#define SV_MAP_BYTES 65536U
#define SV_MAP_PAGES (SV_MAP_BYTES / EFI_PAGE_SIZE + 2U)
#define SV_MAX_REQUEST 65536U
STATIC_ASSERT (N976N_SYSTEM_SEAL_CHUNK_BYTES == N976N_SYSTEM_VOLUME_CHUNK_BYTES, "seal chunk");
STATIC_ASSERT (sizeof (mN976nSystemChunkSha256) == 262144, "seal table");
STATIC_ASSERT (N976N_SYSTEM_SEAL_IMAGE_BYTES == 0x40000000ULL, "sealed volume");
STATIC_ASSERT (N976N_SYSTEM_VOLUME_SDI_BYTES == N976N_SYSTEM_SDI_BYTES, "public SDI length");
STATIC_ASSERT (N976N_SYSTEM_VOLUME_WIM_BYTES == N976N_SYSTEM_WIM_BYTES, "public WIM length");
STATIC_ASSERT (N976N_SYSTEM_VOLUME_PAYLOAD_BYTES == N976N_SYSTEM_BCD_BYTES + N976N_SYSTEM_SDI_BYTES + N976N_SYSTEM_WIM_BYTES, "finite full-file budget");
volatile N976N_SYSTEM_VOLUME_REPORT mN976nSystemVolumeReport;
volatile N976N_SYSTEM_RUN_REPORT mN976nSystemRunReport;
typedef struct {
 UINT8 Before[SV_GUARD], Chunk[N976N_SYSTEM_VOLUME_CHUNK_BYTES], Between[SV_GUARD];
 UINT8 File[SV_FILE_BYTES], InfoBefore[SV_GUARD];
 UINT64 Info[32]; UINT8 After[SV_GUARD];
} SV_STORAGE;
#pragma pack(1)
typedef struct {
 VENDOR_DEVICE_PATH Vendor;
 UINT64 SystemStart, SystemBlocks, ViewOffset, ViewBytes;
 EFI_GUID UniqueGuid;
 UFS_DEVICE_PATH Ufs;
 HARDDRIVE_DEVICE_PATH Hd;
 EFI_DEVICE_PATH_PROTOCOL End;
} SV_PATH;
typedef struct {
 VENDOR_DEVICE_PATH Vendor;
 UINT64 SystemStart, SystemBlocks, ViewOffset, ViewBytes;
 EFI_GUID UniqueGuid; UFS_DEVICE_PATH Ufs; EFI_DEVICE_PATH_PROTOCOL End;
} SV_PARENT_PATH;
#pragma pack()
STATIC SV_STORAGE mSvStorage;
STATIC SV_PATH mSvPath, mSvExpectedPath;
STATIC SV_PARENT_PATH mSvParentPath, mSvParentExpectedPath;
STATIC EFI_HANDLE mSvParentHandle;
STATIC EFI_BLOCK_IO_PROTOCOL mSvParentBlock;
STATIC EFI_BLOCK_IO_MEDIA mSvParentMedia;
STATIC struct { UINT8 Before[64], Sector[512], After[64]; } mSvMbr;
STATIC UINT8 mSvMbrExpected[512];
STATIC BOOLEAN mSvParentBusy, mSvMbrReady, mSvRunning;
STATIC volatile UINT64 mSvProgress;
/* Local display scheduling only; never accepted as a Windows read destination. */
STATIC struct { UINT64 Counter, Progress; BOOLEAN Armed; } mSvPaint;
STATIC UINT64 mSvParentReads, mSvParentMbrReads;
STATIC UINT64 *mSvMemoryMap;
STATIC EFI_PHYSICAL_ADDRESS mSvMapAllocation;
STATIC BOOLEAN mSvMapReady;
STATIC struct { CONST VOID *Buffer; UINTN Bytes; BOOLEAN Active; } mSvLease;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mSvMemory;
STATIC EFI_HANDLE mSvHandle;
STATIC EFI_BLOCK_IO_PROTOCOL mSvBlock;
STATIC EFI_DISK_IO_PROTOCOL mSvDisk;
STATIC EFI_BLOCK_IO_MEDIA mSvMedia;
STATIC EFI_DRIVER_BINDING_PROTOCOL *mSvDriver;
STATIC CONST N976N_PLATFORM_HANDOFF *mSvHandoff;
STATIC FAT_VOLUME *mSvVolume, *mSvMountVolume;
STATIC UINT8 *mSvCache;
STATIC N976N_GPT_READ mSvRead;
STATIC VOID *mSvContext;
STATIC UINT64 mSvExpectedLba, mSvChunkIndex;
STATIC UINT8 *mSvExpectedBuffer;
STATIC BOOLEAN mSvEntered, mSvScope, mSvGate, mSvBusy, mSvMount, mSvMounted;
STATIC BOOLEAN mSvReady, mSvFailed, mSvPending, mSvChunkValid;
STATIC BOOLEAN mSvMountBootSeen, mSvMountDirtySeen, mSvMountInfoSeen;
STATIC BOOLEAN mSvExitClosing, mSvExitFrozen;
STATIC EFI_STATUS mSvExitStatus = EFI_NOT_STARTED;

STATIC EFI_GUID mFatFileGuid = {0x961578fe,0xb6b7,0x44c3,{0xaf,0x35,0x6b,0xc7,0x05,0xcd,0x2b,0x1f}};
extern BOOLEAN N976nUfsCpuRangeAllowed (CONST VOID *, UINTN);
STATIC UINT64 SvLe (CONST UINT8 *P, UINTN N) {
  UINT64 V = 0;
  for (UINTN I = 0; I < N; ++I) { V |= (UINT64)P[I] << (8 * I); }
  return V;
}

STATIC BOOLEAN SvSpan (UINT64 P, UINT64 N, UINT64 Base, UINT64 Bytes) {
  return N != 0 && Bytes <= MAX_UINT64 - Base && P >= Base &&
    P - Base <= Bytes && N <= Bytes - (P - Base);
}
STATIC BOOLEAN SvIn (CONST VOID *P, UINTN N, CONST VOID *Base, UINTN Bytes) {
  return P != NULL && SvSpan ((UINTN)P, N, (UINTN)Base, Bytes);
}
STATIC BOOLEAN SvOverlaps (CONST VOID *A, UINTN An, CONST VOID *B, UINTN Bn) {
  UINTN X = (UINTN)A, Y = (UINTN)B;
  return An > MAX_UINTN - X || Bn > MAX_UINTN - Y || (X < Y + Bn && Y < X + An);
}

STATIC BOOLEAN SvHandoffValid (CONST N976N_PLATFORM_HANDOFF *H) {
  return H != NULL && H->Magic == N976N_PLATFORM_HANDOFF_MAGIC &&
    H->Version == N976N_PLATFORM_ABI_VERSION && H->Size == sizeof (*H) && !H->Reserved &&
    H->Profile <= 1 && H->FirmwareSize == 0x900000 && !(H->FirmwareBase & EFI_PAGE_MASK) &&
    H->ImageSize <= 0xC00000 && SvSpan (H->FirmwareBase, H->FirmwareSize, H->ImageBase, H->ImageSize) &&
    SvSpan (H->StackBase, H->StackSize, H->ImageBase, H->ImageSize) &&
    H->HeapSize != 0 && H->HeapSize <= MAX_UINT64 - H->HeapBase;
}


STATIC BOOLEAN SvFatImage (EFI_LOADED_IMAGE_PROTOCOL *Image) {
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
STATIC EFI_STATUS SvFindDriver (VOID) {
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
    if (!EFI_ERROR (Status) && SvFatImage (Image)) { ++Found; mSvDriver = Binding; }
  }
  FreePool (Handles);
  return Found == 1 ? EFI_SUCCESS : EFI_NOT_FOUND;
}

STATIC BOOLEAN SvMapGuards (VOID) {
 if (!mSvMapReady || !mSvHandoff || !mSvMapAllocation ||
  (mSvMapAllocation & EFI_PAGE_MASK) ||
  mSvMemoryMap!=(UINT64*)(UINTN)(mSvMapAllocation+EFI_PAGE_SIZE) ||
  !SvSpan(mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE,mSvHandoff->HeapBase,mSvHandoff->HeapSize) ||
  !N976nUfsCpuRangeAllowed((VOID*)(UINTN)mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE)) return FALSE;
 CONST UINT8 *Base=(VOID*)(UINTN)mSvMapAllocation;
 for (UINTN I=0; I<EFI_PAGE_SIZE; ++I)
  if (Base[I]!=0xA5 || Base[EFI_PAGE_SIZE+SV_MAP_BYTES+I]!=0xA5) return FALSE;
 return TRUE;
}
STATIC EFI_STATUS SvPrepareMap (VOID) {
 if (mSvMapAllocation || mSvMapReady || mSvMemoryMap || !mSvHandoff) return EFI_ALREADY_STARTED;
 EFI_STATUS Status=gBS->AllocatePages(AllocateAnyPages,EfiBootServicesData,SV_MAP_PAGES,&mSvMapAllocation);
 if (EFI_ERROR(Status)) return Status;
 /* Allocate while the standard allocator is still low-only. An unexpected
  * range is never touched or guessed free; retain it as a failed allocation. */
 if (!mSvMapAllocation || (mSvMapAllocation&EFI_PAGE_MASK) ||
  !SvSpan(mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE,mSvHandoff->HeapBase,mSvHandoff->HeapSize) ||
  !N976nUfsCpuRangeAllowed((VOID*)(UINTN)mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE)) return EFI_SECURITY_VIOLATION;
 SetMem((VOID*)(UINTN)mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE,0xA5);
 mSvMemoryMap=(VOID*)(UINTN)(mSvMapAllocation+EFI_PAGE_SIZE); mSvMapReady=TRUE;
 return SvMapGuards()?EFI_SUCCESS:EFI_SECURITY_VIOLATION;
}
STATIC EFI_STATUS SvReleaseMap (VOID) {
 if (!mSvMapAllocation) return EFI_SUCCESS;
 if (mSvRunning || mSvLease.Active || mSvBusy || mSvParentBusy ||
  mSvMounted || mSvHandle || mSvParentHandle || !SvMapGuards()) return EFI_ACCESS_DENIED;
 EFI_STATUS Status=gBS->FreePages(mSvMapAllocation,SV_MAP_PAGES);
 if (!EFI_ERROR(Status)) { mSvMapAllocation=0; mSvMemoryMap=NULL; mSvMapReady=FALSE; }
 return Status;
}

STATIC BOOLEAN SvGuards (VOID) {
 if (!mSvReady || !N976nUfsCpuRangeAllowed (&mSvStorage, sizeof (mSvStorage))) return FALSE;
 if (mSvMbrReady && CompareMem(mSvMbr.Sector,mSvMbrExpected,512)) return FALSE;
 for (UINTN I=0; I<SV_GUARD; ++I)
  if (mSvStorage.Before[I]!=0xA5 || mSvStorage.Between[I]!=0xA5 ||
      mSvStorage.InfoBefore[I]!=0xA5 || mSvStorage.After[I]!=0xA5 ||
      (mSvMbrReady && (mSvMbr.Before[I]!=0xA5 || mSvMbr.After[I]!=0xA5))) return FALSE;
 return TRUE;
}
STATIC EFI_STATUS SvFail (EFI_STATUS Status, UINT64 Reason) {
 if (!mSvFailed) { mSvFailed=TRUE; mN976nSystemVolumeReport.Status=Status; mN976nSystemVolumeReport.Reason=Reason; }
 return Status;
}
STATIC BOOLEAN SvControlOverlap (CONST VOID *P, UINTN N) {
 return SvOverlaps(P,N,&mSvParentPath,sizeof(mSvParentPath)) ||
  SvOverlaps(P,N,&mSvParentExpectedPath,sizeof(mSvParentExpectedPath)) ||
  SvOverlaps(P,N,&mSvParentBlock,sizeof(mSvParentBlock)) || SvOverlaps(P,N,&mSvParentMedia,sizeof(mSvParentMedia)) ||
  SvOverlaps(P,N,&mSvMbr,sizeof(mSvMbr)) || SvOverlaps(P,N,mSvMbrExpected,sizeof(mSvMbrExpected)) ||
  SvOverlaps(P,N,&mSvLease,sizeof(mSvLease)) ||
  (mSvMapAllocation && SvOverlaps(P,N,(VOID*)(UINTN)mSvMapAllocation,SV_MAP_PAGES*EFI_PAGE_SIZE)) ||
  SvOverlaps(P,N,(CONST VOID*)&mSvProgress,sizeof(mSvProgress)) ||
  SvOverlaps(P,N,&mSvPaint,sizeof(mSvPaint)) ||
  SvOverlaps(P,N,(CONST VOID*)&mN976nSystemRunReport,sizeof(mN976nSystemRunReport)) ||
  SvOverlaps(P,N,&mSvStorage,sizeof(mSvStorage)) || SvOverlaps(P,N,&mSvPath,sizeof(mSvPath)) ||
  SvOverlaps(P,N,&mSvExpectedPath,sizeof(mSvExpectedPath)) || SvOverlaps(P,N,&mSvBlock,sizeof(mSvBlock)) ||
  SvOverlaps(P,N,&mSvDisk,sizeof(mSvDisk)) || SvOverlaps(P,N,&mSvMedia,sizeof(mSvMedia)) ||
  SvOverlaps(P,N,(CONST VOID*)&mN976nSystemVolumeReport,sizeof(mN976nSystemVolumeReport)) ||
  (mSvHandoff && SvOverlaps(P,N,mSvHandoff,sizeof(*mSvHandoff))) ||
  (mSvDriver && SvOverlaps(P,N,mSvDriver,sizeof(*mSvDriver)));
}
STATIC BOOLEAN SvCacheValid (VOID) {
 FAT_VOLUME *V=mSvVolume;
 if (!V || !mSvCache || !mSvHandoff ||
  !SvSpan((UINTN)V,sizeof(*V),mSvHandoff->HeapBase,mSvHandoff->HeapSize) ||
  !SvSpan((UINTN)mSvCache,SV_CACHE_BYTES,mSvHandoff->HeapBase,mSvHandoff->HeapSize) ||
  SvOverlaps(V,sizeof(*V),mSvCache,SV_CACHE_BYTES) || SvControlOverlap(V,sizeof(*V)) ||
  SvControlOverlap(mSvCache,SV_CACHE_BYTES) || !N976nUfsCpuRangeAllowed(V,sizeof(*V)) ||
  V->Signature!=FAT_VOLUME_SIGNATURE || V->Handle!=mSvHandle || !V->Valid || V->DiskError ||
  V->BlockIo!=&mSvBlock || V->DiskIo!=&mSvDisk || V->DiskIo2 || V->MediaId!=SV_MEDIA_ID ||
  !V->ReadOnly || V->FatType!=Fat32 || V->VolumeSize!=N976N_SYSTEM_SEAL_IMAGE_BYTES || V->CacheBuffer!=mSvCache ||
  V->DiskCache[CacheFat].CacheBase!=mSvCache || V->DiskCache[CacheData].CacheBase!=mSvCache+SV_CACHE_FAT_BYTES ||
  V->DiskCache[CacheFat].PageAlignment!=15 || V->DiskCache[CacheData].PageAlignment!=16 ||
  V->DiskCache[CacheFat].GroupMask!=15 || V->DiskCache[CacheData].GroupMask!=63 ||
  V->DiskCache[CacheFat].BlockSize!=512 || V->DiskCache[CacheData].BlockSize!=512 ||
  V->FatDirty || V->DiskCache[CacheFat].Dirty || V->DiskCache[CacheData].Dirty) return FALSE;
 return N976nUfsCpuRangeAllowed(mSvCache,SV_CACHE_BYTES);
}
/* Init.c reads a FAT32 dirty word and FSInfo before it allocates the cache
 * or publishes SFS. Admit only these two fields of one exact trusted-driver
 * instance after the authenticated BPB read, then require that same instance
 * at publication. No arbitrary initialization heap span is admitted. */
STATIC BOOLEAN SvMountDestination (VOID *P, UINTN N, UINT64 Offset) {
 if (!mSvMount || !mSvHandoff) return FALSE;
 if (Offset==0 && N==sizeof(FAT_BOOT_SECTOR))
  return SvSpan((UINTN)P,N,mSvHandoff->StackBase,mSvHandoff->StackSize);
 if (!mSvMountBootSeen) return FALSE;
 BOOLEAN Dirty=Offset==0x4004 && N==sizeof(UINT32);
 BOOLEAN Info=Offset==512 && N==sizeof(FAT_INFO_SECTOR);
 UINTN Field=Dirty ? OFFSET_OF(FAT_VOLUME,NotDirtyValue) : OFFSET_OF(FAT_VOLUME,FatInfoSector);
 if ((!Dirty && !Info) || (UINTN)P<Field || (Info && !mSvMountDirtySeen)) return FALSE;
 FAT_VOLUME *V=(VOID*)((UINT8*)P-Field);
 if (((UINTN)V & (sizeof(UINTN)-1)) ||
  !SvSpan((UINTN)V,sizeof(*V),mSvHandoff->HeapBase,mSvHandoff->HeapSize) ||
  SvControlOverlap(V,sizeof(*V)) || !N976nUfsCpuRangeAllowed(V,sizeof(*V)) ||
  (mSvMountVolume && mSvMountVolume!=V) || V->Signature!=FAT_VOLUME_SIGNATURE ||
  V->Handle!=mSvHandle || V->BlockIo!=&mSvBlock || V->DiskIo!=&mSvDisk || V->DiskIo2 ||
  V->MediaId!=SV_MEDIA_ID || !V->ReadOnly || V->Valid || V->DiskError || V->FatDirty ||
  V->FatType!=Fat12 /* AllocateZeroPool; assigned only at FatOpenDevice end. */ || V->CacheBuffer || V->VolumeSize!=N976N_SYSTEM_SEAL_IMAGE_BYTES ||
  V->FatPos!=0x4000 || V->FatSize!=0x100000 || V->RootPos!=0x204000 ||
  V->FirstClusterPos!=0x204000 || V->MaxCluster!=261628 || V->ClusterSize!=4096 ||
  V->ClusterAlignment!=12 || V->FatEntrySize!=4 || (Info && V->FreeInfoPos!=512)) return FALSE;
 mSvMountVolume=V; return TRUE;
}
/* Runtime clients borrow exactly one synchronous CPU output span. A fresh
 * UEFI memory map must cover the entire span with allocated LoaderCode/Data.
 * A loader memory type does not grant execution: every borrowed page must
 * still be exactly RW-XN. Executable/RO pages, free memory, BootServicesData,
 * firmware, staging and all controls are refused.
 * These buffers are never passed to DMA. No allocation-wide heap allowlist. */
STATIC BOOLEAN SvHighCpuRange (CONST VOID *Buffer, UINTN Bytes) {
 if (!SvSpan((UINTN)Buffer,Bytes,N976N_HIGH_RAM_BASE,N976N_HIGH_RAM_BYTES)) return FALSE;
 for (UINTN At=0; At<Bytes;) {
  UINTN Take=MIN((UINTN)0x400000,Bytes-At);
  if (!N976nHighRamOwnedCpuRange((CONST UINT8*)Buffer+At,Take,
      (1U<<EfiLoaderCode)|(1U<<EfiLoaderData))) return FALSE;
  At+=Take;
 }
 return TRUE;
}
STATIC BOOLEAN SvBorrowAllowed (CONST VOID *Buffer, UINTN Bytes) {
  UINTN MapBytes = SV_MAP_BYTES, Key = 0, DescriptorBytes = 0;
  UINT32 Version = 0; UINT64 Attributes = 0;
  BOOLEAN Low = mSvHandoff != NULL &&
    SvSpan ((UINTN)Buffer, Bytes, mSvHandoff->HeapBase, mSvHandoff->HeapSize);
  if (!mSvRunning || !N976nUfsExecutionActive () || mSvHandoff == NULL ||
      Buffer == NULL || Bytes == 0 || Bytes > N976N_SYSTEM_SEAL_IMAGE_BYTES + 512 ||
      SvControlOverlap (Buffer, Bytes) ||
      (mSvVolume && SvOverlaps (Buffer, Bytes, mSvVolume, sizeof (*mSvVolume))) ||
      (mSvCache && SvOverlaps (Buffer, Bytes, mSvCache, SV_CACHE_BYTES)) ||
      N976nUfsImageSourceOverlaps (Buffer, Bytes) || mSvMemory == NULL ||
      !(Low ? N976nUfsCpuRangeAllowed (Buffer, Bytes) :
        SvHighCpuRange (Buffer, Bytes)) ||
      EFI_ERROR (mSvMemory->GetMemoryAttributes (mSvMemory, (UINTN)Buffer, Bytes, &Attributes)) ||
      Attributes != EFI_MEMORY_XP || gBS->GetMemoryMap == NULL ||
      !SvMapGuards () ||
      EFI_ERROR (gBS->GetMemoryMap (&MapBytes, (VOID *)mSvMemoryMap, &Key, &DescriptorBytes, &Version)) ||
      !SvMapGuards () || DescriptorBytes < sizeof (EFI_MEMORY_DESCRIPTOR) || MapBytes > SV_MAP_BYTES ||
      MapBytes == 0 || MapBytes % DescriptorBytes || Version != EFI_MEMORY_DESCRIPTOR_VERSION) {
    return FALSE;
  }
  UINT64 At = (UINTN)Buffer, End = At + Bytes;
  while (At < End) {
    UINT64 Next = At, Boundary = End; UINTN Matches = 0;
    for (UINTN O = 0; O < MapBytes; O += DescriptorBytes) {
      EFI_MEMORY_DESCRIPTOR *D = (VOID *)((UINT8 *)mSvMemoryMap + O);
      if ((D->PhysicalStart & EFI_PAGE_MASK) || D->NumberOfPages == 0 || D->NumberOfPages > MAX_UINT64 / EFI_PAGE_SIZE ||
          D->PhysicalStart > MAX_UINT64 - D->NumberOfPages * EFI_PAGE_SIZE) { return FALSE; }
      UINT64 Top = D->PhysicalStart + D->NumberOfPages * EFI_PAGE_SIZE;
      if (D->PhysicalStart > At && D->PhysicalStart < Boundary) { Boundary = D->PhysicalStart; }
      if (At >= D->PhysicalStart && At < Top) {
        if ((D->Type != EfiLoaderData && D->Type != EfiLoaderCode) ||
            (D->Attribute & EFI_MEMORY_RUNTIME)) { return FALSE; }
        ++Matches; Next = MIN (Top, End);
      }
    }
    Next = MIN (Next, Boundary);
    if (Matches != 1 || Next <= At) { return FALSE; }
    At = Next;
  }
  return TRUE;
}
STATIC BOOLEAN SvStaticDestination (VOID *P, UINTN N, UINT64 Offset) {
 BOOLEAN Owned=mSvMount ? SvMountDestination(P,N,Offset) :
  (SvIn(P,N,mSvStorage.File,sizeof(mSvStorage.File)) || (SvCacheValid() && SvIn(P,N,mSvCache,SV_CACHE_BYTES)));
 return Owned && N976nUfsCpuRangeAllowed(P,N);
}
STATIC BOOLEAN SvDestination (VOID *P, UINTN N, UINT64 Offset) {
 return SvStaticDestination(P,N,Offset) ||
  (mSvLease.Active && SvIn(P,N,mSvLease.Buffer,mSvLease.Bytes) && SvBorrowAllowed(P,N));
}
BOOLEAN N976nSystemVolumeExecutionActive (VOID) {
 return !mSvExitClosing && mSvRunning && mSvScope && mSvGate && !mSvFailed && N976nUfsExecutionActive();
}
EFI_STATUS N976nSystemVolumeFreezeForExit (VOID) {
 /* Called by the Before-EBS notification at TPL_NOTIFY or higher. No TPL
  * service, protocol call, memory-map request or allocation belongs here. */
 if (mSvExitClosing) return mSvExitStatus;
 BOOLEAN Ready=mSvEntered && mSvScope && mSvRunning && mSvGate &&
  mSvMounted && mSvReady && !mSvFailed && N976nUfsExecutionActive();
 mSvExitClosing=TRUE; mSvGate=FALSE;
 mSvMedia.MediaPresent=FALSE; mSvParentMedia.MediaPresent=FALSE;
 MemoryFence();
 if (!Ready || mSvBusy || mSvParentBusy || mSvPending || mSvExpectedBuffer ||
  mSvExpectedLba || mSvLease.Active || mSvLease.Buffer || mSvLease.Bytes || mSvMount) {
  mSvExitStatus=EFI_NOT_READY; return mSvExitStatus;
 }
 mSvExitFrozen=TRUE; mSvExitStatus=EFI_SUCCESS;
 return EFI_SUCCESS;
}
BOOLEAN N976nSystemVolumeExitFrozen (VOID) {
 /* Local cached state only; usable after the memory map has terminated. */
 return mSvExitClosing && mSvExitFrozen && mSvExitStatus==EFI_SUCCESS &&
  !mSvGate && !mSvMedia.MediaPresent && !mSvParentMedia.MediaPresent &&
  !mSvBusy && !mSvParentBusy && !mSvPending && !mSvExpectedBuffer &&
  !mSvExpectedLba && !mSvLease.Active && !mSvLease.Buffer && !mSvLease.Bytes;
}
UINT64 N976nSystemWindowsProgress (VOID) { return mSvProgress; }
/* Called only after one sealed chunk has been copied and all destination,
 * guard and byte-comparison checks passed. No Boot Services, console protocol
 * or controller access occurs here. The admitted ArmArchTimerLib counter is
 * upward/full-width; a backwards discontinuity rebases without a repaint. */
STATIC VOID SvProgressScreen (VOID) {
 UINT64 Frequency=mN976nWindowsReport.Frequency;
 if (!N976nSystemVolumeExecutionActive() || !mSvProgress ||
     Frequency==0 || Frequency>1000000000ULL) return;
 UINT64 Now=GetPerformanceCounter();
 if (!mSvPaint.Armed) {
  mSvPaint.Counter=mN976nWindowsReport.CounterStart; mSvPaint.Armed=TRUE;
 }
 UINT64 Elapsed=Now-mSvPaint.Counter;
 if (Elapsed>MAX_INT64) { mSvPaint.Counter=Now; return; }
 if (Elapsed<2*Frequency || mSvPaint.Progress==mSvProgress) return;
 mSvPaint.Counter=Now; mSvPaint.Progress=mSvProgress;
 N976nHighRamScreen();
}
STATIC UINT64 SvOverlapBytes (UINT64 Offset, UINTN Bytes, UINT64 Base, UINT64 Length) {
 UINT64 First=MAX(Offset,Base), End=MIN(Offset+Bytes,Base+Length);
 return End>First ? End-First : 0;
}
STATIC VOID SvReadObserved (UINT64 Offset, UINTN Bytes, CONST VOID *Buffer) {
 if (!N976nSystemVolumeExecutionActive()) return;
 mN976nSystemRunReport.Phase=2;
 if (!mN976nSystemRunReport.Reason) mN976nSystemRunReport.Status=EFI_SUCCESS;
 ++mN976nSystemRunReport.Calls; mN976nSystemRunReport.Bytes+=Bytes;
 mN976nSystemRunReport.LastOffset=Offset; mN976nSystemRunReport.LastBytes=Bytes;
 mN976nSystemRunReport.SdiBytes+=SvOverlapBytes(Offset,Bytes,N976N_SYSTEM_SDI_OFFSET,N976N_SYSTEM_SDI_BYTES);
 mN976nSystemRunReport.WimBytes+=SvOverlapBytes(Offset,Bytes,N976N_SYSTEM_WIM_OFFSET,N976N_SYSTEM_WIM_BYTES);
 mN976nSystemRunReport.Checks|=3;
 if (mN976nSystemRunReport.SdiBytes) mN976nSystemRunReport.Checks|=4;
 if (mN976nSystemRunReport.WimBytes) mN976nSystemRunReport.Checks|=8;
 if ((UINTN)Buffer>=N976N_HIGH_RAM_BASE && (UINTN)Buffer<N976N_HIGH_RAM_BASE+N976N_HIGH_RAM_BYTES) {
  ++mN976nSystemRunReport.HighCalls; mN976nSystemRunReport.HighBytes+=Bytes;
  mN976nSystemRunReport.Checks|=16;
 }
 /* Logical request accounting remains separate from validated chunk progress. */
}
BOOLEAN N976nSystemVolumeLbaAllowed (UINT64 Lba) {
 return !mSvExitClosing && mSvScope && mSvBusy && mSvPending && mSvRead && mSvExpectedBuffer &&
  Lba==mSvExpectedLba && Lba>=N976N_SYSTEM_SEAL_START_LBA &&
  Lba-N976N_SYSTEM_SEAL_START_LBA<N976N_SYSTEM_SEAL_IMAGE_BYTES/4096 &&
  mN976nSystemVolumeReport.ReadCount<N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS;
}
BOOLEAN N976nSystemVolumeReadAllowed (UINT64 Lba, CONST VOID *Buffer) {
 return Buffer==mSvExpectedBuffer && N976nSystemVolumeLbaAllowed(Lba) &&
  SvIn(Buffer,4096,mSvStorage.Chunk,sizeof(mSvStorage.Chunk)) && SvGuards();
}
STATIC BOOLEAN SvDigest (CONST VOID *P, UINTN N, CONST UINT8 Expected[32]) {
 UINT8 Digest[32];
 return N976nSystemSha256(P,N,Digest) && CompareMem(Digest,Expected,32)==0;
}
STATIC EFI_STATUS SvLoadChunk (UINT64 Index) {
 if (Index>=N976N_SYSTEM_SEAL_CHUNK_COUNT || !SvGuards()) return SvFail(EFI_SECURITY_VIOLATION,0x20);
 if (mSvChunkValid && mSvChunkIndex==Index) {
  if (!SvDigest(mSvStorage.Chunk,sizeof(mSvStorage.Chunk),mN976nSystemChunkSha256[Index]))
   return SvFail(EFI_COMPROMISED_DATA,0x21);
  ++mN976nSystemVolumeReport.CacheHits; return EFI_SUCCESS;
 }
 mSvChunkValid=FALSE;
 if (mSvPending || mN976nSystemVolumeReport.ChunkLoads>=N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS ||
  mN976nSystemVolumeReport.ReadCount>N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS-32) return SvFail(EFI_OUT_OF_RESOURCES,0x22);
 for (UINTN At=0; At<sizeof(mSvStorage.Chunk); At+=4096) {
  mSvExpectedLba=N976N_SYSTEM_SEAL_START_LBA+Index*32+At/4096;
  mSvExpectedBuffer=mSvStorage.Chunk+At; mSvPending=TRUE;
  if (!N976nSystemVolumeReadAllowed(mSvExpectedLba,mSvExpectedBuffer)) return SvFail(EFI_SECURITY_VIOLATION,0x23);
  EFI_STATUS Status=mSvRead(mSvContext,mSvExpectedLba,mSvExpectedBuffer);
  BOOLEAN Safe=N976nSystemVolumeReadAllowed(mSvExpectedLba,mSvExpectedBuffer);
  mSvPending=FALSE; mSvExpectedBuffer=NULL; mSvExpectedLba=0;
  if (EFI_ERROR(Status)) return SvFail(Status,0x24);
  if (!Safe) return SvFail(EFI_SECURITY_VIOLATION,0x25);
  ++mN976nSystemVolumeReport.ReadCount;
 }
 if (!SvDigest(mSvStorage.Chunk,sizeof(mSvStorage.Chunk),mN976nSystemChunkSha256[Index]) || !SvGuards())
  return SvFail(EFI_COMPROMISED_DATA,0x26);
 mSvChunkIndex=Index; mSvChunkValid=TRUE;
 ++mN976nSystemVolumeReport.ChunkLoads;
 mN976nSystemVolumeReport.AuthenticatedBytes+=sizeof(mSvStorage.Chunk);
 mN976nSystemVolumeReport.LastChunk=Index;
 return EFI_SUCCESS;
}
STATIC BOOLEAN SvPathValid (VOID) {
 VOID *Path=NULL;
 return mSvHandle && N976nUfsCpuRangeAllowed(&mSvPath,sizeof(mSvPath)) &&
  CompareMem(&mSvPath,&mSvExpectedPath,sizeof(mSvPath))==0 &&
  !EFI_ERROR(gBS->HandleProtocol(mSvHandle,&gEfiDevicePathProtocolGuid,&Path)) && Path==&mSvPath;
}
STATIC EFI_STATUS SvState (UINT32 MediaId) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (!mSvGate || !mSvScope || !mSvMedia.MediaPresent) return EFI_NO_MEDIA;
 if (MediaId!=SV_MEDIA_ID) return EFI_MEDIA_CHANGED;
 if (!SvGuards() || mSvBlock.Media!=&mSvMedia || mSvMedia.MediaId!=SV_MEDIA_ID ||
  !mSvMedia.ReadOnly || !mSvMedia.LogicalPartition || mSvMedia.RemovableMedia || mSvMedia.WriteCaching ||
  mSvMedia.BlockSize!=512 || mSvMedia.IoAlign!=1 || mSvMedia.LastBlock!=N976N_SYSTEM_SEAL_IMAGE_BYTES/512-1 ||
  !SvPathValid()) { mSvGate=FALSE; return SvFail(EFI_SECURITY_VIOLATION,0x27); }
 return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI SvDiskRead (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId, UINT64 Offset, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 EFI_STATUS Status; EFI_TPL Old; BOOLEAN Busy=FALSE, Borrowed=FALSE;
 if (This!=&mSvDisk) return EFI_INVALID_PARAMETER;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 Old=gBS->RaiseTPL(TPL_CALLBACK); Status=SvState(MediaId);
 if (EFI_ERROR(Status)) goto Done;
 if (mSvBusy) { Status=EFI_NOT_READY; goto Done; }
 if (!Bytes) { Status=EFI_SUCCESS; goto Done; }
 if (Bytes>(N976nSystemVolumeExecutionActive()?N976N_SYSTEM_SEAL_IMAGE_BYTES:SV_MAX_REQUEST) ||
  !SvSpan(Offset,Bytes,0,N976N_SYSTEM_SEAL_IMAGE_BYTES)) { Status=EFI_INVALID_PARAMETER; goto Done; }
 if (!SvStaticDestination(Buffer,Bytes,Offset)) {
  if (mSvLease.Active || !SvBorrowAllowed(Buffer,Bytes)) { Status=EFI_INVALID_PARAMETER; goto Done; }
  mSvLease.Buffer=Buffer; mSvLease.Bytes=Bytes; mSvLease.Active=TRUE; Borrowed=TRUE;
 }
 UINT64 First=Offset/N976N_SYSTEM_VOLUME_CHUNK_BYTES, Last=(Offset+Bytes-1)/N976N_SYSTEM_VOLUME_CHUNK_BYTES;
 UINTN Needed=(UINTN)(Last-First+1);
 if (mSvChunkValid && mSvChunkIndex==First) --Needed;
 if (mN976nSystemVolumeReport.ChunkLoads>N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS ||
  Needed>N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS-mN976nSystemVolumeReport.ChunkLoads ||
  mN976nSystemVolumeReport.ReadCount>N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS ||
  Needed*32>N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS-mN976nSystemVolumeReport.ReadCount) {
  Status=EFI_OUT_OF_RESOURCES; goto Done;
 }
 mSvBusy=TRUE; Busy=TRUE;
 for (UINTN At=0; At<Bytes;) {
  UINT64 Here=Offset+At; UINTN In=(UINTN)(Here%N976N_SYSTEM_VOLUME_CHUNK_BYTES);
  UINTN Take=MIN(Bytes-At,N976N_SYSTEM_VOLUME_CHUNK_BYTES-In);
  Status=SvLoadChunk(Here/N976N_SYSTEM_VOLUME_CHUNK_BYTES);
  if (EFI_ERROR(Status)) goto Poison;
  if (!SvGuards() || !SvDestination((UINT8*)Buffer+At,Take,Here)) { Status=SvFail(EFI_SECURITY_VIOLATION,0x28); goto Poison; }
  CopyMem((UINT8*)Buffer+At,mSvStorage.Chunk+In,Take);
  if (!SvGuards() || !SvDestination((UINT8*)Buffer+At,Take,Here) ||
      CompareMem((UINT8*)Buffer+At,mSvStorage.Chunk+In,Take)) { Status=SvFail(EFI_SECURITY_VIOLATION,0x29); goto Poison; }
  /* TPL_NOTIFY may interrupt one long DiskIo call. Report only chunks already
   * authenticated, copied and rechecked, so the idle timer sees real progress
   * without claiming the incomplete logical request succeeded. */
  if (N976nSystemVolumeExecutionActive()) {
   if (mSvProgress>MAX_UINT64-Take) { Status=SvFail(EFI_OUT_OF_RESOURCES,0x2A); goto Poison; }
   mSvProgress+=Take;
   SvProgressScreen();
  }
  At+=Take;
 }
 ++mN976nSystemVolumeReport.DiskCalls; mN976nSystemVolumeReport.ReadBytes+=Bytes;
 SvReadObserved(Offset,Bytes,Buffer);
 if (mSvMount) {
  if (Offset==0 && Bytes==sizeof(FAT_BOOT_SECTOR)) mSvMountBootSeen=TRUE;
  if (Offset==0x4004 && Bytes==4) mSvMountDirtySeen=TRUE;
  if (Offset==512 && Bytes==sizeof(FAT_INFO_SECTOR)) mSvMountInfoSeen=TRUE;
  mN976nSystemVolumeReport.OwnerChecks|=2;
 }
 Status=EFI_SUCCESS; goto Done;
Poison:
 mSvGate=FALSE; mSvMedia.MediaPresent=FALSE;
Done:
 if (EFI_ERROR(Status)) {
  ++mN976nSystemVolumeReport.Rejected;
  if (mSvRunning && N976nUfsExecutionActive()) {
   ++mN976nSystemRunReport.Rejected;
   if (!mN976nSystemRunReport.Reason) {
    mN976nSystemRunReport.Status=Status; mN976nSystemRunReport.Reason=1;
    mN976nSystemRunReport.LastOffset=Offset; mN976nSystemRunReport.LastBytes=Bytes;
   }
  }
 }
 if (Borrowed) ZeroMem(&mSvLease,sizeof(mSvLease));
 if (Busy) mSvBusy=FALSE;
 gBS->RestoreTPL(Old); return Status;
}
STATIC EFI_STATUS EFIAPI SvDiskWrite (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId, UINT64 Offset, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 (VOID)Offset; (VOID)Bytes; (VOID)Buffer;
 if (This!=&mSvDisk) return EFI_INVALID_PARAMETER;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 EFI_STATUS Status=SvState(MediaId); return EFI_ERROR(Status)?Status:EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI SvBlockRead (EFI_BLOCK_IO_PROTOCOL *This,UINT32 MediaId,EFI_LBA Lba,UINTN Bytes,VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (This!=&mSvBlock) return EFI_INVALID_PARAMETER;
 if (Bytes%512) return EFI_BAD_BUFFER_SIZE;
 if (Lba>N976N_SYSTEM_SEAL_IMAGE_BYTES/512) return EFI_INVALID_PARAMETER;
 return SvDiskRead(&mSvDisk,MediaId,Lba*512,Bytes,Buffer);
}
STATIC EFI_STATUS EFIAPI SvBlockWrite (EFI_BLOCK_IO_PROTOCOL *This,UINT32 MediaId,EFI_LBA Lba,UINTN Bytes,VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (This!=&mSvBlock) return EFI_INVALID_PARAMETER;
 return SvDiskWrite(&mSvDisk,MediaId,Lba,Bytes,Buffer);
}
STATIC EFI_STATUS EFIAPI SvBlockReset (EFI_BLOCK_IO_PROTOCOL *This,BOOLEAN Extended) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 (VOID)Extended;
 if (This!=&mSvBlock) return EFI_INVALID_PARAMETER;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 EFI_STATUS Status=SvState(SV_MEDIA_ID); return EFI_ERROR(Status)?Status:EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI SvBlockFlush (EFI_BLOCK_IO_PROTOCOL *This) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (This!=&mSvBlock) return EFI_INVALID_PARAMETER;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 return SvState(SV_MEDIA_ID);
}
STATIC BOOLEAN SvParentPathValid (VOID) {
  VOID *Path = NULL;
  return mSvParentHandle != NULL &&
    N976nUfsCpuRangeAllowed (&mSvParentPath, sizeof (mSvParentPath)) &&
    !CompareMem (&mSvParentPath, &mSvParentExpectedPath, sizeof (mSvParentPath)) &&
    !EFI_ERROR (gBS->HandleProtocol (mSvParentHandle, &gEfiDevicePathProtocolGuid, &Path)) &&
    Path == &mSvParentPath;
}
STATIC EFI_STATUS SvParentState (UINT32 MediaId) {
  EFI_STATUS Status = SvState (MediaId);
  if (EFI_ERROR (Status)) { return Status; }
  if (!mSvRunning || mSvParentBlock.Media != &mSvParentMedia ||
      mSvParentMedia.MediaId != SV_MEDIA_ID || !mSvParentMedia.MediaPresent ||
      !mSvParentMedia.ReadOnly || mSvParentMedia.LogicalPartition || mSvParentMedia.RemovableMedia ||
      mSvParentMedia.WriteCaching || mSvParentMedia.BlockSize != 512 || mSvParentMedia.IoAlign != 1 ||
      mSvParentMedia.LastBlock != N976N_SYSTEM_SEAL_IMAGE_BYTES / 512 || !SvParentPathValid ()) {
    mSvGate = FALSE; return SvFail (EFI_SECURITY_VIOLATION, 0x4A);
  }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI SvParentRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
  if (This != &mSvParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_TPL Old = gBS->RaiseTPL (TPL_CALLBACK); BOOLEAN Busy = FALSE;
  EFI_STATUS Status = SvParentState (MediaId);
  if (EFI_ERROR (Status)) { goto Done; }
  if (mSvParentBusy || mSvBusy || mSvLease.Active) { Status = EFI_NOT_READY; goto Done; }
  if (Bytes == 0) { Status = EFI_SUCCESS; goto Done; }
  if (Bytes % 512) { Status = EFI_BAD_BUFFER_SIZE; goto Done; }
  if (Lba > N976N_SYSTEM_SEAL_IMAGE_BYTES / 512 || Bytes / 512 > 1 + N976N_SYSTEM_SEAL_IMAGE_BYTES / 512 - Lba ||
      !SvBorrowAllowed (Buffer, Bytes)) { Status = EFI_INVALID_PARAMETER; goto Done; }
  UINTN Prefix = Lba == 0 ? 512 : 0, PayloadBytes = Bytes - Prefix;
  UINT64 Offset = Lba == 0 ? 0 : (Lba - 1) * 512;
  mSvParentBusy = TRUE; Busy = TRUE;
  if (PayloadBytes) {
    Status = SvDiskRead (&mSvDisk, MediaId, Offset, PayloadBytes, (UINT8 *)Buffer + Prefix);
    if (EFI_ERROR (Status)) { goto Done; }
  }
  /* Copy generated metadata last: payload or ownership failures cannot leave
   * an apparently successful MBR prefix before reporting the failed read. */
  if (Prefix) {
    if (!SvGuards () || !SvParentPathValid () || !SvBorrowAllowed (Buffer, 512)) {
      Status = SvFail (EFI_SECURITY_VIOLATION, 0x4B); mSvGate = FALSE; goto Done;
    }
    CopyMem (Buffer, mSvMbr.Sector, 512); ++mSvParentMbrReads;
  }
  ++mSvParentReads; Status = EFI_SUCCESS;
Done:
  if (Busy) { mSvParentBusy = FALSE; }
  gBS->RestoreTPL (Old); return Status;
}
STATIC EFI_STATUS EFIAPI SvParentWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
  (VOID)Lba; (VOID)Bytes; (VOID)Buffer;
  if (This != &mSvParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = SvParentState (MediaId);
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI SvParentReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
  (VOID)Extended;
  if (This != &mSvParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  EFI_STATUS Status = SvParentState (SV_MEDIA_ID);
  return EFI_ERROR (Status) ? Status : EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI SvParentFlush (EFI_BLOCK_IO_PROTOCOL *This) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
  if (This != &mSvParentBlock) { return EFI_INVALID_PARAMETER; }
  if (EfiGetCurrentTpl () > TPL_CALLBACK) { return EFI_NOT_READY; }
  return SvParentState (SV_MEDIA_ID);
}

STATIC EFI_STATUS SvReadFile (EFI_FILE_PROTOCOL *File, UINT64 Position, UINTN Bytes) {
 UINTN Actual=Bytes; UINT64 End=MAX_UINT64;
 if (!File || !File->Read || !File->GetPosition || !Bytes || Bytes>SV_FILE_BYTES || !SvGuards())
  return SvFail(EFI_SECURITY_VIOLATION,0x40);
 SetMem(mSvStorage.File,sizeof(mSvStorage.File),0xCC);
 EFI_STATUS Status=File->Read(File,&Actual,mSvStorage.File);
 if (EFI_ERROR(Status)) return SvFail(Status,0x41);
 if (Actual!=Bytes || !SvGuards()) return SvFail(EFI_COMPROMISED_DATA,0x42);
 for (UINTN I=Bytes; I<sizeof(mSvStorage.File); ++I)
  if (mSvStorage.File[I]!=0xCC) return SvFail(EFI_SECURITY_VIOLATION,0x43);
 Status=File->GetPosition(File,&End);
 if (EFI_ERROR(Status)) return SvFail(Status,0x44);
 return End==Position+Bytes ? EFI_SUCCESS : SvFail(EFI_COMPROMISED_DATA,0x45);
}
STATIC EFI_STATUS SvEof (EFI_FILE_PROTOCOL *File, UINT64 Position) {
 UINTN Bytes=1; UINT64 Actual=MAX_UINT64;
 if (!SvGuards()) return SvFail(EFI_SECURITY_VIOLATION,0x46);
 SetMem(mSvStorage.File,sizeof(mSvStorage.File),0xA5);
 EFI_STATUS Status=File->Read(File,&Bytes,mSvStorage.File);
 if (EFI_ERROR(Status)) return SvFail(Status,0x47);
 if (Bytes || !SvGuards()) return SvFail(EFI_COMPROMISED_DATA,0x48);
 for (UINTN I=0; I<sizeof(mSvStorage.File); ++I)
  if (mSvStorage.File[I]!=0xA5) return SvFail(EFI_SECURITY_VIOLATION,0x49);
 Status=File->GetPosition(File,&Actual);
 if (EFI_ERROR(Status)) return SvFail(Status,0x4A);
 return Actual==Position ? EFI_SUCCESS : SvFail(EFI_COMPROMISED_DATA,0x4B);
}
STATIC EFI_STATUS SvFile (EFI_FILE_PROTOCOL *Root, CHAR16 *Path, UINT64 Length,
 UINTN Bytes, CONST UINT8 Digest[32], UINTN Which) {
 EFI_FILE_PROTOCOL *File=NULL; EFI_STATUS Status,Cleanup; UINTN InfoBytes=sizeof(mSvStorage.Info);
 UINT64 Position=MAX_UINT64; UINT8 TailDigest[32];
 if (!Root || !Root->Open || !SvGuards()) return SvFail(EFI_SECURITY_VIOLATION,0x4C);
 Status=Root->Open(Root,&File,Path,EFI_FILE_MODE_READ,0);
 if (EFI_ERROR(Status)) { SvFail(Status,0x4D); goto Done; }
 if (!File || !File->GetInfo || !File->GetPosition || !File->SetPosition || !File->Read || !File->Close) {
  Status=SvFail(EFI_COMPROMISED_DATA,0x4E); goto Done;
 }
 Status=File->GetInfo(File,&gEfiFileInfoGuid,&InfoBytes,mSvStorage.Info);
 EFI_FILE_INFO *Info=(VOID*)mSvStorage.Info;
 if (EFI_ERROR(Status)) { SvFail(Status,0x4F); goto Done; }
 if (InfoBytes>sizeof(mSvStorage.Info) || InfoBytes<SIZE_OF_EFI_FILE_INFO+8 || Info->Size!=InfoBytes ||
  Info->FileSize!=Length || (Info->Attribute&EFI_FILE_DIRECTORY) || !SvGuards()) {
  Status=SvFail(EFI_COMPROMISED_DATA,0x50); goto Done;
 }
 Status=File->GetPosition(File,&Position);
 if (EFI_ERROR(Status)) { SvFail(Status,0x51); goto Done; }
 if (Position!=0) { Status=SvFail(EFI_COMPROMISED_DATA,0x52); goto Done; }
 Status=SvReadFile(File,0,Bytes); if (EFI_ERROR(Status)) goto Done;
 if (!SvDigest(mSvStorage.File,Bytes,Digest)) { Status=SvFail(EFI_COMPROMISED_DATA,0x53); goto Done; }
 if (Which==0) {
  mN976nSystemVolumeReport.BcdCrc32=CalculateCrc32(mSvStorage.File,Bytes);
  if (CompareMem(mSvStorage.File,"regf",4) ||
   !N976nSystemSha256(mSvStorage.File+Bytes-4093,4093,TailDigest)) {
   Status=SvFail(EFI_COMPROMISED_DATA,0x54); goto Done;
  }
  Status=SvEof(File,Length); if (EFI_ERROR(Status)) goto Done;
  Status=File->SetPosition(File,Length-4093);
  if (EFI_ERROR(Status)) { SvFail(Status,0x55); goto Done; }
  Status=File->GetPosition(File,&Position);
  if (EFI_ERROR(Status)) { SvFail(Status,0x56); goto Done; }
  if (Position!=Length-4093) { Status=SvFail(EFI_COMPROMISED_DATA,0x57); goto Done; }
  Status=SvReadFile(File,Position,4093); if (EFI_ERROR(Status)) goto Done;
  if (!SvDigest(mSvStorage.File,4093,TailDigest)) { Status=SvFail(EFI_COMPROMISED_DATA,0x58); goto Done; }
  Status=SvEof(File,Length); if (EFI_ERROR(Status)) goto Done;
  mN976nSystemVolumeReport.BcdBytes=Bytes;
 } else if (Which==1) {
  mN976nSystemVolumeReport.SdiHeader0=SvLe(mSvStorage.File,8);
  mN976nSystemVolumeReport.SdiBytes=Bytes;
 } else {
  mN976nSystemVolumeReport.WimHeader0=SvLe(mSvStorage.File,8);
  if (CompareMem(mSvStorage.File,"MSWIM\0\0\0",8)) { Status=SvFail(EFI_COMPROMISED_DATA,0x59); goto Done; }
  mN976nSystemVolumeReport.WimBytes=Bytes;
 }
 mN976nSystemVolumeReport.FileChecks|=1ULL<<Which;
 Status=EFI_SUCCESS;
Done:
 if (File) {
  if (!File->Close) { SvFail(EFI_COMPROMISED_DATA,0x5A); }
  else { Cleanup=File->Close(File); if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x5B); }
 }
 return mSvFailed ? mN976nSystemVolumeReport.Status : Status;
}
STATIC EFI_STATUS SvBootImage (EFI_FILE_PROTOCOL *Root, CONST UINT8 *Expected) {
 EFI_FILE_PROTOCOL *File=NULL; UINTN InfoBytes=sizeof(mSvStorage.Info); EFI_STATUS Status,Cleanup;
 Status=Root->Open(Root,&File,N976N_WINDOWS_PATH,EFI_FILE_MODE_READ,0);
 if (EFI_ERROR(Status)) return SvFail(Status,0x70);
 if (!File || !File->GetInfo || !File->Read || !File->GetPosition || !File->Close) {
  Status=SvFail(EFI_COMPROMISED_DATA,0x71); goto Done;
 }
 Status=File->GetInfo(File,&gEfiFileInfoGuid,&InfoBytes,mSvStorage.Info);
 EFI_FILE_INFO *Info=(VOID*)mSvStorage.Info;
 if (EFI_ERROR(Status) || InfoBytes>sizeof(mSvStorage.Info) || InfoBytes<SIZE_OF_EFI_FILE_INFO+8 ||
  Info->Size!=InfoBytes || Info->FileSize!=N976N_BOOT_WINDOWS_BYTES || (Info->Attribute&EFI_FILE_DIRECTORY) || !SvGuards()) {
  Status=SvFail(EFI_COMPROMISED_DATA,0x72); goto Done;
 }
 for (UINTN At=0; At<N976N_BOOT_WINDOWS_BYTES;) {
  UINTN Take=MIN((UINTN)16384,N976N_BOOT_WINDOWS_BYTES-At);
  Status=SvReadFile(File,At,Take); if (EFI_ERROR(Status)) goto Done;
  if (CompareMem(mSvStorage.File,Expected+At,Take)) { Status=SvFail(EFI_COMPROMISED_DATA,0x73); goto Done; }
  Status=N976nAppendUfsImage(At,mSvStorage.File,Take);
  if (EFI_ERROR(Status)) { SvFail(Status,0x74); goto Done; }
  At+=Take;
 }
 Status=SvEof(File,N976N_BOOT_WINDOWS_BYTES);
Done:
 if (File && File->Close) { Cleanup=File->Close(File); if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x75); }
 return mSvFailed?mN976nSystemVolumeReport.Status:Status;
}
STATIC BOOLEAN SvIdentity (VOID) {
 CONST EFI_PARTITION_ENTRY *E=N976nSystemEntry();
 CONST EFI_GUID Type={0xEBD0A0A2,0xB9E5,0x4433,{0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}};
 /* Exact phone identity from the corrected IMG_0309 observation; do not accept both spellings. */
 CONST EFI_GUID Unique={0x52444E41,0x494F,0x2044,{0x73,0x79,0x73,0x74,0x65,0x6D,0,0}};
 return E && N976nSystemProbeClosed() && mN976nSystemReport.Magic==N976N_SYSTEM_MAGIC &&
  mN976nSystemReport.Version==2 && mN976nSystemReport.Size==sizeof(mN976nSystemReport) &&
  mN976nSystemReport.Phase==8 && mN976nSystemReport.Status==EFI_SUCCESS &&
  mN976nSystemReport.Checks==N976N_SYSTEM_CHECKS && mN976nSystemReport.ReadCount==2 &&
  mN976nSystemReport.SystemIndex==0x1A && mN976nSystemNamesReport.SystemMatches==1 &&
  mN976nGptReport.Phase==8 && mN976nGptReport.Status==EFI_SUCCESS && mN976nGptReport.Checks==0xFF &&
  E->StartingLBA==N976N_SYSTEM_SEAL_START_LBA && E->EndingLBA-E->StartingLBA+1==N976N_SYSTEM_SEAL_BLOCK_COUNT &&
  !(E->Attributes&BIT1) && CompareGuid(&E->PartitionTypeGUID,&Type) && CompareGuid(&E->UniquePartitionGUID,&Unique) &&
  mN976nSystemReport.SystemStart==E->StartingLBA && mN976nSystemReport.SystemBlocks==N976N_SYSTEM_SEAL_BLOCK_COUNT &&
  N976N_SYSTEM_SEAL_IMAGE_BYTES<=N976N_SYSTEM_SEAL_BLOCK_COUNT*4096ULL && mN976nUfsReport.Lun==0;
}
STATIC BOOLEAN SvPreparePath (VOID) {
 if (!N976nUfsCpuRangeAllowed(&mSvPath,sizeof(mSvPath)) ||
  !N976nUfsCpuRangeAllowed(&mSvExpectedPath,sizeof(mSvExpectedPath)) ||
  !N976nUfsCpuRangeAllowed(&mSvParentPath,sizeof(mSvParentPath)) ||
  !N976nUfsCpuRangeAllowed(&mSvParentExpectedPath,sizeof(mSvParentExpectedPath)) ||
  !N976nUfsCpuRangeAllowed(&mSvParentBlock,sizeof(mSvParentBlock)) ||
  !N976nUfsCpuRangeAllowed(&mSvParentMedia,sizeof(mSvParentMedia)) ||
  !N976nUfsCpuRangeAllowed(&mSvMbr,sizeof(mSvMbr)) ||
  !N976nUfsCpuRangeAllowed(mSvMbrExpected,sizeof(mSvMbrExpected))) return FALSE;
 ZeroMem(&mSvExpectedPath,sizeof(mSvExpectedPath));
 mSvExpectedPath.Vendor.Header.Type=HARDWARE_DEVICE_PATH;
 mSvExpectedPath.Vendor.Header.SubType=HW_VENDOR_DP;
 mSvExpectedPath.Vendor.Header.Length[0]=sizeof(VENDOR_DEVICE_PATH)+32+sizeof(EFI_GUID);
 CONST EFI_GUID Guid={0x2ed59163,0x9c71,0x4c25,{0x94,0x5a,0x97,0x6e,0x63,0,0,1}};
 CopyMem(&mSvExpectedPath.Vendor.Guid,&Guid,sizeof(Guid));
 mSvExpectedPath.SystemStart=N976N_SYSTEM_SEAL_START_LBA;
 mSvExpectedPath.SystemBlocks=N976N_SYSTEM_SEAL_BLOCK_COUNT;
 mSvExpectedPath.ViewBytes=N976N_SYSTEM_SEAL_IMAGE_BYTES;
 CopyMem(&mSvExpectedPath.UniqueGuid,&N976nSystemEntry()->UniquePartitionGUID,sizeof(EFI_GUID));
 mSvExpectedPath.Ufs.Header.Type=MESSAGING_DEVICE_PATH; mSvExpectedPath.Ufs.Header.SubType=MSG_UFS_DP;
 mSvExpectedPath.Ufs.Header.Length[0]=sizeof(UFS_DEVICE_PATH); mSvExpectedPath.Ufs.Lun=0;
 mSvExpectedPath.End.Type=END_DEVICE_PATH_TYPE; mSvExpectedPath.End.SubType=END_ENTIRE_DEVICE_PATH_SUBTYPE;
 mSvExpectedPath.End.Length[0]=END_DEVICE_PATH_LENGTH;
 CopyMem(&mSvParentExpectedPath,&mSvExpectedPath,OFFSET_OF(SV_PATH,Hd));
 CopyMem(&mSvParentExpectedPath.End,&mSvExpectedPath.End,sizeof(mSvExpectedPath.End));
 CopyMem(&mSvParentPath,&mSvParentExpectedPath,sizeof(mSvParentPath));
 UINT32 Signature=CalculateCrc32(&mSvParentExpectedPath,sizeof(mSvParentExpectedPath)-4);
 if (!Signature) return FALSE;
 HARDDRIVE_DEVICE_PATH *Hd=&mSvExpectedPath.Hd;
 Hd->Header.Type=MEDIA_DEVICE_PATH; Hd->Header.SubType=MEDIA_HARDDRIVE_DP;
 Hd->Header.Length[0]=sizeof(*Hd); Hd->PartitionNumber=1;
 Hd->PartitionStart=1; Hd->PartitionSize=N976N_SYSTEM_SEAL_IMAGE_BYTES/512;
 CopyMem(Hd->Signature,&Signature,4); Hd->MBRType=1; Hd->SignatureType=1;
 CopyMem(&mSvPath,&mSvExpectedPath,sizeof(mSvPath));
 ZeroMem(mSvMbrExpected,sizeof(mSvMbrExpected));
 CopyMem(mSvMbrExpected+0x1B8,&Signature,4); mSvMbrExpected[0x1BE + 4]=0x0C;
 mSvMbrExpected[0x1BE + 8]=1; UINT32 Sectors=N976N_SYSTEM_SEAL_IMAGE_BYTES/512;
 CopyMem(mSvMbrExpected+0x1BE + 12,&Sectors,4); mSvMbrExpected[510]=0x55; mSvMbrExpected[511]=0xAA;
 SetMem(&mSvMbr,sizeof(mSvMbr),0xA5); CopyMem(mSvMbr.Sector,mSvMbrExpected,512); mSvMbrReady=TRUE;
 return TRUE;
}
VOID N976nResetSystemVolume (VOID) {
 if (mSvExitClosing) return;
 if (mSvEntered || mSvHandle || mSvScope || mSvBusy || mSvPending) return;
 ZeroMem((VOID*)&mN976nSystemVolumeReport,sizeof(mN976nSystemVolumeReport));
 mN976nSystemVolumeReport.Magic=N976N_SYSTEM_VOLUME_MAGIC; mN976nSystemVolumeReport.Version=3;
 mN976nSystemVolumeReport.Size=sizeof(mN976nSystemVolumeReport); mN976nSystemVolumeReport.Status=EFI_NOT_READY;
 mN976nSystemVolumeReport.VolumeBytes=N976N_SYSTEM_SEAL_IMAGE_BYTES;
 mN976nSystemVolumeReport.BudgetBlocks=N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS;
 ZeroMem((VOID*)&mN976nSystemRunReport,sizeof(mN976nSystemRunReport));
 mSvProgress=0; ZeroMem(&mSvPaint,sizeof(mSvPaint));
 mN976nSystemRunReport.Magic=SIGNATURE_64('N','9','7','6','R','U','N','1');
 mN976nSystemRunReport.Version=1; mN976nSystemRunReport.Size=sizeof(mN976nSystemRunReport);
 mN976nSystemRunReport.Status=EFI_NOT_READY;
}
BOOLEAN N976nSystemVolumeClosed (VOID) {
 return !mSvScope && !mSvGate && !mSvBusy && !mSvPending && !mSvExpectedBuffer && !mSvRead && !mSvContext && !mSvLease.Active && !mSvParentBusy && !mSvRunning && !mSvMapAllocation;
}
EFI_STATUS N976nConsumeSystemVolume (CONST N976N_PLATFORM_HANDOFF *Handoff,N976N_GPT_READ Read,VOID *Context) {
 EFI_STATUS Status,Cleanup; EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory=NULL;
 EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs=NULL; EFI_FILE_PROTOCOL *Root=NULL;
 EFI_DEVICE_PATH_PROTOCOL *ImagePath=NULL; CONST UINT8 *Reference=NULL; BOOLEAN ImageBegun=FALSE,ParentPublished=FALSE;
 UINT64 Attributes=0; BOOLEAN Published=FALSE;
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (EfiGetCurrentTpl()!=TPL_APPLICATION) return EFI_NOT_READY;
 if (mSvEntered || mSvHandle || mSvScope) return EFI_ALREADY_STARTED;
 N976nResetSystemVolume(); mSvEntered=TRUE; mSvScope=TRUE; mSvHandoff=Handoff;
 mN976nSystemVolumeReport.Phase=1;
 if (!Read || !Context || !SvHandoffValid(Handoff) || !SvIdentity()) {
  Status=SvFail(EFI_COMPROMISED_DATA,1); goto Done;
 }
 if (!N976nUfsCpuRangeAllowed(&mSvStorage,sizeof(mSvStorage))) { Status=SvFail(EFI_SECURITY_VIOLATION,2); goto Done; }
 SetMem(&mSvStorage,sizeof(mSvStorage),0xA5); mSvReady=TRUE;
 mN976nSystemVolumeReport.OwnerChecks|=1;
 Status=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID**)&Memory);
 if (EFI_ERROR(Status)) { SvFail(Status,3); goto Done; }
 for (UINTN Page=(UINTN)mN976nSystemChunkSha256 & ~4095ULL;
      Page<=(((UINTN)mN976nSystemChunkSha256+sizeof(mN976nSystemChunkSha256)-1)&~4095ULL); Page+=4096) {
  Status=Memory->GetMemoryAttributes(Memory,Page,4096,&Attributes);
  if (EFI_ERROR(Status) || Attributes!=(EFI_MEMORY_RO|EFI_MEMORY_XP)) { Status=SvFail(EFI_SECURITY_VIOLATION,4); goto Done; }
 }
 mSvMemory=Memory;
 mN976nSystemVolumeReport.TableChecks|=1;
 if (!SvDigest(mN976nSystemChunkSha256,sizeof(mN976nSystemChunkSha256),mN976nSystemSealTableSha256)) {
  Status=SvFail(EFI_COMPROMISED_DATA,5); goto Done;
 }
 mN976nSystemVolumeReport.TableChecks|=2; mN976nSystemVolumeReport.Checks|=1;
 mN976nSystemVolumeReport.SystemStart=N976N_SYSTEM_SEAL_START_LBA;
 mN976nSystemVolumeReport.SystemBlocks=N976N_SYSTEM_SEAL_BLOCK_COUNT;
 mN976nSystemVolumeReport.PartitionIndex=mN976nSystemReport.SystemIndex;
 mN976nSystemVolumeReport.Checks|=2;
 Status=SvPrepareMap(); if (EFI_ERROR(Status)) { SvFail(Status,0x83); goto Done; }
 mSvRead=Read; mSvContext=Context;
 Status=SvFindDriver(); if (EFI_ERROR(Status)) { SvFail(Status,6); goto Done; }
 if (!SvPreparePath()) { Status=SvFail(EFI_SECURITY_VIOLATION,7); goto Done; }
 ZeroMem(&mSvMedia,sizeof(mSvMedia)); mSvMedia.MediaId=SV_MEDIA_ID; mSvMedia.MediaPresent=TRUE;
 mSvMedia.ReadOnly=TRUE; mSvMedia.LogicalPartition=TRUE; mSvMedia.BlockSize=512; mSvMedia.IoAlign=1;
 mSvMedia.LastBlock=N976N_SYSTEM_SEAL_IMAGE_BYTES/512-1;
 mSvMedia.LogicalBlocksPerPhysicalBlock=8; mSvMedia.OptimalTransferLengthGranularity=8;
 mSvBlock.Revision=EFI_BLOCK_IO_PROTOCOL_REVISION3; mSvBlock.Media=&mSvMedia;
 mSvBlock.ReadBlocks=SvBlockRead; mSvBlock.WriteBlocks=SvBlockWrite;
 mSvBlock.Reset=SvBlockReset; mSvBlock.FlushBlocks=SvBlockFlush;
 mSvDisk.Revision=EFI_DISK_IO_PROTOCOL_REVISION; mSvDisk.ReadDisk=SvDiskRead; mSvDisk.WriteDisk=SvDiskWrite;
 mSvParentMedia=mSvMedia; mSvParentMedia.LogicalPartition=FALSE;
 mSvParentMedia.LastBlock=N976N_SYSTEM_SEAL_IMAGE_BYTES/512;
 mSvParentBlock=mSvBlock; mSvParentBlock.Media=&mSvParentMedia;
 mSvParentBlock.ReadBlocks=SvParentRead; mSvParentBlock.WriteBlocks=SvParentWrite;
 mSvParentBlock.Reset=SvParentReset; mSvParentBlock.FlushBlocks=SvParentFlush;
 Status=gBS->InstallMultipleProtocolInterfaces(&mSvParentHandle,&gEfiBlockIoProtocolGuid,&mSvParentBlock,
  &gEfiDevicePathProtocolGuid,&mSvParentPath,NULL);
 ParentPublished=mSvParentHandle!=NULL;
 if (EFI_ERROR(Status) || !ParentPublished || !SvParentPathValid()) { SvFail(EFI_COMPROMISED_DATA,0x76); goto Done; }
 Status=gBS->InstallMultipleProtocolInterfaces(&mSvHandle,&gEfiBlockIoProtocolGuid,&mSvBlock,
  &gEfiDiskIoProtocolGuid,&mSvDisk,&gEfiDevicePathProtocolGuid,&mSvPath,NULL);
 Published=mSvHandle!=NULL;
 if (EFI_ERROR(Status)) { SvFail(Status,8); goto Done; }
 if (!Published || !SvPathValid()) { Status=SvFail(EFI_COMPROMISED_DATA,9); goto Done; }
 mSvGate=TRUE; mN976nSystemVolumeReport.Phase=2;
 Status=mSvDriver->Supported(mSvDriver,mSvHandle,NULL);
 if (EFI_ERROR(Status)) { SvFail(Status,10); goto Done; }
 mSvMount=TRUE; Status=mSvDriver->Start(mSvDriver,mSvHandle,NULL); mSvMount=FALSE;
 if (EFI_ERROR(Status)) {
  SvFail(Status,11);
  Cleanup=gBS->HandleProtocol(mSvHandle,&gEfiSimpleFileSystemProtocolGuid,(VOID**)&Fs);
  if (!EFI_ERROR(Cleanup)) mSvMounted=TRUE;
  goto Done;
 }
 mSvMounted=TRUE;
 Status=gBS->HandleProtocol(mSvHandle,&gEfiSimpleFileSystemProtocolGuid,(VOID**)&Fs);
 if (EFI_ERROR(Status)) { SvFail(Status,12); goto Done; }
 if (!Fs || (UINTN)Fs<OFFSET_OF(FAT_VOLUME,VolumeInterface)) { Status=SvFail(EFI_COMPROMISED_DATA,13); goto Done; }
 mSvVolume=(VOID*)((UINT8*)Fs-OFFSET_OF(FAT_VOLUME,VolumeInterface));
 if (!N976nUfsCpuRangeAllowed(mSvVolume,sizeof(*mSvVolume))) { Status=SvFail(EFI_SECURITY_VIOLATION,14); goto Done; }
 mSvCache=mSvVolume->CacheBuffer;
 if (!mSvMountBootSeen || !mSvMountDirtySeen || !mSvMountInfoSeen || mSvVolume!=mSvMountVolume ||
  !SvCacheValid()) { Status=SvFail(EFI_SECURITY_VIOLATION,15); goto Done; }
 mN976nSystemVolumeReport.OwnerChecks|=4; mN976nSystemVolumeReport.Checks|=4;
 mN976nSystemVolumeReport.Phase=3;
 Status=Fs->OpenVolume(Fs,&Root); if (EFI_ERROR(Status)) { SvFail(Status,16); goto Done; }
 Status=SvFile(Root,L"\\EFI\\Microsoft\\Boot\\BCD",N976N_SYSTEM_BCD_BYTES,16384,mN976nSystemBcdSha256,0);
 if (EFI_ERROR(Status)) goto Done;
 mN976nSystemVolumeReport.Checks|=8;
 Status=SvFile(Root,L"\\boot\\boot.sdi",N976N_SYSTEM_SDI_BYTES,4096,mN976nSystemSdiHeaderSha256,1);
 if (EFI_ERROR(Status)) goto Done;
 mN976nSystemVolumeReport.Checks|=0x10;
 Status=SvFile(Root,L"\\sources\\boot.wim",N976N_SYSTEM_WIM_BYTES,4096,mN976nSystemWimHeaderSha256,2);
 if (EFI_ERROR(Status)) goto Done;
 mN976nSystemVolumeReport.Checks|=0x20;
 Status=N976nLocateUfsReferenceMedia(Handoff,&Reference);
 if (EFI_ERROR(Status) || !Reference) { SvFail(EFI_COMPROMISED_DATA,0x77); goto Done; }
 ImageBegun=TRUE;
 Status=N976nBeginUfsImage(Handoff,Reference+N976N_BOOT_WINDOWS_OFFSET,N976N_BOOT_WINDOWS_BYTES);
 if (EFI_ERROR(Status)) { SvFail(Status,0x78); goto Done; }
 Status=SvBootImage(Root,Reference+N976N_BOOT_WINDOWS_OFFSET);
 if (EFI_ERROR(Status)) goto Done;
 UINT64 Reads=mN976nSystemVolumeReport.ReadCount;
 if (SvDiskWrite(&mSvDisk,SV_MEDIA_ID,MAX_UINT64,1,(VOID*)1)!=EFI_WRITE_PROTECTED ||
  SvBlockWrite(&mSvBlock,SV_MEDIA_ID,MAX_UINT64,1,(VOID*)1)!=EFI_WRITE_PROTECTED ||
  SvDiskRead(&mSvDisk,SV_MEDIA_ID+1,0,1,mSvStorage.File)!=EFI_MEDIA_CHANGED ||
  SvDiskRead(&mSvDisk,SV_MEDIA_ID,0,1,(VOID*)1)!=EFI_INVALID_PARAMETER ||
  SvDiskRead(&mSvDisk,SV_MEDIA_ID,N976N_SYSTEM_SEAL_IMAGE_BYTES,1,mSvStorage.File)!=EFI_INVALID_PARAMETER ||
  Reads!=mN976nSystemVolumeReport.ReadCount || !SvCacheValid()) { Status=SvFail(EFI_SECURITY_VIOLATION,17); goto Done; }
 mN976nSystemVolumeReport.OwnerChecks|=8; mN976nSystemVolumeReport.Checks|=0x40;
 ImagePath=FileDevicePath(mSvHandle,N976N_WINDOWS_PATH);
 if (!ImagePath || !SvPathValid() || !SvParentPathValid()) { SvFail(EFI_COMPROMISED_DATA,0x79); goto Done; }
 mSvRunning=TRUE; mN976nSystemRunReport.Phase=1; mN976nSystemRunReport.Checks=1;
 mN976nSystemVolumeReport.Phase=4;
 Status=N976nRunUfsImage(gImageHandle,mSvHandle,ImagePath);
 mSvRunning=FALSE; mN976nSystemRunReport.Phase=3;
 if (EFI_ERROR(Status)) SvFail(Status,0x7A);
Done:
 /* An EBS attempt permanently froze this scope. Do not call FreePool,
  * filesystem Stop, or protocol uninstall even if Windows returns unexpectedly. */
 if (mSvExitClosing) return EFI_ABORTED;
 if (ImageBegun) {
  Cleanup=N976nReleaseUfsImage();
  if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x7B);
  if (!N976nUfsImageClosed()) {
   mSvGate=FALSE; mSvMedia.MediaPresent=FALSE; mSvParentMedia.MediaPresent=FALSE;
   SvFail(EFI_SECURITY_VIOLATION,0x7C); mN976nSystemVolumeReport.Phase=0xE;
   /* Unknown/live child retains source, filesystem and service/DMA ownership. */
   return mN976nSystemVolumeReport.Status;
  }
  mN976nSystemVolumeReport.CloseChecks|=1;
 }
 if (ImagePath) { FreePool(ImagePath); ImagePath=NULL; }
 if (Root) { Cleanup=Root->Close(Root); if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x60); else mN976nSystemVolumeReport.CloseChecks|=2; }
 mSvMount=FALSE; mSvGate=FALSE; mSvMedia.MediaPresent=FALSE; mSvParentMedia.MediaPresent=FALSE;
 if (mSvMounted) {
  Cleanup=mSvDriver->Stop(mSvDriver,mSvHandle,0,NULL);
  if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x61);
  else {
   VOID *Gone=NULL; Cleanup=gBS->HandleProtocol(mSvHandle,&gEfiSimpleFileSystemProtocolGuid,&Gone);
   if (Cleanup!=EFI_UNSUPPORTED || Gone) SvFail(EFI_COMPROMISED_DATA,0x62);
   else { mSvMounted=FALSE; mN976nSystemVolumeReport.CloseChecks|=4; }
  }
 }
 mSvVolume=NULL; mSvCache=NULL; mSvMountVolume=NULL;
 if (Published) {
  if (!SvPathValid()) SvFail(EFI_COMPROMISED_DATA,0x63);
  Cleanup=gBS->UninstallMultipleProtocolInterfaces(mSvHandle,&gEfiBlockIoProtocolGuid,&mSvBlock,
   &gEfiDiskIoProtocolGuid,&mSvDisk,&gEfiDevicePathProtocolGuid,&mSvPath,NULL);
  if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x64);
  else {
   mSvHandle=NULL;
   if (SvDiskRead(&mSvDisk,SV_MEDIA_ID,0,1,(VOID*)1)!=EFI_NO_MEDIA ||
    SvBlockRead(&mSvBlock,SV_MEDIA_ID,0,512,(VOID*)1)!=EFI_NO_MEDIA) SvFail(EFI_SECURITY_VIOLATION,0x65);
   else mN976nSystemVolumeReport.CloseChecks|=8;
  }
 }
 if (ParentPublished && !mSvHandle) {
  if (!SvParentPathValid()) SvFail(EFI_COMPROMISED_DATA,0x7D);
  Cleanup=gBS->UninstallMultipleProtocolInterfaces(mSvParentHandle,&gEfiBlockIoProtocolGuid,&mSvParentBlock,
   &gEfiDevicePathProtocolGuid,&mSvParentPath,NULL);
  if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x7E); else mSvParentHandle=NULL;
 } else if (ParentPublished) SvFail(EFI_SECURITY_VIOLATION,0x7F);
 Cleanup=SvReleaseMap(); if (EFI_ERROR(Cleanup)) SvFail(Cleanup,0x84);
 mSvPending=FALSE; mSvExpectedBuffer=NULL; mSvExpectedLba=0;
 mSvRead=NULL; mSvContext=NULL; mSvChunkValid=FALSE; mSvScope=FALSE; mSvBusy=FALSE;
 if (!mSvFailed && (!SvGuards() || !N976nSystemVolumeClosed() ||
  mN976nSystemVolumeReport.Checks!=0x7F || mSvParentHandle ||
  mN976nSystemVolumeReport.SdiBytes!=4096 || mN976nSystemVolumeReport.WimBytes!=4096 ||
  mN976nSystemVolumeReport.OwnerChecks!=N976N_SYSTEM_VOLUME_OWNER_CHECKS ||
  mN976nSystemVolumeReport.CloseChecks!=N976N_SYSTEM_VOLUME_CLOSE_CHECKS ||
  mN976nSystemVolumeReport.FileChecks!=N976N_SYSTEM_VOLUME_FILE_CHECKS ||
  mN976nSystemVolumeReport.TableChecks!=N976N_SYSTEM_VOLUME_TABLE_CHECKS ||
  !mN976nSystemVolumeReport.ChunkLoads || mN976nSystemVolumeReport.ChunkLoads>N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS ||
  mN976nSystemVolumeReport.ReadCount!=mN976nSystemVolumeReport.ChunkLoads*32 ||
  mN976nSystemVolumeReport.AuthenticatedBytes!=mN976nSystemVolumeReport.ChunkLoads*N976N_SYSTEM_VOLUME_CHUNK_BYTES))
  SvFail(EFI_SECURITY_VIOLATION,0x66);
 if (mSvFailed) { mN976nSystemVolumeReport.Phase=0xE; return mN976nSystemVolumeReport.Status; }
 mN976nSystemVolumeReport.Phase=8; mN976nSystemVolumeReport.Checks|=0x80;
 mN976nSystemVolumeReport.Status=EFI_SUCCESS; return EFI_SUCCESS;
}
