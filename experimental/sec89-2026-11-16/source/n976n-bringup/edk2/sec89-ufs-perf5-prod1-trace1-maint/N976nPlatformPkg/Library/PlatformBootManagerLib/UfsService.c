/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC56 explicit read-only boot-services lease. NTDEV pin6e2cacf15f6b supplies
 * the standard BlockIo/DiskIo composition; inherited N976N transport retains
 * ownership, guards, exact completion and power/controller restoration.
 * The three UpstreamDiskIo files are unmodified EDK2 commit
 * 870158586f14dbf9d57e312ea6ea87141a1b0699. Include the engine in this translation
 * unit to reuse its STATIC template without modifying upstream visibility.
 * Its driver entry/async protocols are never installed or called here.
 */
#include <N976nUfsService.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include "UpstreamDiskIo/DiskIo.c"

#define SERVICE_MEDIA_ID 0x533532U
#define SERVICE_GUARD_BYTES 64U
typedef struct {
  UINT8 Before[SERVICE_GUARD_BYTES];
  UINT8 Sample[8192];
  UINT8 Between[SERVICE_GUARD_BYTES];
  UINT8 Result[8192];
  UINT8 EngineBefore[SERVICE_GUARD_BYTES];
  UINT8 EngineShared[4096];
  UINT8 After[SERVICE_GUARD_BYTES];
} SERVICE_STORAGE;

volatile N976N_SERVICE_REPORT mN976nServiceReport;
STATIC SERVICE_STORAGE mStorage;
STATIC EFI_BLOCK_IO_PROTOCOL mServiceBlock;
/* This private identity distinguishes upstream's legitimate nested block read
 * from a public BlockIo call that reenters during a DiskIo operation. */
STATIC EFI_BLOCK_IO_PROTOCOL mEngineBlock;
STATIC EFI_DISK_IO_PROTOCOL mServiceDisk;
STATIC EFI_BLOCK_IO_MEDIA mServiceMedia;
STATIC DISK_IO_PRIVATE_DATA mEngine;
STATIC EFI_HANDLE mServiceHandle;
STATIC N976N_BLOCK_READ mRead;
STATIC N976N_BLOCK_BUFFER_CHECK mCheck;
STATIC N976N_BLOCK_BUDGET mBudget;
STATIC VOID *mContext;
STATIC UINT64 mStart, mBlocks;
STATIC UINTN mStreamDataLimit;
STATIC BOOLEAN mStarted, mActive, mBlockBusy, mDiskBusy, mConsumerStarted;
STATIC BOOLEAN mStorageReady, mEngineReady, mTombstone, mFailureRecorded;
STATIC BOOLEAN mLifecycleBusy, mConsumerBusy, mFileService;

STATIC BOOLEAN ServiceContains (CONST VOID *Base, UINTN Size, CONST VOID *Buffer, UINTN Bytes) {
  UINTN B = (UINTN)Base, P = (UINTN)Buffer;
  return Buffer != NULL && Bytes != 0 && Size <= MAX_UINTN - B &&
    P >= B && P - B <= Size && Bytes <= Size - (P - B);
}
STATIC BOOLEAN ServiceClientBuffer (CONST VOID *Buffer, UINTN Bytes) {
  return ServiceContains (mStorage.Sample, sizeof (mStorage.Sample), Buffer, Bytes) ||
    ServiceContains (mStorage.Result, sizeof (mStorage.Result), Buffer, Bytes);
}
BOOLEAN N976nServiceBufferOwned (CONST VOID *Buffer, UINTN Bytes) {
  return ServiceClientBuffer (Buffer, Bytes) ||
    ServiceContains (mStorage.EngineShared, sizeof (mStorage.EngineShared), Buffer, Bytes);
}
BOOLEAN N976nServiceStorageOwned (CONST VOID *Buffer, UINTN Bytes) {
  return Buffer == &mStorage && Bytes == sizeof (mStorage);
}
STATIC BOOLEAN ServiceGuards (VOID) {
  if (!mStorageReady) { return FALSE; }
  for (UINTN I = 0; I < SERVICE_GUARD_BYTES; ++I) {
    if (mStorage.Before[I] != 0xA5 || mStorage.Between[I] != 0xA5 ||
        mStorage.EngineBefore[I] != 0xA5 || mStorage.After[I] != 0xA5) { return FALSE; }
  }
  return TRUE;
}
STATIC EFI_STATUS ServiceFail (EFI_STATUS Status, UINT64 Reason) {
  if (!mFailureRecorded) {
    mN976nServiceReport.Status = Status; mN976nServiceReport.Reason = Reason;
    mFailureRecorded = TRUE;
  }
  return Status;
}
STATIC EFI_STATUS ServicePoison (EFI_STATUS Status, UINT64 Reason) {
  mActive = FALSE; mServiceMedia.MediaPresent = FALSE;
  return ServiceFail (Status, Reason);
}
STATIC EFI_STATUS ServiceMediaState (UINT32 MediaId) {
  if (!mActive || mTombstone || !mServiceMedia.MediaPresent) { return EFI_NO_MEDIA; }
  if (MediaId != SERVICE_MEDIA_ID) { return EFI_MEDIA_CHANGED; }
  if (mServiceBlock.Media != &mServiceMedia || mServiceMedia.MediaId != SERVICE_MEDIA_ID ||
      mServiceMedia.BlockSize != N976N_BLOCK_BYTES || mServiceMedia.IoAlign != 1 ||
      mServiceMedia.LastBlock != mBlocks - 1 || !mServiceMedia.ReadOnly ||
      !mServiceMedia.LogicalPartition || mServiceMedia.RemovableMedia ||
      mServiceMedia.WriteCaching || mRead == NULL || mCheck == NULL || mBudget == NULL) {
    return ServicePoison (EFI_SECURITY_VIOLATION, 0x20);
  }
  return EFI_SUCCESS;
}
STATIC BOOLEAN ServiceTplAllowed (VOID) { return EfiGetCurrentTpl () <= TPL_CALLBACK; }
STATIC BOOLEAN ServiceEngineIdle (VOID) {
  /* Do not ask BaseLib to traverse/assert a never-initialized or corrupt list
   * on partial Start failure. This engine never admits asynchronous tasks. */
  return mEngineReady && mEngine.TaskQueue.ForwardLink == &mEngine.TaskQueue &&
    mEngine.TaskQueue.BackLink == &mEngine.TaskQueue;
}
STATIC UINTN ServiceAllowance (VOID) {
  UINTN Limit = mStreamDataLimit != 0 ? mStreamDataLimit :
    (mFileService ? N976N_FILE_SERVICE_MAX_DATA_BLOCKS : N976N_SERVICE_MAX_DATA_BLOCKS);
  if (mBudget == NULL || mN976nServiceReport.DataBlocks >= Limit) { return 0; }
  return MIN (mBudget (mContext), Limit - (UINTN)mN976nServiceReport.DataBlocks);
}
STATIC EFI_STATUS EFIAPI ServiceBlockRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status;
  EFI_TPL OldTpl;
  UINTN Count;
  BOOLEAN OwnBusy = FALSE;
  if (This != &mServiceBlock && This != &mEngineBlock) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);
  Status = ServiceMediaState (MediaId);
  if (EFI_ERROR (Status)) { goto Done; }
  if (mBlockBusy || (This == &mServiceBlock && mDiskBusy) ||
      (This == &mEngineBlock && !mDiskBusy)) { Status = EFI_NOT_READY; goto Done; }
  if (Bytes == 0) { Status = EFI_SUCCESS; goto Done; }
  if (Bytes % N976N_BLOCK_BYTES != 0) { Status = EFI_BAD_BUFFER_SIZE; goto Done; }
  Count = Bytes / N976N_BLOCK_BYTES;
  if (Lba >= mBlocks || Count > mBlocks - Lba ||
      !N976nServiceBufferOwned (Buffer, Bytes) ||
      (This == &mServiceBlock && !ServiceClientBuffer (Buffer, Bytes))) {
    Status = EFI_INVALID_PARAMETER; goto Done;
  }
  mBlockBusy = TRUE; OwnBusy = TRUE;
  if (!ServiceGuards () || !mCheck (mContext, Buffer, Bytes)) {
    Status = ServicePoison (EFI_SECURITY_VIOLATION, 0x21); goto Done;
  }
  if (Count > ServiceAllowance ()) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  for (UINTN I = 0; I < Count; ++I) {
    UINT8 *Target = (UINT8 *)Buffer + I * N976N_BLOCK_BYTES;
    if (!mActive || Count - I > ServiceAllowance ()) {
      Status = ServicePoison (EFI_OUT_OF_RESOURCES, 0x22); break;
    }
    if (!ServiceGuards () || !mCheck (mContext, Target, N976N_BLOCK_BYTES)) {
      Status = ServicePoison (EFI_SECURITY_VIOLATION, 0x23); break;
    }
    Status = mRead (mContext, mStart + Lba + I, Target);
    if (EFI_ERROR (Status)) { ServicePoison (Status, 0x24); break; }
    ++mN976nServiceReport.DataBlocks;
    if (!ServiceGuards ()) { Status = ServicePoison (EFI_SECURITY_VIOLATION, 0x25); break; }
  }
  if (!EFI_ERROR (Status)) { ++mN976nServiceReport.BlockCalls; }
Done:
  if (OwnBusy) { mBlockBusy = FALSE; }
  gBS->RestoreTPL (OldTpl);
  return Status;
}
STATIC EFI_STATUS EFIAPI ServiceBlockWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
  EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status;
  (VOID)Lba; (VOID)Bytes; (VOID)Buffer;
  if (This != &mServiceBlock) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  Status = ServiceMediaState (MediaId);
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI ServiceBlockReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
  EFI_STATUS Status;
  (VOID)Extended;
  if (This != &mServiceBlock) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  Status = ServiceMediaState (SERVICE_MEDIA_ID);
  return EFI_ERROR (Status) ? Status : EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI ServiceBlockFlush (EFI_BLOCK_IO_PROTOCOL *This) {
  if (This != &mServiceBlock) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  return ServiceMediaState (SERVICE_MEDIA_ID);
}
STATIC EFI_STATUS EFIAPI ServiceDiskRead (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId,
  UINT64 Offset, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status;
  EFI_TPL OldTpl;
  UINT64 Total;
  UINTN Needed;
  BOOLEAN OwnBusy = FALSE;
  if (This != &mServiceDisk) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  OldTpl = gBS->RaiseTPL (TPL_CALLBACK);
  Status = ServiceMediaState (MediaId);
  if (EFI_ERROR (Status)) { goto Done; }
  if (mDiskBusy || mBlockBusy) { Status = EFI_NOT_READY; goto Done; }
  if (Bytes == 0) { Status = EFI_SUCCESS; goto Done; }
  Total = mBlocks * N976N_BLOCK_BYTES;
  if (Offset >= Total || Bytes > Total - Offset || !ServiceClientBuffer (Buffer, Bytes)) {
    Status = EFI_INVALID_PARAMETER; goto Done;
  }
  mDiskBusy = TRUE; OwnBusy = TRUE;
  /* At most8192bytes in a client array; therefore this addition cannot wrap. */
  Needed = (UINTN)(((Offset & (N976N_BLOCK_BYTES - 1)) + Bytes + N976N_BLOCK_BYTES - 1) / N976N_BLOCK_BYTES);
  if (!ServiceGuards () || !mCheck (mContext, Buffer, Bytes) ||
      !mCheck (mContext, mStorage.EngineShared, sizeof (mStorage.EngineShared)) ||
      mEngine.Signature != DISK_IO_PRIVATE_DATA_SIGNATURE || mEngine.BlockIo != &mEngineBlock ||
      mEngineBlock.Media != &mServiceMedia || mEngineBlock.ReadBlocks != ServiceBlockRead ||
      mEngine.BlockIo2 != NULL || mEngine.SharedWorkingBuffer != mStorage.EngineShared ||
      !ServiceEngineIdle ()) {
    Status = ServicePoison (EFI_SECURITY_VIOLATION, 0x30); goto Done;
  }
  if (Needed > ServiceAllowance ()) { Status = EFI_OUT_OF_RESOURCES; goto Done; }
  Status = DiskIoReadDisk (&mEngine.DiskIo, MediaId, Offset, Bytes, Buffer);
  if (EFI_ERROR (Status)) { ServicePoison (Status, 0x31); goto Done; }
  if (!ServiceGuards () || !ServiceEngineIdle ()) {
    Status = ServicePoison (EFI_SECURITY_VIOLATION, 0x32); goto Done;
  }
  ++mN976nServiceReport.DiskCalls;
Done:
  if (OwnBusy) { mDiskBusy = FALSE; }
  gBS->RestoreTPL (OldTpl);
  return Status;
}
STATIC EFI_STATUS EFIAPI ServiceDiskWrite (EFI_DISK_IO_PROTOCOL *This, UINT32 MediaId,
  UINT64 Offset, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status;
  (VOID)Offset; (VOID)Bytes; (VOID)Buffer;
  if (This != &mServiceDisk) { return EFI_INVALID_PARAMETER; }
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  Status = ServiceMediaState (MediaId);
  /* Never enter upstream's read-modify-write path, including for zero bytes. */
  return EFI_ERROR (Status) ? Status : EFI_WRITE_PROTECTED;
}

VOID N976nResetUfsService (VOID) {
  /* A published/failed-retirement interface is never revived by reset. */
  if (mStarted || mServiceHandle != NULL || mTombstone || mLifecycleBusy || mConsumerBusy) { return; }
  ZeroMem ((VOID *)&mN976nServiceReport, sizeof (mN976nServiceReport));
  mN976nServiceReport.Magic = N976N_SERVICE_MAGIC;
  mN976nServiceReport.Version = N976N_SERVICE_VERSION;
  mN976nServiceReport.Size = sizeof (mN976nServiceReport);
  mN976nServiceReport.Status = EFI_NOT_READY;
}
STATIC EFI_STATUS ServiceStart (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context) {
  EFI_STATUS Status;
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  if (mStarted || mServiceHandle != NULL || mTombstone) { return EFI_ALREADY_STARTED; }
  mStarted = TRUE; mN976nServiceReport.Phase = 1;
  if (Start < 6 || Start > MAX_UINT32 || Blocks < 2 || Blocks - 1 > MAX_UINT32 - Start ||
      Read == NULL || Check == NULL || Budget == NULL || Context == NULL ||
      PcdGet32 (PcdDiskIoDataBufferBlockNum) != 1) {
    return ServiceFail (EFI_INVALID_PARAMETER, 1);
  }
  mStart = Start; mBlocks = Blocks;
  mRead = Read; mCheck = Check; mBudget = Budget; mContext = Context;
  mN976nServiceReport.PartitionStart = Start; mN976nServiceReport.PartitionBlocks = Blocks;
  mN976nServiceReport.Checks |= BIT0; mN976nServiceReport.Phase = 2;
  if (!Check (Context, &mStorage, sizeof (mStorage))) { return ServiceFail (EFI_SECURITY_VIOLATION, 2); }
  SetMem (&mStorage, sizeof (mStorage), 0xA5);
  SetMem (mStorage.Sample, sizeof (mStorage.Sample), 0xCC);
  SetMem (mStorage.Result, sizeof (mStorage.Result), 0xCC);
  SetMem (mStorage.EngineShared, sizeof (mStorage.EngineShared), 0xCC);
  mStorageReady = TRUE;
  if (!ServiceGuards () || !Check (Context, mStorage.Sample, sizeof (mStorage.Sample)) ||
      !Check (Context, mStorage.Result, sizeof (mStorage.Result)) ||
      !Check (Context, mStorage.EngineShared, sizeof (mStorage.EngineShared))) {
    return ServiceFail (EFI_SECURITY_VIOLATION, 3);
  }
  if (Budget (Context) < (mStreamDataLimit != 0 ? mStreamDataLimit : N976N_SERVICE_EXPECTED_DATA_BLOCKS)) { return ServiceFail (EFI_OUT_OF_RESOURCES, 4); }
  mN976nServiceReport.Checks |= BIT1;
  ZeroMem (&mServiceMedia, sizeof (mServiceMedia));
  mServiceMedia.MediaId = SERVICE_MEDIA_ID; mServiceMedia.ReadOnly = TRUE;
  mServiceMedia.LogicalPartition = TRUE; mServiceMedia.BlockSize = N976N_BLOCK_BYTES;
  mServiceMedia.IoAlign = 1; mServiceMedia.LastBlock = Blocks - 1;
  ZeroMem (&mServiceBlock, sizeof (mServiceBlock));
  mServiceBlock.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3; mServiceBlock.Media = &mServiceMedia;
  mServiceBlock.ReadBlocks = ServiceBlockRead; mServiceBlock.WriteBlocks = ServiceBlockWrite;
  mServiceBlock.Reset = ServiceBlockReset; mServiceBlock.FlushBlocks = ServiceBlockFlush;
  CopyMem (&mEngineBlock, &mServiceBlock, sizeof (mEngineBlock));
  mServiceDisk.Revision = EFI_DISK_IO_PROTOCOL_REVISION;
  mServiceDisk.ReadDisk = ServiceDiskRead; mServiceDisk.WriteDisk = ServiceDiskWrite;
  CopyMem (&mEngine, &gDiskIoPrivateDataTemplate, sizeof (mEngine));
  mEngine.BlockIo = &mEngineBlock; mEngine.BlockIo2 = NULL;
  mEngine.SharedWorkingBuffer = mStorage.EngineShared;
  InitializeListHead (&mEngine.TaskQueue); EfiInitializeLock (&mEngine.TaskQueueLock, TPL_NOTIFY);
  mEngineReady = TRUE;
  mN976nServiceReport.Phase = 3;
  /* Notification callbacks see fully constructed but inactive interfaces. */
  Status = gBS->InstallMultipleProtocolInterfaces (&mServiceHandle,
    &gEfiBlockIoProtocolGuid, &mServiceBlock, &gEfiDiskIoProtocolGuid, &mServiceDisk, NULL);
  if (EFI_ERROR (Status)) { return ServiceFail (Status, 5); }
  mActive = TRUE; mServiceMedia.MediaPresent = TRUE;
  mN976nServiceReport.Status = EFI_SUCCESS; mN976nServiceReport.Phase = 4;
  return EFI_SUCCESS;
}
EFI_STATUS N976nStartUfsService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context) {
  EFI_STATUS Status;
  if (!ServiceTplAllowed () || mLifecycleBusy || mConsumerBusy) { return EFI_NOT_READY; }
  mLifecycleBusy = TRUE;
  Status = ServiceStart (Start, Blocks, Read, Check, Budget, Context);
  mLifecycleBusy = FALSE;
  return Status;
}
/* The filesystem bridge receives only our private staging bytes. It owns
 * admission of its exact CPU destinations; FAT pointers never enter PRDT. */
EFI_STATUS N976nStartUfsFileService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context) {
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  if (mStarted || mServiceHandle != NULL || mTombstone || mLifecycleBusy || mConsumerBusy) {
    return EFI_ALREADY_STARTED;
  }
  mFileService = TRUE;
  return N976nStartUfsService (Start, Blocks, Read, Check, Budget, Context);
}
UINTN N976nUfsStreamDataLimit (UINTN FileBytes) {
  if (FileBytes == 0 || FileBytes > 0x300000U) { return 0; }
  return ((FileBytes + 8191U) / 8192U) * 3U + N976N_FILE_SERVICE_MAX_DATA_BLOCKS;
}
EFI_STATUS N976nStartUfsStreamService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context, UINTN FileBytes) {
  UINTN Limit = N976nUfsStreamDataLimit (FileBytes);
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  if (Limit == 0) { return EFI_INVALID_PARAMETER; }
  if (mStarted || mServiceHandle != NULL || mTombstone || mLifecycleBusy || mConsumerBusy) {
    return EFI_ALREADY_STARTED;
  }
  mStreamDataLimit = Limit;
  return N976nStartUfsFileService (Start, Blocks, Read, Check, Budget, Context);
}
/* Runtime is a separate finite session; legacy stream limits stay unchanged. */
UINTN N976nUfsBootDataLimit (UINTN FileBytes) {
  UINTN Base = N976nUfsStreamDataLimit (FileBytes);
  return Base == 0 ? 0 : Base + N976N_BOOT_RUNTIME_DATA_BLOCKS;
}
EFI_STATUS N976nStartUfsBootService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context, UINTN FileBytes) {
  UINTN Limit = N976nUfsBootDataLimit (FileBytes);
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  if (Limit == 0) { return EFI_INVALID_PARAMETER; }
  if (mStarted || mServiceHandle != NULL || mTombstone || mLifecycleBusy || mConsumerBusy) {
    return EFI_ALREADY_STARTED;
  }
  mStreamDataLimit = Limit;
  return N976nStartUfsFileService (Start, Blocks, Read, Check, Budget, Context);
}
UINTN N976nUfsOwnedBudget (VOID) {
  return mFileService && mActive && !mBlockBusy && !mDiskBusy ? ServiceAllowance () : 0;
}
BOOLEAN N976nUfsOwnedRangeAllowed (UINT64 Offset, UINTN Bytes) {
  UINT64 Total;
  if (!mFileService || !mActive || mTombstone || Bytes == 0 ||
      mBlocks > MAX_UINT64 / N976N_BLOCK_BYTES) { return FALSE; }
  Total = mBlocks * N976N_BLOCK_BYTES;
  return Offset < Total && Bytes <= Total - Offset;
}
EFI_STATUS N976nReadUfsOwned (UINT64 Offset, UINTN Bytes, CONST UINT8 **Data) {
  EFI_STATUS Status;
  if (Data == NULL) { return EFI_INVALID_PARAMETER; }
  *Data = NULL;
  if (Bytes == 0 || Bytes > sizeof (mStorage.Result)) { return EFI_INVALID_PARAMETER; }
  if (!mFileService) { return EFI_NOT_READY; }
  Status = ServiceDiskRead (&mServiceDisk, SERVICE_MEDIA_ID, Offset, Bytes, mStorage.Result);
  if (!EFI_ERROR (Status)) { *Data = mStorage.Result; }
  return Status;
}
STATIC EFI_STATUS ServiceNegativeContracts (EFI_BLOCK_IO_PROTOCOL *Block, EFI_DISK_IO_PROTOCOL *Disk) {
  UINT8 Foreign = 0x5A;
  UINT64 Count = mN976nServiceReport.DataBlocks;
  if (Block->ReadBlocks (Block, SERVICE_MEDIA_ID + 1, MAX_UINT64, 4095, NULL) != EFI_MEDIA_CHANGED ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID + 1, MAX_UINT64, MAX_UINTN, NULL) != EFI_MEDIA_CHANGED) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT0;
  if (Block->ReadBlocks (Block, SERVICE_MEDIA_ID, 0, 4095, mStorage.Result) != EFI_BAD_BUFFER_SIZE) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT1;
  if (Block->ReadBlocks (Block, SERVICE_MEDIA_ID, mBlocks, 4096, mStorage.Result) != EFI_INVALID_PARAMETER ||
      Block->ReadBlocks (Block, SERVICE_MEDIA_ID, mBlocks - 1, 8192, mStorage.Result) != EFI_INVALID_PARAMETER ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, mBlocks * 4096 - 1, 2, mStorage.Result) != EFI_INVALID_PARAMETER ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, MAX_UINT64, 8, mStorage.Result) != EFI_INVALID_PARAMETER) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT2;
  if (Block->ReadBlocks (Block, SERVICE_MEDIA_ID, 0, 4096, &Foreign) != EFI_INVALID_PARAMETER ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, 0, 1, &Foreign) != EFI_INVALID_PARAMETER || Foreign != 0x5A ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, 0, 8, mStorage.EngineShared) != EFI_INVALID_PARAMETER) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT3;
  if (Block->WriteBlocks (Block, SERVICE_MEDIA_ID, MAX_UINT64, MAX_UINTN, (VOID *)(UINTN)1) != EFI_WRITE_PROTECTED ||
      Block->WriteBlocks (Block, SERVICE_MEDIA_ID, 0, 0, NULL) != EFI_WRITE_PROTECTED ||
      Disk->WriteDisk (Disk, SERVICE_MEDIA_ID, MAX_UINT64, MAX_UINTN, (VOID *)(UINTN)1) != EFI_WRITE_PROTECTED ||
      Disk->WriteDisk (Disk, SERVICE_MEDIA_ID, 0, 0, NULL) != EFI_WRITE_PROTECTED) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT4;
  if (Block->Reset (Block, FALSE) != EFI_UNSUPPORTED || Block->Reset (Block, TRUE) != EFI_UNSUPPORTED) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT5;
  if (Block->FlushBlocks (Block) != EFI_SUCCESS) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT6;
  if (Block->ReadBlocks (Block, SERVICE_MEDIA_ID, MAX_UINT64, 0, NULL) != EFI_SUCCESS ||
      Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, MAX_UINT64, 0, NULL) != EFI_SUCCESS ||
      mN976nServiceReport.DataBlocks != Count || mN976nServiceReport.BlockCalls != 0 ||
      mN976nServiceReport.DiskCalls != 0) { return EFI_COMPROMISED_DATA; }
  mN976nServiceReport.RejectChecks |= BIT7;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS ServiceCompareSlice (EFI_DISK_IO_PROTOCOL *Disk, UINT64 Offset, UINTN Bytes) {
  EFI_STATUS Status;
  if (!ServiceGuards () || !mCheck (mContext, mStorage.Result, sizeof (mStorage.Result))) {
    return EFI_SECURITY_VIOLATION;
  }
  SetMem (mStorage.Result, sizeof (mStorage.Result), 0xCC);
  Status = Disk->ReadDisk (Disk, SERVICE_MEDIA_ID, Offset, Bytes, mStorage.Result + 1);
  if (EFI_ERROR (Status)) { return Status; }
  if (Offset > sizeof (mStorage.Sample) || Bytes > sizeof (mStorage.Sample) - Offset ||
      CompareMem (mStorage.Result + 1, mStorage.Sample + Offset, Bytes) != 0) { return EFI_COMPROMISED_DATA; }
  for (UINTN I = 0; I < sizeof (mStorage.Result); ++I) {
    if ((I == 0 || I > Bytes) && mStorage.Result[I] != 0xCC) { return EFI_SECURITY_VIOLATION; }
  }
  return ServiceGuards () ? EFI_SUCCESS : EFI_SECURITY_VIOLATION;
}
STATIC EFI_STATUS ServiceConsume (VOID) {
  EFI_STATUS Status;
  EFI_BLOCK_IO_PROTOCOL *Block = NULL, *AgainBlock = NULL;
  EFI_DISK_IO_PROTOCOL *Disk = NULL, *AgainDisk = NULL;
  if (!ServiceTplAllowed ()) { return EFI_NOT_READY; }
  if (mLifecycleBusy) { return EFI_NOT_READY; }
  if (!mActive || mServiceHandle == NULL) { return EFI_NO_MEDIA; }
  if (mConsumerStarted || mBlockBusy || mDiskBusy) { return EFI_ALREADY_STARTED; }
  mConsumerStarted = TRUE; mN976nServiceReport.LifeChecks |= BIT0;
  Status = gBS->HandleProtocol (mServiceHandle, &gEfiBlockIoProtocolGuid, (VOID **)&Block);
  if (EFI_ERROR (Status) || Block != &mServiceBlock) { return ServicePoison (EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA, 0x40); }
  Status = gBS->HandleProtocol (mServiceHandle, &gEfiDiskIoProtocolGuid, (VOID **)&Disk);
  if (EFI_ERROR (Status) || Disk != &mServiceDisk) { return ServicePoison (EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA, 0x41); }
  mN976nServiceReport.LifeChecks |= BIT1; mN976nServiceReport.Checks |= BIT2;
  Status = ServiceNegativeContracts (Block, Disk);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x42); }
  mN976nServiceReport.Checks |= BIT3; mN976nServiceReport.Phase = 5;
  Status = Block->ReadBlocks (Block, SERVICE_MEDIA_ID, 0, sizeof (mStorage.Sample), mStorage.Sample);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x43); }
  mN976nServiceReport.SampleCrc = CalculateCrc32 (mStorage.Sample, 4096);
  mN976nServiceReport.Checks |= BIT4;
  if (CompareMem (mStorage.Sample, "ANDROID!", 8) != 0) { return ServicePoison (EFI_COMPROMISED_DATA, 0x44); }
  mN976nServiceReport.Checks |= BIT5; mN976nServiceReport.Phase = 6;
  Status = gBS->HandleProtocol (mServiceHandle, &gEfiBlockIoProtocolGuid, (VOID **)&AgainBlock);
  if (EFI_ERROR (Status) || AgainBlock != Block) { return ServicePoison (EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA, 0x45); }
  Status = gBS->HandleProtocol (mServiceHandle, &gEfiDiskIoProtocolGuid, (VOID **)&AgainDisk);
  if (EFI_ERROR (Status) || AgainDisk != Disk) { return ServicePoison (EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA, 0x46); }
  mN976nServiceReport.LifeChecks |= BIT2;
  Status = ServiceCompareSlice (Disk, 0, 8);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x47); }
  Status = ServiceCompareSlice (Disk, 4093, 8);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x48); }
  mN976nServiceReport.SliceCrc = CalculateCrc32 (mStorage.Result + 1, 8);
  Status = ServiceCompareSlice (Disk, 4096, 4096);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x49); }
  Status = ServiceCompareSlice (Disk, 17, 7);
  if (EFI_ERROR (Status)) { return ServicePoison (Status, 0x4A); }
  mN976nServiceReport.Checks |= BIT6; mN976nServiceReport.Phase = 7;
  return EFI_SUCCESS;
}
EFI_STATUS N976nConsumeUfsService (VOID) {
  EFI_STATUS Status;
  if (mFileService) { return EFI_NOT_READY; }
  if (!ServiceTplAllowed () || mLifecycleBusy || mConsumerBusy) { return EFI_NOT_READY; }
  mConsumerBusy = TRUE;
  Status = ServiceConsume ();
  mConsumerBusy = FALSE;
  return Status;
}
EFI_STATUS N976nStopUfsService (VOID) {
  EFI_STATUS Status;
  UINT64 Blocks;
  if (!ServiceTplAllowed () || mLifecycleBusy || mConsumerBusy) { return EFI_NOT_READY; }
  if (mBlockBusy || mDiskBusy) { return EFI_NOT_READY; }
  mLifecycleBusy = TRUE;
  mActive = FALSE; mServiceMedia.MediaPresent = FALSE;
  if (mServiceHandle != NULL) {
    Status = gBS->UninstallMultipleProtocolInterfaces (mServiceHandle,
      &gEfiBlockIoProtocolGuid, &mServiceBlock, &gEfiDiskIoProtocolGuid, &mServiceDisk, NULL);
    if (EFI_ERROR (Status)) { mTombstone = TRUE; ServiceFail (Status, 0x50); }
    else { mServiceHandle = NULL; }
  }
  Blocks = mN976nServiceReport.DataBlocks;
  if (mStarted && mServiceBlock.ReadBlocks != NULL && mServiceDisk.ReadDisk != NULL) {
    if (mServiceBlock.ReadBlocks (&mServiceBlock, SERVICE_MEDIA_ID + 1, MAX_UINT64, MAX_UINTN, NULL) != EFI_NO_MEDIA ||
        mServiceDisk.ReadDisk (&mServiceDisk, SERVICE_MEDIA_ID + 1, MAX_UINT64, MAX_UINTN, NULL) != EFI_NO_MEDIA ||
        mServiceBlock.WriteBlocks (&mServiceBlock, SERVICE_MEDIA_ID, 0, 0, NULL) != EFI_NO_MEDIA ||
        mServiceDisk.WriteDisk (&mServiceDisk, SERVICE_MEDIA_ID, 0, 0, NULL) != EFI_NO_MEDIA ||
        mN976nServiceReport.DataBlocks != Blocks) { ServiceFail (EFI_COMPROMISED_DATA, 0x51); }
    else { mN976nServiceReport.LifeChecks |= BIT3; }
  }
  mRead = NULL; mCheck = NULL; mBudget = NULL; mContext = NULL;
  if (mStorageReady && !ServiceGuards ()) { ServiceFail (EFI_SECURITY_VIOLATION, 0x52); }
  if (mStorageReady && ServiceGuards () && mServiceHandle == NULL && !mTombstone &&
      !mBlockBusy && !mDiskBusy && ServiceEngineIdle ()) { mN976nServiceReport.Checks |= BIT7; }
  if (mFileService && mN976nServiceReport.Status == EFI_SUCCESS &&
      mN976nServiceReport.Checks == (BIT0 | BIT1 | BIT7) &&
      mN976nServiceReport.LifeChecks == BIT3 && !mActive && !mServiceMedia.MediaPresent && !mBlockBusy && !mDiskBusy &&
      !mConsumerBusy && mRead == NULL && mCheck == NULL && mBudget == NULL && mContext == NULL) {
    mN976nServiceReport.Phase = 8;
  } else if (mN976nServiceReport.Status == EFI_SUCCESS && mN976nServiceReport.Checks == N976N_SERVICE_CHECKS &&
      mN976nServiceReport.LifeChecks == N976N_SERVICE_LIFE_CHECKS &&
      mN976nServiceReport.RejectChecks == N976N_SERVICE_REJECT_CHECKS &&
      mN976nServiceReport.BlockCalls == 6 && mN976nServiceReport.DiskCalls == 4 &&
      mN976nServiceReport.DataBlocks == N976N_SERVICE_EXPECTED_DATA_BLOCKS) { mN976nServiceReport.Phase = 8; }
  else if (mN976nServiceReport.Status == EFI_SUCCESS) { ServiceFail (EFI_COMPROMISED_DATA, 0x53); }
  mLifecycleBusy = FALSE;
  return mN976nServiceReport.Status;
}
BOOLEAN N976nUfsServiceClosed (VOID) {
  return !mActive && !mServiceMedia.MediaPresent && !mBlockBusy && !mDiskBusy &&
    !mLifecycleBusy && !mConsumerBusy && mRead == NULL && mCheck == NULL && mBudget == NULL && mContext == NULL;
}
