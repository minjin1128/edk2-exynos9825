/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC56 bounded read-only BlockIo diagnostic, adapted to N976N's live owned
 * UFS session. NTDEV's pinned Star2LtePkg.dsc storage composition supplies the
 * standard-interface direction, not proof of N976N controller behavior.
 * EDK2 870158586f14dbf9d57e312ea6ea87141a1b0699: Protocol/BlockIo.h supplies
 * the ABI; PartitionDxe/Partition.c:1197-1225 supplies logical-partition
 * geometry; UefiGpt.h forbids publication when GPT attribute bit1 is set.
 * Core/Dxe/Hand/Handle.c installation/removal can invoke notifications and
 * driver callbacks: this object's gate is closed throughout those operations.
 * No DevicePath/ConnectController, allocation/free, DiskIo/PartitionDxe/FAT,
 * arbitrary caller destination, controller reset, media write or GPT repair.
 */
#include <N976nUfsBlock.h>
#include <N976nGpt.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/BlockIo.h>

#define BLOCK_MEDIA_ID 0x533531U
#define BLOCK_GUARD_BYTES 64U
#define BLOCK_DATA_LIMIT 3U
typedef struct {
  UINT8 Before[BLOCK_GUARD_BYTES];
  UINT8 Sample[2 * N976N_BLOCK_BYTES];
  UINT8 Between[BLOCK_GUARD_BYTES];
  UINT8 Repeat[N976N_BLOCK_BYTES];
  UINT8 After[BLOCK_GUARD_BYTES];
} BLOCK_SAMPLES;

volatile N976N_BLOCK_REPORT mN976nBlockReport;
STATIC BLOCK_SAMPLES mSamples;
STATIC EFI_BLOCK_IO_PROTOCOL mBlockIo;
STATIC EFI_BLOCK_IO_MEDIA mMedia;
STATIC EFI_HANDLE mBlockHandle;
STATIC N976N_BLOCK_READ mBlockRead;
STATIC N976N_BLOCK_BUFFER_CHECK mBlockCheck;
STATIC N976N_BLOCK_BUDGET mBlockBudget;
STATIC VOID *mBlockContext;
STATIC UINT64 mSelectedStart, mSelectedBlocks, mSelectedLast;
STATIC BOOLEAN mSelected, mActive, mBusy, mProbeStarted, mTombstone, mFailureRecorded;

STATIC EFI_STATUS BlockFail (EFI_STATUS Status, UINT64 Reason) {
  if (!mFailureRecorded) {
    mN976nBlockReport.Status = Status; mN976nBlockReport.Reason = Reason;
    mFailureRecorded = TRUE;
  }
  return Status;
}
STATIC BOOLEAN BlockContains (CONST VOID *Base, UINTN Size, CONST VOID *Buffer, UINTN Bytes) {
  UINTN B = (UINTN)Base, P = (UINTN)Buffer;
  return Buffer != NULL && Bytes != 0 && Size <= MAX_UINTN - B &&
    P >= B && P - B <= Size && Bytes <= Size - (P - B);
}
BOOLEAN N976nBlockBufferOwned (CONST VOID *Buffer, UINTN Bytes) {
  return BlockContains (mSamples.Sample, sizeof (mSamples.Sample), Buffer, Bytes) ||
    BlockContains (mSamples.Repeat, sizeof (mSamples.Repeat), Buffer, Bytes);
}
BOOLEAN N976nBlockStorageOwned (CONST VOID *Buffer, UINTN Bytes) {
  return Buffer == &mSamples && Bytes == sizeof (mSamples);
}
STATIC BOOLEAN BlockGuards (VOID) {
  for (UINTN I = 0; I < BLOCK_GUARD_BYTES; ++I) {
    if (mSamples.Before[I] != 0xA5 || mSamples.Between[I] != 0xA5 ||
        mSamples.After[I] != 0xA5) { return FALSE; }
  }
  return TRUE;
}
STATIC BOOLEAN BlockGuidZero (CONST EFI_GUID *Guid) {
  STATIC CONST EFI_GUID Zero = {0};
  return CompareMem (Guid, &Zero, sizeof (Zero)) == 0;
}
STATIC BOOLEAN BootName (CONST CHAR16 *Name) {
  STATIC CONST CHAR16 Wanted[4] = { 'b', 'o', 'o', 't' };
  for (UINTN I = 0; I < 4; ++I) {
    CHAR16 C = Name[I];
    if (C >= 'A' && C <= 'Z') { C += 'a' - 'A'; }
    if (C != Wanted[I]) { return FALSE; }
  }
  return Name[4] == 0; /* Exact bounded name, never a prefix or an unbounded string. */
}
VOID N976nResetBlockProbe (VOID) {
  /* A failed uninstall can leave external holders. Keep the static object and
   * its permanent tombstone; resetting diagnostics must never revive it. */
  mActive = FALSE; mBusy = FALSE; mMedia.MediaPresent = FALSE;
  mSelected = FALSE; mProbeStarted = FALSE; mFailureRecorded = FALSE;
  mBlockRead = NULL; mBlockCheck = NULL; mBlockBudget = NULL; mBlockContext = NULL;
  mSelectedStart = 0; mSelectedBlocks = 0; mSelectedLast = 0;
  ZeroMem ((VOID *)&mN976nBlockReport, sizeof (mN976nBlockReport));
  mN976nBlockReport.Magic = N976N_BLOCK_MAGIC;
  mN976nBlockReport.Version = N976N_BLOCK_VERSION;
  mN976nBlockReport.Size = sizeof (mN976nBlockReport);
  mN976nBlockReport.Status = EFI_NOT_READY;
}
EFI_STATUS N976nSelectBootPartition (UINT64 DiskLast, UINT64 *Start, UINT64 *Blocks) {
  CONST EFI_PARTITION_ENTRY *Entries = N976nGptEntries ();
  CONST EFI_PARTITION_ENTRY *Found = NULL;
  mN976nBlockReport.Phase = 1;
  if (mTombstone || mBlockHandle != NULL || mActive || mBusy || mProbeStarted) {
    return BlockFail (EFI_ALREADY_STARTED, 1);
  }
  mSelected = FALSE;
  if (Start == NULL || Blocks == NULL) { return BlockFail (EFI_INVALID_PARAMETER, 2); }
  *Start = 0; *Blocks = 0;
  if (Entries == NULL || mN976nGptReport.Magic != N976N_GPT_MAGIC ||
      mN976nGptReport.Version != N976N_GPT_VERSION ||
      mN976nGptReport.Size != sizeof (mN976nGptReport) ||
      mN976nGptReport.Phase != N976N_GPT_PHASE_COMPLETE ||
      mN976nGptReport.Status != EFI_SUCCESS || mN976nGptReport.Checks != 0xFF ||
      mN976nGptReport.EntryCount == 0 || mN976nGptReport.EntryCount > N976N_GPT_MAX_ENTRIES ||
      DiskLast < 16 || DiskLast >= MAX_UINT32) { return BlockFail (EFI_NOT_READY, 3); }
  for (UINTN I = 0; I < mN976nGptReport.EntryCount; ++I) {
    CONST EFI_PARTITION_ENTRY *E = &Entries[I];
    if (BlockGuidZero (&E->PartitionTypeGUID) || !BootName (E->PartitionName)) { continue; }
    if (Found != NULL) { return BlockFail (EFI_VOLUME_CORRUPTED, 4); }
    Found = E;
  }
  if (Found == NULL) { return BlockFail (EFI_NOT_FOUND, 5); }
  if ((Found->Attributes & BIT1) != 0) { return BlockFail (EFI_UNSUPPORTED, 6); }
  if (BlockGuidZero (&Found->UniquePartitionGUID) || Found->StartingLBA < 6 ||
      Found->EndingLBA > DiskLast - 5 || Found->StartingLBA >= Found->EndingLBA) {
    return BlockFail (EFI_VOLUME_CORRUPTED, 7);
  }
  mSelectedStart = Found->StartingLBA;
  mSelectedBlocks = Found->EndingLBA - Found->StartingLBA + 1;
  mSelectedLast = DiskLast; mSelected = TRUE;
  *Start = mSelectedStart; *Blocks = mSelectedBlocks;
  mN976nBlockReport.PartitionStart = *Start; mN976nBlockReport.PartitionBlocks = *Blocks;
  mN976nBlockReport.Checks |= BIT0; mN976nBlockReport.Status = EFI_SUCCESS;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS BlockRequest (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                               EFI_LBA Lba, UINTN Bytes, CONST VOID *Buffer) {
  if (This != &mBlockIo) { return EFI_INVALID_PARAMETER; }
  if (!mActive || mTombstone || !mMedia.MediaPresent) { return EFI_NO_MEDIA; }
  if (MediaId != BLOCK_MEDIA_ID) { return EFI_MEDIA_CHANGED; }
  if (mBusy) { return EFI_NOT_READY; }
  if (Bytes == 0) { return EFI_SUCCESS; }
  if (Bytes % N976N_BLOCK_BYTES != 0) { return EFI_BAD_BUFFER_SIZE; }
  if (mSelectedBlocks < 2 || Lba >= mSelectedBlocks ||
      Bytes / N976N_BLOCK_BYTES > mSelectedBlocks - Lba ||
      mSelectedStart > mSelectedLast || Lba > mSelectedLast - mSelectedStart ||
      Bytes / N976N_BLOCK_BYTES - 1 > mSelectedLast - mSelectedStart - Lba ||
      !N976nBlockBufferOwned (Buffer, Bytes)) { return EFI_INVALID_PARAMETER; }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI BlockRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                                   EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  EFI_STATUS Status = BlockRequest (This, MediaId, Lba, Bytes, Buffer);
  UINTN Blocks = Bytes / N976N_BLOCK_BYTES;
  if (EFI_ERROR (Status) || Bytes == 0) { return Status; }
  mBusy = TRUE;
  if (!BlockGuards () || !mBlockCheck (mBlockContext, Buffer, Bytes)) {
    Status = EFI_SECURITY_VIOLATION; goto Failed;
  }
  if (mN976nBlockReport.ReadBlocks > BLOCK_DATA_LIMIT ||
      Blocks > BLOCK_DATA_LIMIT - mN976nBlockReport.ReadBlocks ||
      Blocks > mBlockBudget (mBlockContext)) { Status = EFI_OUT_OF_RESOURCES; goto Failed; }
  for (UINTN I = 0; I < Blocks; ++I) {
    UINT8 *Target = (UINT8 *)Buffer + I * N976N_BLOCK_BYTES;
    if (!mActive || mBlockBudget (mBlockContext) < Blocks - I) {
      Status = EFI_OUT_OF_RESOURCES; goto Failed;
    }
    if (!BlockGuards () || !mBlockCheck (mBlockContext, Target, N976N_BLOCK_BYTES)) {
      Status = EFI_SECURITY_VIOLATION; goto Failed;
    }
    Status = mBlockRead (mBlockContext, mSelectedStart + Lba + I, Target);
    if (EFI_ERROR (Status)) { goto Failed; }
    if (!BlockGuards ()) { Status = EFI_SECURITY_VIOLATION; goto Failed; }
    ++mN976nBlockReport.ReadBlocks;
  }
  ++mN976nBlockReport.ReadCalls; mBusy = FALSE;
  return EFI_SUCCESS;
Failed:
  mActive = FALSE; mMedia.MediaPresent = FALSE; mBusy = FALSE;
  return Status;
}
STATIC EFI_STATUS EFIAPI BlockWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId,
                                    EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
  (VOID)Lba; (VOID)Bytes; (VOID)Buffer;
  if (This != &mBlockIo) { return EFI_INVALID_PARAMETER; }
  if (!mActive || mTombstone || !mMedia.MediaPresent) { return EFI_NO_MEDIA; }
  if (MediaId != BLOCK_MEDIA_ID) { return EFI_MEDIA_CHANGED; }
  return EFI_WRITE_PROTECTED; /* Even zero-byte or invalid-pointer writes never dereference. */
}
STATIC EFI_STATUS EFIAPI BlockReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
  (VOID)Extended;
  return This == &mBlockIo ? EFI_UNSUPPORTED : EFI_INVALID_PARAMETER;
}
STATIC EFI_STATUS EFIAPI BlockFlush (EFI_BLOCK_IO_PROTOCOL *This) {
  if (This != &mBlockIo) { return EFI_INVALID_PARAMETER; }
  return mActive && !mTombstone && mMedia.MediaPresent ? EFI_SUCCESS : EFI_NO_MEDIA;
}
STATIC EFI_STATUS NegativeContracts (EFI_BLOCK_IO_PROTOCOL *Io) {
  UINT64 Before = mN976nBlockReport.ReadBlocks;
  UINT8 Foreign = 0x5A;
  if (Io->ReadBlocks (Io, BLOCK_MEDIA_ID + 1, 0, 4096, mSamples.Sample) != EFI_MEDIA_CHANGED) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT0;
  if (Io->ReadBlocks (Io, BLOCK_MEDIA_ID, 0, 4095, mSamples.Sample) != EFI_BAD_BUFFER_SIZE) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT1;
  if (Io->ReadBlocks (Io, BLOCK_MEDIA_ID, mSelectedBlocks, 4096, mSamples.Sample) != EFI_INVALID_PARAMETER ||
      Io->ReadBlocks (Io, BLOCK_MEDIA_ID, mSelectedBlocks - 1, 8192, mSamples.Sample) != EFI_INVALID_PARAMETER) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT2;
  if (Io->ReadBlocks (Io, BLOCK_MEDIA_ID, 0, 4096, &Foreign) != EFI_INVALID_PARAMETER || Foreign != 0x5A) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT3;
  if (Io->WriteBlocks (Io, BLOCK_MEDIA_ID, MAX_UINT64, MAX_UINTN, (VOID *)(UINTN)1) != EFI_WRITE_PROTECTED ||
      Io->WriteBlocks (Io, BLOCK_MEDIA_ID, 0, 0, NULL) != EFI_WRITE_PROTECTED) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT4;
  if (Io->Reset (Io, FALSE) != EFI_UNSUPPORTED || Io->Reset (Io, TRUE) != EFI_UNSUPPORTED) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT5;
  if (Io->FlushBlocks (Io) != EFI_SUCCESS) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT6;
  if (Io->ReadBlocks (Io, BLOCK_MEDIA_ID, MAX_UINT64, 0, NULL) != EFI_SUCCESS ||
      Io->ReadBlocks (Io, BLOCK_MEDIA_ID + 1, MAX_UINT64, 0, NULL) != EFI_MEDIA_CHANGED ||
      mN976nBlockReport.ReadBlocks != Before || mN976nBlockReport.ReadCalls != 0) { return EFI_COMPROMISED_DATA; }
  mN976nBlockReport.RejectChecks |= BIT7;
  return EFI_SUCCESS;
}
EFI_STATUS N976nProbeBootBlocks (UINT64 Start, UINT64 Blocks, N976N_BLOCK_READ Read,
  N976N_BLOCK_BUFFER_CHECK Check, N976N_BLOCK_BUDGET Budget, VOID *Context) {
  EFI_STATUS Status;
  EFI_BLOCK_IO_PROTOCOL *Io = NULL;
  if (mTombstone || mBlockHandle != NULL || mProbeStarted || mBusy || mActive) {
    return BlockFail (EFI_ALREADY_STARTED, 0x10);
  }
  mProbeStarted = TRUE;
  if (!mSelected || Start != mSelectedStart || Blocks != mSelectedBlocks || Blocks < 2 ||
      Read == NULL || Check == NULL || Budget == NULL || Context == NULL) {
    return BlockFail (EFI_INVALID_PARAMETER, 0x11);
  }
  mN976nBlockReport.Phase = 2;
  /* Admit the full guarded storage before its first CPU write. Checking only
   * the arrays could omit a guard on a neighboring page. This exact-object
   * admission grants no permission to use guards as read destinations. */
  if (!Check (Context, &mSamples, sizeof (mSamples))) {
    return BlockFail (EFI_SECURITY_VIOLATION, 0x12);
  }
  SetMem (&mSamples, sizeof (mSamples), 0xA5);
  SetMem (mSamples.Sample, sizeof (mSamples.Sample), 0xCC);
  SetMem (mSamples.Repeat, sizeof (mSamples.Repeat), 0xCC);
  mBlockRead = Read; mBlockCheck = Check; mBlockBudget = Budget; mBlockContext = Context;
  if (!Check (Context, mSamples.Sample, sizeof (mSamples.Sample)) ||
      !Check (Context, mSamples.Repeat, sizeof (mSamples.Repeat)) || !BlockGuards ()) {
    return BlockFail (EFI_SECURITY_VIOLATION, 0x12);
  }
  if (Budget (Context) < BLOCK_DATA_LIMIT) { return BlockFail (EFI_OUT_OF_RESOURCES, 0x13); }
  mN976nBlockReport.Checks |= BIT1;
  ZeroMem (&mMedia, sizeof (mMedia));
  mMedia.MediaId = BLOCK_MEDIA_ID; mMedia.LogicalPartition = TRUE; mMedia.ReadOnly = TRUE;
  mMedia.BlockSize = N976N_BLOCK_BYTES; mMedia.IoAlign = 1; mMedia.LastBlock = Blocks - 1;
  ZeroMem (&mBlockIo, sizeof (mBlockIo));
  mBlockIo.Revision = EFI_BLOCK_IO_PROTOCOL_REVISION3; mBlockIo.Media = &mMedia;
  mBlockIo.Reset = BlockReset; mBlockIo.ReadBlocks = BlockRead;
  mBlockIo.WriteBlocks = BlockWrite; mBlockIo.FlushBlocks = BlockFlush;
  mActive = FALSE; mMedia.MediaPresent = FALSE;
  mN976nBlockReport.Phase = 3;
  Status = gBS->InstallProtocolInterface (&mBlockHandle, &gEfiBlockIoProtocolGuid,
                                         EFI_NATIVE_INTERFACE, &mBlockIo);
  if (EFI_ERROR (Status)) { BlockFail (Status, 0x14); goto Done; }
  Status = gBS->HandleProtocol (mBlockHandle, &gEfiBlockIoProtocolGuid, (VOID **)&Io);
  if (EFI_ERROR (Status) || Io != &mBlockIo) {
    BlockFail (EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA, 0x15); goto Done;
  }
  mN976nBlockReport.Checks |= BIT2;
  mActive = TRUE; mMedia.MediaPresent = TRUE;
  mN976nBlockReport.Phase = 4;
  Status = NegativeContracts (Io);
  if (EFI_ERROR (Status)) { BlockFail (Status, 0x16); goto Done; }
  mN976nBlockReport.Checks |= BIT3;
  mN976nBlockReport.Phase = 5;
  Status = Io->ReadBlocks (Io, BLOCK_MEDIA_ID, 0, sizeof (mSamples.Sample), mSamples.Sample);
  if (EFI_ERROR (Status)) { BlockFail (Status, 0x17); goto Done; }
  mN976nBlockReport.Checks |= BIT4;
  CopyMem ((VOID *)&mN976nBlockReport.FirstQword, mSamples.Sample, sizeof (UINT64));
  mN976nBlockReport.FirstCrc = CalculateCrc32 (mSamples.Sample, N976N_BLOCK_BYTES);
  mN976nBlockReport.SecondCrc = CalculateCrc32 (mSamples.Sample + N976N_BLOCK_BYTES, N976N_BLOCK_BYTES);
  mN976nBlockReport.Phase = 6;
  if (CompareMem (mSamples.Sample, "ANDROID!", 8) != 0) {
    BlockFail (EFI_COMPROMISED_DATA, 0x18); goto Done;
  }
  mN976nBlockReport.Checks |= BIT5;
  mN976nBlockReport.Phase = 7;
  Status = Io->ReadBlocks (Io, BLOCK_MEDIA_ID, 0, sizeof (mSamples.Repeat), mSamples.Repeat);
  if (EFI_ERROR (Status)) { BlockFail (Status, 0x19); goto Done; }
  mN976nBlockReport.RepeatCrc = CalculateCrc32 (mSamples.Repeat, N976N_BLOCK_BYTES);
  if (CompareMem (mSamples.Sample, mSamples.Repeat, N976N_BLOCK_BYTES) != 0) {
    BlockFail (EFI_COMPROMISED_DATA, 0x1A); goto Done;
  }
  mN976nBlockReport.Checks |= BIT6;
Done:
  mActive = FALSE; mMedia.MediaPresent = FALSE;
  if (mBlockHandle != NULL) {
    Status = gBS->UninstallProtocolInterface (mBlockHandle, &gEfiBlockIoProtocolGuid, &mBlockIo);
    if (EFI_ERROR (Status)) { mTombstone = TRUE; BlockFail (Status, 0x1B); }
    else { mBlockHandle = NULL; }
  }
  mBlockRead = NULL; mBlockCheck = NULL; mBlockBudget = NULL; mBlockContext = NULL;
  if (!BlockGuards ()) { BlockFail (EFI_SECURITY_VIOLATION, 0x1C); }
  else if (mBlockHandle == NULL && !mActive && !mBusy && !mTombstone) {
    mN976nBlockReport.Checks |= BIT7;
  }
  if (mN976nBlockReport.Status == EFI_SUCCESS &&
      mN976nBlockReport.Checks == N976N_BLOCK_CHECKS &&
      mN976nBlockReport.RejectChecks == N976N_BLOCK_REJECT_CHECKS &&
      mN976nBlockReport.ReadCalls == 2 && mN976nBlockReport.ReadBlocks == 3) {
    mN976nBlockReport.Phase = 8;
  } else if (mN976nBlockReport.Status == EFI_SUCCESS) {
    BlockFail (EFI_COMPROMISED_DATA, 0x1D);
  }
  return mN976nBlockReport.Status;
}
