/* SEC79 type/runtime bridge only. Parser body below is copied unchanged from
 * FIX5 GptProbe.c; pinned EDK2/Samsung/NTDEV provenance remains in that body.
 * Exactly one observation worker owns its static parser state. */
#include "N976nUfsGpt.h"
#include <string.h>
typedef uint64_t UINT64;typedef uint32_t UINT32;typedef uint8_t UINT8;
typedef size_t UINTN;typedef unsigned char BOOLEAN;typedef uint64_t EFI_STATUS;
#define VOID void
#define CONST const
#define STATIC static
#define EFIAPI
#define TRUE 1
#define FALSE 0
#define MAX_UINT32 UINT32_MAX
#define EFI_SUCCESS UINT64_C(0)
#define EFI_INVALID_PARAMETER (NUF_GPT_ERROR|2)
#define EFI_UNSUPPORTED (NUF_GPT_ERROR|3)
#define EFI_NOT_READY (NUF_GPT_ERROR|6)
#define EFI_DEVICE_ERROR (NUF_GPT_ERROR|7)
#define EFI_VOLUME_CORRUPTED (NUF_GPT_ERROR|10)
#define EFI_CRC_ERROR (NUF_GPT_ERROR|27)
#define EFI_ERROR(s) (((s)&NUF_GPT_ERROR)!=0)
#define EFI_GUID NUF_GPT_GUID
#define EFI_PARTITION_ENTRY NUF_GPT_ENTRY
#define EFI_PARTITION_TABLE_HEADER NUF_GPT_HEADER
#define EFI_PTAB_HEADER_ID UINT64_C(0x5452415020494645)
#define N976N_GPT_MAGIC UINT64_C(0x315450473637394E)
#define N976N_GPT_VERSION 1
#define N976N_GPT_BLOCK_BYTES NUF_GPT_BLOCK
#define N976N_GPT_MAX_ENTRIES NUF_GPT_MAX
#define N976N_GPT_REPORT NUF_GPT_REPORT
#define N976N_GPT_READ NUF_GPT_READ
#define N976N_GPT_PHASE_PMBR 1
#define N976N_GPT_PHASE_PRIMARY 2
#define N976N_GPT_PHASE_PRIMARY_ARRAY 3
#define N976N_GPT_PHASE_ENTRIES 4
#define N976N_GPT_PHASE_BACKUP 5
#define N976N_GPT_PHASE_BACKUP_ARRAY 6
#define N976N_GPT_PHASE_COMPARE 7
#define N976N_GPT_PHASE_COMPLETE 8
#define mN976nGptReport mNufGptReport
#define N976nResetGpt NufResetGpt
#define N976nObserveGpt NufObserveGpt
#define N976nGptEntries NufGptEntries
#define BIT0 1U
#define BIT1 2U
#define BIT2 4U
#define BIT3 8U
#define BIT4 16U
#define BIT5 32U
#define BIT6 64U
#define BIT7 128U
#define ZeroMem(p,n) memset((p),0,(n))
#define SetMem(p,n,v) memset((p),(v),(n))
#define CompareMem(a,b,n) memcmp((a),(b),(n))
#define CalculateCrc32 NufGptCrc32
#define GPT_JOIN_(a,b) a##b
#define GPT_JOIN(a,b) GPT_JOIN_(a,b)
#define STATIC_ASSERT(c,m) typedef char GPT_JOIN(GptStaticAssert,__LINE__)[(c)?1:-1]
uint32_t NufGptCrc32(const void *p,size_t n){const uint8_t *b=p;uint32_t c=UINT32_MAX;
 for(size_t i=0;i<n;i++){c^=b[i];for(unsigned j=0;j<8;j++)c=(c>>1)^((0U-(c&1U))&0xEDB88320U);}return ~c;}

/* BEGIN PRESERVED GPT PARSER BODY */
/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Upstream validation reference copyright (c) 2006-2019 Intel Corporation;
 * copyright (c) 2018 Qualcomm Datacenter Technologies, Inc.;
 * copyright (c) 2026 SUSE LLC. All rights reserved.
 * SEC56 bounded read-only GPT observation. Formats and CRC/range/overlap
 * validation adapted from EDK2 870158586f14dbf9d57e312ea6ea87141a1b0699:
 * MdePkg/Include/Uefi/UefiGpt.h; MdeModulePkg/Library/GptLib/Gpt.c,
 * PartitionValidGptTable, PartitionCheckGptEntryArrayCRC, PartitionCheckGptEntry.
 * Samsung N976N block/partitions/efi.c supplies the reviewed exact-128-byte
 * entry and reciprocal metadata policy, not copied GPL implementation.
 * NTDEV installer/src/S9Woa.Installer.Core/Deploy/Gpt.cs confirms header and
 * full-array CRC use. Its mutation paths are deliberately not imported.
 * No BlockIo/DiskIo publication, allocation, fallback, repair or write API.
 */

STATIC_ASSERT (sizeof (EFI_PARTITION_TABLE_HEADER) == 92, "GPT disk header");
STATIC_ASSERT (sizeof (EFI_PARTITION_ENTRY) == 128, "GPT disk entry");
volatile N976N_GPT_REPORT mN976nGptReport;
STATIC UINT8 mPrimaryBlock[N976N_GPT_BLOCK_BYTES];
STATIC UINT8 mScratch[N976N_GPT_BLOCK_BYTES];
STATIC EFI_PARTITION_ENTRY mPrimary[N976N_GPT_MAX_ENTRIES];
STATIC EFI_PARTITION_ENTRY mBackup[N976N_GPT_MAX_ENTRIES];
STATIC BOOLEAN mAccepted;
STATIC CONST EFI_GUID mZeroGuid = {0};
STATIC CONST EFI_GUID mEspGuid = {
  0xC12A7328, 0xF81F, 0x11D2, {0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}
};

STATIC EFI_STATUS Fail (EFI_STATUS Status, UINT64 Reason) {
  mN976nGptReport.Status = Status; mN976nGptReport.Reason = Reason;
  mAccepted = FALSE; return Status;
}
STATIC UINT32 Le32 (CONST UINT8 *P) {
  return P[0] | ((UINT32)P[1] << 8) | ((UINT32)P[2] << 16) | ((UINT32)P[3] << 24);
}
STATIC BOOLEAN ZeroGuid (CONST EFI_GUID *Guid) {
  return CompareMem (Guid, &mZeroGuid, sizeof (*Guid)) == 0;
}
STATIC EFI_STATUS ReadBlock (UINT64 Last, UINT64 Lba, N976N_GPT_READ Read,
                             VOID *Context, UINT8 *Block, UINT64 Reason) {
  EFI_STATUS Status;
  /* Independent parser-side bound; transport enforces the same allowlist.
     Last >= 16 is checked before subtraction, keeping the windows disjoint. */
  if (Lba > Last || (Lba > 5 && Lba < Last - 4)) {
    return Fail (EFI_UNSUPPORTED, 0x28);
  }
  SetMem (Block, N976N_GPT_BLOCK_BYTES, 0xA5);
  Status = Read (Context, Lba, Block);
  if (EFI_ERROR (Status)) { return Fail (Status, Reason); }
  ++mN976nGptReport.ReadCount;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Pmbr (VOID) {
  UINTN Protective = 0;
  if (mScratch[510] != 0x55 || mScratch[511] != 0xAA) {
    return Fail (EFI_VOLUME_CORRUPTED, 0x11);
  }
  for (UINTN I = 0; I < 4; ++I) {
    CONST UINT8 *P = mScratch + 446 + I * 16;
    if (P[4] == 0xEE) {
      if (P[0] != 0 || Le32 (P + 8) != 1 || Le32 (P + 12) == 0) {
        return Fail (EFI_VOLUME_CORRUPTED, 0x12);
      }
      ++Protective;
    } else {
      for (UINTN J = 0; J < 16; ++J) {
        if (P[J] != 0) { return Fail (EFI_UNSUPPORTED, 0x13); }
      }
    }
  }
  /* Samsung's PMBR length comparison is advisory and uses 512-byte sectors;
     EDK2 also does not require this length to equal the logical last LBA.
     GPT/capacity and the read allowlist, never PMBR size, authorize addresses. */
  return Protective == 1 ? EFI_SUCCESS : Fail (EFI_UNSUPPORTED, 0x13);
}
STATIC EFI_STATUS Header (UINT8 *Block, UINT64 Last, BOOLEAN Backup) {
  EFI_PARTITION_TABLE_HEADER *H = (EFI_PARTITION_TABLE_HEADER *)Block;
  UINT32 Saved, Computed;
  UINT64 Bytes, Blocks;
  if (H->Header.Signature != EFI_PTAB_HEADER_ID || H->Header.Revision != 0x10000 ||
      H->Header.HeaderSize < 92 || H->Header.HeaderSize > N976N_GPT_BLOCK_BYTES ||
      H->Header.Reserved != 0) { return Fail (EFI_VOLUME_CORRUPTED, 0x21); }
  Saved = H->Header.CRC32; H->Header.CRC32 = 0;
  Computed = CalculateCrc32 (Block, H->Header.HeaderSize);
  H->Header.CRC32 = Saved;
  if (Computed != Saved) { return Fail (EFI_CRC_ERROR, 0x22); }
  if (H->MyLBA != (Backup ? Last : 1) || H->AlternateLBA != (Backup ? 1 : Last)) {
    return Fail (EFI_VOLUME_CORRUPTED, 0x23);
  }
  /* Four blocks of entry space remain reserved even when fewer entries are
     advertised. This is the GPT minimum 16 KiB reservation on this 4 KiB disk. */
  if (H->FirstUsableLBA < 6 || H->LastUsableLBA > Last - 5 ||
      H->FirstUsableLBA > H->LastUsableLBA) {
    return Fail (EFI_VOLUME_CORRUPTED, 0x24);
  }
  if (ZeroGuid (&H->DiskGUID)) { return Fail (EFI_VOLUME_CORRUPTED, 0x25); }
  if (H->NumberOfPartitionEntries == 0 || H->NumberOfPartitionEntries > N976N_GPT_MAX_ENTRIES ||
      H->SizeOfPartitionEntry != sizeof (EFI_PARTITION_ENTRY)) {
    return Fail (EFI_UNSUPPORTED, 0x26);
  }
  Bytes = (UINT64)H->NumberOfPartitionEntries * sizeof (EFI_PARTITION_ENTRY);
  Blocks = (Bytes + N976N_GPT_BLOCK_BYTES - 1) / N976N_GPT_BLOCK_BYTES;
  /* Subtraction comparisons precede any LBA addition or callback. */
  if ((!Backup && (H->PartitionEntryLBA < 2 || H->PartitionEntryLBA > 5 ||
                   Blocks > 6 - H->PartitionEntryLBA)) ||
      (Backup && (H->PartitionEntryLBA < Last - 4 || H->PartitionEntryLBA >= Last ||
                  Blocks > Last - H->PartitionEntryLBA))) {
    return Fail (EFI_UNSUPPORTED, 0x27);
  }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Array (CONST EFI_PARTITION_TABLE_HEADER *H, EFI_PARTITION_ENTRY *Entries,
                        UINT64 Last, N976N_GPT_READ Read, VOID *Context) {
  UINTN Bytes = (UINTN)H->NumberOfPartitionEntries * sizeof (*Entries);
  UINTN Blocks = (Bytes + N976N_GPT_BLOCK_BYTES - 1) / N976N_GPT_BLOCK_BYTES;
  for (UINTN I = 0; I < Blocks; ++I) {
    EFI_STATUS Status = ReadBlock (Last, H->PartitionEntryLBA + I, Read, Context,
                                   (UINT8 *)Entries + I * N976N_GPT_BLOCK_BYTES, 0x30);
    if (EFI_ERROR (Status)) { return Status; }
  }
  if (CalculateCrc32 (Entries, Bytes) != H->PartitionEntryArrayCRC32) {
    return Fail (EFI_CRC_ERROR, 0x31);
  }
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Entries (CONST EFI_PARTITION_TABLE_HEADER *H) {
  for (UINTN I = 0; I < H->NumberOfPartitionEntries; ++I) {
    CONST EFI_PARTITION_ENTRY *E = &mPrimary[I];
    if (ZeroGuid (&E->PartitionTypeGUID)) { continue; }
    if (ZeroGuid (&E->UniquePartitionGUID)) { return Fail (EFI_VOLUME_CORRUPTED, 0x40); }
    if (E->StartingLBA > E->EndingLBA || E->StartingLBA < H->FirstUsableLBA ||
        E->EndingLBA > H->LastUsableLBA) { return Fail (EFI_VOLUME_CORRUPTED, 0x41); }
    for (UINTN J = 0; J < I; ++J) {
      CONST EFI_PARTITION_ENTRY *P = &mPrimary[J];
      if (ZeroGuid (&P->PartitionTypeGUID)) { continue; }
      if (CompareMem (&E->UniquePartitionGUID, &P->UniquePartitionGUID, sizeof (EFI_GUID)) == 0) {
        return Fail (EFI_VOLUME_CORRUPTED, 0x43);
      }
      if (E->StartingLBA <= P->EndingLBA && P->StartingLBA <= E->EndingLBA) {
        return Fail (EFI_VOLUME_CORRUPTED, 0x42);
      }
    }
    ++mN976nGptReport.UsedCount;
    if (CompareMem (&E->PartitionTypeGUID, &mEspGuid, sizeof (EFI_GUID)) == 0) {
      ++mN976nGptReport.EspCount;
    }
    if (E->EndingLBA - E->StartingLBA + 1 > mN976nGptReport.LargestBlocks) {
      mN976nGptReport.LargestStart = E->StartingLBA;
      mN976nGptReport.LargestBlocks = E->EndingLBA - E->StartingLBA + 1;
    }
  }
  return EFI_SUCCESS;
}
EFI_STATUS N976nObserveGpt (UINT64 LastLba, UINT32 BlockBytes,
                          N976N_GPT_READ Read, VOID *Context) {
  EFI_STATUS Status;
  EFI_PARTITION_TABLE_HEADER *Primary = (EFI_PARTITION_TABLE_HEADER *)mPrimaryBlock;
  EFI_PARTITION_TABLE_HEADER *Backup = (EFI_PARTITION_TABLE_HEADER *)mScratch;
  N976nResetGpt ();
  if (Read == NULL) { return Fail (EFI_INVALID_PARAMETER, 1); }
  if (BlockBytes != N976N_GPT_BLOCK_BYTES || LastLba < 16 || LastLba >= MAX_UINT32) {
    return Fail (EFI_UNSUPPORTED, 2);
  }
  mN976nGptReport.Phase = N976N_GPT_PHASE_PMBR;
  Status = ReadBlock (LastLba, 0, Read, Context, mScratch, 0x10);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Pmbr (); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT0;
  mN976nGptReport.Phase = N976N_GPT_PHASE_PRIMARY;
  Status = ReadBlock (LastLba, 1, Read, Context, mPrimaryBlock, 0x20);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Header (mPrimaryBlock, LastLba, FALSE); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT1;
  mN976nGptReport.PrimaryHeaderCrc32 = Primary->Header.CRC32;
  mN976nGptReport.EntryCount = Primary->NumberOfPartitionEntries;
  mN976nGptReport.TableCrc32 = Primary->PartitionEntryArrayCRC32;
  mN976nGptReport.Phase = N976N_GPT_PHASE_PRIMARY_ARRAY;
  Status = Array (Primary, mPrimary, LastLba, Read, Context); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT2;
  mN976nGptReport.Phase = N976N_GPT_PHASE_ENTRIES;
  Status = Entries (Primary); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT3;
  mN976nGptReport.Phase = N976N_GPT_PHASE_BACKUP;
  Status = ReadBlock (LastLba, LastLba, Read, Context, mScratch, 0x50);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Header (mScratch, LastLba, TRUE); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT4;
  mN976nGptReport.BackupHeaderCrc32 = Backup->Header.CRC32;
  mN976nGptReport.Phase = N976N_GPT_PHASE_BACKUP_ARRAY;
  Status = Array (Backup, mBackup, LastLba, Read, Context); if (EFI_ERROR (Status)) { return Status; }
  mN976nGptReport.Checks |= BIT5;
  mN976nGptReport.Phase = N976N_GPT_PHASE_COMPARE;
  if (Primary->Header.HeaderSize != Backup->Header.HeaderSize ||
      Primary->FirstUsableLBA != Backup->FirstUsableLBA ||
      Primary->LastUsableLBA != Backup->LastUsableLBA ||
      CompareMem (&Primary->DiskGUID, &Backup->DiskGUID, sizeof (EFI_GUID)) != 0 ||
      Primary->NumberOfPartitionEntries != Backup->NumberOfPartitionEntries ||
      Primary->SizeOfPartitionEntry != Backup->SizeOfPartitionEntry ||
      Primary->PartitionEntryArrayCRC32 != Backup->PartitionEntryArrayCRC32 ||
      CompareMem (mPrimaryBlock + 92, mScratch + 92, Primary->Header.HeaderSize - 92) != 0) {
    return Fail (EFI_VOLUME_CORRUPTED, 0x70);
  }
  mN976nGptReport.Checks |= BIT6;
  if (CompareMem (mPrimary, mBackup, Primary->NumberOfPartitionEntries * sizeof (*mPrimary)) != 0) {
    return Fail (EFI_VOLUME_CORRUPTED, 0x71);
  }
  mN976nGptReport.Checks |= BIT7;
  mN976nGptReport.Phase = N976N_GPT_PHASE_COMPLETE;
  mN976nGptReport.Status = EFI_SUCCESS; mAccepted = TRUE;
  return EFI_SUCCESS;
}
CONST EFI_PARTITION_ENTRY *N976nGptEntries (VOID) {
  return mAccepted ? mPrimary : NULL;
}
VOID N976nResetGpt (VOID) {
  mAccepted = FALSE;
  ZeroMem ((VOID *)&mN976nGptReport, sizeof (mN976nGptReport));
  mN976nGptReport.Magic = N976N_GPT_MAGIC; mN976nGptReport.Version = N976N_GPT_VERSION;
  mN976nGptReport.Size = sizeof (mN976nGptReport);
  mN976nGptReport.Status = EFI_NOT_READY;
  ZeroMem (mPrimary, sizeof (mPrimary)); ZeroMem (mBackup, sizeof (mBackup));
}
