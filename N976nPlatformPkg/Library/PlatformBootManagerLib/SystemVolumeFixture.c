/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * QEMU-only, read-only host media for the real GPT/SYSTEM/FAT consumers.
 * The synthetic GPT is not the observed phone table. No media fallback exists
 * in the phone build, and high RAM is published only by the real admitted RAM/volume consumer.
 */
#include <N976nSystemVolumeFixture.h>
#include <N976nSystemProfile.h>
#include <N976nSystemVolume.h>
#include <N976nUfs.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>
#include <Library/SemihostLib.h>

volatile UINT64 mN976nSystemVolumeFixture[8];
#if N976N_SYSTEM_FIXTURE_QEMU
#define FIXTURE_LAST 0x3B94FFFULL
#define FIXTURE_START 0x17A00ULL
#define FIXTURE_BLOCKS 0x182400ULL
#define FIXTURE_BYTES 0x40000000ULL
STATIC CONST N976N_PLATFORM_HANDOFF *mSystemFixtureHandoff;
STATIC EFI_PARTITION_ENTRY mSystemFixtureEntries[128];
STATIC UINT8 mSystemFixtureHeader[4096];
STATIC UINTN mSystemFixtureHandle;
STATIC UINTN mSystemFixturePhase;
STATIC BOOLEAN mSystemFixtureOpen;

STATIC VOID FixtureHeader (BOOLEAN Backup, UINT8 *Block) {
  EFI_PARTITION_TABLE_HEADER *Header = (EFI_PARTITION_TABLE_HEADER *)Block;
  ZeroMem (Block, 4096);
  Header->Header.Signature = EFI_PTAB_HEADER_ID;
  Header->Header.Revision = 0x10000;
  Header->Header.HeaderSize = sizeof (*Header);
  Header->MyLBA = Backup ? FIXTURE_LAST : 1;
  Header->AlternateLBA = Backup ? 1 : FIXTURE_LAST;
  Header->FirstUsableLBA = 6;
  Header->LastUsableLBA = FIXTURE_LAST - 5;
  Header->DiskGUID.Data1 = 0x63363363;
  Header->PartitionEntryLBA = Backup ? FIXTURE_LAST - 4 : 2;
  Header->NumberOfPartitionEntries = 128;
  Header->SizeOfPartitionEntry = sizeof (EFI_PARTITION_ENTRY);
  Header->PartitionEntryArrayCRC32 = CalculateCrc32 (mSystemFixtureEntries, sizeof (mSystemFixtureEntries));
  Header->Header.CRC32 = CalculateCrc32 (Block, sizeof (*Header));
}

STATIC EFI_STATUS EFIAPI FixtureRead (VOID *Context, UINT64 Lba, UINT8 *Block) {
  UINTN Length = 4096;
  RETURN_STATUS Status;
  if (Context != &mSystemFixtureHandoff || mSystemFixtureHandoff == NULL ||
      mSystemFixtureHandoff->Profile != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nPlatformProfile) != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nUfsQueryExperiment) != 13 || !mSystemFixtureOpen ||
      mN976nSystemVolumeFixture[6] != 1 || !N976nUfsCpuRangeAllowed (Block, 4096)) {
    return EFI_ACCESS_DENIED;
  }
  if (mSystemFixturePhase == 1) {
    if (mN976nSystemVolumeFixture[7] >= 11) { return EFI_ACCESS_DENIED; }
    if (Lba == 0) {
      ZeroMem (Block, 4096);
      Block[446 + 4] = 0xEE; Block[446 + 8] = 1;
      SetMem (Block + 446 + 12, 4, 0xFF);
      Block[510] = 0x55; Block[511] = 0xAA;
    } else if (Lba == 1 || Lba == FIXTURE_LAST) {
      FixtureHeader (Lba == FIXTURE_LAST, mSystemFixtureHeader);
      CopyMem (Block, mSystemFixtureHeader, 4096);
    } else if (Lba >= 2 && Lba <= 5) {
      CopyMem (Block, (UINT8 *)mSystemFixtureEntries + (Lba - 2) * 4096, 4096);
    } else if (Lba >= FIXTURE_LAST - 4 && Lba < FIXTURE_LAST) {
      CopyMem (Block, (UINT8 *)mSystemFixtureEntries + (Lba - (FIXTURE_LAST - 4)) * 4096, 4096);
    } else { return EFI_ACCESS_DENIED; }
    ++mN976nSystemVolumeFixture[7];
    return EFI_SUCCESS;
  }
  if (Lba < FIXTURE_START || Lba - FIXTURE_START >= FIXTURE_BYTES / 4096 ||
      mN976nSystemVolumeFixture[5] >= N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS + 2 ||
      (mSystemFixturePhase == 2 && !N976nSystemReadAllowed (Lba, Block)) ||
      (mSystemFixturePhase == 3 && !N976nSystemVolumeReadAllowed (Lba, Block)) ||
      (mSystemFixturePhase != 2 && mSystemFixturePhase != 3)) { return EFI_ACCESS_DENIED; }
  Status = SemihostFileSeek (mSystemFixtureHandle, (UINTN)((Lba - FIXTURE_START) * 4096));
  if (RETURN_ERROR (Status)) { return EFI_DEVICE_ERROR; }
  Status = SemihostFileRead (mSystemFixtureHandle, &Length, Block);
  if (RETURN_ERROR (Status) || Length != 4096) { return EFI_DEVICE_ERROR; }
  ++mN976nSystemVolumeFixture[5];
  return EFI_SUCCESS;
}

EFI_STATUS N976nRunSystemVolumeFixture (CONST N976N_PLATFORM_HANDOFF *Handoff) {
  EFI_STATUS Status;
  RETURN_STATUS Close;
  UINTN Bytes = 0;
  STATIC CONST EFI_GUID Type = {0xEBD0A0A2,0xB9E5,0x4433,{0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}};
  /* Independent physical oracle: references/sec63/guid-correction-2026-10-19.json.
   * Component validation binds this fixture to that receipt, not SvIdentity. */
  STATIC CONST EFI_GUID Unique = {0x52444E41,0x494F,0x2044,{0x73,0x79,0x73,0x74,0x65,0x6D,0,0}};
  if (Handoff == NULL || Handoff->Profile != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nPlatformProfile) != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nUfsQueryExperiment) != 13 ||
      mN976nUfsReport.Phase != 0xF0 || mN976nUfsReport.Buffer != 0 ||
      mN976nUfsReport.CommandCount != 0 || mN976nSystemVolumeFixture[0] != 0) { return EFI_ACCESS_DENIED; }
  mN976nSystemVolumeFixture[0] = SIGNATURE_64 ('N','9','7','6','F','I','X','3');
  mN976nSystemVolumeFixture[1] = 1; mN976nSystemVolumeFixture[2] = 64;
  mN976nSystemVolumeFixture[3] = 1;
  Status = (EFI_STATUS)SemihostFileOpen ("sec63-system.fat", SEMIHOST_FILE_MODE_READ | SEMIHOST_FILE_MODE_BINARY, &mSystemFixtureHandle);
  if (EFI_ERROR (Status)) { goto Done; }
  mSystemFixtureOpen = TRUE;
  mN976nSystemVolumeFixture[6] = 1;
  mN976nSystemVolumeFixture[3] |= 2;
  if (RETURN_ERROR (SemihostFileLength (mSystemFixtureHandle, &Bytes)) || Bytes != FIXTURE_BYTES) {
    Status = EFI_BAD_BUFFER_SIZE; goto Done;
  }
  mSystemFixtureHandoff = Handoff;
  ZeroMem (mSystemFixtureEntries, sizeof (mSystemFixtureEntries));
  mSystemFixtureEntries[25].PartitionTypeGUID = Type;
  mSystemFixtureEntries[25].UniquePartitionGUID = Unique;
  mSystemFixtureEntries[25].StartingLBA = FIXTURE_START;
  mSystemFixtureEntries[25].EndingLBA = FIXTURE_START + FIXTURE_BLOCKS - 1;
  CopyMem (mSystemFixtureEntries[25].PartitionName, L"system", sizeof (L"system"));
  mSystemFixturePhase = 1;
  Status = N976nObserveGpt (FIXTURE_LAST, 4096, FixtureRead, &mSystemFixtureHandoff);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nSystemVolumeFixture[3] |= 4;
  mSystemFixturePhase = 2;
  Status = N976nProbeSystem (FIXTURE_LAST, 4096, FixtureRead, &mSystemFixtureHandoff);
  if (EFI_ERROR (Status)) { goto Done; }
  mN976nSystemVolumeFixture[3] |= 8;
  mSystemFixturePhase = 3;
  Status = N976nConsumeSystemVolume (Handoff, FixtureRead, &mSystemFixtureHandoff);
  if (!EFI_ERROR (Status)) { mN976nSystemVolumeFixture[3] |= 16; }
Done:
  mSystemFixturePhase = 0;
  if (mSystemFixtureOpen) {
    Close = SemihostFileClose (mSystemFixtureHandle);
    if (RETURN_ERROR (Close)) { Status = EFI_DEVICE_ERROR; }
    else { mSystemFixtureOpen = FALSE; mN976nSystemVolumeFixture[6] = 0; mN976nSystemVolumeFixture[3] |= 32; }
  }
  mSystemFixtureHandoff = NULL;
  mN976nSystemVolumeFixture[4] = Status;
  return Status;
}
#else
EFI_STATUS N976nRunSystemVolumeFixture (CONST N976N_PLATFORM_HANDOFF *Handoff) {
  (VOID)Handoff;
  return EFI_UNSUPPORTED;
}
#endif
