/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC62 FIX2 bounded read-only SYSTEM identity and payload observation.
 * NTDEV6e2cacf15f6b99b198ed12ad242da69eb2259bac obtains PIT through its
 * separate Odin transfer command. A GPT entry named PIT is not required.
 * GPT wire types and already accepted parser: pinned upstream EDK2.
 * Exactly two SYSTEM blocks only; no PIT reads/write/repair/public BlockIo.
 */
#include <N976nSystemProbe.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>

volatile N976N_SYSTEM_REPORT mN976nSystemReport;
volatile N976N_SYSTEM_NAMES_REPORT mN976nSystemNamesReport;
STATIC EFI_PARTITION_ENTRY mSystemEntry, mPitEntry;
STATIC UINT8 mContent[8192];
STATIC BOOLEAN mSelected, mRunning, mPending, mSystemKnown, mPitKnown;
STATIC UINT64 mExpectedLba, mDiskLast;
STATIC UINT8 *mExpectedBuffer;
STATIC UINT32 Le32 (CONST UINT8 *P) {
  return P[0] | ((UINT32)P[1] << 8) | ((UINT32)P[2] << 16) | ((UINT32)P[3] << 24);
}
STATIC UINT64 Le64 (CONST UINT8 *P) { return Le32 (P) | ((UINT64)Le32 (P + 4) << 32); }
STATIC UINT16 Fold (UINT16 C) { return C >= 'a' && C <= 'z' ? C - ('a' - 'A') : C; }
/* Upstream UefiGpt.h specifies a NUL-terminated CHAR16[36]. BaseLib's
 * string comparisons stop at NUL. Do not call StrnCmp on this untrusted field:
 * its ASSERT path can StrSize beyond it. Bound every access explicitly.
 * NTDEV's pinned EntryName TrimEnd(NUL) is different; not copied here. */
STATIC UINTN NameTerm (CONST CHAR16 *Field) {
  for (UINTN I = 0; I < 36; ++I) if (Field[I] == 0) return I;
  return 36;
}
STATIC BOOLEAN Prefix (CONST CHAR16 *Field, CONST CHAR8 *Want) {
  for (UINTN I = 0; I < 36; ++I) {
    if (Want[I] == 0) return TRUE;
    if (Field[I] > 0x7F || Fold (Field[I]) != Fold ((UINT8)Want[I])) return FALSE;
  }
  return FALSE;
}
STATIC BOOLEAN Name (CONST CHAR16 *Field, CONST CHAR8 *Want) {
  for (UINTN I = 0; I < 36; ++I) {
    if (Want[I] == 0) return Field[I] == 0;
    if (Field[I] > 0x7F || Fold (Field[I]) != Fold ((UINT8)Want[I])) return FALSE;
  }
  return FALSE;
}
STATIC UINTN NameTail (CONST CHAR16 *Field, UINTN Term) {
  UINTN Count = 0;
  if (Term >= 36) return 0;
  for (UINTN I = Term + 1; I < 36; ++I) if (Field[I] != 0) ++Count;
  return Count;
}
VOID N976nFormatGptName (CONST CHAR16 Field[36], CHAR16 Text[37]) {
  CHAR16 Safe[37];
  if (Text == NULL) return;
  ZeroMem (Safe, sizeof (Safe));
  if (Field != NULL) {
    for (UINTN I = 0; I < 36 && Field[I] != 0; ++I)
      Safe[I] = Field[I] >= 0x20 && Field[I] <= 0x7E ? Field[I] : '?';
  }
  CopyMem (Text, Safe, sizeof (Safe));
}
STATIC BOOLEAN GuidZero (CONST EFI_GUID *Guid) {
  CONST UINT8 *P = (CONST UINT8 *)Guid;
  for (UINTN I = 0; I < sizeof (*Guid); ++I) if (P[I] != 0) return FALSE;
  return TRUE;
}
STATIC EFI_STATUS Fail (EFI_STATUS Status, UINT64 Reason) {
  mN976nSystemReport.Status = Status; mN976nSystemReport.Reason = Reason;
  mPending = FALSE; mRunning = FALSE; mExpectedBuffer = NULL; mExpectedLba = 0;
  return Status;
}
VOID N976nResetSystemProbe (VOID) {
  if (mRunning) return;
  ZeroMem ((VOID *)&mN976nSystemReport, sizeof (mN976nSystemReport));
  mN976nSystemReport.Magic = N976N_SYSTEM_MAGIC; mN976nSystemReport.Version = 2;
  mN976nSystemReport.Size = sizeof (mN976nSystemReport);
  mN976nSystemReport.Status = EFI_NOT_READY;
  mN976nSystemReport.ImageBytes = N976N_SYSTEM_IMAGE_BYTES;
  mSelected = FALSE; mSystemKnown = FALSE; mPitKnown = FALSE; mPending = FALSE; mExpectedBuffer = NULL; mExpectedLba = 0; mDiskLast = 0;
  ZeroMem (&mSystemEntry, sizeof (mSystemEntry)); ZeroMem (&mPitEntry, sizeof (mPitEntry));
  ZeroMem (mContent, sizeof (mContent));
  ZeroMem ((VOID *)&mN976nSystemNamesReport, sizeof (mN976nSystemNamesReport));
  mN976nSystemNamesReport.Magic = N976N_SYSTEM_NAMES_MAGIC;
  mN976nSystemNamesReport.Version = 1; mN976nSystemNamesReport.Size = sizeof (mN976nSystemNamesReport);
  mN976nSystemNamesReport.SystemTerm = 36; mN976nSystemNamesReport.PitTerm = 36;
}
CONST EFI_PARTITION_ENTRY *N976nSystemEntry (VOID) { return mSystemKnown ? &mSystemEntry : NULL; }
CONST EFI_PARTITION_ENTRY *N976nSystemPitEntry (VOID) { return mPitKnown ? &mPitEntry : NULL; }
BOOLEAN N976nSystemProbeClosed (VOID) { return !mRunning && !mPending && mExpectedBuffer == NULL; }
BOOLEAN N976nSystemLbaAllowed (UINT64 Lba) {
  if (!mRunning || !mSelected || !mPending || Lba != mExpectedLba || Lba > mDiskLast ||
      mN976nSystemReport.ReadCount >= 2) return FALSE;
  return Lba >= mSystemEntry.StartingLBA && Lba - mSystemEntry.StartingLBA < 2;
}
BOOLEAN N976nSystemReadAllowed (UINT64 Lba, CONST VOID *Buffer) {
  return Buffer != NULL && Buffer == mExpectedBuffer && N976nSystemLbaAllowed (Lba);
}
STATIC EFI_STATUS ReadOne (UINT64 Lba, UINT8 *Buffer, N976N_GPT_READ Read, VOID *Context) {
  EFI_STATUS Status;
  if (mPending || mExpectedBuffer != NULL) return Fail (EFI_ALREADY_STARTED, 0x20);
  mExpectedLba = Lba; mExpectedBuffer = Buffer; mPending = TRUE;
  if (!N976nSystemReadAllowed (Lba, Buffer)) return Fail (EFI_ACCESS_DENIED, 0x21);
  SetMem (Buffer, 4096, 0xA5);
  Status = Read (Context, Lba, Buffer);
  mPending = FALSE; mExpectedLba = 0; mExpectedBuffer = NULL;
  if (EFI_ERROR (Status)) return Fail (Status, 0x22);
  ++mN976nSystemReport.ReadCount;
  return EFI_SUCCESS;
}
STATIC BOOLEAN ValidEntry (CONST EFI_PARTITION_ENTRY *E, UINT64 Last) {
  return !GuidZero (&E->PartitionTypeGUID) && !GuidZero (&E->UniquePartitionGUID) &&
    (E->Attributes & BIT1) == 0 && E->StartingLBA >= 6 && E->StartingLBA < E->EndingLBA &&
    E->EndingLBA <= Last - 5 && E->EndingLBA - E->StartingLBA < MAX_UINT64 / 4096;
}
STATIC EFI_STATUS Select (UINT64 Last, UINT32 BlockBytes) {
  CONST EFI_PARTITION_ENTRY *Entries = N976nGptEntries (), *System = NULL, *Pit = NULL;
  if (Entries == NULL || Last < 16 || Last >= MAX_UINT32 || BlockBytes != 4096 ||
      mN976nGptReport.Magic != N976N_GPT_MAGIC || mN976nGptReport.Version != 1 ||
      mN976nGptReport.Size != sizeof (mN976nGptReport) || mN976nGptReport.Phase != 8 ||
      mN976nGptReport.Status != EFI_SUCCESS || mN976nGptReport.Checks != 0xFF ||
      mN976nGptReport.EntryCount == 0 || mN976nGptReport.EntryCount > N976N_GPT_MAX_ENTRIES)
    return Fail (EFI_NOT_READY, 0x10);
  mN976nSystemReport.Checks |= BIT0; mN976nSystemNamesReport.Checks |= BIT0;
  for (UINTN I = 0; I < mN976nGptReport.EntryCount; ++I) {
    CONST EFI_PARTITION_ENTRY *E = &Entries[I];
    UINTN Term, Tail;
    BOOLEAN NonAscii = FALSE;
    ++mN976nSystemNamesReport.Scanned;
    if (GuidZero (&E->PartitionTypeGUID)) continue;
    ++mN976nSystemNamesReport.Used;
    Term = NameTerm (E->PartitionName); Tail = NameTail (E->PartitionName, Term);
    if (Term == 36) {
      ++mN976nSystemNamesReport.UnterminatedNames;
      if (mN976nSystemNamesReport.FirstUnterminatedIndex == 0) mN976nSystemNamesReport.FirstUnterminatedIndex = I + 1;
    }
    for (UINTN J = 0; J < Term; ++J) if (E->PartitionName[J] > 0x7F) NonAscii = TRUE;
    if (NonAscii) {
      ++mN976nSystemNamesReport.NonAsciiNames;
      if (mN976nSystemNamesReport.FirstNonAsciiIndex == 0) mN976nSystemNamesReport.FirstNonAsciiIndex = I + 1;
    }
    /* Prefix indices only explain why a near-name did NOT match. They never
     * authorize a selected entry, copied range or media read. */
    if (Prefix (E->PartitionName, "SYSTEM") && mN976nSystemNamesReport.FirstSystemPrefixIndex == 0)
      mN976nSystemNamesReport.FirstSystemPrefixIndex = I + 1;
    if (Prefix (E->PartitionName, "PIT") && mN976nSystemNamesReport.FirstPitPrefixIndex == 0)
      mN976nSystemNamesReport.FirstPitPrefixIndex = I + 1;
    if (Name (E->PartitionName, "SYSTEM")) {
      ++mN976nSystemNamesReport.SystemMatches;
      if (Tail == 0) ++mN976nSystemNamesReport.LegacySystemMatches;
      if (System == NULL) {
        System = E; mN976nSystemNamesReport.SystemIndex = I + 1;
        mN976nSystemNamesReport.SystemTerm = Term; mN976nSystemNamesReport.SystemTailNonzero = Tail;
      }
    }
    if (Name (E->PartitionName, "PIT")) {
      ++mN976nSystemNamesReport.PitMatches;
      if (Tail == 0) ++mN976nSystemNamesReport.LegacyPitMatches;
      if (Pit == NULL) {
        Pit = E; mN976nSystemNamesReport.PitIndex = I + 1;
        mN976nSystemNamesReport.PitTerm = Term; mN976nSystemNamesReport.PitTailNonzero = Tail;
      }
    }
  }
  mN976nSystemNamesReport.Checks |= BIT1;
  if (mN976nSystemNamesReport.SystemMatches == 0) mN976nSystemNamesReport.MissingMask |= BIT0;
  if (mN976nSystemNamesReport.PitMatches == 0) mN976nSystemNamesReport.MissingMask |= BIT1;
  if (mN976nSystemNamesReport.SystemMatches > 1) mN976nSystemNamesReport.DuplicateMask |= BIT0;
  if (mN976nSystemNamesReport.PitMatches > 1) mN976nSystemNamesReport.DuplicateMask |= BIT1;
  /* SYSTEM alone is the payload identity. PIT names are diagnostic metadata;
   * neither their absence nor duplication is a SYSTEM selection predicate. */
  if (mN976nSystemNamesReport.SystemMatches == 1 && ValidEntry (System, Last)) {
    CopyMem (&mSystemEntry, System, sizeof (*System)); mSystemKnown = TRUE;
    mN976nSystemReport.SystemIndex = mN976nSystemNamesReport.SystemIndex;
    mN976nSystemReport.SystemStart = System->StartingLBA; mN976nSystemReport.SystemLast = System->EndingLBA;
    mN976nSystemReport.SystemBlocks = System->EndingLBA - System->StartingLBA + 1;
    mN976nSystemReport.SystemBytes = mN976nSystemReport.SystemBlocks * 4096;
    mN976nSystemReport.SystemAttributes = System->Attributes;
    mN976nSystemReport.Fit = mN976nSystemReport.SystemBytes >= N976N_SYSTEM_IMAGE_BYTES ? 1 : 0;
    mN976nSystemNamesReport.Checks |= BIT2;
  }
  if (mN976nSystemNamesReport.PitMatches == 1 && ValidEntry (Pit, Last)) {
    CopyMem (&mPitEntry, Pit, sizeof (*Pit)); mPitKnown = TRUE;
    mN976nSystemNamesReport.Checks |= BIT3;
  }
  if (mN976nSystemNamesReport.SystemMatches > 1) return Fail (EFI_VOLUME_CORRUPTED, 0x11);
  if (mN976nSystemNamesReport.UnterminatedNames != 0) return Fail (EFI_VOLUME_CORRUPTED, 0x19);
  if (mN976nSystemNamesReport.SystemMatches == 0) return Fail (EFI_NOT_FOUND, 0x16);
  if (!mSystemKnown) return Fail (EFI_VOLUME_CORRUPTED, 0x14);
  /* The accepted GPT parser already rejects overlaps/duplicate GUIDs globally.
   * Keep SYSTEM's capability independent of the diagnostic PIT name and repeat
   * its own range/GUID exclusions against every other used entry. */
  for (UINTN I = 0; I < mN976nGptReport.EntryCount; ++I) {
    CONST EFI_PARTITION_ENTRY *Other = &Entries[I];
    if (Other == System || GuidZero (&Other->PartitionTypeGUID)) continue;
    if ((System->StartingLBA <= Other->EndingLBA && Other->StartingLBA <= System->EndingLBA) ||
        CompareMem (&System->UniquePartitionGUID, &Other->UniquePartitionGUID, sizeof (EFI_GUID)) == 0)
      return Fail (EFI_VOLUME_CORRUPTED, 0x14);
  }
  mN976nSystemReport.Checks |= BIT1;
  if (!mN976nSystemReport.Fit) return Fail (EFI_BAD_BUFFER_SIZE, 0x15);
  mN976nSystemReport.Checks |= BIT2;
  mSelected = TRUE; mDiskLast = Last;
  return EFI_SUCCESS;
}
EFI_STATUS N976nProbeSystem (UINT64 LastLba, UINT32 BlockBytes, N976N_GPT_READ Read, VOID *Context) {
  EFI_STATUS Status;
  if (mRunning) return EFI_ALREADY_STARTED;
  N976nResetSystemProbe (); mRunning = TRUE; mN976nSystemReport.Phase = 1;
  if (Read == NULL) return Fail (EFI_INVALID_PARAMETER, 1);
  Status = Select (LastLba, BlockBytes); if (EFI_ERROR (Status)) return Status;
  mN976nSystemReport.Phase = 2;
  for (UINTN I = 0; I < 2; ++I) {
    Status = ReadOne (mSystemEntry.StartingLBA + I, mContent + I * 4096, Read, Context);
    if (EFI_ERROR (Status)) return Status;
    mN976nSystemReport.Checks |= BIT3 << I;
  }
  mN976nSystemReport.Header0 = Le64 (mContent); mN976nSystemReport.Header4096 = Le64 (mContent + 4096);
  mN976nSystemReport.ContentCrc32 = CalculateCrc32 (mContent, sizeof (mContent));
  if (Le32 (mContent + 4096) == 0x616C4467) mN976nSystemReport.ContentKind = 1;
  else if (mContent[1080] == 0x53 && mContent[1081] == 0xEF) mN976nSystemReport.ContentKind = 2;
  else if (mContent[510] == 0x55 && mContent[511] == 0xAA &&
    (CompareMem (mContent + 82, "FAT32   ", 8) == 0 || CompareMem (mContent + 54, "FAT16   ", 8) == 0))
    mN976nSystemReport.ContentKind = 3;
  mN976nSystemReport.Checks |= BIT5; mN976nSystemReport.Phase = 8;
  mN976nSystemReport.Status = EFI_SUCCESS; mRunning = FALSE;
  return EFI_SUCCESS;
}
