/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_SYSTEM_PROBE_H_
#define N976N_SYSTEM_PROBE_H_
#include <N976nGpt.h>
#define N976N_SYSTEM_MAGIC SIGNATURE_64 ('N','9','7','6','S','Y','S','2')
#define N976N_SYSTEM_IMAGE_BYTES 0x40000000ULL
#define N976N_SYSTEM_CHECKS 0x3FULL
#define N976N_UFS_SYSTEM 12ULL
/* Version2 checks: accepted GPT1, unique safe SYSTEM2, image capacity4,
 * first4KiB8, second4KiB10, bounded content inspection20. Exactly two reads.
 * PitStart through StockChecks and PitCrc32 are reserved0 in Version2.
 * PIT is independent Odin/Download-mode metadata, never a GPT prerequisite.
 * ContentKind identifies only: 0 unknown,1 LP geometry signature,2 ext4 magic,
 * 3 FAT signature. No filesystem validity or mount is implied. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, ReadCount;
  UINT64 SystemIndex, SystemStart, SystemLast, SystemBlocks, SystemBytes, SystemAttributes, PitStart, PitBlocks;
  UINT64 PitCount, BinaryType, DeviceType, Identifier, PitSystemStart, PitSystemBlocks, MapChecks, StockChecks;
  UINT64 ImageBytes, Fit, ContentKind, Header0, Header4096, PitCrc32, ContentCrc32, Reserved;
} N976N_SYSTEM_REPORT;
STATIC_ASSERT (sizeof (N976N_SYSTEM_REPORT) == 256, "SYSTEM report ABI");
extern volatile N976N_SYSTEM_REPORT mN976nSystemReport;
#define N976N_SYSTEM_NAMES_MAGIC SIGNATURE_64 ('N','9','7','6','N','A','M','1')
/* Actual accepted-GPT observations only. Names stop at the first NUL within
 * 36 CHAR16s; bytes after it remain recorded evidence, not part of identity.
 * Legacy counts reproduce SEC62's additional zero-tail predicate.
 * Missing/DuplicateMask: SYSTEM1/PIT2. Indices are one-based; 0 is absent.
 * Term: first NUL index, 36 means absent. TailNonzero counts CHAR16s after NUL.
 * Checks: accepted GPT1, complete bounded scan2, unique safe SYSTEM4/PIT8.
 * Name evidence never opens a read capability. Reason16 is absent SYSTEM;
 * 19 is an unterminated used name;11 is duplicate SYSTEM. PIT counters and
 * metadata are informational and never a prerequisite for SYSTEM reads. */
typedef struct {
  UINT64 Magic, Version, Size, Scanned;
  UINT64 Used, SystemMatches, PitMatches, LegacySystemMatches;
  UINT64 LegacyPitMatches, UnterminatedNames, NonAsciiNames, SystemIndex;
  UINT64 PitIndex, SystemTerm, PitTerm, SystemTailNonzero;
  UINT64 PitTailNonzero, MissingMask, DuplicateMask, FirstUnterminatedIndex;
  UINT64 FirstNonAsciiIndex, FirstSystemPrefixIndex, FirstPitPrefixIndex, Checks;
} N976N_SYSTEM_NAMES_REPORT;
STATIC_ASSERT (sizeof (N976N_SYSTEM_NAMES_REPORT) == 192, "SYSTEM names report ABI");
extern volatile N976N_SYSTEM_NAMES_REPORT mN976nSystemNamesReport;
/* Display-only bounded ASCII sanitization; output is37 CHAR16s including NUL. */
VOID N976nFormatGptName (CONST CHAR16 Field[36], CHAR16 Text[37]);
VOID N976nResetSystemProbe (VOID);
EFI_STATUS N976nProbeSystem (UINT64 LastLba, UINT32 BlockBytes, N976N_GPT_READ Read, VOID *Context);
CONST EFI_PARTITION_ENTRY *N976nSystemEntry (VOID);
CONST EFI_PARTITION_ENTRY *N976nSystemPitEntry (VOID);
BOOLEAN N976nSystemLbaAllowed (UINT64 Lba);
BOOLEAN N976nSystemReadAllowed (UINT64 Lba, CONST VOID *Buffer);
BOOLEAN N976nSystemProbeClosed (VOID);
#endif
