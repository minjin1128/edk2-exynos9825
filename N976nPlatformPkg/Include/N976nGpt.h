/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_GPT_H_
#define N976N_GPT_H_
#include <Uefi.h>
#include <Uefi/UefiGpt.h>

#define N976N_GPT_MAGIC SIGNATURE_64 ('N','9','7','6','G','P','T','1')
#define N976N_GPT_VERSION 1ULL
#define N976N_GPT_BLOCK_BYTES 4096U
#define N976N_GPT_MAX_ENTRIES 128U
#define N976N_GPT_TABLE_BYTES (N976N_GPT_MAX_ENTRIES * sizeof (EFI_PARTITION_ENTRY))

/* Phase 0 is not started. Failure retains its phase, status and reason.
 * Checks: 01 PMBR; 02 primary header; 04 primary array CRC; 08 entry safety;
 * 10 backup header; 20 backup array CRC; 40 reciprocal metadata;
 * 80 identical complete arrays. Only Phase 8 / Status 0 / Checks FF admits
 * entries. ReadCount counts completed block callbacks, not bytes or writes. */
#define N976N_GPT_PHASE_PMBR 1ULL
#define N976N_GPT_PHASE_PRIMARY 2ULL
#define N976N_GPT_PHASE_PRIMARY_ARRAY 3ULL
#define N976N_GPT_PHASE_ENTRIES 4ULL
#define N976N_GPT_PHASE_BACKUP 5ULL
#define N976N_GPT_PHASE_BACKUP_ARRAY 6ULL
#define N976N_GPT_PHASE_COMPARE 7ULL
#define N976N_GPT_PHASE_COMPLETE 8ULL
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, EntryCount;
  UINT64 UsedCount, EspCount, TableCrc32, LargestStart, LargestBlocks;
  UINT64 PrimaryHeaderCrc32, BackupHeaderCrc32, ReadCount;
} N976N_GPT_REPORT;
STATIC_ASSERT (sizeof (N976N_GPT_REPORT) == 128, "GPT report ABI");
typedef EFI_STATUS (EFIAPI *N976N_GPT_READ) (VOID *Context, UINT64 Lba, UINT8 *Block);
extern volatile N976N_GPT_REPORT mN976nGptReport;
VOID N976nResetGpt (VOID);
EFI_STATUS N976nObserveGpt (UINT64 LastLba, UINT32 BlockBytes,
                          N976N_GPT_READ Read, VOID *Context);
CONST EFI_PARTITION_ENTRY *N976nGptEntries (VOID);
#endif
