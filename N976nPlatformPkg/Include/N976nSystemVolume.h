/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_SYSTEM_VOLUME_H_
#define N976N_SYSTEM_VOLUME_H_
#include <N976nSystemProbe.h>
#include <N976nPlatform.h>
#define N976N_SYSTEM_VOLUME_MAGIC SIGNATURE_64 ('N','9','7','6','V','O','L','1')
#define N976N_SYSTEM_VOLUME_CHECKS 0xFFULL
#define N976N_SYSTEM_VOLUME_OWNER_CHECKS 0xFULL
#define N976N_SYSTEM_VOLUME_CLOSE_CHECKS 0xFULL
#define N976N_SYSTEM_VOLUME_FILE_CHECKS 0x7ULL
#define N976N_SYSTEM_VOLUME_TABLE_CHECKS 0x3ULL
#define N976N_SYSTEM_VOLUME_CHUNK_BYTES 0x20000U
/* Fixed sealed payload-derived read budget. Two complete passes plus metadata
 * allowance bound Windows rereads; exhaustion fails closed without spending
 * the independent UFS cleanup reserve. */
#define N976N_SYSTEM_VOLUME_SDI_BYTES 3170304ULL
#define N976N_SYSTEM_VOLUME_WIM_BYTES 940090097ULL
#define N976N_SYSTEM_VOLUME_PAYLOAD_BYTES (16384ULL + N976N_SYSTEM_VOLUME_SDI_BYTES + N976N_SYSTEM_VOLUME_WIM_BYTES)
#define N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS (2U * ((N976N_SYSTEM_VOLUME_PAYLOAD_BYTES + N976N_SYSTEM_VOLUME_CHUNK_BYTES - 1) / N976N_SYSTEM_VOLUME_CHUNK_BYTES) + 64U)
#define N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS (N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS * (N976N_SYSTEM_VOLUME_CHUNK_BYTES / 4096U))
/* Checks: seal1, exact GPT identity2, scoped FAT4, BCD8, SDI10, WIM20,
 * rejected writes/bounds/foreign destinations40, exact retirement80.
 * FileChecks: complete BCD+EOF+seek1, SDI header2, WIM header4.
 * TableChecks: immutable RO-XN trusted image storage1, complete table SHA2562.
 * ReadCount counts successful physical pages, ChunkLoads counts complete
 * authenticated128KiB chunks. Version3 SDI/WIM byte fields count preflight
 * headers only; actual Windows reads are in the distinct run report below. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, ReadCount;
  UINT64 ChunkLoads, AuthenticatedBytes, DiskCalls, ReadBytes, FileChecks, BcdBytes, SdiBytes, WimBytes;
  UINT64 SystemStart, SystemBlocks, VolumeBytes, OwnerChecks, CloseChecks, LastChunk, CacheHits, Rejected;
  UINT64 BcdCrc32, SdiHeader0, WimHeader0, TableChecks, PartitionIndex, BudgetBlocks, Reserved0, Reserved1;
} N976N_SYSTEM_VOLUME_REPORT;
STATIC_ASSERT (sizeof (N976N_SYSTEM_VOLUME_REPORT) == 256, "SEC66 system volume report ABI");
extern volatile N976N_SYSTEM_VOLUME_REPORT mN976nSystemVolumeReport;
/* Successful runtime logical reads, not whole-file/unique coverage. SDI/WIM
 * bytes count overlap with independently sealed contiguous file extents, so
 * repeated reads may exceed file size. Active observation retains the source,
 * filesystem and private low DMA; phase3 means StartImage returned. */
typedef struct {
 UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, Calls;
 UINT64 Bytes, SdiBytes, WimBytes, HighCalls, HighBytes, LastOffset, LastBytes, Rejected;
} N976N_SYSTEM_RUN_REPORT;
STATIC_ASSERT (sizeof (N976N_SYSTEM_RUN_REPORT) == 128, "SEC66 runtime report ABI");
extern volatile N976N_SYSTEM_RUN_REPORT mN976nSystemRunReport;
BOOLEAN N976nSystemVolumeExecutionActive (VOID);
/* Permanent no-allocation transport gate before ExitBootServices. Retains
 * filesystem allocations/handles; does not claim normal filesystem retirement.
 * Failed/busy freeze cannot be reset or reopened in this firmware invocation. */
EFI_STATUS N976nSystemVolumeFreezeForExit (VOID);
BOOLEAN N976nSystemVolumeExitFrozen (VOID);
/* Successful authenticated/copied runtime chunk bytes, including chunks of
 * an unfinished logical read. A no-I/O monotonic idle-timer input, not a file
 * completion claim; RunReport.Bytes counts only completed logical requests. */
UINT64 N976nSystemWindowsProgress (VOID);
VOID N976nResetSystemVolume (VOID);
EFI_STATUS N976nConsumeSystemVolume (CONST N976N_PLATFORM_HANDOFF *Handoff, N976N_GPT_READ Read, VOID *Context);
BOOLEAN N976nSystemVolumeLbaAllowed (UINT64 Lba);
BOOLEAN N976nSystemVolumeReadAllowed (UINT64 Lba, CONST VOID *Buffer);
BOOLEAN N976nSystemVolumeClosed (VOID);
BOOLEAN N976nSystemSha256 (CONST VOID *Data, UINTN Bytes, UINT8 Digest[32]);
#endif
