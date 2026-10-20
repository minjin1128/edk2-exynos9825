/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_SERVICE_H_
#define N976N_UFS_SERVICE_H_
#include <N976nUfsBlock.h>

#define N976N_SERVICE_MAGIC SIGNATURE_64 ('N','9','7','6','S','R','V','1')
#define N976N_SERVICE_VERSION 1ULL
#define N976N_SERVICE_MAX_DATA_BLOCKS 16U
#define N976N_FILE_SERVICE_MAX_DATA_BLOCKS 40U
/* Eight finite3MiB-volume passes for post-StartImage reads; no write/DMA change. */
#define N976N_BOOT_RUNTIME_DATA_BLOCKS (8U * (0x300000U / 4096U))
#define N976N_SERVICE_EXPECTED_DATA_BLOCKS 7U
#define N976N_SERVICE_CHECKS 0xFFULL
#define N976N_SERVICE_LIFE_CHECKS 0xFULL
#define N976N_SERVICE_REJECT_CHECKS 0xFFULL

/* An explicit boot-services lease, not an indefinite storage driver. Start
 * returns with BlockIo/DiskIo published; a separate consumer uses the lease;
 * Stop retires both interfaces BEFORE the owner restores UFS power/controller.
 * Only provider-owned CPU windows are admitted. The original seven-page DMA
 * transport and its independent cleanup reservation remain unchanged.
 * Checks: selection, storage, interfaces, negatives, baseline, magic, disk
 * comparisons, retirement. LifeChecks: separate consumer, first lookup,
 * second lookup identity, retired callbacks. SliceCrc covers bytes4093..4100.
 */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 BlockCalls, DiskCalls, DataBlocks, SampleCrc, SliceCrc;
  UINT64 LifeChecks, RejectChecks, PartitionStart, PartitionBlocks;
} N976N_SERVICE_REPORT;
STATIC_ASSERT (sizeof (N976N_SERVICE_REPORT) == 128, "SEC56 service report ABI");

extern volatile N976N_SERVICE_REPORT mN976nServiceReport;
VOID N976nResetUfsService (VOID);
EFI_STATUS N976nStartUfsService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context);
EFI_STATUS N976nConsumeUfsService (VOID);
EFI_STATUS N976nStartUfsFileService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context);
/* Derive a bounded session allowance from the admitted file length: at most
 * three physical4KiB reads per owned8KiB chunk, plus the already bounded40
 * metadata/tail-read allowance. This does not enlarge any DMA transfer. */
UINTN N976nUfsStreamDataLimit (UINTN FileBytes);
UINTN N976nUfsBootDataLimit (UINTN FileBytes);
EFI_STATUS N976nStartUfsBootService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context, UINTN FileBytes);
EFI_STATUS N976nStartUfsStreamService (UINT64 Start, UINT64 Blocks,
  N976N_BLOCK_READ Read, N976N_BLOCK_BUFFER_CHECK Check,
  N976N_BLOCK_BUDGET Budget, VOID *Context, UINTN FileBytes);
EFI_STATUS N976nReadUfsOwned (UINT64 Offset, UINTN Bytes, CONST UINT8 **Data);
UINTN N976nUfsOwnedBudget (VOID);
BOOLEAN N976nUfsOwnedRangeAllowed (UINT64 Offset, UINTN Bytes);
EFI_STATUS N976nStopUfsService (VOID);
/* TRUE only after the transport gate and all saved callbacks are retired.
 * A failed uninstall may retain a static, inactive tombstone and still be
 * closed; callers must separately preserve/report the uninstall error. */
BOOLEAN N976nUfsServiceClosed (VOID);
BOOLEAN N976nServiceBufferOwned (CONST VOID *Buffer, UINTN Bytes);
BOOLEAN N976nServiceStorageOwned (CONST VOID *Buffer, UINTN Bytes);
#endif
