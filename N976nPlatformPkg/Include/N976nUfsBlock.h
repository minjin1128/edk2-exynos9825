/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_BLOCK_H_
#define N976N_UFS_BLOCK_H_
#include <Uefi.h>

#define N976N_BLOCK_MAGIC SIGNATURE_64 ('N','9','7','6','B','L','K','1')
#define N976N_BLOCK_VERSION 1ULL
#define N976N_BLOCK_BYTES 4096U
#define N976N_BLOCK_CHECKS 0xFFULL
#define N976N_BLOCK_REJECT_CHECKS 0xFFULL

/* A restricted, synchronous diagnostic consumer of standard BlockIo, not a
 * persistent general-purpose disk or filesystem service. Three data blocks
 * maximum: partition blocks0/1 followed by a repeated block0. Transport keeps
 * its independent command/cleanup reserve, DMA ownership and completion rules.
 * ReadCalls counts successful nonempty BlockIo calls; ReadBlocks counts fully
 * accepted individual callbacks. Neither includes the preceding GPT reads.
 * Checks: select, buffers, installed/identity, negative contracts, two-block
 * read, ANDROID! signature, byte-identical repeat, disabled/uninstalled/guards.
 */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 PartitionStart, PartitionBlocks, ReadCalls, ReadBlocks, FirstQword;
  UINT64 FirstCrc, SecondCrc, RepeatCrc, RejectChecks;
} N976N_BLOCK_REPORT;
STATIC_ASSERT (sizeof (N976N_BLOCK_REPORT) == 128, "SEC56 block report ABI");

typedef EFI_STATUS (EFIAPI *N976N_BLOCK_READ) (VOID *Context, UINT64 AbsoluteLba,
                                             UINT8 *Block);
typedef BOOLEAN (EFIAPI *N976N_BLOCK_BUFFER_CHECK) (VOID *Context, VOID *Buffer,
                                                  UINTN Bytes);
/* Remaining command allowance AFTER reserving the transport's three cleanup
 * commands. Called for the whole request and again before every block. */
typedef UINTN (EFIAPI *N976N_BLOCK_BUDGET) (VOID *Context);

extern volatile N976N_BLOCK_REPORT mN976nBlockReport;
VOID N976nResetBlockProbe (VOID);
EFI_STATUS N976nSelectBootPartition (UINT64 DiskLast, UINT64 *Start, UINT64 *Blocks);
EFI_STATUS N976nProbeBootBlocks (UINT64 Start, UINT64 Blocks, N976N_BLOCK_READ Read,
  N976N_BLOCK_BUFFER_CHECK Check, N976N_BLOCK_BUDGET Budget, VOID *Context);
/* TRUE only for nonempty, nonwrapping ranges entirely inside ONE of the two
 * CPU sample arrays. Guard bytes, protocol/context and arbitrary caller RAM
 * are never admitted as destinations; no caller buffer is used for DMA. */
BOOLEAN N976nBlockBufferOwned (CONST VOID *Buffer, UINTN Bytes);
/* Admission-only identity: exactly the entire CPU storage object, including
 * all guards. Never use this predicate to authorize a read destination. */
BOOLEAN N976nBlockStorageOwned (CONST VOID *Buffer, UINTN Bytes);
#endif
