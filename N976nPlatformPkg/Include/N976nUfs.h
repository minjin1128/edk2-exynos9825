/* SPDX-License-Identifier: MIT */
#ifndef N976N_UFS_H_
#define N976N_UFS_H_
#include <N976nPlatform.h>

#define N976N_UFS_ADMISSION_MAGIC SIGNATURE_64 ('N','9','7','6','U','F','S','1')
#define N976N_UFS_ADMISSION_VERSION 1ULL
#define N976N_UFS_REPORT_MAGIC SIGNATURE_64 ('N','9','7','6','U','F','S','R')
typedef struct {
  UINT64 Magic, Version, Size, Admitted, Reason, Hci, Vendor, Coherency;
} N976N_UFS_ADMISSION;
STATIC_ASSERT (sizeof (N976N_UFS_ADMISSION) == 64, "UFS admission ABI");

#define N976N_UFS_NOT_TESTED  1ULL
#define N976N_UFS_NOT_READY   2ULL
#define N976N_UFS_READ        3ULL
#define N976N_UFS_FAILED      4ULL
#define N976N_UFS_QUARANTINED 5ULL
#define N976N_UFS_QUERY_OBSERVED 6ULL
#define N976N_UFS_POWER_OBSERVED 7ULL
#define N976N_UFS_GPT 8ULL
#define N976N_UFS_BLOCK 9ULL
#define N976N_UFS_SERVICE 10ULL
#define N976N_UFS_FILESYSTEM 11ULL
#define N976N_UFS_VOLUME 13ULL

/* Cumulative evidence, not a generic success mask:
 * 01 DT admission; 02 inherited controller/format ready; 04 owned RW-XN DMA;
 * 08 private ring installed; 10 current LU valid capacity; 20 one block read;
 * 40 immutable descriptors/guards intact; 80 controller restored and idle.
 * Restore: 1 stopped/idle, 2 original base/nexus/AHIT/RSR, 4 original IE and
 * final guards verified. Phase E0 means DMA quiescence unproved; E2 means a
 * terminal hold after completion (for example restoring IE would unmask a
 * newly pending interrupt). Neither case releases DMA pages.
 * READ/Phase8 requires Status0, ChecksFF, ReadCount1, Restore7 and verified
 * active preparation plus exact original power. A read before failed cleanup
 * is retained as partial evidence but cannot claim complete probe success.
 * QUERY_OBSERVED/Phase9 is a terminal query experiment, not a sector
 * read. It requires accepted replies and controller restore with Checks CF.
 * POWER_OBSERVED/PhaseA requires active preparation and exact original power
 * verification plus controller restore with Checks CF; it proves no sector
 * read or link ACTIVE state. This milestone builds mode8 (bounded complete-file streaming).
 * GPT/PhaseB requires complete parserFF and exact power/controller cleanup.
 * BLOCK/PhaseC requires GPTFF, BlockFF and successful retired interface with
 * three payload reads, exact power/controller cleanup and total read count.
 * SERVICE/PhaseD requires GPTFF, serviceFF/lifetimeF/rejectFF, seven payload
 * blocks via BlockIo and checked upstream DiskIo, retirement and exact restore.
 * FILESYSTEM/PhaseE additionally requires complete owned file comparison and
 * retirement; mode8 proves >255 payload reads with every command acknowledged.
 * ReadCount in modes5..8 sums metadata and payload; mode4 is metadata only, mode0 one block.
 * QEMU Outcome NOT_TESTED has no UFS hardware checks. */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Outcome, Phase, Status, Reason, Checks;
  UINT64 Hci, Vendor, Coherency, Cap, VersionReg, Hce, Hcs, Is, Ie, Ahit;
  UINT64 TrlBase, TrlBaseUpper, TrlDoorbell, TrlRun, TmDoorbell, TmRun;
  UINT64 TxPrdt, RxPrdt, Reorder, Nexus, CoherencyValue;
  UINT64 Buffer, BufferBytes, BufferAttributes, CommandCount, ReadCount;
  UINT64 Lun, BlockBytes, LastLba, Ocs, Response, ScsiStatus, Residual;
  UINT64 SenseBytes, SenseKey, Asc, Ascq, DataCrc32, FirstQword, LastDoorbell;
  UINT64 Restore, Quarantined, Frequency, CounterStart, CounterEnd;
  UINT64 LunStatus[8];
} N976N_UFS_REPORT;
STATIC_ASSERT (sizeof (N976N_UFS_REPORT) == 496, "UFS report ABI");
extern EFI_GUID gN976nUfsAdmissionGuid;
extern volatile N976N_UFS_REPORT mN976nUfsReport;
#define N976N_UFS_EXIT_MAGIC SIGNATURE_64 ('N','9','7','6','U','E','X','1')
#define N976N_UFS_EXIT_PHONE_CHECKS 0xFFULL
#define N976N_UFS_EXIT_FIXTURE_CHECKS 0x183ULL
/* This is quiescence for OS ownership, not inherited-state restoration.
 * Checks: state1, permanent gate2, completed/ACKed idle4, stopped lists8,
 * final empty/IRQ state10, mapping20, immutable DMA40, complete80.
 * Bit100 marks the QEMU file fixture: no hardware/cache operations or DMA proof.
 * Queue words place transfer in low32 and task-management in high32. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason, Profile;
  UINT64 Attempts, PreQueues, PostQueues, Doorbells;
} N976N_UFS_EXIT_REPORT;
STATIC_ASSERT (sizeof (N976N_UFS_EXIT_REPORT) == 96, "SEC68 UFS exit ABI");
extern volatile N976N_UFS_EXIT_REPORT mN976nUfsExitReport;
/* Before-EBS only. No Boot Services, allocations, command submission, power
 * change or inherited-ring restoration. Failed attempts stay permanently shut.
 * Cached getter is safe in the successful EBS notification. */
EFI_STATUS N976nUfsQuiesceForExit (VOID);
BOOLEAN N976nUfsExitQuiesced (VOID);
VOID N976nRunUfsProbe (CONST N976N_PLATFORM_HANDOFF *Handoff);
BOOLEAN N976nUfsServiceOpen (VOID);
BOOLEAN N976nUfsShutdownSafe (VOID);
/* Read-only pre-StartImage recheck; QEMU fixture is explicitly not DMA proof. */
BOOLEAN N976nUfsWindowsDmaReady (VOID);
BOOLEAN N976nUfsVolumeDmaReady (VOID);
BOOLEAN N976nUfsCpuRangeAllowed (CONST VOID *Buffer, UINTN Bytes);
EFI_STATUS N976nRunUfsFileFixture (CONST N976N_PLATFORM_HANDOFF *Handoff);
EFI_STATUS N976nFinishUfsService (EFI_STATUS ConsumerStatus);
VOID N976nPublishUfsObservation (VOID);
#endif
