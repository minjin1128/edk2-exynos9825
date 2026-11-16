/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_CORE_H
#define N976N_UFS_CORE_H
#include <stddef.h>
#include "N976nUfsNtfsExpected.h"
#include "N976nUfsSystem.h"
typedef unsigned char U8;
typedef unsigned int U32;
typedef unsigned long long U64;
#define NUF_FIRMWARE_DMA_BYTES (7U*4096U)
#define NUF_DMA_BYTES (22U*4096U)
#define NUF_PRDT_BYTES (17U*16U)
#define NUF_FATAL_IS ((1U<<7)|(1U<<11)|(1U<<12)|(1U<<16)|(1U<<17)|(1U<<18))
#define NUF_COH 0x2000U
#define NUF_DIAG_MAGIC 0x393746554EULL
#define NUF_DIAG_VERSION 3U
#define NUF_CONTROL 0x790001U
#define NUF_BLOCK_BYTES 4096U
#define NUF_MAX_TRANSFER (16U*NUF_BLOCK_BYTES)
#define NUF_GUARD_FULL 1U
#define NUF_GUARD_CYCLIC 2U
#define NUF_GUARD_PAGES 16U
#define NUF_GUARD_BOUNDARY 64U
/* Full admission; runtime policy selected only after successful admission. */
#ifndef NUF_RUNTIME_GUARD_POLICY
#define NUF_RUNTIME_GUARD_POLICY NUF_GUARD_CYCLIC
#endif
#if NUF_RUNTIME_GUARD_POLICY != NUF_GUARD_FULL && NUF_RUNTIME_GUARD_POLICY != NUF_GUARD_CYCLIC
#error Unsupported runtime guard policy
#endif
/* Finite bring-up policy, not measured device worst-case latencies. */
#define NUF_CONTROL_WAIT_US 250000ULL
#define NUF_READ_WAIT_US 250000ULL
#define NUF_WRITE_WAIT_US 5000000ULL
#define NUF_FLUSH_WAIT_US 30000000ULL
#define NUF_SPIN_WAIT_US 100ULL
/* Bounded READ10 completion-observation policy, not a larger I/O deadline.
 * Poll in short documented Storport stalls for at most 1ms of elapsed time;
 * then retain the existing passive sleep and command-specific deadline. */
#define NUF_READ_POLL_WINDOW_US 1000ULL
#define NUF_READ_POLL_STEP_US 10U
#define NUF_WAIT_BUCKETS 8U
/* The independent hardware fence and admission use the same sealed image
 * geometry. A caller cannot enlarge this compile-time candidate contract. */
#define NUF_WRITE_REGION_FIRST NUF_NTFS_PARTITION_START_LBA
#define NUF_WRITE_REGION_BLOCKS NUF_NTFS_IMAGE_BLOCKS
enum { NufOk=0, NufBadArgument=1, NufOwnership=2, NufDrift=3,
 NufGuard=4, NufTimeout=5, NufClock=6, NufResponse=7, NufAck=8,
 NufCapacity=9, NufCompare=10, NufCleanup=11, NufResource=12,
 NufLease=13, NufReplay=14, NufMapping=15,NufHeaderView=16 };
enum { NufStageFind=1,NufStageResources=2,NufStageLease=3,NufStageClaim=4,
 NufStagePrepare=5,NufStageCapacity=6,NufStageRead=7,NufStageCompare=8,
 NufStageRetire=9,NufStageComplete=10,NufStageWrite=11,NufStageFlush=12 };
typedef struct {
 U64 Request,Lba,MyLba,AlternateLba,FirstUsable,LastUsable,EntryLba;
 U32 Seen,Reason,Checks,OriginalSize,OriginalCrc,ComputedCrc,ReturnedSize,ReturnedCrc;
 U32 EntryCount,EntrySize,ArrayCrc,Reserved;
 U8 DiskGuid[16];
} NUF_GPT_VIEW_SNAPSHOT;
/* Fixed scalar report, no kernel pointers. First failure survives cleanup. */
typedef struct {
 U64 Magic;
 U32 Version,Bytes,Stage,Reason,FirstStage,FirstReason,CleanupReason,Quarantined;
 U32 Claim,Issued,Acknowledged,CapacityChecked,ReadChecked,Compared,Retired,Reserved;
 U64 DmaBase,OldTrlBase,ExpectedLastLba,LastLba;
 U32 BlockBytes,Lun,ExpectedCrc,ReadCrc,FirstMismatch,ExpectedByte,ActualByte,Opcode;
 U32 Tag,Ocs,Response,ScsiStatus,Residual,SenseBytes,Is,Dbr,Hcs,TrlRun;
 U32 TrlBase,TrlBaseHi,Coherency,GuardOffset,GuardExpected,GuardActual;
 U64 WaitUs,WaitLoops;
 U8 RawResponse[52];
 U32 ResourceIndex,ResourceCount;
 U64 ResourceBase,ResourceLength,LeaseBase,LeaseClaim;
 U32 DriverStatus,Ready,LeaseCheck,Reserved2;
 /* Initial probe above is immutable after successful admission. Runtime
  * counters and last request below are separate, never overwrite its proof. */
 U64 RuntimeRequests,RuntimeCompleted,RuntimeBytes,RuntimeLastLba;
 U32 RuntimeOpcode,RuntimeStatus,RuntimeReason,RuntimeIssued,RuntimeAck;
 U32 RuntimeRetired,RuntimeQuarantined,WriteRefused,UnsupportedRequests;
 U32 SessionState; /* 0 init, 1 admitted disk ready, 2 stopped, 3 terminal fault */
 U32 RuntimeFirstStage,RuntimeFirstReason,RuntimeOcs,RuntimeResponse,RuntimeScsi;
 U32 RuntimeIs,RuntimeDbr,WorkerStatus;
 U64 RuntimeWaitUs;
 U64 ViewCandidates,ViewApplied,ViewUnchanged,ViewRefused;
 U32 ViewLastReason,ViewSeenMask;
 /* Last physical header observed on each side, captured before CPU-view edit.
  * Never confused with the OS-returned 92-byte header or the firmware LBA0 CRC. */
 NUF_GPT_VIEW_SNAPSHOT ViewHeader[2];
} NUF_REPORT;
typedef struct {
 U64 DmaBase,OldTrlBase,LastLba;
 U32 BlockBytes,Lun,Cap,Version,Hcs,Tx,Rx,Reorder,Nexus,Axi,Iacr,Coherency,TmBase,TmBaseHi;
 U64 WriteFirst,WriteBlocks;
 U64 SystemWriteFirst,SystemWriteBlocks;
 U32 WriteEnabled;
 const U8 *Baseline;
} NUF_CONFIG;
typedef struct {
 void *Context;
 U32 (*Read)(void *,U32);
 void (*Write)(void *,U32,U32);
 U64 (*ClockUs)(void *);
 void (*Pause)(void *);
 void (*Fence)(void *);
 int (*Owned)(void *);
 /* Optional passive-only bounded sleep. Stop/Restart never invoke it. */
 void (*SleepUs)(void *,U32);
 /* Optional passive-worker short poll cadence; each call must be <1ms. */
 void (*StallUs)(void *,U32);
} NUF_OPS;
/* Private sampled observation. Us values use the existing monotonic deadline
 * clock. SleepElapsedUs ends at its first reading after the callback returns,
 * so it includes scheduling. No timestamp claims hardware-only latency. */
typedef struct {
 U64 StartUs,LastPendingUs,ClearUs,FirstSleepUs,LastSleepUs,LastWakeUs;
 U64 SleepCalls,SleepRequestedUs,SleepElapsedUs,MaxSleepUs;
 U64 StallCalls,StallRequestedUs,Polls;
 U64 SleepBuckets[NUF_WAIT_BUCKETS];
 U32 WindowUs,Kind,Completed,DoneAfterWake;
} NUF_WAIT_SAMPLE;
typedef struct {
 NUF_CONFIG Config;
 NUF_OPS Ops;
 volatile U8 *Dma;
 NUF_REPORT *Report;
 U8 ExpectedTrd[32],ExpectedCommand[32],ExpectedPrdt[NUF_PRDT_BYTES];
 U8 ExpectedData[NUF_MAX_TRANSFER];
 U32 DataOut,NoData,DataCapacity;
 U32 Changed,Running;
 /* Private session state, never part of the fixed diagnostic wire ABI.
  * Report may be cleared between completed requests; these fields must not. */
 U32 SessionActive,DmaInitialized,RequestPrepared,RequestRetired;
 U32 Quarantined,Stopped,Closed;
 U64 SessionOpens,SessionCloses,SessionStops,SessionRestarts,ListPrograms;
 U64 DmaInitBytes,RequestResetBytes,GuardCheckBytes,GuardReadOps;
 /* Private KD diagnostics: control/read/write/flush. No wire ABI change. */
 U64 MaxWaitUs[4],WaitSleeps,WaitTimeouts;
 /* Only the serialized runtime worker arms these private diagnostics. */
 U64 (*PerfClock)(void *);
 U64 PerfIssue[2],PerfDone[2],PerfGuardTicks;
 U64 PerfGuardPreTicks,PerfGuardPostTicks,PerfReadCopyTicks,PerfWriteCopyTicks;
 U32 PerfCommands,ControlGuard32,PerfClockError;
 U32 ControlWaitLegacy;
 NUF_WAIT_SAMPLE PerfWait[2];
 /* Session state, never cleared with the per-request report. Cursor advances
  * once per post-check, including active pages; never on a pre-check. */
 U32 GuardPolicy,GuardCursor;
 U64 GuardFullChecks,GuardSweepSteps,GuardSweepBytes,GuardBoundaryBytes,GuardActivateBytes;
} NUF_ENGINE;
U32 NufCrc32(const void *,U32);
int NufReadCommandAllowed(U32 Opcode,U32 Lun,U32 Bytes,U64 Lba,U32 Tag);
int NufRun(NUF_ENGINE *);
/* Open once, issue serialized commands, then Close. Stop/Restart are bounded
 * immediate-register operations for an already drained adapter at DIRQL.
 * They never call ClockUs/Pause or initialize DMA. Failed retirement retains
 * the arena/controller lease; callers must not unmap or reuse it. */
int NufSessionOpen(NUF_ENGINE *);
int NufSessionClose(NUF_ENGINE *);
int NufSessionStop(NUF_ENGINE *);
int NufSessionRestart(NUF_ENGINE *);
int NufRequestRetired(const NUF_ENGINE *);
int NufReadBlock(NUF_ENGINE *,U64 Lba,U32 Tag,U8 *Output,U32 Bytes);
/* Independent fixed candidate range fence; permission comes only from fresh admission. */
int NufWriteRangeAllowed(const NUF_CONFIG *,U64 Lba,U32 Bytes);
int NufWriteBlock(NUF_ENGINE *,U64 Lba,U32 Tag,const U8 *Payload,U32 Bytes);
int NufFlushCache(NUF_ENGINE *,U32 Tag);
#endif
