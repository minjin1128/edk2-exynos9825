/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_SCOPE_H
#define N976N_UFS_SCOPE_H
#include "N976nUfsCore.h"
#include "N976nGptVolumeView.h"
#define NUF_SCOPE_MAGIC 0x343846535546394EULL
#define NUF_SCOPE_VERSION 3U
#define NUF_SCOPE_COMPLETION_WRITEBACK 1U
#define NUF_SCOPE_CONTROL 0x840001U
#define NUF_SCOPE_WIRE_OFFSET 32U
#define NUF_SCOPE_USERDATA_START NUF_NTFS_PARTITION_START_LBA
#define NUF_SCOPE_USERDATA_BLOCKS NUF_NTFS_PARTITION_BLOCKS
#define NUF_SCOPE_VOLUME_BLOCKS NUF_NTFS_IMAGE_BLOCKS
enum {NufScopeIdle=0,NufScopeGpt=1,NufScopeTarget=2,NufScopeBoot=3,
 NufScopeBackup=4,NufScopeReady=5,NufScopeIo=6,NufScopeFailed=7};
enum {NufScopeOk=0,NufScopeArgument=1,NufScopeTransport=2,NufScopeGptInvalid=3,
 NufScopeIdentity=4,NufScopeGeometry=5,NufScopeBootMismatch=6,
 NufScopeBackupMismatch=7,NufScopeBounds=8,NufScopeOwnership=9,
 NufScopeCompare=10,NufScopeWorker=11,NufScopeStopped=12,NufScopeView=13,
 NufScopeSystemIdentity=14,NufScopeSystemGeometry=15,NufScopeSystemBoot=16,NufScopeSystemBackup=17};
/* Separate read-only IOCTL. Existing NUF_REPORT ABI is unchanged. No setters.
 * SRB_IO_CONTROL uses Signature "N976UFS\0", HeaderLength28, ControlCode above,
 * Length4+sizeof(report), total32+sizeof(report). Bytes28..31 are zero.
 * Input report contains Magic/Version/Bytes; output replaces the full report.
 * Version3 retains v2 completion semantics: Writes/WriteBytes count acknowledged and retired device writes,
 * not power-loss persistence or readback proof. Readbacks remains zero.
 * Flushes counts successful device flushes; FuaWrites counts blocks in fully
 * completed FUA OS requests after their one real flush. Requests counts
 * physical write/flush attempts. Last
 * Issued/Acknowledged/Retired refer to the actual last device subcommand.
 * ReadChecks bits1/2/4 mean full GPT/primary boot/backup boot; GptChecks=0xFF.
 * WriteUncertain covers an active or failed write/flush, and clears only after
 * its response, ACK and DMA retirement succeed. CacheDirty separately means
 * acknowledged writes may still be volatile; only a successful flush clears
 * it. CompletionPolicy identifies these semantics. No retry is implied. */
typedef struct {
 U64 Magic;
 U32 Version,Bytes,Stage,Reason,FirstStage,FirstReason,Ready,ReadChecks;
 U32 GptChecks,GptReason,TargetMatches,PartitionIndex;
 U64 PartitionStart,PartitionBlocks,WriteStart,WriteBlocks,NtfsSerial;
 U8 DiskGuid[16],PartitionGuid[16],PartitionType[16];
 U64 Requests,Writes,WriteBytes,Flushes,Readbacks,FuaWrites,Rejected,LastLba;
 U32 LastOpcode,LastReason,Issued,Acknowledged,Retired,Quarantined,Cleanup,WriteUncertain;
 U64 ElapsedUs;
 U32 CacheDirty,CompletionPolicy;
 /* Version3 adds the independently admitted real ESP and bounded FAT extent.
  * SystemChecks bits1/2/4 are GPT identity/primary BPB/backup BPB.
  * SystemWrites/SystemWriteBytes are the SYSTEM subset of Writes/WriteBytes. */
 U64 SystemPartitionStart,SystemPartitionBlocks,SystemWriteStart,SystemWriteBlocks;
 U8 SystemGuid[16],SystemType[16];
 U32 SystemChecks,SystemMatches,SystemPartitionIndex,FatSerial;
 U64 SystemWrites,SystemWriteBytes;
} NUF_SCOPE_REPORT;
/* Expected is reserved to retain the existing private workspace offsets;
 * only Core.ExpectedData owns the outgoing per-command payload snapshot. */
typedef struct {U8 Block[4096];U32 NextTag;U64 StartUs;NUV_VIEW View;} NUF_SCOPE_WORK;
int NufScopeAdmit(NUF_ENGINE *,NUF_SCOPE_REPORT *,NUF_SCOPE_WORK *);
int NufScopeContains(const NUF_SCOPE_REPORT *,U64,U32);
int NufScopeWrite(NUF_ENGINE *,NUF_SCOPE_REPORT *,NUF_SCOPE_WORK *,U64,const U8 *,U32);
int NufScopeFlush(NUF_ENGINE *,NUF_SCOPE_REPORT *,U32);
#endif
