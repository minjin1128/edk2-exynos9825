/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * TRACE1 pointer-free little-endian ABI shared by KD and the ARM64 reader.
 * Ordinary nonpaged CPU RAM only; never a DMA address or hardware command.
 */
#ifndef N976N_UFS_TRACE_H
#define N976N_UFS_TRACE_H
#define NUF_TRACE_MAGIC 0x314543415254554EULL /* NUTRACE1 */
#define NUF_TRACE_VERSION 1U
#define NUF_TRACE_DRIVER 0x00590206U
#define NUF_TRACE_CONTROL 0x790006U
#define NUF_TRACE_WIRE_OFFSET 32U
#define NUF_TRACE_CAPACITY 128U
#define NUF_TRACE_BINS 7U
#define NUF_TRACE_PERIOD 65U
#define NUF_TRACE_VALID_TIMING 1U
#define NUF_TRACE_TIMING_INVALID 2U
#define NUF_TRACE_STORAGE_FAILED 4U
#define NUF_TRACE_TWO_COMMANDS 8U
typedef unsigned int NUF_T32;
typedef unsigned long long NUF_T64;
typedef struct {
 NUF_T64 Sequence,T0,Worker,T1[2],T2[2],T3;
 NUF_T64 GuardPreTicks,GuardPostTicks,ReadCopyTicks,WriteCopyTicks;
 NUF_T64 GuardBytes,GuardLoads,SleepCalls,SleepRequestedUs,SleepElapsedUs,WaitObservedUs;
 NUF_T64 Lba;
 NUF_T32 Kind,Opcode,Bytes,Flags,SrbStatus,ScsiStatus,Reason,Commands;
 NUF_T32 CursorBefore,CursorAfter,Reserved[2];
} NUF_TRACE_RECORD;
typedef struct {
 NUF_T64 Attempts,Selected,Valid,Failed,Invalid,Bytes;
 NUF_T64 TotalTicks,QueueTicks,PrepareTicks,DeviceTicks,BetweenTicks,FinishTicks;
 NUF_T64 GuardPreTicks,GuardPostTicks,ReadCopyTicks,WriteCopyTicks;
 NUF_T64 GuardBytes,GuardLoads,MaxTotalTicks,MaxDeviceTicks;
 NUF_T64 SleepCalls,SleepRequestedUs,SleepElapsedUs,WaitObservedUs;
} NUF_TRACE_BIN;
typedef struct {
 NUF_T64 Magic;
 NUF_T32 Version,Bytes,Driver,RecordBytes,Capacity,Period;
 /* Odd while an admitted runtime request owns publication. Even at idle.
  * No user query can copy while that request holds the existing Busy gate. */
 NUF_T64 Generation,Frequency,InstanceQpc,InstanceSystemTime;
 NUF_T64 Attempts,Selected,Published,Overwritten,InvalidTimings;
 NUF_T64 GuardBytes,GuardLoads,ResetBytes,SweepSteps,WaitSleeps,WaitTimeouts,MaxWaitUs[4];
 NUF_T32 RecordCount,NextRecord,LastStop,LastQuarantined;
 NUF_T32 LastSessionState,Reserved[3];
 NUF_TRACE_BIN Bin[NUF_TRACE_BINS];
 NUF_TRACE_RECORD Record[NUF_TRACE_CAPACITY];
} NUF_TRACE_SNAPSHOT;
typedef char NufTraceU64Is8[(sizeof(NUF_T64)==8)?1:-1];
typedef char NufTraceRecordIs8Multiple[(sizeof(NUF_TRACE_RECORD)%8==0)?1:-1];
/* Host readers must validate all of these before indexing the record array. */
static int NufTraceHeaderValid(const NUF_TRACE_SNAPSHOT *s){
 return s&&s->Magic==NUF_TRACE_MAGIC&&s->Version==NUF_TRACE_VERSION&&s->Bytes==sizeof(*s)&&
  s->Driver==NUF_TRACE_DRIVER&&s->RecordBytes==sizeof(NUF_TRACE_RECORD)&&
  s->Capacity==NUF_TRACE_CAPACITY&&s->Period==NUF_TRACE_PERIOD&&!(s->Generation&1)&&
  s->RecordCount<=NUF_TRACE_CAPACITY&&s->NextRecord<NUF_TRACE_CAPACITY&&
  s->Published>=s->RecordCount&&s->Overwritten==s->Published-s->RecordCount&&
  s->Selected==s->Published&&s->Selected<=s->Attempts&&
  !s->Reserved[0]&&!s->Reserved[1]&&!s->Reserved[2];
}
#endif
