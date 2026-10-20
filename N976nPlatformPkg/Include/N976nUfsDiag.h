/* SPDX-License-Identifier: MIT */
#ifndef N976N_UFS_DIAG_H_
#define N976N_UFS_DIAG_H_
#include <N976nPlatform.h>

#define N976N_UFS_DIAG_MAGIC SIGNATURE_64 ('N','9','7','6','U','F','1','0')
#define N976N_UFS_DIAG_VERSION 7ULL

/* Snapshot 0: no attempt; 1: request metadata, not issued; 2: issued;
 * 3: doorbells clear and format stable; 4: invalidated, immutable bytes and
 * guards checked, response copied. Response and completion IS fields are
 * meaningful only at 4. Each attempt clears the preceding response values;
 * InitFlag/PowerInitial/PowerFinal/Prepare/PowerRestore persist across attempts.
 * RawHeader0/1 pack response bytes 0..7/8..15 in wire order (big endian).
 * This separate diagnostic ABI does not change N976N_UFS_REPORT.
 * Observed* is a separate, unvalidated terminal DMA sample when flags bit2
 * is set. It can race the device and NEVER proves completion or ownership
 * return. Flags bit3 instead means the normal immutable/guard checks passed.
 * Pre/Post registers describe one attempt, not a link ACTIVE/SLEEP verdict.
 * WaitExit: 1 doorbell retired, 2 elapsed deadline, 3 iteration ceiling.
 * Experiment: 0 retained full probe, 1 two READ_FLAGs, 2 one READ_ATTR
 * (component regression only); 3 prepare device power then restore its exact
 * initial state without a media command. QueryAccepted counts validated and
 * acknowledged query replies. Prepare: 1 init flag clear, 2 known initial
 * power, 4 accepted current WLUN sense, 8 wake attempted, 10 active verified.
 * PowerRestore: 1 potentially changed, 2 restoring SSU attempted, 4 original
 * power verified. Counters include cleanup; successful cleanup preserves the
 * primary request diagnostics and updates PowerFinal/PowerRestore.
 * AckPhase: 0 none, 1 before W1C, 2 W1C returned, 3 clear/readback checked.
 * AckBefore/After are real IS values; AckCount is cumulative successful ACKs.
 * ObservationFlags bit4: invalidated raw sample after an immutable rejection;
 * it does NOT validate a response or authorize ACK, data use, or power changes.
 * ImmutableMask: bits0..3 guard pages0/2/4/6; bit4 UTRD[0,8), bit5 [9,32),
 * bit6 ring padding, bit7 command, bit8 command padding, bit9 response gap
 * (empty in this layout), bit10 PRDT, bit11 UCD tail, bit12 data DMA tail;
 * bit13 invalid length; pre-DMA-only bit14 response not zero, bit15 OCS not
 * its submitted initial byte. Offset is relative to the seven-page allocation,
 * first differing byte in that scan order; all failed regions are recorded.
 * ExpectedActual packs expected<<8|actual. Mask0 means no mismatch recorded
 * (Offset/ExpectedActual0). Invalid length uses Offset=MAX_UINT64.
 * DataTail packs data bytes16..23 in wire order after invalidation, including
 * REQUEST SENSE payload16..17 and declared DMA padding18..23.
 * It is raw evidence only; semantic sense parsing remains limited to18.
 * DmaPhase: 1 prepared CPU bytes; 2 after first clean/invalidate readback;
 * 3 re-cleaned/invalidated for submission; 4 post-completion invalidation.
 * DmaPreChecks: bit0 constructed image passed; bit1 post-flush readback passed;
 * bit2 re-sealed. Both prechecks include ALL data bytesCC and response zeros.
 * DataTailChanged counts CC differences in the tested data region;
 * DataTailLast is its last DATA-PAGE-relative byte index (zero when count0).
 * Prechecks and zero-data requests test the entire page as immutable. At
 * phase4, nonzero requests observe padding after DWORD-rounded logical Bytes;
 * that padding is INSIDE declared capacity and its changes are informational.
 * ImmutableMask/Offset still reject every change outside declared capacity.
 * DmaCapacity is the current request's explicit PRD capacity:0 or4096.
 * RequestedBytes remains the logical CDB/UPIU/response/parser bound. */
typedef struct {
  UINT64 Magic, Version, Size, Snapshot, Opcode, RequestedBytes;
  UINT64 ExpectedLun, ExpectedTag, CompletionIs, FailureMask;
  UINT64 RawHeader0, RawHeader1;
  UINT64 RawSense0, RawSense1, RawSense2, SenseFormat;
  UINT64 InitFlag, PowerInitial, PowerFinal, Prepare, PowerRestore;
  UINT64 Experiment, QueryAccepted, QueryOpcode, QueryIdn, WaitUs, WaitExit;
  UINT64 PreDbr, PostDbr, PreIs, PostIs, PreHcs, PostHcs;
  UINT64 PreIacr, PostIacr, PreAxi, PostAxi;
  UINT64 ObservedOcs, ObservedHeader0, ObservedHeader1, ObservationFlags;
  UINT64 AckPhase, AckBefore, AckAfter, AckCount;
  UINT64 ImmutableMask, ImmutableOffset, ImmutableExpectedActual, DataTail;
  UINT64 DmaPhase, DmaPreChecks, DataTailChanged, DataTailLast;
  UINT64 DmaCapacity;
} N976N_UFS_DIAG;
STATIC_ASSERT (sizeof (N976N_UFS_DIAG) == 432, "UFS diagnostic ABI");

/* Bits 0..13 are all failed predicates of the first response-validation
 * group. Only when that group passes and status is not CHECK CONDITION do
 * bits 14..18 evaluate. FIX3 decodes bounded current sense before choosing
 * a narrowly allowed recovery; only 05/25/00 marks an absent logical unit.
 * OCS7/Response1 remain recorded errors, never successful data commands. */
#define N976N_UFS_DIAG_FATAL_IS               BIT0
#define N976N_UFS_DIAG_OCS                    BIT1
#define N976N_UFS_DIAG_TRANS_CODE             BIT2
#define N976N_UFS_DIAG_TAG                    BIT3
#define N976N_UFS_DIAG_LUN                    BIT4
#define N976N_UFS_DIAG_RESPONSE               BIT5
#define N976N_UFS_DIAG_EHS                    BIT6
#define N976N_UFS_DIAG_CMD_SET                BIT7
#define N976N_UFS_DIAG_DD                     BIT8
#define N976N_UFS_DIAG_HD                     BIT9
#define N976N_UFS_DIAG_SENSE_LEN_OVERFLOW     BIT10
#define N976N_UFS_DIAG_DATA_SEG_OVERFLOW      BIT11
#define N976N_UFS_DIAG_SENSE_SEGMENT_MISMATCH BIT12
#define N976N_UFS_DIAG_RESIDUAL_EXCEEDS       BIT13
#define N976N_UFS_DIAG_STATUS                 BIT14
#define N976N_UFS_DIAG_RESIDUAL               BIT15
#define N976N_UFS_DIAG_FLAGS                  BIT16
#define N976N_UFS_DIAG_SENSE_LEN              BIT17
#define N976N_UFS_DIAG_DATA_SEG               BIT18
#define N976N_UFS_DIAG_SENSE_FORMAT           BIT19
#define N976N_UFS_DIAG_QUERY                  BIT20

extern volatile N976N_UFS_DIAG mN976nUfsDiag;
#endif
