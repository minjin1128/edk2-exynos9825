/* SPDX-License-Identifier: MIT
 * Pointer-free, read-only cached report. All times are target monotonic time.
 * This protocol cannot request hardware access, charging or rearm.
 */
#ifndef N976N_CHARGE_DIAG_PROTOCOL_H
#define N976N_CHARGE_DIAG_PROTOCOL_H
#include <stdint.h>
#define NCD_IOCTL 0x00296224U /* BATTERY, function 0x889, READ_ACCESS, BUFFERED */
#define NCD_MAGIC 0x4439384EU
#define NCD_VERSION 5U
#define NCD_DRIVER 606U
enum NCD_QUARANTINE_SITE {
 NCD_Q_ADC_RELEASE=1,
 NCD_Q_THERMAL=2,
 NCD_Q_SNAPSHOT_OWNER=3,
 NCD_Q_WORKER_OWNER=4,
 NCD_Q_ACQUIRE=5,
 NCD_Q_LOOP_OWNER=6,
 NCD_Q_CONTROL=7,
 NCD_Q_POST_OWNER=8,
 NCD_Q_BUS_OR_ACCESS=9,
 NCD_Q_EXIT_CONTROL=10,
 NCD_Q_EXIT_OWNER=11,
 NCD_Q_BUS_RELEASE=12,
 NCD_Q_PREPARE_OWNER=13,
 NCD_Q_PREPARE_ADC=14,
 NCD_Q_D0_BINDING=15,
 NCD_Q_D0_HSI=16,
 NCD_Q_D0_ADC=17
};
typedef struct {
 uint64_t SampleId,Reason,Status,FailurePhase,Requested,Received;
 uint64_t FirstInterrupt,FirstFifo,FirstWaitUs,FirstWaitExit;
 uint64_t FirstAddress,FirstExpected,FirstActual,FirstMask;
} NCD_BUS_EVENT;
typedef struct {
 uint64_t Count,At100ns;
 uint32_t Status,Tag,PowerState,Capacity,Voltage,Reserved;
} NCD_QUERY;
typedef struct {
 uint32_t Magic,Version,Bytes,Driver;
 uint64_t Sequence,Published100ns,Query100ns,Generation;
 uint64_t Samples,Failures,ControlCycles,StartedMs,StoppedMs,LastServiceMs,LastKickMs;
 uint64_t StartCalls,ManagedStarts,ManagedAtMs,PowerAt100ns,PowerReadStatus;
 uint64_t GaugeStart100ns,GaugeEnd100ns,SourceStart100ns,SourceEnd100ns,SourceEpoch;
 uint32_t Stage,Status,Point,StopRequested,Quarantined,WorkerLive;
 uint32_t ControlState,Reason,FirstReason,Attempt,Preflight,Mode4Confirmed,Uncertain;
 uint32_t ControlReads,ControlWrites,ControlKicks,SessionMs,ChargeMa;
 uint32_t PowerValidMask,GaugeValidMask,SourceValid,SourceOnlineKnown,SourceOnline;
 uint32_t Mode,Detail,WdtEnabled,WdtExpired,InputMa,ConfiguredMa,CvMv,RpCode,PsReady;
 int32_t CurrentMa;
 uint32_t VoltageMv,SocPermille,GaugeChargeState;
 uint8_t PowerRaw[20];
 uint32_t PowerDecoded,Reserved[2];
 NCD_QUERY LastQuery;
 uint64_t InputAtMs,InputSourceEpoch;
 uint32_t InputConfigured,InputWrites,InputBefore,InputAfter,PreflightEvidence,PreflightMissing,InputFallbackConfirmed,InputTouched;

 /* Frozen first failure. Times are monotonic milliseconds, not current facts. */
 uint32_t FirstPhase,FirstSite,FirstControlReason,FirstSnapshotIssue;
 uint32_t FirstThermalReason,FirstEvidence,FirstMaxAgeMs,FirstServiceMs;
 uint64_t FirstNowMs,FirstSampleMs,FirstSourceMs,FirstThermalMs,FirstKickMs,FirstStartedMs;
 uint64_t SnapshotCalls,SnapshotTotalMs,SnapshotMaxMs,StartSnapshotCalls,StartElapsedMs;
 uint64_t Attachment,Detaches;
 uint32_t Policy,HoldReason,ConnectionSignal,Detached,ConnectionFault,Reserved4;
 /* Append-only v5: first device quarantine is separate from first bus error.
  * No MMIO on query; legacy LastQuery remains at offset360. */
 uint64_t QuarantineAt100ns;
 uint32_t QuarantineSite,Reserved5;
 NCD_BUS_EVENT QuarantineBus,FirstBus;
} NCD_REPORT;
#endif
