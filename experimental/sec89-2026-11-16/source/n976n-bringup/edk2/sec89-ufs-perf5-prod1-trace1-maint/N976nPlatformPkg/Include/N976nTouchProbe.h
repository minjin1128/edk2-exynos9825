/* SPDX-License-Identifier: MIT */
#ifndef N976N_TOUCH_PROBE_H_
#define N976N_TOUCH_PROBE_H_
#include <N976nTouch.h>

#define N976N_TOUCH_SNAPSHOT_MAGIC 0x3936505348435554ULL
#define N976N_TOUCH_SNAPSHOT_CHECKS 0xFFULL
enum {
  TouchCmuOsc, TouchCmuBusReset, TouchCmuApb0, TouchCmuApb1,
  TouchCmuGpio, TouchCmuSysreg, TouchCmuI2cReset, TouchCmuI2cIp,
  TouchCmuI2cPclk, TouchCmuI2cQch, TouchCmuBusMux,
  TouchCmuI2cMux, TouchCmuI2cDiv, TouchCmuCount
};
enum {
  TouchAliveCon, TouchAliveData, TouchAlivePull, TouchAliveDrive,
  TouchAliveEintCon, TouchAliveEintFilter, TouchAliveEintMask,
  TouchAliveEintPending, TouchAliveCount
};
enum { TouchGppCon, TouchGppData, TouchGppPull, TouchGppDrive, TouchGppCount };
enum {
  TouchHsiCtl, TouchHsiFifoCtl, TouchHsiTrailing,
  TouchHsiIntEnable, TouchHsiIntStatus, TouchHsiFifoStatus,
  TouchHsiConf, TouchHsiAutoConf, TouchHsiTransStatus,
  TouchHsiTimingHs1, TouchHsiTimingHs2, TouchHsiTimingHs3,
  TouchHsiTimingFs1, TouchHsiTimingFs2, TouchHsiTimingFs3,
  TouchHsiAddr, TouchHsiCount
};
#define N976N_TOUCH_CLASS_ALIVE  1ULL
#define N976N_TOUCH_CLASS_CMU    2ULL
#define N976N_TOUCH_CLASS_GPIO   4ULL
#define N976N_TOUCH_CLASS_USI    8ULL
#define N976N_TOUCH_CLASS_HSI   16ULL
#define N976N_TOUCH_CLASS_ALL  31ULL

/* Frozen after SEC. Experimental Version8 records transfer-setup readback
 * mismatches without aborting only these five ordinary writes per transaction.
 * The previous 584-byte prefix remains byte-layout compatible, but its seven
 * SetupFailure fields now describe the first NONFATAL mismatch. Never accept
 * this experimental ABI under the older fatal-readback contract.
 * ValidMask describes captured register classes; Hsi[] is captured only after
 * source-backed access prerequisites are established, before HSI reconfiguration.
 * ReadCount counts all MMIO reads, not just the initial snapshot.
 * Checks: admission, CPU/counter, ALIVE, CMU, GPIO, USI, HSI, retired safely.
 * Bit7 is clear if any owned configuration cannot be safely restored.
 * Phase8 means a bounded attempt ended; only Status=SUCCESS with PrepChecks=FF,
 * RestoreChecks=3F and Id!=0/FFFFFF means a completed three-byte ID observation.
 * FIFO/W1C are transaction state, not included in an exact-register-restore claim.
 */
#define TOUCH_PREP_SOURCE       BIT0
#define TOUCH_PREP_QCH          BIT1
#define TOUCH_PREP_USI          BIT2
#define TOUCH_PREP_PINS         BIT3
#define TOUCH_PREP_IDLE         BIT4
#define TOUCH_PREP_CLOCK        BIT5
#define TOUCH_PREP_CONFIG       BIT6
#define TOUCH_PREP_ID           BIT7
#define TOUCH_PREP_ALL          0xFFULL
#define TOUCH_RESTORE_IDLE      BIT0
#define TOUCH_RESTORE_HSI       BIT1
#define TOUCH_RESTORE_USI_CTL   BIT2
#define TOUCH_RESTORE_PINS      BIT3
#define TOUCH_RESTORE_USI_MODE  BIT4
#define TOUCH_RESTORE_QCH       BIT5
#define TOUCH_RESTORE_ALL       0x3FULL
#define TOUCH_POLL_LIMIT        65536U
#define TOUCH_WAIT_US           100000U
/* Seven bounded loops: initial reset/cleanup/recovery idle (4 each), TX/RX
 * transfer (3 each), TX/RX completion idle (4 each), plus all fixed reads. */
#define TOUCH_MAX_MMIO_READS    (26ULL * TOUCH_POLL_LIMIT + 512ULL + TOUCH_EVENT_MAX_TRANSACTIONS * (12ULL * TOUCH_POLL_LIMIT + 32ULL))
#define TOUCH_MAX_MMIO_WRITES   (128ULL + 12ULL * TOUCH_EVENT_MAX_TRANSACTIONS)
#define TOUCH_STAGE_PINS        BIT0
#define TOUCH_STAGE_RELEASED    BIT1
#define TOUCH_STAGE_RESET       BIT2
#define TOUCH_STAGE_CONFIGURED  BIT3
#define TOUCH_STAGE_CLEANUP     BIT4
#define TOUCH_STAGE_RECOVERY    BIT5
#define TOUCH_STAGE_RECOVERED   BIT6
#define TOUCH_STAGE_ALL         0x7FULL
#define TOUCH_INPUT_OBSERVED    BIT0
#define TOUCH_INPUT_HIGH        BIT1
#define TOUCH_INPUT_PULL_WRITE  BIT2
#define TOUCH_INPUT_AF_SKIP     BIT3
#define TOUCH_INPUT_RAW         BIT4
#define TOUCH_INPUT_ALL         0x1FULL
/* The first five bits mark five raw observations, each TRANS_STATUS in high32
 * and full GPP1_DAT in low32. RECOVERY means one pre-start local HSI reset was
 * attempted; RECOVERED additionally proves idle/empty/IRQoff and high bus lines.
 * CleanupReason is separate from the first fault (Reason/FailureStage). */
/* EXP2 RX observations are sequential register samples, not an atomic bus
 * snapshot. Data32 comes only from the actual payload dequeue; diagnostics
 * never reread RX_DATA. First is immutable; Failure independently preserves
 * the first functional RX failure even after an earlier accepted anomaly.
 * Kind1/2/3 are nonfatal observations; Kind4..9 describe functional failure.
 * With Kind0 every member is zero. Other records have Phase6/count2,
 * Before0..3 and Remaining=3-Before. Only Kind3 carries DataValid/Data32/Payload.
 */
#define TOUCH_RX_LEVEL_ZERO    1ULL
#define TOUCH_RX_LEVEL_EXCESS  2ULL
#define TOUCH_RX_DATA_HIGH     3ULL
#define TOUCH_RX_EXCESS        4ULL
#define TOUCH_RX_CONTROLLER    5ULL
#define TOUCH_RX_IDLE          6ULL
#define TOUCH_RX_ACK           7ULL
#define TOUCH_RX_TIMEOUT       8ULL
#define TOUCH_RX_ID            9ULL
typedef struct {
  UINT64 Kind, Phase, TransactionCount, Before, Remaining;
  UINT64 Fifo, Interrupt, Transfer, Auto;
  UINT64 DataValid, Data32, Payload;
} N976N_TOUCH_RX_OBSERVATION;
STATIC_ASSERT (sizeof (N976N_TOUCH_RX_OBSERVATION)==96, "EXP2 RX record ABI");

/* SEC72 cold-owned Y771 event session. Successful transport/retirement does
 * not imply a finger was observed. Outcome1=no accepted finger; Outcome2=at
 * least one accepted coordinate. Original sensing state is not readable: this
 * session is permitted only with both touch rails originally disabled. */
#define TOUCH_EVENT_WINDOW_SECONDS 20U
#define TOUCH_EVENT_POLL_LIMIT 1000U
#define TOUCH_EVENT_BOOT_LIMIT 101U
#define TOUCH_EVENT_DELAY_LIMIT 10000000U
#define TOUCH_EVENT_MAX_TRANSACTIONS (2ULL * (TOUCH_EVENT_POLL_LIMIT + TOUCH_EVENT_BOOT_LIMIT) + 16ULL)
#define TOUCH_EVENT_MAX_BYTES (16ULL * TOUCH_EVENT_MAX_TRANSACTIONS)
#define TOUCH_EVENT_ALL 0xFFULL
#define TOUCH_EVENT_BOOT_READY BIT0
#define TOUCH_EVENT_APP BIT1
#define TOUCH_EVENT_FUNCTION_READ BIT2
#define TOUCH_EVENT_FUNCTION_SET BIT3
#define TOUCH_EVENT_SENSE_ON BIT4
#define TOUCH_EVENT_WINDOW BIT5
#define TOUCH_EVENT_SENSE_OFF BIT6
#define TOUCH_EVENT_FUNCTION_RESTORE BIT7
typedef struct {
  UINT64 Mode, Phase, Status, Reason, Checks, Outcome;
  UINT64 Transactions, TxBytes, RxBytes, Command, Length, Done, Direction;
  UINT64 BootReady, BootStatus, FunctionBefore, FunctionEnabled, FunctionRestored;
  UINT64 SenseOn, SenseOff, CleanupReason;
  UINT64 Polls, EmptyCount, StatusCount, CoordinateCount;
  UINT64 PressCount, MoveCount, ReleaseCount, OtherCount, ActiveMask;
  UINT64 FirstX, FirstY, FirstId, LastX, LastY, LastId, LastAction, LastType, Remaining;
  UINT64 WindowTicks, ElapsedTicks, Stop;
  UINT64 SetupSeen, SetupMismatch, SetupOffset, SetupExpected, SetupActual;
  UINT8 FirstRaw[16], LastRaw[16], RejectRaw[16];
  N976N_TOUCH_RX_OBSERVATION RxFirst, RxFailure;
} N976N_TOUCH_EVENT_OBSERVATION;
STATIC_ASSERT (sizeof (N976N_TOUCH_EVENT_OBSERVATION)==616, "SEC72 event ABI");

typedef struct {
  UINT64 Magic, Version, Size, Profile, Phase, Status, Checks, Reason;
  UINT64 CpuEl, CpuSctlr, CpuDaif;
  UINT64 ReadCount, ValidMask, SkipMask;
  UINT32 Cmu[TouchCmuCount], Alive[TouchAliveCount], Gpp[TouchGppCount];
  UINT32 UsiMode, Hsi[TouchHsiCount];
  UINT64 WriteCount, PrepChecks, RestoreChecks, Quarantined;
  UINT64 InputHz, CounterHz, WaitTicks, TransactionCount;
  UINT64 TxBytes, RxBytes, Id, TransferStatus, InterruptStatus, FifoStatus;
  UINT64 UsiControlBefore, UsiOptionBefore;
  UINT64 TimingFs1, TimingFs2, TimingFs3, FailureStage;
  UINT64 StageMask, PinsState, ReleasedState, ResetState, ConfiguredState;
  UINT64 CleanupState, CleanupReason;
  /* OBSERVED proves GPIO input/no pull/USI reset held, stable configuration,
   * clock and inactive empty controller at the raw TRANS/DAT observation.
   * HIGH requires OBSERVED; PULL_WRITE records an attempted two-pin PUD write.
   * AF_SKIP means both pins were already function2, with no input proof.
   * RAW permits retaining InputState when later verification contradicts it.
   * PDN fields are raw GPIO-class reads, not an active-retention indication. */
  UINT64 InputCheck, InputState, GppConPdn, GppPullPdn;
  /* First observed mismatch, diagnostic only in experimental Version8.
   * Step1..5 identifies FIFO_CTL/CTL/ADDR/INT_EN/AUTO before AUTO_RUN.
   * Phase5/count0 is TX; Phase6/count1 is RX. The existing field names retain
   * the prefix layout, not the old Version5 fatal-mismatch semantics.
   * A zero Step requires these seven fields to be zero; cleanup cannot replace
   * this first observation. Actual transfer and cleanup failures remain in
   * Reason/FailureStage/CleanupReason, independently of this mismatch. */
  UINT64 SetupFailureStep, SetupFailureOffset;
  UINT64 SetupFailureExpected, SetupFailureObserved, SetupFailureMask;
  UINT64 SetupFailurePhase, SetupFailureTransactionCount;
  /* Ten fixed slots: TX steps1..5 then RX steps1..5. Captured bits describe
   * one existing immediate read after each programmed write; mismatch bits
   * compare all32 bits, but do not claim the device accepted the write.
   * Both masks are ten bits. Uncaptured raw slots stay zero. Expected values
   * and offsets are fixed by direction/step; no extra MMIO reads are added. */
  UINT64 SetupObservedMask, SetupMismatchMask;
  UINT32 SetupObserved[10];
  N976N_TOUCH_RX_OBSERVATION RxFirst, RxFailure;
  N976N_TOUCH_EVENT_OBSERVATION Event;
} N976N_TOUCH_SNAPSHOT;
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, SetupFailureStep)==528,
  "SEC72 preserves touch prefix");
STATIC_ASSERT (sizeof (N976N_TOUCH_SNAPSHOT)==1448, "SEC72 touch snapshot ABI");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, SetupObservedMask)==584,
  "SEC72 experimental observation extension");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, SetupMismatchMask)==592,
  "SEC72 mismatch mask ABI");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, SetupObserved)==600,
  "SEC72 fixed raw slot ABI");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, RxFirst)==640, "EXP2 first RX observation ABI");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, RxFailure)==736, "EXP2 first RX failure ABI");
STATIC_ASSERT (OFFSET_OF (N976N_TOUCH_SNAPSHOT, Event)==832, "SEC72 append-only event ABI");
extern EFI_GUID gN976nTouchSnapshotGuid;

/* Called only in SEC before the MMU is enabled. Captures current CPU state and
 * rejects any state other than EL1, MMU/cache disabled and all DAIF masked.
 * Address allowlisting is checked again before the first MMIO read. */
BOOLEAN EFIAPI N976nSnapshotTouch (
  CONST N976N_TOUCH_ADMISSION *Admission, N976N_TOUCH_SNAPSHOT *Snapshot);
/* Caller must have proved both touch rail enable fields were originally off,
 * enabled only the admitted rails, and owns the cold-powered callback lifetime.
 * This API does not authorize use on an inherited running touch session. */
BOOLEAN EFIAPI N976nObserveTouchEvents (
  CONST N976N_TOUCH_ADMISSION *Admission, N976N_TOUCH_SNAPSHOT *Snapshot);
/* Fixed platform diagnostic hook; no address or callback supplied by devices. */
BOOLEAN EFIAPI N976nTouchEventProgress (CONST N976N_TOUCH_SNAPSHOT *Snapshot);
/* Accepted coordinate only. A display refusal ends observation through normal
 * owned peripheral cleanup; it never grants device access or forces a reset. */
BOOLEAN EFIAPI N976nTouchEventContact (CONST N976N_TOUCH_SNAPSHOT *Snapshot);
#endif
