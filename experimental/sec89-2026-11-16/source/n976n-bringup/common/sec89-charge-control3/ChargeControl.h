/* SPDX-License-Identifier: MIT
 * SEC89 CONTROL3 continuous development core; preserved WIN1 is separate.
 * Qualifying this core on a host does NOT qualify a physical charge path.
 */
#ifndef N976N_CHARGE_CONTROL_H
#define N976N_CHARGE_CONTROL_H
#include <stdint.h>

#define NCC_RAW_COUNT 11U
#define NCC_EVIDENCE_ALL 0x3FU
enum { NCC_SOURCE_VOLTAGE=1, NCC_SOURCE_CURRENT=2, NCC_THERMISTORS=4,
       NCC_DIRECT_OFF=8, NCC_WDT_FAIL_OFF=16, NCC_PROTECTION=32 };
#define NCC_BENCH_EVIDENCE (NCC_EVIDENCE_ALL & ~NCC_WDT_FAIL_OFF)
/* 5500mV is the upper bound of VBADC bucket2, not a precise measurement.
 * WDT is armed but its physical timeout/fail-off has not been qualified. */
enum NCC_STATE { NCC_IDLE, NCC_CONFIGURING, NCC_MANAGED, NCC_MODE4_CONFIRMED,
                 NCC_REFUSED, NCC_QUARANTINED };
enum NCC_REASON { NCC_OK, NCC_ARGUMENT, NCC_OWNER, NCC_STALE, NCC_SOURCE,
 NCC_TEMPERATURE, NCC_EVIDENCE, NCC_BASELINE, NCC_CANCELLED, NCC_IO,
 NCC_READBACK, NCC_SESSION_END, NCC_REENTRANT, NCC_UNCERTAIN,
 NCC_FULL, NCC_SAFETY_TIME };
/* NOT_ISSUED means no bus effect. RETIRED_ERROR does not mean no PMIC effect.
 * UNKNOWN includes missing STOP/DONE/ACK, late completion or uncertain owner. */
enum NCC_IO_RESULT { NCC_IO_OK, NCC_IO_NOT_ISSUED, NCC_IO_RETIRED_ERROR,
                     NCC_IO_UNKNOWN };
typedef struct {
 /* C0[7] is called CHG_EN by reference code, but N976N can charge with it
  * clear. Preserve and observe it; MODE is our explicit ON/OFF control. */
 uint8_t Mode,Cnfg09Bit7,WdtEnabled,WdtExpired,FastTimerCode;
 uint8_t Wired,Wireless,WcinDetail,ChginDetail,BatteryDetail,ChargeDetail;
 uint8_t ProtectionUnlocked,AutoIbus,Route;
 uint32_t InputMa,ChargeMa,CvMv;
} NCC_VALUES;
typedef struct {
 /* All timestamps are monotonic milliseconds. SampleAt is the oldest
  * constituent measurement, never the newest of unequal-age sensors.
  * Evidence is bound to this generation/source epoch and qualified platform
  * by the adapter, not a user-set knob or a host-test PASS. */
 uint64_t Now,SampleAt,OwnerGeneration,SourceEpoch,SampleSourceEpoch;
 uint64_t InputOwnerGeneration,InputSourceEpoch,InputValidUntil;
 uint32_t MaxAgeMs,SourceMv,SourceMa,Evidence,DtCvMv;
 uint32_t WatchdogServiceMs,QualifiedWatchdogMs;
 int32_t PackDeciC,ChargerDeciC,UsbDeciC;
 uint8_t OwnerReady,Retired,Cancelled,Sink,Wired,InputLimitEnforced;
 uint8_t Raw[NCC_RAW_COUNT]; /* B2 B3 B4 B7 B8 B9 BA BB BD C0 C3 */
 /* Diagnostic only. Never substitutes for SampleAt/Evidence admission. */
 uint64_t SourceAt,ThermalAt;
 uint32_t SnapshotIssue,ThermalReason;
} NCC_FACTS;
enum NCC_PHASE { NCC_PHASE_NONE, NCC_PHASE_REARM, NCC_PHASE_START,
 NCC_PHASE_FIRST_KICK, NCC_PHASE_CC, NCC_PHASE_SECOND_KICK,
 NCC_PHASE_ENABLE, NCC_PHASE_SERVICE, NCC_PHASE_STOP, NCC_PHASE_INPUT };
enum NCC_SITE { NCC_SITE_NONE, NCC_SITE_OWNER, NCC_SITE_CANCEL, NCC_SITE_CLOCK,
 NCC_SITE_FACTS, NCC_SITE_SAMPLE_FLOOR, NCC_SITE_SOURCE, NCC_SITE_SESSION,
 NCC_SITE_KICK, NCC_SITE_NEW_SAMPLE, NCC_SITE_READ_LEASE, NCC_SITE_TICKET,
 NCC_SITE_INPUT_EPOCH, NCC_SITE_IO, NCC_SITE_READBACK, NCC_SITE_BASELINE };
typedef struct {
 NCC_FACTS Facts;
 uint64_t Now,LastKick,StartedAt;
 uint32_t Phase,Site,Reason;
} NCC_FAILURE;
enum NCC_POLICY { NCC_TIMED_TRIAL, NCC_CONTINUOUS };
/* N976N DT expired_time=10800s, adapted as a conservative wall-clock cap.
 * This is not Samsung's current-normalized/pausable safety-time algorithm. */
#define NCC_CONTINUOUS_SAFETY_MS 10800000U
typedef struct { uint32_t ChargeMa,SessionMs,Policy; } NCC_REQUEST;
typedef struct {
 uint64_t OwnerGeneration,SourceEpoch;
 uint32_t ChargeMa,InputMa,InputMilliwatts,CvMv,SessionMs;
 uint32_t WatchdogServiceMs,QualifiedWatchdogMs,Policy;
 uint8_t ChargeCode,AutoIbus,Cnfg09Bit7,Config01,Config03,Config12;
} NCC_PLAN;
typedef struct {
 uint64_t Now,OwnerGeneration;
 uint8_t OwnerReady,Retired,Cancelled;
} NCC_IDENTITY;
typedef struct {
 uint64_t OwnerGeneration,SourceEpoch,CheckedAt,NotAfter;
 uint8_t Cleanup,CompareBefore,Before,InputSetup;
} NCC_TICKET;
typedef struct {
 /* Every callback must have a finite deadline AND frozen-clock escape.
  * Snapshot=0 means transport/identity cannot be established. A sensor
  * failure returns 1 with its Evidence bit cleared; never cached-success.
  * Owner is a separate bounded identity-only check: no ADC/source sampling.
  * Cleanup=1 bypasses normal cancellation ONLY for an owned bounded stop.
  * It must never bypass owner/retirement/quarantine checks. Callbacks must
  * not reenter and must serialize against every other charger/HSI user.
  * Read/Write must validate the ticket under the ownership lock immediately
  * before issuance: generation, retirement, and (unless cleanup) cancellation,
  * source epoch and CheckedAt <= clock < NotAfter. Otherwise NOT_ISSUED.
  * Each callback holds the lock through its own issuance and retirement.
  * Inside Write, re-read the current byte under that lock, compare to Before,
  * then revalidate time/identity before payload issue without dropping it.
  * A cleanly retired pre-read failure or mismatch returns NOT_ISSUED; an
  * unknown pre-read completion returns UNKNOWN. This callback-local lock
  * does not span the core's separate Read/Snapshot/Write calls.
  * Never issue a late queued write or retry one.
  * The real adapter must test these boundaries; a mock cannot qualify it. */
 int (*Snapshot)(void *,NCC_FACTS *);
 int (*Owner)(void *,NCC_IDENTITY *);
 enum NCC_IO_RESULT (*Read)(void *,uint8_t Address,uint8_t Register,
                           uint8_t *Value,const NCC_TICKET *);
 enum NCC_IO_RESULT (*Write)(void *,uint8_t Address,uint8_t Register,
                            uint8_t Value,const NCC_TICKET *);
} NCC_OPS;
typedef struct {
 NCC_OPS Ops; void *Opaque; NCC_PLAN Plan;
 uint64_t OwnerGeneration,SourceEpoch,StartedAt,LastKick,LastNow,LastService,LastSample,StoppedAt,SampleFloor;
 uint32_t State,Reason,FirstReason,Reads,Writes,Kicks;
 uint8_t Busy,Uncertain,Mode4Confirmed,Mode4NotConfirmed,CancelLatched,CcConfigured,ExpectedMode;
 uint64_t InputAt,InputSourceEpoch;
 uint32_t InputWrites;
 uint8_t InputConfigured,InputBefore,InputAfter,InputTouched,InputFallbackConfirmed;
 /* Single owner; first failure is frozen before stop/fallback changes state. */
 NCC_FACTS ObservedFacts;
 NCC_FAILURE First;
 uint64_t ObservedNow;
 uint32_t Phase,Site;
} NCC_CONTEXT;
int NccDecode(const uint8_t Raw[NCC_RAW_COUNT],NCC_VALUES *Values);
/* Five successful 12-bit ADC samples, trimmed mean then DT interpolation.
 * The caller must bind this table/channel to the actual admitted DT. */
int NccThermistor(const uint16_t Samples[5],const uint16_t *Adc,
                 const int32_t *DeciC,uint32_t Count,uint16_t MaxMiddleSpread,
                 int32_t *Temperature);
enum NCC_REASON NccBenchPreflight(const NCC_FACTS *);
enum NCC_REASON NccPlan(const NCC_FACTS *,const NCC_REQUEST *,NCC_PLAN *);
/* A fresh independently claimed context only. Never use Init to clear an
 * active/quarantined context; that requires external hardware retirement.
 * Caller serializes every public call; Busy detects reentry, is not a lock.
 * D0 exit: latch cancellation, drain bounded worker, Stop, then release owner.
 * Keep quarantine outside a disposable D0/context lifetime. Worker loss is
 * NOT bounded by a physically qualified watchdog in CONTROL2. The enabled
 * hardware watchdog is retained; exact physical cutoff remains unverified.
 * SessionMs is a soft limit; the residual watchdog interval is additional. */
void NccInit(NCC_CONTEXT *,const NCC_OPS *,void *);
/* Initial start requires confirmed MODE4. Existing MODE5 is never adopted.
 * CC, MODE and WDTCLR plus fixed MODE4 input900/fallback100 are writable.
 * No CV/timer/unlock/route writes.
 * Return 0 means this call failed, NOT that charging is off. Inspect State
 * and Mode4Confirmed (configuration proof only). A duplicate Start leaves
 * an existing MANAGED session active: continue Service or explicitly Stop. */
int NccStart(NCC_CONTEXT *,const NCC_REQUEST *);
int NccService(NCC_CONTEXT *);
/* Explicit same-owner transition after confirmed Stop. Requires entirely new
 * admitted facts newer than the stop, including source/thermal/protection.
 * No payload writes and no clearing of cancellation, quarantine, counters or
 * FirstReason. Start must independently validate again before any writes.
 * This is not an automatic session renewal or a production recharge policy. */
int NccRearm(NCC_CONTEXT *,const NCC_REQUEST *);
/* Stop also works from an independently captured MODE5 baseline. MODE4
 * readback means command configuration confirmed, not measured zero current. */
int NccStop(NCC_CONTEXT *);
/* CONTROL2 only: fresh qualified 5V/Rp and MODE4; fixed C0[6:0]=0x23.
 * Preserve bit7. Caller invalidates source+thermal after this call, even on
 * failure. Start above500mA requires a NEW source epoch and sample afterward.
 * Stop confirms MODE4 then reduces input to100mA, preserving bit7; it never
 * replays an old limit after a cable/source change. No charging enable/PD. */
int NccPrepareInput900(NCC_CONTEXT *);
#endif
