/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 isolated ID diagnostic engine. No MMIO backend or Windows activation.
 */
#ifndef N976N_HSI2C_H
#define N976N_HSI2C_H
#include "N976nResources.h"

enum {
    N976nHsiLeaseExclusive = 1U,
    N976nHsiLeaseFirmwareRetired = 2U,
    N976nHsiLeasePowerStable = 4U,
    N976nHsiLeaseClockPrepared = 8U,
    N976nHsiLeasePinsPrepared = 16U,
    N976nHsiLeaseControllerPrepared = 32U,
    N976nHsiLeasePrimaryIrqMaskedOwned = 64U,
    N976nHsiLeaseRequired = 127U
};
#define N976N_HSI_MAX_POLLS 20000U
#define N976N_HSI_TIMEOUT_US 100000U
#define N976N_HSI_ID_SPEED_HZ 100000U
/* Samsung transfer-state bits8..11 + DONE7; no FIFO IRQ sources. */
#define N976N_HSI_COMPLETION_MASK 0xF80U

typedef enum {
    N976nHsiOk = 0, N976nHsiInvalid = 1, N976nHsiOwnership = 2,
    N976nHsiIo = 3, N976nHsiInitialState = 4, N976nHsiController = 5,
    N976nHsiTimeout = 6, N976nHsiExcess = 7, N976nHsiIdle = 8,
    N976nHsiAck = 9, N976nHsiCancelled = 10, N976nHsiClock = 11
} N976N_HSI_STATUS;

/* Trusted internal evidence, NOT an ACPI blob or a security capability.
 * A future provider must first acquire and retain actual framework/controller,
 * power, clock, pin and primary IRQ ownership. Flags cannot manufacture that
 * ownership. The primary IRQ is held masked for this polling-only experiment;
 * the independent touch GPIO IRQ is not used by an ID read.
 */
typedef struct {
    N976N_U64 Generation, Base, Bytes, InputHz;
    N976N_U32 Flags, Address, SpeedHz;
    N976N_U32 TimingFs1, TimingFs2, TimingFs3, Timeout, Trailing;
} N976N_HSI_LEASE;

/* Callbacks must be bounded, ordered/fenced, non-reentrant, and restricted to
 * the admitted HSI2C page. Read32 returns one sample, especially for RX_DATA;
 * failure must not be reported as data. Write32 success means submitted, not
 * necessarily a matching readback. A failed write may have reached hardware.
 * StillOwned must check the same continuously held provider lease/generation;
 * no callback may release/replace it. NowUs is monotonic within this call.
 * Cancellation does not transfer ownership; natural retirement is still
 * observed. No callback may reset the controller or touch power implicitly.
 */
typedef struct {
    void *Context;
    int (*Read32)(void *Context, N976N_U32 Offset, N976N_U32 *Value);
    int (*Write32)(void *Context, N976N_U32 Offset, N976N_U32 Value);
    N976N_U64 (*NowUs)(void *Context);
    int (*StillOwned)(void *Context, N976N_U64 Generation);
    int (*Cancelled)(void *Context); /* Optional. */
} N976N_HSI_IO;

typedef struct {
    N976N_U32 Interrupt, Transfer, Fifo, Auto, Valid;
} N976N_HSI_SAMPLE;

/* EXP4 keeps one clock check per message poll, using the precise interrupt
 * clock. No register read is added. Clear transitions use existing samples. Completion means the byte/DONE
 * condition won; subsequent natural-idle/ACK failure is reported by Status.
 * ElapsedUs is the last EXISTING budget check, not total request wall time. */
enum { N976nWaitNone=0, N976nWaitComplete=1, N976nWaitDeadline=2,
       N976nWaitClockStall=3, N976nWaitClock=4, N976nWaitOther=5 };
enum { N976nSeenRun=1, N976nSeenBusy=2, N976nSeenRx=4,
       N976nSeenDone=8, N976nSeenError=16 };
typedef struct {
    N976N_U64 Iteration;
    N976N_HSI_SAMPLE Sample;
    N976N_U32 Reserved;
} N976N_HSI_TRANSITION;
/* At most100000 forward1us steps before deadline, fewer than20000 unchanged
 * samples between advances. Conservative diagnostic bound, never loop control. */
#define N976N_HSI_WAIT_MAX_ITERATIONS (100000ULL * 20001ULL + 1ULL)
typedef struct {
    N976N_U32 Valid, MessageIndex, Receive, Requested, RunIssued;
    N976N_U32 Exit, Seen, Status, Phase, ClockStarted, SameClock, MaxSameClock;
    N976N_U64 Iterations, ClockChecks;
    N976N_U64 StartUs, PreviousUs, LastNowUs, ElapsedUs;
    N976N_HSI_SAMPLE First, Last;
    N976N_HSI_TRANSITION RunClear, BusyClear;
} N976N_HSI_WAIT;

/* Diagnostic-only ordered operands. TX/RX message ACK and final retirement
 * have distinct slots, so cleanup never overwrites the message boundary. */
enum { N976nBoundaryPreStatus=1U, N976nBoundaryPreEnable=2U,
       N976nBoundaryArmAttempt=4U, N976nBoundaryArmRead=8U,
       N976nBoundaryIdleSample=16U, N976nBoundaryMaskAttempt=32U,
       N976nBoundaryMaskRead=64U, N976nBoundaryPendingRead=128U,
       N976nBoundaryAckAttempt=256U, N976nBoundaryAfterRead=512U };
typedef struct {
    N976N_U32 Valid, PreStatus, PreEnable, ArmWanted, ArmRead;
    N976N_U32 IdleStatus, MaskRead, Pending, After;
} N976N_HSI_BOUNDARY;

typedef struct {
    N976N_U32 Status, FirstPhase, CleanupStatus;
    N976N_U32 MessagesIssued, TxBytes, RxBytes, Id, IdValid;
    N976N_U32 Retired, Quarantined, Writes, DiscardedBytes;
    N976N_U64 Polls, Reads;
    N976N_U32 SetupSeen, SetupMismatch;
    N976N_U32 FirstSetupOffset, FirstSetupExpected, FirstSetupActual;
    N976N_HSI_SAMPLE FirstFailure, Last;
    N976N_HSI_WAIT Wait;
    N976N_HSI_BOUNDARY Boundary[3]; /* TX, RX, final Retire; no extra reads */
} N976N_HSI_RESULT;

/* Exactly command0x52 TX1+STOP, RX3+STOP; no retries or submitted-request reset.
 * This is not SPBCx sequence handling: target/controller serialization is an
 * explicit caller prerequisite across the two standalone STOP transactions.
 * Prepared configuration is required, not initialized here. This isolated ID
 * uses the physically exercised SEC72 100kHz standard-speed timing equation;
 * the disabled ACPI 400kHz future SPB policy is a different contract. The
 * caller's independently proven InputHz and exact prepared FS1/2/3 words are
 * rechecked against the SEC72 equation and fresh register reads. Matching
 * words alone do not measure the input clock. Retired means
 * owned request activity/IRQ has retired; it does NOT claim exact platform
 * restoration or rail-off permission. IdValid requires both messages and final
 * retirement. Input/callback storage and Result must be disjoint, kernel-owned
 * storage. An invalid argument/lease performs no callbacks or MMIO.
 */
N976N_HSI_STATUS N976nHsiReadFirstEvent(const N976N_HSI_IO *Io,
    const N976N_HSI_LEASE *Lease, N976N_U8 Event[16], N976N_HSI_RESULT *Result);
N976N_HSI_STATUS N976nHsiReadId(const N976N_HSI_IO *Io,
    const N976N_HSI_LEASE *Lease, N976N_HSI_RESULT *Result);
/* Internal bounded command surface, not an IOCTL. Read52/3,55/1,30/2,60/16,61/(16..480 aligned16);
 * write10/0,11/0,30/2. Caller serializes whole STOP-terminated command pairs.
 * Read buffers are zeroed before dispatch; failure never authorizes their use. */
N976N_HSI_STATUS N976nHsiCommand(const N976N_HSI_IO *Io,
    const N976N_HSI_LEASE *Lease, N976N_U8 Command, int Receive,
    N976N_U8 *Bytes, N976N_U32 Count, N976N_HSI_RESULT *Result);
#endif
