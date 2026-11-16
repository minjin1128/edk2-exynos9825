/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76: source-led adaptation of the physically observed SEC72 ID transport.
 * Samsung i2c-exynos5.c and pinned9820 controller.cpp establish register/RX
 * contracts; the bounded polling and retirement policy is local. No live
 * Windows backend, reset, ACPM, GPIO, GIC, DMA or allocation is present here.
 */
#include "N976nHsi2c.h"

#define H_CTL 0x00U
#define H_FIFO_CTL 0x04U
#define H_INT_EN 0x20U
#define H_INT_ST 0x24U
#define H_FIFO_ST 0x30U
#define H_TX 0x34U
#define H_RX 0x38U
#define H_CONF 0x40U
#define H_AUTO 0x44U
#define H_TIMEOUT 0x48U
#define H_TRANS 0x50U
#define H_FS1 0x60U
#define H_FS2 0x64U
#define H_FS3 0x68U
#define H_TRAILING 0x08U
#define H_ADDR 0x70U
#define H_USI 0xC4U
#define U32_ALL 0xFFFFFFFFU
#define H_BUSY 0x30000U
#define F_EMPTY 0x01000100U
#define F_LEVEL_FULL 0x00FF00FFU
#define I_DONE 0x80U
#define I_ERRORS 0xF3CU
#define I_KNOWN 0xFFFU
#define A_RUN 0x80000000U
#define A_STOP 0x20000U
#define A_READ 0x10000U
#define F_RX_EMPTY 0x01000000U

typedef struct {
    N976N_U64 Start, Previous, Last, Elapsed, Checks;
    N976N_U32 Same, MaxSame;
} HSI_CLOCK;

typedef struct {
    const N976N_HSI_IO *Io;
    const N976N_HSI_LEASE *Lease;
    N976N_HSI_RESULT *R;
    N976N_U32 Phase, Admitted, Touched, Lost;
    N976N_HSI_BOUNDARY *Boundary;
    HSI_CLOCK *DiscardClock;
    N976N_HSI_STATUS DiscardFailure;
} HSI_CONTEXT;

static N976N_U32 ClockCheck(HSI_CONTEXT *C, HSI_CLOCK *Clock);

static void Clear(void *P, N976N_SIZE N)
{
    N976N_U8 *B = (N976N_U8 *)P;
    while (N != 0) { *B++ = 0; --N; }
}

static int Fail(HSI_CONTEXT *C, N976N_HSI_STATUS S)
{
    if (C->R->Status == N976nHsiOk) {
        C->R->Status = (N976N_U32)S;
        C->R->FirstPhase = C->Phase;
        C->R->FirstFailure = C->R->Last;
    }
    return 0;
}

static int Owned(HSI_CONTEXT *C)
{
    if (C->Lost || !C->Io->StillOwned(C->Io->Context, C->Lease->Generation)) {
        C->Lost = 1;
        return Fail(C, N976nHsiOwnership);
    }
    /* The failed READ_ALL owns one finite cleanup window, including ACK.
     * Gate each register access so a stalled/cancelled cleanup cannot carry
     * on dequeuing or write a stale ACK when it next gets scheduled. */
    if (C->DiscardClock) {
        if (C->Io->Cancelled && C->Io->Cancelled(C->Io->Context)) {
            C->DiscardFailure = N976nHsiCancelled;
            return 0;
        }
        N976N_U32 Exit = ClockCheck(C, C->DiscardClock);
        if (Exit != N976nWaitNone) {
            C->DiscardFailure = Exit == N976nWaitDeadline ? N976nHsiTimeout : N976nHsiClock;
            return 0;
        }
    }
    return 1;
}

static int Read(HSI_CONTEXT *C, N976N_U32 Offset, N976N_U32 *V)
{
    if (!Owned(C)) return 0;
    ++C->R->Reads;
    if (!C->Io->Read32(C->Io->Context, Offset, V))
        return Fail(C, N976nHsiIo);
    return 1;
}

static int Write(HSI_CONTEXT *C, N976N_U32 Offset, N976N_U32 V)
{
    if (!Owned(C)) return 0;
    ++C->R->Writes;
    C->Touched = 1; /* Failed writes may have reached the controller. */
    if (!C->Io->Write32(C->Io->Context, Offset, V))
        return Fail(C, N976nHsiIo);
    return 1;
}

static int Sample(HSI_CONTEXT *C)
{
    N976N_HSI_SAMPLE *S = &C->R->Last;
    S->Valid = 0;
    if (!Read(C, H_INT_ST, &S->Interrupt)) return 0;
    S->Valid |= 1;
    if (!Read(C, H_TRANS, &S->Transfer)) return 0;
    S->Valid |= 2;
    if (!Read(C, H_FIFO_ST, &S->Fifo)) return 0;
    S->Valid |= 4;
    if (!Read(C, H_AUTO, &S->Auto)) return 0;
    S->Valid |= 8;
    return 1;
}

static int SampleAccessible(const N976N_HSI_SAMPLE *S)
{
    return S->Valid == 15 && S->Interrupt != U32_ALL &&
        S->Transfer != U32_ALL && S->Fifo != U32_ALL && S->Auto != U32_ALL;
}

static int Empty(N976N_U32 F)
{
    return (F & F_EMPTY) == F_EMPTY && (F & F_LEVEL_FULL) == 0;
}

static int Idle(const N976N_HSI_SAMPLE *S)
{
    /* Samsung generation INIT1 and inactive IDLE0, neither BUSY nor AUTO_RUN. */
    return SampleAccessible(S) && (S->Transfer & H_BUSY) == 0 &&
        (S->Transfer & 15U) <= 1 && Empty(S->Fifo) && (S->Auto & A_RUN) == 0;
}

static int CheckCancel(HSI_CONTEXT *C)
{
    if (C->Io->Cancelled && C->Io->Cancelled(C->Io->Context))
        return Fail(C, N976nHsiCancelled);
    return 1;
}

static void ClockStart(HSI_CONTEXT *C,HSI_CLOCK *K)
{
    Clear(K,sizeof(*K));K->Start=K->Last=C->Io->NowUs(C->Io->Context);
}
/* Same100ms deadline;20000 is only a consecutive clock-stall watchdog.
 * Reject regression against the immediately previous sample, not just start.
 * A stopped clock cannot spin forever; a progressing clock may exceed20000
 * total iterations. Return values are diagnostic exit kinds, not EFI status. */
static N976N_U32 ClockCheck(HSI_CONTEXT *C,HSI_CLOCK *K)
{
    N976N_U64 Now=C->Io->NowUs(C->Io->Context);++K->Checks;K->Previous=K->Last;
    if(Now<K->Last){K->Last=Now;K->Elapsed=0;(void)Fail(C,N976nHsiClock);return N976nWaitClock;}
    if(Now==K->Last){++K->Same;if(K->Same>K->MaxSame)K->MaxSame=K->Same;}
    else K->Same=0;
    K->Last=Now;K->Elapsed=Now-K->Start;
    if(K->Elapsed>=N976N_HSI_TIMEOUT_US)return N976nWaitDeadline;
    return K->Same>=N976N_HSI_MAX_POLLS?N976nWaitClockStall:N976nWaitNone;
}

static int Preflight(HSI_CONTEXT *C)
{
    N976N_U32 Enable, Usi, Conf, Ctl, Fs1, Fs2, Fs3, Timeout, Trailing;
    if (!Sample(C)) return 0;
    /* Outer admission has no message slot; its FirstFailure already records
     * failure. Do not leak that earlier sample into a later partial preflight. */
    if(C->Boundary){C->Boundary->Valid|=N976nBoundaryPreStatus;C->Boundary->PreStatus=C->R->Last.Interrupt;}
    if (!Read(C,H_INT_EN,&Enable)) return 0;
    if(C->Boundary){C->Boundary->Valid|=N976nBoundaryPreEnable;C->Boundary->PreEnable=Enable;}
    if (!Read(C, H_USI, &Usi) || !Read(C, H_CONF, &Conf) ||
        !Read(C, H_CTL, &Ctl) || !Read(C, H_FS1, &Fs1) ||
        !Read(C, H_FS2, &Fs2) || !Read(C, H_FS3, &Fs3) ||
        !Read(C, H_TIMEOUT, &Timeout) || !Read(C, H_TRAILING, &Trailing)) return 0;
    if (!Idle(&C->R->Last) || C->R->Last.Interrupt != 0 || Enable != 0 ||
        Usi != 0 || Conf == U32_ALL || (Conf & 0xE0000000U) != A_RUN ||
        Ctl == U32_ALL || (Ctl & A_RUN) != 0 ||
        Fs1 != C->Lease->TimingFs1 || Fs2 != C->Lease->TimingFs2 ||
        Fs3 != C->Lease->TimingFs3 || Timeout != C->Lease->Timeout ||
        Trailing != C->Lease->Trailing)
        return Fail(C, N976nHsiInitialState);
    return CheckCancel(C);
}

static int Setup(HSI_CONTEXT *C, N976N_U32 Offset, N976N_U32 V)
{
    N976N_U32 Actual;
    if (!CheckCancel(C)) return 0;
    if(Offset==H_INT_EN){C->Boundary->Valid|=N976nBoundaryArmAttempt;C->Boundary->ArmWanted=V;}
    if (!Write(C, Offset, V) || !Read(C, Offset, &Actual)) return 0;
    if(Offset==H_INT_EN){C->Boundary->Valid|=N976nBoundaryArmRead;C->Boundary->ArmRead=Actual;}
    ++C->R->SetupSeen;
    if (Actual == U32_ALL) return Fail(C, N976nHsiIo);
    if (Actual != V) {
        if (C->R->SetupMismatch == 0) {
            C->R->FirstSetupOffset = Offset;
            C->R->FirstSetupExpected = V;
            C->R->FirstSetupActual = Actual;
        }
        ++C->R->SetupMismatch;
        /* Completion/error activation is an exact control contract. CTL
         * channel readback remains observational as physically established. */
        if(Offset==H_INT_EN)return Fail(C,N976nHsiController);
    }
    /* EXP2/SEC72 physically showed CTL channel bits need not read back.
     * This evidence is not a functional success; completion/bytes still gate. */
    return 1;
}

/* Read-only natural retirement; no reset, retry or FIFO drain. An error/unknown
 * IRQ cannot be turned into success merely because the bus has become idle. */
static int WaitIdle(HSI_CONTEXT *C)
{
    HSI_CLOCK K;ClockStart(C,&K);
    for (;;) {
        ++C->R->Polls;
        if (!Sample(C)) return 0;
        if (!SampleAccessible(&C->R->Last)) return Fail(C, N976nHsiIo);
        if (C->R->Last.Interrupt & ~I_KNOWN) return Fail(C, N976nHsiController);
        if (C->R->Last.Interrupt & I_ERRORS) Fail(C, N976nHsiController);
        if (Idle(&C->R->Last)) return 1;
        if (ClockCheck(C,&K)!=N976nWaitNone) break;
    }
    return Fail(C, N976nHsiIdle);
}

static int Ack(HSI_CONTEXT *C)
{
    N976N_U32 Pending, Enable, After;
    C->Boundary->Valid|=N976nBoundaryIdleSample;C->Boundary->IdleStatus=C->R->Last.Interrupt;
    if (C->DiscardClock && C->R->Last.Interrupt != I_DONE) return 0;
    C->Boundary->Valid|=N976nBoundaryMaskAttempt;
    if (!Write(C, H_INT_EN, 0) || !Read(C, H_INT_EN, &Enable)) return 0;
    C->Boundary->Valid|=N976nBoundaryMaskRead;C->Boundary->MaskRead=Enable;
    if (Enable != 0) return Fail(C, N976nHsiAck);
    if (!Read(C, H_INT_ST, &Pending)) return 0;
    C->Boundary->Valid|=N976nBoundaryPendingRead;C->Boundary->Pending=Pending;
    if (C->DiscardClock && Pending != I_DONE) return 0;
    if (Pending & ~I_KNOWN) return Fail(C, N976nHsiAck);
    if (Pending & I_ERRORS) Fail(C, N976nHsiController);
    /* Only this exclusively owned attempt's observed status, never0xFFFFFFFF. */
    if(Pending){C->Boundary->Valid|=N976nBoundaryAckAttempt;if(!Write(C,H_INT_ST,Pending))return 0;}
    if (!Read(C, H_INT_ST, &After)) return 0;
    C->Boundary->Valid|=N976nBoundaryAfterRead;C->Boundary->After=After;
    if (After != 0) return Fail(C, N976nHsiAck);
    return 1;
}

static int MessageBody(HSI_CONTEXT *C, int Receive, N976N_U8 *Bytes, N976N_U32 Len)
{
    N976N_U32 Done = 0;
    N976N_U32 Auto = A_STOP | (Receive ? A_READ : 0) | Len;
    HSI_CLOCK K;
    N976N_U32 Trigger=Len<8U?Len:8U; /* Samsung FIFO_TRIG_CRITERIA, not transfer length. */
    C->Phase = Receive ? 4U : 2U;
    if (!Preflight(C) || !Setup(C, H_FIFO_CTL, 3U | (Trigger << 4) | (Trigger << 16)) ||
        !Setup(C, H_CTL, 8U | (Receive ? 0x40U : 0x80U)) ||
        !Setup(C, H_ADDR, (7U << 24) | (0x48U << 10)) ||
        !Setup(C, H_INT_EN, N976N_HSI_COMPLETION_MASK) || !Setup(C, H_AUTO, Auto) || !CheckCancel(C))
        return 0;
    /* Count the RUN attempt before its write: failure may still submit it. */
    ++C->R->MessagesIssued;C->R->Wait.RunIssued=1;
    if (!Write(C, H_AUTO, Auto | A_RUN)) return 0;
    C->Phase = Receive ? 5U : 3U;
    ClockStart(C,&K);
    C->R->Wait.ClockStarted=1;C->R->Wait.StartUs=K.Start;
    for (;;) {
        int Progress = 0;
        ++C->R->Polls;++C->R->Wait.Iterations;
        if (!CheckCancel(C) || !Sample(C)) return 0;
        /* Ordered individual register samples, not one atomic hardware snapshot. */
        /* First clear after a prior observed high; initial-low is not an edge.
         * RX/DONE at each edge is in the same already-read, ordered sample. */
        if((C->R->Wait.Seen&N976nSeenRun)&&!(C->R->Last.Auto&A_RUN)&&!C->R->Wait.RunClear.Iteration){
            C->R->Wait.RunClear.Iteration=C->R->Wait.Iterations;C->R->Wait.RunClear.Sample=C->R->Last;
        }
        if((C->R->Wait.Seen&N976nSeenBusy)&&!(C->R->Last.Transfer&H_BUSY)&&!C->R->Wait.BusyClear.Iteration){
            C->R->Wait.BusyClear.Iteration=C->R->Wait.Iterations;C->R->Wait.BusyClear.Sample=C->R->Last;
        }
        C->R->Wait.Last=C->R->Last;
        if(!C->R->Wait.First.Valid)C->R->Wait.First=C->R->Last;
        if(C->R->Last.Auto&A_RUN)C->R->Wait.Seen|=N976nSeenRun;
        if(C->R->Last.Transfer&H_BUSY)C->R->Wait.Seen|=N976nSeenBusy;
        if(!(C->R->Last.Fifo&0x01000000U))C->R->Wait.Seen|=N976nSeenRx;
        if(C->R->Last.Interrupt&I_DONE)C->R->Wait.Seen|=N976nSeenDone;
        if(C->R->Last.Interrupt&(~I_KNOWN|I_ERRORS))C->R->Wait.Seen|=N976nSeenError;
        if (!SampleAccessible(&C->R->Last) ||
            (C->R->Last.Interrupt & (~I_KNOWN | I_ERRORS)))
            return Fail(C, N976nHsiController);
        if (Receive && !(C->R->Last.Fifo & 0x01000000U)) {
            N976N_U32 Data;
            /* Samsung RX_FULL describes occupancy, not RX_OVERRUN.
             * The latter is INT_STATUS bit5, already rejected above. A full
             * FIFO still supplies one byte under the remaining-length bound. */
            if (Done == Len)
                return Fail(C, N976nHsiExcess);
            /* Exactly one dequeue after each fresh RX_EMPTY sample. Level
             * bits are not a batch-consumption grant. Upper24 bits are not data. */
            if (!Read(C, H_RX, &Data)) return 0;
            Bytes[Done] = (N976N_U8)Data;
            C->R->RxBytes = ++Done;
            Progress = 1;
        } else if (!Receive) {
            if (!(C->R->Last.Fifo & 0x01000000U)) return Fail(C, N976nHsiExcess);
            if (Done < Len && (C->R->Last.Fifo & 0xFFU) == 0) {
                if (!Write(C, H_TX, Bytes[Done])) return 0;
                C->R->TxBytes = ++Done;
                Progress = 1;
            }
        }
        /* A fresh sample after the final byte must exclude unexpected data. */
        if (!Progress && Done == Len && (C->R->Last.Interrupt & I_DONE)) {
            C->R->Wait.Exit=N976nWaitComplete;
            if (!WaitIdle(C) || !Ack(C)) return 0;
            return C->R->Status == N976nHsiOk;
        }
        {
            N976N_U32 Exit=ClockCheck(C,&K);
            C->R->Wait.ClockChecks=K.Checks;C->R->Wait.PreviousUs=K.Previous;C->R->Wait.LastNowUs=K.Last;C->R->Wait.ElapsedUs=K.Elapsed;
            C->R->Wait.SameClock=K.Same;C->R->Wait.MaxSameClock=K.MaxSame;
            if(Exit!=N976nWaitNone){C->R->Wait.Exit=Exit;break;}
        }
    }
    return Fail(C, N976nHsiTimeout);
}
static int Message(HSI_CONTEXT *C,int Receive,N976N_U8 *Bytes,N976N_U32 Len)
{
    int Ok;C->Boundary=&C->R->Boundary[Receive?1:0];
    Clear(&C->R->Wait,sizeof(C->R->Wait));C->R->Wait.Valid=1;
    C->R->Wait.MessageIndex=C->R->MessagesIssued+1;
    C->R->Wait.Receive=(N976N_U32)Receive;C->R->Wait.Requested=Len;
    Ok=MessageBody(C,Receive,Bytes,Len);
    if(C->R->Wait.Exit==N976nWaitNone)C->R->Wait.Exit=N976nWaitOther;
    C->R->Wait.Status=C->R->Status;C->R->Wait.Phase=C->Phase;
    return Ok;
}

static int TimedOutEvent(const N976N_HSI_RESULT *R, int RuntimeFirst, N976N_U8 Command, N976N_U32 Length)
{
    return (Command == 0x61 || (RuntimeFirst && Command == 0x60 && Length == 16)) &&
        R->Status == N976nHsiTimeout && R->FirstPhase == 5 &&
        R->Wait.Exit == N976nWaitDeadline && R->Wait.MessageIndex == 2 &&
        R->Wait.Receive && R->Wait.RunIssued && R->Wait.Requested == Length &&
        R->MessagesIssued == 2 && R->TxBytes == 1 && R->RxBytes && R->RxBytes < Length;
}

/* Drain only the residual of the RX already in flight. Its timeout, Wait,
 * FirstFailure and original RxBytes remain the evidence for the failed batch.
 * No new RUN, sensor command or reset. Data read here is never published. */
static N976N_HSI_STATUS DiscardResidual(HSI_CONTEXT *C, N976N_U32 Length)
{
    N976N_HSI_RESULT *R = C->R;
    const N976N_U32 Residual = Length - R->RxBytes;
    const N976N_U32 Auto = A_STOP | A_READ | Length;

    for (;;) {
        ++R->Polls;
        if (!Sample(C) || !SampleAccessible(&R->Last)) return N976nHsiIo;
        if ((R->Last.Auto & ~A_RUN) != Auto || (R->Last.Interrupt & ~I_DONE))
            return N976nHsiController;

        if (!(R->Last.Fifo & F_RX_EMPTY)) {
            N976N_U32 Discard;
            if (R->DiscardedBytes == Residual) return N976nHsiExcess;
            if (!Read(C, H_RX, &Discard)) return N976nHsiIo;
            ++R->DiscardedBytes;
            continue;
        }
        if (!(R->Last.Interrupt & I_DONE)) continue;
        if (R->DiscardedBytes != Residual) return N976nHsiController;
        if (!Idle(&R->Last)) continue;
        return N976nHsiOk;
    }
}

static void Retire(HSI_CONTEXT *C, int RuntimeFirst, N976N_U8 Command, N976N_U32 Length)
{
    N976N_U32 Enable;
    HSI_CLOCK CleanupClock;
    C->Phase = 6;C->Boundary=&C->R->Boundary[2];
    if (!C->Admitted || C->Lost) {
        C->R->Quarantined = 1;
        C->R->CleanupStatus = C->Lost ? N976nHsiOwnership : N976nHsiInitialState;
        return;
    }
    if (TimedOutEvent(C->R, RuntimeFirst, Command, Length)) {
        ClockStart(C, &CleanupClock);
        if (CleanupClock.Start < C->R->Wait.LastNowUs) {
            C->R->CleanupStatus = N976nHsiClock;
            goto DiscardFailed;
        }
        C->DiscardClock = &CleanupClock;
        N976N_HSI_STATUS Status = DiscardResidual(C, Length);
        if (Status != N976nHsiOk) {
            C->R->CleanupStatus = Status;
            goto DiscardFailed;
        }
    } else if (!WaitIdle(C)) {
        C->R->Quarantined = 1;
        C->R->CleanupStatus = C->Lost ? N976nHsiOwnership : N976nHsiIdle;
        return;
    }
    if (C->R->MessagesIssued) {
        if (!Ack(C)) {
            C->R->Quarantined = 1;
            C->R->CleanupStatus = C->Lost ? N976nHsiOwnership : N976nHsiAck;
            if (C->DiscardClock) goto DiscardFailed;
            return;
        }
    } else if (C->Touched) {
        /* Setup failed before RUN: disable our source but never ACK an
         * unexplained pending status from a request we did not submit. */
        if (C->R->Last.Interrupt || !Write(C, H_INT_EN, 0) ||
            !Read(C, H_INT_EN, &Enable) || Enable != 0) {
            C->R->Quarantined = 1;
            C->R->CleanupStatus = N976nHsiAck;
            return;
        }
    }
    if (!Sample(C) || !Idle(&C->R->Last) || C->R->Last.Interrupt != 0) {
        C->R->Quarantined = 1;
        C->R->CleanupStatus = C->Lost ? N976nHsiOwnership : N976nHsiIdle;
        if (C->DiscardClock) goto DiscardFailed;
        return;
    }
    if (C->DiscardClock && !Owned(C)) goto DiscardFailed;
    C->DiscardClock = 0;
    C->R->Retired = 1;
    return;

DiscardFailed:
    C->DiscardClock = 0;
    C->R->Quarantined = 1;
    if (C->Lost) C->R->CleanupStatus = N976nHsiOwnership;
    else if (C->DiscardFailure) C->R->CleanupStatus = C->DiscardFailure;
}

/* SEC72 TouchProbe.c Timing/InputClock: standard-speed equation and its exact
 * admitted clock/divisor/shift bounds, preserving all other prepared bits. */
static int TimingValid(const N976N_HSI_LEASE *L)
{
    N976N_U64 Div, Shift;
    if (L->SpeedHz != N976N_HSI_ID_SPEED_HZ || L->InputHz < 1600000 || L->InputHz > 400000000 ||
        L->TimingFs1 == U32_ALL || L->TimingFs2 == U32_ALL || L->TimingFs3 == U32_ALL ||
        (L->Timeout & A_RUN) != 0 || L->Trailing != 0xFFFFFFU) return 0;
    Div = L->InputHz / (100000U * 16U);
    if (Div == 0 || Div > 255) return 0;
    Shift = (25U * (L->InputHz / 1000000U)) / ((Div + 1U) * 10U);
    if (Shift == 0 || Shift >= 8) return 0;
    return (L->TimingFs1 & 0x00FF0000U) == (((0xFFU << (Shift - 1)) & 255U) << 16) &&
        (L->TimingFs2 & 255U) == ((0xFFU << Shift) & 255U) &&
        (L->TimingFs3 & 0x00FF0000U) == (Div << 16);
}

/* Exact Samsung grammar: READ_ALL is bounded by30 remaining16-byte packets.
 * Buffer ownership/capacity is established by the private runtime caller. */
static int Allowed(N976N_U8 Command, int Receive, N976N_U32 Count)
{
    if (Receive) return (Command == 0x52 && Count == 3) ||
        (Command == 0x55 && Count == 1) || (Command == 0x30 && Count == 2) ||
        (Command == 0x60 && Count == 16) ||
        (Command == 0x61 && Count >= 16 && Count <= 480 && (Count & 15U) == 0);
    return ((Command == 0x10 || Command == 0x11 || Command == 0x62) && Count == 0) ||
        (Command == 0x30 && Count == 2);
}
static N976N_HSI_STATUS HsiCommand(const N976N_HSI_IO *Io,
    const N976N_HSI_LEASE *Lease, N976N_U8 Command, int Receive,
    N976N_U8 *Bytes, N976N_U32 Count, N976N_HSI_RESULT *Result, int RuntimeFirst)
{
    HSI_CONTEXT C;
    N976N_U8 Tx[3] = {Command, 0, 0};
    if (!Result) return N976nHsiInvalid;
    Clear(Result, sizeof(*Result));
    if (!Io || !Lease || !Io->Read32 || !Io->Write32 || !Io->NowUs ||
        !Io->StillOwned || !Lease->Generation || Lease->Base != 0x104B0000ULL ||
        Lease->Bytes != 0x1000 || Lease->Flags != N976nHsiLeaseRequired ||
        Lease->Address != 0x48 || !TimingValid(Lease) ||
        (Receive != 0 && Receive != 1) || !Allowed(Command, Receive, Count) ||
        (Count && !Bytes)) {
        Result->Status = N976nHsiInvalid;
        return N976nHsiInvalid;
    }
    if (Receive) Clear(Bytes, Count);
    else if (Count) { Tx[1] = Bytes[0]; Tx[2] = Bytes[1]; }
    Clear(&C, sizeof(C));
    C.Io = Io; C.Lease = Lease; C.R = Result; C.Phase = 1;
    if (Preflight(&C)) {
        C.Admitted = 1;
        if (Message(&C, 0, Tx, Receive ? 1 : Count + 1) && Receive)
            (void)Message(&C, 1, Bytes, Count);
    }
    Retire(&C, RuntimeFirst, Command, Count);
    if (Result->Status == N976nHsiOk && (!Result->Retired ||
        Result->MessagesIssued != (Receive ? 2U : 1U) ||
        Result->TxBytes != (Receive ? 1U : Count + 1) ||
        Result->RxBytes != (Receive ? Count : 0)))
        (void)Fail(&C, N976nHsiIdle);
    if ((RuntimeFirst || Command == 0x61) && Receive && Result->Status != N976nHsiOk)
        Clear(Bytes, Count);
    return (N976N_HSI_STATUS)Result->Status;
}
N976N_HSI_STATUS N976nHsiCommand(const N976N_HSI_IO *Io, const N976N_HSI_LEASE *Lease,
    N976N_U8 Command, int Receive, N976N_U8 *Bytes, N976N_U32 Count, N976N_HSI_RESULT *Result)
{
    return HsiCommand(Io, Lease, Command, Receive, Bytes, Count, Result, 0);
}
/* Startup's READ_ONE observation has different failure semantics. */
N976N_HSI_STATUS N976nHsiReadFirstEvent(const N976N_HSI_IO *Io, const N976N_HSI_LEASE *Lease,
    N976N_U8 Event[16], N976N_HSI_RESULT *Result)
{
    return HsiCommand(Io, Lease, 0x60, 1, Event, 16, Result, 1);
}
N976N_HSI_STATUS N976nHsiReadId(const N976N_HSI_IO *Io,
    const N976N_HSI_LEASE *Lease, N976N_HSI_RESULT *Result)
{
    N976N_U8 Id[3] = {0,0,0};
    N976N_HSI_STATUS S = N976nHsiCommand(Io, Lease, 0x52, 1, Id, 3, Result);
    if (Result) {
        Result->Id = ((N976N_U32)Id[0] << 16) | ((N976N_U32)Id[1] << 8) | Id[2];
        Result->IdValid = S == N976nHsiOk;
    }
    return S;
}
