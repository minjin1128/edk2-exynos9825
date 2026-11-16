/* SPDX-License-Identifier: GPL-2.0-only
 * Fixed-size, diagnostic-only boot evidence. Never grants MMIO or claim access.
 * Existing stable NVS operands identify the boot; no additional hardware reads.
 */
#ifndef N976N_DEMO_LIFECYCLE_H
#define N976N_DEMO_LIFECYCLE_H
#include "N976nHsi2c.h"
#include "N976nDemoDiagnostic.h"
#include "N976nDemoStartup.h"
#include "N976nHsiWaitShape.h"
#define N976N_LIFECYCLE_VERSION 12U
#define N976N_LIFECYCLE_VALID 0x3A4C4354U
#define N976N_LIFECYCLE_VALUE L"TouchLifecycleEvidence"
enum { N976nLifePrepare=1, N976nLifeD0Entry=2, N976nLifeD0Exit=3,
       N976nLifeReleaseHardware=4, N976nLifeStartFailure=5,
       N976nLifePollFailure=6, N976nLifeInputBusy=7, N976nLifePoll=8 };
enum { N976nLifeOriginNew=0, N976nLifeOriginContext=1, N976nLifeOriginRegistry=2 };
enum { N976nLifeRegistryNone=0, N976nLifeRegistryRestored=1,
       N976nLifeRegistryOtherBoot=2, N976nLifeRegistryMalformed=3,
       N976nLifeRegistryUnavailable=4 };
#pragma pack(push,8)
typedef struct {
    unsigned int Valid,Prepare,Callback,Stage,Status,Id,CleanupStatus;
    unsigned int Claimed,Mapped,Quarantined,FunctionSaved,SenseAttempted;
    unsigned int Command,HsiCurrent,Reserved;
    N976N_HSI_RESULT Hsi;
} N976N_LIFECYCLE_STATE;
/* Runtime event-read policy only. A recovered packet is never delivered to HID. */
enum { N976nRecoveryNone=0, N976nRecoveryRecovered=1,
       N976nRecoveryExhausted=2, N976nRecoveryAborted=3 };
typedef struct {
    unsigned int Requests,Faults,Retries,Recovered,Exhausted;
    unsigned int Attempt,Outcome,GapPending,Reserved;
    N976N_LIFECYCLE_STATE FirstTransient,LastAttempt;
} N976N_EVENT_RECOVERY;
/* Exact naturally-retired RX NODEV, not a general controller-error retry.
 * TX pending may already be zero: the RX message proves TX byte/DONE passed.
 * All observed retirement error bits must still be NODEV only. */
static __inline int N976nEventNodevLength(const N976N_HSI_RESULT *H,unsigned int Bytes)
{
    const N976N_HSI_BOUNDARY *T=&H->Boundary[0],*R=&H->Boundary[2];
    const unsigned int AckReads=16U|32U|64U|128U|512U;
    return N976nHsiEvidenceShape(H)&&H->Status==N976nHsiController&&H->FirstPhase==5&&
        H->MessagesIssued==2&&H->TxBytes==1&&!H->RxBytes&&H->Retired==1&&
        !H->Quarantined&&!H->CleanupStatus&&H->Wait.Valid&&H->Wait.MessageIndex==2&&
        H->Wait.Receive==1&&H->Wait.Requested==Bytes&&H->Wait.Exit==N976nWaitOther&&
        H->FirstFailure.Valid==15&&H->Wait.Last.Valid==15&&
        H->FirstFailure.Interrupt==0x400&&H->Wait.Last.Interrupt==0x400&&
        (T->Valid&AckReads)==AckReads&&!T->MaskRead&&!T->After&&
        !(T->Pending&~0x80U)&&(R->Valid&AckReads)==AckReads&&
        !R->MaskRead&&!R->After&&!(R->IdleStatus&~0x480U)&&
        !(R->Pending&~0x480U)&&H->Last.Valid==15&&!H->Last.Interrupt;
}
static __inline int N976nEventNodev(const N976N_HSI_RESULT *H)
{ return N976nEventNodevLength(H,16); }

/* A failed batch may be dropped only after its original RX completed and
 * retired under the same lease. RxBytes counts bytes before the timeout. */
static __inline int N976nTailCanDrop(const N976N_HSI_RESULT *H, unsigned int Status,
                                    unsigned int Bytes)
{
    const N976N_HSI_BOUNDARY *Retire = &H->Boundary[2];
    const unsigned int Done = 0x80U;
    const unsigned int Ack = N976nBoundaryIdleSample | N976nBoundaryMaskAttempt |
        N976nBoundaryMaskRead | N976nBoundaryPendingRead | N976nBoundaryAckAttempt |
        N976nBoundaryAfterRead;
    if (Status == 0xC0000483U) return N976nEventNodevLength(H, Bytes);
    return Status == 0xC00000B5U && N976nHsiEvidenceShape(H) &&
        Bytes >= 16 && Bytes <= 480 && !(Bytes & 15U) &&
        H->Status == N976nHsiTimeout && H->FirstPhase == 5 && H->MessagesIssued == 2 &&
        H->TxBytes == 1 && H->RxBytes && H->RxBytes < Bytes &&
        H->DiscardedBytes == Bytes - H->RxBytes && H->Wait.Requested == Bytes &&
        H->Wait.Exit == N976nWaitDeadline && H->Retired == 1 && !H->Quarantined &&
        !H->CleanupStatus && (Retire->Valid & Ack) == Ack && Retire->IdleStatus == Done &&
        Retire->Pending == Done && !Retire->MaskRead && !Retire->After &&
        H->Last.Valid == 15 && !H->Last.Interrupt;
}
static __inline int N976nRecoveryShape(const N976N_EVENT_RECOVERY *R)
{
    const N976N_LIFECYCLE_STATE *F=&R->FirstTransient,*L=&R->LastAttempt;
    if(R->Reserved||R->Attempt>3||R->Outcome>N976nRecoveryAborted||R->GapPending>1||
       R->Recovered>R->Requests||R->Exhausted>R->Requests||R->Retries>R->Faults||
       (R->Faults>0&&(!R->Requests||!R->Attempt)))return 0;
    if(!R->Faults){
        const unsigned char *A=(const unsigned char*)F,*B=(const unsigned char*)L;
        if(R->Retries||R->Recovered||R->Exhausted||R->Attempt||R->Outcome||R->GapPending)return 0;
        for(unsigned int I=0;I<sizeof(*F);++I)if(A[I]||B[I])return 0;
        return 1;
    }
    if(R->Outcome==N976nRecoveryNone)return 0;
    if(F->Valid!=1||F->Callback!=N976nLifePoll||F->Stage!=90||F->Status!=0xC0000483U||
       F->Command!=0x60||F->HsiCurrent!=1||F->Reserved||!N976nEventNodev(&F->Hsi)||
       L->Valid!=1||L->Callback!=N976nLifePoll||L->HsiCurrent>1||L->Reserved||
       !N976nHsiEvidenceShape(&L->Hsi))return 0;
    if(R->Outcome==N976nRecoveryRecovered&&(!R->Recovered||R->Attempt<2||L->Status||
       L->HsiCurrent!=1||L->Hsi.Status||L->Hsi.RxBytes!=16||!L->Hsi.Retired||L->Hsi.Quarantined))return 0;
    if(R->Outcome==N976nRecoveryExhausted&&(!R->Exhausted||R->Attempt!=3||!N976nEventNodev(&L->Hsi)))return 0;
    if(R->Outcome==N976nRecoveryAborted&&!L->Status)return 0;
    if(R->GapPending&&R->Outcome!=N976nRecoveryRecovered)return 0;
    return 1;
}
/* Fixed-size event-service accounting, not buffer admission authority. */
typedef struct {
    unsigned int ReadOne,ReadAll,ClearAttempts,Cleared,Completed,Packets;
    unsigned int LastRemaining,LastCount,LastBytes,Reserved;
} N976N_EVENT_SERVICE;
static __inline int N976nEventServiceShape(const N976N_EVENT_SERVICE *S)
{
    if(S->Reserved||S->ReadAll>S->ReadOne||S->ClearAttempts>S->ReadOne||
       S->Cleared>S->ClearAttempts||S->Completed>S->ReadOne||S->Completed>S->Packets||
       S->LastRemaining>31||S->LastCount>31||S->LastBytes>480||(S->LastBytes&15U))return 0;
    if(!S->ReadOne){const unsigned char *B=(const unsigned char*)S;
        for(unsigned int I=0;I<sizeof(*S);++I)if(B[I])return 0;}
    if(S->LastBytes&&(!S->ReadAll||S->LastCount<2||S->LastBytes!=(S->LastCount-1)*16))return 0;
    return 1;
}
/* READ_ALL is never retried. Diagnostic state does not authorize I/O.
 * Third consecutive eligible failure is a local stop policy, not Samsung's
 * three-attempt I2C retry. Only a complete nonempty validated batch resets it. */
enum { N976nTailNone=0,N976nTailDeferred=1,N976nTailResumed=2,N976nTailTerminal=3 };
enum { N976nTailDecisionNone=0,N976nTailSafe=1,N976nTailLimit=2,
       N976nTailTransport=3,N976nTailCancelled=4,N976nTailOwner=5,N976nTailFresh=6 };
typedef struct {
    unsigned int Ordinal,Remaining,Requested,Reserved;
    unsigned char FirstPacket[16];
    N976N_LIFECYCLE_STATE State;
} N976N_TAIL_FAULT;
typedef struct {
    unsigned int Faults,Deferred,Resumed,Streak,Fatal,GapPending,AwaitingFresh;
    unsigned int Disposition,Decision,ResumeOrdinal,Reserved;
    N976N_TAIL_FAULT FirstDeferred,LastFailure;
} N976N_TAIL_RECOVERY;
/* Diagnostic history for the current prepare only. Not loaded from registry. */
typedef struct {
    unsigned int Faults, Clears, Resumed, Streak, GapPending, AwaitingFresh;
    N976N_LIFECYCLE_STATE LastFailure;
} N976N_FIRST_RECOVERY;
static __inline int N976nTailFaultShape(const N976N_TAIL_FAULT *F,int Eligible)
{
    const N976N_LIFECYCLE_STATE *S=&F->State;
    if(S->Valid!=1||!F->Ordinal||F->Remaining<1||F->Remaining>30||
       F->Requested!=F->Remaining*16||F->Reserved||!F->FirstPacket[0]||
       (F->FirstPacket[7]&31U)!=F->Remaining||S->Callback!=N976nLifePoll||
       (S->Stage!=29&&S->Stage!=90)||!(S->Status&0x80000000U)||S->Command!=0x61||
       S->HsiCurrent>1||S->Reserved||!N976nHsiEvidenceShape(&S->Hsi))return 0;
    return !Eligible || (S->HsiCurrent == 1 && !S->Quarantined &&
        N976nTailCanDrop(&S->Hsi, S->Status, F->Requested));
}
static __inline int N976nTailRecoveryShape(const N976N_TAIL_RECOVERY *R)
{
    if(R->Reserved||R->Disposition>N976nTailTerminal||R->Decision>N976nTailFresh||
       R->Streak>3||R->GapPending>1||R->AwaitingFresh>1||R->Deferred>R->Faults||
       R->Resumed>R->Deferred||R->Fatal>R->Faults)return 0;
    if(!R->Faults){const unsigned char *B=(const unsigned char*)R;
        for(unsigned int I=0;I<sizeof(*R);++I)if(B[I])return 0;return 1;}
    if(!R->Disposition||!R->Decision||!N976nTailFaultShape(&R->LastFailure,0))return 0;
    if(R->Deferred){if(!N976nTailFaultShape(&R->FirstDeferred,1))return 0;}
    else {const unsigned char *B=(const unsigned char*)&R->FirstDeferred;
        for(unsigned int I=0;I<sizeof(R->FirstDeferred);++I)if(B[I])return 0;}
    if(R->GapPending&&(R->Disposition!=N976nTailDeferred||!R->AwaitingFresh))return 0;
    if(R->Disposition==N976nTailDeferred&&(!R->Deferred||!R->Streak||R->Streak>=3||
       !R->AwaitingFresh||R->Decision!=N976nTailSafe||!N976nTailFaultShape(&R->LastFailure,1)))return 0;
    if(R->Disposition==N976nTailResumed&&(!R->Resumed||R->Streak||R->GapPending||
       R->AwaitingFresh||!R->ResumeOrdinal||R->ResumeOrdinal<R->LastFailure.Ordinal))return 0;
    if(R->Disposition==N976nTailTerminal&&(!R->Fatal||R->GapPending))return 0;
    if(R->Decision==N976nTailLimit&&(R->Disposition!=N976nTailTerminal||R->Streak!=3||
       !N976nTailFaultShape(&R->LastFailure,1)))return 0;
    return 1;
}
/* GPIO observations precede a logical event service; they are not contemporaneous
 * voltage samples at a later transport error and never authorize hardware I/O. */
typedef struct {
    unsigned int Checks,Low,HighSkip,Rejected,LastValid,LastRaw;
    unsigned int FirstErrorValid,FirstErrorRaw,LastErrorValid,LastErrorRaw;
} N976N_EVENT_READY;
static __inline int N976nReadyShape(const N976N_EVENT_READY *R)
{
    if(R->Low>R->Checks||R->HighSkip>R->Checks||R->Rejected>R->Checks||
       R->LastValid>1||R->FirstErrorValid>1||R->LastErrorValid>1)return 0;
    if((R->LastValid&&R->LastRaw==0xFFFFFFFFU)||(!R->LastValid&&R->LastRaw)||
       (R->FirstErrorValid&&(!R->Low||R->FirstErrorRaw==0xFFFFFFFFU||(R->FirstErrorRaw&1)))||
       (!R->FirstErrorValid&&R->FirstErrorRaw)||
       (R->LastErrorValid&&(!R->FirstErrorValid||R->LastErrorRaw==0xFFFFFFFFU||(R->LastErrorRaw&1)))||
       (!R->LastErrorValid&&R->LastErrorRaw))return 0;
    if(!R->Checks){const unsigned char *B=(const unsigned char*)R;
        for(unsigned int I=0;I<sizeof(*R);++I)if(B[I])return 0;}
    return 1;
}
typedef struct {
    unsigned int Version,Bytes,Crc32,Valid;
    unsigned long long NvsAddress,BootCounter,CounterHz;
    unsigned int HandoffCrc,IdentityValid;
    unsigned int PrepareCount,PrepareSuccessCount,ClaimCount,StartCount;
    unsigned int StopCount,ReleaseCount,D0EntryCount,D0ExitCount;
    unsigned int Sequence,Origin,RegistryState,CurrentCallback;
    unsigned int FirstPrepareNumber,Reserved[3];
    N976N_DEMO_DIAGNOSTIC FirstPrepareFailure;
    N976N_LIFECYCLE_STATE FirstStart,FirstStartFailure;
    N976N_LIFECYCLE_STATE FirstFailure,FirstStop,FirstCleanup,FirstCleanupFailure,FirstRelease,Current;
    /* Correspond to FirstStart, FirstStartFailure and Current respectively. */
    N976N_STARTUP_EVIDENCE FirstStartup,FirstStartupFailure,CurrentStartup;
    N976N_EVENT_RECOVERY Recovery;
    N976N_EVENT_SERVICE Service;
    N976N_TAIL_RECOVERY Tail;
    N976N_EVENT_READY Ready;
} N976N_DEMO_LIFECYCLE;
#pragma pack(pop)
#endif
