/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 runnable private polling transport under one ACPI HID owner.
 * No GIC/GPIO writes, ACPM, reset, DMA, PLL retune, firmware update or storage.
 * Firmware grants a prepared boot-lifetime rail lease; this driver leaves
 * those rails enabled. D0 quiesces sensing/controller, not a false rail restore.
 * Only the PnP/D0 path and one passive one-shot timer call this backend. D0Exit
 * first cancels and joins that producer; no user I/O reaches these methods.
 */
#include "N976nDemoRuntime.h"
#include "Y771Event.h"
#include "ClockShare.h"
#include <stddef.h>
static PVOID volatile Owner;
static const ULONGLONG Bases[7]={0x104B0000ULL,0x10400000ULL,0x10421000ULL,0x10430000ULL,0x1A240000ULL,0,0x15850000ULL};
static const ULONG Sizes[7]={0x1000,0x8000,0x1000,0x1000,0x3000,4096,0x1000};
/* Evidence has no authority over mappings, MMIO, claims or cleanup decisions. */
static VOID LifeInc(unsigned int *V) { if(*V!=0xFFFFFFFFU)++*V; }
ULONG N976nDemoLifecycleCrc(const N976N_DEMO_LIFECYCLE *L)
{
    const UCHAR *B=(const UCHAR*)L;ULONG C=~0U;
    for(ULONG I=0;I<sizeof(*L);++I){
        UCHAR V=I>=offsetof(N976N_DEMO_LIFECYCLE,Crc32)&&I<offsetof(N976N_DEMO_LIFECYCLE,Crc32)+4?0:B[I];
        C^=V;for(ULONG Bit=0;Bit<8;++Bit)C=(C>>1)^((C&1)?0xEDB88320U:0);
    }return ~C;
}
static VOID LifeInit(N976N_DEMO_LIFECYCLE *L)
{ RtlZeroMemory(L,sizeof(*L));L->Version=N976N_LIFECYCLE_VERSION;L->Bytes=sizeof(*L);L->Valid=N976N_LIFECYCLE_VALID; }
static int LifeShape(const N976N_DEMO_LIFECYCLE *L)
{
    const N976N_LIFECYCLE_STATE *States[]={&L->FirstStart,&L->FirstStartFailure,&L->FirstFailure,
        &L->FirstStop,&L->FirstCleanup,&L->FirstCleanupFailure,&L->FirstRelease,&L->Current};
    if(L->Version!=N976N_LIFECYCLE_VERSION||L->Bytes!=sizeof(*L)||L->Valid!=N976N_LIFECYCLE_VALID||
       L->IdentityValid!=1||!L->BootCounter||!L->CounterHz||L->NvsAddress<N976N_TOUCH_HANDOFF_LOW||
       L->NvsAddress>N976N_TOUCH_HANDOFF_END-4096||(L->NvsAddress&4095)||
       L->Origin>N976nLifeOriginRegistry||L->RegistryState>N976nLifeRegistryUnavailable||
       L->CurrentCallback>N976nLifePoll||L->Reserved[0]||L->Reserved[1]||L->Reserved[2]||
       L->Crc32!=N976nDemoLifecycleCrc(L)||
       !N976nStartupShape(&L->FirstStartup)||!N976nStartupShape(&L->FirstStartupFailure)||
       !N976nStartupShape(&L->CurrentStartup)||!N976nRecoveryShape(&L->Recovery)||!N976nEventServiceShape(&L->Service)||!N976nTailRecoveryShape(&L->Tail)||!N976nReadyShape(&L->Ready))return 0;
    for(ULONG I=0;I<RTL_NUMBER_OF(States);++I)
        if(States[I]->Valid>1||States[I]->Callback>N976nLifePoll||States[I]->HsiCurrent>1||States[I]->Reserved||!N976nHsiEvidenceShape(&States[I]->Hsi))return 0;
    const N976N_DEMO_DIAGNOSTIC *D=&L->FirstPrepareFailure;
    if(D->Valid&&(D->Version!=N976N_DIAGNOSTIC_VERSION||D->Bytes!=sizeof(*D)||D->Valid!=N976N_DIAGNOSTIC_VALID||
       D->Bucket<N976nDiagResource||D->Bucket>N976nDiagClaim||D->Condition<N976nWhyCount||
       D->Condition>N976nWhyAtomic||D->MappedCount>N976N_DEMO_MAP_COUNT||D->ReadOk>1||D->Reserved))return 0;
    return 1;
}
static VOID LifeState(N976N_DEMO_RUNTIME *R,N976N_LIFECYCLE_STATE *S)
{
    RtlZeroMemory(S,sizeof(*S));S->Prepare=R->Lifecycle.PrepareCount;S->Callback=R->Lifecycle.CurrentCallback;
    S->Stage=R->Stage;S->Status=R->Status;S->Id=R->Id;S->CleanupStatus=R->CleanupStatus;
    S->Claimed=R->Claimed;S->Mapped=R->Mapped;S->Quarantined=R->Quarantined;
    S->FunctionSaved=R->FunctionSaved;S->SenseAttempted=R->SenseAttempted;
    S->Command=R->CurrentCommand;S->HsiCurrent=R->HsiCurrent;S->Hsi=R->Last;S->Valid=1;
}
static VOID LifeFirst(N976N_DEMO_RUNTIME *R,N976N_LIFECYCLE_STATE *S)
{ if(!S->Valid)LifeState(R,S); }
static VOID LifeFailure(N976N_DEMO_RUNTIME *R)
{ if(!NT_SUCCESS((NTSTATUS)R->Status))LifeFirst(R,&R->Lifecycle.FirstFailure); }
VOID N976nDemoCallback(N976N_DEMO_RUNTIME *R,ULONG Callback)
{
    if(!R)return;
    R->Lifecycle.CurrentCallback=Callback;LifeInc(&R->Lifecycle.Sequence);
    if(Callback==N976nLifeD0Entry)LifeInc(&R->Lifecycle.D0EntryCount);
    if(Callback==N976nLifeD0Exit)LifeInc(&R->Lifecycle.D0ExitCount);
    if(Callback==N976nLifeReleaseHardware)LifeFirst(R,&R->Lifecycle.FirstRelease);
    if(Callback==N976nLifeStartFailure||Callback==N976nLifePollFailure||Callback==N976nLifeInputBusy)LifeFailure(R);
}
static int LifeSame(const N976N_DEMO_LIFECYCLE *L,const N976N_TOUCH_HANDOFF *H,ULONGLONG Address)
{ return L->NvsAddress==Address&&L->BootCounter==H->BootCounter&&L->CounterHz==H->CounterHz&&L->HandoffCrc==H->Crc32; }
static VOID LifeBind(N976N_DEMO_RUNTIME *R,ULONGLONG Address)
{
    N976N_TOUCH_HANDOFF *H=&R->Handoff;N976N_DEMO_LIFECYCLE *L=&R->Lifecycle,Stored;
    WDFKEY K;UNICODE_STRING Name;ULONG Bytes=0,Type=0;NTSTATUS S;
    /* These are already copied stable NVS bytes, with the existing page guard.
     * Identity validation is pure memory and does not accept RETIRED as READY. */
    if(H->Magic!=N976N_TOUCH_HANDOFF_MAGIC||H->Version!=N976N_TOUCH_HANDOFF_VERSION||
       H->Bytes!=sizeof(*H)||H->ImmutableBytes!=offsetof(N976N_TOUCH_HANDOFF,ClaimState)||
       !H->BootCounter||!H->CounterHz||H->Profile||H->ProducerStage!=N976N_TOUCH_HANDOFF_RELEASED||
       H->Guard!=N976N_TOUCH_HANDOFF_GUARD||H->Crc32!=N976nDemoCrc(H))return;
    if(L->IdentityValid&&LifeSame(L,H,Address)){
        L->Origin=N976nLifeOriginContext;
        R->LifeCanPublish=L->RegistryState!=N976nLifeRegistryMalformed&&L->RegistryState!=N976nLifeRegistryUnavailable;
        return;
    }
    if(L->IdentityValid){LifeInit(L);L->PrepareCount=1;L->CurrentCallback=N976nLifePrepare;}
    L->NvsAddress=Address;L->BootCounter=H->BootCounter;L->CounterHz=H->CounterHz;
    L->HandoffCrc=H->Crc32;L->IdentityValid=1;
    S=WdfDeviceOpenRegistryKey(R->Device,PLUGPLAY_REGKEY_DEVICE,KEY_QUERY_VALUE,WDF_NO_OBJECT_ATTRIBUTES,&K);
    if(!NT_SUCCESS(S)){L->RegistryState=N976nLifeRegistryUnavailable;return;}
    RtlInitUnicodeString(&Name,N976N_LIFECYCLE_VALUE);RtlZeroMemory(&Stored,sizeof(Stored));
    S=WdfRegistryQueryValue(K,&Name,sizeof(Stored),&Stored,&Bytes,&Type);WdfRegistryClose(K);
    if(!NT_SUCCESS(S)){L->RegistryState=S==STATUS_OBJECT_NAME_NOT_FOUND?N976nLifeRegistryNone:N976nLifeRegistryUnavailable;R->LifeCanPublish=S==STATUS_OBJECT_NAME_NOT_FOUND;return;}
    if(Type!=REG_BINARY||Bytes!=sizeof(Stored)||!LifeShape(&Stored)){L->RegistryState=N976nLifeRegistryMalformed;return;}
    if(!LifeSame(&Stored,H,Address)){L->RegistryState=N976nLifeRegistryOtherBoot;R->LifeCanPublish=1;return;}
    /* A new context may have made bounded unbound Prepare attempts first. */
    ULONG Pending=L->PrepareCount;
    *L=Stored;L->Origin=N976nLifeOriginRegistry;L->RegistryState=N976nLifeRegistryRestored;
    if(Pending>0xFFFFFFFFU-L->PrepareCount)L->PrepareCount=0xFFFFFFFFU;else L->PrepareCount+=Pending;
    L->CurrentCallback=N976nLifePrepare;LifeInc(&L->Sequence);R->LifeCanPublish=1;
}
static VOID LifePrepareResult(N976N_DEMO_RUNTIME *R,NTSTATUS S)
{
    if(NT_SUCCESS(S)){LifeInc(&R->Lifecycle.PrepareSuccessCount);LifeInc(&R->Lifecycle.ClaimCount);}
    else if(!R->Lifecycle.FirstPrepareFailure.Valid&&R->Diagnostic.Valid){
        R->Lifecycle.FirstPrepareFailure=R->Diagnostic;R->Lifecycle.FirstPrepareNumber=R->Lifecycle.PrepareCount;
    }
    LifeFailure(R);
}
static NTSTATUS LifeStartResult(N976N_DEMO_RUNTIME *R,NTSTATUS S)
{
    N976N_LIFECYCLE_STATE State;LifeState(R,&State);State.Status=(ULONG)S;
    if(!R->Lifecycle.FirstStart.Valid){R->Lifecycle.FirstStart=State;R->Lifecycle.FirstStartup=R->Startup;}
    if(!NT_SUCCESS(S)){
        if(!R->Lifecycle.FirstStartFailure.Valid){R->Lifecycle.FirstStartFailure=State;R->Lifecycle.FirstStartupFailure=R->Startup;}
        if(!R->Lifecycle.FirstFailure.Valid)R->Lifecycle.FirstFailure=State;
    }
    return S;
}
static int ReadMap(void *C,N976N_U32 M,N976N_U32 O,N976N_U32 *V)
{
    N976N_DEMO_RUNTIME *R=C;
    if(!R||!V||M>=N976N_DEMO_MAP_COUNT||M==N976nMapHandoff||!R->Map[M]||
       R->Bytes[M]<4||(O&3)||O>R->Bytes[M]-4)return 0;
    if(M==N976nMapAlive&&O!=0x20&&O!=0x24&&O!=0x28&&O!=0x904)return 0;
    *V=READ_REGISTER_ULONG((PULONG)(R->Map[M]+O));return 1;
}
static int ReadHsi(void *C,N976N_U32 O,N976N_U32 *V)
{ return ReadMap(C,N976nMapHsi,O,V); }
static int WriteHsi(void *C,N976N_U32 O,N976N_U32 V)
{
    N976N_DEMO_RUNTIME *R=C;
    /* Exact backend write surface. No reset/timebase/config/GPIO writes. */
    if(!R||!R->Map[0]||!R->Claimed||R->Quarantined||
       (O!=0&&O!=4&&O!=0x20&&O!=0x24&&O!=0x34&&O!=0x44&&O!=0x70)||
       (O==0&&(V&0x80000000U)))return 0;
    WRITE_REGISTER_ULONG((PULONG)(R->Map[0]+O),V);return 1;
}
static N976N_U64 NowUs(void *C) { UNREFERENCED_PARAMETER(C); return KeQueryInterruptTime()/10; }
/* HSI deadline uses the precise interrupt clock. Startup's6.4s admission
 * policy intentionally keeps NowUs above. No coarse fallback is permitted. */
static N976N_U64 HsiNowUs(void *C)
{ ULONGLONG Qpc;UNREFERENCED_PARAMETER(C);return KeQueryInterruptTimePrecise(&Qpc)/10; }
static int StillOwned(void *C,N976N_U64 G)
{
    N976N_DEMO_RUNTIME *R=C;
    return R && R->Claimed && !R->Quarantined && R->Mapped &&
        G==R->Handoff.BootCounter && Owner==R &&
        R->Map[5] && ((N976N_TOUCH_HANDOFF*)R->Map[5])->ClaimState==N976N_TOUCH_CLAIM_OWNED;
}
static int Cancelled(void *C) { return ((N976N_DEMO_RUNTIME*)C)->StopRequested!=0; }
static NTSTATUS Fail(N976N_DEMO_RUNTIME *R,ULONG Stage,NTSTATUS Status)
{
    R->Stage=Stage;R->Status=(ULONG)Status;
    if(Stage==11||Stage==12||Stage==19)LifePrepareResult(R,Status);
    else if(Stage>=21&&Stage<=29)return LifeStartResult(R,Status);
    else LifeFailure(R);
    return Status;
}
static VOID DelayMs(ULONG Ms)
{ LARGE_INTEGER I;I.QuadPart=-((LONGLONG)Ms*10000);(void)KeDelayExecutionThread(KernelMode,FALSE,&I); }
static VOID ReadyTransportFailure(N976N_DEMO_RUNTIME *R)
{
    N976N_EVENT_READY *E=&R->Lifecycle.Ready;
    if(R->Stage!=29||!E->LastValid||(E->LastRaw&1))return;
    if(!E->FirstErrorValid){E->FirstErrorValid=1;E->FirstErrorRaw=E->LastRaw;}
    E->LastErrorValid=1;E->LastErrorRaw=E->LastRaw;
}
/* Successful sample and Ready=false means GPIO HIGH, not an empty event or a
 * successful transport. No state/status or HID barrier is cleared on HIGH. */
NTSTATUS N976nDemoEventReady(N976N_DEMO_RUNTIME *R,BOOLEAN *Ready)
{
    NTSTATUS S=STATUS_DEVICE_NOT_READY;N976N_U32 V=0;
    if(!R||!Ready)return STATUS_INVALID_PARAMETER;
    *Ready=FALSE;R->CurrentCommand=0x60;R->HsiCurrent=0;
    if(R->StopRequested||R->Stage!=29)return STATUS_CANCELLED;
    if(R->FirstRead.GapPending||R->Lifecycle.Recovery.GapPending||R->Lifecycle.Tail.GapPending)return STATUS_DEVICE_BUSY;
    N976N_EVENT_READY *E=&R->Lifecycle.Ready;
    N976nDemoCallback(R,N976nLifePoll);LifeInc(&E->Checks);E->LastValid=0;E->LastRaw=0;
    if(!StillOwned(R,R->Handoff.BootCounter)||
       !N976nDemoFresh(&R->Handoff,R,ReadMap,&R->Lease)){R->Quarantined=1;goto Reject;}
    if(Cancelled(R)){S=STATUS_CANCELLED;goto Reject;}
    if(!StillOwned(R,R->Handoff.BootCounter)){R->Quarantined=1;goto Reject;}
    if(!ReadMap(R,N976nMapAlive,0x24,&V)||V==0xFFFFFFFFU){R->Quarantined=1;goto Reject;}
    E->LastValid=1;E->LastRaw=V;
    if(Cancelled(R)){S=STATUS_CANCELLED;goto Reject;}
    if(!StillOwned(R,R->Handoff.BootCounter)){R->Quarantined=1;goto Reject;}
    if(V&1)LifeInc(&E->HighSkip);
    else{LifeInc(&E->Low);*Ready=TRUE;}
    return STATUS_SUCCESS;
Reject:
    LifeInc(&E->Rejected);R->CurrentCommand=0x60;R->HsiCurrent=0;
    return Fail(R,90,S);
}
static NTSTATUS RunCommand(N976N_DEMO_RUNTIME *R,UCHAR C,int Receive,UCHAR *Data,ULONG N,BOOLEAN FirstEvent)
{
    N976N_HSI_STATUS S;
    R->CurrentCommand=C;R->HsiCurrent=0;
    if(!StillOwned(R,R->Handoff.BootCounter)||
       !N976nDemoFresh(&R->Handoff,R,ReadMap,&R->Lease)) {
        R->Quarantined=1;if(C==0x60||C==0x61)ReadyTransportFailure(R);return STATUS_DEVICE_NOT_READY;
    }
    S=FirstEvent ? N976nHsiReadFirstEvent(&R->Io,&R->Lease,Data,&R->Last) :
        N976nHsiCommand(&R->Io,&R->Lease,C,Receive,Data,N,&R->Last);
    R->HsiCurrent=1;
    if(R->Last.Quarantined||!R->Last.Retired)R->Quarantined=1;
    if(S!=N976nHsiOk){if(C==0x60||C==0x61)ReadyTransportFailure(R);return S==N976nHsiTimeout?STATUS_IO_TIMEOUT:STATUS_DEVICE_HARDWARE_ERROR;}
    return STATUS_SUCCESS;
}
static NTSTATUS Command(N976N_DEMO_RUNTIME *R,UCHAR C,int Receive,UCHAR *Data,ULONG N)
{
    return RunCommand(R,C,Receive,Data,N,FALSE);
}
NTSTATUS N976nDemoPrepare(N976N_DEMO_RUNTIME *R,WDFDEVICE Device,WDFCMRESLIST Raw,WDFCMRESLIST Translated)
{
    ULONG I,J;NTSTATUS S=STATUS_DEVICE_CONFIGURATION_ERROR;
    N976N_TOUCH_HANDOFF Again;
    N976N_DEMO_DIAGNOSTIC *D;
    PHYSICAL_ADDRESS Pa;
    ULONGLONG PageGuard,Claim,NvsAddress=0;
    if(!R||!Raw||!Translated)return STATUS_INVALID_PARAMETER;
    /* WDF device context is zero-initialized. Preserve only its diagnostic
     * lifetime; all active transport state is still reset exactly as before. */
    if(R->Lifecycle.Version!=N976N_LIFECYCLE_VERSION||R->Lifecycle.Bytes!=sizeof(R->Lifecycle)||R->Lifecycle.Valid!=N976N_LIFECYCLE_VALID)
        LifeInit(&R->Lifecycle);
    RtlZeroMemory(R,offsetof(N976N_DEMO_RUNTIME,Lifecycle));R->Device=Device;R->Stage=10;D=&R->Diagnostic;
    LifeInc(&R->Lifecycle.PrepareCount);N976nDemoCallback(R,N976nLifePrepare);
    D->Version=N976N_DIAGNOSTIC_VERSION;D->Bytes=sizeof(*D);
    D->RawCount=WdfCmResourceListGetCount(Raw);D->TransCount=WdfCmResourceListGetCount(Translated);
    if(D->RawCount!=N976N_DEMO_MAP_COUNT||D->TransCount!=N976N_DEMO_MAP_COUNT){
        N976nDemoReject(D,N976nDiagResource,N976nWhyCount,D->RawCount!=N976N_DEMO_MAP_COUNT?0:1,0,N976N_DEMO_MAP_COUNT,D->RawCount!=N976N_DEMO_MAP_COUNT?D->RawCount:D->TransCount,0,1);
        return Fail(R,11,S);
    }
    if(InterlockedCompareExchangePointer(&Owner,R,NULL)!=NULL){
        N976nDemoReject(D,N976nDiagClaim,N976nWhyOwner,0,0,0,1,0,1);
        return Fail(R,11,STATUS_DEVICE_BUSY);
    }
#define REFUSE(C,W,E,A,M) do{if(!(C)){N976nDemoReject(D,N976nDiagResource,W,I,0,E,A,M,1);goto Error;}}while(0)
    for(I=0;I<N976N_DEMO_MAP_COUNT;++I){
        PCM_PARTIAL_RESOURCE_DESCRIPTOR A=WdfCmResourceListGetDescriptor(Raw,I);
        PCM_PARTIAL_RESOURCE_DESCRIPTOR B=WdfCmResourceListGetDescriptor(Translated,I);
        ULONGLONG Base;ULONG Flags,Protection;
        UCHAR ExpectedShare=(I==N976nMapTop)?CmResourceShareShared:CmResourceShareDeviceExclusive;
        /* Capture only the descriptors already returned by WDF. Non-memory
         * unions are not interpreted as an address/length. */
        D->RawType=A?A->Type:0;D->RawShare=A?A->ShareDisposition:0;D->RawFlags=A?A->Flags:0;
        D->RawStart=A&&A->Type==CmResourceTypeMemory?(ULONGLONG)A->u.Memory.Start.QuadPart:0;
        D->RawLength=A&&A->Type==CmResourceTypeMemory?A->u.Memory.Length:0;
        D->TransType=B?B->Type:0;D->TransShare=B?B->ShareDisposition:0;D->TransFlags=B?B->Flags:0;
        D->TransStart=B&&B->Type==CmResourceTypeMemory?(ULONGLONG)B->u.Memory.Start.QuadPart:0;
        D->TransLength=B&&B->Type==CmResourceTypeMemory?B->u.Memory.Length:0;
        REFUSE(A&&B,N976nWhyDescriptor,3,(A?1U:0U)|(B?2U:0U),3);
        REFUSE(A->Type==CmResourceTypeMemory,N976nWhyType,CmResourceTypeMemory,A->Type,0xFF);
        REFUSE(B->Type==CmResourceTypeMemory,N976nWhyType,CmResourceTypeMemory,B->Type,0xFF);
        REFUSE(A->ShareDisposition==ExpectedShare,N976nWhyShare,ExpectedShare,A->ShareDisposition,0xFF);
        REFUSE(B->ShareDisposition==ExpectedShare,N976nWhyShare,ExpectedShare,B->ShareDisposition,0xFF);
        REFUSE(A->Flags==B->Flags,N976nWhyFlagsPair,A->Flags,B->Flags,0xFFFF);
        REFUSE(!(A->Flags&~CM_RESOURCE_MEMORY_READ_ONLY),N976nWhyFlagsMask,0,A->Flags,(unsigned short)~CM_RESOURCE_MEMORY_READ_ONLY);
        REFUSE(A->u.Memory.Start.QuadPart==B->u.Memory.Start.QuadPart,N976nWhyBasePair,(ULONGLONG)A->u.Memory.Start.QuadPart,(ULONGLONG)B->u.Memory.Start.QuadPart,~0ULL);
        REFUSE(A->u.Memory.Length==B->u.Memory.Length,N976nWhyLengthPair,A->u.Memory.Length,B->u.Memory.Length,0xFFFFFFFFU);
        REFUSE(A->u.Memory.Start.QuadPart>0,N976nWhyPositiveBase,1,(ULONGLONG)A->u.Memory.Start.QuadPart,0);
        Base=(ULONGLONG)B->u.Memory.Start.QuadPart;Flags=B->Flags;
        if(I!=N976nMapHandoff){REFUSE(Base==Bases[I],N976nWhyBase,Bases[I],Base,~0ULL);REFUSE(B->u.Memory.Length==Sizes[I],N976nWhyLength,Sizes[I],B->u.Memory.Length,0xFFFFFFFFU);}
        else{
            REFUSE(!(Base&4095),N976nWhyAlignment,0,Base,4095);
            REFUSE(Base>=N976N_TOUCH_HANDOFF_LOW,N976nWhyRange,N976N_TOUCH_HANDOFF_LOW,Base,0);
            REFUSE(Base<=N976N_TOUCH_HANDOFF_END-4096,N976nWhyRange,N976N_TOUCH_HANDOFF_END-4096,Base,~0ULL);
            REFUSE(B->u.Memory.Length==4096,N976nWhyLength,4096,B->u.Memory.Length,0xFFFFFFFFU);
        }
        if(I==0||I==5)REFUSE(Flags==CM_RESOURCE_MEMORY_READ_WRITE,N976nWhyWritable,CM_RESOURCE_MEMORY_READ_WRITE,Flags,0xFFFF);
        if(I==N976nMapAlive)REFUSE(Flags==CM_RESOURCE_MEMORY_READ_ONLY,N976nWhyFlagsMask,CM_RESOURCE_MEMORY_READ_ONLY,Flags,0xFFFF);
        if(I==N976nMapTop)REFUSE(N976nClockSharePreparePair(A,B),N976nWhyShare,CmResourceShareShared,B->ShareDisposition,0xFF);
        if(I==N976nMapHandoff)NvsAddress=Base;
        Pa=B->u.Memory.Start;R->Bytes[I]=B->u.Memory.Length;
        Protection=(I==0||I==5)?PAGE_READWRITE:PAGE_READONLY;
        if(I!=N976nMapHandoff)Protection|=PAGE_NOCACHE;
        R->Map[I]=MmMapIoSpaceEx(Pa,R->Bytes[I],Protection);
        if(!R->Map[I]){S=STATUS_INSUFFICIENT_RESOURCES;N976nDemoReject(D,N976nDiagMap,N976nWhyMap,I,Protection,1,0,0,1);goto Error;}
        D->MappedCount=I+1;
    }
#undef REFUSE
    R->Mapped=1;
    RtlCopyMemory(&R->Handoff,R->Map[5],sizeof(R->Handoff));KeMemoryBarrier();
    RtlCopyMemory(&Again,R->Map[5],sizeof(Again));
    if(RtlCompareMemory(&R->Handoff,&Again,sizeof(Again))!=sizeof(Again)){
        /* Both operands are the original bounded copies, never a third NVS read. */
        const UCHAR *A=(const UCHAR*)&R->Handoff,*B=(const UCHAR*)&Again;
        for(I=0;I<sizeof(Again);++I)if(A[I]!=B[I])break;
        N976nDemoReject(D,N976nDiagNvs,N976nWhySnapshot,5,I,A[I],B[I],0xFF,1);goto Error;
    }
    PageGuard=*(volatile ULONGLONG*)(R->Map[5]+4096-8);
    if(PageGuard!=N976N_TOUCH_HANDOFF_GUARD){N976nDemoReject(D,N976nDiagNvs,N976nWhyPageGuard,5,4096-8,N976N_TOUCH_HANDOFF_GUARD,PageGuard,~0ULL,1);goto Error;}
    LifeBind(R,NvsAddress);
    if(R->Handoff.ClaimState!=N976N_TOUCH_CLAIM_READY){N976nDemoReject(D,N976nDiagNvs,N976nWhyReady,5,(unsigned)offsetof(N976N_TOUCH_HANDOFF,ClaimState),N976N_TOUCH_CLAIM_READY,R->Handoff.ClaimState,~0ULL,1);goto Error;}
    if(!N976nDemoValidateHandoffEx(&R->Handoff,D)||!N976nDemoFreshEx(&R->Handoff,R,ReadMap,&R->Lease,D))goto Error;
    Claim=(ULONGLONG)InterlockedCompareExchange64((volatile LONG64*)&((N976N_TOUCH_HANDOFF*)R->Map[5])->ClaimState,N976N_TOUCH_CLAIM_OWNED,N976N_TOUCH_CLAIM_READY);
    if(Claim!=N976N_TOUCH_CLAIM_READY){S=STATUS_DEVICE_BUSY;N976nDemoReject(D,N976nDiagClaim,N976nWhyAtomic,5,(unsigned)offsetof(N976N_TOUCH_HANDOFF,ClaimState),N976N_TOUCH_CLAIM_READY,Claim,~0ULL,1);goto Error;}
    R->Claimed=1;R->Handoff.ClaimState=N976N_TOUCH_CLAIM_OWNED;
    R->Io.Context=R;R->Io.Read32=ReadHsi;R->Io.Write32=WriteHsi;
    R->Io.NowUs=HsiNowUs;R->Io.StillOwned=StillOwned;R->Io.Cancelled=Cancelled;
    return Fail(R,19,STATUS_SUCCESS);
Error:
    for(J=0;J<N976N_DEMO_MAP_COUNT;++J)if(R->Map[J]){MmUnmapIoSpace(R->Map[J],R->Bytes[J]);R->Map[J]=NULL;}
    R->Mapped=0;InterlockedCompareExchangePointer(&Owner,NULL,R);return Fail(R,12,S);
}
static VOID StartupPacket(N976N_STARTUP_PACKET *P,const UCHAR D[16],ULONG Ordinal,ULONG Bytes)
{
    N976N_Y771_EVENT Event;
    RtlZeroMemory(P,sizeof(*P));P->Valid=1;P->Ordinal=Ordinal;P->Bytes=Bytes;
    RtlCopyMemory(P->Raw,D,16);P->Decoded=N976nY771Invalid;
    if(Bytes!=16)return;
    P->Class=D[0]&3;P->Subtype=(D[0]>>2)&15;P->Id=D[1];P->Data=D[2];P->Remaining=D[7]&31;
    P->Decoded=N976nY771DecodeEvent(D,16,&Event);
}
/* Samsung N976N y771_d sec_ts.c read_event(): normal status and gesture
 * notifications are not corrupt FIFO content. Startup retires them without
 * emitting HID. Running-input watchdog/error policy remains unchanged.
 * EXP2 observes exactly PRE/POST; only the owned initialization issues clear. */
static VOID StartupObserve(N976N_STARTUP_EVIDENCE *E,ULONG Mask)
{
    if(!Mask)return;
    ++E->ObservedPackets;
    if(Mask&N976nObserveRemaining31)++E->Remaining31Count;
    if(Mask&N976nObserveUnknownVendor){
        ++E->UnknownVendorCount;
        if(!E->FirstUnknownVendor.Valid)E->FirstUnknownVendor=E->Last;
    }
    if(!E->FirstObserved.Valid){E->FirstObserved=E->Last;E->FirstObservedMask=Mask;}
}
static ULONG StartupClassify(N976N_STARTUP_EVIDENCE *E,int Post)
{
    N976N_STARTUP_PACKET *P=&E->Last;
    ULONG Observe=0,Reason=N976nStartupNone;
    if(P->Decoded==N976nY771ErrorStatus){++E->Error;return N976nStartupChipError;}
    if(P->Decoded==N976nY771Invalid){++E->Malformed;return N976nStartupMalformed;}
    /* Scalar 16-byte reads do not use remaining as an allocation/read count.
     * EXP1 records the former gate, never treats 31 as proof of queue depth. */
    if(P->Remaining==31)Observe|=N976nObserveRemaining31;
    if(P->Decoded==N976nY771Coordinate){++E->Coordinate;goto Classified;}
    if(P->Class==1){
        /* Samsung wait_for_ready accepts INFO/VENDOR ACK by subtype/id only.
         * Repeated ACKs remain bounded here; running boot events still fail.
         * Application/function state is checked around SenseOn/Clear. */
        if((P->Subtype==2||P->Subtype==7)&&P->Id==0){
            ++E->Boot;if(Post)return N976nStartupPostBoot;goto Classified;
        }
        if(P->Subtype==2&&P->Id==1){++E->Status;goto Classified;}
        if(P->Subtype==7){
            if(N976nStartupKnownVendorId(P->Id)){++E->Status;goto Classified;}
            ++E->Unknown;Observe|=N976nObserveUnknownVendor;goto Classified;
        }
    }
    if(P->Decoded==N976nY771Gesture&&
       (P->Subtype==0||P->Subtype==3||P->Subtype==4||(P->Subtype==1&&P->Id<=1))){
        ++E->Gesture;goto Classified;
    }
    ++E->Unknown;Reason=N976nStartupUnknown;
Classified:
    StartupObserve(E,Observe);return Reason;
}
static NTSTATUS StartupFail(N976N_DEMO_RUNTIME *R,ULONG Reason,NTSTATUS Status,int Packet)
{
    R->Startup.Phase=N976nStartupFailed;R->Startup.Reason=Reason;
    if(Packet)R->Startup.Rejected=R->Startup.Last;
    return Fail(R,25,Status);
}
/* One scalar observation at each side of owned initialization. Coordinates are
 * deliberately consumed as diagnostics, never injected into HID. Clear success
 * proves TX retirement, not that the queue remains empty after sensing starts. */
static int StartupBudget(N976N_DEMO_RUNTIME *R,ULONGLONG Start)
{
    R->Startup.ElapsedUs=NowUs(R)-Start;
    return R->Startup.ElapsedUs<N976N_STARTUP_DEADLINE_US;
}
static NTSTATUS StartupSnapshot(N976N_DEMO_RUNTIME *R,ULONGLONG Start,int Post)
{
    N976N_STARTUP_EVIDENCE *E=&R->Startup;UCHAR D[16]={0};NTSTATUS S;ULONG Why;
    E->InitPhase=Post?N976nInitPost:N976nInitPre;
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    ++E->Reads;S=Command(R,0x60,1,D,16);E->TransferStatus=(ULONG)S;
    (void)StartupBudget(R,Start);
    StartupPacket(&E->Last,D,E->Reads,R->HsiCurrent?R->Last.RxBytes:0);
    if(!E->First.Valid)E->First=E->Last;
    if(!NT_SUCCESS(S))return StartupFail(R,N976nStartupTransfer,S,1);
    if(D[0])++E->NonEmpty;else ++E->Empty;
    /* Classification still runs before admitting further commands; no physical
     * ERROR/malformed packet is hidden by the observational vendor policy. */
    Why=D[0]?StartupClassify(E,Post):N976nStartupNone;
    if(Why){if(Why==N976nStartupPostBoot)R->Quarantined=1;return StartupFail(R,Why,STATUS_DEVICE_DATA_ERROR,1);}
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,1);
    if(R->StopRequested)return StartupFail(R,N976nStartupTransfer,STATUS_CANCELLED,1);
    return STATUS_SUCCESS;
}
static NTSTATUS StartupState(N976N_DEMO_RUNTIME *R,ULONGLONG Start,int Post)
{
    N976N_STARTUP_EVIDENCE *E=&R->Startup;UCHAR D[2]={0};NTSTATUS S;
    unsigned int *Checks=Post?&E->PostChecks:&E->PreChecks;
    unsigned int *AppStatus=Post?&E->AppStatus:&E->PreAppStatus,*AppValue=Post?&E->AppValue:&E->PreAppValue;
    unsigned int *FunctionStatus=Post?&E->FunctionStatus:&E->PreFunctionStatus,*FunctionValue=Post?&E->FunctionValue:&E->PreFunctionValue;
    E->InitPhase=Post?N976nInitPostState:N976nInitPreState;
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    *Checks|=1;S=Command(R,0x55,1,D,1);*AppStatus=(ULONG)S;*AppValue=D[0];(void)StartupBudget(R,Start);
    if(!NT_SUCCESS(S)||D[0]!=0x20){
        /* An unknown app grammar cannot authorize even cleanup function writes. */
        R->Quarantined=1;return StartupFail(R,N976nStartupAppState,NT_SUCCESS(S)?STATUS_DEVICE_NOT_READY:S,0);
    }
    *Checks|=2;
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    *Checks|=4;D[0]=D[1]=0;S=Command(R,0x30,1,D,2);
    (void)StartupBudget(R,Start);*FunctionStatus=(ULONG)S;*FunctionValue=(ULONG)D[0]|((ULONG)D[1]<<8);
    if(!NT_SUCCESS(S)||*FunctionValue!=R->FunctionEnabled)
        return StartupFail(R,N976nStartupFunctionState,NT_SUCCESS(S)?STATUS_DEVICE_HARDWARE_ERROR:S,0);
    *Checks|=8;
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    return STATUS_SUCCESS;
}
static NTSTATUS StartupWrite(N976N_DEMO_RUNTIME *R,ULONGLONG Start,int Clear)
{
    N976N_STARTUP_EVIDENCE *E=&R->Startup;NTSTATUS S;
    unsigned int *Attempted=Clear?&E->ClearAttempted:&E->SenseAttempted;
    unsigned int *Issued=Clear?&E->ClearIssued:&E->SenseIssued;
    unsigned int *Completed=Clear?&E->ClearCompleted:&E->SenseCompleted;
    unsigned int *Status=Clear?&E->ClearStatus:&E->SenseStatus;
    E->InitPhase=Clear?N976nInitClear:N976nInitSense;
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    *Attempted=1;if(!Clear)R->SenseAttempted=1;
    S=Command(R,Clear?0x62:0x10,0,NULL,0);*Status=(ULONG)S;(void)StartupBudget(R,Start);
    *Issued=R->HsiCurrent&&R->Last.MessagesIssued!=0;
    *Completed=NT_SUCCESS(S)&&R->HsiCurrent&&R->Last.MessagesIssued==1&&
        R->Last.TxBytes==1&&R->Last.RxBytes==0&&R->Last.Retired&&!R->Last.Quarantined;
    if(!NT_SUCCESS(S)||!*Completed)return StartupFail(R,Clear?N976nStartupClear:N976nStartupSense,NT_SUCCESS(S)?STATUS_DEVICE_HARDWARE_ERROR:S,0);
    if(!StartupBudget(R,Start))return StartupFail(R,N976nStartupDeadline,STATUS_IO_TIMEOUT,0);
    return STATUS_SUCCESS;
}
NTSTATUS N976nDemoStart(N976N_DEMO_RUNTIME *R)
{
    UCHAR D[16]={0};NTSTATUS S;ULONGLONG Start;
    if(!R)return STATUS_DEVICE_NOT_READY;
    LifeInc(&R->Lifecycle.StartCount);
    RtlZeroMemory(&R->Startup,sizeof(R->Startup));
    if(!R->Claimed||R->Quarantined)return LifeStartResult(R,STATUS_DEVICE_NOT_READY);
    R->Stage=20;R->Status=STATUS_SUCCESS;InterlockedExchange(&R->StopRequested,0);
    S=Command(R,0x52,1,D,3);
    if(!NT_SUCCESS(S))return Fail(R,21,S);
    R->Id=((ULONG)D[0]<<16)|((ULONG)D[1]<<8)|D[2];
    if(R->Id!=0xAC3771)return Fail(R,21,STATUS_DEVICE_HARDWARE_ERROR);
    /* Fresh firmware application state, not elapsed-time or cold boot guessing.
     * Firmware already consumed no sensing data and owns stable rails. */
    S=Command(R,0x55,1,D,1);
    if(!NT_SUCCESS(S)||D[0]!=0x20)return Fail(R,22,NT_SUCCESS(S)?STATUS_DEVICE_NOT_READY:S);
    S=Command(R,0x30,1,D,2);
    if(!NT_SUCCESS(S))return Fail(R,23,S);
    R->FunctionBefore=(ULONG)D[0]|((ULONG)D[1]<<8);
    if(R->FunctionBefore==0xFFFF)return Fail(R,23,STATUS_DEVICE_HARDWARE_ERROR);
    R->FunctionSaved=1;R->FunctionEnabled=R->FunctionBefore|0x61;
    if(R->FunctionEnabled!=R->FunctionBefore){
        D[0]=(UCHAR)R->FunctionEnabled;D[1]=(UCHAR)(R->FunctionEnabled>>8);
        R->FunctionChanged=1;S=Command(R,0x30,0,D,2);
        if(!NT_SUCCESS(S))return Fail(R,24,S);DelayMs(30);
    }
    S=Command(R,0x30,1,D,2);
    if(!NT_SUCCESS(S)||((ULONG)D[0]|((ULONG)D[1]<<8))!=R->FunctionEnabled)
        return Fail(R,24,NT_SUCCESS(S)?STATUS_DEVICE_HARDWARE_ERROR:S);
    R->Startup.Phase=N976nStartupObserving;Start=NowUs(R);
    S=StartupSnapshot(R,Start,0);if(!NT_SUCCESS(S))return S;
    S=StartupState(R,Start,0);if(!NT_SUCCESS(S))return S;
    /* Pinned 9820 Device.c startup: SenseOn then ClearEventStack, each a
     * standalone command byte. N976N y771_d defines the same 10/62 commands. */
    S=StartupWrite(R,Start,0);if(!NT_SUCCESS(S))return S;
    S=StartupWrite(R,Start,1);if(!NT_SUCCESS(S))return S;
    S=StartupState(R,Start,1);if(!NT_SUCCESS(S))return S;
    S=StartupSnapshot(R,Start,1);if(!NT_SUCCESS(S))return S;
    R->Startup.Phase=N976nStartupComplete;R->Startup.InitPhase=N976nInitComplete;
    /* A proven new sensing session has its own input gap. Preserve evidence
     * and totals, but never attribute its first valid input to a prior D0. */
    R->FirstRead.Streak=R->FirstRead.GapPending=R->FirstRead.AwaitingFresh=0;
    return Fail(R,29,STATUS_SUCCESS);
}
/* A lost first packet cannot supply the tail count. Clear the sensor queue
 * exactly once, after the original transfer retired. Never replay READ_ONE. */
static NTSTATUS RecoverFirstEvent(N976N_DEMO_RUNTIME *R, NTSTATUS status)
{
    N976N_FIRST_RECOVERY *first=&R->FirstRead;
    NTSTATUS cleared;
    R->Status=(ULONG)status;
    LifeInc(&first->Faults);
    LifeState(R,&first->LastFailure);
    if (!R->HsiCurrent || R->Quarantined ||
        !N976nTailCanDrop(&R->Last,(ULONG)status,16) ||
        !R->Last.DiscardedBytes || R->Last.Wait.Requested!=16)
        return Fail(R,90,status);
    if (R->StopRequested) return STATUS_CANCELLED; /* D0Exit owns teardown. */
    if (++first->Streak >= 3)
        return Fail(R,90,status);
    /* CLEAR performs the existing ownership, freshness, completion and ACK checks. */
    cleared=N976nDemoClearEvents(R);
    if (!NT_SUCCESS(cleared)) return cleared;
    if (R->StopRequested) return STATUS_CANCELLED;
    if (!StillOwned(R,R->Handoff.BootCounter) ||
        !N976nDemoFresh(&R->Handoff,R,ReadMap,&R->Lease) ||
        !StillOwned(R,R->Handoff.BootCounter)){
        R->Quarantined=1;
        return Fail(R,90,STATUS_DEVICE_NOT_READY);
    }
    if (R->StopRequested) return STATUS_CANCELLED;
    LifeInc(&first->Clears);
    first->GapPending=1;
    first->AwaitingFresh=1;
    return status;
}
NTSTATUS N976nDemoReadEvent(N976N_DEMO_RUNTIME *R,UCHAR Event[16])
{
    NTSTATUS S=STATUS_SUCCESS;N976N_EVENT_RECOVERY *D;
    if(!R||!Event||R->StopRequested||R->Stage!=29)return STATUS_CANCELLED;
    /* Producer must retire the input gap before another logical read. */
    if(R->FirstRead.GapPending||R->Lifecycle.Recovery.GapPending||R->Lifecycle.Tail.GapPending)return STATUS_DEVICE_BUSY;
    N976nDemoCallback(R,N976nLifePoll);D=&R->Lifecycle.Recovery;
    LifeInc(&R->Lifecycle.Service.ReadOne);
    R->Lifecycle.Service.LastRemaining=R->Lifecycle.Service.LastCount=R->Lifecycle.Service.LastBytes=0;
    LifeInc(&D->Requests);RtlZeroMemory(&R->EventFirst,sizeof(R->EventFirst));
    for(ULONG Attempt=1;Attempt<=3;++Attempt){
        if(Attempt>1){
            LARGE_INTEGER Delay;Delay.QuadPart=-10000; /* Samsung1ms, checked. */
            R->HsiCurrent=0;
            if(R->StopRequested){S=STATUS_CANCELLED;goto Aborted;}
            if(!StillOwned(R,R->Lease.Generation)){S=STATUS_DEVICE_NOT_READY;goto Aborted;}
            S=KeDelayExecutionThread(KernelMode,FALSE,&Delay);
            if(!NT_SUCCESS(S))goto Aborted;
            if(R->StopRequested){S=STATUS_CANCELLED;goto Aborted;}
            if(!StillOwned(R,R->Lease.Generation)){S=STATUS_DEVICE_NOT_READY;goto Aborted;}
            LifeInc(&D->Retries);
        }
        /* Command rechecks exact live ownership/clock/pad/controller state. */
        S=RunCommand(R,0x60,1,Event,16,TRUE);LifeInc(&R->Polls);
        if(Attempt>1){D->Attempt=Attempt;LifeState(R,&D->LastAttempt);D->LastAttempt.Status=(ULONG)S;}
        if(NT_SUCCESS(S)){
            if(Attempt>1){LifeInc(&D->Recovered);D->Outcome=N976nRecoveryRecovered;D->GapPending=1;}
            return S;
        }
        if(S==STATUS_IO_TIMEOUT && R->HsiCurrent && R->Last.RxBytes && R->Last.RxBytes<16){
            if(R->EventFirst.Valid)D->Outcome=N976nRecoveryAborted;
            return RecoverFirstEvent(R,S);
        }
        if(!R->HsiCurrent||!N976nEventNodev(&R->Last))goto Aborted;
        LifeInc(&D->Faults);D->Attempt=Attempt;D->Outcome=N976nRecoveryNone;
        LifeState(R,&D->LastAttempt);D->LastAttempt.Stage=90;D->LastAttempt.Status=(ULONG)S;
        if(!R->EventFirst.Valid)R->EventFirst=D->LastAttempt;
        if(!D->FirstTransient.Valid)D->FirstTransient=D->LastAttempt;
        if(Attempt==3){LifeInc(&D->Exhausted);D->Outcome=N976nRecoveryExhausted;break;}
    }
    goto Failed;
Aborted:
    if(R->EventFirst.Valid){
        D->Outcome=N976nRecoveryAborted;LifeState(R,&D->LastAttempt);
        D->LastAttempt.Status=(ULONG)S;D->LastAttempt.Stage=90;
    }
Failed:
    /* Keep first fault of this logical request; LastAttempt retains the later
     * cancellation/freshness/transport result, never overwriting first cause. */
    if(R->EventFirst.Valid&&!R->Lifecycle.FirstFailure.Valid)R->Lifecycle.FirstFailure=R->EventFirst;
    return Fail(R,90,S);
}
NTSTATUS N976nDemoReadTail(N976N_DEMO_RUNTIME *R,ULONG Remaining)
{
    NTSTATUS S;N976N_TAIL_RECOVERY *T;N976N_TAIL_FAULT *F;
    if(!R||R->StopRequested||R->Stage!=29)return STATUS_CANCELLED;
    if(Remaining<1||Remaining>30||R->FirstRead.GapPending||R->Lifecycle.Recovery.GapPending||R->Lifecycle.Tail.GapPending)return STATUS_INVALID_PARAMETER;
    LifeInc(&R->Lifecycle.Service.ReadAll);
    R->Lifecycle.Service.LastRemaining=Remaining;R->Lifecycle.Service.LastCount=Remaining+1;
    R->Lifecycle.Service.LastBytes=Remaining*16;
    /* Never replay READ_ALL: it may have consumed sensor events even at RX0. */
    S=Command(R,0x61,1,((UCHAR*)R->EventBatch)+16,Remaining*16);LifeInc(&R->Polls);
    if(NT_SUCCESS(S))return S;
    R->Status=(ULONG)S;T=&R->Lifecycle.Tail;LifeInc(&T->Faults);
    F=&T->LastFailure;RtlZeroMemory(F,sizeof(*F));
    F->Ordinal=R->Lifecycle.Service.ReadOne;F->Remaining=Remaining;F->Requested=Remaining*16;
    RtlCopyMemory(F->FirstPacket,R->EventBatch[0],16);LifeState(R,&F->State);
    T->Decision=N976nTailTransport;
    if(R->HsiCurrent && !R->Quarantined && N976nTailCanDrop(&R->Last,(ULONG)S,Remaining*16)){
        /* Existing admission reads only. No speculative state relaxation. */
        T->Decision=N976nTailCancelled;
        if(!R->StopRequested){
            T->Decision=N976nTailOwner;
            if(StillOwned(R,R->Handoff.BootCounter)){
                T->Decision=N976nTailFresh;
                if(N976nDemoFresh(&R->Handoff,R,ReadMap,&R->Lease)){
                    T->Decision=N976nTailCancelled;
                    if(!R->StopRequested){
                        T->Decision=N976nTailOwner;
                        if(StillOwned(R,R->Handoff.BootCounter)){
                            if(T->Streak<3)++T->Streak;
                            T->Decision=T->Streak==3?N976nTailLimit:N976nTailSafe;
                            if(T->Decision==N976nTailSafe){
                                LifeInc(&T->Deferred);T->Disposition=N976nTailDeferred;
                                T->GapPending=1;T->AwaitingFresh=1;
                                if(!T->FirstDeferred.State.Valid)T->FirstDeferred=*F;
                                return S; /* Failed transport remains failed. */
                            }
                        }
                    }
                }
            }
        }
    }
    if(T->Decision==N976nTailOwner||T->Decision==N976nTailFresh)R->Quarantined=1;
    T->Disposition=N976nTailTerminal;T->GapPending=0;LifeInc(&T->Fatal);F->State.Stage=90;
    return Fail(R,90,S);
}
VOID N976nDemoValidatedBatch(N976N_DEMO_RUNTIME *R)
{
    N976N_TAIL_RECOVERY *T=&R->Lifecycle.Tail;
    /* Only the producer calls this after complete nonempty batch validation.
     * Empty, overflow-clear and60-recovery paths never reach this boundary. */
    if(R->StopRequested||R->Stage!=29||T->GapPending||R->FirstRead.GapPending)return;
    if(R->FirstRead.AwaitingFresh){
        LifeInc(&R->FirstRead.Resumed);
        R->FirstRead.AwaitingFresh=0;
    }
    R->FirstRead.Streak=0;
    if(T->AwaitingFresh){
        LifeInc(&T->Resumed);T->AwaitingFresh=0;T->Disposition=N976nTailResumed;
        T->ResumeOrdinal=R->Lifecycle.Service.ReadOne;
    }
    T->Streak=0;R->Status=STATUS_SUCCESS;
}
NTSTATUS N976nDemoClearEvents(N976N_DEMO_RUNTIME *R)
{
    NTSTATUS S;
    if(!R||R->StopRequested||R->Stage!=29)return STATUS_CANCELLED;
    if(R->FirstRead.GapPending||R->Lifecycle.Recovery.GapPending||R->Lifecycle.Tail.GapPending)return STATUS_DEVICE_BUSY;
    LifeInc(&R->Lifecycle.Service.ClearAttempts);
    S=Command(R,0x62,0,NULL,0);
    if(!NT_SUCCESS(S))return Fail(R,90,S);
    LifeInc(&R->Lifecycle.Service.Cleared);return S;
}
NTSTATUS N976nDemoStop(N976N_DEMO_RUNTIME *R)
{
    NTSTATUS S=STATUS_SUCCESS;UCHAR D[2];
    if(!R)return STATUS_SUCCESS;
    LifeInc(&R->Lifecycle.StopCount);LifeFirst(R,&R->Lifecycle.FirstStop);
    if(!R->Claimed)return STATUS_SUCCESS;
    /* Caller joined the producer. Natural retirement only; cancellation is
     * disabled for this bounded owned cleanup, never a new sensing session. */
    if(R->Quarantined){R->CleanupStatus=STATUS_DEVICE_HARDWARE_ERROR;
        LifeFirst(R,&R->Lifecycle.FirstCleanup);LifeFirst(R,&R->Lifecycle.FirstCleanupFailure);return STATUS_DEVICE_HARDWARE_ERROR;}
    R->Io.Cancelled=NULL;
    if(R->SenseAttempted){S=Command(R,0x11,0,NULL,0);if(!NT_SUCCESS(S))goto Done;DelayMs(100);R->SenseAttempted=0;}
    if(R->FunctionSaved&&R->FunctionChanged){
        D[0]=(UCHAR)R->FunctionBefore;D[1]=(UCHAR)(R->FunctionBefore>>8);
        S=Command(R,0x30,0,D,2);if(!NT_SUCCESS(S))goto Done;DelayMs(30);
    }
    if(R->FunctionSaved){
        S=Command(R,0x30,1,D,2);if(!NT_SUCCESS(S))goto Done;
        if(((ULONG)D[0]|((ULONG)D[1]<<8))!=R->FunctionBefore){S=STATUS_DEVICE_HARDWARE_ERROR;goto Done;}
        R->FunctionSaved=0;R->FunctionChanged=0;
    }
Done:
    R->Io.Cancelled=Cancelled;R->CleanupStatus=(ULONG)S;
    if(!NT_SUCCESS(S))R->Quarantined=1;
    LifeFirst(R,&R->Lifecycle.FirstCleanup);
    if(!NT_SUCCESS(S))LifeFirst(R,&R->Lifecycle.FirstCleanupFailure);
    if(R->Stage!=90&&NT_SUCCESS(S))R->Stage=40;
    return S;
}
VOID N976nDemoRelease(N976N_DEMO_RUNTIME *R)
{
    ULONG I;
    if(!R)return;
    LifeInc(&R->Lifecycle.ReleaseCount);LifeFirst(R,&R->Lifecycle.FirstRelease);
    if(R->Claimed&&R->Map[5]){
        /* Permanent current-boot retirement: remove/re-add cannot reuse stale
         * producer evidence or reacquire after an unresolved transfer. */
        (void)InterlockedCompareExchange64((volatile LONG64*)&((N976N_TOUCH_HANDOFF*)R->Map[5])->ClaimState,
            R->Quarantined?N976N_TOUCH_CLAIM_QUARANTINED:N976N_TOUCH_CLAIM_RETIRED,N976N_TOUCH_CLAIM_OWNED);
    }
    R->Claimed=0;R->Mapped=0;
    for(I=0;I<N976N_DEMO_MAP_COUNT;++I)if(R->Map[I]){MmUnmapIoSpace(R->Map[I],R->Bytes[I]);R->Map[I]=NULL;}
    InterlockedCompareExchangePointer(&Owner,NULL,R);
    N976nDemoRecord(R);
}
VOID N976nDemoRecord(N976N_DEMO_RUNTIME *R)
{
    WDFKEY K;UNICODE_STRING N;
    static const WCHAR *Names[]={L"TouchStartStage",L"TouchStartStatus",L"TouchId",L"TouchPollCount",L"TouchEventCount",L"TouchLastX",L"TouchLastY",L"TouchLastAction",L"TouchHsiStatus",L"TouchHsiCleanup",L"TouchQuarantined"};
    ULONG V[]={R->Stage,R->Status,R->Id,R->Polls,R->Events,R->LastX,R->LastY,R->LastAction,R->Last.Status,R->CleanupStatus,R->Quarantined};
    if(!NT_SUCCESS(WdfDeviceOpenRegistryKey(R->Device,PLUGPLAY_REGKEY_DEVICE,KEY_SET_VALUE,WDF_NO_OBJECT_ATTRIBUTES,&K)))return;
    for(ULONG I=0;I<RTL_NUMBER_OF(V);++I){RtlInitUnicodeString(&N,Names[I]);(void)WdfRegistryAssignULong(K,&N,V[I]);}
    /* One complete first-refusal value. Repeated cleanup/record callbacks
     * leave its identity untouched; Valid=0 is explicit no-refusal evidence. */
    if(!R->DiagnosticRecorded){
        RtlInitUnicodeString(&N,L"TouchPrepareDiagnostic");
        if(NT_SUCCESS(WdfRegistryAssignValue(K,&N,REG_BINARY,sizeof(R->Diagnostic),&R->Diagnostic)))R->DiagnosticRecorded=1;
    }
    /* One bounded value persists across WDF context recreation/reload, but
     * only a matching current NVS identity can restore it on a later Prepare. */
    if(R->Lifecycle.IdentityValid&&R->LifeCanPublish){
        LifeState(R,&R->Lifecycle.Current);R->Lifecycle.CurrentStartup=R->Startup;
        R->Lifecycle.Crc32=N976nDemoLifecycleCrc(&R->Lifecycle);
        RtlInitUnicodeString(&N,N976N_LIFECYCLE_VALUE);
        (void)WdfRegistryAssignValue(K,&N,REG_BINARY,sizeof(R->Lifecycle),&R->Lifecycle);
    }
    WdfRegistryClose(K);
}
