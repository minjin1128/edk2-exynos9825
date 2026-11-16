/* SEC76 EXP9: native ARM64 UI and guarded disposable-PE driver startup.
 * WM_POINTER touch messages are distinguished from mouse movement. */
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#include <windows.h>
#include <windowsx.h>
#include <stdio.h>
#include <wchar.h>
#include <cfgmgr32.h>
#include "N976nStartup.h"
#include "N976nDemoDiagnostic.h"
#include "N976nDemoLifecycle.h"
#include "N976nTouchHandoff.h"
#include <stddef.h>

static const wchar_t *Names[] = {
    L"TouchStartStage", L"TouchStartStatus", L"TouchId", L"TouchPollCount",
    L"TouchEventCount", L"TouchLastX", L"TouchLastY", L"TouchLastAction",
    L"TouchHsiStatus", L"TouchHsiCleanup", L"TouchQuarantined"
};
static DWORD Values[11], Present;
static N976N_DEMO_DIAGNOSTIC Diagnostic;
static DWORD DiagnosticPresence;
static N976N_DEMO_LIFECYCLE Lifecycle;
static DWORD LifecyclePresence;
static int SideMargin=20;
static POINT LastPoint;
static BOOL TouchDown;
static unsigned DownCount, MoveCount, UpCount;
static HFONT Font;
static unsigned StartupStage=N976nUiReady;
static DWORD StartupExit, PnpStatus, PnpProblem, PnpQuery;
static ULONGLONG StageTick;
static BOOL PnpPresent, PeStart, Painted, WorkerDone, UiFixture;
static wchar_t StartupMessage[256]=L"Display ready. Worker has not started.";
static wchar_t FixtureName[32];
static CRITICAL_SECTION StateLock;
static HANDLE Worker;
static HWND MainWindow;
static void UpdateSceneFont(BOOL Landscape);
static int LineGap=10,LastTextBottom;
static N976N_NATIVE_STARTUP Native;
static N976N_STARTUP_OPS StartupOps;

static DWORD DiagnosticClass(const N976N_DEMO_DIAGNOSTIC *D,DWORD Type,DWORD Bytes)
{
    if(Type!=REG_BINARY||Bytes!=sizeof(*D)||D->Version!=N976N_DIAGNOSTIC_VERSION||
       D->Bytes!=sizeof(*D)||D->Reserved||D->MappedCount>7||D->ReadOk>1)return 3;
    if(!D->Valid)return 1; /* present, explicitly no first refusal recorded */
    if(D->Valid!=N976N_DIAGNOSTIC_VALID||D->Bucket<N976nDiagResource||
       D->Bucket>N976nDiagClaim||D->Condition<N976nWhyCount||D->Condition>N976nWhyAtomic)return 3;
    return 2;
}
static unsigned LifecycleCrc(const N976N_DEMO_LIFECYCLE *L)
{
    const unsigned char *P=(const unsigned char*)L;unsigned C=0xFFFFFFFFU;
    for(unsigned I=0;I<sizeof(*L);++I){
        unsigned V=I>=offsetof(N976N_DEMO_LIFECYCLE,Crc32)&&I<offsetof(N976N_DEMO_LIFECYCLE,Crc32)+4?0:P[I];
        C^=V;for(unsigned B=0;B<8;++B)C=(C>>1)^((C&1)?0xEDB88320U:0);
    }return ~C;
}
static DWORD LifecycleClass(const N976N_DEMO_LIFECYCLE *L,DWORD Type,DWORD Bytes)
{
    const N976N_LIFECYCLE_STATE *States[]={&L->FirstStart,&L->FirstStartFailure,&L->FirstFailure,
        &L->FirstStop,&L->FirstCleanup,&L->FirstCleanupFailure,&L->FirstRelease,&L->Current};
    if(Type!=REG_BINARY||Bytes!=sizeof(*L)||L->Version!=N976N_LIFECYCLE_VERSION||
       L->Bytes!=sizeof(*L)||L->Valid!=N976N_LIFECYCLE_VALID||L->IdentityValid!=1||
       !L->BootCounter||!L->CounterHz||L->NvsAddress<N976N_TOUCH_HANDOFF_LOW||
       L->NvsAddress>N976N_TOUCH_HANDOFF_END-4096||(L->NvsAddress&4095)||
       L->Origin>N976nLifeOriginRegistry||L->RegistryState>N976nLifeRegistryUnavailable||
       L->CurrentCallback>N976nLifePoll||!N976nRecoveryShape(&L->Recovery)||!N976nEventServiceShape(&L->Service)||!N976nTailRecoveryShape(&L->Tail)||!N976nReadyShape(&L->Ready)||L->Crc32!=LifecycleCrc(L))return 3;
    for(unsigned I=0;I<3;++I)if(L->Reserved[I])return 3;
    for(unsigned I=0;I<sizeof(States)/sizeof(States[0]);++I)
        if(States[I]->Valid>1||States[I]->Callback>N976nLifePoll||States[I]->HsiCurrent>1||States[I]->Reserved||!N976nHsiEvidenceShape(&States[I]->Hsi))return 3;
    if(!N976nStartupShape(&L->FirstStartup)||!N976nStartupShape(&L->FirstStartupFailure)||
       !N976nStartupShape(&L->CurrentStartup))return 3;
    if(DiagnosticClass(&L->FirstPrepareFailure,REG_BINARY,sizeof(L->FirstPrepareFailure))==3&&
       L->FirstPrepareFailure.Valid)return 3;
    return 2;
}
static void ReadValues(HKEY key, unsigned depth)
{
    DWORD index,diagType=0,diagBytes=sizeof(Diagnostic);N976N_DEMO_DIAGNOSTIC d;
    if(!LifecyclePresence){
        N976N_DEMO_LIFECYCLE l;DWORD type=0,bytes=sizeof(l);
        LSTATUS status=RegQueryValueExW(key,N976N_LIFECYCLE_VALUE,NULL,&type,(BYTE*)&l,&bytes);
        if(status==ERROR_SUCCESS){LifecyclePresence=LifecycleClass(&l,type,bytes);if(LifecyclePresence==2)Lifecycle=l;}
        else if(status==ERROR_MORE_DATA)LifecyclePresence=3;
    }
    if(!DiagnosticPresence){
        LSTATUS status=RegQueryValueExW(key,L"TouchPrepareDiagnostic",NULL,&diagType,(BYTE*)&d,&diagBytes);
        if(status==ERROR_SUCCESS){
            DiagnosticPresence=DiagnosticClass(&d,diagType,diagBytes);
            if(DiagnosticPresence==1||DiagnosticPresence==2)Diagnostic=d;
        }else if(status==ERROR_MORE_DATA)DiagnosticPresence=3;
    }
    for (index = 0; index < 11; ++index) {
        DWORD value, bytes = sizeof(value), type = 0;
        if (RegQueryValueExW(key, Names[index], NULL, &type,
                            (BYTE *)&value, &bytes) == ERROR_SUCCESS &&
            type == REG_DWORD && bytes == sizeof(value)) {
            Values[index] = value;
            Present |= 1u << index;
        }
    }
    if (depth >= 3 || Present == 0x7ff) return;
    for (index = 0; index < 32; ++index) {
        wchar_t name[256]; DWORD size = 256; HKEY child;
        if (RegEnumKeyExW(key, index, name, &size, NULL, NULL, NULL, NULL)
            != ERROR_SUCCESS) break;
        if (RegOpenKeyExW(key, name, 0, KEY_READ, &child) == ERROR_SUCCESS) {
            ReadValues(child, depth + 1);
            RegCloseKey(child);
        }
    }
}

static void Refresh(void)
{
    HKEY key, instance; DWORD index=0, size=256; wchar_t name[256], id[512]; DEVINST dev;
    if(UiFixture) return;
    Present=0; ZeroMemory(Values,sizeof(Values));DiagnosticPresence=0;ZeroMemory(&Diagnostic,sizeof(Diagnostic));
    LifecyclePresence=0;ZeroMemory(&Lifecycle,sizeof(Lifecycle));
    PnpPresent=FALSE; PnpStatus=PnpProblem=0; PnpQuery=CR_NO_SUCH_DEVNODE;
    if(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Enum\\ACPI\\NNTC0076",0,KEY_READ,&key)!=ERROR_SUCCESS) return;
    /* One instance supplies all fields; never merge diagnostics across devices. */
    if(RegEnumKeyExW(key,index,name,&size,NULL,NULL,NULL,NULL)==ERROR_SUCCESS) {
        wchar_t other[256];DWORD otherSize=256;
        if(RegEnumKeyExW(key,1,other,&otherSize,NULL,NULL,NULL,NULL)==ERROR_NO_MORE_ITEMS) {
            PnpPresent=TRUE;
            if(RegOpenKeyExW(key,name,0,KEY_READ,&instance)==ERROR_SUCCESS) {
                ReadValues(instance,0);RegCloseKey(instance);
            }
            swprintf_s(id,512,L"ACPI\\NNTC0076\\%s",name);
            PnpQuery=CM_Locate_DevNodeW(&dev,id,CM_LOCATE_DEVNODE_NORMAL);
            if(PnpQuery==CR_SUCCESS) PnpQuery=CM_Get_DevNode_Status(&PnpStatus,&PnpProblem,dev,0);
        } else PnpQuery=CR_INVALID_DEVNODE;
    }
    RegCloseKey(key);
}

static void Publish(void *Context,unsigned Stage,DWORD Code,const wchar_t *Message)
{
    UNREFERENCED_PARAMETER(Context);
    EnterCriticalSection(&StateLock);
    if(StartupStage!=Stage)StageTick=GetTickCount64();
    StartupStage=Stage;StartupExit=Code;wcsncpy_s(StartupMessage,256,Message,_TRUNCATE);
    LeaveCriticalSection(&StateLock);
    N976nStartupLog(&Native,Stage,Code);
    if(MainWindow) PostMessageW(MainWindow,WM_APP+2,0,0);
}
static DWORD Execute(void *Context,unsigned Stage)
{ UNREFERENCED_PARAMETER(Context);return N976nStartupExecute(&Native,Stage); }
static DWORD WINAPI StartupWorker(void *Context)
{
    DWORD E;
    UNREFERENCED_PARAMETER(Context);
    E=N976nStartupRun(&StartupOps,TRUE);
    N976nStartupRelease(&Native);
    PostMessageW(MainWindow,WM_APP+3,E,0);return E;
}

static void Line(HDC dc,int width,int *y,const wchar_t *text)
{
    RECT r={SideMargin,*y,width-SideMargin,*y+160};
    int height=DrawTextW(dc,text,-1,&r,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX|DT_CALCRECT);
    r.bottom=r.top+height;DrawTextW(dc,text,-1,&r,DT_LEFT|DT_WORDBREAK|DT_NOPREFIX);
    LastTextBottom=r.bottom;*y+=height+LineGap;
}
static const wchar_t *DriverStageName(DWORD stage)
{
    switch(stage) {
    case 10:return L"preparing resources";case 11:return L"resource/owner refusal";
    case 12:return L"mapping/handoff/fresh-state refusal";case 19:return L"resources and boot lease claimed";
    case 20:return L"starting sensor";case 21:return L"ID read/identity failed";
    case 22:return L"application state failed";case 23:return L"function read failed";
    case 24:return L"function setup failed";case 25:return L"sensor initialization failed";
    case 26:return L"sense-on failed";case 29:return L"sensor polling active";
    case 40:return L"transport retired";case 90:return L"poll failure";
    default:return L"unknown driver stage";
    }
}
static const wchar_t *BucketName(unsigned B)
{
    switch(B){case N976nDiagResource:return L"RESOURCE";case N976nDiagMap:return L"MAP";
    case N976nDiagNvs:return L"NVS";case N976nDiagShape:return L"NVS FIELD";
    case N976nDiagClock:return L"NVS CLOCK";case N976nDiagFresh:return L"FRESH MMIO";
    case N976nDiagClaim:return L"CLAIM";default:return L"unknown";}
}
static const wchar_t *ConditionName(unsigned C)
{
    static const wchar_t *ConditionNames[]={L"none",L"count",L"owner",L"descriptor",L"type",L"share",L"flags pair",L"flags mask",
      L"base pair",L"length pair",L"positive base",L"base",L"length",L"alignment",L"range",L"writable",L"map",
      L"snapshot",L"page guard",L"ready",L"field",L"CRC",L"clock word",L"clock reuse",L"clock missing",L"clock rate",
      L"gate",L"PLL",L"timing",L"read",L"equal",L"masked",L"idle",L"atomic"};
    return C<sizeof(ConditionNames)/sizeof(ConditionNames[0])?ConditionNames[C]:L"unknown";
}
static void DrawDiagnostic(HDC dc,int width,int *y)
{
    wchar_t s[512];
    if(DiagnosticPresence!=2){
        if(Values[0]==11||Values[0]==12){
            SetTextColor(dc,RGB(255,190,90));
            Line(dc,width,y,DiagnosticPresence==3?L"Prepare diagnosis INVALID/incomplete; do not interpret zero fields.":
                DiagnosticPresence==1?L"Prepare diagnosis present, no first refusal recorded.":L"Prepare diagnosis not yet available.");
        }return;
    }
    SetTextColor(dc,RGB(255,190,90));
    swprintf_s(s,512,L"CURRENT %s / %s [%u:%u]",BucketName(Diagnostic.Bucket),ConditionName(Diagnostic.Condition),Diagnostic.Bucket,Diagnostic.Condition);Line(dc,width,y,s);
    swprintf_s(s,512,L"Index %u | offset %04X | mapped %u/7 | read %u",Diagnostic.Index,Diagnostic.Offset,Diagnostic.MappedCount,Diagnostic.ReadOk);Line(dc,width,y,s);
    swprintf_s(s,512,L"Expected %016llX",Diagnostic.Expected);Line(dc,width,y,s);
    swprintf_s(s,512,L"Actual   %016llX",Diagnostic.Actual);Line(dc,width,y,s);
    swprintf_s(s,512,L"Mask/limit %016llX",Diagnostic.Mask);Line(dc,width,y,s);
    if(Diagnostic.Bucket==N976nDiagResource||Diagnostic.Bucket==N976nDiagMap){
        swprintf_s(s,512,L"RAW type/share/flags %X/%X/%04X",Diagnostic.RawType,Diagnostic.RawShare,Diagnostic.RawFlags);Line(dc,width,y,s);
        swprintf_s(s,512,L"RAW base %016llX len %08X",Diagnostic.RawStart,Diagnostic.RawLength);Line(dc,width,y,s);
        swprintf_s(s,512,L"TRN type/share/flags %X/%X/%04X",Diagnostic.TransType,Diagnostic.TransShare,Diagnostic.TransFlags);Line(dc,width,y,s);
        swprintf_s(s,512,L"TRN base %016llX len %08X",Diagnostic.TransStart,Diagnostic.TransLength);Line(dc,width,y,s);
        swprintf_s(s,512,L"Resource counts RAW %u / TRN %u",Diagnostic.RawCount,Diagnostic.TransCount);Line(dc,width,y,s);
    }
}
static const wchar_t *CallbackName(unsigned C)
{
    switch(C){case N976nLifePrepare:return L"Prepare";case N976nLifeD0Entry:return L"D0 entry";
    case N976nLifeD0Exit:return L"D0 exit";case N976nLifeReleaseHardware:return L"Release";
    case N976nLifeStartFailure:return L"start failure";case N976nLifePollFailure:return L"poll failure";
    case N976nLifePoll:return L"poll";case N976nLifeInputBusy:return L"input busy";default:return L"none";}
}
static const wchar_t *StartupReasonName(unsigned R)
{
    switch(R){case N976nStartupNone:return L"none";case N976nStartupTransfer:return L"transfer";
    case N976nStartupChipError:return L"chip error";case N976nStartupMalformed:return L"malformed";
    case N976nStartupUnknown:return L"unknown status";
    case N976nStartupOverflow:return L"queue overflow";case N976nStartupReadLimit:return L"read limit";
    case N976nStartupDeadline:return L"deadline";case N976nStartupAppState:return L"app state";
    case N976nStartupFunctionState:return L"function state";case N976nStartupSense:return L"sense-on";
    case N976nStartupClear:return L"clear command";case N976nStartupPostBoot:return L"post-sense boot/reset";default:return L"invalid";}
}
static void DrawStartupPacket(HDC dc,int width,int *y,const wchar_t *Name,const N976N_STARTUP_PACKET *P)
{
    wchar_t s[512],raw[33];
    if(!P->Valid)return;
    for(unsigned I=0;I<P->Bytes;++I)swprintf_s(raw+I*2,33-I*2,L"%02X",P->Raw[I]);
    raw[P->Bytes*2]=0;
    swprintf_s(s,512,L"%s #%u bytes %u class/sub/id/left %u/%u/%02X/%u | RAW %s%s",Name,P->Ordinal,P->Bytes,P->Class,P->Subtype,P->Id,P->Remaining,P->Bytes?raw:L"(none)",P->Bytes<16?L" [partial; not decoded]":L"");Line(dc,width,y,s);
}
static const wchar_t *InitPhaseName(unsigned Phase)
{
    switch(Phase){case N976nInitPre:return L"PRE snapshot";case N976nInitPreState:return L"PRE state";
    case N976nInitSense:return L"SENSE_ON";case N976nInitClear:return L"CLEAR62";
    case N976nInitPostState:return L"POST state";case N976nInitPost:return L"POST snapshot";
    case N976nInitComplete:return L"complete";default:return L"not run";}
}
static void DrawStartupEvidence(HDC dc,int width,int *y)
{
    const N976N_STARTUP_EVIDENCE *E=Lifecycle.FirstStartupFailure.Phase==N976nStartupFailed?&Lifecycle.FirstStartupFailure:&Lifecycle.FirstStartup;
    wchar_t s[512];
    if(E->Phase==N976nStartupNotRun)return;
    if(Lifecycle.FirstFailure.Valid&&Lifecycle.FirstFailure.Stage==90&&E->Phase==N976nStartupComplete){
        swprintf_s(s,512,L"INIT complete: SENSE %u/%u/%u %08X / CLEAR %u/%u/%u %08X; details in lifecycle/log",E->SenseAttempted,E->SenseIssued,E->SenseCompleted,E->SenseStatus,E->ClearAttempted,E->ClearIssued,E->ClearCompleted,E->ClearStatus);Line(dc,width,y,s);
        return;
    }
    swprintf_s(s,512,L"INIT: %s / %s | reason %u (%s)",E->Phase==N976nStartupComplete?L"completed":E->Phase==N976nStartupFailed?L"failed":L"in progress",InitPhaseName(E->InitPhase),E->Reason,StartupReasonName(E->Reason));Line(dc,width,y,s);
    swprintf_s(s,512,L"PRE/POST reads %u/2 nonempty/empty %u/%u %lluus | observed/left31/vendor %u/%u/%u",E->Reads,E->NonEmpty,E->Empty,E->ElapsedUs,E->ObservedPackets,E->Remaining31Count,E->UnknownVendorCount);Line(dc,width,y,s);
    swprintf_s(s,512,L"SENSE A/I/C %u/%u/%u %08X / CLEAR A/I/C %u/%u/%u %08X",E->SenseAttempted,E->SenseIssued,E->SenseCompleted,E->SenseStatus,E->ClearAttempted,E->ClearIssued,E->ClearCompleted,E->ClearStatus);Line(dc,width,y,s);
    swprintf_s(s,512,L"PRE %X app %02X/%08X fn %04X/%08X | POST %X app %02X/%08X fn %04X/%08X",E->PreChecks,E->PreAppValue,E->PreAppStatus,E->PreFunctionValue,E->PreFunctionStatus,E->PostChecks,E->AppValue,E->AppStatus,E->FunctionValue,E->FunctionStatus);Line(dc,width,y,s);
    DrawStartupPacket(dc,width,y,L"PRE",&E->First);
    if(E->Last.Valid&&E->Last.Ordinal==2)DrawStartupPacket(dc,width,y,E->Rejected.Valid?L"POST REJECT":L"POST",&E->Last);
    Line(dc,width,y,L"Clear completed is not an empty proof. PRE/POST coordinates are not HID.");
    if(E->Phase==N976nStartupComplete)Line(dc,width,y,L"Initialization complete: make a NEW tap now to test Windows input.");
}
static const wchar_t *WaitExitName(unsigned E)
{
    switch(E){case N976nWaitComplete:return L"byte+DONE";case N976nWaitDeadline:return L"WALL LIMIT";
    case N976nWaitClockStall:return L"CLOCK STALL";case N976nWaitClock:return L"CLOCK BACKWARD";
    case N976nWaitOther:return L"OTHER FAILURE";default:return L"none";}
}
static void DrawWait(HDC dc,int width,int *y,const N976N_HSI_WAIT *W)
{
    wchar_t s[512];if(!W->Valid)return;
    swprintf_s(s,512,L"WAIT %s: %s | status/phase %u/%u",W->Receive?L"RX":L"TX",WaitExitName(W->Exit),W->Status,W->Phase);Line(dc,width,y,s);
    swprintf_s(s,512,L"Message %u len %u RUN attempted %u | loops %llu",W->MessageIndex,W->Requested,W->RunIssued,W->Iterations);Line(dc,width,y,s);
    swprintf_s(s,512,L"CLOCK checks %llu | last-check delta %lluus / 100000us%s",W->ClockChecks,W->ElapsedUs,W->Exit==N976nWaitClock?L" [invalid delta]":L"");Line(dc,width,y,s);
    if(W->Exit==N976nWaitClock){swprintf_s(s,512,L"Precise start/previous/last %llu / %llu / %llu",W->StartUs,W->PreviousUs,W->LastNowUs);Line(dc,width,y,s);}
    swprintf_s(s,512,L"Same clock current/max %u/%u / watchdog 20000",W->SameClock,W->MaxSameClock);Line(dc,width,y,s);
    swprintf_s(s,512,L"RAW seen run/busy/rx-ready/done/error %u/%u/%u/%u/%u",(unsigned)!!(W->Seen&1),(unsigned)!!(W->Seen&2),(unsigned)!!(W->Seen&4),(unsigned)!!(W->Seen&8),(unsigned)!!(W->Seen&16));Line(dc,width,y,s);
    swprintf_s(s,512,L"FIRST[%X] I/T/F/A %08X %08X %08X %08X",W->First.Valid,W->First.Interrupt,W->First.Transfer,W->First.Fifo,W->First.Auto);Line(dc,width,y,s);
    swprintf_s(s,512,L"LAST [%X] I/T/F/A %08X %08X %08X %08X",W->Last.Valid,W->Last.Interrupt,W->Last.Transfer,W->Last.Fifo,W->Last.Auto);Line(dc,width,y,s);
    if(W->RunClear.Iteration){swprintf_s(s,512,L"RAW RUN clear #%llu I/T/F/A %08X %08X %08X %08X",W->RunClear.Iteration,W->RunClear.Sample.Interrupt,W->RunClear.Sample.Transfer,W->RunClear.Sample.Fifo,W->RunClear.Sample.Auto);Line(dc,width,y,s);}else Line(dc,width,y,L"RAW RUN clear: not observed");
    if(W->BusyClear.Iteration){swprintf_s(s,512,L"RAW BUSY clear #%llu I/T/F/A %08X %08X %08X %08X",W->BusyClear.Iteration,W->BusyClear.Sample.Interrupt,W->BusyClear.Sample.Transfer,W->BusyClear.Sample.Fifo,W->BusyClear.Sample.Auto);Line(dc,width,y,s);}else Line(dc,width,y,L"RAW BUSY clear: not observed");

}
static void BoundaryWord(wchar_t S[9],unsigned Valid,unsigned Bit,unsigned Value)
{
    if(Valid&Bit)swprintf_s(S,9,L"%08X",Value);else wcscpy_s(S,9,L"--------");
}
static void DrawBoundary(HDC dc,int width,int *y,const N976N_HSI_RESULT *R)
{
    wchar_t s[512],A[9],B[9],C[9],D[9];
    if(!(R->Boundary[0].Valid|R->Boundary[1].Valid|R->Boundary[2].Valid))return;
    for(unsigned I=0;I<3;++I){
        const N976N_HSI_BOUNDARY *P=&R->Boundary[I];const wchar_t *N=I==0?L"TX":I==1?L"RX":L"RET";
        if(!P->Valid){swprintf_s(s,512,L"%s boundary: not observed",N);Line(dc,width,y,s);continue;}
        if(I<2){
            BoundaryWord(A,P->Valid,1,P->PreStatus);BoundaryWord(B,P->Valid,2,P->PreEnable);
            BoundaryWord(C,P->Valid,4,P->ArmWanted);BoundaryWord(D,P->Valid,8,P->ArmRead);
            swprintf_s(s,512,L"%s[%03X] pre S/E %s/%s arm %s/%s",N,P->Valid,A,B,C,D);Line(dc,width,y,s);
        }
        if(P->Valid&N976nBoundaryIdleSample){
            BoundaryWord(A,P->Valid,16,P->IdleStatus);BoundaryWord(B,P->Valid,64,P->MaskRead);
            BoundaryWord(C,P->Valid,128,P->Pending);BoundaryWord(D,P->Valid,512,P->After);
            swprintf_s(s,512,L"%s ACK[%03X] W1C attempt%u I/M/P/A %s %s %s %s",N,P->Valid,(unsigned)!!(P->Valid&256),A,B,C,D);Line(dc,width,y,s);
        }
    }
}
static BOOL DrawLifecycle(HDC dc,int width,int *y)
{
    wchar_t s[512];const N976N_LIFECYCLE_STATE *F;
    if(LifecyclePresence!=2){
        if(LifecyclePresence==3){SetTextColor(dc,RGB(255,190,90));Line(dc,width,y,L"Lifecycle evidence INVALID/incomplete. Do not infer zero values.");}
        return FALSE;
    }
    if(Lifecycle.Ready.Checks){
        const N976N_EVENT_READY *G=&Lifecycle.Ready;wchar_t Last[16],First[16],Fault[16];
        if(G->LastValid)swprintf_s(Last,16,L"%08X",G->LastRaw);else wcscpy_s(Last,16,L"not read");
        if(G->FirstErrorValid)swprintf_s(First,16,L"%08X",G->FirstErrorRaw);else wcscpy_s(First,16,L"none");
        if(G->LastErrorValid)swprintf_s(Fault,16,L"%08X",G->LastErrorRaw);else wcscpy_s(Fault,16,L"none");
        swprintf_s(s,512,L"GPIO LOW/HIGH skip/refused %u/%u/%u | last %s | fault service-entry %s/%s",G->Low,G->HighSkip,G->Rejected,Last,First,Fault);Line(dc,width,y,s);
    }
    F=Lifecycle.FirstFailure.Valid?&Lifecycle.FirstFailure:&Lifecycle.FirstStart;
    if(Lifecycle.FirstFailure.Valid&&(Lifecycle.Recovery.Outcome==N976nRecoveryExhausted||Lifecycle.Recovery.Outcome==N976nRecoveryAborted))F=&Lifecycle.Recovery.LastAttempt;
    SetTextColor(dc,RGB(255,190,90));
    if(Lifecycle.Tail.Faults&&!Lifecycle.FirstFailure.Valid){
        Line(dc,width,y,L"No terminal failure recorded; failed61 transport is shown separately below.");
    }else if(F->Valid){
        swprintf_s(s,512,L"%s: stage %u / NTSTATUS %08X / ID %06X / cmd %02X",F==&Lifecycle.Recovery.LastAttempt?L"TERMINAL ATTEMPT":Lifecycle.FirstFailure.Valid?L"FIRST FAILURE":L"FIRST START",F->Stage,F->Status,F->Id,F->Command);Line(dc,width,y,s);
        if(!Lifecycle.Ready.Checks){swprintf_s(s,512,L"Attempt %u | %s | command %02X | HSI current %u",F->Prepare,CallbackName(F->Callback),F->Command,F->HsiCurrent);Line(dc,width,y,s);}
        if(F->HsiCurrent){
            swprintf_s(s,512,L"HSI status/phase %u/%u messages/TX/RX %u/%u/%u | retired/Q %u/%u cleanup %u",F->Hsi.Status,F->Hsi.FirstPhase,F->Hsi.MessagesIssued,F->Hsi.TxBytes,F->Hsi.RxBytes,F->Hsi.Retired,F->Hsi.Quarantined,F->Hsi.CleanupStatus);Line(dc,width,y,s);
        }else Line(dc,width,y,L"This command did not enter the HSI engine; prior HSI result is hidden.");
        if(F->HsiCurrent){DrawWait(dc,width,y,&F->Hsi.Wait);DrawBoundary(dc,width,y,&F->Hsi);}
        if(F->HsiCurrent&&F->Hsi.FirstFailure.Valid&&(!F->Hsi.Wait.Valid||memcmp(&F->Hsi.FirstFailure,&F->Hsi.Wait.Last,sizeof(F->Hsi.FirstFailure)))){
            swprintf_s(s,512,L"FAULT[%X] I/T/F/A %08X %08X %08X %08X",F->Hsi.FirstFailure.Valid,F->Hsi.FirstFailure.Interrupt,F->Hsi.FirstFailure.Transfer,F->Hsi.FirstFailure.Fifo,F->Hsi.FirstFailure.Auto);Line(dc,width,y,s);
        }
    }else Line(dc,width,y,L"No first sensor-start result recorded.");
    if(!Lifecycle.Service.ReadOne&&!Lifecycle.Recovery.Faults&&F->Valid&&(F->Callback==N976nLifePoll||F->Stage==90)&&(Present&24)==24){swprintf_s(s,512,L"Runtime event reads %lu / coordinates %lu",Values[3],Values[4]);Line(dc,width,y,s);}
    if(Lifecycle.Service.ReadOne){
        const N976N_EVENT_SERVICE *B=&Lifecycle.Service;
        swprintf_s(s,512,L"Batch60/61 %u/%u | clear %u/%u | validated %u | last left/count/request %u/%u/%uB",B->ReadOne,B->ReadAll,B->ClearAttempts,B->Cleared,B->Completed,B->LastRemaining,B->LastCount,B->LastBytes);Line(dc,width,y,s);
    }
    if(Lifecycle.Tail.Faults){
        const N976N_TAIL_RECOVERY *T=&Lifecycle.Tail;
        const N976N_TAIL_FAULT *A=T->FirstDeferred.State.Valid?&T->FirstDeferred:&T->LastFailure;
        wchar_t Raw[33];for(unsigned I=0;I<16;++I)swprintf_s(Raw+I*2,33-I*2,L"%02X",A->FirstPacket[I]);
        swprintf_s(s,512,L"61 drop %u / service-resumed %u / streak %u/3 / fatal %u | disposition %u decision %u",T->Deferred,T->Resumed,T->Streak,T->Fatal,T->Disposition,T->Decision);Line(dc,width,y,s);
        swprintf_s(s,512,L"%s61 #%u left %u request %uB | first60 %s",T->FirstDeferred.State.Valid?L"First deferred ":L"Failed ",A->Ordinal,A->Remaining,A->Requested,Raw);Line(dc,width,y,s);
        if(A->State.HsiCurrent)swprintf_s(s,512,L"61 first IRQ/TRANS %08X/%08X final %08X | last #%u status %08X | resume #%u",A->State.Hsi.FirstFailure.Interrupt,A->State.Hsi.FirstFailure.Transfer,A->State.Hsi.Last.Transfer,T->LastFailure.Ordinal,T->LastFailure.State.Status,T->ResumeOrdinal);
        else swprintf_s(s,512,L"61 HSI not entered; prior samples hidden | last #%u status %08X | resume #%u",T->LastFailure.Ordinal,T->LastFailure.State.Status,T->ResumeOrdinal);
        Line(dc,width,y,s);
        if(A->State.HsiCurrent && A->State.Hsi.Status == N976nHsiTimeout){
            swprintf_s(s,512,L"Expired RX: %u received, %u discarded / %u requested | retired %u quarantine %u",
                A->State.Hsi.RxBytes,A->State.Hsi.DiscardedBytes,A->Requested,
                A->State.Hsi.Retired,A->State.Hsi.Quarantined);Line(dc,width,y,s);
        }
    }
    if(Lifecycle.Recovery.Faults){
        const N976N_EVENT_RECOVERY *R=&Lifecycle.Recovery;
        swprintf_s(s,512,L"EVENT recovery: faults %u / retries %u / recovered %u / exhausted %u | last attempt %u/3",R->Faults,R->Retries,R->Recovered,R->Exhausted,R->Attempt);Line(dc,width,y,s);
        if(!Lifecycle.Tail.Faults){swprintf_s(s,512,L"First60 NODEV I/T/F/A %08X %08X %08X %08X | gap %u: all-up + NEW press",R->FirstTransient.Hsi.FirstFailure.Interrupt,R->FirstTransient.Hsi.FirstFailure.Transfer,R->FirstTransient.Hsi.FirstFailure.Fifo,R->FirstTransient.Hsi.FirstFailure.Auto,R->GapPending);Line(dc,width,y,s);}
    }else if(!Lifecycle.Service.ReadOne)DrawStartupEvidence(dc,width,y);
    if(Lifecycle.Tail.Faults&&Lifecycle.FirstStop.Valid){
        const N976N_LIFECYCLE_STATE *C=Lifecycle.FirstCleanupFailure.Valid?&Lifecycle.FirstCleanupFailure:&Lifecycle.FirstCleanup;
        swprintf_s(s,512,L"STOP %08X | cleanup %u/%08X Q%u | release %u/%08X",Lifecycle.FirstStop.Status,C->Valid,C->CleanupStatus,C->Quarantined,Lifecycle.FirstRelease.Valid,Lifecycle.FirstRelease.Status);Line(dc,width,y,s);
    }else if(Lifecycle.FirstStop.Valid){
        const N976N_LIFECYCLE_STATE *S=&Lifecycle.FirstStop;
        swprintf_s(s,512,L"FIRST STOP: %s / stage %u / status %08X",CallbackName(S->Callback),S->Stage,S->Status);Line(dc,width,y,s);
    }
    if(!Lifecycle.Tail.Faults&&(Lifecycle.FirstCleanupFailure.Valid||Lifecycle.FirstCleanup.Valid)){
        const N976N_LIFECYCLE_STATE *C=Lifecycle.FirstCleanupFailure.Valid?&Lifecycle.FirstCleanupFailure:&Lifecycle.FirstCleanup;
        swprintf_s(s,512,L"%s NTSTATUS %08X / quarantine %u",Lifecycle.FirstCleanupFailure.Valid?L"FIRST CLEANUP FAILURE":L"First cleanup",C->CleanupStatus,C->Quarantined);Line(dc,width,y,s);
    }
    if(!Lifecycle.Tail.Faults&&Lifecycle.FirstRelease.Valid){
        swprintf_s(s,512,L"FIRST RELEASE: stage %u / status %08X / claimed %u",Lifecycle.FirstRelease.Stage,Lifecycle.FirstRelease.Status,Lifecycle.FirstRelease.Claimed);Line(dc,width,y,s);
    }
    if(!Lifecycle.Service.ReadOne){swprintf_s(s,512,L"Calls Prep/D0-in/out/Rel %u/%u/%u/%u | PrepOK/claim/start/stop %u/%u/%u/%u",Lifecycle.PrepareCount,Lifecycle.D0EntryCount,Lifecycle.D0ExitCount,Lifecycle.ReleaseCount,Lifecycle.PrepareSuccessCount,Lifecycle.ClaimCount,Lifecycle.StartCount,Lifecycle.StopCount);Line(dc,width,y,s);}
    if(DiagnosticPresence==2){
        swprintf_s(s,512,L"CURRENT refusal: %s / %s [%u:%u] offset %04X",BucketName(Diagnostic.Bucket),ConditionName(Diagnostic.Condition),Diagnostic.Bucket,Diagnostic.Condition,Diagnostic.Offset);Line(dc,width,y,s);
        swprintf_s(s,512,L"Expected %llX / actual %llX",Diagnostic.Expected,Diagnostic.Actual);Line(dc,width,y,s);
    }
    return TRUE;
}
static int SafeInset(int width,int height)
{
    int shortSide=width<height?width:height;
    /* All four edges: the physical punch-hole rotates with the panel. */
    return shortSide/12<72?72:shortSide/12;
}
static void DrawScene(HDC dc,RECT r)
{
    int y=SafeInset(r.right-r.left,r.bottom-r.top);wchar_t s[512],message[256];DWORD stage,code;ULONGLONG tick;int width=r.right-r.left;
    LastTextBottom=0;SideMargin=y;FillRect(dc,&r,(HBRUSH)GetStockObject(BLACK_BRUSH));SelectObject(dc,Font);
    SetBkMode(dc,TRANSPARENT);SetTextColor(dc,RGB(225,235,245));
    Line(dc,width,&y,L"N976N SEC76 EXP9 - GPIO-ready service entry");
    if(UiFixture) Line(dc,width,&y,L"UI TEST FIXTURE - no driver or hardware operation");
    EnterCriticalSection(&StateLock);stage=StartupStage;code=StartupExit;
    tick=StageTick;wcscpy_s(message,256,StartupMessage);LeaveCriticalSection(&StateLock);
    BOOL LifeShown=DrawLifecycle(dc,width,&y);
    if(!LifeShown)DrawDiagnostic(dc,width,&y);
    SetTextColor(dc,RGB(225,235,245));
    swprintf_s(s,512,L"Startup %s | code 0x%08lX",N976nStartupName(stage),code);Line(dc,width,&y,s);
    if(DiagnosticPresence==2||(LifeShown&&Values[0]!=29)){
        if((Present&7)==7){swprintf_s(s,512,L"Driver %lu / NTSTATUS %08lX / ID %06lX",Values[0],Values[1],Values[2]);Line(dc,width,&y,s);}
        else Line(dc,width,&y,L"Driver stage/status/ID not yet complete.");
        swprintf_s(s,512,L"PnP query %08lX / status %08lX / problem %lu",PnpQuery,PnpStatus,PnpProblem);Line(dc,width,&y,s);
        Line(dc,width,&y,LifeShown?L"CURRENT is separate. HSI current 0 means no new engine result.":L"Current Prepare refusal. Earlier start is not recorded here.");
        return;
    }
    if(LifeShown){
        swprintf_s(s,512,L"CURRENT Driver %lu / NTSTATUS %08lX / ID %06lX | PnP problem %lu",Values[0],Values[1],Values[2],PnpProblem);Line(dc,width,&y,s);
        swprintf_s(s,512,L"Polls %lu / events %lu | raw X %lu Y %lu | HSI %lu",Values[3],Values[4],Values[5],Values[6],Values[8]);Line(dc,width,&y,s);
    }else{
    swprintf_s(s,512,L"Stage elapsed %llu seconds%s",(GetTickCount64()-tick)/1000,
        stage==N976nWpeInit?L" | wpeinit deadline 300s":stage==N976nDriverLoad?L" | drvload deadline 120s":L"");Line(dc,width,&y,s);
    SetTextColor(dc,code?RGB(255,140,90):RGB(140,210,255));Line(dc,width,&y,message);
    if(code) {
        wchar_t error[384]={0};
        if(FormatMessageW(FORMAT_MESSAGE_FROM_SYSTEM|FORMAT_MESSAGE_IGNORE_INSERTS,NULL,code,0,error,384,NULL))Line(dc,width,&y,error);
        else Line(dc,width,&y,L"No system message for this code; the raw code above is retained.");
    }
    SetTextColor(dc,RGB(225,235,245));
    if(!PnpPresent) {
        swprintf_s(s,512,L"PnP device absent/unavailable (CM result 0x%08lX).",PnpQuery);Line(dc,width,&y,s);
    } else {
        swprintf_s(s,512,L"PnP query 0x%08lX | status 0x%08lX | problem %lu",PnpQuery,PnpStatus,PnpProblem);Line(dc,width,&y,s);
    }
    if(!Present) {
        SetTextColor(dc,RGB(255,190,90));
        Line(dc,width,&y,L"No driver diagnostic fields. Package load success alone is not device start.");
    } else {
        if((Present&7)==7) {
            swprintf_s(s,512,L"Driver %lu (%s) | NTSTATUS %08lX | ID %06lX",Values[0],DriverStageName(Values[0]),Values[1],Values[2]);Line(dc,width,&y,s);
        } else Line(dc,width,&y,L"Driver stage/status/ID incomplete (missing fields are not zero results).");
        if((Present&0xf8)==0xf8) {
            swprintf_s(s,512,L"Polls %lu | events %lu | raw X %lu Y %lu | action %lu",Values[3],Values[4],Values[5],Values[6],Values[7]);Line(dc,width,&y,s);
        }
        if((Present&0x700)==0x700) {
            swprintf_s(s,512,L"HSI %lu | cleanup %lu | quarantine %lu",Values[8],Values[9],Values[10]);Line(dc,width,&y,s);
        }
        swprintf_s(s,512,L"Present fields %03lX / 7FF",Present);Line(dc,width,&y,s);
    }
    }
    SetTextColor(dc,RGB(80,230,230));
    swprintf_s(s,512,L"Windows TOUCH: DOWN %u / MOVE %u / UP %u / active %u",DownCount,MoveCount,UpCount,TouchDown?1u:0u);Line(dc,width,&y,s);
    swprintf_s(s,512,L"Client X %ld Y %ld | screen %ld x %ld",LastPoint.x,LastPoint.y,r.right,r.bottom);Line(dc,width,&y,s);
    SetTextColor(dc,RGB(160,170,180));
    Line(dc,width,&y,L"Tap, drag, then lift. Mouse motion does not count as touch. Logs stay on the PE X: RAM disk.");
    if(DownCount) {
        HPEN pen=CreatePen(PS_SOLID,5,TouchDown?RGB(0,255,230):RGB(255,180,50));
        HGDIOBJ oldPen=SelectObject(dc,pen),oldBrush=SelectObject(dc,GetStockObject(NULL_BRUSH));
        Ellipse(dc,LastPoint.x-32,LastPoint.y-32,LastPoint.x+33,LastPoint.y+33);
        SelectObject(dc,oldBrush);SelectObject(dc,oldPen);DeleteObject(pen);
    }
}
static void Paint(HWND hwnd)
{
    PAINTSTRUCT ps;RECT r;HDC dc=BeginPaint(hwnd,&ps);GetClientRect(hwnd,&r);DrawScene(dc,r);EndPaint(hwnd,&ps);
    if(!Painted) {Painted=TRUE;PostMessageW(hwnd,WM_APP+1,0,0);}
}
static BOOL SaveFixture(void)
{
    BITMAPINFO bi={0};BITMAPFILEHEADER header={0};void *pixels=NULL;DWORD written,pixelBytes;
    RECT r={0,0,1000,1500};HDC dc=CreateCompatibleDC(NULL);HBITMAP bitmap;HGDIOBJ old;
    wchar_t name[80];HANDLE file;BOOL ok;
    if(wcsstr(FixtureName,L"landscape")){r.right=1600;r.bottom=1000;}
    pixelBytes=(DWORD)r.right*(DWORD)r.bottom*4U;
    bi.bmiHeader.biSize=sizeof(BITMAPINFOHEADER);bi.bmiHeader.biWidth=r.right;bi.bmiHeader.biHeight=-r.bottom;
    bi.bmiHeader.biPlanes=1;bi.bmiHeader.biBitCount=32;bi.bmiHeader.biCompression=BI_RGB;
    bitmap=CreateDIBSection(dc,&bi,DIB_RGB_COLORS,&pixels,NULL,0);if(!bitmap){DeleteDC(dc);return FALSE;}
    old=SelectObject(dc,bitmap);DrawScene(dc,r);
    BOOL textFits=LastTextBottom<=r.bottom-SafeInset(r.right,r.bottom);
    header.bfType=0x4d42;header.bfOffBits=sizeof(header)+sizeof(bi.bmiHeader);header.bfSize=header.bfOffBits+pixelBytes;
    swprintf_s(name,80,L"ui-%s.bmp",FixtureName);file=CreateFileW(name,GENERIC_WRITE,0,NULL,CREATE_NEW,FILE_ATTRIBUTE_NORMAL,NULL);
    ok=file!=INVALID_HANDLE_VALUE;
    if(ok) {
        ok=WriteFile(file,&header,sizeof(header),&written,NULL)&&written==sizeof(header);
        ok=ok&&WriteFile(file,&bi.bmiHeader,sizeof(bi.bmiHeader),&written,NULL)&&written==sizeof(bi.bmiHeader);
        ok=ok&&WriteFile(file,pixels,pixelBytes,&written,NULL)&&written==pixelBytes;CloseHandle(file);
    }
    SelectObject(dc,old);DeleteObject(bitmap);DeleteDC(dc);return ok&&textFits;
}

static LRESULT CALLBACK WindowProc(HWND hwnd, UINT msg, WPARAM w, LPARAM l)
{
    switch (msg) {
    case WM_CREATE: SetTimer(hwnd,1,1000,NULL);Refresh();return 0;
    case WM_APP+1:
        if(UiFixture) {BOOL ok=SaveFixture();PostQuitMessage(ok?0:9);return 0;}
        if(PeStart) {
            MainWindow=hwnd;StartupOps.Context=NULL;StartupOps.Execute=Execute;StartupOps.Publish=Publish;
            Worker=CreateThread(NULL,0,StartupWorker,NULL,0,NULL);
            if(!Worker){WorkerDone=TRUE;Publish(NULL,N976nUiReady,GetLastError(),L"Cannot start bootstrap worker.");}
        }
        return 0;
    case WM_APP+2: InvalidateRect(hwnd,NULL,FALSE);return 0;
    case WM_APP+3: WorkerDone=TRUE;Refresh();InvalidateRect(hwnd,NULL,FALSE);return 0;
    case WM_CLOSE:
        if(Worker&&!WorkerDone)return 0;
        DestroyWindow(hwnd);return 0;
    case WM_TIMER: Refresh(); InvalidateRect(hwnd, NULL, FALSE); return 0;
    case WM_PAINT: Paint(hwnd); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_POINTERDOWN: case WM_POINTERUPDATE: case WM_POINTERUP: {
        POINTER_INFO info;
        if (GetPointerInfo(GET_POINTERID_WPARAM(w), &info) && info.pointerType == PT_TOUCH) {
            LastPoint = info.ptPixelLocation; ScreenToClient(hwnd, &LastPoint);
            if (msg == WM_POINTERDOWN) { DownCount++; TouchDown = TRUE; }
            else if (msg == WM_POINTERUP) { UpCount++; TouchDown = FALSE; }
            else MoveCount++;
            InvalidateRect(hwnd, NULL, FALSE);
            return 0;
        }
        break;
    }
    case WM_DISPLAYCHANGE:
        UpdateSceneFont(GetSystemMetrics(SM_CXSCREEN)>GetSystemMetrics(SM_CYSCREEN));
        SetWindowPos(hwnd, HWND_TOP, 0, 0, GetSystemMetrics(SM_CXSCREEN),
            GetSystemMetrics(SM_CYSCREEN), SWP_NOACTIVATE); return 0;
    case WM_KEYDOWN: if(w==VK_ESCAPE){SendMessageW(hwnd,WM_CLOSE,0,0);return 0;}break;
    case WM_DESTROY: KillTimer(hwnd, 1); PostQuitMessage(0); return 0;
    }
    return DefWindowProcW(hwnd, msg, w, l);
}

static void LifecycleFixture(void)
{
    N976N_LIFECYCLE_STATE *F;
    ZeroMemory(&Lifecycle,sizeof(Lifecycle));LifecyclePresence=2;
    Lifecycle.Version=N976N_LIFECYCLE_VERSION;Lifecycle.Bytes=sizeof(Lifecycle);
    Lifecycle.Valid=N976N_LIFECYCLE_VALID;Lifecycle.IdentityValid=1;
    Lifecycle.NvsAddress=0x93000000;Lifecycle.BootCounter=123;Lifecycle.CounterHz=26000000;
    Lifecycle.PrepareCount=2;Lifecycle.PrepareSuccessCount=1;Lifecycle.ClaimCount=1;
    Lifecycle.StartCount=1;Lifecycle.StopCount=2;Lifecycle.ReleaseCount=1;
    Lifecycle.D0EntryCount=1;Lifecycle.Origin=N976nLifeOriginRegistry;
    Lifecycle.RegistryState=N976nLifeRegistryRestored;Lifecycle.CurrentCallback=N976nLifePrepare;
    F=&Lifecycle.FirstFailure;F->Valid=1;F->Prepare=1;F->Callback=N976nLifeD0Entry;
    F->Stage=21;F->Status=0xC0000185;F->Claimed=F->Mapped=1;F->Command=0x52;F->HsiCurrent=1;
    F->Hsi.Status=4;F->Hsi.FirstPhase=3;F->Hsi.MessagesIssued=2;F->Hsi.TxBytes=1;
    F->Hsi.FirstFailure.Valid=1;F->Hsi.FirstFailure.Interrupt=0x200;
    F->Hsi.FirstFailure.Transfer=0x2000A;F->Hsi.FirstFailure.Fifo=0x100;F->Hsi.FirstFailure.Auto=0x80030003;
    Lifecycle.FirstStart=Lifecycle.FirstStartFailure=*F;
    Lifecycle.FirstStop=*F;Lifecycle.FirstStop.Callback=N976nLifeStartFailure;
    Lifecycle.FirstCleanup=*F;Lifecycle.FirstCleanup.Stage=40;Lifecycle.FirstCleanup.CleanupStatus=0;
    Lifecycle.FirstRelease=Lifecycle.FirstCleanup;Lifecycle.FirstRelease.Callback=N976nLifeReleaseHardware;
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void StartupFixture(BOOL Active)
{
    N976N_STARTUP_EVIDENCE *E;N976N_LIFECYCLE_STATE *F;
    LifecycleFixture();F=&Lifecycle.FirstStart;F->Stage=Active?29:25;F->Status=Active?0:0xC000009C;
    F->Id=0xAC3771;F->Command=0x60;
    ZeroMemory(&F->Hsi,sizeof(F->Hsi));F->Hsi.MessagesIssued=2;F->Hsi.TxBytes=1;F->Hsi.RxBytes=16;F->Hsi.Retired=1;
    E=&Lifecycle.FirstStartup;E->Phase=Active?N976nStartupComplete:N976nStartupFailed;
    E->InitPhase=Active?N976nInitComplete:N976nInitPost;E->Reason=Active?N976nStartupNone:N976nStartupUnknown;
    E->Reads=2;E->NonEmpty=2;E->Unknown=2;E->ElapsedUs=16700;
    E->PreChecks=E->PostChecks=15;E->PreAppValue=E->AppValue=0x20;E->PreFunctionValue=E->FunctionValue=0x61;
    E->SenseAttempted=E->SenseIssued=E->SenseCompleted=1;E->ClearAttempted=E->ClearIssued=E->ClearCompleted=1;
    E->First.Valid=1;E->First.Ordinal=1;E->First.Bytes=16;E->First.Class=1;
    E->First.Subtype=7;E->First.Id=1;E->First.Data=0x88;E->First.Remaining=31;E->First.Decoded=2;
    {const unsigned char raw[16]={0x1D,0x01,0x88,0xE7,0xA4,0xC6,0x08,0x1F,0x22,0x00,0x03,0xAD,0,0,0,0};CopyMemory(E->First.Raw,raw,16);}
    E->ObservedPackets=E->Remaining31Count=E->UnknownVendorCount=Active?2:1;E->FirstObservedMask=3;
    E->FirstObserved=E->FirstUnknownVendor=E->First;E->Last=E->First;E->Last.Ordinal=2;E->Last.Raw[3]=7;
    if(!Active){E->Last.Subtype=6;E->Last.Id=0x91;E->Last.Raw[0]=0x19;E->Last.Raw[1]=0x91;E->Rejected=E->Last;}
    if(Active){
        ZeroMemory(&Lifecycle.FirstFailure,sizeof(Lifecycle.FirstFailure));ZeroMemory(&Lifecycle.FirstStartFailure,sizeof(Lifecycle.FirstStartFailure));
        ZeroMemory(&Lifecycle.FirstStop,sizeof(Lifecycle.FirstStop));ZeroMemory(&Lifecycle.FirstCleanup,sizeof(Lifecycle.FirstCleanup));ZeroMemory(&Lifecycle.FirstRelease,sizeof(Lifecycle.FirstRelease));
        Lifecycle.PrepareCount=1;Lifecycle.ReleaseCount=Lifecycle.StopCount=0;
    }else{
        Lifecycle.FirstStartupFailure=*E;Lifecycle.FirstFailure=Lifecycle.FirstStartFailure=*F;
        Lifecycle.FirstStop=*F;Lifecycle.FirstStop.Callback=N976nLifeStartFailure;
        Lifecycle.FirstCleanup=*F;Lifecycle.FirstCleanup.Stage=40;Lifecycle.FirstRelease=Lifecycle.FirstCleanup;Lifecycle.FirstRelease.Callback=N976nLifeReleaseHardware;
    }
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void SplitObservationFixture(void)
{
    N976N_STARTUP_EVIDENCE *E;StartupFixture(TRUE);E=&Lifecycle.FirstStartup;
    E->First.Raw[0]=9;E->First.Raw[1]=1;E->First.Subtype=2;E->First.Id=1;
    E->FirstObserved=E->First;E->FirstObservedMask=1;E->FirstUnknownVendor=E->Last;
    E->Unknown=E->UnknownVendorCount=1;E->Status=1;
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void ClearFailureFixture(void)
{
    N976N_STARTUP_EVIDENCE *E;StartupFixture(FALSE);E=&Lifecycle.FirstStartup;
    E->InitPhase=N976nInitClear;E->Reason=N976nStartupClear;E->Reads=E->NonEmpty=E->Unknown=1;
    E->ClearCompleted=0;E->ClearStatus=0xC0000185;E->PostChecks=E->AppValue=E->FunctionValue=0;
    E->Last=E->First;ZeroMemory(&E->Rejected,sizeof(E->Rejected));
    Lifecycle.FirstStartupFailure=*E;Lifecycle.FirstStart.Command=0x62;
    Lifecycle.FirstStart.Hsi.MessagesIssued=1;Lifecycle.FirstStart.Hsi.TxBytes=1;Lifecycle.FirstStart.Hsi.RxBytes=0;
    Lifecycle.FirstStart.Hsi.Status=5;Lifecycle.FirstStart.Hsi.Retired=0;Lifecycle.FirstStart.Hsi.Quarantined=1;
    Lifecycle.FirstStart.Quarantined=1;Lifecycle.FirstStart.Status=0xC0000185;
    Lifecycle.FirstStartFailure=Lifecycle.FirstFailure=Lifecycle.FirstStart;
    Lifecycle.FirstStop=Lifecycle.FirstStart;Lifecycle.FirstStop.Callback=N976nLifeStartFailure;
    Lifecycle.FirstRelease=Lifecycle.FirstStart;Lifecycle.FirstRelease.Callback=N976nLifeReleaseHardware;
    Lifecycle.FirstCleanupFailure=Lifecycle.FirstStart;Lifecycle.FirstCleanupFailure.CleanupStatus=0xC0000185;
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void RxWaitFixture(unsigned Exit)
{
    N976N_LIFECYCLE_STATE *F;N976N_HSI_WAIT *W;StartupFixture(TRUE);
    F=&Lifecycle.FirstFailure;*F=Lifecycle.FirstStart;F->Callback=N976nLifePoll;
    F->Stage=90;F->Status=Exit==N976nWaitClock?0xC0000185:0xC00000B5;
    F->Hsi.Status=Exit==N976nWaitClock?N976nHsiClock:N976nHsiTimeout;F->Hsi.FirstPhase=5;F->Hsi.RxBytes=0;
    W=&F->Hsi.Wait;W->Valid=1;W->MessageIndex=2;W->Receive=1;W->Requested=16;W->RunIssued=1;
    W->ClockStarted=1;W->StartUs=1000000;W->PreviousUs=Exit==N976nWaitDeadline?1099999:1000010;W->LastNowUs=Exit==N976nWaitClock?1000009:Exit==N976nWaitDeadline?1100000:1000010;
    W->ElapsedUs=Exit==N976nWaitDeadline?100000:Exit==N976nWaitClock?0:10;W->Iterations=W->ClockChecks=Exit==N976nWaitClockStall?20020:60000;
    W->SameClock=W->MaxSameClock=Exit==N976nWaitClockStall?20000:0;
    W->Exit=Exit;W->Status=F->Hsi.Status;W->Phase=5;
    W->First.Valid=W->Last.Valid=15;W->First.Transfer=W->Last.Transfer=0x80001;
    W->First.Fifo=W->Last.Fifo=0x01000100;W->First.Auto=0x80030010;W->Last.Auto=0x30010;W->First.Transfer=0xA0002;W->Seen=3;
    W->RunClear.Iteration=100;W->RunClear.Sample=W->First;W->RunClear.Sample.Auto=W->Last.Auto;
    W->BusyClear.Iteration=102;W->BusyClear.Sample=W->Last;
    F->Hsi.Boundary[0]=(N976N_HSI_BOUNDARY){1023,0,0,N976N_HSI_COMPLETION_MASK,N976N_HSI_COMPLETION_MASK,0x80,0,0x80,0};
    F->Hsi.Boundary[1]=(N976N_HSI_BOUNDARY){15,0,0,N976N_HSI_COMPLETION_MASK,N976N_HSI_COMPLETION_MASK,0,0,0,0};
    F->Hsi.Boundary[2]=(N976N_HSI_BOUNDARY){752,0,0,0,0,0,0,0,0};
    F->Hsi.FirstFailure=W->Last;
    Lifecycle.FirstStop=*F;Lifecycle.FirstStop.Callback=N976nLifePollFailure;
    Lifecycle.FirstCleanup=*F;Lifecycle.FirstCleanup.CleanupStatus=0;Lifecycle.StopCount=1;
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
/* Layout stress only: combine separately valid failure evidence which may coexist. */
static void DenseFailureFixture(BOOL Startup)
{
    N976N_HSI_RESULT H;N976N_LIFECYCLE_STATE *F;
    RxWaitFixture(N976nWaitClock);H=Lifecycle.FirstFailure.Hsi;
    if(Startup){StartupFixture(FALSE);Lifecycle.FirstFailure.Hsi=H;Lifecycle.FirstFailure.Status=0xC0000185;}
    F=&Lifecycle.FirstFailure;F->Hsi.FirstFailure.Interrupt=0x200;
    Lifecycle.FirstStop=*F;Lifecycle.FirstStop.Callback=Startup?N976nLifeStartFailure:N976nLifePollFailure;
    Lifecycle.FirstCleanupFailure=*F;Lifecycle.FirstCleanupFailure.CleanupStatus=0xC0000185;
    Lifecycle.FirstCleanupFailure.Quarantined=1;
    Lifecycle.FirstRelease=*F;Lifecycle.FirstRelease.Callback=N976nLifeReleaseHardware;
    Lifecycle.FirstRelease.Stage=40;Lifecycle.ReleaseCount=1;
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
    DiagnosticPresence=2;Diagnostic.Version=1;Diagnostic.Bytes=sizeof(Diagnostic);Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;
    Diagnostic.Bucket=N976nDiagNvs;Diagnostic.Condition=N976nWhyReady;Diagnostic.Index=5;Diagnostic.Offset=0x180;
    Diagnostic.Expected=0;Diagnostic.Actual=3;Diagnostic.Mask=~0ULL;Diagnostic.MappedCount=7;Diagnostic.ReadOk=1;
}
static void RecoveryFixture(BOOL Exhausted)
{
    N976N_LIFECYCLE_STATE F;N976N_HSI_RESULT *H=&F.Hsi;N976N_HSI_WAIT *W=&H->Wait;
    StartupFixture(TRUE);F=Lifecycle.FirstStart;F.Stage=90;F.Status=0xC0000483;
    F.Callback=N976nLifePoll;H->Status=N976nHsiController;H->FirstPhase=5;H->RxBytes=0;
    W->Valid=W->Receive=W->RunIssued=W->ClockStarted=1;W->MessageIndex=2;W->Requested=16;
    W->Exit=N976nWaitOther;W->Seen=3|16;W->Status=N976nHsiController;W->Phase=5;
    W->Iterations=1;W->StartUs=1000;
    W->First=W->Last=(N976N_HSI_SAMPLE){0x400,0xA0003,0x01000100,0x80030010,15};
    H->FirstFailure=W->Last;H->Last=(N976N_HSI_SAMPLE){0,1,0x01000100,0x30010,15};
    H->Boundary[0]=(N976N_HSI_BOUNDARY){1023,0,0,0xF80,0xF80,0x80,0,0x80,0};
    H->Boundary[1]=(N976N_HSI_BOUNDARY){15,0,0,0xF80,0xF80,0,0,0,0};
    H->Boundary[2]=(N976N_HSI_BOUNDARY){1008,0,0,0,0,0x400,0,0x400,0};
    Lifecycle.Recovery.Requests=141;Lifecycle.Recovery.Faults=Exhausted?3:1;
    Lifecycle.Recovery.Retries=Exhausted?2:1;Lifecycle.Recovery.Recovered=Exhausted?0:1;
    Lifecycle.Recovery.Exhausted=Exhausted?1:0;Lifecycle.Recovery.Attempt=Exhausted?3:2;
    Lifecycle.Recovery.Outcome=Exhausted?N976nRecoveryExhausted:N976nRecoveryRecovered;
    Lifecycle.Recovery.FirstTransient=F;Lifecycle.Recovery.LastAttempt=Exhausted?F:Lifecycle.FirstStart;
    Lifecycle.Recovery.LastAttempt.Callback=N976nLifePoll;
    if(Exhausted){Lifecycle.FirstFailure=F;Lifecycle.FirstStop=F;Lifecycle.FirstStop.Callback=N976nLifePollFailure;Lifecycle.FirstCleanup=F;Lifecycle.StopCount=1;}
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void BatchFixture(unsigned Kind)
{
    StartupFixture(TRUE);
    Lifecycle.Service=(N976N_EVENT_SERVICE){171,120,1,1,170,2600,30,31,480,0};
    if(Kind==1){
        RxWaitFixture(N976nWaitDeadline);
        Lifecycle.Service=(N976N_EVENT_SERVICE){171,120,0,0,170,2600,30,31,480,0};
        Lifecycle.FirstFailure.Command=0x61;Lifecycle.FirstFailure.Hsi.Wait.Requested=480;
        Lifecycle.FirstFailure.Hsi.RxBytes=479;
        Lifecycle.FirstFailure.Hsi.Wait.First.Auto=0x800301E0;Lifecycle.FirstFailure.Hsi.Wait.Last.Auto=0x301E0;
        Lifecycle.FirstFailure.Hsi.Wait.RunClear.Sample.Auto=0x301E0;Lifecycle.FirstFailure.Hsi.Wait.BusyClear.Sample.Auto=0x301E0;
        Lifecycle.FirstFailure.Hsi.FirstFailure=Lifecycle.FirstFailure.Hsi.Wait.Last;
        Lifecycle.FirstStop=Lifecycle.FirstFailure;Lifecycle.FirstStop.Callback=N976nLifePollFailure;
    }else if(Kind==2){Lifecycle.Service.LastRemaining=31;Lifecycle.Service.LastCount=Lifecycle.Service.LastBytes=0;}
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void TailFixture(unsigned Kind)
{
    N976N_LIFECYCLE_STATE F;RecoveryFixture(FALSE);F=Lifecycle.Recovery.FirstTransient;
    F.Command=0x61;F.Stage=29;F.Hsi.Wait.Requested=480;
    F.Hsi.Wait.First.Auto=F.Hsi.Wait.Last.Auto=0x800301E0;
    F.Hsi.FirstFailure=F.Hsi.Wait.Last;F.Hsi.Last.Auto=0x301E0;
    Lifecycle.Service=(N976N_EVENT_SERVICE){173,122,0,0,170,2600,30,31,480,0};
    Lifecycle.Tail.Faults=Kind==2?3:1;Lifecycle.Tail.Deferred=Kind==2?2:1;
    Lifecycle.Tail.Streak=Kind==2?3:Kind==1?0:1;Lifecycle.Tail.Resumed=Kind==1?1:0;
    Lifecycle.Tail.AwaitingFresh=Kind==1?0:1;
    Lifecycle.Tail.Disposition=Kind==2?N976nTailTerminal:Kind==1?N976nTailResumed:N976nTailDeferred;
    Lifecycle.Tail.Decision=Kind==2?N976nTailLimit:N976nTailSafe;
    Lifecycle.Tail.ResumeOrdinal=Kind==1?173:0;Lifecycle.Tail.Fatal=Kind==2?1:0;
    Lifecycle.Tail.FirstDeferred.Ordinal=171;Lifecycle.Tail.FirstDeferred.Remaining=30;
    Lifecycle.Tail.FirstDeferred.Requested=480;Lifecycle.Tail.FirstDeferred.FirstPacket[0]=0x44;
    Lifecycle.Tail.FirstDeferred.FirstPacket[7]=30;Lifecycle.Tail.FirstDeferred.State=F;
    Lifecycle.Tail.LastFailure=Lifecycle.Tail.FirstDeferred;
    if(Kind==2){
        F.Stage=90;Lifecycle.FirstFailure=F;Lifecycle.Tail.LastFailure.State=F;Lifecycle.Tail.LastFailure.Ordinal=173;
        Lifecycle.FirstStop=F;Lifecycle.FirstCleanup=F;Lifecycle.FirstRelease=F;
        DiagnosticPresence=2;Diagnostic.Version=N976N_DIAGNOSTIC_VERSION;Diagnostic.Bytes=sizeof(Diagnostic);
        Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;Diagnostic.Bucket=N976nDiagClaim;Diagnostic.Condition=N976nWhyReady;
        Diagnostic.Expected=0;Diagnostic.Actual=2;Diagnostic.Offset=0x180;Diagnostic.ReadOk=1;Diagnostic.MappedCount=7;
    }
    if(Kind==3){
        ZeroMemory(&Lifecycle.Tail.FirstDeferred,sizeof(Lifecycle.Tail.FirstDeferred));
        Lifecycle.Tail.Faults=Lifecycle.Tail.Fatal=1;Lifecycle.Tail.Deferred=Lifecycle.Tail.Resumed=Lifecycle.Tail.Streak=Lifecycle.Tail.AwaitingFresh=0;
        Lifecycle.Tail.Disposition=N976nTailTerminal;Lifecycle.Tail.Decision=N976nTailTransport;
        F.Stage=90;F.Status=0xC00000A3;F.HsiCurrent=0;F.Quarantined=1;
        Lifecycle.Tail.LastFailure.State=F;Lifecycle.FirstFailure=Lifecycle.FirstStop=F;
        Lifecycle.FirstCleanup=F;Lifecycle.FirstCleanup.CleanupStatus=0;
        Lifecycle.FirstCleanupFailure=F;Lifecycle.FirstCleanupFailure.CleanupStatus=0xC0000483;
    }
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void ReadyFixture(unsigned Kind)
{
    /* Reuse the dense failed61 screen, keeping real first-fault operands. */
    TailFixture(Kind==2?2:1);
    Lifecycle.Ready=(N976N_EVENT_READY){300,174,126,0,1,Kind?0:1,1,0x20,1,0x40};
    if(Kind==3){
        TailFixture(3);Lifecycle.Ready=(N976N_EVENT_READY){1,0,0,1,0,0,0,0,0,0};
        Lifecycle.FirstFailure.Command=0x60;Lifecycle.FirstFailure.HsiCurrent=0;
        DiagnosticPresence=2;Diagnostic.Version=N976N_DIAGNOSTIC_VERSION;Diagnostic.Bytes=sizeof(Diagnostic);
        Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;Diagnostic.Bucket=N976nDiagFresh;Diagnostic.Condition=N976nWhyRead;
        Diagnostic.Index=6;Diagnostic.Offset=0x24;Diagnostic.Expected=1;Diagnostic.Actual=0;Diagnostic.MappedCount=7;Diagnostic.ReadOk=0;
    }
    Lifecycle.Crc32=LifecycleCrc(&Lifecycle);
}
static void UpdateSceneFont(BOOL Landscape)
{
    HFONT Old=Font;LineGap=Landscape?0:10; /* Preserve font and safe area; dense evidence needs vertical space. */
    Font=CreateFontW(UiFixture?(Landscape?22:28):(Landscape?24:32),0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,CLEARTYPE_QUALITY,DEFAULT_PITCH,L"Segoe UI");
    if(Old)DeleteObject(Old);
}
static int DiagnosticSelfTest(void)
{
    N976N_DEMO_DIAGNOSTIC D={0};int Count=0;
    D.Version=1;D.Bytes=sizeof(D);
    if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=1)return 1;++Count;
    D.Valid=N976N_DIAGNOSTIC_VALID;D.Bucket=N976nDiagFresh;D.Condition=N976nWhyEqual;D.ReadOk=1;
    if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=2)return 2;++Count;
    if(DiagnosticClass(&D,REG_DWORD,sizeof(D))!=3||DiagnosticClass(&D,REG_BINARY,sizeof(D)-1)!=3)return 3;++Count;
    D.Version=2;if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=3)return 4;D.Version=1;++Count;
    D.Valid=1;if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=3)return 5;D.Valid=N976N_DIAGNOSTIC_VALID;++Count;
    D.Reserved=1;if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=3)return 6;D.Reserved=0;++Count;
    D.Condition=N976nWhyAtomic+1;if(DiagnosticClass(&D,REG_BINARY,sizeof(D))!=3)return 7;D.Condition=N976nWhyEqual;++Count;
    if(SafeInset(1440,3040)!=120||SafeInset(3040,1440)!=120||SafeInset(800,600)<72)return 8;++Count;
    LifecycleFixture();
    if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 9;++Count;
    Lifecycle.FirstFailure.Status^=1;if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 10;++Count;LifecycleFixture();
    if(LifecycleClass(&Lifecycle,REG_DWORD,sizeof(Lifecycle))!=3||LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle)-1)!=3)return 11;++Count;
    Lifecycle.NvsAddress=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 12;++Count;LifecycleFixture();
    Lifecycle.IdentityValid=0;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 13;++Count;LifecycleFixture();
    Lifecycle.FirstFailure.HsiCurrent=2;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 14;++Count;LifecycleFixture();
    Lifecycle.FirstFailure.Reserved=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 15;++Count;
    StartupFixture(FALSE);
    if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 16;++Count;
    Lifecycle.FirstStartupFailure.Rejected.Raw[3]^=1;if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 17;++Count;StartupFixture(FALSE);
    Lifecycle.Version=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 18;++Count;StartupFixture(FALSE);
    Lifecycle.FirstStartupFailure.Rejected.Bytes=17;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 19;++Count;StartupFixture(FALSE);
    Lifecycle.FirstStartupFailure.Rejected.Ordinal=4;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 20;++Count;StartupFixture(FALSE);
    Lifecycle.FirstStartupFailure.Reason=N976nStartupReservedReason;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 21;++Count;StartupFixture(FALSE);
    Lifecycle.FirstStartupFailure.PostChecks=16;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 22;++Count;StartupFixture(FALSE);
    Lifecycle.FirstStartupFailure.Rejected.Bytes=7;Lifecycle.FirstStartupFailure.Rejected.Decoded=-1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 23;++Count;
    StartupFixture(TRUE);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 24;++Count;
    Lifecycle.FirstStartup.ObservedPackets=34;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 25;++Count;StartupFixture(TRUE);
    Lifecycle.FirstStartup.FirstObservedMask=4;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 26;++Count;StartupFixture(TRUE);
    Lifecycle.FirstStartup.FirstObserved.Raw[7]=0;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 27;++Count;StartupFixture(TRUE);
    Lifecycle.FirstStartup.FirstUnknownVendor.Subtype=2;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 28;++Count;StartupFixture(TRUE);
    Lifecycle.FirstStartup.FirstUnknownVendor.Valid=0;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 29;++Count;StartupFixture(TRUE);
    Lifecycle.Version=2;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 30;++Count;
    SplitObservationFixture();if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 31;++Count;
    ClearFailureFixture();if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 32;++Count;
    Lifecycle.FirstStartupFailure.ClearCompleted=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 33;++Count;
    StartupFixture(TRUE);Lifecycle.FirstStartup.AppValue=0x10;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 34;++Count;
    StartupFixture(TRUE);Lifecycle.FirstStartup.FunctionValue^=2;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 35;++Count;
    StartupFixture(TRUE);Lifecycle.FirstStartup.PreAppStatus=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 36;++Count;
    StartupFixture(TRUE);Lifecycle.FirstStartup.InitPhase=N976nInitPre;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 37;++Count;
    RxWaitFixture(N976nWaitDeadline);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 38;++Count;
    RxWaitFixture(N976nWaitClockStall);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 39;++Count;
    RxWaitFixture(N976nWaitClock);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 40;++Count;
    Lifecycle.FirstFailure.Hsi.Wait.ElapsedUs=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 41;++Count;
    RxWaitFixture(N976nWaitDeadline);Lifecycle.FirstFailure.Hsi.Wait.Exit=N976nWaitClockStall;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 42;++Count;
    RxWaitFixture(N976nWaitDeadline);Lifecycle.FirstFailure.Callback=99;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 43;++Count;
    RxWaitFixture(N976nWaitDeadline);Lifecycle.Version=6;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 44;++Count;
    RxWaitFixture(N976nWaitDeadline);Lifecycle.FirstFailure.Hsi.Boundary[1].ArmRead=0x80;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 45;++Count;
    RxWaitFixture(N976nWaitDeadline);Lifecycle.FirstFailure.Hsi.Boundary[0].Valid=767;Lifecycle.FirstFailure.Hsi.Boundary[0].Pending=0;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 46;++Count;
    RecoveryFixture(FALSE);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 47;++Count;
    RecoveryFixture(TRUE);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 48;++Count;
    Lifecycle.Recovery.Attempt=4;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 49;++Count;
    RecoveryFixture(TRUE);Lifecycle.Recovery.FirstTransient.Hsi.RxBytes=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 50;++Count;
    RecoveryFixture(TRUE);Lifecycle.Recovery.LastAttempt.Reserved=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 51;++Count;
    RecoveryFixture(TRUE);Lifecycle.Version=7;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 52;++Count;
    BatchFixture(0);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 53;++Count;
    BatchFixture(1);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 54;++Count;
    Lifecycle.Service.LastBytes=496;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 55;++Count;
    BatchFixture(2);Lifecycle.Version=8;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 56;++Count;
    TailFixture(0);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 57;++Count;
    TailFixture(1);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 58;++Count;
    TailFixture(2);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 59;++Count;
    Lifecycle.Tail.FirstDeferred.State.Hsi.RxBytes=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 60;++Count;
    TailFixture(0);Lifecycle.Tail.Streak=3;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 61;++Count;
    TailFixture(1);Lifecycle.Tail.ResumeOrdinal=170;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 62;++Count;
    TailFixture(0);Lifecycle.Version=9;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 63;++Count;
    TailFixture(3);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 64;++Count;
    for(unsigned K=0;K<4;++K){ReadyFixture(K);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 65;++Count;}
    Lifecycle.Ready.LastValid=2;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 66;++Count;
    ReadyFixture(0);Lifecycle.Ready.FirstErrorRaw=1;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 67;++Count;
    ReadyFixture(0);Lifecycle.Version=10;Lifecycle.Crc32=LifecycleCrc(&Lifecycle);if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=3)return 68;++Count;
    printf("PASS %d diagnostic viewer groups; no device or registry mutation\n",Count);return 0;
}

int WINAPI wWinMain(HINSTANCE instance,HINSTANCE previous,PWSTR cmd,int show)
{
    WNDCLASSW wc={0};HWND window;MSG msg;BOOL result;int exitCode=0;
    UNREFERENCED_PARAMETER(previous);UNREFERENCED_PARAMETER(show);
    if(wcscmp(cmd,L"--verify-own-package")==0||wcscmp(cmd,L"\"--verify-own-package\"")==0)return (int)N976nStartupVerifyOwnPackage();
    if(wcscmp(cmd,L"--diagnostic-self-test")==0||wcscmp(cmd,L"\"--diagnostic-self-test\"")==0)return DiagnosticSelfTest();
    if(wcscmp(cmd,L"--self-test")==0||wcscmp(cmd,L"\"--self-test\"")==0)return N976nStartupSelfTest();
    InitializeCriticalSection(&StateLock);StageTick=GetTickCount64();PeStart=wcscmp(cmd,L"--pe-start")==0||wcscmp(cmd,L"\"--pe-start\"")==0;
    if(wcscmp(cmd,L"--smoke")==0||wcscmp(cmd,L"\"--smoke\"")==0){Refresh();DeleteCriticalSection(&StateLock);return 0;}
    if(wcsstr(cmd,L"--ui-test-ready-")){
        unsigned kind=wcsstr(cmd,L"ready-low")?1:wcsstr(cmd,L"ready-terminal")?2:wcsstr(cmd,L"ready-refusal")?3:0;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,kind==1?L"ready-low-landscape":kind==2?L"ready-terminal-landscape":kind==3?L"ready-refusal-landscape":L"ready-high-landscape");
        ReadyFixture(kind);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=kind>=2?90:29;Values[1]=kind==1?0:kind==3?0xC00000A3:0xC0000483;Values[2]=0xAC3771;Values[3]=295;Values[4]=2600;PnpProblem=0;
        if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 11;
    }
    else if(wcsstr(cmd,L"--ui-test-tail-")){
        unsigned kind=wcsstr(cmd,L"tail-resumed")?1:wcsstr(cmd,L"tail-terminal")?2:wcsstr(cmd,L"tail-admission")?3:0;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,kind==1?L"tail-resumed-landscape":kind==2?L"tail-terminal-landscape":kind==3?L"tail-admission-landscape":L"tail-deferred-landscape");
        TailFixture(kind);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=kind>=2?90:29;Values[1]=kind==1?0:kind==3?0xC00000A3:0xC0000483;Values[2]=0xAC3771;Values[3]=295;Values[4]=2600;PnpProblem=0;
        if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 11;
    }
    else if(wcsstr(cmd,L"--ui-test-batch-")){
        unsigned kind=wcsstr(cmd,L"batch-tail")?1:wcsstr(cmd,L"batch-overflow")?2:0;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,kind==1?L"batch-tail-failure-landscape":kind==2?L"batch-overflow-landscape":L"batch-active-landscape");
        BatchFixture(kind);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=kind==1?90:29;Values[1]=kind==1?0xC00000B5:0;Values[2]=0xAC3771;Values[3]=291;Values[4]=2600;PnpProblem=0;
        if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 11;
    }
    else     if(wcsstr(cmd,L"--ui-test-recovery-")){
        BOOL exhausted=wcsstr(cmd,L"recovery-exhausted")!=NULL;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,exhausted?L"recovery-exhausted-landscape":L"recovery-active-landscape");
        RecoveryFixture(exhausted);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=exhausted?90:29;Values[1]=exhausted?0xC0000483:0;Values[2]=0xAC3771;Values[3]=141;Values[4]=135;PnpProblem=0;
        if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 11;
    }
    else     if(wcsstr(cmd,L"--ui-test-dense-")){
        BOOL startup=wcsstr(cmd,L"dense-startup")!=NULL;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,startup?L"dense-startup-landscape":L"dense-rx-landscape");
        DenseFailureFixture(startup);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=12;Values[1]=0xC0000182;PnpProblem=10;
        if(LifecycleClass(&Lifecycle,REG_BINARY,sizeof(Lifecycle))!=2)return 11;
    }
    else     if(wcsstr(cmd,L"--ui-test-rx-")){
        BOOL landscape=wcsstr(cmd,L"landscape")!=NULL;
        unsigned kind=wcsstr(cmd,L"rx-loop")?N976nWaitClockStall:wcsstr(cmd,L"rx-clock")?N976nWaitClock:N976nWaitDeadline;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,landscape?L"rx-wall-landscape":kind==N976nWaitClockStall?L"rx-loop":kind==N976nWaitClock?L"rx-clock":L"rx-wall");
        RxWaitFixture(kind);StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=90;Values[1]=Lifecycle.FirstFailure.Status;Values[2]=0xAC3771;PnpProblem=0;
    }
    else    if(wcsstr(cmd,L"--ui-test-startup-")){
        BOOL clear=wcsstr(cmd,L"startup-clear")!=NULL;
        BOOL split=wcsstr(cmd,L"startup-split")!=NULL;
        BOOL active=split||wcsstr(cmd,L"startup-active")!=NULL;
        UiFixture=TRUE;wcscpy_s(FixtureName,32,clear?L"startup-clear-landscape":split?L"startup-split-landscape":active?L"startup-active-landscape":wcsstr(cmd,L"landscape")?L"startup-event-landscape":L"startup-event");
        if(clear)ClearFailureFixture();else if(split)SplitObservationFixture();else StartupFixture(active);
        StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=active?29:12;Values[1]=active?0:0xC0000182;Values[2]=active?0xAC3771:0;PnpProblem=active?0:10;
        if(!active){
            DiagnosticPresence=2;Diagnostic.Version=1;Diagnostic.Bytes=sizeof(Diagnostic);Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;
            Diagnostic.Bucket=N976nDiagNvs;Diagnostic.Condition=N976nWhyReady;Diagnostic.Index=5;Diagnostic.Offset=0x180;
            Diagnostic.Expected=0;Diagnostic.Actual=clear?3:2;Diagnostic.Mask=~0ULL;Diagnostic.MappedCount=7;Diagnostic.ReadOk=1;
        }else{Values[3]=123;Values[4]=7;Values[5]=1234;Values[6]=2345;Values[7]=2;DownCount=1;MoveCount=6;TouchDown=TRUE;LastPoint.x=1100;LastPoint.y=800;}
    }
    else if(wcsstr(cmd,L"--ui-test-lifecycle")){
        UiFixture=TRUE;wcscpy_s(FixtureName,32,wcsstr(cmd,L"landscape")?L"lifecycle-landscape":L"lifecycle");
        LifecycleFixture();StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;
        Values[0]=12;Values[1]=0xC0000182;PnpProblem=10;
        DiagnosticPresence=2;Diagnostic.Version=1;Diagnostic.Bytes=sizeof(Diagnostic);Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;
        Diagnostic.Bucket=N976nDiagNvs;Diagnostic.Condition=N976nWhyReady;Diagnostic.Index=5;Diagnostic.Offset=0x180;
        Diagnostic.Expected=0;Diagnostic.Actual=2;Diagnostic.Mask=~0ULL;Diagnostic.MappedCount=7;Diagnostic.ReadOk=1;
    }
    else if(wcsstr(cmd,L"--ui-test-resource")||wcsstr(cmd,L"--ui-test-landscape")){
        UiFixture=TRUE;wcscpy_s(FixtureName,32,wcsstr(cmd,L"landscape")?L"landscape":L"resource");
        StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;Values[0]=12;Values[1]=0xC0000182;PnpProblem=10;
        DiagnosticPresence=2;Diagnostic.Version=1;Diagnostic.Bytes=sizeof(Diagnostic);Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;
        Diagnostic.Bucket=N976nDiagResource;Diagnostic.Condition=N976nWhyFlagsMask;Diagnostic.Index=0;
        Diagnostic.Expected=0;Diagnostic.Actual=0x20;Diagnostic.Mask=0xFFFE;
        Diagnostic.RawType=Diagnostic.TransType=3;Diagnostic.RawShare=Diagnostic.TransShare=1;
        Diagnostic.RawFlags=Diagnostic.TransFlags=0x20;Diagnostic.RawStart=Diagnostic.TransStart=0x104B0000;
        Diagnostic.RawLength=Diagnostic.TransLength=0x1000;Diagnostic.RawCount=Diagnostic.TransCount=6;Diagnostic.ReadOk=1;
    }
    else if(wcsstr(cmd,L"--ui-test-fresh")){
        UiFixture=TRUE;wcscpy_s(FixtureName,32,L"fresh");StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;Values[0]=12;Values[1]=0xC0000182;
        DiagnosticPresence=2;Diagnostic.Version=1;Diagnostic.Bytes=sizeof(Diagnostic);Diagnostic.Valid=N976N_DIAGNOSTIC_VALID;
        Diagnostic.Bucket=N976nDiagFresh;Diagnostic.Condition=N976nWhyEqual;Diagnostic.Index=1;Diagnostic.Offset=0x2008;
        Diagnostic.Expected=0x300001;Diagnostic.Actual=0x100001;Diagnostic.Mask=0xFFFFFFFF;Diagnostic.MappedCount=7;Diagnostic.ReadOk=1;
    }
    else if(wcsstr(cmd,L"--ui-test-missing")) {UiFixture=TRUE;wcscpy_s(FixtureName,32,L"missing");StartupStage=N976nObserve;PnpQuery=CR_NO_SUCH_DEVNODE;}
    else if(wcsstr(cmd,L"--ui-test-error")) {UiFixture=TRUE;wcscpy_s(FixtureName,32,L"error");StartupStage=N976nDriverLoad;StartupExit=ERROR_ACCESS_DENIED;}
    else if(wcsstr(cmd,L"--ui-test-active")) {UiFixture=TRUE;wcscpy_s(FixtureName,32,L"active");StartupStage=N976nObserve;PnpPresent=TRUE;Present=0x7ff;Values[0]=29;Values[2]=0xAC3771;Values[3]=123;Values[4]=7;Values[5]=1234;Values[6]=2345;Values[7]=2;DownCount=1;MoveCount=6;TouchDown=TRUE;LastPoint.x=600;LastPoint.y=800;}
    if(UiFixture)wcscpy_s(StartupMessage,256,StartupExit?L"Stopped here. No automatic retry; diagnostics remain visible.":L"Fixture: startup reached observation; input is a separate result.");
    SetProcessDPIAware();
    UpdateSceneFont(UiFixture?wcsstr(FixtureName,L"landscape")!=NULL:GetSystemMetrics(SM_CXSCREEN)>GetSystemMetrics(SM_CYSCREEN));
    /* prlctl's noninteractive desktop is not a display visibility test. Render
     * the exact production scene to an owned DIB; real first-paint is VM tested. */
    if(UiFixture){exitCode=SaveFixture()?0:9;goto Done;}
    wc.hInstance=instance;wc.lpfnWndProc=WindowProc;wc.lpszClassName=L"N976nTouchDemo76Exp9";wc.hCursor=LoadCursorW(NULL,IDC_ARROW);
    if(!RegisterClassW(&wc)){exitCode=2;goto Done;}
    window=CreateWindowExW(WS_EX_APPWINDOW,wc.lpszClassName,L"N976N Touch Demo EXP9",WS_POPUP|WS_VISIBLE,0,0,
        UiFixture?1000:GetSystemMetrics(SM_CXSCREEN),UiFixture?1100:GetSystemMetrics(SM_CYSCREEN),NULL,NULL,instance,NULL);
    if(!window){exitCode=3;goto Done;}
    ShowWindow(window,SW_SHOW);UpdateWindow(window);
    while((result=GetMessageW(&msg,NULL,0,0))>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
    exitCode=result<0?4:(int)msg.wParam;
    if(Worker) {
        /* A broken message loop must not leave an invisible endless bootstrap.
         * Exiting this owned app closes its kill-on-close child job handles. */
        if(WaitForSingleObject(Worker,10000)!=WAIT_OBJECT_0)ExitProcess(ERROR_TIMEOUT);
        CloseHandle(Worker);
    }
    if(IsWindow(window))DestroyWindow(window);
Done:
    DeleteObject(Font);DeleteCriticalSection(&StateLock);return exitCode;
}
