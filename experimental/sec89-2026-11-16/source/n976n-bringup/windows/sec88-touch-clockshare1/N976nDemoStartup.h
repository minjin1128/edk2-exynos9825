/* SPDX-License-Identifier: GPL-2.0-only
 * Bounded, diagnostic-only startup FIFO evidence. No access authority.
 * Sharing the pure shape check keeps kernel restore and viewer interpretation
 * identical. Raw bytes are sequential packet data, not atomic MMIO snapshots.
 */
#ifndef N976N_DEMO_STARTUP_H
#define N976N_DEMO_STARTUP_H
#define N976N_STARTUP_READ_LIMIT 2U /* PRE and POST snapshots; no drain loop. */
/* Unchanged local admission budget. Existing bounded idle and
 * retirement waits may finish after it; it is not a hard execution deadline. */
#define N976N_STARTUP_DEADLINE_US 6400000ULL
enum { N976nStartupNotRun=0, N976nStartupObserving=1,
       N976nStartupComplete=2, N976nStartupFailed=3 };
enum { N976nStartupNone=0, N976nStartupTransfer=1, N976nStartupChipError=2,
       N976nStartupMalformed=3, N976nStartupUnknown=4,
       N976nStartupReservedReason=5, N976nStartupOverflow=6,
       N976nStartupReadLimit=7, N976nStartupDeadline=8,
       N976nStartupAppState=9, N976nStartupFunctionState=10, N976nStartupSense=11, N976nStartupClear=12,
       N976nStartupPostBoot=13 };
enum { N976nInitNone=0, N976nInitPre=1, N976nInitPreState=2,
       N976nInitSense=3, N976nInitClear=4, N976nInitPostState=5,
       N976nInitPost=6, N976nInitComplete=7 };
enum { N976nObserveRemaining31=1, N976nObserveUnknownVendor=2 };
#pragma pack(push,8)
typedef struct {
    unsigned int Valid,Ordinal,Bytes,Class,Subtype,Id,Data,Remaining;
    int Decoded;
    unsigned int Reserved;
    unsigned char Raw[16];
} N976N_STARTUP_PACKET;
typedef struct {
    unsigned int Phase,Reason,Reads,NonEmpty,Empty,Coordinate,Status,Gesture;
    unsigned int Boot,Error,Unknown,Malformed,TransferStatus,Reserved;
    unsigned int PostChecks,AppStatus,AppValue,FunctionStatus,FunctionValue,PostReserved;
    /* EXP1 observations are not a claim that the packet is understood/safe.
     * Unknown vendor remains separate from source-defined Status count. */
    unsigned int ObservedPackets,Remaining31Count,UnknownVendorCount,FirstObservedMask;
    unsigned int InitPhase,PreChecks,PreAppStatus,PreAppValue,PreFunctionStatus,PreFunctionValue;
    unsigned int SenseAttempted,SenseIssued,SenseCompleted,SenseStatus;
    unsigned int ClearAttempted,ClearIssued,ClearCompleted,ClearStatus;
    unsigned long long ElapsedUs;
    N976N_STARTUP_PACKET First,Last,Rejected;
    N976N_STARTUP_PACKET FirstObserved,FirstUnknownVendor;
} N976N_STARTUP_EVIDENCE;
#pragma pack(pop)
static __inline int N976nStartupKnownVendorId(unsigned int Id)
{
    switch(Id){case 0:case 0x40:case 0x41:case 0x42:case 0x43:case 0x44:
    case 0x46:case 0x47:case 0x58:case 0x61:case 0x64:case 0x6A:case 0x6D:return 1;}
    return 0;
}
static __inline int N976nStartupShape(const N976N_STARTUP_EVIDENCE *E)
{
    const N976N_STARTUP_PACKET *P[5]={&E->First,&E->Last,&E->Rejected,&E->FirstObserved,&E->FirstUnknownVendor};
    if(E->Phase>N976nStartupFailed||E->Reason>N976nStartupPostBoot||E->Reason==5||E->Reserved||
       E->InitPhase>N976nInitComplete||E->PreChecks>15||E->PreAppValue>255||E->PreFunctionValue>65535||
       E->SenseAttempted>1||E->SenseIssued>E->SenseAttempted||E->SenseCompleted>E->SenseIssued||
       E->ClearAttempted>E->SenseCompleted||E->ClearIssued>E->ClearAttempted||E->ClearCompleted>E->ClearIssued||
       (E->SenseCompleted&&E->SenseStatus)||(E->ClearCompleted&&E->ClearStatus)||
       (E->SenseAttempted&&(E->InitPhase<N976nInitSense||E->PreChecks!=15||E->PreAppStatus||E->PreFunctionStatus||E->PreAppValue!=0x20))||
       (E->ClearAttempted&&E->InitPhase<N976nInitClear)||(E->Reads==2&&E->InitPhase<N976nInitPost)||
       (E->Phase==N976nStartupComplete&&(E->InitPhase!=N976nInitComplete||E->Reads!=2||
         !E->SenseCompleted||!E->ClearCompleted||E->PreChecks!=15||E->PostChecks!=15||E->Reason||
         E->AppStatus||E->FunctionStatus||E->AppValue!=0x20||E->PreFunctionValue!=E->FunctionValue||
         E->FunctionValue==65535||(E->FunctionValue&0x61U)!=0x61U||E->TransferStatus||
         E->NonEmpty+E->Empty!=2||!E->First.Valid||!E->Last.Valid||E->First.Bytes!=16||E->Last.Bytes!=16||
         E->First.Ordinal!=1||E->Last.Ordinal!=2||E->Rejected.Valid))||
       E->PostReserved||E->PostChecks>15||E->AppValue>255||E->FunctionValue>65535||
       E->Reads>N976N_STARTUP_READ_LIMIT||E->NonEmpty>E->Reads||E->Empty>E->Reads||
       E->Coordinate>E->NonEmpty||E->Status>E->NonEmpty||E->Gesture>E->NonEmpty||
       E->Boot>E->NonEmpty||E->Error>E->NonEmpty||E->Unknown>E->NonEmpty||
       E->Malformed>E->NonEmpty||E->ObservedPackets>E->NonEmpty||
       E->Remaining31Count>E->ObservedPackets||E->UnknownVendorCount>E->ObservedPackets||
       E->UnknownVendorCount>E->Unknown||E->ObservedPackets>E->Remaining31Count+E->UnknownVendorCount||
       E->FirstObservedMask>3||!!E->ObservedPackets!=!!E->FirstObserved.Valid||
       !!E->ObservedPackets!=!!E->FirstObservedMask||
       !!E->UnknownVendorCount!=!!E->FirstUnknownVendor.Valid)return 0;
    for(unsigned int I=0;I<5;++I)
        if(P[I]->Valid>1||P[I]->Reserved||P[I]->Bytes>16||P[I]->Class>3||
           P[I]->Subtype>15||P[I]->Id>255||P[I]->Data>255||P[I]->Remaining>31||
           P[I]->Decoded < -3||P[I]->Decoded>4||
           (P[I]->Valid&&(!P[I]->Ordinal||P[I]->Ordinal>E->Reads)))return 0;
    if(E->FirstObserved.Valid){
        const N976N_STARTUP_PACKET *O=&E->FirstObserved;
        if(O->Bytes!=16||O->Decoded==-1||O->Decoded==-2||
           O->Class!=(O->Raw[0]&3U)||O->Subtype!=((O->Raw[0]>>2U)&15U)||
           O->Id!=O->Raw[1]||O->Data!=O->Raw[2]||O->Remaining!=(O->Raw[7]&31U))return 0;
        if((E->FirstObservedMask&N976nObserveRemaining31)&&(!E->Remaining31Count||O->Remaining!=31))return 0;
        if((E->FirstObservedMask&N976nObserveUnknownVendor)&&(!E->UnknownVendorCount||O->Class!=1||O->Subtype!=7||O->Decoded!=2||N976nStartupKnownVendorId(O->Id)))return 0;
    }
    if(E->FirstUnknownVendor.Valid){
        const N976N_STARTUP_PACKET *V=&E->FirstUnknownVendor;
        if(V->Bytes!=16||V->Class!=1||V->Subtype!=7||V->Decoded!=2||N976nStartupKnownVendorId(V->Id)||
           V->Class!=(V->Raw[0]&3U)||V->Subtype!=((V->Raw[0]>>2U)&15U)||
           V->Id!=V->Raw[1]||V->Data!=V->Raw[2]||V->Remaining!=(V->Raw[7]&31U)||
           V->Ordinal<E->FirstObserved.Ordinal)return 0;
    }
    return 1;
}
#endif
