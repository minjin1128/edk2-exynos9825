/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC86 boot-start Storport disk. Initial capacity/LBA0 proof is retained;
 * one real LUN accepts reads and standard WRITE10/16 inside the freshly
 * admitted SYSTEM FAT prefix and USERDATA NTFS extent. All flush requests reach the device.
 * Adapter-owned mappings and low DMA list persist across SRBs.
 * Each I/O SRB owns its worker: target Storport rejects a still-running worker.
 * Passive requests are serialized; power-stop keeps resources, adapter PnP
 * removal retires before releasing mappings. No OS buffer is a DMA address.
 */
#include <ntddk.h>
#include <storport.h>
#include <ntddscsi.h>
#include "N976nUfsLease.h"
#include "N976nUfsScsi.h"
#include "N976nUfsGptView.h"
#include "N976nUfsScope.h"
enum { PerfRead4K,PerfReadLarge,PerfWrite4K,PerfWriteLarge,PerfFua4K,PerfFuaLarge,
       PerfFlush,PerfRead4KControl,PerfReadLargeControl,PerfBinCount };
typedef struct {
 U64 Samples,Bytes,QueueTicks,PrepareTicks,DeviceTicks,BetweenTicks,FinishTicks;
 U64 MaxTotalTicks,GuardTicks,GuardBytes,GuardLoads,RejectedSamples,FailedSamples;
 U64 WaitSamples,SleepCalls,SleepRequestedUs,SleepElapsedUs,MaxSleepUs;
 U64 StallCalls,StallRequestedUs,DoneBeforeSleep,DoneAfterWake,DoneOtherPoll;
 U64 ObservedWaitUs,MaxObservedWaitUs;
 U64 SleepBuckets[NUF_WAIT_BUCKETS],ObservedBuckets[NUF_WAIT_BUCKETS];
} NUF_PERF_BIN;
typedef struct {
 U32 Version,ReadWindowUs,LegacyWindowUs,PollStepUs;
 U32 WriteWindowUs,FlushWindowUs,GuardPolicy,RangeVersion;
 U64 Frequency,QueueAttempts[PerfRead4KControl];
 NUF_PERF_BIN Bin[PerfBinCount];
} NUF_PERFORMANCE;
typedef struct {
 NUF_REPORT Report,IoReport;
 NUF_ENGINE Engine;
 N976N_UFS_HANDOFF LeaseCopy;
 U8 Baseline[4096],LeaseTail[4096-328];
 U8 *Hci,*Coherency,*Lease,*Dma;
 U64 LeaseBase,DmaBase;
 volatile LONG Busy,Started,Stop,PowerStopped,Removed;
 BOOLEAN Claimed,Mapped;
 U8 LastSense[18];
 BOOLEAN SenseValid;
 PVOID Worker,OrphanWorker; /* reserved final-removal item; I/O workers belong to SRBs */
 U64 MapCount,UnmapCount,WorkerCreates,WorkerQueues,CompletedBlocks,PartialBytes;
 /* Adapter-owned, WB memory. Never used as a device DMA address or placed
  * on the small kernel stack. Existing Busy serializes every request in the admitted session. */
 NUF_SCOPE_WORK ScopeWork;
 NUF_SCOPE_REPORT Scope;
 NUF_PERFORMANCE Perf; /* debugger-only; public report format is unchanged */
} NUF_ADAPTER;
enum { NufRequestWrite=3,NufRequestFlush=4,NufRequestShutdown=5 };
typedef struct {
 PVOID Worker;ULONG WorkerStatus;U64 Lba;U32 Tag,Operation,Flags,Bytes;
 U32 Sample,Bin;U64 Queued,Entered,GuardStart,LoadsStart;
} NUF_REQUEST;
static const U8 Signature[8]={'N','9','7','6','U','F','S',0};
static void SetFailure(NUF_ADAPTER *a,U32 why,NTSTATUS status){
 if(!a->Report.FirstReason){a->Report.FirstReason=why;a->Report.FirstStage=a->Report.Stage;}
 a->Report.Reason=why;a->Report.DriverStatus=(U32)status;}
static U32 ReadRegister(void *p,U32 o){NUF_ADAPTER *a=p;
 if(InterlockedCompareExchange(&a->Removed,0,0))return ~0U;
 if(o==NUF_COH)return READ_REGISTER_ULONG((PULONG)(a->Coherency+0x700));
 return READ_REGISTER_ULONG((PULONG)(a->Hci+o));}
static void WriteRegister(void *p,U32 o,U32 v){NUF_ADAPTER *a=p;
 if(InterlockedCompareExchange(&a->Removed,0,0))return;
 /* All core writes are statically constrained; refuse future expansion. */
 if(o==0x20||o==0x50||o==0x54||o==0x58||o==0x60||o==0x1140)
  WRITE_REGISTER_ULONG((PULONG)(a->Hci+o),v);
 else InterlockedExchange(&a->Stop,1);}
static U64 ClockUs(void *p){ULONGLONG qpc;UNREFERENCED_PARAMETER(p);return KeQueryInterruptTimePrecise(&qpc)/10ULL;}
static void Pause(void *p){UNREFERENCED_PARAMETER(p);YieldProcessor();}
static void StallUs(void *p,U32 us){UNREFERENCED_PARAMETER(p);
 /* Core bounds every call to 1..10us; never request a millisecond stall. */
 StorPortStallExecution(us);}
static void SleepUs(void *p,U32 us){LARGE_INTEGER delay;UNREFERENCED_PARAMETER(p);
 delay.QuadPart=-(LONGLONG)us*10;KeDelayExecutionThread(KernelMode,FALSE,&delay);}
static void Fence(void *p){UNREFERENCED_PARAMETER(p);KeMemoryBarrier();}
static int Owned(void *p){NUF_ADAPTER *a=p;N976N_UFS_HANDOFF *h=(N976N_UFS_HANDOFF*)a->Lease;U64 guard;
 if(!a->Claimed||InterlockedCompareExchange(&a->Removed,0,0)||!h)return 0;
 if(InterlockedCompareExchange64((volatile LONG64*)&h->ClaimState,1,1)!=1)return 0;
 if(RtlCompareMemory(h,&a->LeaseCopy,320)!=320||h->Guard!=N976N_UFS_HANDOFF_GUARD)return 0;
 RtlCopyMemory(&guard,a->Lease+4088,8);return guard==N976N_UFS_HANDOFF_GUARD;}
static void Unmap(NUF_ADAPTER *a){
 a->Engine.Config.WriteEnabled=0;
 if(a->Dma){a->UnmapCount++;MmUnmapIoSpace(a->Dma,NUF_DMA_BYTES);a->Dma=NULL;}
 if(a->Lease){a->UnmapCount++;MmUnmapIoSpace(a->Lease,8192);a->Lease=NULL;}
 if(a->Coherency){a->UnmapCount++;MmUnmapIoSpace(a->Coherency,4096);a->Coherency=NULL;}
 if(a->Hci){a->UnmapCount++;MmUnmapIoSpace(a->Hci,8192);a->Hci=NULL;}a->Mapped=FALSE;}
static PVOID Map(U64 address,ULONG bytes,ULONG flags){PHYSICAL_ADDRESS p;p.QuadPart=(LONGLONG)address;
 return MmMapIoSpaceEx(p,bytes,flags);}
static void CopyConfig(NUF_ADAPTER *a){N976N_UFS_HANDOFF *h=&a->LeaseCopy;NUF_CONFIG *c=&a->Engine.Config;
 c->DmaBase=h->DmaBase;c->OldTrlBase=((U64)h->TrlBaseHi<<32)|h->TrlBase;c->LastLba=h->LastLba;
 c->BlockBytes=h->BlockBytes;c->Lun=h->Lun;c->Cap=h->HciCap;c->Version=h->HciVersion;c->Hcs=h->Hcs;
 c->Tx=h->TxPrdt;c->Rx=h->RxPrdt;c->Reorder=h->Reorder;c->Nexus=h->Nexus;c->Axi=h->Axi;c->Iacr=h->Iacr;
 c->WriteEnabled=a->Scope.Ready;c->WriteFirst=a->Scope.WriteStart;c->WriteBlocks=a->Scope.WriteBlocks;
 c->SystemWriteFirst=a->Scope.SystemWriteStart;c->SystemWriteBlocks=a->Scope.SystemWriteBlocks;
 c->Coherency=h->Coherency;c->TmBase=h->TmBase;c->TmBaseHi=h->TmBaseHi;c->Baseline=a->Baseline;
 a->Engine.Dma=a->Dma;a->Engine.Report=&a->Report;
 a->Engine.Ops.Context=a;a->Engine.Ops.Read=ReadRegister;a->Engine.Ops.Write=WriteRegister;
 a->Engine.Ops.ClockUs=ClockUs;a->Engine.Ops.Pause=Pause;a->Engine.Ops.Fence=Fence;a->Engine.Ops.Owned=Owned;a->Engine.Ops.SleepUs=SleepUs;
 a->Engine.Ops.StallUs=StallUs;}
static int MapResources(NUF_ADAPTER *a){
 if(a->Hci||a->Coherency||a->Lease||a->Dma)return 0;
 a->MapCount+=4;
 a->Hci=Map(0x13D60000,8192,PAGE_READWRITE|PAGE_NOCACHE);
 a->Coherency=Map(0x13C10000,4096,PAGE_READONLY|PAGE_NOCACHE);
 a->Lease=Map(a->LeaseBase,8192,PAGE_READWRITE);a->Dma=Map(a->DmaBase,NUF_DMA_BYTES,PAGE_READWRITE|PAGE_NOCACHE);
 a->Mapped=a->Hci&&a->Coherency&&a->Lease&&a->Dma;return a->Mapped;
}
static void EndClaim(NUF_ADAPTER *a,U32 value){
 if(!a->Claimed||!a->Lease)return;
 if(InterlockedCompareExchange64((volatile LONG64*)&((N976N_UFS_HANDOFF*)a->Lease)->ClaimState,value,1)!=1){
  a->Report.RuntimeReason=NufOwnership;a->Report.RuntimeQuarantined=1;}
 a->Report.Claim=value;a->Claimed=FALSE;
}
/* Immutable lease contents were authenticated once. Compare the same bytes
 * to their private snapshot instead of hashing them again for every request. */
static int SessionValid(NUF_ADAPTER *a){
 return a->Mapped&&Owned(a)&&
  RtlCompareMemory(a->Lease+328,a->LeaseTail,sizeof(a->LeaseTail))==sizeof(a->LeaseTail)&&
  RtlCompareMemory(a->Lease+4096,a->Baseline,sizeof(a->Baseline))==sizeof(a->Baseline);
}
/* Notification/idempotency checks use retained private state and RAM only.
 * Hardware start/stop is performed separately by the bounded core routines. */
static int RetainedSession(NUF_ADAPTER *a){
 return a->Started==2&&!a->Stop&&!a->Removed&&a->Worker&&a->Claimed&&
  a->Scope.Ready&&a->ScopeWork.View.Ready&&!a->Engine.Quarantined&&
  !a->IoReport.Quarantined&&!a->IoReport.CleanupReason&&SessionValid(a);
}
static int StoppedSession(NUF_ADAPTER *a){
 return a->Engine.Stopped&&!a->Engine.Closed&&!a->Engine.SessionActive&&
  !a->Engine.Changed&&!a->Engine.Running&&a->IoReport.Retired&&NufRequestRetired(&a->Engine);
}
static int ActiveSession(NUF_ADAPTER *a){
 return a->Engine.SessionActive&&!a->Engine.Stopped&&!a->Engine.Closed&&
  a->Engine.Changed&&a->Engine.Running&&NufRequestRetired(&a->Engine);
}
static void ReleaseWorker(NUF_ADAPTER *a){
 if(!a->Worker)return;
 PVOID w=a->Worker;ULONG status=StorPortFreeWorker(a,w);
 if(status!=STOR_STATUS_SUCCESS){a->OrphanWorker=w;a->Report.WorkerStatus=status;}
 a->Worker=NULL;
}
static void Terminal(NUF_ADAPTER *a,U32 why){
 /* Keep the first transfer report while attempting bounded retirement. A
  * quarantined command must never be reset/replayed merely to free a session. */
 a->Report.SessionState=3;a->Scope.Ready=0;a->Engine.Config.WriteEnabled=0;
 if(a->Mapped&&a->Claimed&&!a->Removed){
  if(!NufSessionClose(&a->Engine))a->Report.RuntimeQuarantined=1;
 }
 if(a->Claimed)EndClaim(a,a->Engine.SessionActive||a->Engine.Quarantined||a->IoReport.Quarantined||a->Removed?3:2);
 if(!a->Report.RuntimeReason)a->Report.RuntimeReason=why;
 InterlockedExchange(&a->Stop,1);
}
static BOOLEAN PassiveInitialize(PVOID extension){NUF_ADAPTER *a=extension;N976N_UFS_HANDOFF *h;
 if(InterlockedCompareExchange(&a->Started,1,0)!=0)return a->Started==2;
 InterlockedExchange(&a->Busy,1);
 if(a->Report.FirstReason)goto done;
 if(a->Stop||a->Removed){SetFailure(a,NufOwnership,STATUS_CANCELLED);goto done;}
 if(!MapResources(a)){SetFailure(a,NufMapping,STATUS_INSUFFICIENT_RESOURCES);goto done;}
 if(a->Stop||a->Removed){SetFailure(a,NufOwnership,STATUS_CANCELLED);goto done;}
 a->Report.Stage=NufStageLease;h=(N976N_UFS_HANDOFF*)a->Lease;
 RtlCopyMemory(&a->LeaseCopy,h,sizeof(*h));KeMemoryBarrier();
 a->Report.Ready=a->LeaseCopy.ProducerStage;
 a->Report.LeaseCheck=NufValidateLease(&a->LeaseCopy,a->LeaseBase,a->DmaBase);
 if(a->Report.LeaseCheck||NufValidateLeasePage(a->Lease)||RtlCompareMemory(h,&a->LeaseCopy,320)!=320){SetFailure(a,NufLease,STATUS_DEVICE_CONFIGURATION_ERROR);goto done;}
 RtlCopyMemory(a->Baseline,a->Lease+4096,4096);
 RtlCopyMemory(a->LeaseTail,a->Lease+328,sizeof(a->LeaseTail));KeMemoryBarrier();
 if(NufCrc32(a->Baseline,4096)!=a->LeaseCopy.BaselineCrc32||RtlCompareMemory(h,&a->LeaseCopy,320)!=320){SetFailure(a,NufLease,STATUS_DEVICE_CONFIGURATION_ERROR);goto done;}
 a->Report.Stage=NufStageClaim;
 a->Report.LeaseClaim=(U64)InterlockedCompareExchange64((volatile LONG64*)&h->ClaimState,1,0);
 if(a->Report.LeaseClaim){SetFailure(a,NufReplay,STATUS_DEVICE_BUSY);goto done;}
 a->Claimed=TRUE;a->Report.Claim=1;CopyConfig(a);
 if(a->Stop||a->Removed||!SessionValid(a)||!NufSessionOpen(&a->Engine)||!NufRun(&a->Engine)||!NufRequestRetired(&a->Engine)){
  if(!a->Report.FirstReason)SetFailure(a,NufOwnership,STATUS_IO_DEVICE_ERROR);goto done;
 }
 a->Report.DriverStatus=STATUS_SUCCESS;
 RtlZeroMemory(&a->IoReport,sizeof(a->IoReport));a->Engine.Report=&a->IoReport;
 if(!NufScopeAdmit(&a->Engine,&a->Scope,&a->ScopeWork)||!a->ScopeWork.View.Ready||
    a->Scope.Quarantined||!NufRequestRetired(&a->Engine)||a->Stop||a->Removed)goto done;
 /* Admission above remains full. Enable the explicitly selected runtime
  * policy only after all physical metadata and ownership checks pass. */
 a->Engine.GuardPolicy=NUF_RUNTIME_GUARD_POLICY;
 a->Report.WorkerStatus=StorPortInitializeWorker(a,&a->Worker);
 if(a->Report.WorkerStatus!=STOR_STATUS_SUCCESS||!a->Worker){SetFailure(a,NufResource,STATUS_INSUFFICIENT_RESOURCES);goto done;}
 a->WorkerCreates++;a->Report.SessionState=1;
 done:
 if(a->Report.SessionState!=1){
  if(a->Claimed){a->Engine.Report=&a->IoReport;Terminal(a,a->Report.Reason?a->Report.Reason:NufLease);}
  ReleaseWorker(a);Unmap(a);a->Engine.Dma=NULL;a->Engine.Config.Baseline=NULL;
  a->Report.SessionState=3;InterlockedExchange(&a->Stop,1);
 }
 KeMemoryBarrier();InterlockedExchange(&a->Started,a->Report.SessionState==1?2:3);
 BOOLEAN success=a->Report.SessionState==1;InterlockedExchange(&a->Busy,0);return success;
}
static ULONG FindAdapter(PVOID extension,PVOID context,PVOID bus,PCHAR args,
 PPORT_CONFIGURATION_INFORMATION cfg,PBOOLEAN again){NUF_ADAPTER *a=extension;
 if(args){const char token[]="dump=1";U32 n=0;while(n<6&&args[n]==token[n])n++;if(n==6){*again=FALSE;return SP_RETURN_ERROR;}}
 UNREFERENCED_PARAMETER(context);UNREFERENCED_PARAMETER(bus);UNREFERENCED_PARAMETER(args);
 *again=FALSE;RtlZeroMemory(a,sizeof(*a));a->Report.Magic=NUF_DIAG_MAGIC;a->Report.Version=NUF_DIAG_VERSION;
 a->Perf.Version=5;a->Perf.ReadWindowUs=(U32)NUF_READ_POLL_WINDOW_US;
 a->Perf.WriteWindowUs=(U32)NUF_READ_POLL_WINDOW_US;a->Perf.FlushWindowUs=(U32)NUF_READ_POLL_WINDOW_US;
 a->Perf.GuardPolicy=NUF_RUNTIME_GUARD_POLICY;a->Perf.RangeVersion=2;
 a->Perf.LegacyWindowUs=(U32)NUF_SPIN_WAIT_US;a->Perf.PollStepUs=NUF_READ_POLL_STEP_US;
 a->Report.Bytes=sizeof(a->Report);a->Report.Stage=NufStageFind;a->Report.DriverStatus=STATUS_PENDING;
 cfg->MaximumTransferLength=NUF_MAX_TRANSFER;cfg->NumberOfPhysicalBreaks=NUF_MAX_TRANSFER/4096+1;
 cfg->AlignmentMask=3;cfg->NumberOfBuses=1;cfg->MaximumNumberOfTargets=2;cfg->MaximumNumberOfLogicalUnits=1;
 cfg->InitiatorBusId[0]=1;cfg->CachesData=TRUE;cfg->MapBuffers=STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE;
 cfg->Dma64BitAddresses=0;cfg->Dma32BitAddresses=TRUE;cfg->SynchronizationModel=StorSynchronizeFullDuplex;
 cfg->InterruptSynchronizationMode=InterruptSupportNone;cfg->MaxNumberOfIO=1;cfg->MaxIOsPerLun=1;cfg->InitialLunQueueDepth=1;
 a->Report.Stage=NufStageResources;a->Report.ResourceCount=cfg->NumberOfAccessRanges;
 if(cfg->NumberOfAccessRanges!=4||!cfg->AccessRanges){SetFailure(a,NufResource,STATUS_DEVICE_CONFIGURATION_ERROR);return SP_RETURN_FOUND;}
 for(U32 i=0;i<4;i++){
  ACCESS_RANGE *r=&(*cfg->AccessRanges)[i];U64 b=(U64)r->RangeStart.QuadPart;U32 n=r->RangeLength;
  a->Report.ResourceIndex=i;a->Report.ResourceBase=b;a->Report.ResourceLength=n;
  if(!NufResourceAllowed(i,b,n,r->RangeInMemory)){SetFailure(a,NufResource,STATUS_DEVICE_CONFIGURATION_ERROR);return SP_RETURN_FOUND;}
  if(i==2)a->LeaseBase=b;if(i==3)a->DmaBase=b;
 }
 a->Report.LeaseBase=a->LeaseBase;a->Report.DmaBase=a->DmaBase;
 if(NufOverlap(a->LeaseBase,8192,a->DmaBase,NUF_DMA_BYTES)){SetFailure(a,NufResource,STATUS_DEVICE_CONFIGURATION_ERROR);return SP_RETURN_FOUND;}
 return SP_RETURN_FOUND;}
static SCSI_ADAPTER_CONTROL_STATUS Control(PVOID,SCSI_ADAPTER_CONTROL_TYPE,PVOID);
static BOOLEAN Initialize(PVOID extension){NUF_ADAPTER *a=extension;
 LONG started=InterlockedCompareExchange(&a->Started,0,0);
 if(started!=0){
  /* Storport may use HwInitialize for a same-resource restart. Never reset
   * the lease/guard snapshots or report success for a terminal failed adapter. */
  if(started!=2||a->Busy)return FALSE;
  return Control(extension,ScsiRestartAdapter,NULL)==ScsiAdapterControlSuccess;
 }
 if(!StorPortEnablePassiveInitialization(extension,PassiveInitialize)){
  SetFailure(a,NufResource,STATUS_NOT_SUPPORTED);InterlockedExchange(&a->Stop,1);
  InterlockedCompareExchange(&a->Started,3,0);InterlockedExchange(&a->Busy,0);return FALSE;}
 return TRUE;}
static void Finish(NUF_ADAPTER *a,PSCSI_REQUEST_BLOCK srb){
 /* No access to extension/SRB follows completion; Storport may immediately
  * start another SRB, stop, or remove this adapter. */
 KeMemoryBarrier();InterlockedExchange(&a->Busy,0);
 StorPortNotification(RequestComplete,a,srb);
}
static void ScsiCheck(NUF_ADAPTER *a,PSCSI_REQUEST_BLOCK srb,U8 key,U8 asc,U8 ascq){
 U8 sense[18]={0};sense[0]=0x70;sense[2]=key;sense[7]=10;sense[12]=asc;sense[13]=ascq;
 RtlCopyMemory(a->LastSense,sense,sizeof(sense));a->SenseValid=TRUE;
 srb->SrbStatus=SRB_STATUS_ERROR;srb->ScsiStatus=2;srb->DataTransferLength=0;
 if(!(srb->SrbFlags&SRB_FLAGS_DISABLE_AUTOSENSE)&&srb->SenseInfoBuffer&&srb->SenseInfoBufferLength>=sizeof(sense)){
  RtlCopyMemory(srb->SenseInfoBuffer,sense,sizeof(sense));srb->SrbStatus|=SRB_STATUS_AUTOSENSE_VALID;a->SenseValid=FALSE;}
}

static NUF_SCOPE_REPORT *ScopePacket(PSCSI_REQUEST_BLOCK srb){
 if(srb->Function!=SRB_FUNCTION_IO_CONTROL||!srb->DataBuffer||
    srb->DataTransferLength!=NUF_SCOPE_WIRE_OFFSET+sizeof(NUF_SCOPE_REPORT))return NULL;
 PSRB_IO_CONTROL c=srb->DataBuffer;
 if(((ULONG_PTR)c&7U)||sizeof(*c)!=28U)return NULL;
 for(U32 n=sizeof(*c);n<NUF_SCOPE_WIRE_OFFSET;n++)if(((U8*)c)[n])return NULL;
 NUF_SCOPE_REPORT *p=(void*)((U8*)c+NUF_SCOPE_WIRE_OFFSET);
 if(c->HeaderLength!=sizeof(*c)||c->Length!=4+sizeof(*p)||c->ControlCode!=NUF_SCOPE_CONTROL||
    RtlCompareMemory(c->Signature,Signature,8)!=8||p->Magic!=NUF_SCOPE_MAGIC||
    p->Version!=NUF_SCOPE_VERSION||p->Bytes!=sizeof(*p))return NULL;
 return p;
}
static void ScopeFailure(NUF_ADAPTER *a,U32 reason){NUF_SCOPE_REPORT *r=&a->Scope;
 if(!r->FirstReason){r->FirstReason=reason;r->FirstStage=r->Stage;}
 r->Ready=0;r->Reason=r->LastReason=reason;r->Stage=NufScopeFailed;
}
static int FreeRequestWorker(NUF_ADAPTER *a,NUF_REQUEST *q){
 if(!q||!q->Worker)return 1;
 PVOID worker=q->Worker;q->Worker=NULL;
 /* The target defers destruction of its executing callback until return.
  * RequestComplete can immediately enter the next SRB: detach/free first,
  * never touch this SRB or adapter after that notification. */
 ULONG status=StorPortFreeWorker(a,worker);
 if(status==STOR_STATUS_SUCCESS)return 1;
 a->OrphanWorker=worker;a->Report.WorkerStatus=status;
 ScopeFailure(a,NufScopeWorker);a->Report.SessionState=3;InterlockedExchange(&a->Stop,1);return 0;
}
static BOOLEAN BuildIo(PVOID extension,PSCSI_REQUEST_BLOCK srb){NUF_ADAPTER *a=extension;
 /* PnP SRBs have their own structure: do not touch ordinary transfer fields. */
 if(srb->Function==SRB_FUNCTION_PNP||!srb->SrbExtension)return TRUE;
 NUF_REQUEST *q=srb->SrbExtension;RtlZeroMemory(q,sizeof(*q));
 /* QueueWorker allocates only after CDB/range/ownership admission. Retain a
  * distinct item per accepted SRB and free-before-complete: never requeue the
  * executing callback's item. Rejected/empty/BUSY requests allocate nothing. */
 UNREFERENCED_PARAMETER(a);
 return TRUE;
}
static int ApplyReadView(NUF_ADAPTER *a,U64 start,U8 *buffer,U32 bytes){
 NUV_SPAN_RESULT span;
 if(!NuvViewApplySpan(&a->ScopeWork.View,start,buffer,bytes,&span)){
  a->Report.ViewLastReason=NuvDrift;a->Report.ViewRefused++;return 0;
 }
 for(U32 n=0;n<bytes/4096;n++){
 U64 lba=start+n;U8 *out=buffer+n*4096;
 int metadata=(span.Candidates&(1U<<n))!=0;U32 changed=(span.Changed&(1U<<n))!=0;
 unsigned side=lba==1?0:1;int isHeader=lba==1||lba==a->LeaseCopy.LastLba;
 if(metadata)a->Report.ViewCandidates++;if(isHeader)a->Report.ViewSeenMask|=1U<<side;
 int ok=1;a->Report.ViewLastReason=0;
 if(ok&&isHeader){NUF_GPT_VIEW_SNAPSHOT *view=&a->Report.ViewHeader[side];
  ok=NufGptView(out,4096,lba,a->LeaseCopy.LastLba,view);
  RtlCopyMemory(&view->OriginalSize,a->ScopeWork.View.Header[side]+12,4);
  RtlCopyMemory(&view->OriginalCrc,a->ScopeWork.View.Header[side]+16,4);view->ComputedCrc=view->OriginalCrc;
  RtlCopyMemory(&view->ArrayCrc,a->ScopeWork.View.Header[side]+88,4);view->Request=a->Report.RuntimeRequests;
  a->Report.ViewLastReason=view->Reason;
 }
 if(!ok)a->Report.ViewRefused++;else if(changed)a->Report.ViewApplied++;else if(metadata)a->Report.ViewUnchanged++;
 if(!ok)return 0;
 }return 1;
}
static void IoObservation(NUF_ADAPTER *a,int ok,U32 bytes){NUF_REPORT *r=&a->IoReport;
 a->Report.RuntimeStatus=ok?STATUS_SUCCESS:STATUS_IO_DEVICE_ERROR;
 a->Report.RuntimeReason=r->Reason;a->Report.RuntimeIssued=r->Issued;a->Report.RuntimeAck=r->Acknowledged;
 /* RuntimeRetired describes request DMA/ACK retirement. The initial Retired
  * and engine SessionActive independently describe full controller release. */
 a->Report.RuntimeRetired=NufRequestRetired(&a->Engine);a->Report.RuntimeQuarantined=r->Quarantined;
 a->Report.RuntimeFirstStage=r->FirstStage;a->Report.RuntimeFirstReason=r->FirstReason;
 a->Report.RuntimeOcs=r->Ocs;a->Report.RuntimeResponse=r->Response;a->Report.RuntimeScsi=r->ScsiStatus;
 a->Report.RuntimeIs=r->Is;a->Report.RuntimeDbr=r->Dbr;a->Report.RuntimeWaitUs=r->WaitUs;
 if(ok){a->Report.RuntimeCompleted++;a->Report.RuntimeBytes+=bytes;}
}
/* PERF3: one sample per64 requests, all READs use the measured1ms window.
 * Legacy control bins7/8 remain reserved/zero for layout compatibility, but
 * Version3 is distinct and collectors must not label them as live controls. */
static U64 PerfClock(void *extension){
 LARGE_INTEGER ticks;
 if(StorPortQueryPerformanceCounter(extension,NULL,&ticks)!=STOR_STATUS_SUCCESS||ticks.QuadPart<=0)return 0;
 return (U64)ticks.QuadPart;
}
static void PerfQueue(NUF_ADAPTER *a,NUF_REQUEST *q,int read){
 U32 small=q->Bytes==NUF_BLOCK_BYTES;
 U32 kind=read?(small?PerfRead4K:PerfReadLarge):q->Operation!=NufRequestWrite?PerfFlush:
     (q->Flags&NUF_SCSI_FUA)?(small?PerfFua4K:PerfFuaLarge):(small?PerfWrite4K:PerfWriteLarge);
 U64 sequence=a->Perf.QueueAttempts[kind]++;
 U32 slot=(U32)(sequence&63);
 q->Sample=slot==0;
 if(!q->Sample)return;
 q->Bin=kind;
 LARGE_INTEGER frequency,ticks;
 q->Queued=0;
 if(StorPortQueryPerformanceCounter(a,&frequency,&ticks)==STOR_STATUS_SUCCESS&&
    ticks.QuadPart>0&&frequency.QuadPart>0&&
    (!a->Perf.Frequency||a->Perf.Frequency==(U64)frequency.QuadPart)){
  a->Perf.Frequency=(U64)frequency.QuadPart;q->Queued=(U64)ticks.QuadPart;
 }
}
static void PerfEnter(NUF_ADAPTER *a,NUF_REQUEST *q){
 if(!q->Sample)return;
 q->Entered=PerfClock(a);q->GuardStart=a->Engine.GuardCheckBytes;q->LoadsStart=a->Engine.GuardReadOps;
 a->Engine.PerfCommands=0;a->Engine.PerfClockError=0;a->Engine.PerfGuardTicks=0;
 RtlZeroMemory(a->Engine.PerfIssue,sizeof(a->Engine.PerfIssue));
 RtlZeroMemory(a->Engine.PerfDone,sizeof(a->Engine.PerfDone));
 RtlZeroMemory(a->Engine.PerfWait,sizeof(a->Engine.PerfWait));
 a->Engine.ControlWaitLegacy=0;
 a->Engine.PerfClock=PerfClock;
}
static void PerfWaitFinish(NUF_PERF_BIN *b,const NUF_WAIT_SAMPLE *w){
 U64 observed=w->ClearUs-w->StartUs;
 b->WaitSamples++;b->SleepCalls+=w->SleepCalls;b->SleepRequestedUs+=w->SleepRequestedUs;
 b->SleepElapsedUs+=w->SleepElapsedUs;b->StallCalls+=w->StallCalls;b->StallRequestedUs+=w->StallRequestedUs;
 if(w->MaxSleepUs>b->MaxSleepUs)b->MaxSleepUs=w->MaxSleepUs;
 if(!w->SleepCalls)b->DoneBeforeSleep++;else if(w->DoneAfterWake)b->DoneAfterWake++;else b->DoneOtherPoll++;
 b->ObservedWaitUs+=observed;if(observed>b->MaxObservedWaitUs)b->MaxObservedWaitUs=observed;
 const U32 upper[NUF_WAIT_BUCKETS-1]={100,250,500,1000,2000,4000,8000};
 U32 i=0;while(i<NUF_WAIT_BUCKETS-1&&observed>=upper[i])i++;b->ObservedBuckets[i]++;
 for(i=0;i<NUF_WAIT_BUCKETS;i++)b->SleepBuckets[i]+=w->SleepBuckets[i];
}
static void PerfFinish(NUF_ADAPTER *a,NUF_REQUEST *q,int success){
 if(!q->Sample)return;
 NUF_ENGINE *e=&a->Engine;
 U64 end=PerfClock(a),qpc=q->Queued,entry=q->Entered,issue=e->PerfIssue[0],done=e->PerfDone[0];
 U64 between=0,device=0;
 U32 commands=e->PerfCommands;
 NUF_PERF_BIN *b=&a->Perf.Bin[q->Bin];
 e->PerfClock=NULL;e->ControlGuard32=0;e->ControlWaitLegacy=0;q->Sample=0;
 if(!success){b->FailedSamples++;return;}
 if(e->PerfClockError||!qpc||entry<qpc||issue<entry||done<issue||
    commands!=((q->Bin==PerfFua4K||q->Bin==PerfFuaLarge)?2U:1U)){b->RejectedSamples++;return;}
 device=done-issue;
 if(commands==2){
  U64 second=e->PerfIssue[1],last=e->PerfDone[1];
  if(second<done||last<second){b->RejectedSamples++;return;}
  between=second-done;device+=last-second;done=last;
 }
 if(end<done||e->PerfGuardTicks>end-entry-device){b->RejectedSamples++;return;}
 for(U32 i=0;i<commands;i++){
  const NUF_WAIT_SAMPLE *w=&e->PerfWait[i];
  if(!w->Completed||w->ClearUs<w->StartUs||w->LastPendingUs>w->ClearUs){b->RejectedSamples++;return;}
 }
 b->QueueTicks+=entry-qpc;b->PrepareTicks+=issue-entry;b->DeviceTicks+=device;
 b->BetweenTicks+=between;b->FinishTicks+=end-done;b->Bytes+=q->Bytes;
 b->GuardTicks+=e->PerfGuardTicks;b->GuardBytes+=e->GuardCheckBytes-q->GuardStart;b->GuardLoads+=e->GuardReadOps-q->LoadsStart;
 if(end-qpc>b->MaxTotalTicks)b->MaxTotalTicks=end-qpc;
 for(U32 i=0;i<commands;i++)PerfWaitFinish(b,&e->PerfWait[i]);
 b->Samples++;
}
static VOID ReadWorker(PVOID extension,PVOID context,PVOID worker){
 NUF_ADAPTER *a=extension;PSCSI_REQUEST_BLOCK srb=context;NUF_REQUEST *q=srb->SrbExtension;
 NUF_REPORT *r=&a->IoReport;U32 done=0;int ok=0;UNREFERENCED_PARAMETER(worker);
 PerfEnter(a,q);
 RtlZeroMemory(r,sizeof(*r));a->Engine.Report=r;
 a->Report.RuntimeRequests++;a->Report.RuntimeOpcode=srb->Cdb[0];a->Report.RuntimeLastLba=q->Lba;
 if(a->Stop||a->PowerStopped||!SessionValid(a)){r->Reason=NufLease;goto finish;}
 if(!q->Bytes||q->Bytes>NUF_MAX_TRANSFER||(q->Bytes%4096)||q->Bytes!=srb->DataTransferLength||
    !srb->DataBuffer||q->Lba>a->LeaseCopy.LastLba||q->Bytes/4096-1>a->LeaseCopy.LastLba-q->Lba){r->Reason=NufBadArgument;goto finish;}
 U32 tag=(U32)(a->CompletedBlocks%255)+1;
 if(a->Stop||a->Removed){r->Reason=NufOwnership;goto finish;}
 if(!NufReadBlock(&a->Engine,q->Lba,tag,(U8*)srb->DataBuffer,q->Bytes)||
    !NufRequestRetired(&a->Engine)||r->Reason||r->FirstReason||r->CleanupReason||r->Quarantined)goto finish;
 if(!ApplyReadView(a,q->Lba,(U8*)srb->DataBuffer,q->Bytes)){r->Reason=NufHeaderView;goto finish;}
 done=q->Bytes;a->CompletedBlocks+=done/4096;
 if(a->Stop||a->Removed){r->Reason=NufOwnership;goto finish;}
 ok=1;
 finish:
 a->PartialBytes=done;IoObservation(a,ok,done);
 if(ok){srb->SrbStatus=SRB_STATUS_SUCCESS;srb->ScsiStatus=0;srb->DataTransferLength=done;}
 else{if(!r->FirstReason){r->FirstReason=r->Reason;r->FirstStage=r->Stage?r->Stage:NufStageLease;}
  ScopeFailure(a,NufScopeTransport);Terminal(a,r->Reason);IoObservation(a,0,0);ScsiCheck(a,srb,4,0x44,0);}
 if(!FreeRequestWorker(a,q))ScsiCheck(a,srb,4,0x44,0);
 PerfFinish(a,q,srb->SrbStatus==SRB_STATUS_SUCCESS);
 Finish(a,srb);
}
static VOID WriteWorker(PVOID extension,PVOID context,PVOID worker){
 NUF_ADAPTER *a=extension;PSCSI_REQUEST_BLOCK srb=context;NUF_REQUEST *q=srb->SrbExtension;
 NUF_REPORT *io=&a->IoReport;U32 done=0;int ok=0;UNREFERENCED_PARAMETER(worker);
 PerfEnter(a,q);
 RtlZeroMemory(io,sizeof(*io));a->Engine.Report=io;
 if(a->Stop||a->PowerStopped||!SessionValid(a)){io->Reason=NufLease;goto finish;}
 if(q->Operation==NufRequestWrite){
  /* Admit the entire OS request before its irreversible command. The
   * independent physical fence remains in the entire hardware transfer. */
  if((q->Flags&~NUF_SCSI_FUA)||!srb->DataBuffer||q->Bytes!=srb->DataTransferLength||!NufScopeContains(&a->Scope,q->Lba,q->Bytes)){
   io->Reason=NufBadArgument;goto finish;}
  if(a->Stop||a->Removed){io->Reason=NufOwnership;goto finish;}
  if(!NufScopeWrite(&a->Engine,&a->Scope,&a->ScopeWork,
     q->Lba,(U8*)srb->DataBuffer,q->Bytes))goto finish;
  done=q->Bytes;
  /* FUA is emulated for the complete OS request. Native device FUA has not
   * been admitted. The serialized owner prevents a later request overtaking
   * this barrier, and no SRB success is visible before real flush retirement. */
  if(q->Flags&NUF_SCSI_FUA){
   if(a->Stop||a->Removed||!NufScopeFlush(&a->Engine,&a->Scope,(U32)(a->Scope.Requests%255)+1))goto finish;
   a->Scope.FuaWrites+=done/NUF_BLOCK_BYTES;
  }
  ok=1;
 }else ok=NufScopeFlush(&a->Engine,&a->Scope,q->Tag);
 finish:
 a->PartialBytes=done;
 if(!ok||a->Stop||a->Removed){
  if(!io->Reason)io->Reason=a->Stop||a->Removed?NufOwnership:NufBadArgument;
  if(!io->FirstReason){io->FirstReason=io->Reason;io->FirstStage=io->Stage?io->Stage:NufStageLease;}
  ScopeFailure(a,NufScopeTransport);a->Scope.Quarantined=io->Quarantined;
  a->Scope.Issued=io->Issued;a->Scope.Acknowledged=io->Acknowledged;
  a->Scope.Retired=NufRequestRetired(&a->Engine);a->Scope.Cleanup=io->CleanupReason;
  Terminal(a,io->Reason);ok=0;}
 /* SHUTDOWN is a persistence notification, not permission to free the HBA. */
 if(ok){srb->SrbStatus=SRB_STATUS_SUCCESS;srb->ScsiStatus=0;srb->DataTransferLength=done;}
 else ScsiCheck(a,srb,4,0x44,0);
 if(!FreeRequestWorker(a,q))ScsiCheck(a,srb,4,0x44,0);
 PerfFinish(a,q,srb->SrbStatus==SRB_STATUS_SUCCESS);
 Finish(a,srb);
}
static int QueueWorker(NUF_ADAPTER *a,PSCSI_REQUEST_BLOCK srb,PHW_WORKITEM callback){
 NUF_REQUEST *q=srb->SrbExtension;
 /* FindAdapter selects full duplex: StartIo is DISPATCH_LEVEL, where
  * InitializeWorker is supported. BUSY resubmission need not call BuildIo.
  * No DMA command has been issued on this path. */
 if(q&&!q->Worker){q->WorkerStatus=StorPortInitializeWorker(a,&q->Worker);
  if(q->WorkerStatus==STOR_STATUS_SUCCESS&&q->Worker)InterlockedIncrement64((volatile LONG64*)&a->WorkerCreates);}
 ULONG status=q?q->WorkerStatus:STOR_STATUS_INVALID_PARAMETER;
 if(status==STOR_STATUS_SUCCESS){
  if(!q||!q->Worker)status=STOR_STATUS_INVALID_PARAMETER;
  else{a->WorkerQueues++; /* callback may complete immediately */
   PerfQueue(a,q,callback==ReadWorker);
   status=StorPortQueueWorkItem(a,callback,q->Worker,srb);}
 }
 if(status==STOR_STATUS_SUCCESS)return 1;
 a->Report.WorkerStatus=status;
 /* The caller frees this unqueued worker before completion. Failure to
  * free still quarantines the adapter; lack of a worker alone does not. */
 if(status==STOR_STATUS_BUSY||status==STOR_STATUS_INSUFFICIENT_RESOURCES){
  srb->SrbStatus=SRB_STATUS_BUSY;srb->ScsiStatus=0;
 }else ScsiCheck(a,srb,4,0x44,0);
 return 0;
}
/* PnP remove runs through its reserved serialized passive item, never a detached
 * callback after PnP completion. Physical DMA pages remain firmware-reserved;
 * an uncertain command leaves ClaimState quarantined even after VA unmapping. */
static VOID RemoveWorker(PVOID extension,PVOID context,PVOID worker){
 NUF_ADAPTER *a=extension;PSCSI_PNP_REQUEST_BLOCK p=context;int clean=1;UNREFERENCED_PARAMETER(worker);
 if(a->Claimed){
  a->Engine.Report=&a->IoReport;
  if(a->Removed||a->Engine.Quarantined||a->IoReport.Quarantined||!SessionValid(a))clean=0;
  else if(a->Scope.WriteUncertain)clean=0;
  else{
   /* Normal removal is passive and serialized. Dirty cached writes need a
    * barrier before controller retirement; surprise removal never uses MMIO. */
   if(a->Scope.CacheDirty&&(!a->Engine.SessionActive||
      !NufScopeFlush(&a->Engine,&a->Scope,(U32)(a->Scope.Requests%255)+1)))clean=0;
   if(clean&&a->Engine.SessionActive&&!NufSessionClose(&a->Engine))clean=0;
  }
  EndClaim(a,clean?2:3);
 }
 InterlockedExchange(&a->Stop,1);a->Scope.Ready=0;a->Report.SessionState=clean?2:3;
 Unmap(a);a->Engine.Dma=NULL;a->Engine.Config.Baseline=NULL;ReleaseWorker(a);
 if(a->OrphanWorker)clean=0;
 p->SrbStatus=clean?SRB_STATUS_SUCCESS:SRB_STATUS_ERROR;
 Finish(a,(PSCSI_REQUEST_BLOCK)p);
}
static BOOLEAN PnpIo(NUF_ADAPTER *a,PSCSI_PNP_REQUEST_BLOCK p){
 /* Removal forbids new MMIO immediately, including while the passive owner
  * is busy. Only resource destruction waits for that owner to drain. */
 if(p->Length==sizeof(*p)&&p->SrbPnPFlags==SRB_PNP_FLAGS_ADAPTER_REQUEST&&p->PnPAction==StorSurpriseRemoval){
  if(a->Scope.CacheDirty)a->Scope.WriteUncertain=1;
  InterlockedExchange(&a->Removed,1);InterlockedExchange(&a->PowerStopped,1);InterlockedExchange(&a->Stop,1);
 }
 if(InterlockedCompareExchange(&a->Busy,1,0)!=0){p->SrbStatus=SRB_STATUS_BUSY;StorPortNotification(RequestComplete,a,p);return TRUE;}
 p->SrbStatus=SRB_STATUS_INVALID_REQUEST;
 if(p->Length!=sizeof(*p)||(p->SrbPnPFlags&~SRB_PNP_FLAGS_ADAPTER_REQUEST))goto done;
 if(!(p->SrbPnPFlags&SRB_PNP_FLAGS_ADAPTER_REQUEST)){
  if(p->PathId||p->TargetId||p->Lun)p->SrbStatus=SRB_STATUS_NO_DEVICE;
  else if(p->PnPAction==StorStartDevice||p->PnPAction==StorStopDevice||p->PnPAction==StorRemoveDevice||p->PnPAction==StorSurpriseRemoval)
   p->SrbStatus=SRB_STATUS_SUCCESS;
  goto done; /* a LUN notification never releases adapter mappings */
 }
 if(p->PnPAction==StorStopDevice||p->PnPAction==StorStartDevice){
  /* StorStopDevice is a notification before ScsiStopAdapter, not final
   * removal. Preserve resources/claim for the real stop/restart callbacks.
   * A start notification does not itself resume I/O or claim RUN is set.
   * This supports the retained fixed resources, not arbitrary PnP rebalance. */
  if(RetainedSession(a)&&(ActiveSession(a)||StoppedSession(a))){
   /* Leave the gate unchanged: Storport can still send its final FLUSH
    * between this notification and ScsiStopAdapter. */
   p->SrbStatus=SRB_STATUS_SUCCESS;
  }else p->SrbStatus=SRB_STATUS_NO_DEVICE;
 }else if(p->PnPAction==StorRemoveDevice||p->PnPAction==StorSurpriseRemoval){
  if(p->PnPAction==StorSurpriseRemoval)InterlockedExchange(&a->Removed,1);
  InterlockedExchange(&a->PowerStopped,1);
  if(!a->Worker&&!a->Mapped){p->SrbStatus=SRB_STATUS_SUCCESS;goto done;}
  p->SrbStatus=SRB_STATUS_PENDING;
  a->WorkerQueues++;
  ULONG status=a->Worker?StorPortQueueWorkItem(a,RemoveWorker,a->Worker,p):STOR_STATUS_INVALID_PARAMETER;
  if(status==STOR_STATUS_SUCCESS)return TRUE;
  a->Report.WorkerStatus=status;InterlockedExchange(&a->Stop,1);p->SrbStatus=SRB_STATUS_ERROR;
 }
 done:Finish(a,(PSCSI_REQUEST_BLOCK)p);return TRUE;
}
static int QueueWriteRequest(NUF_ADAPTER *a,PSCSI_REQUEST_BLOCK srb,NUF_REQUEST *q){
 if(!q){ScsiCheck(a,srb,4,0x44,0);return 0;}
 srb->SrbStatus=SRB_STATUS_PENDING;return QueueWorker(a,srb,WriteWorker);
}
static BOOLEAN StartIo(PVOID extension,PSCSI_REQUEST_BLOCK srb){NUF_ADAPTER *a=extension;
 if(srb->Function==SRB_FUNCTION_PNP)return PnpIo(a,(PSCSI_PNP_REQUEST_BLOCK)srb);
 NUF_REQUEST *q=srb->SrbExtension;
 srb->SrbStatus=SRB_STATUS_INVALID_REQUEST;srb->ScsiStatus=0;
 if(InterlockedCompareExchange(&a->Busy,1,0)!=0){
  FreeRequestWorker(a,q);srb->SrbStatus=SRB_STATUS_BUSY;
  StorPortNotification(RequestComplete,a,srb);return TRUE;}
 NUF_SCOPE_REPORT *query=ScopePacket(srb);
 if(query){if(srb->PathId||srb->TargetId||srb->Lun)srb->SrbStatus=SRB_STATUS_NO_DEVICE;else{
   if(InterlockedCompareExchange(&a->Stop,0,0)&&!a->Scope.FirstReason)ScopeFailure(a,NufScopeStopped);
   RtlCopyMemory(query,&a->Scope,sizeof(*query));((PSRB_IO_CONTROL)srb->DataBuffer)->ReturnCode=0;
   srb->SrbStatus=SRB_STATUS_SUCCESS;srb->ScsiStatus=0;
  }
 }else if(srb->Function==SRB_FUNCTION_IO_CONTROL&&srb->DataBuffer&&srb->DataTransferLength==sizeof(SRB_IO_CONTROL)+sizeof(NUF_REPORT)){
  PSRB_IO_CONTROL c=srb->DataBuffer;
  if(c->HeaderLength==sizeof(*c)&&c->ControlCode==NUF_CONTROL&&c->Length==sizeof(NUF_REPORT)&&RtlCompareMemory(c->Signature,Signature,8)==8){
   NUF_REPORT out;RtlCopyMemory(&out,&a->Report,sizeof(out));
   RtlCopyMemory((U8*)c+sizeof(*c),&out,sizeof(out));c->ReturnCode=0;srb->SrbStatus=SRB_STATUS_SUCCESS;}
 }else if(srb->Function==SRB_FUNCTION_EXECUTE_SCSI){
  U32 direction=((srb->SrbFlags&SRB_FLAGS_DATA_IN)?NufDirectionIn:0)|((srb->SrbFlags&SRB_FLAGS_DATA_OUT)?NufDirectionOut:0);
  if(srb->PathId||srb->TargetId||srb->Lun){srb->SrbStatus=SRB_STATUS_NO_DEVICE;srb->DataTransferLength=0;}
  else if(InterlockedCompareExchange(&a->Started,0,0)!=2||InterlockedCompareExchange(&a->Stop,0,0)||a->PowerStopped||a->Report.SessionState!=1){ScsiCheck(a,srb,2,4,0);}
  else{
   NUF_SCSI_RESULT p=NufScsiPlan(srb->Cdb,srb->CdbLength,direction,srb->DataBuffer,srb->DataTransferLength,a->LeaseCopy.LastLba);
   if(p.Disposition==NufScsiCheck){if(p.WriteDenied)a->Report.WriteRefused++;else a->Report.UnsupportedRequests++;ScsiCheck(a,srb,p.Key,p.Asc,p.Ascq);}
   else if(p.Disposition==NufScsiWrite||p.Disposition==NufScsiFlush){
    if(p.Disposition==NufScsiWrite&&!NufScopeContains(&a->Scope,p.Lba,srb->DataTransferLength)){
     a->Report.WriteRefused++;a->Scope.Rejected++;a->Scope.LastReason=NufScopeBounds;ScsiCheck(a,srb,7,0x27,0);
    }else{
     if(q){q->Operation=p.Disposition==NufScsiWrite?NufRequestWrite:NufRequestFlush;q->Flags=p.Flags;
      q->Lba=p.Lba;q->Bytes=p.Bytes;q->Tag=(U32)(a->Scope.Requests%255)+1;
     }
     if(QueueWriteRequest(a,srb,q))return TRUE;
    }
   }
   else if(p.Disposition==NufScsiRead){
    if(!q)ScsiCheck(a,srb,4,0x44,0);
    else{q->Lba=p.Lba;q->Bytes=p.Bytes;q->Tag=(U32)(a->Report.RuntimeRequests%255)+1;
     srb->SrbStatus=SRB_STATUS_PENDING;if(QueueWorker(a,srb,ReadWorker))return TRUE;}
   }else{
    if(srb->Cdb[0]==3&&a->SenseValid){U32 count=p.Bytes;if(count>sizeof(a->LastSense))count=sizeof(a->LastSense);
     if(count)RtlCopyMemory(srb->DataBuffer,a->LastSense,count);a->SenseValid=FALSE;}
    srb->SrbStatus=SRB_STATUS_SUCCESS;srb->DataTransferLength=p.Bytes;
   }
  }
 }else if(srb->Function==SRB_FUNCTION_SHUTDOWN||srb->Function==SRB_FUNCTION_FLUSH){
  /* Only Function/PathId/TargetId/Lun are input fields for these two SRBs.
   * Do not reject a valid notification using undefined transfer fields. */
  if(srb->PathId||srb->TargetId||srb->Lun||
     InterlockedCompareExchange(&a->Started,0,0)!=2||InterlockedCompareExchange(&a->Stop,0,0)||a->PowerStopped||a->Report.SessionState!=1)ScsiCheck(a,srb,2,4,0);
  else{if(q){q->Operation=srb->Function==SRB_FUNCTION_SHUTDOWN?NufRequestShutdown:NufRequestFlush;q->Tag=(U32)(a->Scope.Requests%255)+1;}
   if(QueueWriteRequest(a,srb,q))return TRUE;}
 }
 if(!FreeRequestWorker(a,q))ScsiCheck(a,srb,4,0x44,0);
 Finish(a,srb);return TRUE;
}
static BOOLEAN ResetBus(PVOID extension,ULONG path){UNREFERENCED_PARAMETER(extension);UNREFERENCED_PARAMETER(path);return FALSE;}
static BOOLEAN Interrupt(PVOID extension){
 /* Firmware declares the real IRQ281; HCI IE stays0. This polling candidate
  * never claims an interrupt or inspects hardware outside the passive owner. */
 UNREFERENCED_PARAMETER(extension);return FALSE;}
static SCSI_ADAPTER_CONTROL_STATUS Control(PVOID extension,SCSI_ADAPTER_CONTROL_TYPE type,PVOID params){
 NUF_ADAPTER *a=extension;
 if(type==ScsiQuerySupportedControlTypes){PSCSI_SUPPORTED_CONTROL_TYPE_LIST list=params;
  for(ULONG i=0;i<list->MaxControlType;i++)list->SupportedTypeList[i]=FALSE;
  if(ScsiQuerySupportedControlTypes<list->MaxControlType)list->SupportedTypeList[ScsiQuerySupportedControlTypes]=TRUE;
  if(ScsiStopAdapter<list->MaxControlType)list->SupportedTypeList[ScsiStopAdapter]=TRUE;
  if(ScsiRestartAdapter<list->MaxControlType)list->SupportedTypeList[ScsiRestartAdapter]=TRUE;
  if(ScsiAdapterSurpriseRemoval<list->MaxControlType)list->SupportedTypeList[ScsiAdapterSurpriseRemoval]=TRUE;
  return ScsiAdapterControlSuccess;}
 if(type==ScsiAdapterSurpriseRemoval){
  if(a->Scope.CacheDirty)a->Scope.WriteUncertain=1;
  InterlockedExchange(&a->Removed,1);InterlockedExchange(&a->PowerStopped,1);InterlockedExchange(&a->Stop,1);
  return ScsiAdapterControlSuccess;
 }
 if(type!=ScsiStopAdapter&&type!=ScsiRestartAdapter)return ScsiAdapterControlUnsuccessful;
 if(InterlockedCompareExchange(&a->Busy,1,0)!=0){
  /* The documented stop contract drains SRBs. Never claim a concurrent DMA
   * was retired; its existing passive owner will finish/quarantine it. */
  InterlockedExchange(&a->PowerStopped,1);InterlockedExchange(&a->Stop,1);return ScsiAdapterControlUnsuccessful;
 }
 int ok=0;a->Engine.Report=&a->IoReport;
 if(type==ScsiStopAdapter){
  InterlockedExchange(&a->PowerStopped,1);
  if(!a->Mapped)ok=!a->Claimed&&!a->Stop&&!a->Removed&&!a->Engine.Quarantined;
  else if(RetainedSession(a)&&!a->Scope.CacheDirty&&!a->Scope.WriteUncertain){
   if(StoppedSession(a))ok=1; /* Already retired: no duplicate MMIO or cleanup. */
   else if(ActiveSession(a))ok=NufSessionStop(&a->Engine);
  }
  if(ok)a->Report.SessionState=2;
 }else if(RetainedSession(a)){
  if(!a->PowerStopped&&a->Report.SessionState==1&&ActiveSession(a))ok=1;
  else if(a->PowerStopped&&StoppedSession(a))ok=NufSessionRestart(&a->Engine);
  if(ok){a->Report.SessionState=1;InterlockedExchange(&a->PowerStopped,0);}
 }
 if(!ok){a->Report.SessionState=3;a->Report.RuntimeQuarantined=1;InterlockedExchange(&a->Stop,1);}
 InterlockedExchange(&a->Busy,0);return ok?ScsiAdapterControlSuccess:ScsiAdapterControlUnsuccessful;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING registry){HW_INITIALIZATION_DATA init;
 if(!object||!registry)return STATUS_NOT_SUPPORTED;
 RtlZeroMemory(&init,sizeof(init));init.HwInitializationDataSize=sizeof(init);init.AdapterInterfaceType=InterfaceTypeUndefined;
 init.DeviceExtensionSize=sizeof(NUF_ADAPTER);init.HwFindAdapter=FindAdapter;init.HwInitialize=Initialize;
 init.HwStartIo=StartIo;init.HwBuildIo=BuildIo;init.SrbExtensionSize=sizeof(NUF_REQUEST);init.HwInterrupt=Interrupt;init.HwResetBus=ResetBus;init.HwAdapterControl=Control;
 init.NumberOfAccessRanges=4;init.MapBuffers=STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE;
 /* Storport's physical-miniport contract requires these capabilities. The
  * adapter exposes one LUN with immutable NTFS extent write admission and queue depth one.
  * SRB buffers never become device DMA buffers. */
 init.NeedPhysicalAddresses=TRUE;init.TaggedQueuing=TRUE;init.AutoRequestSense=TRUE;init.MultipleRequestPerLu=TRUE;
 init.FeatureSupport=STOR_FEATURE_SET_ADAPTER_INTERFACE_TYPE|STOR_FEATURE_ADAPTER_NOT_REQUIRE_IO_PORT;
 init.SrbTypeFlags=SRB_TYPE_FLAG_SCSI_REQUEST_BLOCK;init.AddressTypeFlags=ADDRESS_TYPE_FLAG_BTL8;
 return StorPortInitialize(object,registry,&init,NULL);}
