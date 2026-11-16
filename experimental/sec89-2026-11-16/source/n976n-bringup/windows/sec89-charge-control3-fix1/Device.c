/* SPDX-License-Identifier: MIT
 * SEC89 D0-owned battery KMDF/Battc adapter. Class IRP/WMI plumbing follows pinned
 * Microsoft SimBatt, see FRONTEND.md and references/ms-simbatt/wdf.c. One
 * PASSIVE producer owns HSI45. Query callbacks only read the expiring cache.
 */
#include <ntddk.h>
#include <wdf.h>
#include <wmistr.h>
#include <wmilib.h>
#include <batclass.h>
#include "Miniclass.h"
#include "Backend.h"
#include "Resources.h"
#include "ClockShare.h"
#include "ThermalBridge.h"
#include "AdcWdf.h"
#include "PowerSource.h"
#include "ChargeControl.h"
#include "DiagProtocol.h"
#include "Connection.h"
int N976nBenchFacts(const N976N_SOURCE_STATE *,const N976N_POWER_RAW *,N976N_BAT_U64,NCC_FACTS *);

typedef struct {
 WDFDEVICE Device; WDFWAITLOCK StateLock,ClassLock;
 N976N_BATTERY_CACHE Cache; N976N_BATTERY_MINICLASS_CONTEXT Mini;
 PVOID ClassHandle; WMILIB_CONTEXT Wmi; UNICODE_STRING RegistryPath;
 BOOLEAN WmiRegistered,Claimed,LeaseValidated; ULONG Mapped;
 NCA_WDF *Adc; BOOLEAN D0Entered,HsiFinalChecked; volatile LONG QuarantinePending;
 PVOID Maps[N976N_BAT_RESOURCES]; N976N_BAT_U64 LeaseAddress;
 N976N_BAT_LEASE *Lease; N976N_BAT_LEASE Copy;
 N976N_POWER_RAW PowerRaw;N976N_POWER_VALUES PowerValues;N976N_POWER_DECISION PowerDecision;
 N976N_SOURCE_STATE Source;
 NCC_CONTEXT Control;NCC_FACTS ControlFacts;
 NCL_CONNECTION Connection;ULONG HoldReason;
 ULONG ControlAttempt,ControlPreflight,PreflightEvidence;ULONGLONG ControlCycles,LastCycleAt;
 /* Actual ADC provider bound only after the complete v3 resource/lease admission. */
 NCT_CONTEXT Thermal;NCT_OPS ThermalOps;void *ThermalOwner;
 NCT_IDENTITY ThermalIdentity;
 N976N_BAT_BACKEND Backend; N976N_BAT_BACKEND_SAMPLE Last;
 KEVENT StopEvent; volatile LONG StopRequested,AccessRefused;
 HANDLE Thread; ULONGLONG Generation,Samples,Failures;
 ULONG Stage; NTSTATUS LastStatus;
 /* Worker-owned observation, copied under StateLock; IOCTL never reads live
  * controller state or mutable Control/Source fields. No kernel pointers. */
 NCD_REPORT Diag; NCD_QUERY DiagQuery;
 NCD_BUS_EVENT QuarantineBus;ULONGLONG QuarantineAt100ns;ULONG QuarantineSite;
 N976N_POWER_RAW DiagPower;
 ULONGLONG DiagPowerAt,DiagPowerStatus,DiagStartCalls,DiagManagedStarts,DiagManagedAt;
 ULONGLONG SnapshotCalls,SnapshotTotalMs,SnapshotMaxMs,StartSnapshotCalls,StartElapsedMs;
} BAT_DEVICE;
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(BAT_DEVICE,BatGet)
DRIVER_INITIALIZE DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD BatAdd;
EVT_WDF_DEVICE_PREPARE_HARDWARE BatPrepare;
EVT_WDF_DEVICE_RELEASE_HARDWARE BatRelease;
EVT_WDF_DEVICE_D0_ENTRY BatD0Entry;
EVT_WDF_DEVICE_D0_EXIT BatD0Exit;
EVT_WDF_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED BatPostIrq;
EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED BatPreIrq;
EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT BatClassInit;
EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP BatClassCleanup;
EVT_WDFDEVICE_WDM_IRP_PREPROCESS BatIoctl;
EVT_WDFDEVICE_WDM_IRP_PREPROCESS BatSystemControl;
EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL BatUnsupported;
static void BatStateLock(PVOID p){WdfWaitLockAcquire(((BAT_DEVICE*)p)->StateLock,NULL);}
static void BatStateUnlock(PVOID p){WdfWaitLockRelease(((BAT_DEVICE*)p)->StateLock);}
static N976N_BAT_U64 Now(PVOID p){ULONGLONG q;UNREFERENCED_PARAMETER(p);return KeQueryInterruptTimePrecise(&q);}
static int Cancel(void *p){return InterlockedCompareExchange(&((BAT_DEVICE*)p)->StopRequested,0,0)!=0;}
static void Fence(void *p){UNREFERENCED_PARAMETER(p);KeMemoryBarrier();}
static N976N_BAT_U64 Counter(void *p){UNREFERENCED_PARAMETER(p);return (N976N_BAT_U64)KeQueryPerformanceCounter(NULL).QuadPart;}
static void Stall(void *p,N976N_BAT_U32 us){UNREFERENCED_PARAMETER(p);if(us<=100)KeStallExecutionProcessor(us);}
static int Owned(BAT_DEVICE *c);
static volatile ULONG *Register(BAT_DEVICE *c,N976N_BAT_U64 a,BOOLEAN write)
{
 ULONG i;
 if(!Owned(c)||(a&3)|| (write&&!N976nBatWriteAllowed(a)))goto Refuse;
 for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++) {
  N976N_BAT_U64 start=N976nBatResources[i].Address;
  if(a>=start&&a-start<=N976nBatResources[i].Bytes-4&&c->Maps[i]&&
     (!write||N976nBatResources[i].Writable))return (volatile ULONG*)((PUCHAR)c->Maps[i]+(SIZE_T)(a-start));
 }
Refuse:
 InterlockedExchange(&c->AccessRefused,1);return NULL;
}
static N976N_BAT_U32 Read(void *p,N976N_BAT_U64 a)
{volatile ULONG *r=Register(p,a,FALSE);return r?READ_REGISTER_ULONG(r):MAXULONG;}
static void Write(void *p,N976N_BAT_U64 a,N976N_BAT_U32 v)
{volatile ULONG *r=Register(p,a,TRUE);if(r)WRITE_REGISTER_ULONG(r,v);}
static const N976N_BAT_BUS_OPS Ops={Read,Write,Fence,Counter,Stall,Cancel};
static void Notify(BAT_DEVICE *c)
{
 /* Never hold StateLock here: Battc may reenter QueryStatus synchronously. */
 WdfWaitLockAcquire(c->ClassLock,NULL);
 if(c->ClassHandle)BatteryClassStatusNotify(c->ClassHandle);
 WdfWaitLockRelease(c->ClassLock);
}
static void BusEvent(NCD_BUS_EVENT *out,const N976N_BAT_BUS_REPORT *in)
{
 out->SampleId=in->SampleId;out->Reason=in->Reason;out->Status=in->Status;
 out->FailurePhase=in->FailurePhase;out->Requested=in->Requested;out->Received=in->Received;
 out->FirstInterrupt=in->FirstInterrupt;out->FirstFifo=in->FirstFifo;
 out->FirstWaitUs=in->FirstWaitUs;out->FirstWaitExit=in->FirstWaitExit;
 out->FirstAddress=in->FirstAddress;out->FirstExpected=in->FirstExpected;
 out->FirstActual=in->FirstActual;out->FirstMask=in->FirstMask;
}
static void Quarantine(BAT_DEVICE *c,ULONG site)
{
 /* Keep our claim through HSI rundown AND ADC EvtInterruptDisable. An ADC
  * fault must not mark the unrelated HSI engine unsafe before its cleanup. */
 /* The producer captures its cached report before rundown; lifecycle callers
  * run before the worker or after join. FIRST is never reset by cleanup. */
 if(InterlockedCompareExchange(&c->QuarantinePending,1,0)==0){
  c->QuarantineSite=site;c->QuarantineAt100ns=Now(c);
  BusEvent(&c->QuarantineBus,&c->Backend.Bus.Report);
 }
 InterlockedExchange(&c->StopRequested,1);
 if(c->Adc)NcaWdfRequestStop(c->Adc);
 KeSetEvent(&c->StopEvent,IO_NO_INCREMENT,FALSE);
}
static int Owned(BAT_DEVICE *c)
{
 KeMemoryBarrier();
 return c->Claimed&&c->LeaseValidated&&c->Lease&&N976nBatLeaseMatches(&c->Copy,c->Lease,
   *(volatile ULONGLONG*)((PUCHAR)c->Lease+4088));
}
static int AdcOwned(void *p)
{BAT_DEVICE *c=p;return !c->AccessRefused&&Owned(c);}
static uint32_t AdcRead(void *p,uint64_t a)
{
 BAT_DEVICE *c=p;unsigned i;
 if(a==NCA_BASE||a==NCA_BASE+4||a==NCA_BASE+8||a==NCA_BASE+0x10)return Read(c,a);
 for(i=0;i<NCA_CLOCKS;i++)if(a==NcaClockAddresses[i])return Read(c,a);
 InterlockedExchange(&c->AccessRefused,1);return UINT32_MAX;
}
static void AdcWrite(void *p,uint64_t a,uint32_t value)
{
 BAT_DEVICE *c=p;
 if(!Owned(c)||!N976nBatAdcWriteAllowed(a)||!c->Maps[N976N_BAT_ADC_INDEX]){
  InterlockedExchange(&c->AccessRefused,1);return;
 }
 WRITE_REGISTER_ULONG((volatile ULONG*)((PUCHAR)c->Maps[N976N_BAT_ADC_INDEX]+(SIZE_T)(a-NCA_BASE)),value);
}
static const NCA_OPS AdcOps={AdcRead,AdcWrite,Fence,Now,AdcOwned};
static int PrepareThermal(BAT_DEVICE *c,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 NCT_PROFILE profile;NCA_BINDING binding;unsigned i,j;NTSTATUS status;
 const NCA_LEASE_BINDING *a=&c->Copy.Adc;
 RtlZeroMemory(&profile,sizeof(profile));RtlZeroMemory(&binding,sizeof(binding));
 RtlCopyMemory(profile.DtHash,a->AdmissionDigest,32);
 profile.AdcAddress=a->Thermal.AdcAddress;profile.AdcBytes=a->Thermal.AdcBytes;profile.Irq=a->Thermal.Irq;
 for(i=0;i<3;i++){
  profile.Channel[i]=(uint8_t)a->Thermal.Channels[i];
  profile.MaxMiddleSpread[i]=64; /* local observation cap, not a Samsung hardware limit */
  for(j=0;j<NCT_POINTS;j++){profile.Adc[i][j]=(uint16_t)a->Thermal.Adc[i][j];profile.DeciC[i][j]=a->Thermal.DeciC[i][j];}
 }
 if(!NctInit(&c->Thermal,&profile,a->Generation))return 0;
 RtlCopyMemory(binding.Original,a->Original,sizeof(binding.Original));
 RtlCopyMemory(binding.Clocks,a->Clocks,sizeof(binding.Clocks));binding.Generation=a->Generation;
 binding.FirmwareRetired=a->FirmwareRetired;binding.FirmwareRestored=a->FirmwareRestored;
 binding.FirmwareIrqDetached=a->FirmwareIrqDetached;
 status=NcaWdfPrepare(c->Adc,&AdcOps,c,&binding,
  WdfCmResourceListGetDescriptor(raw,N976N_BAT_IRQ_INDEX),
  WdfCmResourceListGetDescriptor(translated,N976N_BAT_IRQ_INDEX));
 if(!NT_SUCCESS(status))return 0;
 c->ThermalOps.Identity=NcaWdfIdentity;c->ThermalOps.Convert=NcaWdfConvert;c->ThermalOwner=c->Adc;
 return 1;
}
static void ResetUnstartedThermal(BAT_DEVICE *c)
{
 /* A failed Prepare is retryable only before any D0/IRQ initialization. Never
  * erase a used/cancelled engine or its failure record to manufacture resume. */
 if(c->D0Entered||!c->Adc||c->Adc->Engine.Initialized||c->Adc->Enabled||c->Adc->Active)return;
 if(!NT_SUCCESS(NcaWdfRelease(c->Adc))){Quarantine(c,NCD_Q_ADC_RELEASE);return;}
 RtlZeroMemory(&c->Thermal,sizeof(c->Thermal));
 RtlZeroMemory(&c->ThermalOps,sizeof(c->ThermalOps));c->ThermalOwner=NULL;
 RtlZeroMemory(&c->ThermalIdentity,sizeof(c->ThermalIdentity));
}
static void InvalidatePower(BAT_DEVICE *c)
{
 N976nSourceInvalidate(&c->Source);
 NctInvalidate(&c->Thermal,NCT_MISSING,0);
 RtlZeroMemory(&c->PowerValues,sizeof(c->PowerValues));
 N976nPowerEvaluate(NULL,NULL,&c->PowerDecision);
 /* PowerRaw is diagnostic only; the next sampling attempt clears it. */
}
static N976N_BAT_U64 ObserveCharge(BAT_DEVICE *c,N976N_POWER_RAW *r)
{
 N976N_BAT_U64 start=Now(c);
 N976N_BAT_U64 s=N976nBatBusReadChargeActive(&c->Backend.Bus,c->Samples,r);
 c->DiagPowerStatus=s;
 if(!s){c->DiagPower=*r;c->DiagPowerAt=start;}
 return s;
}
/* Called by the single producer or after its confirmed join, with StateLock held, at completed
 * software publication boundaries. Physical fields were sampled sequentially. */
static void PublishDiagLocked(BAT_DEVICE *c,ULONG point,ULONG live)
{
 NCD_REPORT r;N976N_POWER_VALUES v;ULONGLONG sequence=c->Diag.Sequence;
 RtlZeroMemory(&r,sizeof(r));RtlZeroMemory(&v,sizeof(v));
 r.PowerDecoded=(ULONG)N976nPowerDecode(&c->DiagPower,&v);
 r.Magic=NCD_MAGIC;r.Version=NCD_VERSION;r.Bytes=sizeof(r);r.Driver=NCD_DRIVER;
 r.Sequence=sequence==UINT64_MAX?sequence:sequence+1;r.Published100ns=Now(c);r.Generation=c->Generation;
 r.Samples=c->Samples;r.Failures=c->Failures;r.ControlCycles=c->ControlCycles;
 r.StartedMs=c->Control.StartedAt;r.StoppedMs=c->Control.StoppedAt;
 r.LastServiceMs=c->Control.LastService;r.LastKickMs=c->Control.LastKick;
 r.StartCalls=c->DiagStartCalls;r.ManagedStarts=c->DiagManagedStarts;r.ManagedAtMs=c->DiagManagedAt;
 r.PowerAt100ns=c->DiagPowerAt;r.PowerReadStatus=c->DiagPowerStatus;
 r.GaugeStart100ns=c->Cache.View.SampleStart100ns;r.GaugeEnd100ns=c->Cache.View.SampleCompleted100ns;
 r.SourceStart100ns=c->Source.StartedAt;r.SourceEnd100ns=c->Source.CompletedAt;r.SourceEpoch=c->Source.Epoch;
 r.Stage=c->Stage;r.Status=(ULONG)c->LastStatus;r.Point=point;r.WorkerLive=live;
 r.StopRequested=!!Cancel(c);r.Quarantined=!!(c->QuarantinePending||c->Backend.Bus.Quarantined);
 r.ControlState=c->Control.State;r.Reason=c->Control.Reason;r.FirstReason=c->Control.FirstReason;
 r.Attempt=c->ControlAttempt;r.Preflight=c->ControlPreflight;r.Mode4Confirmed=c->Control.Mode4Confirmed;r.Uncertain=c->Control.Uncertain;
 r.ControlReads=c->Control.Reads;r.ControlWrites=c->Control.Writes;r.ControlKicks=c->Control.Kicks;
 r.SessionMs=c->Control.Plan.SessionMs;r.ChargeMa=c->Control.Plan.ChargeMa;
 r.PowerValidMask=c->DiagPower.ValidMask;
 r.GaugeValidMask=c->Cache.HaveSample?c->Cache.View.Values.ValueValidMask:0;
 r.SourceValid=c->Source.Valid;r.SourceOnlineKnown=c->Source.OnlineKnown;r.SourceOnline=c->Source.Online;
 r.Mode=v.Mode;r.Detail=v.ChargeDetail;r.WdtEnabled=v.WdtEnabled;r.WdtExpired=v.WdtExpired;
 r.InputMa=v.InputMa;r.ConfiguredMa=v.ChargeMa;r.CvMv=v.CvMv;r.RpCode=v.RpCode;r.PsReady=v.PsReady;
 r.CurrentMa=c->Cache.View.Values.CurrentMa;r.VoltageMv=c->Cache.View.Values.VoltageMv;
 r.SocPermille=c->Cache.View.Values.SocPermille;r.GaugeChargeState=c->Cache.View.Values.ChargeState;
 RtlCopyMemory(r.PowerRaw,c->DiagPower.Byte,sizeof(c->DiagPower.Byte));
 r.InputAtMs=c->Control.InputAt;r.InputSourceEpoch=c->Control.InputSourceEpoch;
 r.InputFallbackConfirmed=c->Control.InputFallbackConfirmed;r.InputTouched=c->Control.InputTouched;
 r.InputConfigured=c->Control.InputConfigured;r.InputWrites=c->Control.InputWrites;
 r.InputBefore=c->Control.InputBefore;r.InputAfter=c->Control.InputAfter;
 r.PreflightEvidence=c->PreflightEvidence;r.PreflightMissing=NCC_BENCH_EVIDENCE&~c->PreflightEvidence;
 r.FirstPhase=c->Control.First.Phase;r.FirstSite=c->Control.First.Site;
 r.FirstControlReason=c->Control.First.Reason;r.FirstSnapshotIssue=c->Control.First.Facts.SnapshotIssue;
 r.FirstThermalReason=c->Control.First.Facts.ThermalReason;r.FirstEvidence=c->Control.First.Facts.Evidence;
 r.FirstMaxAgeMs=c->Control.First.Facts.MaxAgeMs;r.FirstServiceMs=c->Control.First.Facts.WatchdogServiceMs;
 r.FirstNowMs=c->Control.First.Now;r.FirstSampleMs=c->Control.First.Facts.SampleAt;
 r.FirstSourceMs=c->Control.First.Facts.SourceAt;r.FirstThermalMs=c->Control.First.Facts.ThermalAt;
 r.FirstKickMs=c->Control.First.LastKick;r.FirstStartedMs=c->Control.First.StartedAt;
 r.SnapshotCalls=c->SnapshotCalls;r.SnapshotTotalMs=c->SnapshotTotalMs;r.SnapshotMaxMs=c->SnapshotMaxMs;
 r.StartSnapshotCalls=c->StartSnapshotCalls;r.StartElapsedMs=c->StartElapsedMs;
 r.Policy=NCC_CONTINUOUS;r.HoldReason=c->HoldReason;
 r.Attachment=c->Connection.Id;r.Detaches=c->Connection.Detaches;
 r.ConnectionSignal=c->Connection.Signal;r.Detached=c->Connection.Detached;
 r.ConnectionFault=c->Connection.Fault;
 r.QuarantineAt100ns=c->QuarantineAt100ns;r.QuarantineSite=c->QuarantineSite;
 r.QuarantineBus=c->QuarantineBus;BusEvent(&r.FirstBus,&c->Backend.Bus.FirstFailure);
 c->Diag=r;
}
static NTSTATUS DiagQueryStatus(PVOID p,ULONG tag,PBATTERY_STATUS out)
{
 N976N_BATTERY_MINICLASS_CONTEXT *mini=p;BAT_DEVICE *c=mini->Owner;
 NTSTATUS s=N976nBatteryQueryStatus(p,tag,out);
 BatStateLock(c);if(c->DiagQuery.Count!=UINT64_MAX)++c->DiagQuery.Count;c->DiagQuery.At100ns=Now(c);
 c->DiagQuery.Status=(ULONG)s;c->DiagQuery.Tag=tag;
 c->DiagQuery.PowerState=NT_SUCCESS(s)&&out?out->PowerState:0;
 c->DiagQuery.Capacity=NT_SUCCESS(s)&&out?out->Capacity:BATTERY_UNKNOWN_CAPACITY;
 c->DiagQuery.Voltage=NT_SUCCESS(s)&&out?out->Voltage:BATTERY_UNKNOWN_VOLTAGE;
 /* Actual callback return and its recording time only. This is deliberately
  * not labelled as an atomic match to the worker's hardware snapshot. */
 BatStateUnlock(c);return s;
}
static void CollectThermal(BAT_DEVICE *c,N976N_POWER_FACTS *f)
{
   /* One batch per producer cycle, never per repeated policy Snapshot call. */
   RtlZeroMemory(&c->ThermalIdentity,sizeof(c->ThermalIdentity));
   if(!f->OwnerReady||Cancel(c))NctInvalidate(&c->Thermal,Cancel(c)?NCT_CANCELLED:NCT_OWNER,0);
   else if(NctCollect(&c->Thermal,&c->ThermalOps,c->ThermalOwner,500)) {
    if(c->ThermalOps.Identity(c->ThermalOwner,&c->ThermalIdentity))f->Now=c->ThermalIdentity.Now100ns;
    else NctInvalidate(&c->Thermal,NCT_OWNER,1);
   }
   /* Thermal freshness remains distinct from source-current admission. */
   f->OwnerReady=c->Backend.Bus.D0Active&&!c->Backend.Bus.Quarantined&&Owned(c)&&!Cancel(c)&&!c->AccessRefused;
   if(Cancel(c)){c->ThermalIdentity.Cancelled=1;NctInvalidate(&c->Thermal,NCT_CANCELLED,0);}
   N976nThermalObserve(&c->Thermal,&c->ThermalIdentity,f);
   if(c->Thermal.Quarantined||c->Adc->Engine.Quarantined)Quarantine(c,NCD_Q_THERMAL);
}
static int ControlOwner(void *p,NCC_IDENTITY *o)
{
 BAT_DEVICE *c=p;RtlZeroMemory(o,sizeof(*o));o->Now=Now(c)/10000;
 o->OwnerGeneration=c->Generation;o->Cancelled=(uint8_t)!!Cancel(c);
 o->OwnerReady=Owned(c)&&!c->AccessRefused&&c->Backend.Bus.D0Active&&!c->Backend.Bus.Quarantined;
 o->Retired=c->Backend.Bus.Report.Retired&&!c->Backend.Bus.S.InTransaction&&!c->Backend.Bus.S.Held;
 return o->OwnerReady&&o->Retired;
}
static int ControlGuard(void *p,const NCC_TICKET *t)
{
 BAT_DEVICE *c=p;NCC_IDENTITY o;N976N_BAT_U64 now;
 /* Admission requires retired. The payload of this exact admitted transfer
  * may continue while InTransaction; it is not a new request or new owner. */
 ControlOwner(c,&o);
 if(!t||!o.OwnerReady||o.OwnerGeneration!=t->OwnerGeneration||
    (!o.Retired&&!(c->Backend.Bus.ControlPayload&&c->Backend.Bus.S.InTransaction&&
                 c->Backend.Bus.ControlTicket==t)))return 0;
 /* Once this exact payload has issued RUN, finish its bounded transfer.
  * Ordinary cancellation/freshness expiry is handled before the next request,
  * then MODE4 cleanup; owner/generation loss still refuses immediately. */
 if(!o.Retired&&c->Backend.Bus.ControlPayload&&c->Backend.Bus.S.InTransaction&&
    c->Backend.Bus.ControlTicket==t)return 1;
 if(t->Cleanup)return 1; /* Bus API restricts this to B7 MODE4 only. */
 now=Now(c)/10000;
 return !o.Cancelled&&c->Source.Valid&&c->Source.Epoch==t->SourceEpoch&&
   now>=t->CheckedAt&&now<t->NotAfter;
}
static enum NCC_IO_RESULT ControlRead(void *p,uint8_t addr,uint8_t reg,uint8_t *v,const NCC_TICKET *t)
{BAT_DEVICE *c=p;if(addr!=0x69)return NCC_IO_NOT_ISSUED;
 return N976nBatBusControl(&c->Backend.Bus,0,reg,v,t,ControlGuard,c);}
static enum NCC_IO_RESULT ControlWrite(void *p,uint8_t addr,uint8_t reg,uint8_t v,const NCC_TICKET *t)
{BAT_DEVICE *c=p;if(addr!=0x69)return NCC_IO_NOT_ISSUED;
 return N976nBatBusControl(&c->Backend.Bus,1,reg,&v,t,ControlGuard,c);}
/* Diagnostic issue IDs: 1 owner, 2 cancelled, 3 charge-read, 4 source mismatch,
 * 5 source facts/age, 6 ADC identity, 7 thermal facts. No new admission policy. */
static int ControlSnapshotInner(BAT_DEVICE *c,NCC_FACTS *f)
{
 NCC_IDENTITY o;NCT_IDENTITY a;N976N_POWER_RAW r;N976N_BAT_U64 benchNow;
 RtlZeroMemory(f,sizeof(*f));
 f->SourceAt=c->Source.StartedAt/10000;f->ThermalAt=c->Thermal.Result.Oldest100ns/10000;
 f->ThermalReason=c->Thermal.Reason;
 if(!ControlOwner(c,&o)){f->SnapshotIssue=1;f->Now=o.Now;return 0;}
 f->Now=o.Now;f->OwnerGeneration=o.OwnerGeneration;f->OwnerReady=o.OwnerReady;
 f->Retired=o.Retired;f->Cancelled=o.Cancelled;
 if(o.Cancelled){f->SnapshotIssue=2;return 1;}
 /* Register refresh cannot renew either the source or thermal timestamp. */
 if(ObserveCharge(c,&r)){
  f->SnapshotIssue=3;InvalidatePower(c);
  int ok=ControlOwner(c,&o);f->Now=o.Now;f->OwnerReady=o.OwnerReady;f->Retired=o.Retired;f->Cancelled=o.Cancelled;
  return ok;
 }
 if(!ControlOwner(c,&o)){f->SnapshotIssue=1;f->Now=o.Now;return 0;}
 f->Now=o.Now;f->Retired=o.Retired;
 if(!N976nSourceMatches(&c->Source,&r)){f->SnapshotIssue=4;InvalidatePower(c);return 1;}
 c->PowerRaw=r;N976nPowerDecode(&r,&c->PowerValues);
 benchNow=Now(c);f->Now=benchNow/10000;
 if(!N976nBenchFacts(&c->Source,&r,benchNow,f)){f->SnapshotIssue=5;return 1;}
 if(!NcaWdfIdentity(c->Adc,&a)){
  f->SnapshotIssue=6;NctInvalidate(&c->Thermal,NCT_OWNER,1);Quarantine(c,NCD_Q_SNAPSHOT_OWNER);
  f->Cancelled=1;f->ThermalReason=c->Thermal.Reason;return 1;
 }
 f->Now=a.Now100ns/10000;
 if(!NctApply(&c->Thermal,&a,f))f->SnapshotIssue=7;
 f->ThermalReason=c->Thermal.Reason;
 c->ControlFacts=*f;return 1;
}
static int ControlSnapshot(void *p,NCC_FACTS *f)
{
 BAT_DEVICE *c=p;ULONGLONG start=Now(c)/10000,end,duration;
 int ok=ControlSnapshotInner(c,f);end=Now(c)/10000;
 if(c->SnapshotCalls!=UINT64_MAX)++c->SnapshotCalls;
 if(end>=start){
  duration=end-start;
  if(duration>c->SnapshotMaxMs)c->SnapshotMaxMs=duration;
  c->SnapshotTotalMs=duration>UINT64_MAX-c->SnapshotTotalMs?UINT64_MAX:c->SnapshotTotalMs+duration;
 }
 return ok;
}
static const NCC_OPS ControlOps={ControlSnapshot,ControlOwner,ControlRead,ControlWrite};
static void ControlCycle(BAT_DEVICE *c)
{
 NCC_FACTS f;NCC_REQUEST request={600,NCC_CONTINUOUS_SAFETY_MS,NCC_CONTINUOUS};
 ULONGLONG observedAt=Now(c)/10000;
 int attached=NclObserve(&c->Connection,observedAt,c->Source.StartedAt/10000,
    c->Source.CompletedAt/10000,c->Source.Valid,c->Source.OnlineKnown,c->Source.Online);
 ++c->ControlCycles;
 if(c->Connection.Fault){
  c->HoldReason=NCC_STALE;
  if(c->ControlAttempt&&!c->Control.Uncertain&&(c->Control.State!=NCC_MODE4_CONFIRMED||c->Control.InputTouched)){c->ControlAttempt=3;NccStop(&c->Control);}
  return;
 }
 if(attached&&c->Connection.Id>1){
  /* A new physical attachment does not grant a new owner or erase errors.
   * Rearm later rechecks facts newer than Stop; never Init a live context. */
  if(!Cancel(c)&&!c->Control.CancelLatched&&!c->Control.Uncertain&&
     c->Control.State==NCC_MODE4_CONFIRMED&&c->Control.Mode4Confirmed&&
     !c->Control.Mode4NotConfirmed&&!c->Control.InputTouched&&!c->Control.InputConfigured){
   c->ControlAttempt=0;c->HoldReason=0;InvalidatePower(c);return;
  }
 }
 if(c->Connection.Signal==NCL_OFFLINE&&c->ControlAttempt){
  c->HoldReason=NCC_SOURCE;c->ControlAttempt=3;
  if(!c->Control.Uncertain&&(c->Control.State!=NCC_MODE4_CONFIRMED||c->Control.InputTouched))
   NccStop(&c->Control);
  return;
 }
 if(c->Control.State==NCC_MANAGED){
  if(!NccService(&c->Control))c->HoldReason=c->Control.Reason;
  return;
 }
 if(c->ControlAttempt>=3||c->Control.Uncertain)return;
 if(c->Connection.Signal!=NCL_ONLINE)goto AbortInput;
 if(!ControlSnapshot(c,&f)){c->ControlPreflight=NCC_OWNER;goto AbortInput;}
 c->PreflightEvidence=f.Evidence;
 c->ControlPreflight=NccBenchPreflight(&f);
 if(c->ControlPreflight)goto AbortInput;
 /* Samsung maps both top-off/done (3/4) to FULL. This development profile
  * conservatively stops here instead of implementing Samsung's second stage. */
 if((f.Raw[2]&15)==3||(f.Raw[2]&15)==4){
  c->HoldReason=NCC_FULL;c->ControlAttempt=3;NccStop(&c->Control);return;
 }
 if(!c->ControlAttempt){
  c->ControlAttempt=1;
  if(!NccStop(&c->Control)){c->ControlAttempt=3;c->HoldReason=c->Control.Reason;}
  return; /* New independent sensor/source sample after the confirmed stop. */
 }
 if(c->ControlAttempt==1){
  c->ControlAttempt=2;
  if(!NccPrepareInput900(&c->Control)){c->ControlAttempt=3;c->HoldReason=c->Control.Reason;}
  /* C0 remains part of source identity. Do not fake an unchanged epoch or
   * reuse pre-change ADC facts: next producer cycle recollects both. */
  InvalidatePower(c);
  return;
 }
 c->ControlAttempt=3;
 if(NccRearm(&c->Control,&request)){
  ULONGLONG at=Now(c)/10000,calls=c->SnapshotCalls,end;
  ++c->DiagStartCalls;
  if(NccStart(&c->Control,&request)){++c->DiagManagedStarts;c->DiagManagedAt=Now(c)/10000;}
  end=Now(c)/10000;c->StartElapsedMs=end>=at?end-at:0;
  c->StartSnapshotCalls=c->SnapshotCalls-calls;
 }
AbortInput:
 if(c->ControlAttempt>=3&&c->Control.State!=NCC_MANAGED&&!c->HoldReason)c->HoldReason=c->Control.Reason;
 /* Prepared input is a live obligation even before MODE5. A failed fresh
  * source/thermal observation or start consumes the attempt and lowers ICL. */
 if(c->Control.InputTouched&&c->Control.State!=NCC_MANAGED&&!c->Control.Uncertain){
  c->HoldReason=c->ControlPreflight?c->ControlPreflight:(c->Control.Reason?c->Control.Reason:NCC_STALE);
  c->ControlAttempt=3;NccStop(&c->Control);
 }
 /* No retry on this attachment. Only separately confirmed detach+attach
  * can grant a fresh attempt; cancellation/uncertainty are never cleared. */
}
/* A clean failed gauge transaction may retain the previous observation only
 * until its ORIGINAL TTL. This is never input to charging control. Caller
 * holds StateLock; CacheRead still enforces clock/TTL and source freshness. */
static int KeepFailedGaugeLocked(BAT_DEVICE *c,ULONGLONG start,ULONGLONG end,ULONGLONG now)
{
 N976N_BATTERY_CACHE_VIEW view;
 if(!c->Last.CleanReadFailure || c->Last.Publishable || !c->Last.Status ||
    start>end || end>now || Cancel(c) || c->AccessRefused ||
    c->QuarantinePending || c->Backend.Bus.Quarantined || !c->Backend.Bus.D0Active ||
    c->Control.Uncertain || !Owned(c) || c->Generation!=c->Cache.Generation)return 0;
 return N976nBatteryCacheRead(&c->Cache,now,&view);
}
static void Worker(void *p)
{
 BAT_DEVICE *c=p;LARGE_INTEGER delay;ULONGLONG start,end;enum N976N_BATTERY_CACHE_RESULT accepted;
 N976N_BAT_U64 acquired;
 InvalidatePower(c);
 NccInit(&c->Control,&ControlOps,c);
 BatStateLock(c);PublishDiagLocked(c,1,1);BatStateUnlock(c);
 if(Cancel(c))goto Exit;
 if(!Owned(c)||c->AccessRefused) {
  BatStateLock(c);N976nBatteryCacheFail(&c->Cache,c->Generation);BatStateUnlock(c);
  ++c->Failures;Quarantine(c,NCD_Q_WORKER_OWNER);c->Stage=0xE1;c->LastStatus=STATUS_DEVICE_CONFIGURATION_ERROR;
  Notify(c);goto Exit;
 }
 acquired=N976nBatBusAcquireD0(&c->Backend.Bus);
 if(acquired) {
  BatStateLock(c);N976nBatteryCacheFail(&c->Cache,c->Generation);BatStateUnlock(c);
  ++c->Failures;if(c->Backend.Bus.Quarantined)Quarantine(c,NCD_Q_ACQUIRE);
  c->Stage=0xE0;c->LastStatus=STATUS_DEVICE_NOT_READY;Notify(c);goto Exit;
 }
 c->Backend.Bus.KeepControlOwner=1;
 while(!Cancel(c)) {
  if(!Owned(c)) {
   BatStateLock(c);N976nBatteryCacheFail(&c->Cache,c->Generation);BatStateUnlock(c);
   ++c->Failures;Quarantine(c,NCD_Q_LOOP_OWNER);c->Stage=0xE1;c->LastStatus=STATUS_DEVICE_CONFIGURATION_ERROR;Notify(c);break;
  }
  start=Now(c);c->LastCycleAt=start;c->Stage=4;
  N976nBatBackendReadActive(&c->Backend,&c->Last);end=Now(c);++c->Samples;
  RtlZeroMemory(&c->PowerRaw,sizeof(c->PowerRaw));
  RtlZeroMemory(&c->PowerValues,sizeof(c->PowerValues));
  if(c->Last.Publishable&&!Cancel(c)&&Owned(c)&&!c->AccessRefused) {
   if(!ObserveCharge(c,&c->PowerRaw))
    N976nPowerDecode(&c->PowerRaw,&c->PowerValues);
   /* A clean charger failure does not undo the already retired gauge sample.
    * Quarantine/lease loss still invalidates it below. No automatic reacquire:
    * a clean release ends this worker, and the last sample expires by its TTL. */
  }
  {N976N_POWER_FACTS f;N976N_POWER_RAW after;RtlZeroMemory(&f,sizeof(f));
   f.Now=Now(c);f.SampleAt=start;f.MaxAge=500*10000U;
   f.Generation=f.SampleGeneration=c->Generation;
   f.OwnerReady=c->Backend.Bus.D0Active&&!c->Backend.Bus.Quarantined&&Owned(c);
   if(f.OwnerReady&&N976nSourceBegin(&c->Source,&c->PowerRaw,start)){
    f.SourceEpoch=f.SampleSourceEpoch=c->Source.Epoch;
    c->Adc->ObservedSourceEpoch=c->Source.Epoch;
   }else{N976nSourceInvalidate(&c->Source);c->Adc->ObservedSourceEpoch=0;}
   CollectThermal(c,&f);
   RtlZeroMemory(&after,sizeof(after));
   if(!Cancel(c)&&Owned(c)&&c->Source.Open&&
      !ObserveCharge(c,&after)&&
      N976nSourceFinish(&c->Source,&after,Now(c))){
    c->PowerRaw=after;N976nPowerDecode(&after,&c->PowerValues);
   }else{
    N976nSourceInvalidate(&c->Source);NctInvalidate(&c->Thermal,NCT_MISSING,0);
    f.FreshThermistors=f.ThermalAllowed=0;
   }
   f.Now=Now(c);
   N976nPowerEvaluate(&c->PowerValues,&f,&c->PowerDecision);
  }
  ControlCycle(c);
  if(c->Control.Uncertain){
   /* Unknown stop completion is sticky across both control and observation.
    * Do not issue even another read before the worker exits/quarantines. */
   c->Backend.Bus.Quarantined=1;Quarantine(c,NCD_Q_CONTROL);break;
  }
  /* A final observation reflects MODE4/5 changes before publishing charging.
   * Source is never made fresh by this additional read. */
  if(c->Backend.Bus.D0Active&&!c->Backend.Bus.Quarantined&&!Cancel(c)&&Owned(c)){
   N976N_POWER_RAW latest;
   if(!ObserveCharge(c,&latest)&&N976nSourceMatches(&c->Source,&latest)){
    c->PowerRaw=latest;N976nPowerDecode(&latest,&c->PowerValues);
   }else N976nSourceInvalidate(&c->Source);
  }
  if(!Owned(c))Quarantine(c,NCD_Q_POST_OWNER);
  BatStateLock(c);
  accepted=N976N_BAT_CACHE_BAD_SAMPLE;
  if(!Cancel(c)&&!c->AccessRefused&&!c->Backend.Bus.Quarantined&&c->Last.Publishable)
   accepted=N976nBatteryCachePublish(&c->Cache,&c->Last.Raw,c->Copy.Factor,c->Generation,start,end,Now(c));
  if(accepted==N976N_BAT_CACHE_OK&&c->Source.Valid)
   N976nBatteryCachePower(&c->Cache,c->Generation,c->Source.StartedAt,Now(c),c->Source.OnlineKnown,c->Source.Online,
    c->PowerValues.Mode==5&&!c->PowerValues.WdtExpired&&c->PowerValues.ChargeDetail<=2);
  if(accepted!=N976N_BAT_CACHE_OK){
   if(!KeepFailedGaugeLocked(c,start,end,Now(c)))N976nBatteryCacheFail(&c->Cache,c->Generation);
   ++c->Failures;
  }
  BatStateUnlock(c);
  c->LastStatus=accepted==N976N_BAT_CACHE_OK?STATUS_SUCCESS:STATUS_DEVICE_NOT_READY;
  if(c->Backend.Bus.Quarantined||c->AccessRefused){Quarantine(c,NCD_Q_BUS_OR_ACCESS);c->LastStatus=STATUS_DEVICE_HARDWARE_ERROR;}
  c->Stage=c->Backend.Bus.Quarantined?0xE0:8;
  BatStateLock(c);PublishDiagLocked(c,2,1);BatStateUnlock(c);
  Notify(c);
  if(Cancel(c)||c->Backend.Bus.Quarantined||!c->Backend.Bus.D0Active)break;
  {ULONGLONG current=Now(c),period=c->Control.State==NCC_MANAGED?2500000:10000000;
   /* Absolute cycle cadence, not work duration plus a full service period.
    * Late work never issues catch-up kicks: NccService stops on stale facts. */
   ULONGLONG elapsed=current>=c->LastCycleAt?current-c->LastCycleAt:period;
   delay.QuadPart=-(LONGLONG)(elapsed<period?period-elapsed:10000);
  }
  if(KeWaitForSingleObject(&c->StopEvent,Executive,KernelMode,FALSE,&delay)==STATUS_SUCCESS)break;
 }
Exit:
 if(c->ControlAttempt&&(c->Control.State!=NCC_MODE4_CONFIRMED||c->Control.InputTouched)&&!c->Control.Uncertain)
  NccStop(&c->Control);
 if(c->Control.Uncertain){c->Backend.Bus.Quarantined=1;Quarantine(c,NCD_Q_EXIT_CONTROL);}
 /* The producer owns final retirement. Stop joins it before unmapping. A lost
  * lease cannot authorize cleanup MMIO against somebody else's controller. */
 if(c->Backend.Bus.D0Active) {
  if(!Owned(c)||c->AccessRefused) {
   c->Backend.Bus.S.RestoreBlocked=1;Quarantine(c,NCD_Q_EXIT_OWNER);
  }
  if(N976nBatBusReleaseD0(&c->Backend.Bus)||c->Backend.Bus.Quarantined) {
   BatStateLock(c);N976nBatteryCacheFail(&c->Cache,c->Generation);BatStateUnlock(c);
   Quarantine(c,NCD_Q_BUS_RELEASE);c->Stage=0xE0;c->LastStatus=STATUS_DEVICE_HARDWARE_ERROR;Notify(c);
  }
 }
 InvalidatePower(c);
 BatStateLock(c);PublishDiagLocked(c,3,0);BatStateUnlock(c);
 PsTerminateSystemThread(STATUS_SUCCESS);
}
static void Stop(BAT_DEVICE *c)
{
 LARGE_INTEGER deadline;NTSTATUS status;
 InterlockedExchange(&c->StopRequested,1);
 if(c->Adc)NcaWdfRequestStop(c->Adc);
 KeSetEvent(&c->StopEvent,IO_NO_INCREMENT,FALSE);
 /* No lock is acquired before joining. This development deadline is not a
  * promise that Windows schedules the worker in time. Failure is terminal;
  * WDF must not disable its IRQ or free memory beneath the live producer. */
 if(c->Thread){
  deadline.QuadPart=-10*10000000LL;
  status=ZwWaitForSingleObject(c->Thread,FALSE,&deadline);
  if(status!=STATUS_SUCCESS)KeBugCheckEx(0xE0000089UL,0x4E4E4144,1,(ULONG_PTR)status,(ULONG_PTR)c);
  ZwClose(c->Thread);c->Thread=NULL;
 }
 deadline.QuadPart=-10*10000000LL;
 status=WdfWaitLockAcquire(c->StateLock,&deadline.QuadPart);
 if(status!=STATUS_SUCCESS)KeBugCheckEx(0xE0000089UL,0x4E4E4144,3,(ULONG_PTR)status,(ULONG_PTR)c);
 N976nBatteryCacheStop(&c->Cache);
 InvalidatePower(c);PublishDiagLocked(c,4,0);BatStateUnlock(c);
 /* No Battc reentrant notification during rundown. Its query callbacks see
  * the stopped cache; the normal class/power lifecycle owns notification. */
 InvalidatePower(c);
}
static void Unmap(BAT_DEVICE *c)
{
 ULONG i;for(i=0;i<N976N_BAT_RESOURCES;i++)if(c->Maps[i]) {
  SIZE_T bytes=i==N976N_BAT_NVS_INDEX?4096:N976nBatResources[i].Bytes;
  MmUnmapIoSpace(c->Maps[i],bytes);c->Maps[i]=NULL;
 }
 c->Mapped=0;c->Lease=NULL;c->LeaseValidated=FALSE;
}
NTSTATUS BatPrepare(WDFDEVICE d,WDFCMRESLIST raw,WDFCMRESLIST translated)
{
 BAT_DEVICE *c=BatGet(d);ULONG i;PHYSICAL_ADDRESS pa;NTSTATUS status=STATUS_DEVICE_CONFIGURATION_ERROR;
 if(!c->Adc||c->Adc->Engine.Initialized||c->Mapped||c->Claimed||WdfCmResourceListGetCount(raw)!=N976N_BAT_DESCRIPTOR_COUNT||
    WdfCmResourceListGetCount(translated)!=N976N_BAT_DESCRIPTOR_COUNT)return status;
 {PCM_PARTIAL_RESOURCE_DESCRIPTOR r=WdfCmResourceListGetDescriptor(raw,N976N_BAT_IRQ_INDEX),
   t=WdfCmResourceListGetDescriptor(translated,N976N_BAT_IRQ_INDEX);
  if(!r||!t||r->Type!=CmResourceTypeInterrupt||t->Type!=CmResourceTypeInterrupt||
   r->ShareDisposition!=CmResourceShareDeviceExclusive||t->ShareDisposition!=CmResourceShareDeviceExclusive||
   r->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||t->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||
   r->u.Interrupt.Vector!=116||!t->u.Interrupt.Vector)return status;
 }
 for(i=0;i<N976N_BAT_RESOURCES;i++) {
  PCM_PARTIAL_RESOURCE_DESCRIPTOR r=WdfCmResourceListGetDescriptor(raw,i),t=WdfCmResourceListGetDescriptor(translated,i);
  if(!r||!t||r->Type!=CmResourceTypeMemory||t->Type!=CmResourceTypeMemory||
    r->u.Memory.Start.QuadPart!=t->u.Memory.Start.QuadPart||r->u.Memory.Length!=t->u.Memory.Length||
    r->Flags!=t->Flags||(r->Flags!=0&&r->Flags!=CM_RESOURCE_MEMORY_READ_ONLY))goto Bad;
  if(i==N976N_BAT_TOP_INDEX) {
   if(!N976nClockSharePreparePair(r,t))goto Bad;
  } else if(r->ShareDisposition!=CmResourceShareDeviceExclusive||t->ShareDisposition!=CmResourceShareDeviceExclusive)goto Bad;
  if(i<N976N_BAT_FIXED_RESOURCES) {
   if((ULONGLONG)r->u.Memory.Start.QuadPart!=N976nBatResources[i].Address||r->u.Memory.Length!=N976nBatResources[i].Bytes||
     (N976nBatResources[i].Writable&&r->Flags!=0))goto Bad;
  } else {
   c->LeaseAddress=(ULONGLONG)r->u.Memory.Start.QuadPart;
   if(c->LeaseAddress<N976N_BAT_LEASE_LOW||c->LeaseAddress>N976N_BAT_LEASE_END-4096||
      (c->LeaseAddress&4095)||r->u.Memory.Length!=4096||r->Flags!=0)goto Bad;
  }
 }
 pa.QuadPart=c->LeaseAddress;
 c->Maps[N976N_BAT_NVS_INDEX]=MmMapIoSpaceEx(pa,4096,PAGE_READWRITE);
 if(!c->Maps[N976N_BAT_NVS_INDEX]){status=STATUS_INSUFFICIENT_RESOURCES;goto Bad;}
 c->Lease=c->Maps[N976N_BAT_NVS_INDEX];RtlCopyMemory(&c->Copy,c->Lease,sizeof(c->Copy));
 if(!N976nBatLeaseValid(&c->Copy,N976N_BAT_LEASE_RELEASED)||
   *(volatile ULONGLONG*)((PUCHAR)c->Lease+4088)!=N976N_BAT_LEASE_GUARD)goto Bad;
 c->LeaseValidated=TRUE;
 if(InterlockedCompareExchange((volatile LONG*)&c->Lease->ClaimState,N976N_BAT_CLAIM_OWNED,N976N_BAT_CLAIM_READY)!=N976N_BAT_CLAIM_READY)goto Bad;
 c->Claimed=TRUE;KeMemoryBarrier();
 if(!Owned(c)){Quarantine(c,NCD_Q_PREPARE_OWNER);goto Bad;}
 for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++) {
  pa.QuadPart=N976nBatResources[i].Address;
  c->Maps[i]=MmMapIoSpaceEx(pa,N976nBatResources[i].Bytes,PAGE_NOCACHE|
    (N976nBatResources[i].Writable?PAGE_READWRITE:PAGE_READONLY));
  if(!c->Maps[i]){status=STATUS_INSUFFICIENT_RESOURCES;goto Bad;}
 }
 c->Mapped=N976N_BAT_RESOURCES;c->Stage=2;
 /* Windows performance-counter frequency need not equal firmware CNTFRQ.
  * Binding immutable clocks are unchanged; the wait clock has its own rate. */
 {LARGE_INTEGER hz;N976N_BAT_BUS_BINDING binding=c->Copy.Binding;KeQueryPerformanceCounter(&hz);
  if(hz.QuadPart<=0||hz.QuadPart>1000000000LL)goto Bad;
  binding.CounterHz=(ULONGLONG)hz.QuadPart;
  if(!N976nBatBackendInit(&c->Backend,&Ops,c,&binding,c->Copy.Factor,c->Copy.SelectedConfig))goto Bad;
 }
 if(!PrepareThermal(c,raw,translated))goto Bad;
 c->HsiFinalChecked=TRUE;c->LastStatus=STATUS_SUCCESS;return STATUS_SUCCESS;
Bad:
 ResetUnstartedThermal(c);
 if(c->Claimed){
  if(!c->Backend.Bus.Quarantined&&!c->QuarantinePending&&!c->AccessRefused&&Owned(c))
   InterlockedCompareExchange((volatile LONG*)&c->Lease->ClaimState,N976N_BAT_CLAIM_READY,N976N_BAT_CLAIM_OWNED);
  else InterlockedCompareExchange((volatile LONG*)&c->Lease->ClaimState,N976N_BAT_CLAIM_QUARANTINED,N976N_BAT_CLAIM_OWNED);
  c->Claimed=FALSE;
 }
 Unmap(c);c->LastStatus=status;return status;
}
NTSTATUS BatRelease(WDFDEVICE d,WDFCMRESLIST resources)
{
 BAT_DEVICE *c=BatGet(d);NTSTATUS adc;UNREFERENCED_PARAMETER(resources);Stop(c);
 /* Hardware is inaccessible here. Only joined/disabled cached evidence and
  * live NVS claim bytes are used; no MMIO validation in ReleaseHardware. */
 adc=NcaWdfRelease(c->Adc);
 if(!NT_SUCCESS(adc))Quarantine(c,NCD_Q_PREPARE_ADC);
 if(c->Claimed) {
  LONG next=(!Owned(c)||c->AccessRefused||c->Backend.Bus.Quarantined||
    c->QuarantinePending||!c->HsiFinalChecked)?N976N_BAT_CLAIM_QUARANTINED:
    (c->D0Entered?N976N_BAT_CLAIM_CONSUMED:N976N_BAT_CLAIM_READY);
  InterlockedCompareExchange((volatile LONG*)&c->Lease->ClaimState,next,N976N_BAT_CLAIM_OWNED);
  c->Claimed=FALSE;
 }
 ResetUnstartedThermal(c);Unmap(c);c->Stage=9;
 BatStateLock(c);PublishDiagLocked(c,5,0);BatStateUnlock(c);return STATUS_SUCCESS;
}
NTSTATUS BatD0Entry(WDFDEVICE d,WDF_POWER_DEVICE_STATE previous)
{
 BAT_DEVICE *c=BatGet(d);UNREFERENCED_PARAMETER(previous);
 if(!c->Claimed||c->Thread||c->AccessRefused||c->Backend.Bus.Quarantined||
    c->QuarantinePending||c->D0Entered||c->Adc->Engine.Initialized)return STATUS_DEVICE_NOT_READY;
 InterlockedExchange(&c->StopRequested,0);KeClearEvent(&c->StopEvent);
 if(!Owned(c)||!N976nBatBusValidateBinding(&c->Backend.Bus)){Quarantine(c,NCD_Q_D0_BINDING);return STATUS_DEVICE_CONFIGURATION_ERROR;}
 c->D0Entered=TRUE;c->HsiFinalChecked=FALSE;
 BatStateLock(c);c->Generation=N976nBatteryCacheBeginD0(&c->Cache);BatStateUnlock(c);
 N976nSourceInit(&c->Source,c->Generation);
 return c->Generation?STATUS_SUCCESS:STATUS_DEVICE_CONFIGURATION_ERROR;
}
NTSTATUS BatPostIrq(WDFDEVICE d,WDF_POWER_DEVICE_STATE previous)
{
 BAT_DEVICE *c=BatGet(d);OBJECT_ATTRIBUTES oa;NTSTATUS s;UNREFERENCED_PARAMETER(previous);
 if(!c->D0Entered||!c->Adc->Enabled||Cancel(c)||!Owned(c))return STATUS_DEVICE_NOT_READY;
 InitializeObjectAttributes(&oa,NULL,OBJ_KERNEL_HANDLE,NULL,NULL);
 s=PsCreateSystemThread(&c->Thread,SYNCHRONIZE,&oa,NULL,NULL,Worker,c);
 if(!NT_SUCCESS(s)){c->Thread=NULL;Stop(c);}return s;
}
NTSTATUS BatPreIrq(WDFDEVICE d,WDF_POWER_DEVICE_STATE target)
{
 BAT_DEVICE *c=BatGet(d);UNREFERENCED_PARAMETER(target);Stop(c);
 /* Worker has retired HSI; ADC disable still needs our claim to mask/ACK. */
 c->HsiFinalChecked=Owned(c)&&!c->AccessRefused&&!c->Backend.Bus.D0Active&&
  !c->Backend.Bus.Quarantined&&N976nBatBusValidateBinding(&c->Backend.Bus);
 if(!c->HsiFinalChecked)Quarantine(c,NCD_Q_D0_HSI);
 return STATUS_SUCCESS; /* WDF must still call EvtInterruptDisable */
}
NTSTATUS BatD0Exit(WDFDEVICE d,WDF_POWER_DEVICE_STATE target)
{
 BAT_DEVICE *c=BatGet(d);UNREFERENCED_PARAMETER(target);Stop(c);
 if(c->Adc->Enabled||c->Adc->Active)KeBugCheckEx(0xE0000089UL,0x4E4E4144,2,0,(ULONG_PTR)c);
 if(c->D0Entered&&!c->Adc->ReleaseReady)Quarantine(c,NCD_Q_D0_ADC);
 if(c->QuarantinePending&&c->Claimed&&c->Lease)
  InterlockedCompareExchange((volatile LONG*)&c->Lease->ClaimState,N976N_BAT_CLAIM_QUARANTINED,N976N_BAT_CLAIM_OWNED);
 return c->QuarantinePending?STATUS_DEVICE_HARDWARE_ERROR:STATUS_SUCCESS;
}
NTSTATUS BatIoctl(WDFDEVICE d,PIRP irp)
{
 BAT_DEVICE *c=BatGet(d);NTSTATUS s=STATUS_NOT_SUPPORTED;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL){irp->IoStatus.Status=STATUS_INVALID_DEVICE_STATE;irp->IoStatus.Information=0;IoCompleteRequest(irp,0);return STATUS_INVALID_DEVICE_STATE;}
 {PIO_STACK_LOCATION stack=IoGetCurrentIrpStackLocation(irp);
  if(stack->Parameters.DeviceIoControl.IoControlCode==NCD_IOCTL){
   irp->IoStatus.Information=0;
   if(stack->Parameters.DeviceIoControl.InputBufferLength)s=STATUS_INVALID_PARAMETER;
   else if(stack->Parameters.DeviceIoControl.OutputBufferLength<sizeof(NCD_REPORT))s=STATUS_BUFFER_TOO_SMALL;
   else if(!irp->AssociatedIrp.SystemBuffer)s=STATUS_INVALID_PARAMETER;
   else {
    NCD_REPORT r;BatStateLock(c);r=c->Diag;r.LastQuery=c->DiagQuery;BatStateUnlock(c);
    r.Magic=NCD_MAGIC;r.Version=NCD_VERSION;r.Bytes=sizeof(r);r.Driver=NCD_DRIVER;r.Query100ns=Now(c);
    RtlCopyMemory(irp->AssociatedIrp.SystemBuffer,&r,sizeof(r));irp->IoStatus.Information=sizeof(r);s=STATUS_SUCCESS;
   }
   irp->IoStatus.Status=s;IoCompleteRequest(irp,0);return s;
  }
 }
 WdfWaitLockAcquire(c->ClassLock,NULL);if(c->ClassHandle)s=BatteryClassIoctl(c->ClassHandle,irp);WdfWaitLockRelease(c->ClassLock);
 if(s==STATUS_NOT_SUPPORTED){IoSkipCurrentIrpStackLocation(irp);s=WdfDeviceWdmDispatchPreprocessedIrp(d,irp);}return s;
}
NTSTATUS BatSystemControl(WDFDEVICE d,PIRP irp)
{
 BAT_DEVICE *c=BatGet(d);NTSTATUS s=STATUS_NOT_SUPPORTED;SYSCTL_IRP_DISPOSITION disposition=IrpForward;
 if(KeGetCurrentIrql()!=PASSIVE_LEVEL){irp->IoStatus.Status=STATUS_INVALID_DEVICE_STATE;irp->IoStatus.Information=0;IoCompleteRequest(irp,0);return STATUS_INVALID_DEVICE_STATE;}
 WdfWaitLockAcquire(c->ClassLock,NULL);
 if(c->ClassHandle)s=BatteryClassSystemControl(c->ClassHandle,&c->Wmi,WdfDeviceWdmGetDeviceObject(d),irp,&disposition);
 WdfWaitLockRelease(c->ClassLock);
 if(disposition==IrpNotCompleted)IoCompleteRequest(irp,0);
 else if(disposition!=IrpProcessed){IoSkipCurrentIrpStackLocation(irp);s=WdfDeviceWdmDispatchPreprocessedIrp(d,irp);}return s;
}
static NTSTATUS WmiReg(PDEVICE_OBJECT o,PULONG flags,PUNICODE_STRING name,PUNICODE_STRING *path,PUNICODE_STRING mof,PDEVICE_OBJECT *pdo)
{
 WDFDEVICE d=WdfWdmDeviceGetWdfDeviceHandle(o);BAT_DEVICE *c=BatGet(d);
 UNREFERENCED_PARAMETER(name);UNREFERENCED_PARAMETER(mof);*flags=WMIREG_FLAG_INSTANCE_PDO;*path=&c->RegistryPath;*pdo=WdfDeviceWdmGetPhysicalDevice(d);return STATUS_SUCCESS;
}
static NTSTATUS WmiQuery(PDEVICE_OBJECT o,PIRP irp,ULONG guid,ULONG instance,ULONG count,PULONG sizes,ULONG bytes,PUCHAR buffer)
{
 BAT_DEVICE *c=BatGet(WdfWdmDeviceGetWdfDeviceHandle(o));NTSTATUS s;
 if(instance||count!=1||!sizes)return WmiCompleteRequest(o,irp,STATUS_INVALID_PARAMETER,0,0);
 s=BatteryClassQueryWmiDataBlock(c->ClassHandle,o,irp,guid,sizes,bytes,buffer);
 if(s==STATUS_WMI_GUID_NOT_FOUND)s=WmiCompleteRequest(o,irp,s,0,0);return s;
}
NTSTATUS BatClassInit(WDFDEVICE d)
{
 BAT_DEVICE *c=BatGet(d);BATTERY_MINIPORT_INFO_V1_1 info;NTSTATUS s;
 RtlZeroMemory(&info,sizeof(info));info.MajorVersion=BATTERY_CLASS_MAJOR_VERSION;info.MinorVersion=BATTERY_CLASS_MINOR_VERSION_1;
 info.Pdo=WdfDeviceWdmGetPhysicalDevice(d);info.Fdo=WdfDeviceWdmGetDeviceObject(d);
 if(!N976nBatteryMiniBind((PBATTERY_MINIPORT_INFO)&info,&c->Mini))return STATUS_INVALID_PARAMETER;
 info.QueryStatus=DiagQueryStatus;
 WdfWaitLockAcquire(c->ClassLock,NULL);s=BatteryClassInitializeDevice((PBATTERY_MINIPORT_INFO)&info,&c->ClassHandle);WdfWaitLockRelease(c->ClassLock);
 if(!NT_SUCCESS(s))return s;
 c->Wmi.QueryWmiRegInfo=WmiReg;c->Wmi.QueryWmiDataBlock=WmiQuery;
 c->WmiRegistered=NT_SUCCESS(IoWMIRegistrationControl(info.Fdo,WMIREG_ACTION_REGISTER));Notify(c);return STATUS_SUCCESS;
}
VOID BatClassCleanup(WDFDEVICE d)
{
 BAT_DEVICE *c=BatGet(d);Stop(c);
 if(c->WmiRegistered){IoWMIRegistrationControl(WdfDeviceWdmGetDeviceObject(d),WMIREG_ACTION_DEREGISTER);c->WmiRegistered=FALSE;}
 WdfWaitLockAcquire(c->ClassLock,NULL);if(c->ClassHandle){BatteryClassUnload(c->ClassHandle);c->ClassHandle=NULL;}WdfWaitLockRelease(c->ClassLock);
}
VOID BatUnsupported(WDFQUEUE q,WDFREQUEST r,size_t out,size_t in,ULONG code)
{UNREFERENCED_PARAMETER(q);UNREFERENCED_PARAMETER(out);UNREFERENCED_PARAMETER(in);UNREFERENCED_PARAMETER(code);WdfRequestComplete(r,STATUS_NOT_SUPPORTED);}
NTSTATUS BatAdd(WDFDRIVER driver,PWDFDEVICE_INIT init)
{
 WDF_PNPPOWER_EVENT_CALLBACKS cb;WDF_OBJECT_ATTRIBUTES a;WDFDEVICE d;BAT_DEVICE *c;NTSTATUS s;WDF_IO_QUEUE_CONFIG queue;
 WDF_PNPPOWER_EVENT_CALLBACKS_INIT(&cb);cb.EvtDevicePrepareHardware=BatPrepare;cb.EvtDeviceReleaseHardware=BatRelease;
 cb.EvtDeviceD0Entry=BatD0Entry;cb.EvtDeviceD0Exit=BatD0Exit;
 cb.EvtDeviceD0EntryPostInterruptsEnabled=BatPostIrq;cb.EvtDeviceD0ExitPreInterruptsDisabled=BatPreIrq;cb.EvtDeviceSelfManagedIoInit=BatClassInit;cb.EvtDeviceSelfManagedIoCleanup=BatClassCleanup;
 WdfDeviceInitSetPnpPowerEventCallbacks(init,&cb);N976nClockShareRegister(init);
 s=WdfDeviceInitAssignWdmIrpPreprocessCallback(init,BatIoctl,IRP_MJ_DEVICE_CONTROL,NULL,0);if(!NT_SUCCESS(s))return s;
 s=WdfDeviceInitAssignWdmIrpPreprocessCallback(init,BatSystemControl,IRP_MJ_SYSTEM_CONTROL,NULL,0);if(!NT_SUCCESS(s))return s;
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&a,BAT_DEVICE);a.ExecutionLevel=WdfExecutionLevelPassive;a.SynchronizationScope=WdfSynchronizationScopeNone;
 s=WdfDeviceCreate(&init,&a,&d);if(!NT_SUCCESS(s))return s;
 c=BatGet(d);c->Device=d;
 s=NcaWdfCreate(d,&c->Adc);if(!NT_SUCCESS(s))return s;KeInitializeEvent(&c->StopEvent,NotificationEvent,FALSE);c->StopRequested=1;
 WDF_OBJECT_ATTRIBUTES_INIT(&a);a.ParentObject=d;s=WdfWaitLockCreate(&a,&c->StateLock);if(!NT_SUCCESS(s))return s;
 s=WdfWaitLockCreate(&a,&c->ClassLock);if(!NT_SUCCESS(s))return s;
 N976nBatteryCacheInit(&c->Cache,15*10000000ULL);c->Mini.Cache=&c->Cache;c->Mini.Owner=c;c->Mini.Lock=BatStateLock;c->Mini.Unlock=BatStateUnlock;c->Mini.Now100ns=Now;
 RtlInitUnicodeString(&c->RegistryPath,WdfDriverGetRegistryPath(driver));
 WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(&queue,WdfIoQueueDispatchParallel);queue.EvtIoDeviceControl=BatUnsupported;
 /* Unknown/unclaimed class IOCTLs must complete even outside D0: never keep
  * a power-managed fallback request pending during stop/rebalance. */
 queue.PowerManaged=WdfFalse;
 return WdfIoQueueCreate(d,&queue,WDF_NO_OBJECT_ATTRIBUTES,WDF_NO_HANDLE);
}
NTSTATUS DriverEntry(PDRIVER_OBJECT object,PUNICODE_STRING path)
{WDF_DRIVER_CONFIG config;WDF_DRIVER_CONFIG_INIT(&config,BatAdd);return WdfDriverCreate(object,path,WDF_NO_OBJECT_ATTRIBUTES,&config,WDF_NO_HANDLE);}
