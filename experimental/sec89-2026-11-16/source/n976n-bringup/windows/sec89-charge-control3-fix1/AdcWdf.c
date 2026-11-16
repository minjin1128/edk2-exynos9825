/* SPDX-License-Identifier: MIT */
#include "AdcWdf.h"
WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(NCA_WDF,NcaWdfGet)
EVT_WDF_INTERRUPT_ISR NcaWdfIsr;
EVT_WDF_INTERRUPT_DPC NcaWdfDpc;
EVT_WDF_INTERRUPT_ENABLE NcaWdfEnable;
EVT_WDF_INTERRUPT_DISABLE NcaWdfDisable;
EVT_WDF_INTERRUPT_SYNCHRONIZE NcaWdfSync;
enum SYNC_ACTION {SYNC_BEGIN,SYNC_POLL,SYNC_RETIRE,SYNC_IDENTITY,SYNC_WAIT_FAILED};
typedef struct {
 enum SYNC_ACTION Action;const NCT_TICKET *Ticket;NCT_COMPLETION_RECORD *Record;
 NCT_IDENTITY *Identity;int Result,TimedOut,UnissuedClean;
} SYNC_REQUEST;
static LONG AtomicRead(volatile LONG *p){return InterlockedCompareExchange(p,0,0);}
/* IRQ lock held. Cancel does not make a restored, unissued request unsafe.
 * This describes retirement, never sample success or a completed conversion. */
static int Clean(NCA_WDF *c)
{
 return c->Engine.Initialized&&!c->Engine.Quarantined&&!c->Engine.Changed&&
  c->Engine.State==NCA_IDLE&&c->Engine.Restored&&c->Engine.MaskVerified&&
  (!c->Engine.Record.Issued||c->Engine.Record.Retired)&&c->Ops.Owned(c->Owner);
}
NTSTATUS NcaWdfCreate(WDFDEVICE device,NCA_WDF **out)
{
 WDF_INTERRUPT_CONFIG cfg;WDF_OBJECT_ATTRIBUTES attr;WDFINTERRUPT irq;NTSTATUS status;
 if(!out)return STATUS_INVALID_PARAMETER;*out=NULL;
 WDF_INTERRUPT_CONFIG_INIT(&cfg,NcaWdfIsr,NcaWdfDpc);
 cfg.EvtInterruptEnable=NcaWdfEnable;cfg.EvtInterruptDisable=NcaWdfDisable;
 cfg.PassiveHandling=FALSE;cfg.AutomaticSerialization=FALSE;cfg.ShareVector=WdfFalse;
 /* Default device parent; explicit ParentObject would require serialization. */
 WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(&attr,NCA_WDF);
 status=WdfInterruptCreate(device,&cfg,&attr,&irq);if(!NT_SUCCESS(status))return status;
 *out=NcaWdfGet(irq);(*out)->Interrupt=irq;
 KeInitializeEvent(&(*out)->Completion,NotificationEvent,FALSE);return STATUS_SUCCESS;
}
NTSTATUS NcaWdfPrepare(NCA_WDF *c,const NCA_OPS *ops,void *owner,const NCA_BINDING *b,
 PCM_PARTIAL_RESOURCE_DESCRIPTOR raw,PCM_PARTIAL_RESOURCE_DESCRIPTOR translated)
{
 if(!c||!ops||!ops->Read||!ops->Write||!ops->Fence||!ops->Now||!ops->Owned||!b||
  !raw||!translated||!c->Interrupt||AtomicRead(&c->Prepared)||AtomicRead(&c->Enabled)||
  AtomicRead(&c->Active)||c->Engine.Initialized)return STATUS_INVALID_DEVICE_STATE;
 if(raw->Type!=CmResourceTypeInterrupt||translated->Type!=CmResourceTypeInterrupt||
  raw->ShareDisposition!=CmResourceShareDeviceExclusive||translated->ShareDisposition!=CmResourceShareDeviceExclusive||
  raw->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||translated->Flags!=CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE||
  raw->u.Interrupt.Vector!=116||!translated->u.Interrupt.Vector)return STATUS_DEVICE_CONFIGURATION_ERROR;
 /* Translated vector/affinity belong to Windows, not the DT's GSIV value. */
 c->Ops=*ops;c->Owner=owner;c->Binding=*b;
 InterlockedExchange(&c->ReleaseReady,0);InterlockedExchange(&c->StopRequested,0);
 InterlockedExchange(&c->Prepared,1);return STATUS_SUCCESS;
}
NTSTATUS NcaWdfEnable(WDFINTERRUPT irq,WDFDEVICE device)
{
 NCA_WDF *c=NcaWdfGet(irq);UNREFERENCED_PARAMETER(device);
 /* WDF invokes this with IRQ synchronization. No waits and no IRQ-lock recurse. */
 if(!AtomicRead(&c->Prepared)||AtomicRead(&c->StopRequested)||AtomicRead(&c->Active)||
  !NcaInit(&c->Engine,&c->Ops,c->Owner,&c->Binding))return STATUS_DEVICE_CONFIGURATION_ERROR;
 InterlockedExchange(&c->Enabled,1);return STATUS_SUCCESS;
}
BOOLEAN NcaWdfIsr(WDFINTERRUPT irq,ULONG message)
{
 NCA_WDF *c=NcaWdfGet(irq);UNREFERENCED_PARAMETER(message);
 if(!AtomicRead(&c->Enabled)||!AtomicRead(&c->Prepared))return FALSE;
 NcaIrq(&c->Engine);
 /* KeSetEvent is not legal at this DIRQL; the DPC signals a persistent event.
  * Completion itself is stored by ISR before this notification is queued. */
 WdfInterruptQueueDpcForIsr(irq);return TRUE;
}
VOID NcaWdfDpc(WDFINTERRUPT irq,WDFOBJECT object)
{
 NCA_WDF *c=NcaWdfGet(irq);UNREFERENCED_PARAMETER(object);
 /* No Owner/Engine/MMIO access: queued DPC is safe after map rundown. Its
  * context lives with the framework interrupt object, not worker stack. */
 KeSetEvent(&c->Completion,IO_NO_INCREMENT,FALSE);
}
NTSTATUS NcaWdfDisable(WDFINTERRUPT irq,WDFDEVICE device)
{
 NCA_WDF *c=NcaWdfGet(irq);int clean;UNREFERENCED_PARAMETER(device);
 InterlockedExchange(&c->StopRequested,1);
 clean=c->Engine.Initialized?NcaDisable(&c->Engine):0;
 clean=clean&&Clean(c)&&!AtomicRead(&c->Active)&&NcaRestoredBinding(&c->Engine);
 InterlockedExchange(&c->ReleaseReady,clean);
 InterlockedExchange(&c->Enabled,0);
 /* This return is NOT permission to free a live worker. The caller must join
  * in PreInterruptsDisabled. Retain the active flag if that contract is broken. */
 return clean?STATUS_SUCCESS:STATUS_DEVICE_HARDWARE_ERROR;
}
BOOLEAN NcaWdfSync(WDFINTERRUPT irq,WDFCONTEXT context)
{
 NCA_WDF *c=NcaWdfGet(irq);SYNC_REQUEST *s=context;int stop=AtomicRead(&c->StopRequested)!=0;
 s->Result=0;
 if(!AtomicRead(&c->Enabled)||!AtomicRead(&c->Prepared))return FALSE;
 switch(s->Action){
 case SYNC_BEGIN:
  if(stop)NcaCancel(&c->Engine);
  s->Result=NcaBegin(&c->Engine,s->Ticket);
  if(!s->Result&&Clean(c)){
   /* No START or configuration change for this ticket. A software request
    * can retire without claiming an IRQ, ACK, raw sample, or prior result. */
   RtlZeroMemory(s->Record,sizeof(*s->Record));s->Record->Ticket=*s->Ticket;
   s->Record->Retired=1;s->Record->Cancelled=(uint8_t)c->Engine.Cancelled;
   s->UnissuedClean=1;
  }
  break;
 case SYNC_POLL:s->Result=NcaPoll(&c->Engine,stop);break;
 case SYNC_RETIRE:
  if(stop)NcaCancel(&c->Engine);
  s->Result=NcaRetire(&c->Engine,s->Record);break;
 case SYNC_WAIT_FAILED:
  /* An IRQ may have won the timeout/DPC race. Recheck before failing. */
  s->Result=NcaPoll(&c->Engine,stop);
  if(s->Result==0){NcaWaitFailed(&c->Engine,s->TimedOut);s->Result=-1;}
  break;
 case SYNC_IDENTITY:
  s->Identity->Now100ns=c->Ops.Now(c->Owner);
  s->Identity->AdcGeneration=c->Engine.Binding.Generation;
  s->Identity->SourceEpoch=c->ObservedSourceEpoch;
  s->Identity->Ready=(uint8_t)(c->Ops.Owned(c->Owner)&&!stop&&!c->Engine.Quarantined);
  s->Identity->Retired=(uint8_t)(c->Engine.State==NCA_IDLE&&c->Engine.Restored&&c->Engine.MaskVerified);
  s->Identity->Cancelled=(uint8_t)(stop||c->Engine.Cancelled);
  s->Identity->Quarantined=(uint8_t)c->Engine.Quarantined;s->Result=1;break;
 }
 return TRUE;
}
int NcaWdfIdentity(void *p,NCT_IDENTITY *out)
{
 NCA_WDF *c=p;SYNC_REQUEST s={0};if(!out)return 0;RtlZeroMemory(out,sizeof(*out));
 if(!c||!AtomicRead(&c->Enabled)||!AtomicRead(&c->Prepared))return 0;
 s.Action=SYNC_IDENTITY;s.Identity=out;WdfInterruptSynchronize(c->Interrupt,NcaWdfSync,&s);return s.Result;
}
int NcaWdfConvert(void *p,const NCT_TICKET *ticket,NCT_COMPLETION_RECORD *out)
{
 NCA_WDF *c=p;SYNC_REQUEST s={0};LARGE_INTEGER wait;NTSTATUS status;uint64_t now,remaining;int result=0;
 if(!out)return 0;RtlZeroMemory(out,sizeof(*out));
 if(!c||!ticket||KeGetCurrentIrql()!=PASSIVE_LEVEL||!AtomicRead(&c->Enabled)||
  !AtomicRead(&c->Prepared)||InterlockedCompareExchange(&c->Active,1,0))return 0;
 c->SpuriousWakes=0;c->LastWait=STATUS_SUCCESS;KeClearEvent(&c->Completion);
 s.Action=SYNC_BEGIN;s.Ticket=ticket;s.Record=out;WdfInterruptSynchronize(c->Interrupt,NcaWdfSync,&s);
 if(s.UnissuedClean)goto End;
 if(!s.Result)goto Retire;
 for(;;){
  /* Clear before checking the durable ISR record, never after the check. */
  KeClearEvent(&c->Completion);s.Action=SYNC_POLL;
  WdfInterruptSynchronize(c->Interrupt,NcaWdfSync,&s);if(s.Result!=0)break;
  now=c->Ops.Now(c->Owner);remaining=now<ticket->Deadline100ns?ticket->Deadline100ns-now:1;
  if(remaining>NCT_CONVERSION_MS*NCT_MS)remaining=NCT_CONVERSION_MS*NCT_MS;
  wait.QuadPart=-(LONGLONG)remaining;
  status=KeWaitForSingleObject(&c->Completion,Executive,KernelMode,FALSE,&wait);c->LastWait=status;
  /* STATUS_TIMEOUT is nonnegative: NT_SUCCESS would incorrectly accept it. */
  if(status!=STATUS_SUCCESS||++c->SpuriousWakes>32){
   s.Action=SYNC_WAIT_FAILED;s.TimedOut=status==STATUS_TIMEOUT;
   WdfInterruptSynchronize(c->Interrupt,NcaWdfSync,&s);break;
  }
 }
Retire:
 s.Action=SYNC_RETIRE;s.Record=out;WdfInterruptSynchronize(c->Interrupt,NcaWdfSync,&s);result=s.Result;
End:
 InterlockedExchange(&c->Active,0);return result;
}
void NcaWdfRequestStop(NCA_WDF *c){if(c)InterlockedExchange(&c->StopRequested,1);}
NTSTATUS NcaWdfRelease(NCA_WDF *c)
{
 if(!c||AtomicRead(&c->Enabled)||AtomicRead(&c->Active))return STATUS_INVALID_DEVICE_STATE;
 /* Prepare can be unwound without ever entering D0/IRQ enable. No ADC MMIO
  * was issued in that path and there is no hardware result to retire. */
 if(!c->Engine.Initialized){
  InterlockedExchange(&c->Prepared,0);c->Owner=NULL;
  RtlZeroMemory(&c->Ops,sizeof(c->Ops));RtlZeroMemory(&c->Binding,sizeof(c->Binding));
  return STATUS_SUCCESS;
 }
 if(!AtomicRead(&c->ReleaseReady))return STATUS_DEVICE_HARDWARE_ERROR;
 /* D0 resume requires a newly admitted generation and clean rundown policy;
  * do not zero Engine/Cancelled to rearm a cancelled or quarantined engine. */
 InterlockedExchange(&c->Prepared,0);c->Owner=NULL;RtlZeroMemory(&c->Ops,sizeof(c->Ops));
 return STATUS_SUCCESS;
}
