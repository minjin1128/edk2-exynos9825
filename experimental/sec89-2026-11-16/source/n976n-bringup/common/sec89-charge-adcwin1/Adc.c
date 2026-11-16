/* SPDX-License-Identifier: MIT */
#include "Adc.h"
const uint64_t NcaClockAddresses[NCA_CLOCKS]={0x15C00100,0x15C01000,0x15C01800,
 0x15C01804,0x15C02004,0x15C02008,0x15C03000,0x15C03008,0x15C0300C};
static void Zero(void *p,unsigned n){uint8_t *b=p;while(n--)*b++=0;}
static uint32_t Read(NCA_CONTEXT *c,unsigned off){return c->Ops.Read(c->Owner,NCA_BASE+off);}
static void Write(NCA_CONTEXT *c,unsigned off,uint32_t v)
{c->Ops.Write(c->Owner,NCA_BASE+off,v);c->Ops.Fence(c->Owner);}
static int Fail(NCA_CONTEXT *c,unsigned why,int uncertain)
{
 c->Reason=why;if(!c->FirstReason)c->FirstReason=why;
 if(uncertain){c->Quarantined=1;c->State=NCA_QUARANTINED;c->Record.Quarantined=1;}
 return 0;
}
static int Owner(NCA_CONTEXT *c)
{return c->Ops.Owned(c->Owner)?1:Fail(c,NCA_OWNER,1);}
static int Clocks(NCA_CONTEXT *c)
{
 unsigned i;for(i=0;i<NCA_CLOCKS;i++)
  if(c->Ops.Read(c->Owner,NcaClockAddresses[i])!=c->Binding.Clocks[i])c->ClockDrift|=1U<<i;
 return !c->ClockDrift||Fail(c,NCA_CLOCK_DRIFT,1);
}
static int Mask(NCA_CONTEXT *c)
{
 if(!Owner(c))return 0;
 Write(c,0x10,0);c->MaskVerified=Read(c,0x10)==0;
 return c->MaskVerified||Fail(c,NCA_MASK,1);
}
int NcaInit(NCA_CONTEXT *c,const NCA_OPS *ops,void *owner,const NCA_BINDING *b)
{
 unsigned i;
 if(!c||c->Initialized||!ops||!ops->Read||!ops->Write||!ops->Fence||!ops->Now||
    !ops->Owned||!b||!b->Generation||b->FirmwareRetired!=1||b->FirmwareRestored!=1||
    b->FirmwareIrqDetached!=1||(b->Original[0]&~2U)||(b->Original[1]&~0x7FU)||b->Original[2])return 0;
 for(i=0;i<NCA_CLOCKS;i++)if(b->Clocks[i]==UINT32_MAX)return 0;
 if(b->Clocks[1]||!(b->Clocks[4]&(1U<<21))||!(b->Clocks[5]&(1U<<21))||
   (b->Clocks[7]&3)!=2||(b->Clocks[8]&3)!=2)return 0;
 Zero(c,sizeof(*c));c->Ops=*ops;c->Owner=owner;c->Binding=*b;c->Initialized=1;c->State=NCA_OFF;
 if(!Owner(c)||!Clocks(c))return 0;
 if(Read(c,0)!=b->Original[0]||Read(c,4)!=b->Original[1]||Read(c,0x10)!=b->Original[2])
  return Fail(c,NCA_CONFIGURATION,1);
 c->LastNow=c->Ops.Now(owner);if(!c->LastNow)return Fail(c,NCA_CLOCK_BACKWARD,1);
 c->State=NCA_IDLE;c->Restored=c->MaskVerified=1;return 1;
}
int NcaBegin(NCA_CONTEXT *c,const NCT_TICKET *t)
{
 uint64_t now;
 if(!c||!c->Initialized||!t)return 0;
 if(c->Cancelled)return Fail(c,NCA_CANCEL,0);
 if(c->State!=NCA_IDLE||c->Quarantined)return Fail(c,NCA_REPLAY,c->State!=NCA_IDLE);
 if(!t->Batch||!t->Sequence||t->Sequence<=c->LastSequence||t->AdcGeneration!=c->Binding.Generation||
   (t->Channel!=4&&t->Channel!=3&&t->Channel!=1)||t->Deadline100ns<=t->NotBefore100ns||
   t->Deadline100ns-t->NotBefore100ns>NCT_CONVERSION_MS*NCT_MS)return Fail(c,NCA_ARGUMENT,0);
 if(!Owner(c)||!Clocks(c))return 0;
 now=c->Ops.Now(c->Owner);
 if(!now||now<c->LastNow)return Fail(c,NCA_CLOCK_BACKWARD,1);
 c->LastNow=now;
 if(now<t->NotBefore100ns||now>=t->Deadline100ns)return Fail(c,NCA_DEADLINE,0);
 if(Read(c,0)!=c->Binding.Original[0]||Read(c,4)!=c->Binding.Original[1]||Read(c,0x10))
  return Fail(c,NCA_CONFIGURATION,1);
 Zero(&c->Record,sizeof(c->Record));c->Record.Ticket=*t;c->Reason=0;
 c->Changed=1;c->Restored=0;c->LastSequence=t->Sequence;c->Frozen=0;
 /* All these operations and publication of PENDING share the ISR lock. */
 if(!Mask(c))return 0;
 Write(c,0,4);Write(c,0,2);Write(c,4,0x60|t->Channel);
 Write(c,0x14,1); /* discard stale peripheral status BEFORE issuing this request */
 if(Read(c,0)!=2||Read(c,4)!=(0x60|t->Channel))return Fail(c,NCA_CONFIGURATION,1);
 Write(c,0x10,1);c->MaskVerified=0;
 if(Read(c,0x10)!=1)return Fail(c,NCA_CONFIGURATION,1);
 now=c->Ops.Now(c->Owner);
 if(now<c->LastNow||now>=t->Deadline100ns){
  Fail(c,now<c->LastNow?NCA_CLOCK_BACKWARD:NCA_DEADLINE,1);return 0;
 }
 c->LastNow=now;c->Record.Started100ns=now;c->Record.Issued=1;c->State=NCA_PENDING;
 Write(c,0,3);return 1;
}
void NcaIrq(NCA_CONTEXT *c)
{
 uint64_t at;uint32_t raw;
 if(!c||!c->Initialized)return;
 c->Irqs++;
 if(!Owner(c))return; /* Lost lease authorizes no cleanup MMIO. */
 if(!Mask(c))return;
 if(c->State!=NCA_PENDING||c->Record.Issued!=1||c->Record.Irq){
  c->Unexpected++;Write(c,0x14,1);Fail(c,NCA_IRQ_UNEXPECTED,1);return;
 }
 at=c->Ops.Now(c->Owner);raw=Read(c,8);Write(c,0x14,1);
 c->Record.Irq=1;c->Record.Ack=1;c->Record.Raw=raw;c->Record.Completed100ns=at;
 if(at<c->LastNow||at<c->Record.Started100ns){Fail(c,NCA_CLOCK_BACKWARD,1);return;}
 c->LastNow=at;
 if(at>=c->Record.Ticket.Deadline100ns){Fail(c,NCA_IRQ_LATE,1);return;}
 if(raw==UINT32_MAX){Fail(c,NCA_DATA,1);return;}
 c->State=NCA_DONE;
}
void NcaCancel(NCA_CONTEXT *c)
{if(c&&c->Initialized){c->Cancelled=1;c->Record.Cancelled=1;}}
int NcaPoll(NCA_CONTEXT *c,int cancel)
{
 uint64_t now;
 if(!c||!c->Initialized)return -1;
 if(cancel)NcaCancel(c);
 if(c->Quarantined)return -1;
 if(!Owner(c))return -1;
 if(c->State==NCA_DONE)return 1;
 if(c->State!=NCA_PENDING)return -1;
 c->Polls++;now=c->Ops.Now(c->Owner);
 if(!now||now<c->LastNow){Fail(c,NCA_CLOCK_BACKWARD,1);return -1;}
 c->Frozen=now==c->LastNow?c->Frozen+1:0;
 if(c->Frozen>c->MaxFrozen)c->MaxFrozen=c->Frozen;
 c->LastNow=now;
 if(now>=c->Record.Ticket.Deadline100ns||c->Frozen>=NCA_FROZEN_LIMIT){
  Fail(c,c->Frozen>=NCA_FROZEN_LIMIT?NCA_CLOCK_FROZEN:NCA_DEADLINE,1);return -1;
 }
 return 0;
}
void NcaWaitFailed(NCA_CONTEXT *c,int timedOut)
{
 if(c&&c->Initialized&&c->State==NCA_PENDING&&!c->Quarantined)
  Fail(c,timedOut?NCA_WAIT_TIMEOUT:NCA_WAIT_FAILED,1);
}
int NcaRetire(NCA_CONTEXT *c,NCT_COMPLETION_RECORD *out)
{
 int good;
 if(out)Zero(out,sizeof(*out));
 if(!c||!c->Initialized||!out)return 0;
 /* A result is consumed exactly once. An invalid next Begin cannot reuse the
  * prior transaction's successful retirement or trigger cleanup MMIO. */
 if(c->Record.Retired||(!c->Changed&&c->State==NCA_IDLE))return 0;
 good=c->State==NCA_DONE&&!c->Quarantined&&c->Record.Irq==1&&c->Record.Ack==1;
 if(!Owner(c))goto End;
 if(!Mask(c))goto End;
 if(!Clocks(c))goto End;
 /* A timed out START is not proven aborted by clearing the initialization
  * fields. Keep it quarantined; do not reset and pretend it retired. */
 if(!good){if(c->Record.Issued&&!c->Record.Retired&&!c->Quarantined)Fail(c,NCA_DEADLINE,1);goto End;}
 Write(c,4,c->Binding.Original[1]);Write(c,0,c->Binding.Original[0]);
 c->Restored=Read(c,0)==c->Binding.Original[0]&&Read(c,4)==c->Binding.Original[1]&&Read(c,0x10)==0;
 if(!c->Restored){Fail(c,NCA_RESTORE,1);goto End;}
 c->Record.Retired=1;c->Changed=0;c->State=NCA_IDLE;
End:
 c->Record.Cancelled=(uint8_t)c->Cancelled;
 c->Record.Quarantined=(uint8_t)c->Quarantined;*out=c->Record;
 return out->Retired&&!out->Quarantined&&!out->Cancelled;
}
int NcaDisable(NCA_CONTEXT *c)
{
 if(!c||!c->Initialized)return 0;
 NcaCancel(c);
 if(!Owner(c))return 0;
 if(c->State==NCA_PENDING)Fail(c,NCA_CANCEL,1);
 if(!Mask(c))return 0;
 /* ACK only while we still own the endpoint. No success/retirement is forged. */
 Write(c,0x14,1);return 1;
}
int NcaRestoredBinding(NCA_CONTEXT *c)
{
 if(!c||!c->Initialized||c->Quarantined||c->State!=NCA_IDLE||
   c->Changed||!c->Restored||!c->MaskVerified||
   (c->Record.Issued&&!c->Record.Retired))return 0;
 if(!Owner(c)||!Clocks(c))return 0;
 if(Read(c,0)!=c->Binding.Original[0]||Read(c,4)!=c->Binding.Original[1]||Read(c,0x10))
  return Fail(c,NCA_RESTORE,1);
 return 1;
}
