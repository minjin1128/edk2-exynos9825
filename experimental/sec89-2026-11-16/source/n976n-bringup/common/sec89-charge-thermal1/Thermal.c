/* SPDX-License-Identifier: MIT */
#include "Thermal.h"
static void Zero(void *p,uint32_t n){uint8_t *b=p;while(n--)*b++=0;}
static int Profile(const NCT_PROFILE *p)
{
 unsigned i,j;uint8_t hash=0;uint16_t s[5];int32_t t;
 if(!p||p->AdcAddress!=0x15C40000ULL||p->AdcBytes!=0x100||p->Irq!=116||
    p->Channel[0]!=4||p->Channel[1]!=3||p->Channel[2]!=1)return 0;
 for(i=0;i<32;i++)hash|=p->DtHash[i];if(!hash)return 0;
 for(i=0;i<NCT_CHANNELS;i++){
  for(j=0;j<5;j++)s[j]=p->Adc[i][11];
  if(!NccThermistor(s,p->Adc[i],p->DeciC[i],NCT_POINTS,p->MaxMiddleSpread[i],&t))return 0;
 }
 return 1;
}
int NctInit(NCT_CONTEXT *c,const NCT_PROFILE *p,uint64_t generation)
{
 if(!c||c->Initialized||!generation||!Profile(p))return 0;
 Zero(c,sizeof(*c));c->Profile=*p;c->AdcGeneration=generation;c->Initialized=1;
 return 1;
}
void NctInvalidate(NCT_CONTEXT *c,enum NCT_REASON why,int uncertain)
{
 if(!c)return;
 Zero(&c->Result,sizeof(c->Result));c->Reason=why;c->State=NCT_INVALID;
 if(why==NCT_CANCELLED)c->CancelLatched=1;
 if(uncertain)c->Quarantined=1;
 /* Preserve pending/records for diagnosis; invalidation is not retirement. */
}
static int Fail(NCT_CONTEXT *c,enum NCT_REASON why,int uncertain)
{NctInvalidate(c,why,uncertain);return 0;}
static int Identity(NCT_CONTEXT *c,const NCT_IDENTITY *i)
{
 if(!c||!c->Initialized)return 0;
 if(i&&i->Cancelled)c->CancelLatched=1;
 if(c->Quarantined)return Fail(c,NCT_UNCERTAIN,1);
 if(!i||!i->Ready||i->Quarantined||!i->AdcGeneration||
    i->AdcGeneration!=c->AdcGeneration)return Fail(c,NCT_OWNER,1);
 if(!i->Retired)return Fail(c,NCT_UNCERTAIN,1);
 if(c->CancelLatched)return Fail(c,NCT_CANCELLED,0);
 if(!i->Now100ns||i->Now100ns<c->LastNow100ns)return Fail(c,NCT_CLOCK,0);
 c->LastNow100ns=i->Now100ns;return 1;
}
static int Current(NCT_CONTEXT *c,const NCT_IDENTITY *i)
{
 if(!Identity(c,i))return 0;
 if(i->SourceEpoch!=c->SourceEpoch)return Fail(c,NCT_SOURCE,0);
 if(i->Now100ns>=c->Deadline100ns)return Fail(c,NCT_DEADLINE,0);
 return 1;
}
int NctBegin(NCT_CONTEXT *c,const NCT_IDENTITY *i,uint32_t budget)
{
 if(!c||!c->Initialized)return 0;
 if(c->State==NCT_COLLECTING||c->Outstanding)return Fail(c,NCT_REENTRANT,c->Outstanding!=0);
 Zero(&c->Result,sizeof(c->Result));
 if(!Identity(c,i))return 0;
 if(!budget||budget>NCT_BATCH_MAX_MS||i->Now100ns>UINT64_MAX-budget*NCT_MS||
    c->Batch==UINT64_MAX)return Fail(c,NCT_ARGUMENT,0);
 c->SourceEpoch=i->SourceEpoch;c->Deadline100ns=i->Now100ns+budget*NCT_MS;
 c->Batch++;c->Count=0;c->Reason=NCT_OK;c->State=NCT_COLLECTING;
 Zero(c->Samples,sizeof(c->Samples));Zero(&c->Pending,sizeof(c->Pending));return 1;
}
int NctNext(NCT_CONTEXT *c,const NCT_IDENTITY *i,NCT_TICKET *t)
{
 uint64_t end;if(t)Zero(t,sizeof(*t));
 if(!c||!t)return 0;
 if(c->State!=NCT_COLLECTING||c->Outstanding||c->Count>=NCT_TOTAL)
  return Fail(c,NCT_SEQUENCE,c->Outstanding!=0);
 if(!Current(c,i))return 0;
 if(c->Sequence==UINT64_MAX)return Fail(c,NCT_SEQUENCE,0);
 end=c->Deadline100ns;
 if(i->Now100ns<=UINT64_MAX-NCT_CONVERSION_MS*NCT_MS&&
    i->Now100ns+NCT_CONVERSION_MS*NCT_MS<end)end=i->Now100ns+NCT_CONVERSION_MS*NCT_MS;
 c->Pending=(NCT_TICKET){c->Batch,++c->Sequence,c->AdcGeneration,c->SourceEpoch,
   i->Now100ns,end,c->Profile.Channel[c->Count%NCT_CHANNELS]};
 c->Outstanding=1;*t=c->Pending;return 1;
}
static int Ticket(const NCT_TICKET *a,const NCT_TICKET *b)
{return a->Batch==b->Batch&&a->Sequence==b->Sequence&&a->AdcGeneration==b->AdcGeneration&&
 a->SourceEpoch==b->SourceEpoch&&a->NotBefore100ns==b->NotBefore100ns&&
 a->Deadline100ns==b->Deadline100ns&&a->Channel==b->Channel;}
int NctAccept(NCT_CONTEXT *c,const NCT_IDENTITY *i,const NCT_COMPLETION_RECORD *r)
{
 if(!c||!r)return 0;
 if(c->State!=NCT_COLLECTING||!c->Outstanding||c->Count>=NCT_TOTAL)
  return Fail(c,NCT_SEQUENCE,1);
 /* A mismatched completion cannot retire the expected request. */
 if(!Ticket(&c->Pending,&r->Ticket))return Fail(c,NCT_SEQUENCE,1);
 if(!r->Retired||r->Quarantined)return Fail(c,NCT_UNCERTAIN,1);
 c->Outstanding=0;
 if(r->Cancelled){c->CancelLatched=1;return Fail(c,NCT_CANCELLED,0);}
 if(!Current(c,i))return 0;
 if(r->Issued!=1||r->Irq!=1||r->Ack!=1)return Fail(c,NCT_COMPLETION,0);
 if(r->Started100ns<c->Pending.NotBefore100ns||r->Completed100ns<r->Started100ns||
    r->Completed100ns>i->Now100ns||r->Completed100ns>=c->Pending.Deadline100ns)
  return Fail(c,NCT_DEADLINE,0);
 if(r->Raw==UINT32_MAX||!(r->Raw&0xFFF)||(r->Raw&0xFFF)==4095)return Fail(c,NCT_SAMPLE,0);
 c->Samples[c->Count++]=*r;return 1;
}
int NctFinish(NCT_CONTEXT *c,const NCT_IDENTITY *i)
{
 unsigned ch,j;uint16_t s[5];NCT_RESULT r;
 if(!c)return 0;
 if(c->State!=NCT_COLLECTING||c->Outstanding||c->Count!=NCT_TOTAL)
  return Fail(c,NCT_MISSING,c->Outstanding!=0);
 if(!Current(c,i))return 0;
 Zero(&r,sizeof(r));
 for(ch=0;ch<NCT_CHANNELS;ch++){
  for(j=0;j<NCT_SAMPLES;j++)s[j]=(uint16_t)(c->Samples[j*NCT_CHANNELS+ch].Raw&0xFFF);
  if(!NccThermistor(s,c->Profile.Adc[ch],c->Profile.DeciC[ch],NCT_POINTS,
      c->Profile.MaxMiddleSpread[ch],&r.DeciC[ch]))return Fail(c,NCT_SAMPLE,0);
 }
 r.Batch=c->Batch;r.AdcGeneration=c->AdcGeneration;r.SourceEpoch=c->SourceEpoch;
 r.Oldest100ns=c->Samples[0].Started100ns;r.Newest100ns=c->Samples[NCT_TOTAL-1].Completed100ns;
 r.Finished100ns=i->Now100ns;r.Count=NCT_TOTAL;r.Valid=1;
 c->Result=r;c->State=NCT_READY;c->Reason=NCT_OK;return 1;
}
int NctApply(NCT_CONTEXT *c,const NCT_IDENTITY *i,NCC_FACTS *f)
{
 uint64_t at,now;
 if(!f)return 0;
 f->Evidence&=~NCC_THERMISTORS;f->PackDeciC=f->ChargerDeciC=f->UsbDeciC=0;
 if(!c||c->State!=NCT_READY||c->Result.Valid!=1||c->Result.Count!=NCT_TOTAL)return 0;
 if(!Identity(c,i))return 0;
 if(!i->SourceEpoch||i->SourceEpoch!=c->Result.SourceEpoch||
    f->SourceEpoch!=i->SourceEpoch||f->SampleSourceEpoch!=i->SourceEpoch)return Fail(c,NCT_SOURCE,0);
 now=i->Now100ns/NCT_MS;at=c->Result.Oldest100ns/NCT_MS;
 if(!at||!f->SampleAt||!f->MaxAgeMs||f->MaxAgeMs>1000||f->Now!=now||
    i->Now100ns<c->Result.Finished100ns||i->Now100ns-c->Result.Oldest100ns>f->MaxAgeMs*NCT_MS||
    f->SampleAt>now||now-f->SampleAt>f->MaxAgeMs)return Fail(c,NCT_STALE,0);
 if(at<f->SampleAt)f->SampleAt=at;
 f->PackDeciC=c->Result.DeciC[0];f->ChargerDeciC=c->Result.DeciC[1];f->UsbDeciC=c->Result.DeciC[2];
 f->Evidence|=NCC_THERMISTORS;return 1;
}
int NctCollect(NCT_CONTEXT *c,const NCT_OPS *o,void *p,uint32_t budget)
{
 NCT_IDENTITY i;NCT_TICKET t;NCT_COMPLETION_RECORD r;unsigned n;int ok;
 if(!c)return 0;
 if(!o||!o->Identity||!o->Convert)return Fail(c,NCT_MISSING,0);
 Zero(&i,sizeof(i));if(!o->Identity(p,&i))return Fail(c,NCT_OWNER,1);
 if(!NctBegin(c,&i,budget))return 0;
 for(n=0;n<NCT_TOTAL;n++){
  Zero(&i,sizeof(i));if(!o->Identity(p,&i))return Fail(c,NCT_OWNER,1);
  if(!NctNext(c,&i,&t))return 0;
  Zero(&r,sizeof(r));ok=o->Convert(p,&t,&r);
  if(!ok){
   /* Failure must not cause a retry, nor conceal an unretired issued request. */
   if(Ticket(&t,&r.Ticket)&&r.Retired&&!r.Quarantined)c->Outstanding=0;
   if(r.Cancelled)c->CancelLatched=1;
   return Fail(c,r.Cancelled?NCT_CANCELLED:NCT_COMPLETION,c->Outstanding!=0||r.Quarantined);
  }
  Zero(&i,sizeof(i));if(!o->Identity(p,&i))return Fail(c,NCT_OWNER,1);
  if(!NctAccept(c,&i,&r))return 0;
 }
 Zero(&i,sizeof(i));if(!o->Identity(p,&i))return Fail(c,NCT_OWNER,1);
 return NctFinish(c,&i);
}
