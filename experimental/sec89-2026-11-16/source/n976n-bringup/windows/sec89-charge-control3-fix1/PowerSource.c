/* SPDX-License-Identifier: MIT */
#include "PowerSource.h"
static void Zero(void *p,unsigned n){N976N_BAT_U8 *b=p;while(n--)*b++=0;}
static int Same(const N976N_POWER_RAW *a,const N976N_POWER_RAW *b)
{
 unsigned i;
 /* Hardware-owned input details, route and the six CCIC status bytes.
  * Charge completion/current/gauge changes are not source-contract changes. */
 if(((a->Byte[0]^b->Byte[0])&0x60)||a->Byte[1]!=b->Byte[1]||
    a->Byte[9]!=b->Byte[9]||a->Byte[10]!=b->Byte[10])return 0;
 for(i=N976N_PWR_USBC1;i<=N976N_PWR_PD1;i++)if(a->Byte[i]!=b->Byte[i])return 0;
 return 1;
}
void N976nSourceInvalidate(N976N_SOURCE_STATE *s)
{if(s){s->Valid=s->OnlineKnown=s->Online=s->Open=0;s->CompletedAt=0;}}
void N976nSourceInit(N976N_SOURCE_STATE *s,N976N_BAT_U64 generation)
{if(s){Zero(s,sizeof(*s));s->Generation=generation;}}
static int Accept(N976N_SOURCE_STATE *s,const N976N_POWER_RAW *r,N976N_BAT_U64 now)
{
 N976N_POWER_VALUES v;
 if(!s||!s->Generation||s->Exhausted||!now||now<s->LastNow||!N976nPowerDecode(r,&v)){
  N976nSourceInvalidate(s);return 0;
 }
 s->LastNow=now;return 1;
}
int N976nSourceBegin(N976N_SOURCE_STATE *s,const N976N_POWER_RAW *r,N976N_BAT_U64 now)
{
 if(s&&s->Open){N976nSourceInvalidate(s);return 0;}
 if(!Accept(s,r,now))return 0;
 s->Changed=!s->Valid||!Same(&s->Last,r);
 if(s->Changed){
  if(s->Epoch==~(N976N_BAT_U64)0){s->Exhausted=1;N976nSourceInvalidate(s);return 0;}
  ++s->Epoch;
 }
 s->Last=*r;s->StartedAt=now;s->CompletedAt=0;
 s->Valid=s->OnlineKnown=s->Online=0;s->Open=1;return 1;
}
int N976nSourceFinish(N976N_SOURCE_STATE *s,const N976N_POWER_RAW *r,N976N_BAT_U64 now)
{
 N976N_POWER_VALUES v;
 if(!Accept(s,r,now)||!s->Open||!s->StartedAt||!s->Epoch||now<s->StartedAt||
    now-s->StartedAt>1000ULL*10000||!Same(&s->Last,r)){
  N976nSourceInvalidate(s);return 0;
 }
 if(!N976nPowerDecode(r,&v)){N976nSourceInvalidate(s);return 0;}
 s->Last=*r;s->CompletedAt=now;s->Valid=1;s->Open=0;
 /* Samsung raw cc_SINK=1 (not the software PD enum CC_SNK=0).
  * Bracketed sink+VBUS+CHGIN is an observed external
  * supply, not proof of negotiated current, voltage accuracy or exclusivity. */
 if(v.VbusDetected&&v.CcStatus==1&&(v.IntOk&0x40)&&v.ChginDetail==3&&
    !(v.IntOk&0x20)&&!v.BoostMode&&!v.ReservedMode){s->OnlineKnown=s->Online=1;}
 else if(!v.VbusDetected&&!(v.IntOk&0x60)&&v.CcStatus==0){s->OnlineKnown=1;s->Online=0;}
 return 1;
}

int N976nSourceMatches(const N976N_SOURCE_STATE *s,const N976N_POWER_RAW *r)
{N976N_POWER_VALUES v;return s&&s->Valid&&N976nPowerDecode(r,&v)&&Same(&s->Last,r);}
