/* SPDX-License-Identifier: MIT
 * CONTROL1 commissioning facts. USB-C Rp entitlement only; no PD, CCIC mailbox,
 * ICL/voltage/route/unlock writes. 60-second supervised test is not a physical
 * watchdog cutoff guarantee or continuous charging qualification.
 */
#include "PowerSource.h"
#include "ChargeControl.h"
int N976nBenchFacts(const N976N_SOURCE_STATE *s,const N976N_POWER_RAW *r,
 N976N_BAT_U64 now,NCC_FACTS *f)
{
 N976N_POWER_VALUES v;unsigned i;
 if(!s||!f||!s->Valid||!s->OnlineKnown||!s->Online||
   now<s->StartedAt||now-s->StartedAt>=1000ULL*10000||
   !N976nSourceMatches(s,r)||!N976nPowerDecode(r,&v))return 0;
 for(i=0;i<NCC_RAW_COUNT;i++)f->Raw[i]=r->Byte[i];
 f->SourceEpoch=f->SampleSourceEpoch=s->Epoch;
 f->SampleAt=s->StartedAt/10000;f->MaxAgeMs=1000;
 f->WatchdogServiceMs=1000;f->QualifiedWatchdogMs=0;
 f->Sink=v.CcStatus==1;f->Wired=!!(v.IntOk&0x40);
 /* VBADC2 is a bounded bucket. Use its upper edge for the power ceiling. */
 if(v.VoltageBucket==2){f->SourceMv=5500;f->Evidence|=NCC_SOURCE_VOLTAGE;}
 if(!v.PsReady&&(v.RpCode==2||v.RpCode==3)&&v.AutoIbus){
  f->SourceMa=v.RpCode==2?1500:3000;
  if(v.InputMa<=f->SourceMa){
   f->InputLimitEnforced=1;f->InputOwnerGeneration=f->OwnerGeneration;
   f->InputSourceEpoch=s->Epoch;f->InputValidUntil=f->SampleAt+1000;
   f->Evidence|=NCC_SOURCE_CURRENT;
  }
 }
 if(v.PcaStandby&&!v.PcaActive&&v.PcaForceStandby)f->Evidence|=NCC_DIRECT_OFF;
 if((v.ProtectionRaw&12)==12&&v.WdtEnabled)f->Evidence|=NCC_PROTECTION;
 /* CV must match the preserved N976N baseline, never derived from the same
  * live byte under validation. TWRP runtime.dts (20261105-02), battery,chg_float_voltage=0x10fe.
  * A different firmware CV is refused, not overwritten. */
 f->DtCvMv=4350;
 return 1;
}
