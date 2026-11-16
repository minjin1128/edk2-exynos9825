/* SPDX-License-Identifier: MIT */
#include "ThermalBridge.h"
int N976nThermalObserve(NCT_CONTEXT *c,const NCT_IDENTITY *i,N976N_POWER_FACTS *f)
{
 NCC_FACTS core={0};
 /* Cancellation remains latched even when owner/age validation also fails. */
 if(c&&i&&i->Cancelled)NctInvalidate(c,NCT_CANCELLED,0);
 if(!f)return 0;
 f->FreshThermistors=0;f->ThermalAllowed=0;
 if(!c)return 0;
 if(!i){NctInvalidate(c,NCT_MISSING,0);return 0;}
 if(c->CancelLatched)return 0;
 /* Reject before narrowing units. No future or sub-ms-old sample may become
  * fresh simply because both timestamps rounded to the same millisecond. */
 if(!f->OwnerReady||!f->Generation||f->Generation!=f->SampleGeneration||
    f->Now!=i->Now100ns||!f->SampleAt||f->SampleAt>f->Now||
    !f->MaxAge||f->MaxAge>1000*NCT_MS||f->MaxAge%NCT_MS||
    f->Now-f->SampleAt>f->MaxAge){NctInvalidate(c,NCT_STALE,0);return 0;}
 core.Now=f->Now/NCT_MS;core.SampleAt=f->SampleAt/NCT_MS;
 core.MaxAgeMs=(uint32_t)(f->MaxAge/NCT_MS);
 core.OwnerGeneration=f->Generation;
 core.SourceEpoch=f->SourceEpoch;core.SampleSourceEpoch=f->SampleSourceEpoch;
 if(!NctApply(c,i,&core))return 0;
 if(c->Result.Oldest100ns<f->SampleAt)f->SampleAt=c->Result.Oldest100ns;
 f->FreshThermistors=1;
 /* Same conservative bench limits as preserved ChargeControl.c; these are
  * engineering caps, not a claim of Samsung's complete charging policy. */
 f->ThermalAllowed=core.PackDeciC>=100&&core.PackDeciC<400&&
   core.ChargerDeciC>=0&&core.ChargerDeciC<450&&core.UsbDeciC>=0&&core.UsbDeciC<450;
 return 1;
}
