/* SPDX-License-Identifier: MIT */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ThermalBridge.h"
#include "../../../common/sec89-charge-win1/tests/twrp_dt_fixture.h"
static unsigned assertions;
#define CHECK(x) do{assertions++;if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(1);}}while(0)
static NCT_CONTEXT C;static NCT_IDENTITY I;static N976N_POWER_FACTS F;
static void Fresh(unsigned point)
{
 NCT_PROFILE p={0};NCT_COMPLETION_RECORD r;
 const uint16_t *adc[3]={temp_adc,chg_temp_adc,usb_temp_adc};
 const int32_t *deci[3]={temp_deci_c,chg_temp_deci_c,usb_temp_deci_c};
 memset(&C,0,sizeof(C));memset(&F,0,sizeof(F));
 p.DtHash[0]=1; /* Synthetic binding for this host test, not current DT proof. */
 p.AdcAddress=0x15C40000;p.AdcBytes=0x100;p.Irq=116;p.Channel[0]=4;p.Channel[1]=3;p.Channel[2]=1;
 for(unsigned k=0;k<3;k++){memcpy(p.Adc[k],adc[k],sizeof(p.Adc[k]));memcpy(p.DeciC[k],deci[k],sizeof(p.DeciC[k]));p.MaxMiddleSpread[k]=64;}
 I=(NCT_IDENTITY){100000000,7,9,1,1,0,0};CHECK(NctInit(&C,&p,7));CHECK(NctBegin(&C,&I,500));
 for(unsigned n=0;n<15;n++){
  memset(&r,0,sizeof(r));CHECK(NctNext(&C,&I,&r.Ticket));r.Started100ns=I.Now100ns;
  I.Now100ns+=1040;r.Completed100ns=I.Now100ns;r.Raw=adc[n%3][point];
  r.Issued=r.Irq=r.Ack=r.Retired=1;CHECK(NctAccept(&C,&I,&r));
 }
 CHECK(NctFinish(&C,&I));F.Now=I.Now100ns;F.SampleAt=F.Now;F.MaxAge=500*10000;
 F.Generation=F.SampleGeneration=27;F.OwnerReady=1;F.SourceEpoch=F.SampleSourceEpoch=9;
}
int main(void)
{
 N976N_POWER_DECISION d;N976N_POWER_VALUES v={0};
 Fresh(12);CHECK(N976nThermalObserve(&C,&I,&F));
 CHECK(F.FreshThermistors&&F.ThermalAllowed&&F.SampleAt==100000000);
 CHECK(F.Generation==27&&C.AdcGeneration==7);CHECK(!F.SourceContractValid&&!F.ProtectionProven&&!F.DirectInactive);
 v.Valid=1;N976nPowerEvaluate(&v,&F,&d);CHECK(!d.WriteCapability&&!d.GatesPresent);
 Fresh(12);F.SampleAt=99999999;CHECK(N976nThermalObserve(&C,&I,&F));CHECK(F.SampleAt==99999999);
 for(unsigned k=0;k<11;k++){
  Fresh(12);F.FreshThermistors=F.ThermalAllowed=1;
  switch(k){case 0:F.Now++;break;case 1:F.SampleAt=F.Now+1;break;
   case 2:F.SampleAt=F.Now-F.MaxAge-1;break;case 3:F.Generation++;break;
   case 4:F.OwnerReady=0;break;case 5:F.MaxAge--;break;case 6:F.MaxAge=1001*10000;break;
   case 7:F.SourceEpoch++;break;case 8:I.AdcGeneration++;break;case 9:I.Cancelled=1;break;case 10:F.SourceEpoch=F.SampleSourceEpoch=0;break;}
  CHECK(!N976nThermalObserve(&C,&I,&F));CHECK(!F.FreshThermistors&&!F.ThermalAllowed);
 }
 Fresh(12);F.Now=I.Now100ns=C.Result.Oldest100ns+500*NCT_MS;F.SampleAt=F.Now;
 CHECK(N976nThermalObserve(&C,&I,&F));I.Now100ns++;F.Now++;CHECK(!N976nThermalObserve(&C,&I,&F));
 /* In-range electrical samples may represent a temperature outside the
  * conservative charge window. Fresh is distinct from thermally allowed. */
 Fresh(0);CHECK(N976nThermalObserve(&C,&I,&F));CHECK(F.FreshThermistors&&!F.ThermalAllowed);
 Fresh(22);CHECK(N976nThermalObserve(&C,&I,&F));CHECK(F.FreshThermistors&&!F.ThermalAllowed);
 Fresh(12);F.FreshThermistors=F.ThermalAllowed=1;
 CHECK(!N976nThermalObserve(NULL,&I,&F));CHECK(!F.FreshThermistors&&!F.ThermalAllowed);
 CHECK(!N976nThermalObserve(&C,NULL,&F));CHECK(!C.Result.Valid);
 CHECK(!N976nThermalObserve(&C,&I,NULL));
 for(unsigned k=0;k<3;k++){
  Fresh(12);I.Cancelled=1;
  if(k==0)F.OwnerReady=0;if(k==1)F.SampleAt=F.Now-F.MaxAge-1;
  CHECK(!N976nThermalObserve(&C,&I,k==2?NULL:&F));CHECK(C.CancelLatched&&!C.Result.Valid);
  I.Cancelled=0;CHECK(!NctBegin(&C,&I,500));
 }
 printf("PASS %u assertions\n",assertions);return 0;
}
