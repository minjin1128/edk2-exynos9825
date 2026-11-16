/* SPDX-License-Identifier: MIT */
#include "Charge.h"
static void Clear(void *P,unsigned N){N976N_BAT_U8 *B=P;while(N--)*B++=0;}
int N976nPowerDecode(const N976N_POWER_RAW *R,N976N_POWER_VALUES *V)
{
 unsigned Cv,I;
 if(!V)return 0;Clear(V,sizeof(*V));
 if(!R||!R->Sequence||R->ValidMask!=N976N_PWR_ALL)return 0;
 /* A complete FF image is inaccessible/suspicious, not a real configuration. */
 for(I=0;I<N976N_PWR_COUNT&&R->Byte[I]==255;I++);
 if(I==N976N_PWR_COUNT)return 0;
 V->IntOk=R->Byte[N976N_PWR_INT_OK];V->Valid=1;V->Mode=R->Byte[N976N_PWR_MODE]&15;
 V->ChargingMode=V->Mode==5||V->Mode==6||V->Mode==7||V->Mode==13||V->Mode==15;
 V->BoostMode=V->Mode>=8;V->ReservedMode=V->Mode==11;
 V->WdtEnabled=(R->Byte[N976N_PWR_MODE]>>4)&1;
 V->ChargeDetail=R->Byte[N976N_PWR_DETAIL1]&15;
 V->WdtExpired=V->ChargeDetail==11;
 /* 0 unknown,1 charging,2 full,3 not charging,4 discharging. */
 V->ObservedCharge=V->ChargeDetail<=2?1:V->ChargeDetail<=4?2:V->ChargeDetail<=7?3:
  (V->ChargeDetail==8||V->ChargeDetail==10||V->ChargeDetail==11)?4:0;
 V->BatteryDetail=(R->Byte[N976N_PWR_DETAIL1]>>4)&7;
 V->ChginDetail=(R->Byte[N976N_PWR_DETAIL0]>>5)&3;
 /* Samsung max77705_get_autoibus(): DTLS_00 bit7, observation only. */
 V->AutoIbus=(R->Byte[N976N_PWR_DETAIL0]>>7)&1;
 I=R->Byte[N976N_PWR_ICL]&127;V->InputMa=I<=3?100:(I+1)*25;
 I=R->Byte[N976N_PWR_CC]&63;V->ChargeMa=I<=2?100:I*50;
 Cv=R->Byte[N976N_PWR_CV]&63;
 /* Decode the getter through 0x22 (4500mV). Setter uses 0x23 at >=4500,
  * while getter maps 0x23 to4510; 38/39 also disagree. Do not infer a safe
  * write encoding from this observation. Codes >=0x23 stay invalid. */
 if(Cv<=0x22){V->CvValid=1;V->CvMv=Cv<=4?4000+Cv*50:4200+(Cv-4)*10;}
 V->TopoffMa=150+(R->Byte[N976N_PWR_TOPOFF]&7)*50;
 V->RouteRaw=R->Byte[N976N_PWR_ROUTE];V->TimerRaw=R->Byte[N976N_PWR_TIMER];
 V->ProtectionRaw=R->Byte[N976N_PWR_PROTECTION];
 V->Cnfg09Bit7=R->Byte[N976N_PWR_ICL]>>7;
 V->VoltageBucket=R->Byte[N976N_PWR_USBC1]>>4;
 V->VbusDetected=R->Byte[N976N_PWR_BC]>>7;V->ChargerType=R->Byte[N976N_PWR_BC]&3;
 V->CcStatus=R->Byte[N976N_PWR_CC1]&7;V->RpCode=(R->Byte[N976N_PWR_CC1]>>4)&3;
 V->CcPin=R->Byte[N976N_PWR_CC1]>>6;V->CcStatus2=R->Byte[N976N_PWR_CC2];
 V->PdMessage=R->Byte[N976N_PWR_PD0];V->PsReady=(R->Byte[N976N_PWR_PD1]>>4)&1;
 V->PcaStandby=(R->Byte[N976N_PWR_PCA_STATUS_B]>>2)&1;
 V->PcaActive=(R->Byte[N976N_PWR_PCA_STATUS_B]>>4)&1;
 V->PcaForceStandby=(R->Byte[N976N_PWR_PCA_START]>>5)&1;
 V->PcaEnableActiveLow=(R->Byte[N976N_PWR_PCA_START]>>6)&1;
 /* Do not infer SourceMv/SourceMa/InputLimitEnforced, a source epoch or any
  * charge capability from these sequential status bytes. */
 return 1;
}
void N976nPowerEvaluate(const N976N_POWER_VALUES *V,const N976N_POWER_FACTS *F,N976N_POWER_DECISION *D)
{
 if(!D)return;Clear(D,sizeof(*D));D->Reasons=N976N_POWER_CONTROL_DISABLED;
 if(F){D->EvaluatedAt=F->Now;D->SampleAt=F->SampleAt;D->Generation=F->Generation;
  if(F->MaxAge&&F->SampleAt<=~(N976N_BAT_U64)0-F->MaxAge)D->ValidUntil=F->SampleAt+F->MaxAge;}
 if(!V||!V->Valid||!F){D->Reasons|=N976N_POWER_NO_SAMPLE;return;}
 if(!F->Generation||F->Generation!=F->SampleGeneration||!F->OwnerReady)D->Reasons|=N976N_POWER_OWNER;
 if(!F->MaxAge||!F->SampleAt||F->Now<F->SampleAt||F->Now-F->SampleAt>F->MaxAge)D->Reasons|=N976N_POWER_STALE;
 if(!F->SourceEpoch||F->SourceEpoch!=F->SampleSourceEpoch||!F->SourceContractValid||
    !F->SourceMa||F->SourceMv<4500||F->SourceMv>5500||!F->SourceSink||!F->SourceWired||
    V->InputMa>F->SourceMa||!(V->IntOk&0x40)||(V->RouteRaw&0x60)!=0x60)D->Reasons|=N976N_POWER_SOURCE;
 if(!F->FreshThermistors||!F->ThermalAllowed)D->Reasons|=N976N_POWER_THERMAL;
 if(!F->DirectInactive)D->Reasons|=N976N_POWER_DIRECT;
 if(!F->ProtectionProven||!V->WdtEnabled||V->WdtExpired)D->Reasons|=N976N_POWER_PROTECTION;
 if(V->BoostMode||V->ReservedMode)D->Reasons|=N976N_POWER_MODE;
 if(V->ChginDetail!=3||V->BatteryDetail!=3||!V->CvValid||V->ChargeDetail>=8)D->Reasons|=N976N_POWER_DEVICE;
 if(!V->ObservedCharge||(V->ObservedCharge==1&&!V->ChargingMode))D->Reasons|=N976N_POWER_INCONSISTENT;
 D->GatesPresent=(D->Reasons==N976N_POWER_CONTROL_DISABLED);
 if(D->Reasons&(N976N_POWER_STALE|N976N_POWER_OWNER|N976N_POWER_MODE|N976N_POWER_INCONSISTENT))return;
 D->State=V->ChargingMode?N976N_POWER_EXISTING_UNMANAGED:N976N_POWER_NONCHARGING_MODE;
 /* This is an unmet stop requirement, never a claim that charging was stopped. */
 if(V->ChargingMode&&(D->Reasons&~N976N_POWER_CONTROL_DISABLED))D->State=N976N_POWER_STOP_REQUIRED;
 /* WriteCapability remains zero. Neither Battc nor a caller can override it. */
}
