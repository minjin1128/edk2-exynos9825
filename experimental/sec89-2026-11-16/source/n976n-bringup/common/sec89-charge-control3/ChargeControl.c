/* SPDX-License-Identifier: MIT */
#include "ChargeControl.h"
static void Zero(void *P,uint32_t N){uint8_t *B=P;while(N--)*B++=0;}
static int Fresh(uint64_t Now,uint64_t At,uint32_t Age)
{return At&&Age&&Age<=2000&&Now>=At&&Now-At<=Age;}
int NccDecode(const uint8_t R[NCC_RAW_COUNT],NCC_VALUES *V)
{
 unsigned I,C;if(!V)return 0;Zero(V,sizeof(*V));if(!R)return 0;
 for(I=0;I<NCC_RAW_COUNT&&R[I]==255;I++) {}
 if(I==NCC_RAW_COUNT)return 0;
 V->Mode=R[3]&15;V->Cnfg09Bit7=R[9]>>7;V->WdtEnabled=(R[3]>>4)&1;
 V->FastTimerCode=R[4]&7;V->WdtExpired=(R[2]&15)==11;
 V->Wired=(R[0]>>6)&1;V->Wireless=(R[0]>>5)&1;
 V->WcinDetail=(R[1]>>3)&3;V->ChginDetail=(R[1]>>5)&3;
 V->BatteryDetail=(R[2]>>4)&7;V->ChargeDetail=R[2]&15;
 V->ProtectionUnlocked=((R[8]>>2)&3)==3;
 V->AutoIbus=R[1]>>7;V->Route=R[10];
 C=R[9]&127;V->InputMa=C<=3?100:(C+1)*25;
 C=R[5]&63;V->ChargeMa=C<=2?100:C*50;
 C=R[7]&63;if(C<=0x22)V->CvMv=C<=4?4000+C*50:4200+(C-4)*10;
 return 1;
}
int NccThermistor(const uint16_t S[5],const uint16_t *A,const int32_t *T,
                 uint32_t N,uint16_t MaxSpread,int32_t *Out)
{
 uint32_t I,J,X;uint16_t Sorted[5],Q;int64_t V;
 if(!Out)return 0;*Out=0;
 if(!S||!A||!T||N<2||N>64||!MaxSpread||MaxSpread>=4095)return 0;
 for(I=0;I<N;I++)if(!A[I]||A[I]>=4095||T[I]<-400||T[I]>1250||
   (I&&(A[I]<=A[I-1]||T[I]>=T[I-1])))return 0;
 for(I=0;I<5;I++){if(!S[I]||S[I]>=4095)return 0;Sorted[I]=S[I];}
 for(I=1;I<5;I++)for(J=I;J&&Sorted[J]<Sorted[J-1];J--){
   Q=Sorted[J];Sorted[J]=Sorted[J-1];Sorted[J-1]=Q;}
 if(Sorted[3]-Sorted[1]>MaxSpread)return 0;
 X=((uint32_t)Sorted[1]+Sorted[2]+Sorted[3])/3;
 /* No endpoint clamp: open/short/out-of-table is missing evidence. */
 if(X<A[0]||X>A[N-1])return 0;
 for(I=1;I<N&&X>A[I];I++);
 V=(int64_t)(T[I]-T[I-1])*(X-A[I-1])/(A[I]-A[I-1]);
 *Out=T[I-1]+(int32_t)V;return 1;
}
static enum NCC_REASON Check(const NCC_FACTS *F,NCC_VALUES *V)
{
 if(!F||!NccDecode(F->Raw,V))return NCC_ARGUMENT;
 if(!F->OwnerGeneration||!F->OwnerReady||!F->Retired)return NCC_OWNER;
 if(F->Cancelled)return NCC_CANCELLED;
 if(!Fresh(F->Now,F->SampleAt,F->MaxAgeMs))return NCC_STALE;
 /* Supervised CONTROL3: no claim of a measured physical watchdog cutoff.
  * Keep the independently preserved qualified core unchanged. */
 if(F->Evidence!=NCC_BENCH_EVIDENCE||F->QualifiedWatchdogMs)return NCC_EVIDENCE;
 if(!F->SourceEpoch||F->SourceEpoch!=F->SampleSourceEpoch||!F->Sink||!F->Wired||
    F->SourceMv!=5500||F->SourceMa<100||F->SourceMa>5000||
    !F->InputLimitEnforced||F->InputOwnerGeneration!=F->OwnerGeneration||
    F->InputSourceEpoch!=F->SourceEpoch||F->InputValidUntil<=F->Now||
    !V->Wired||V->Wireless||V->WcinDetail||V->ChginDetail!=3||
    (V->Route&0x60)!=0x60||!V->AutoIbus||V->InputMa>F->SourceMa||
    (uint64_t)F->SourceMv*V->InputMa>25000000ULL)return NCC_SOURCE;
 /* Conservative first bench profile, not Samsung's whole thermal policy. */
 /* First bench caps are deliberately below the recovered DT's pack 41C
  * swelling and charger 48C high thresholds. Not a general charge policy. */
 if(F->PackDeciC<100||F->PackDeciC>=400||F->ChargerDeciC<0||
    F->ChargerDeciC>=450||F->UsbDeciC<0||F->UsbDeciC>=450)return NCC_TEMPERATURE;
 if(!V->ProtectionUnlocked||!V->WdtEnabled||(V->WdtExpired&&V->Mode!=4)||
    V->BatteryDetail!=3||(V->ChargeDetail>4&&V->ChargeDetail!=8&&!(V->Mode==4&&V->WdtExpired))||
    !V->CvMv||V->CvMv!=F->DtCvMv||V->CvMv>4400||
    !F->WatchdogServiceMs||F->WatchdogServiceMs>1000||
    F->MaxAgeMs>F->WatchdogServiceMs)return NCC_BASELINE;
 return NCC_OK;
}
/* Preflight may admit an inherited MODE5 only for an owned MODE4 stop.
 * Expired watchdog is recoverable only after that stop, never by adoption. */
enum NCC_REASON NccBenchPreflight(const NCC_FACTS *F)
{
 NCC_FACTS T;NCC_VALUES V;enum NCC_REASON E;
 if(!F)return NCC_ARGUMENT;T=*F;
 if((T.Raw[3]&15)!=4&&(T.Raw[3]&15)!=5)return NCC_BASELINE;
 T.Raw[3]=(uint8_t)((T.Raw[3]&0xF0)|4);
 E=Check(&T,&V);return E;
}
enum NCC_REASON NccPlan(const NCC_FACTS *F,const NCC_REQUEST *R,NCC_PLAN *P)
{
 NCC_VALUES V;enum NCC_REASON E;if(!P)return NCC_ARGUMENT;Zero(P,sizeof(*P));
 if(!R||R->ChargeMa<100||R->ChargeMa>600||
    (R->Policy!=NCC_TIMED_TRIAL&&R->Policy!=NCC_CONTINUOUS)||
    (R->Policy==NCC_TIMED_TRIAL&&(R->SessionMs<1000||R->SessionMs>60000))||
    (R->Policy==NCC_CONTINUOUS&&R->SessionMs!=NCC_CONTINUOUS_SAFETY_MS))
   return NCC_ARGUMENT;
 E=Check(F,&V);if(E)return E;
 if(V.Mode!=4)return NCC_BASELINE;
 if(R->Policy==NCC_CONTINUOUS&&(V.ChargeDetail==3||V.ChargeDetail==4))return NCC_FULL;
 if(R->ChargeMa>500&&(V.InputMa!=900||F->SourceMa<1500))return NCC_SOURCE;
 P->OwnerGeneration=F->OwnerGeneration;P->SourceEpoch=F->SourceEpoch;
 P->ChargeCode=(uint8_t)(R->ChargeMa/50);P->ChargeMa=P->ChargeCode*50U;
 P->InputMa=V.InputMa;P->InputMilliwatts=F->SourceMv*V.InputMa/1000;
 P->CvMv=V.CvMv;P->SessionMs=R->SessionMs;P->Policy=R->Policy;P->AutoIbus=V.AutoIbus;
 P->Cnfg09Bit7=V.Cnfg09Bit7;
 P->Config01=F->Raw[4];P->Config03=F->Raw[6];P->Config12=F->Raw[10];
 P->WatchdogServiceMs=F->WatchdogServiceMs;P->QualifiedWatchdogMs=F->QualifiedWatchdogMs;
 return NCC_OK;
}
void NccInit(NCC_CONTEXT *C,const NCC_OPS *O,void *P)
{if(C){Zero(C,sizeof(*C));if(O)C->Ops=*O;C->Opaque=P;C->Mode4NotConfirmed=1;}}
static void Fail(NCC_CONTEXT *C,enum NCC_REASON R)
{
 C->Reason=R;
 if(!C->FirstReason){
  C->FirstReason=R;C->First.Facts=C->ObservedFacts;
  C->First.Now=C->ObservedNow;C->First.LastKick=C->LastKick;C->First.StartedAt=C->StartedAt;
  C->First.Phase=C->Phase;C->First.Site=C->Site;C->First.Reason=R;
 }
}
static void Quarantine(NCC_CONTEXT *C,enum NCC_REASON R)
{C->Uncertain=1;C->Mode4Confirmed=0;C->Mode4NotConfirmed=1;C->State=NCC_QUARANTINED;Fail(C,R);}
static int Enter(NCC_CONTEXT *C)
{
 if(!C)return 0;
 if(C->Busy){Fail(C,NCC_REENTRANT);return 0;}
 if(C->Uncertain)return 0;
 if(!C->Ops.Snapshot||!C->Ops.Owner||!C->Ops.Read||!C->Ops.Write){Fail(C,NCC_ARGUMENT);return 0;}
 C->Busy=1;return 1;
}
static int IdentityRead(NCC_CONTEXT *C,NCC_FACTS *F,int Cleanup,int Observe)
{
 NCC_IDENTITY O;int Valid;Zero(F,sizeof(*F));Zero(&O,sizeof(O));
 if(!Observe){Valid=C->Ops.Owner(C->Opaque,&O);F->Now=O.Now;F->OwnerGeneration=O.OwnerGeneration;
   F->OwnerReady=O.OwnerReady;F->Retired=O.Retired;F->Cancelled=O.Cancelled;}
 else Valid=C->Ops.Snapshot(C->Opaque,F);
 C->ObservedNow=F->Now;if(Observe)C->ObservedFacts=*F;
 if(!Valid||!F->OwnerReady||!F->Retired||!F->OwnerGeneration||
   (C->OwnerGeneration&&C->OwnerGeneration!=F->OwnerGeneration)){
   C->Site=NCC_SITE_OWNER;
   Quarantine(C,NCC_OWNER);return 0;}
 if(!C->OwnerGeneration)C->OwnerGeneration=F->OwnerGeneration;
 if(F->Cancelled)C->CancelLatched=1;
 if(!Cleanup&&C->CancelLatched){C->Site=NCC_SITE_CANCEL;Fail(C,NCC_CANCELLED);return 0;}
 if(!Cleanup&&C->LastNow&&F->Now<C->LastNow){C->Site=NCC_SITE_CLOCK;Fail(C,NCC_STALE);return 0;}
 /* Cleanup may still stop charging after clock rollback, but must never
  * lower the monotonic floor used for a later explicit rearm. */
 if(F->Now>C->LastNow)C->LastNow=F->Now;return 1;
}
static int Identity(NCC_CONTEXT *C,NCC_FACTS *F,int Cleanup)
{return IdentityRead(C,F,Cleanup,!Cleanup);}
static int Result(NCC_CONTEXT *C,enum NCC_IO_RESULT R)
{
 if(R==NCC_IO_OK)return 1;
 C->Site=NCC_SITE_IO;
 if(R<NCC_IO_OK||R>=NCC_IO_UNKNOWN)Quarantine(C,NCC_UNCERTAIN);
 else Fail(C,NCC_IO);
 return 0;
}
static int Read(NCC_CONTEXT *C,uint8_t Reg,uint8_t *V,int Cleanup)
{
 NCC_FACTS F;NCC_TICKET T;
 /* A register read neither enables nor renews charging. Validate its owner,
  * cancellation and monotonic clock without 19 additional register reads.
  * Every payload still has a full Ready snapshot immediately before it, and
  * every successful Patch still has the caller's full Ready afterward. */
 if(!IdentityRead(C,&F,Cleanup,0))return 0;
 Zero(&T,sizeof(T));T.OwnerGeneration=C->OwnerGeneration;T.Cleanup=(uint8_t)Cleanup;
 /* Reads do not renew charging. Ordinary reads still require current source,
  * cancellation and a finite sample lease; the write uses tighter deadlines. */
 if(!Cleanup){
  /* Plan was admitted once; a later failed sensor snapshot must not extend
   * this read lease through an unvalidated MaxAgeMs value. */
  if(!C->Plan.WatchdogServiceMs||C->Plan.WatchdogServiceMs>1000||
     F.Now>UINT64_MAX-C->Plan.WatchdogServiceMs){C->Site=NCC_SITE_READ_LEASE;Fail(C,NCC_STALE);return 0;}
  T.SourceEpoch=C->SourceEpoch;T.CheckedAt=F.Now;
  T.NotAfter=F.Now+C->Plan.WatchdogServiceMs;
 }
 C->Reads++;return Result(C,C->Ops.Read(C->Opaque,0x69,Reg,V,&T));
}
static int Ready(NCC_CONTEXT *C,NCC_FACTS *F)
{
 NCC_VALUES V;enum NCC_REASON E;
 if(!Identity(C,F,0))return 0;
 C->Site=NCC_SITE_FACTS;E=Check(F,&V);
 /* The oldest constituent must stay newer than the last confirmed stop,
  * and never move back behind any admitted rearm/start/ready snapshot. */
 if(!E&&(F->SampleAt<=C->StoppedAt||F->SampleAt<C->SampleFloor)){C->Site=NCC_SITE_SAMPLE_FLOOR;E=NCC_STALE;}
 if(!E&&(F->SourceEpoch!=C->SourceEpoch||V.InputMa!=C->Plan.InputMa||V.CvMv!=C->Plan.CvMv||
    V.AutoIbus!=C->Plan.AutoIbus||V.Cnfg09Bit7!=C->Plan.Cnfg09Bit7||V.Mode!=C->ExpectedMode||
    F->Raw[4]!=C->Plan.Config01||F->Raw[6]!=C->Plan.Config03||F->Raw[10]!=C->Plan.Config12||
    F->WatchdogServiceMs!=C->Plan.WatchdogServiceMs||
    F->QualifiedWatchdogMs!=C->Plan.QualifiedWatchdogMs||
    (C->CcConfigured&&V.ChargeMa!=C->Plan.ChargeMa))){C->Site=NCC_SITE_SOURCE;E=NCC_SOURCE;}
 if(!E&&(F->Now<C->StartedAt||F->Now-C->StartedAt>=C->Plan.SessionMs)){C->Site=NCC_SITE_SESSION;E=C->Plan.Policy==NCC_CONTINUOUS?NCC_SAFETY_TIME:NCC_SESSION_END;}
 if(!E&&C->Plan.Policy==NCC_CONTINUOUS&&(V.ChargeDetail==3||V.ChargeDetail==4)){C->Site=NCC_SITE_BASELINE;E=NCC_FULL;}
 if(!E&&C->LastKick&&(F->Now<C->LastKick||F->Now-C->LastKick>F->WatchdogServiceMs)){C->Site=NCC_SITE_KICK;E=NCC_STALE;}
 if(!E&&C->State==NCC_MANAGED&&F->SampleAt<=C->LastSample){C->Site=NCC_SITE_NEW_SAMPLE;E=NCC_STALE;}
 if(E){Fail(C,E);return 0;}C->SampleFloor=F->SampleAt;return 1;
}
/* No generic RMW entry point is exported. Only these three operations exist.
 * WDTCLR is a command: never replay readback bits 1:0 in another write. */
static int Patch(NCC_CONTEXT *C,uint8_t Reg,uint8_t Mask,uint8_t Bits,int Cleanup)
{
 uint8_t Before,After,Payload;NCC_FACTS F;NCC_TICKET T;uint64_t Limit;
 if(!((Reg==0xB7&&Mask==15&&(Bits==4||Bits==5))||
      (Reg==0xB9&&Mask==63&&Bits>=2&&Bits<=12)||
      (Reg==0xBD&&Mask==3&&Bits==1))){Fail(C,NCC_ARGUMENT);return 0;}
 if(!Read(C,Reg,&Before,Cleanup))return 0;
 if(Reg==0xB7&&(Before&15)!=4&&(Before&15)!=5){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);return 0;}
 if(Reg==0xBD&&(Before&12)!=12){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);return 0;}
 if(Cleanup){if(!Identity(C,&F,1))return 0;}else if(!Ready(C,&F))return 0;
 Zero(&T,sizeof(T));T.OwnerGeneration=C->OwnerGeneration;T.Cleanup=(uint8_t)Cleanup;
 T.CompareBefore=1;T.Before=Before;
 if(!Cleanup){
  C->Site=NCC_SITE_TICKET;
  T.SourceEpoch=C->SourceEpoch;T.CheckedAt=F.Now;
  if(C->StartedAt>UINT64_MAX-C->Plan.SessionMs||F.SampleAt>UINT64_MAX-F.MaxAgeMs||
    (C->LastKick&&C->LastKick>UINT64_MAX-C->Plan.WatchdogServiceMs)){
    Fail(C,NCC_STALE);return 0;}
  T.NotAfter=C->StartedAt+C->Plan.SessionMs;
  Limit=F.SampleAt+F.MaxAgeMs;if(Limit<T.NotAfter)T.NotAfter=Limit;
  if(F.InputValidUntil<T.NotAfter)T.NotAfter=F.InputValidUntil;
  if(C->LastKick){Limit=C->LastKick+C->Plan.WatchdogServiceMs;
    if(Limit<T.NotAfter)T.NotAfter=Limit;}
  if(T.NotAfter<=F.Now){Fail(C,NCC_STALE);return 0;}
 }
 Payload=(uint8_t)((Before&~Mask)|Bits);
 if(Reg==0xB7&&Bits==5)C->Mode4NotConfirmed=1;
 C->Writes++;
 if(!Result(C,C->Ops.Write(C->Opaque,0x69,Reg,Payload,&T)))return 0;
 if(Reg==0xB7)C->ExpectedMode=Bits;
 if(!Read(C,Reg,&After,Cleanup))return 0;
 if(Reg==0xBD){if((After&252)!=(Before&252)||(After&3)>1){C->Site=NCC_SITE_READBACK;Fail(C,NCC_READBACK);return 0;}}
 else if(After!=Payload){C->Site=NCC_SITE_READBACK;Fail(C,NCC_READBACK);return 0;}
 if(Reg==0xB7&&Bits==4){C->Mode4Confirmed=1;C->Mode4NotConfirmed=0;}
 if(Reg==0xBD){C->LastKick=F.Now;C->Kicks++;}
 if(Reg==0xB9)C->CcConfigured=1;
 return 1;
}
static int InputFallback(NCC_CONTEXT *C)
{
 NCC_FACTS F;NCC_TICKET T;uint8_t Before,After,Payload;
 if(!C->InputTouched)return 1;
 if(!Identity(C,&F,1))return 0;
 Zero(&T,sizeof(T));T.OwnerGeneration=C->OwnerGeneration;T.Cleanup=1;
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xC0,&Before,&T)))return 0;
 Payload=(uint8_t)((Before&0x80)|3);T.CompareBefore=1;T.Before=Before;
 if(Before!=Payload){
  ++C->Writes;++C->InputWrites;
  if(!Result(C,C->Ops.Write(C->Opaque,0x69,0xC0,Payload,&T)))return 0;
 }
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xC0,&After,&T)))return 0;
 if(After!=Payload){C->Site=NCC_SITE_READBACK;Fail(C,NCC_READBACK);return 0;}
 if(!Identity(C,&F,1))return 0;
 C->InputFallbackConfirmed=1;C->InputTouched=0;C->InputConfigured=0;return 1;
}
static int StopInner(NCC_CONTEXT *C)
{
 uint8_t Mode;NCC_FACTS F;
 /* Source loss/cancel is a stop reason, not a loss of the hardware lease.
  * Unknown completion/owner blocks new traffic, including an optimistic OFF. */
 if(C->Uncertain)return 0;
 if(!Read(C,0xB7,&Mode,1))goto Unknown;
 if((Mode&15)==4){
  if(!InputFallback(C))goto Unknown;
  if(!Identity(C,&F,1))goto Unknown;
  C->Mode4Confirmed=1;C->Mode4NotConfirmed=0;C->StoppedAt=C->LastNow;
  C->State=NCC_MODE4_CONFIRMED;return 1;
 }
 C->Mode4NotConfirmed=1;
 if((Mode&15)!=5){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Unknown;}
 if(!Patch(C,0xB7,15,4,1))goto Unknown;
 if(!InputFallback(C))goto Unknown;
 if(!Identity(C,&F,1))goto Unknown;
 C->StoppedAt=C->LastNow;C->State=NCC_MODE4_CONFIRMED;return 1;
Unknown:
 if(!C->Uncertain)Quarantine(C,C->Reason?C->Reason:NCC_UNCERTAIN);
 return 0;
}
int NccStop(NCC_CONTEXT *C)
{int Ok;if(!Enter(C))return 0;C->Phase=NCC_PHASE_STOP;Ok=StopInner(C);C->Busy=0;return Ok;}
int NccRearm(NCC_CONTEXT *C,const NCC_REQUEST *R)
{
 NCC_FACTS F;NCC_PLAN P;enum NCC_REASON E;int Ok=0;
 if(!Enter(C))return 0;
 C->Phase=NCC_PHASE_REARM;C->Site=NCC_SITE_BASELINE;
 if(C->State!=NCC_MODE4_CONFIRMED||!C->Mode4Confirmed||C->Mode4NotConfirmed){
  C->Reason=NCC_BASELINE;goto Done;
 }
 if(!Identity(C,&F,0))goto Done;
 /* Check age before interpreting MODE: an old MODE5 cannot revoke a newer
  * confirmed stop. Snapshot may perform reads; no Read/Write callbacks here. */
 C->Site=NCC_SITE_SAMPLE_FLOOR;
 if(!Fresh(F.Now,F.SampleAt,F.MaxAgeMs)||F.Now<=C->StoppedAt||
    F.SampleAt<=C->StoppedAt||F.SampleAt<C->SampleFloor){Fail(C,NCC_STALE);goto Done;}
 if((F.Raw[3]&15)!=4){
  C->Mode4Confirmed=0;C->Mode4NotConfirmed=1;
  Fail(C,NCC_BASELINE);C->State=NCC_REFUSED;goto Done;
 }
 C->Site=NCC_SITE_FACTS;E=NccPlan(&F,R,&P);
 if(E){Fail(C,E);goto Done;}
 /* No Init: retain owner, cancellation, lifetime evidence and counters. */
 Zero(&C->Plan,sizeof(C->Plan));C->SourceEpoch=0;C->StartedAt=0;
 C->LastKick=0;C->LastService=0;C->LastSample=0;C->SampleFloor=F.SampleAt;C->CcConfigured=0;
 C->ExpectedMode=4;C->Reason=NCC_OK;C->Mode4Confirmed=0;C->Mode4NotConfirmed=1;
 C->State=NCC_IDLE;Ok=1;
Done:C->Busy=0;return Ok;
}
int NccStart(NCC_CONTEXT *C,const NCC_REQUEST *R)
{
 NCC_FACTS F;NCC_VALUES V;enum NCC_REASON E;int Ok=0;
 if(!Enter(C))return 0;
 C->Phase=NCC_PHASE_START;C->Site=NCC_SITE_BASELINE;
 /* A duplicate API request neither stops the managed session nor replaces
  * its first hardware/policy failure. Caller must keep servicing or Stop. */
 if(C->State!=NCC_IDLE){C->Reason=NCC_BASELINE;goto Done;}
 if(!Identity(C,&F,0))goto Done;
 C->Site=NCC_SITE_INPUT_EPOCH;
 if(R&&R->ChargeMa>500&&(!C->InputConfigured||!C->InputTouched||F.SampleAt<=C->InputAt||
    F.SourceEpoch==C->InputSourceEpoch)){Fail(C,NCC_STALE);goto Done;}
 C->Site=NCC_SITE_SAMPLE_FLOOR;
 if(F.SampleAt<=C->StoppedAt||F.SampleAt<C->SampleFloor){
  Fail(C,NCC_STALE);C->State=NCC_REFUSED;goto Done;
 }
 C->Site=NCC_SITE_FACTS;E=NccPlan(&F,R,&C->Plan);
 if(E){Fail(C,E);C->State=NCC_REFUSED;goto Done;}
 C->SourceEpoch=F.SourceEpoch;C->StartedAt=F.Now;C->ExpectedMode=4;C->State=NCC_CONFIGURING;
 C->SampleFloor=F.SampleAt;
 /* A sampled MODE4 is admission evidence, not a fresh stop readback. */
 C->Mode4Confirmed=0;C->Mode4NotConfirmed=1;
 /* Hardware timer/CV/C0[7] remain unchanged. ICL was prepared separately. Service fail-off evidence
  * is not physically qualified in this supervised development profile.
  * The finite software session does not promise cutoff after kernel loss. */
 /* Exactly one recovery kick while MODE4; no enable if fresh detail remains B. */
 C->Phase=NCC_PHASE_FIRST_KICK;
 if(!Patch(C,0xBD,3,1,0)||!Ready(C,&F))goto Stop;
 if((F.Raw[2]&15)==11){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Stop;}
 C->Phase=NCC_PHASE_CC;
 if(!Patch(C,0xB9,63,C->Plan.ChargeCode,0)||!Ready(C,&F))goto Stop;
 C->Phase=NCC_PHASE_SECOND_KICK;
 if(!Patch(C,0xBD,3,1,0)||!Ready(C,&F))goto Stop;
 C->Phase=NCC_PHASE_ENABLE;
 if(!Patch(C,0xB7,15,5,0)||!Ready(C,&F))goto Stop;
 NccDecode(F.Raw,&V);
 if(V.Mode!=5||V.ChargeMa!=C->Plan.ChargeMa||F.Now<C->LastKick||
    F.Now-C->LastKick>F.WatchdogServiceMs){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Stop;}
 C->Mode4Confirmed=0;C->LastService=F.Now;C->LastSample=F.SampleAt;C->State=NCC_MANAGED;Ok=1;goto Done;
Stop:
 StopInner(C); /* No restoration of a saved MODE5 or stale source settings. */
Done:C->Busy=0;return Ok;
}
int NccService(NCC_CONTEXT *C)
{
 NCC_FACTS F;NCC_VALUES V;int Ok=0;
 if(!Enter(C))return 0;
 C->Phase=NCC_PHASE_SERVICE;C->Site=NCC_SITE_BASELINE;
 if(C->State!=NCC_MANAGED){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Done;}
 if(!Ready(C,&F))goto Stop;
 if(F.Now<=C->LastService||F.SampleAt<=C->LastSample){C->Site=NCC_SITE_NEW_SAMPLE;Fail(C,NCC_STALE);goto Stop;}
 if(F.Now<C->StartedAt||F.Now-C->StartedAt>=C->Plan.SessionMs){C->Site=NCC_SITE_SESSION;Fail(C,C->Plan.Policy==NCC_CONTINUOUS?NCC_SAFETY_TIME:NCC_SESSION_END);goto Stop;}
 NccDecode(F.Raw,&V);
 if(V.Mode!=5||V.ChargeMa!=C->Plan.ChargeMa){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Stop;}
 if(F.Now<C->LastKick||F.Now-C->LastKick>F.WatchdogServiceMs){C->Site=NCC_SITE_KICK;Fail(C,NCC_STALE);goto Stop;}
 /* Each service call is an explicit fresh monitoring point; stale/missing
  * facts never extend the watchdog lease. No catch-up kicks or retries. */
 if(!Patch(C,0xBD,3,1,0)||!Ready(C,&F))goto Stop;
 C->LastService=F.Now;C->LastSample=F.SampleAt;Ok=1;goto Done;
Stop:StopInner(C);
Done:C->Busy=0;return Ok;
}

int NccPrepareInput900(NCC_CONTEXT *C)
{
 NCC_FACTS F;NCC_VALUES V;NCC_TICKET T;NCC_IDENTITY O;
 uint8_t Mode,Before,After,Payload;uint64_t Limit;enum NCC_REASON E;int Ok=0,Admitted=0;
 if(!Enter(C))return 0;
 C->Phase=NCC_PHASE_INPUT;C->Site=NCC_SITE_BASELINE;
 if(C->InputConfigured||C->State!=NCC_MODE4_CONFIRMED||!C->Mode4Confirmed||
    C->Mode4NotConfirmed){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Done;}
 Admitted=1;C->State=NCC_CONFIGURING;C->Mode4Confirmed=0;C->Mode4NotConfirmed=1;
 if(!Identity(C,&F,0))goto Done;
 C->Site=NCC_SITE_FACTS;E=Check(&F,&V);if(E){Fail(C,E);goto Done;}
 if(V.Mode!=4||F.SourceMa<1500||F.SourceMa>3000||F.SampleAt<=C->StoppedAt){
  C->Site=NCC_SITE_SOURCE;Fail(C,NCC_SOURCE);goto Done;}
 Zero(&T,sizeof(T));T.OwnerGeneration=C->OwnerGeneration;T.SourceEpoch=F.SourceEpoch;
 T.CheckedAt=F.Now;T.InputSetup=1;
 C->Site=NCC_SITE_TICKET;
 if(F.SampleAt>UINT64_MAX-F.MaxAgeMs){Fail(C,NCC_STALE);goto Done;}
 T.NotAfter=F.SampleAt+F.MaxAgeMs;Limit=F.InputValidUntil;
 if(Limit<T.NotAfter)T.NotAfter=Limit;
 if(T.NotAfter<=F.Now){Fail(C,NCC_STALE);goto Done;}
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xB7,&Mode,&T)))goto Done;
 if(Mode!=F.Raw[3]||(Mode&15)!=4){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Done;}
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xC0,&Before,&T)))goto Done;
 if(Before!=F.Raw[9]){C->Site=NCC_SITE_SOURCE;Fail(C,NCC_SOURCE);goto Done;}
 C->InputBefore=Before;Payload=(uint8_t)((Before&0x80)|0x23);
 T.CompareBefore=1;T.Before=Before;
 C->InputTouched=1;C->InputFallbackConfirmed=0;
 if(Payload!=Before){
  ++C->Writes;++C->InputWrites;
  if(!Result(C,C->Ops.Write(C->Opaque,0x69,0xC0,Payload,&T)))goto Done;
 }
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xC0,&After,&T)))goto Done;
 C->InputAfter=After;if(After!=Payload){C->Site=NCC_SITE_READBACK;Fail(C,NCC_READBACK);goto Done;}
 ++C->Reads;if(!Result(C,C->Ops.Read(C->Opaque,0x69,0xB7,&Mode,&T)))goto Done;
 if(Mode!=F.Raw[3]||(Mode&15)!=4){C->Site=NCC_SITE_BASELINE;Fail(C,NCC_BASELINE);goto Done;}
 Zero(&O,sizeof(O));
 int OwnerOk=C->Ops.Owner(C->Opaque,&O);C->ObservedNow=O.Now;
 if(!OwnerOk||!O.OwnerReady||!O.Retired||
    O.OwnerGeneration!=C->OwnerGeneration){C->Site=NCC_SITE_OWNER;Quarantine(C,NCC_OWNER);goto Done;}
 if(O.Cancelled){C->CancelLatched=1;C->Site=NCC_SITE_CANCEL;Fail(C,NCC_CANCELLED);goto Done;}
 if(O.Now<T.CheckedAt||O.Now>=T.NotAfter){C->Site=NCC_SITE_TICKET;Fail(C,NCC_STALE);goto Done;}
 C->InputAt=O.Now;C->InputSourceEpoch=F.SourceEpoch;C->InputConfigured=1;
 C->State=NCC_MODE4_CONFIRMED;C->Mode4Confirmed=1;C->Mode4NotConfirmed=0;Ok=1;
Done:
 /* Lost MODE4 proof must not survive a failed new observation. Only a known
  * owner/retired transport may establish a new stop. Never retry the ICL. */
 if(Admitted&&!Ok&&!C->Uncertain)StopInner(C);
 C->Busy=0;return Ok;
}
