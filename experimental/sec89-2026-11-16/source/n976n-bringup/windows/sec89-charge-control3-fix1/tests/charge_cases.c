/* Actual byte-read engine and pure charger decode; no device access. */
#define N976N_D0_INCLUDE
#include "d0_cases.c"
#include "../Charge.c"
static unsigned cancel_at;
static BAT_U32 CancelRead(void *o,N976N_BAT_U64 a)
{
 BAT_U32 v=Read(o,a);
 if(a==HSI+RX&&cancel_at&&done==cancel_at)cancel_mode=1;
 return v;
}
static void CancelWrite(void *o,N976N_BAT_U64 a,N976N_BAT_U32 v)
{
 BankWrite(o,a,v);
 if(a==HSI+TX&&cancel_at==3)cancel_mode=1;
}
int main(void)
{
 N976N_POWER_RAW r;N976N_POWER_VALUES v;N976N_POWER_DECISION d;
 N976N_POWER_FACTS f={.Now=100,.SampleAt=99,.Generation=1,.SampleGeneration=1,
 .SourceEpoch=1,.SampleSourceEpoch=1,.MaxAge=2,.OwnerReady=1,
 .SourceContractValid=1,.SourceMa=100,.SourceMv=5000,.FreshThermistors=1,
 .SourceSink=1,.SourceWired=1,.ThermalAllowed=1,.DirectInactive=1,.ProtectionProven=1};
 N976N_BATTERY_READ s;
 for(unsigned i=0;i<N976N_PWR_COUNT;i++)need(N976nPowerReadSpec(i,&s)&&
  N976nPowerReadAllowed(s.Address,s.Register,1)&&!N976nPowerReadAllowed(s.Address,s.Register,2),"fixed_charger_read_spec_no_burst");
 need(!N976nPowerReadSpec(N976N_PWR_COUNT,&s)&&!N976nPowerReadSpec(0,NULL)&&
  !N976nPowerReadAllowed(0x69,0xB0,1)&&!N976nPowerReadAllowed(0x25,0xB2,1),"no_irq_or_mailbox_read");
 bank_seed();need(!N976nBatBusAcquireD0(C),"charger_acquire");
 need(!N976nBatBusReadChargeActive(C,1,&r)&&r.ValidMask==N976N_PWR_ALL&&r.Sequence&&
  starts==38&&txcount==19&&acks==38&&C->D0Active&&C->Report.Retired&&!C->Quarantined,
  "exact_19_pointer_read_pairs_no_configuration_payload");
 need(!N976nBatBusReleaseD0(C)&&bank_restored(),"charger_observation_restores_d0");
 memset(&r,0,sizeof(r));r.Sequence=1;r.ValidMask=N976N_PWR_ALL;
 for(unsigned m=0;m<16;m++) {
  r.Byte[N976N_PWR_MODE]=m;
  need(N976nPowerDecode(&r,&v)&&v.Mode==m&&
   v.ChargingMode==(m==5||m==6||m==7||m==13||m==15)&&
   v.ReservedMode==(m==11),"mode_entire_enum_not_bit0");
 }
 unsigned cc[]={0,2,3,63},cce[]={100,100,150,3150};
 unsigned ic[]={0,3,4,126,127},ice[]={100,100,125,3175,3200};
 for(unsigned i=0;i<4;i++){r.Byte[N976N_PWR_CC]=cc[i];need(N976nPowerDecode(&r,&v)&&v.ChargeMa==cce[i],"cc_boundaries");}
 for(unsigned i=0;i<5;i++){r.Byte[N976N_PWR_ICL]=ic[i];need(N976nPowerDecode(&r,&v)&&v.InputMa==ice[i],"icl_boundaries");}
 unsigned cv[]={0,4,5,0x13,0x22,0x23,0x38,0x39},cve[]={4000,4200,4210,4350,4500,0,0,0};
 for(unsigned i=0;i<8;i++){r.Byte[N976N_PWR_CV]=cv[i];need(N976nPowerDecode(&r,&v)&&v.CvMv==cve[i]&&v.CvValid==(i<5),"cv_ambiguous_encodings_not_guessed");}
 r.Byte[N976N_PWR_ICL]=255;need(N976nPowerDecode(&r,&v)&&v.InputMa==3200,"individual_ff_byte_not_missing");
 r.Byte[N976N_PWR_DETAIL1]=0x3B;need(N976nPowerDecode(&r,&v)&&v.WdtExpired,"watchdog_expiry_not_hidden");
 memset(r.Byte,255,sizeof(r.Byte));need(!N976nPowerDecode(&r,&v)&&!v.Valid,"all_ff_frame_unknown");
 memset(r.Byte,0,sizeof(r.Byte));r.Byte[N976N_PWR_MODE]=0x15;r.Byte[N976N_PWR_DETAIL0]=0x60;
 r.Byte[N976N_PWR_DETAIL1]=0x31;r.Byte[N976N_PWR_ROUTE]=0x60;r.Byte[N976N_PWR_CV]=0x13;
 r.Byte[N976N_PWR_ICL]=3;r.Byte[N976N_PWR_INT_OK]=0x40;
 need(N976nPowerDecode(&r,&v),"valid_observation_fixture");
 N976nPowerEvaluate(&v,&f,&d);need(d.GatesPresent&&!d.WriteCapability&&
  d.State==N976N_POWER_EXISTING_UNMANAGED,"even_synthetic_complete_facts_never_enable_or_adopt");
 r.Byte[N976N_PWR_MODE]=11;N976nPowerDecode(&r,&v);N976nPowerEvaluate(&v,&f,&d);
 need(d.State==N976N_POWER_UNKNOWN,"reserved_mode_never_off");
 r.Byte[N976N_PWR_MODE]=0x15;r.Byte[N976N_PWR_ICL]=127;N976nPowerDecode(&r,&v);N976nPowerEvaluate(&v,&f,&d);
 need(!d.GatesPresent&&(d.Reasons&N976N_POWER_SOURCE),"configured_current_above_contract_blocks");
 r.Byte[N976N_PWR_ICL]=3;N976nPowerDecode(&r,&v);
 f.SourceContractValid=0;N976nPowerEvaluate(&v,&f,&d);
 need((d.Reasons&N976N_POWER_SOURCE)&&!d.WriteCapability&&d.State==N976N_POWER_STOP_REQUIRED,
  "source_presence_and_limits_do_not_authorize_charging");
 f.Now=103;N976nPowerEvaluate(&v,&f,&d);
 need(d.State==N976N_POWER_UNKNOWN&&(d.Reasons&N976N_POWER_STALE),"stale_is_unknown_not_off");
 f.Now=98;N976nPowerEvaluate(&v,&f,&d);need(d.State==N976N_POWER_UNKNOWN,"future_sample_unknown");
 f.Now=100;f.SampleGeneration=2;N976nPowerEvaluate(&v,&f,&d);need(d.State==N976N_POWER_UNKNOWN,"wrong_owner_generation_unknown");
 for(unsigned mask=0;mask<64;mask++) {
  f.SourceContractValid=mask&1;f.FreshThermistors=!!(mask&2);f.ThermalAllowed=!!(mask&4);
  f.DirectInactive=!!(mask&8);f.ProtectionProven=!!(mask&16);f.OwnerReady=!!(mask&32);
  N976nPowerEvaluate(&v,&f,&d);need(!d.WriteCapability&&(d.Reasons&N976N_POWER_CONTROL_DISABLED),"all_gate_combinations_write_disabled");
 }
 for(cancel_at=1;cancel_at<=3;cancel_at++) {
  bank_seed();N976N_BAT_BUS_OPS ops=BankOps;ops.Read32=CancelRead;ops.Write32=CancelWrite;
  need(N976nBatBackendInit(&Backend,&ops,NULL,&Binding,5,Original)&&!N976nBatBusAcquireD0(C),"cancel_pair_fixture");
  N976N_BAT_BACKEND_SAMPLE b;
  need(N976nBatBackendReadActive(&Backend,&b)==N976N_BAT_BUS_ABORTED&&!b.Publishable&&
   starts==2&&C->Report.RxBytes==2&&C->Report.Retired&&C->Report.Restored&&!C->Quarantined&&bank_restored(),
   "cancel_at_pointer_or_each_rx_byte_drains_exact_pair_before_release");
 }
 bank_seed();need(!N976nBatBusAcquireD0(C),"charge_failure_fixture");fault=6;
 memset(&r,255,sizeof(r));need(N976nBatBusReadChargeActive(C,1,&r)&&!r.ValidMask,
  "failed_charge_frame_invalidates_previous_bytes");
 {const N976N_BAT_U8 usb[]={0xDF,0xE0,0x31,0x15,0x38,0x52,0x99,0x13,0x0C,0x23,0x68,
   0x27,0x81,0xA1,0x08,0x19,0x47,0x04,0x73};
  const N976N_BAT_U8 wall[]={0xDF,0xE0,0x31,0x15,0x38,0x6A,0x99,0x13,0x0C,0x47,0x68,
   0x27,0x83,0x71,0x08,0x01,0x57,0x04,0x73};
  r.Sequence=1;r.ValidMask=N976N_PWR_ALL;memcpy(r.Byte,usb,sizeof(usb));
  need(N976nPowerDecode(&r,&v)&&v.VoltageBucket==2&&v.VbusDetected&&v.ChargerType==1&&
   v.CcStatus==1&&v.RpCode==2&&v.CcPin==2&&!v.PsReady&&v.PdMessage==0x19&&
   v.PcaStandby&&!v.PcaActive&&v.PcaForceStandby&&v.PcaEnableActiveLow&&!v.Cnfg09Bit7,
   "physical_usb_photo_decode_does_not_synthesize_contract");
  memcpy(r.Byte,wall,sizeof(wall));
  need(N976nPowerDecode(&r,&v)&&v.VoltageBucket==2&&v.ChargerType==3&&v.CcStatus==1&&
   v.RpCode==3&&v.CcPin==1&&v.PsReady&&v.PdMessage==1&&v.PcaStandby&&!v.PcaActive&&
   v.InputMa==1800&&v.ChargeMa==2100,"physical_wall_photo_decode");
  memset(&f,0,sizeof(f));N976nPowerEvaluate(&v,&f,&d);
  need(!d.WriteCapability&&!d.GatesPresent&&(d.Reasons&N976N_POWER_SOURCE)&&
   (d.Reasons&N976N_POWER_THERMAL)&&(d.Reasons&N976N_POWER_PROTECTION),"photo_not_write_authority");
 }
 for(unsigned i=0;i<N976N_PWR_COUNT;i++){
  memset(&r,0xA5,sizeof(r));r.Sequence=1;r.ValidMask=N976N_PWR_ALL^(1U<<i);
  need(!N976nPowerDecode(&r,&v)&&!v.Valid,"partial_19_byte_snapshot_never_published");
 }
 /* Explicitly exclude clearing IRQs, USBC mailbox and PCA controls. */
 need(!N976nPowerReadAllowed(0x25,0x02,1)&&!N976nPowerReadAllowed(0x25,0x51,1)&&
  !N976nPowerReadAllowed(0x57,0x01,1)&&!N976nPowerReadAllowed(0x57,0x21,1),"no_extra_endpoint_ranges");
 printf("PASS %u cases\n",tests);return 0;
}
