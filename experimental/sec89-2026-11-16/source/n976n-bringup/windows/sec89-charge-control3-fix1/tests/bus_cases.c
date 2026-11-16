/* Actual portable Bus.c/Backend.c with functional MMIO, never real hardware. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../Bus.c"
#include "../Backend.c"
#include "../../../common/sec88-battery1/N976nBattery.c"
static N976N_BAT_BACKEND Backend;
static N976N_BAT_BUS_CONTEXT *C=&Backend.Bus;
static struct { BAT_SIZE a; BAT_U32 v; } regs[256];
static unsigned nregs, reads, writes, starts, resets, acks, txcount;
static unsigned len, done, pointer, client, txread, stop, active, held;
static unsigned no_rx, sticky, gpio_writes, out_mask, tests, done_reads;
static int fault;
static BAT_U64 ticks;
static unsigned late_jump_us, late_jumped, reverse_on_rx;
static BAT_U8 data[3];
static unsigned control_model,payloads,cancel_payload;static BAT_U8 pmic[256];
/* FIX1 fixture: a reset/unconfigured controller does not synthesize EMPTY.
 * This models the DIAG1 observation, not a universal hardware reset guarantee. */
static unsigned reset_model, force_ready_fifo_zero, hsi_writes, setup_faults;
static unsigned inactive_fifo_reads, configured_fifo_reads;
static BAT_U32 inherited_fifo;
static BAT_U32 *reg(BAT_SIZE a) {
  for(unsigned i=0;i<nregs;i++) if(regs[i].a==a) return &regs[i].v;
  if(nregs==256) abort(); regs[nregs].a=a; return &regs[nregs++].v;
}
static BAT_U64 Counter(void *Opaque) { (void)Opaque; if(fault!=4) ticks+=10; return ticks; }
static void Barrier(void *Opaque) { (void)Opaque; }
static void Stall(void *Opaque,N976N_BAT_U32 Us) { (void)Opaque;(void)Us; }
static unsigned cancel_mode;
static int Cancel(void *Opaque) { (void)Opaque; return cancel_mode==1 || (cancel_mode==2&&starts>=2); }
static void finish(void) {
  active=0; held=!stop; *reg(0x15D60044)&=~BAT_BIT31;
  if(fault!=9 || !txread) *reg(0x15D60024)|=BAT_BIT7;
  *reg(0x15D60050)=stop?1:(BAT_BIT17|1);
}
static BAT_U16 sample(unsigned addr,unsigned r) {
  if(addr==0x36) switch(r) {
    case 0: return 0; case 6: return 0x3280; case 9: return 0xC800;
    case 0xA: return 0xFFFF; case 0xB: return 0xFFE0;
    case 5: return 800; case 0x35: return 1600;
    default: abort();
  }
  if(control_model&&addr==0x69)return pmic[r];
  if(addr==0x69 && r==0xB2) return 0x40;
  if(addr==0x69 && r==0xB4) return 1;
  if(N976nPowerReadAllowed(addr,r,1))return 0;
  abort();
}
static BAT_U32 Read(void *Opaque,N976N_BAT_U64 a) {
  (void)Opaque;
  reads++;
  if(a==HSI+INT_ST && active && txread && late_jump_us && !late_jumped){ticks+=late_jump_us;late_jumped=1;}
  if(fault==12 && starts && a==0x15C01020) return 1;
  if(a==0x15C30184 || a==0x15C301A4) {
    unsigned p=a==0x15C301A4; BAT_U32 con=*reg(p?0x15C301A0:0x15C30180);
    if((con&15)==1) return *reg(a);
    if(fault==16 && !p) return 0;
    return 1;
  }
  if(a==0x15D60030) {
    if(reset_model && *reg(MODE)==0) {
      inactive_fifo_reads++; return inherited_fifo;
    }
    if(reset_model) configured_fifo_reads++;
    if(force_ready_fifo_zero && !(*reg(HSI+USI_CON)&1)) return 0;
    if(active && txread && !no_rx && done<len+(fault==8?1:0))
      return BAT_BIT8|((len+(fault==8?1:0)-done)<<16);
    return BAT_BIT24|BAT_BIT8;
  }
  if(a==0x15D60038) {
    if(!active||!txread||done>=3) abort();
    BAT_U8 b=data[done++];
    if(reverse_on_rx)ticks=0;
    if(fault==7 && done==1) finish();
    else if(done==len+(fault==8?1:0)) finish();
    return 0xABCD0000U|b;
  }
  if(a==0x15D60024) {
    if(fault==6 && active && txread) return 0x400;
    if(sticky) return BAT_BIT7;
    if((*reg(a)&BAT_BIT7) && txread && ++done_reads>=(fault==21?1u:2u) && (fault==20||fault==21))
      return BAT_BIT7|BAT_BIT10;
  }
  return *reg(a);
}
static void Write(void *Opaque,N976N_BAT_U64 a,BAT_U32 v) {
  (void)Opaque;
  writes++;
  if(a>=HSI && a<=HSI+0xC8) hsi_writes++;
  /* No target device configuration, GPIO DAT, shared PLL or arbitrary MMIO. */
  if(a==0x15C30184 || a==0x15C301A4) abort();
  if(!((a>=0x15D60000 && a<=0x15D600C8) || a==0x15C0304C || a==0x15C22030 ||
       (a>=0x15C30180 && a<=0x15C301AC))) abort();
  if(a>=0x15C30180 && a<=0x15C301AC) {
    gpio_writes++;
    if((fault==30 || fault==33) && !starts && a==GPIO+0x180 && (v&15)==2) {
      setup_faults++;
      if(fault==33) *reg(HSI+CONF)=BAT_BIT31; /* foreign drift before Configure */
      return;
    }
    if(fault==17 && starts && a==0x15C30188 && (v&15)==4) return;
    if((a==0x15C30180 || a==0x15C301A0) && (v&15)==1)
      out_mask|=a==0x15C30180?1:2;
  }
  if(fault==31 && a==HSI+USI_CON && v==0) { setup_faults++; return; }
  if(a==0x15D60024) {
    if(v&BAT_BIT7) acks++;
    if(fault==10 && starts && (v&BAT_BIT7)) sticky=1;
    *reg(a)&=~v; return;
  }
  if(a==0x15D60020 && fault==11 && starts && v==0) return;
  if(a==0x15D60034) {
    if(control_model&&active&&!txread&&len==2&&stop&&client==0x69){
      if(v>255||done>=2)abort();
      if(!done){pointer=v;if(cancel_payload)cancel_mode=1;}
      else {pmic[pointer]=(BAT_U8)v;payloads++;if(pointer==0xBD)pmic[pointer]&=0xFC;}
      done++;txcount++;if(done==2)finish();return;
    }
    if(!active || txread || len!=1 || done || stop || v>0xFF) abort();
    pointer=v; done++; txcount++;
    (void)sample(client,pointer);
    if(fault!=4) finish();
    return;
  }
  *reg(a)=v;
  if(a==0x15D60000 && (v&BAT_BIT31)) {
    if(active || held) abort(); resets++; *reg(0x15D60050)=1;
  }
  if(a==0x15D60044 && (v&BAT_BIT31)) {
    if(active) abort();
    unsigned nextclient=(*reg(0x15D60070)>>10)&0x7F;
    active=1; starts++; done=done_reads=0;late_jumped=0; len=v&0xFFFF; stop=!!(v&BAT_BIT17); txread=!!(v&BAT_BIT16);
    if(!len||len>2||*reg(0x15D60070)!=((7U<<24)|(nextclient<<10))) abort();
    if(txread) {
      if(!held || !stop || nextclient!=client || len!=(client==0x36?2:1)) abort();
      BAT_U16 w=sample(client,pointer); data[0]=(BAT_U8)w;data[1]=(BAT_U8)(w>>8);data[2]=0xEE;
    } else {
      if(held || (!(control_model&&stop&&len==2&&nextclient==0x69)&&(stop||len!=1)) || (nextclient!=0x36 && nextclient!=0x69 && nextclient!=0x25 && nextclient!=0x57)) abort();
      client=nextclient;
    }
    no_rx=fault==5 && txread;
    *reg(0x15D60050)=BAT_BIT17|2; *reg(0x15D60024)=0;
  }
  return;
}


static N976N_BAT_BUS_OPS Ops={Read,Write,Barrier,Counter,Stall,Cancel};
static N976N_BAT_BUS_BINDING Binding;
static void bind(void) {
  memset(&Binding,0,sizeof(Binding));Binding.CounterHz=1000000;Binding.InputHz=49152000;
  const N976N_BAT_U64 clocks[]={CMGP+0x1020,CMGP+0x1824,CMGP+0x2010,CMGP+0x206C,CMGP+0x205C,CMGP+0x2088,CMGP+0x208C};
  Binding.ClockCount=7;
  for(unsigned i=0;i<7;i++){Binding.ClockAddress[i]=clocks[i];Binding.ClockValue[i]=*reg(clocks[i]);}
  Binding.Qch=*reg(QCH);Binding.Mode=*reg(MODE);
  for(unsigned i=0;i<6;i++)Binding.Gpio[i]=*reg(GPIO+mGpioOffsets[i]);
  for(unsigned i=0;i<16;i++)Binding.Config[i]=*reg(HSI+mConfigOffsets[i]);
  if(!N976nBatBackendInit(&Backend,&Ops,NULL,&Binding,5,Binding.Config)){fprintf(stderr,"init failed\n");exit(1);}
}
static void seed(int f) {
  memset(regs,0,sizeof(regs));nregs=reads=writes=starts=resets=acks=txcount=0;
  len=done=pointer=client=txread=stop=active=held=no_rx=sticky=gpio_writes=out_mask=done_reads=cancel_mode=0;
  late_jump_us=late_jumped=reverse_on_rx=0;
  fault=f;ticks=0;control_model=payloads=cancel_payload=0;memset(pmic,0,sizeof(pmic));
  reset_model=force_ready_fifo_zero=hsi_writes=setup_faults=0;
  inactive_fifo_reads=configured_fifo_reads=0;inherited_fifo=0;
  *reg(MODE)=4;*reg(HSI+CTL)=8;*reg(HSI+CONF)=BAT_BIT31;*reg(HSI+TRANS)=1;
  *reg(GPIO+0x180)=*reg(GPIO+0x1A0)=2;
  *reg(GPIO+0x188)=*reg(GPIO+0x1A8)=4;
  *reg(GPIO+0x18C)=*reg(GPIO+0x1AC)=2;
  *reg(GPIO+0x184)=*reg(GPIO+0x1A4)=1;
  if(f==15 || f==16 || f==17) {
    *reg(GPIO+0x180)=*reg(GPIO+0x1A0)=1;*reg(GPIO+0x184)=0;
  }
  bind();
  if(f==1)*reg(CMGP+0x1020)=BAT_BIT16;
  if(f==2)*reg(HSI+TRANS)=BAT_BIT17|2;
  if(f==3)*reg(GPIO+0x180)=3;
  if(f==18)*reg(HSI+INT_ST)=BAT_BIT31;
}
static void need(int ok,const char *name) {
  if(!ok) {
    fprintf(stderr,"FAIL %s status%llx reason%llx phase%llu starts%u reset%u active%u held%u wait%llu restored%llu Q%llu\n",
      name,(unsigned long long)C->Report.Status,(unsigned long long)C->Report.Reason,(unsigned long long)C->Report.Phase,
      starts,resets,active,held,(unsigned long long)C->Report.WaitUs,(unsigned long long)C->Report.Restored,(unsigned long long)C->Report.Quarantine);
    exit(1);
  }
  tests++;puts(name);
}
int main(void) {
  N976N_BAT_BACKEND_SAMPLE out;N976N_BATTERY_RAW raw;N976N_BAT_U64 status;
  seed(0);status=N976nBatBackendSample(&Backend,&out);
  need(!status&&out.Publishable&&out.Raw.ValidMask==N976N_BAT_ALL_FIELDS&&starts==18&&txcount==9&&C->Report.TxBytes==9&&C->Report.RxBytes==16,"nine_read_pairs_exact_done_ack_restore");
  need(C->Report.Restored&&C->Report.Retired&&!C->Quarantined&&*reg(HSI+INT_EN)==0&&*reg(QCH)==0&&(*reg(GPIO+0x188)&15)==4,"restore_original_hsi_pin_qch_no_dat");
  need(out.Values.SocPermille==505&&out.Values.FgResistor==5,"shared_codec_factor_and_low8");
  for(unsigned i=0;i<20;i++)need(!N976nBatBackendSample(&Backend,&out)&&out.Publishable&&out.Raw.SampleId==i+2,"repeated_sample_context_restored");
  need(starts==21*18&&C->Samples==21,"repeated_exact_request_count");
  for(int f=1;f<=3;f++){seed(f);status=N976nBatBackendSample(&Backend,&out);need(status&&!out.Publishable&&!writes&&!starts,"changed_binding_or_foreign_busy_refused_without_mutation");}
  seed(4);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.FirstWaitExit==2&&C->Quarantined&&!out.Publishable,"stopped_clock_bounded_and_quarantined");
  unsigned before=writes;need(N976nBatBackendSample(&Backend,&out)!=0&&writes==before&&!out.Publishable,"quarantine_is_sticky_across_sample");
  seed(5);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.FirstWaitExit==1&&C->Report.FirstWaitUs>=100000&&ticks<210000&&C->Quarantined&&starts==2,"100ms_deadline_unretired_no_reset");
  seed(6);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.FirstInterrupt==0x400&&!out.Publishable,"hsi_error_not_measurement");
  seed(7);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.Received==1&&C->Report.Restored&&!C->Quarantined&&!out.Publishable,"short_read_restored_not_published");
  fault=0;need(!N976nBatBackendSample(&Backend,&out)&&out.Publishable,"clean_failure_can_be_sampled_again");
  seed(8);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.Received==2&&C->Quarantined&&!out.Publishable,"extra_fifo_byte_not_read_or_accepted");
  seed(9);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Report.Received==2&&C->Report.Restored&&!out.Publishable,"exact_rx_without_done_rejected");
  seed(10);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Quarantined&&!out.Publishable,"sticky_ack_rejected");
  seed(11);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Quarantined&&!out.Publishable,"restore_mismatch_blocks_publication");
  seed(12);status=N976nBatBackendSample(&Backend,&out);need(status&&starts==1&&C->Quarantined&&!out.Publishable,"clock_drift_blocks_new_transfer_and_restore");
  seed(15);status=N976nBatBackendSample(&Backend,&out);need(!status&&C->Report.PinOutputMask==3&&C->Report.PinRestoredMask==3&&C->Report.PinDataBefore[0]==0&&C->Report.PinDataReleased[0]==1&&C->Report.PinDataRestored[0]==0,"output_low_released_and_latch_unmodified");
  seed(16);status=N976nBatBackendSample(&Backend,&out);need(status&&!starts&&C->Report.Restored&&!C->Quarantined,"pin_prepare_failure_restores_interrupt_mask");
  seed(17);status=N976nBatBackendSample(&Backend,&out);need(status&&C->Quarantined&&(out_mask&1)==0,"pad_restore_failure_does_not_enable_output");
  seed(18);status=N976nBatBackendSample(&Backend,&out);need(status&&!starts&&!writes,"unknown_irq_refused_before_mutation");
  seed(20);status=N976nBatBackendSample(&Backend,&out);need(status&&starts==2&&C->Report.FirstInterrupt==(BAT_BIT7|BAT_BIT10)&&C->Report.Restored&&!out.Publishable,"late_error_before_ack_rejected");
  seed(0);cancel_mode=1;status=N976nBatBackendSample(&Backend,&out);need(status==N976N_BAT_BUS_ABORTED&&!writes&&!out.Publishable,"pre_start_cancel_no_mutation");
  seed(5);cancel_mode=2;status=N976nBatBackendSample(&Backend,&out);need(status==N976N_BAT_BUS_TIMEOUT&&C->Report.FirstWaitExit==1&&C->Quarantined&&!out.Publishable,"active_cancel_keeps_original_deadline_unretired_quarantine");
  seed(0);N976N_BATTERY_READ bad={0x25,0,2};BAT_U8 bytes[2]={0,0};need(!Transfer(C,&bad,0,0,bytes,1)&&!writes,"reject_muic_target");
  seed(0);bad.Address=0x69;bad.Register=0xBD;bad.Bytes=1;bytes[0]=0xBD;need(!Transfer(C,&bad,0,0,bytes,2)&&!writes,"reject_charger_watchdog_write");
  seed(0);need(N976nBatBusSample(C,0,&raw)==N976N_BAT_BUS_INVALID_PARAMETER&&!writes,"invalid_id_no_mutation");
  Binding.ClockAddress[0]=0xBAD00000;need(!N976nBatBusInit(C,&Ops,NULL,&Binding)&&!writes,"unowned_clock_descriptor_rejected");
  seed(0);Binding.ClockCount=8;Binding.ClockAddress[7]=Binding.ClockAddress[0];need(!N976nBatBusInit(C,&Ops,NULL,&Binding),"duplicate_clock_descriptor_rejected");
  seed(0);C->Running=1;need(N976nBatBusSample(C,1,&raw)==N976N_BAT_BUS_BUSY&&!writes,"serialization_guard");
  seed(0);N976N_BAT_BUS_BINDING captured;N976N_BAT_BUS_REPORT captureReport;
  need(N976nBatBusCaptureBinding(&Ops,NULL,1000000,&captured,&captureReport)&&!writes&&!memcmp(&captured,&Binding,sizeof(Binding)),"capture_uses_same_resolver_exact_state_read_only");
  need(N976nBatBusValidateBinding(C)&&!writes,"validate_final_binding_read_only");
  *reg(GPIO+0x180)^=1;need(!N976nBatBusValidateBinding(C)&&!writes,"fresh_pin_drift_refused_before_any_mutation");
  seed(0);
  *reg(CMGP+0x1020)=1;*reg(CMGP+0x100)=BAT_BIT4;
  *reg(APM+0x1004)=1;*reg(APM+0x100)=BAT_BIT4;
  *reg(TOP+0x160)=BAT_BIT31|BAT_BIT29|BAT_BIT4|(200U<<16)|(13U<<8);
  need(N976nBatBusCaptureBinding(&Ops,NULL,1000000,&captured,&captureReport)&&captured.InputHz==400000000&&!writes,"capture_real_400MHz_TOP_path_preserved");
  need(N976nBatBackendInit(&Backend,&Ops,NULL,&captured,5,captured.Config)&&!N976nBatBackendSample(&Backend,&out)&&out.Publishable,"sample_400MHz_TOP_path_exact_restore");
  seed(0);Binding.ClockCount--;C->Binding=Binding;need(N976nBatBackendSample(&Backend,&out)!=0&&!writes&&!out.Publishable,"missing_clock_mapping_refused_before_mutation");
  seed(0);N976N_BAT_BACKEND second;need(N976nBatBackendInit(&second,&Ops,NULL,&Binding,0,Binding.Config),"independent_context_init_unknown_factor");
  need(!N976nBatBackendSample(&second,&out)&&out.Publishable&&out.Values.FgResistor==0&&!(out.Values.ValueValidMask&N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT))&&Backend.Sequence==0,"per_device_state_no_cross_contamination");
  seed(0);Binding.ClockReserved=1;need(!N976nBatBusInit(C,&Ops,NULL,&Binding),"reserved_binding_field_refused");
  seed(0);Binding.ClockAddress[Binding.ClockCount]=CMGP+0x100;need(!N976nBatBusInit(C,&Ops,NULL,&Binding),"unused_clock_slot_must_be_zero");
  printf("PASS %u cases\n",tests);return 0;
}
