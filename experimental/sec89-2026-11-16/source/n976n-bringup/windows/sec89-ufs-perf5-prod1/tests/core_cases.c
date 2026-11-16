/* Independent fake HCI: executes the actual production core and lease parser. */
#include "N976nUfsLease.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>
typedef struct {NUF_ENGINE E;NUF_REPORT R;_Alignas(8) U8 D[NUF_DMA_BYTES+4],Base[65536],Media[65536];U32 Reg[0x2004/4];U64 Clock;
 U32 AckWrites,Fault,Writes,Submits,Forbidden,StopWrites,ClockCalls,PauseCalls,Runtime,Lba,Tag,ListWrites,CorruptOffset;U64 CompleteAt;
 U32 SleepCalls,ClockStep,StallCalls,StallMaxUs,SleepExtra,SleepFault,StallFault;U8 IssueFirst,IssueLast;int Owned;} MODEL;
static MODEL M;
static void be(U8 *p,U32 x){p[0]=(U8)(x>>24);p[1]=(U8)(x>>16);p[2]=(U8)(x>>8);p[3]=(U8)x;}
static U32 little(const U8 *p){return (U32)p[0]|((U32)p[1]<<8)|((U32)p[2]<<16)|((U32)p[3]<<24);}
static U32 readreg(void *p,U32 o){MODEL*m=p;assert(o<=NUF_COH&&o%4==0);if(o==0x58&&m->CompleteAt&&m->Clock>=m->CompleteAt)m->Reg[o/4]=0;return m->Reg[o/4];}
static void writereg(void *p,U32 o,U32 x){MODEL*m=p;m->Writes++;
 assert(o==0x20||o==0x50||o==0x54||o==0x58||o==0x60||o==0x1140);
 if(o==0x20){m->AckWrites++;if(m->Fault!=5)m->Reg[o/4]&=~x;return;}
 m->Reg[o/4]=x;if(o==0x50||o==0x54)m->ListWrites++;
 if(o==0x60&&x==0){m->StopWrites++;if(m->Fault==10)m->Reg[o/4]=1;}
 if(o==0x60&&x==1&&m->Fault==19)m->Reg[o/4]=0;
 if(o!=0x58)return;
 assert(x==1);m->Submits++;U8*t=(U8*)m->E.Dma+4096,*c=(U8*)m->E.Dma+12288,*r=c+1024,*data=(U8*)m->E.Dma+20480;
 assert(t[8]==15); /* Every reuse must reset the controller-owned OCS byte. */
 int write=c[16]==0x2A,flush=c[16]==0x35;
 assert(little(t)==(write?0x13000000U:flush?0x11000000U:0x15000000U)&&little(t+16)==m->E.Config.DmaBase+12288&&little(t+20)==0);
 U32 bytes=((U32)c[12]<<24)|((U32)c[13]<<16)|((U32)c[14]<<8)|c[15];
 U32 blocks=((U32)c[23]<<8)|c[24],entries=(bytes+4095)/4096;
 assert(little(t+24)==0x04000400&&little(t+28)==(0x08000000U|(entries?(entries+1)*16:0)));
 assert(entries<=16);
 for(U32 n=0;n<entries;n++){
  U8 *prd=c+2048+n*16;
  assert(little(prd)==m->E.Config.DmaBase+20480+n*4096&&little(prd+4)==0&&little(prd+8)==0&&little(prd+12)==4095);
 }
 for(U32 n=entries*16;n<2048;n++)assert(c[2048+n]==0);
 assert(c[0]==1&&c[1]==(write?0x21:flush?1:0x41)&&c[2]==0&&c[3]==(m->Runtime?m->Tag:m->Submits));
 assert((c[16]==0x25&&m->Submits==1&&bytes==8&&blocks==0)||
  ((c[16]==0x28||write)&&(m->Submits==2||m->Runtime)&&bytes==blocks*4096&&blocks>=1&&blocks<=16)||
  (flush&&bytes==0&&blocks==0));
 assert(c[18]==(U8)(m->Lba>>24)&&c[19]==(U8)(m->Lba>>16)&&c[20]==(U8)(m->Lba>>8)&&c[21]==(U8)m->Lba&&c[22]==0);
 m->IssueFirst=data[0];m->IssueLast=data[65535];
 for(U32 i=0;i<52;i++)assert(r[i]==0);
 if(m->Fault==1||m->Fault==8||m->Fault==9)return;
 if(m->Fault==21){t[8]=0;m->Reg[0x58/4]=0;m->Reg[0x20/4]=1;return;}
 t[8]=0;r[0]=0x21;r[2]=0;r[3]=c[3];m->Reg[0x58/4]=0;m->Reg[0x20/4]=1;
 if(c[16]==0x25){be(data,(U32)m->E.Config.LastLba);be(data+4,4096);}
 else for(U32 n=0;n<entries;n++){
  U32 off=little(c+2048+n*16)-(U32)m->E.Config.DmaBase;
  assert(off>=20480&&off+4096<=21*4096);
  if(write)memcpy(m->Media+n*4096,(U8*)m->E.Dma+off,4096);
  else if(!flush)memcpy((U8*)m->E.Dma+off,m->Base+n*4096,4096);
 }
 if(m->Fault==2)m->D[0]^=1;if(m->Fault==3)r[3]^=7;if(m->Fault==4)t[8]=4;
 if(m->Fault==6&&c[16]==0x28)data[101]^=1;if(m->Fault==7&&c[16]==0x25)data[0]^=1;
 if(m->Fault==11)m->Reg[0x20/4]|=1U<<11;if(m->Fault==12)r[15]=1;
 if(m->Fault==13)m->Reg[0x1104/4]^=1;if(m->Fault==14)m->Owned=0;
 if(m->Fault==15)m->Reg[0x20/4]=0;if(m->Fault==16)c[2048]^=1;
 if(m->Fault==17)r[7]=2;if(m->Fault==18)r[32]=1;
 if(m->Fault==20)m->D[m->CorruptOffset]^=0x81;
 if(m->CompleteAt)m->Reg[0x58/4]=1;
}
static U64 clockus(void *p){MODEL*m=p;m->ClockCalls++;if(m->Fault==8&&m->Submits)return m->Clock;
 if(m->Fault==9&&m->Submits)return --m->Clock;return m->Clock+=m->ClockStep;}
static void pausefn(void*p){((MODEL*)p)->PauseCalls++;}static void fence(void*p){(void)p;}
static void sleepfn(void*p,U32 us){MODEL*m=p;assert(us&&us<=1000);m->SleepCalls++;m->Clock+=us+m->SleepExtra;
 if(m->SleepFault==1)m->Owned=0;if(m->SleepFault==2)m->Reg[0x20/4]|=NUF_FATAL_IS;
 if(m->SleepFault==3)m->Clock-=us+m->SleepExtra+m->ClockStep+1;
}
static void stallfn(void*p,U32 us){MODEL*m=p;assert(us&&us<=NUF_READ_POLL_STEP_US&&us<1000);
 m->StallCalls++;if(us>m->StallMaxUs)m->StallMaxUs=us;m->Clock+=us;
 if(m->StallFault==1)m->Owned=0;if(m->StallFault==2)m->Reg[0x20/4]|=NUF_FATAL_IS;
 if(m->StallFault==3)m->Clock-=us+m->ClockStep+1;
}
static U64 perfclock(void*p){return ((MODEL*)p)->Clock;}
static int owner(void*p){return ((MODEL*)p)->Owned;}
static void setup(U32 fault){memset(&M,0,sizeof(M));M.Fault=fault;M.Owned=1;M.ClockStep=100;
 for(U32 i=0;i<65536;i++)M.Base[i]=(U8)(i*13+7+(i/4096)*11);
 NUF_CONFIG*c=&M.E.Config;c->DmaBase=0x93000000;c->OldTrlBase=0x93101000;c->LastLba=0x123456;c->BlockBytes=4096;
 c->Cap=0x1303FF1F;c->Version=0x300;c->Hcs=0x10F;c->Tx=c->Rx=12;c->Reorder=10;c->Nexus=~0U;c->Axi=0x18000003;c->Coherency=0x11;
 c->Baseline=M.Base;M.E.Dma=M.D;M.E.Report=&M.R;M.E.Ops=(NUF_OPS){&M,readreg,writereg,clockus,pausefn,fence,owner,sleepfn,stallfn};
 M.Reg[0]=c->Cap;M.Reg[2]=c->Version;M.Reg[0x34/4]=1;M.Reg[0x30/4]=0x10F;M.Reg[0x50/4]=(U32)c->OldTrlBase;
 M.Reg[0x1100/4]=M.Reg[0x1104/4]=12;M.Reg[0x1160/4]=10;M.Reg[0x1140/4]=~0U;M.Reg[0x116c/4]=c->Axi;M.Reg[NUF_COH/4]=0x11;}
static void pass(const char*s){puts(s);}
static U8 LeasePage[8192];
static void runtime(void){M.Runtime=1;M.Lba=13;M.Tag=37;}

static void perf2_wait_cases(void){
 U8 data[65536];NUF_WAIT_SAMPLE fast,control;
 for(U32 size=4096;size<=65536;size*=16){
  for(U32 old=0;old<2;old++){
   setup(0);runtime();assert(NufSessionOpen(&M.E));M.ClockStep=1;
   M.E.PerfClock=perfclock;M.E.ControlWaitLegacy=old;M.CompleteAt=M.Clock+500;M.SleepExtra=5000;
   assert(NufReadBlock(&M.E,M.Lba,M.Tag,data,size)&&NufRequestRetired(&M.E)&&!memcmp(data,M.Base,size));
   NUF_WAIT_SAMPLE *w=&M.E.PerfWait[0];assert(w->Completed&&w->ClearUs>=w->LastPendingUs&&M.R.Issued==1&&M.R.Acknowledged==1);
   if(!old){fast=*w;assert(!w->SleepCalls&&!w->DoneAfterWake&&M.StallCalls&&M.StallMaxUs<=10&&w->StallCalls==M.StallCalls);
    assert(w->ClearUs-w->StartUs<NUF_READ_POLL_WINDOW_US&&w->WindowUs==1000&&w->StallRequestedUs<1000);
   }else{control=*w;assert(w->SleepCalls==1&&w->SleepRequestedUs==1000&&w->SleepElapsedUs==6001&&w->MaxSleepUs==6001);
    assert(w->DoneAfterWake&&!M.StallCalls&&w->WindowUs==100&&w->FirstSleepUs==w->LastSleepUs&&w->LastWakeUs==w->ClearUs);
    assert(w->SleepBuckets[6]==1&&w->ClearUs-w->StartUs>fast.ClearUs-fast.StartUs+5000);
   }
  }
 }
 (void)control;
 pass("perf2_actual_core_short_read_window_avoids_quantized_sleep_at_4k_and_64k_without_extra_dma");
 setup(0);runtime();assert(NufSessionOpen(&M.E));M.ClockStep=1;M.E.PerfClock=perfclock;M.CompleteAt=M.Clock+2500;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,data,4096)&&NufRequestRetired(&M.E));
 NUF_WAIT_SAMPLE *w=&M.E.PerfWait[0];assert(w->SleepCalls==2&&M.SleepCalls==2&&w->SleepRequestedUs==2000&&w->SleepElapsedUs==2002);
 assert(w->FirstSleepUs-w->StartUs>=1000&&w->StallRequestedUs<=1000&&w->DoneAfterWake&&w->LastPendingUs<w->LastWakeUs);
 pass("perf2_longer_read_reverts_to_passive_wait_and_records_actual_sleep_and_completion_interval");
 for(U32 fault=1;fault<=3;fault++){
  setup(0);runtime();assert(NufSessionOpen(&M.E));M.ClockStep=1;M.E.PerfClock=perfclock;
  M.CompleteAt=M.Clock+100000;M.SleepFault=fault;memset(data,0xEA,4096);
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,data,4096)&&M.E.Quarantined&&!M.R.Acknowledged&&!NufRequestRetired(&M.E));
  assert(M.R.Reason==(fault==1?NufOwnership:fault==2?NufResponse:NufClock));
  for(U32 i=0;i<4096;i++)assert(data[i]==0xEA);
 }
 pass("perf2_sleep_return_ownership_fatal_and_clock_regression_fail_closed_without_publication");
 setup(0);runtime();assert(NufSessionOpen(&M.E));M.ClockStep=1;M.E.PerfClock=perfclock;
 M.E.Ops.StallUs=NULL;M.CompleteAt=M.Clock+500;assert(NufReadBlock(&M.E,M.Lba,M.Tag,data,4096));
 assert(M.E.PerfWait[0].WindowUs==100&&M.E.PerfWait[0].SleepCalls==1&&!M.StallCalls);
 pass("perf2_missing_stall_callback_keeps_legacy_window_without_unbounded_busy_poll");
 setup(0);runtime();assert(NufSessionOpen(&M.E));M.ClockStep=1;M.E.PerfClock=perfclock;
 M.CompleteAt=M.Clock+1000000;assert(!NufReadBlock(&M.E,M.Lba,M.Tag,data,4096));
 assert(M.R.Reason==NufTimeout&&M.E.Quarantined&&M.E.WaitTimeouts==1&&M.R.WaitUs>=NUF_READ_WAIT_US&&M.R.WaitUs<NUF_READ_WAIT_US+1010);
 assert(M.E.PerfWait[0].StallRequestedUs<=NUF_READ_POLL_WINDOW_US&&M.E.PerfWait[0].SleepCalls>1&&!M.R.Acknowledged);
 pass("perf2_fast_window_does_not_extend_read_deadline_or_replay_timed_out_request");
}

static void write_setup(void){
 setup(0);runtime();M.Lba=NUF_WRITE_REGION_FIRST;
 M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
 M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;
 M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;M.E.Config.WriteEnabled=1;
 assert(NufSessionOpen(&M.E));M.ClockStep=1;
}
static int write_or_flush(U32 bytes,U8 *data){
 if(!bytes){M.Lba=0;return NufFlushCache(&M.E,M.Tag);}
 return NufWriteBlock(&M.E,M.Lba,M.Tag,data,bytes);
}
static void perf4_wait_cases(void){
 U8 data[65536]={0};const U32 sizes[]={4096,65536,0};
 for(U32 i=0;i<3;i++)for(U32 old=0;old<2;old++)for(U32 sampled=0;sampled<2;sampled++){
  write_setup();M.E.PerfClock=sampled?perfclock:NULL;M.E.ControlWaitLegacy=old;M.CompleteAt=M.Clock+500;M.SleepExtra=5000;
  assert(write_or_flush(sizes[i],data)&&NufRequestRetired(&M.E)&&M.R.Issued==1&&M.R.Acknowledged==1);
  if(old)assert(M.SleepCalls==1&&!M.StallCalls&&M.R.WaitUs>6000);
  else assert(!M.SleepCalls&&M.StallCalls&&M.StallMaxUs<=10&&M.R.WaitUs<1000);
  if(sampled)assert(M.E.PerfWait[0].WindowUs==(old?100U:1000U)&&M.E.PerfWait[0].Completed);
 }
 pass("perf4_write4k_64k_flush_short_completion_and_unsampled_policy_preserve_real_commands");
 for(U32 i=0;i<3;i++){
  write_setup();M.E.PerfClock=perfclock;M.CompleteAt=M.Clock+2500;
  assert(write_or_flush(sizes[i],data)&&M.SleepCalls==2&&M.E.PerfWait[0].FirstSleepUs-M.E.PerfWait[0].StartUs>=1000);
  assert(M.E.PerfWait[0].StallRequestedUs<=1000&&M.E.PerfWait[0].DoneAfterWake);
 }
 pass("perf4_write_flush_after_one_ms_yield_and_record_observation");
 for(U32 i=0;i<3;i++)for(U32 fault=1;fault<=3;fault++)for(U32 stall=0;stall<2;stall++){
  write_setup();M.E.PerfClock=perfclock;M.CompleteAt=M.Clock+100000;
  if(stall)M.StallFault=fault;else M.SleepFault=fault;
  assert(!write_or_flush(sizes[i],data)&&M.E.Quarantined&&!M.R.Acknowledged&&!NufRequestRetired(&M.E));
  assert(M.R.Reason==(fault==1?NufOwnership:fault==2?NufResponse:NufClock));
 }
 pass("perf4_write_flush_stall_and_wake_ownership_fatal_clock_fail_closed");
 for(U32 i=0;i<3;i++){
  write_setup();M.E.Ops.StallUs=NULL;M.E.PerfClock=perfclock;M.CompleteAt=M.Clock+500;
  assert(write_or_flush(sizes[i],data)&&M.SleepCalls==1&&!M.StallCalls&&M.E.PerfWait[0].WindowUs==100);
 }
 pass("perf4_write_flush_missing_stall_keeps_legacy_bounded_fallback");
}

static void wait_policy_cases(void){
 U8 data[4096]={0};
 for(U32 op=0;op<3;op++){
  setup(0);runtime();M.Lba=NUF_WRITE_REGION_FIRST;
  M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
  M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;
  M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;M.E.Config.WriteEnabled=1;
  assert(NufSessionOpen(&M.E));M.CompleteAt=M.Clock+1000000;if(op==2)M.Lba=0;
  int ok=op==0?NufReadBlock(&M.E,M.Lba,M.Tag,data,4096):op==1?NufWriteBlock(&M.E,M.Lba,M.Tag,data,4096):NufFlushCache(&M.E,M.Tag);
  if(!op)assert(!ok&&M.R.Reason==NufTimeout&&M.R.Quarantined&&M.E.WaitTimeouts==1&&M.R.WaitUs>=NUF_READ_WAIT_US);
  else assert(ok&&NufRequestRetired(&M.E)&&M.E.MaxWaitUs[op+1]>=999000&&!M.E.WaitTimeouts);
  assert(M.SleepCalls&&M.SleepCalls==M.E.WaitSleeps);
 }
 pass("command_specific_read_write_flush_budgets_and_passive_yield");
 for(U32 op=0;op<2;op++)for(U32 fault=0;fault<3;fault++){
  setup(0);runtime();M.Lba=NUF_WRITE_REGION_FIRST;
  M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
  M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;
  M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;M.E.Config.WriteEnabled=1;
  assert(NufSessionOpen(&M.E));M.Fault=fault==0?1:fault==1?8:9;if(op)M.Lba=0;
  assert(!(op?NufFlushCache(&M.E,M.Tag):NufWriteBlock(&M.E,M.Lba,M.Tag,data,4096)));
  assert(M.R.Quarantined&&!M.R.Acknowledged&&!NufRequestRetired(&M.E));
  if(fault)assert(M.R.Reason==NufClock&&!M.SleepCalls);
  else assert(M.R.Reason==NufTimeout&&M.R.WaitUs>=(op?NUF_FLUSH_WAIT_US:NUF_WRITE_WAIT_US));
 }
 pass("write_flush_deadlines_and_stopped_backward_clock_preserve_quarantine");
 setup(0);runtime();assert(NufSessionOpen(&M.E)&&NufReadBlock(&M.E,M.Lba,M.Tag,data,4096));
 assert(!M.SleepCalls);assert(NufSessionStop(&M.E)&&NufSessionRestart(&M.E)&&!M.SleepCalls);
 pass("immediate_completion_and_dirql_stop_restart_never_sleep");
}
static void session_cases(void){
 U8 out[4097],payload[4097];U32 clocks,pauses,writes,submits;U64 reset;
 setup(0);assert(NufSessionOpen(&M.E));assert(NufRun(&M.E));
 assert(M.E.SessionActive&&!M.R.Retired&&NufRequestRetired(&M.E)&&M.R.CapacityChecked&&M.R.Compared);
 runtime();for(U32 n=0;n<16;n++){memset(&M.R,0,sizeof(M.R));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
  assert(NufRequestRetired(&M.E)&&!M.R.Retired&&M.E.SessionActive&&!memcmp(out,M.Base,4096));}
 assert(M.E.DmaInitBytes==NUF_DMA_BYTES&&M.E.ListPrograms==1&&M.ListWrites==2&&M.StopWrites==0);
 assert(M.E.RequestResetBytes==1208ULL); /* 140+92+76+15*60 independently counted stores */
 assert(M.E.GuardReadOps*3<M.E.GuardCheckBytes&&M.Submits==18);
 /* Expanded arena: small reads retain a checked inactive payload tail.
  * Assert the actual NC scan cost; this is not a hardware timing result. */
 assert(M.E.GuardCheckBytes==90112ULL+35ULL*84991ULL);
 assert(M.E.GuardCheckBytes+18ULL*90112ULL==4686813ULL);
 assert(NufSessionClose(&M.E)&&M.R.Retired&&!M.E.SessionActive&&M.E.Closed&&M.ListWrites==4&&M.StopWrites==1);
 pass("persistent_admission_and_16_reads_initialize_once_keep_list_until_close");
 pass("expanded_arena_exact_scan_coverage_with_reduced_prepare_stores");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 clocks=M.ClockCalls;pauses=M.PauseCalls;reset=M.E.RequestResetBytes;
 assert(NufSessionStop(&M.E)&&M.E.Stopped&&M.R.Retired&&!M.E.SessionActive);
 assert(NufSessionRestart(&M.E)&&M.E.SessionActive&&!M.R.Retired&&!M.E.Stopped);
 assert(M.ClockCalls==clocks&&M.PauseCalls==pauses&&M.E.DmaInitBytes==NUF_DMA_BYTES&&M.E.RequestResetBytes==reset);
 assert(M.E.SessionStops==1&&M.E.SessionRestarts==1&&M.E.ListPrograms==2);
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&NufSessionClose(&M.E));
 pass("stop_restart_no_clock_pause_or_dma_initialization");
 const U32 ranges[][2]={{0,4096},{4096,8},{4105,23},{4128,4064},{8192,4096},{12288,32},{12320,992},{14336,272},{14608,1776},{16384,4096},{24576,61440},{86016,4096}};
 for(U32 n=0;n<sizeof(ranges)/sizeof(ranges[0]);n++)for(U32 k=0;k<10;k++){
  U32 off=ranges[n][0]+(k<8?k:k==8?ranges[n][1]/2:ranges[n][1]-1);
  setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
  U8 expected=M.D[off];M.D[off]^=0x81;reset=M.E.RequestResetBytes;writes=M.Writes;submits=M.Submits;
  memset(&M.R,0,sizeof(M.R));memset(out,0xEA,4096);
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&M.R.FirstReason==NufGuard&&M.E.Quarantined);
  assert(M.R.GuardOffset==off&&M.R.GuardExpected==expected&&M.R.GuardActual==(U8)(expected^0x81));
  assert(M.Submits==submits&&M.Writes==writes&&M.E.RequestResetBytes==reset);
  for(U32 i=0;i<4096;i++)assert(out[i]==0xEA);
  memset(&M.R,0,sizeof(M.R));assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&M.E.Quarantined&&M.Submits==submits);
 }pass("every_immutable_region_and_word_lane_checked_before_reset_report_clear_cannot_hide_fault");
 for(U32 n=0;n<sizeof(ranges)/sizeof(ranges[0]);n++)for(U32 k=0;k<10;k++){
  U32 off=ranges[n][0]+(k<8?k:k==8?ranges[n][1]/2:ranges[n][1]-1);
  setup(20);runtime();M.CorruptOffset=off;memset(out,0xEA,4096);
  assert(NufSessionOpen(&M.E));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&M.R.FirstReason==NufGuard&&M.E.Quarantined);
  assert(M.Submits==1&&M.R.Acknowledged==0&&M.R.GuardOffset==off&&!M.E.RequestRetired);
  for(U32 i=0;i<4096;i++)assert(out[i]==0xEA);
 }pass("every_immutable_region_after_dma_checked_before_ack_or_output_publication");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 M.D[24576+20]^=1;writes=M.Writes;assert(!NufSessionStop(&M.E)&&M.Writes==writes&&M.E.Quarantined&&!M.R.Retired);
 pass("stop_rechecks_all_guards_before_any_controller_write");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 assert(NufSessionStop(&M.E));M.D[12320+11]^=1;writes=M.Writes;assert(!NufSessionRestart(&M.E)&&M.E.Quarantined&&M.Writes==writes);
 pass("restart_rejects_corruption_without_erasing_arena");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 M.Fault=10;clocks=M.ClockCalls;assert(!NufSessionStop(&M.E)&&M.E.Quarantined&&!M.R.Retired&&M.Reg[0x50/4]==M.E.Config.DmaBase+4096&&M.ClockCalls==clocks);
 pass("immediate_stop_failure_quarantines_without_wait_or_list_restore");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 assert(NufSessionStop(&M.E));M.Fault=19;clocks=M.ClockCalls;assert(!NufSessionRestart(&M.E)&&M.E.Quarantined&&!M.R.Retired&&M.ClockCalls==clocks);
 pass("immediate_restart_failure_quarantines_without_wait");
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
 assert(NufSessionStop(&M.E));M.Reg[0x50/4]^=4096;writes=M.Writes;clocks=M.ClockCalls;
 assert(!NufSessionRestart(&M.E)&&M.E.Quarantined&&!M.R.Retired&&M.Writes==writes&&M.ClockCalls==clocks);
 memset(&M.R,0,sizeof(M.R));assert(!NufSessionClose(&M.E)&&M.E.Quarantined&&!M.R.Retired&&M.Writes==writes);
 pass("restart_controller_drift_quarantines_before_writes");
 setup(0);runtime();assert(NufSessionOpen(&M.E));M.Fault=5;
 assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&M.E.Quarantined);writes=M.Writes;reset=M.E.RequestResetBytes;
 memset(&M.R,0,sizeof(M.R));M.Fault=0;
 assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out,4096)&&M.Writes==writes&&M.E.RequestResetBytes==reset&&!NufRequestRetired(&M.E));
 pass("cleared_report_cannot_reuse_unacknowledged_quarantined_slot");
 for(U32 f=0;f<3;f++){
  setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,4096));
  if(f==0)M.Reg[0x58/4]=1;else if(f==1)M.Reg[0x20/4]=1;else M.Owned=0;
  writes=M.Writes;clocks=M.ClockCalls;assert(!NufSessionStop(&M.E)&&M.E.Quarantined&&M.Writes==writes&&M.ClockCalls==clocks);
 }pass("stop_refuses_pending_doorbell_ack_or_lost_ownership_without_writes");
 setup(0);runtime();assert(NufSessionOpen(&M.E));writes=M.Writes;
 assert(!NufSessionOpen(&M.E)&&M.Writes==writes&&M.E.DmaInitBytes==NUF_DMA_BYTES);
 assert(NufSessionClose(&M.E));memset(&M.R,0,sizeof(M.R));writes=M.Writes;
 assert(!NufSessionOpen(&M.E)&&!NufSessionRestart(&M.E)&&M.Writes==writes&&M.E.DmaInitBytes==NUF_DMA_BYTES);
 pass("duplicate_open_and_terminal_close_replay_never_reinitialize");
 for(U32 align=0;align<4;align++){
  setup(0);runtime();M.E.Dma=M.D+align;M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
  M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;M.E.Config.WriteEnabled=1;
  M.Lba=(U32)NUF_WRITE_REGION_FIRST;for(U32 i=0;i<4096;i++)payload[i+1]=(U8)(i*7+align);
  assert(NufSessionOpen(&M.E)&&NufWriteBlock(&M.E,M.Lba,M.Tag,payload+1,4096));
  assert(!memcmp(M.Media,payload+1,4096)&&NufRequestRetired(&M.E));
  M.Lba=0;assert(NufFlushCache(&M.E,M.Tag));
  M.Lba=13;assert(NufReadBlock(&M.E,M.Lba,M.Tag,out+1,4096)&&!memcmp(out+1,M.Base,4096));
  assert(NufSessionClose(&M.E));
 }pass("aligned_word_access_byte_prologue_tail_and_unaligned_cpu_buffers");
 setup(0);runtime();M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
 M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;M.E.Config.WriteEnabled=1;M.Lba=(U32)NUF_WRITE_REGION_FIRST;
 assert(NufSessionOpen(&M.E)&&NufWriteBlock(&M.E,M.Lba,M.Tag,payload+1,4096));
 M.D[20480+4095]^=1;writes=M.Writes;assert(!NufSessionClose(&M.E)&&M.E.Quarantined&&M.Writes==writes&&M.R.GuardOffset==20480+4095);
 pass("data_out_page_remains_immutable_until_session_close");
 setup(0);runtime();M.Lba=0;assert(NufSessionOpen(&M.E)&&NufFlushCache(&M.E,M.Tag));
 M.D[20480+55]^=1;writes=M.Writes;assert(!NufSessionStop(&M.E)&&M.Writes==writes&&M.R.GuardOffset==20480+55);
 pass("no_data_page_remains_immutable_at_stop");
 setup(0);NUF_CONFIG c=M.E.Config;c.LastLba=0x3B94A04;c.WriteEnabled=1;
 c.WriteFirst=0x222200;c.WriteBlocks=0x1000000;c.SystemWriteFirst=0x17A00;c.SystemWriteBlocks=0x40000;
 const U64 good[]={0x17A00,0x579FF,0x222200,0x12221FF};
 const U64 bad[]={0,1,0x179FF,0x57A00,0x199DFF,0x2221FF,0x1222200,0x3B94A04,0x100017A00ULL};
 for(U32 n=0;n<sizeof(good)/sizeof(*good);n++)assert(NufWriteRangeAllowed(&c,good[n],4096));
 for(U32 n=0;n<sizeof(bad)/sizeof(*bad);n++)assert(!NufWriteRangeAllowed(&c,bad[n],4096));
 assert(NufWriteRangeAllowed(&c,0x17A00,8192)&&!NufWriteRangeAllowed(&c,0x17A00,4095));
 for(U32 f=0;f<7;f++){NUF_CONFIG wrong=c;
  if(f==0)wrong.WriteEnabled=0;if(f==1)wrong.SystemWriteFirst++;if(f==2)wrong.SystemWriteBlocks++;
  if(f==3)wrong.WriteFirst++;if(f==4)wrong.WriteBlocks++;if(f==5)wrong.Lun=1;if(f==6)wrong.LastLba=0x579FE;
  assert(!NufWriteRangeAllowed(&wrong,0x17A00,4096)&&!NufWriteRangeAllowed(&wrong,0x222200,4096));
 }pass("dual_physical_fences_require_exact_admitted_extents_and_refuse_neighbors_wrap_or_configuration_drift");
}
static N976N_UFS_HANDOFF *lease(void){memset(LeasePage,0,sizeof(LeasePage));N976N_UFS_HANDOFF*h=(void*)LeasePage;
 h->Magic=N976N_UFS_HANDOFF_MAGIC;h->Version=2;h->Bytes=336;h->ImmutableBytes=320;h->ProducerStage=3;
 h->ProducerChecks=0x7F;h->Flags=7;h->PowerRaw=0x11;h->Guard=N976N_UFS_HANDOFF_GUARD;h->BootCounter=1;h->CounterHz=26000000;
 h->LeaseBase=0x93200000;h->LeaseBytes=8192;h->DmaBase=0x93000000;h->DmaBytes=NUF_DMA_BYTES;
 h->FirmwareDmaBase=0x93100000;h->FirmwareDmaBytes=NUF_FIRMWARE_DMA_BYTES;
 h->HciBase=0x13D60000;h->HciBytes=8192;h->VendorOffset=0x1100;h->CoherencyBase=0x13C10000;
 h->CoherencyOffset=0x700;h->CoherencyBytes=4096;h->BaselineOffset=4096;h->BaselineBytes=4096;
 h->LastLba=0x123456;h->BlockBytes=4096;h->Hce=1;h->Hcs=0x10F;h->TrlBase=0x93101000;
 h->TxPrdt=h->RxPrdt=12;h->Reorder=10;h->Coherency=0x11;
 memcpy(LeasePage+4088,&h->Guard,8);h->BaselineCrc32=NufCrc32(LeasePage+4096,4096);h->Crc32=NufLeaseCrc(h);return h;}
static void batch_cases(void){
 static U8 out[65536+2],payload[65536];
 const U32 lengths[]={4096,8192,65536,4096,65536};
 U64 singleScans,batchScans,singleReset,batchReset;
 for(U32 n=0;n<65536;n++)payload[n]=(U8)(n*7+(n/4096)*19);
 setup(0);runtime();assert(NufSessionOpen(&M.E));
 for(U32 n=0;n<5;n++){
  memset(out,0xEA,sizeof(out));assert(NufReadBlock(&M.E,M.Lba,M.Tag,out+1,lengths[n]));
  assert(!memcmp(out+1,M.Base,lengths[n])&&out[0]==0xEA&&out[lengths[n]+1]==0xEA);
  assert(NufRequestRetired(&M.E)&&M.R.Acknowledged==n+1);
 }assert(NufSessionClose(&M.E));
 pass("read_1_2_16_blocks_and_large_small_large_exact_prdt_payload_and_output_canaries");
 setup(0);runtime();M.E.Config.LastLba=NUF_WRITE_REGION_FIRST+NUF_WRITE_REGION_BLOCKS;
 M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;
 M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;M.E.Config.WriteEnabled=1;
 assert(NufSessionOpen(&M.E));
 for(U32 n=0;n<5;n++){
  M.Lba=NUF_WRITE_REGION_FIRST;assert(NufWriteBlock(&M.E,M.Lba,M.Tag,payload,lengths[n]));
  assert(!memcmp(M.Media,payload,lengths[n])&&NufRequestRetired(&M.E));
  M.Lba=13;assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,lengths[n]));
  M.Lba=0;assert(NufFlushCache(&M.E,M.Tag));
 }assert(NufSessionClose(&M.E));
 pass("multi_block_write_read_flush_transitions_reset_prior_tail_without_erasing_corruption");
 for(U32 bytes=0;bytes<=17*4096;bytes+=4096){
  int good=bytes>=4096&&bytes<=65536;
  assert(NufReadCommandAllowed(0x28,0,bytes,13,2)==good);
 }
 assert(!NufReadCommandAllowed(0x28,0,65535,13,2));
 assert(NufReadCommandAllowed(0x28,0,65536,0xFFFFFFF0ULL,2));
 assert(!NufReadCommandAllowed(0x28,0,65536,0xFFFFFFF1ULL,2));
 for(U32 n=0;n<2;n++){
  setup(0);runtime();M.Lba=(U32)M.E.Config.LastLba-15+n;
  assert(NufReadBlock(&M.E,M.Lba,M.Tag,out,65536)==!n);
  if(n)assert(!M.Submits&&!M.Writes);
 }
 NUF_CONFIG c=M.E.Config;c.LastLba=0x3B94A04;c.WriteEnabled=1;c.WriteFirst=0x222200;c.WriteBlocks=0x1000000;
 c.SystemWriteFirst=0x17A00;c.SystemWriteBlocks=0x40000;
 assert(NufWriteRangeAllowed(&c,0x579F0,65536)&&!NufWriteRangeAllowed(&c,0x579F1,65536));
 assert(NufWriteRangeAllowed(&c,0x12221F0,65536)&&!NufWriteRangeAllowed(&c,0x12221F1,65536));
 pass("multi_block_zero_17_unaligned_wrap_and_exact_physical_write_end_fences");
 const U32 faults[]={1,2,3,4,5,8,9,10,11,12,13,14,15,16,17,18};
 for(U32 n=0;n<sizeof(faults)/sizeof(*faults);n++){
  setup(faults[n]);runtime();memset(out,0xEA,sizeof(out));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out+1,65536));
  for(U32 i=0;i<sizeof(out);i++)assert(out[i]==0xEA);
 }pass("full_64k_fault_matrix_never_publishes_failed_buffer");
 const U32 offsets[]={14336+256,14336+271,14336+272,16383,86016,90111};
 for(U32 n=0;n<sizeof(offsets)/sizeof(*offsets);n++){
  setup(20);runtime();M.CorruptOffset=offsets[n];memset(out,0xEA,sizeof(out));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,out+1,65536)&&M.R.Reason==NufGuard&&!M.R.Acknowledged);
  for(U32 i=0;i<sizeof(out);i++)assert(out[i]==0xEA);
 }pass("full_prdt_zero_suffix_padding_and_final_guard_checked_before_ack");
 setup(0);runtime();assert(NufSessionOpen(&M.E));
 for(U32 n=0;n<16;n++)assert(NufReadBlock(&M.E,M.Lba,M.Tag,out+n*4096,4096));
 singleScans=M.E.GuardCheckBytes;singleReset=M.E.RequestResetBytes;
 assert(M.Submits==16&&M.R.Acknowledged==16);
 setup(0);runtime();assert(NufSessionOpen(&M.E)&&NufReadBlock(&M.E,M.Lba,M.Tag,out,65536));
 batchScans=M.E.GuardCheckBytes;batchReset=M.E.RequestResetBytes;
 assert(M.Submits==1&&M.R.Acknowledged==1&&batchScans<singleScans&&batchReset<singleReset);
 assert(singleScans==2724833&&batchScans==113663&&singleReset==1048&&batchReset==388);
 pass("64k_batch_reduces_16_commands_ack_and_nc_scans_with_exact_bounded_reset_counts");
 for(U32 n=0;n<4;n++){
  N976N_UFS_HANDOFF *h=lease();
  if(n==0)h->Version=1;if(n==1)h->DmaBytes=28672;if(n==2)h->FirmwareDmaBytes=90112;
  if(n==3){h->DmaBytes=28672;h->FirmwareDmaBytes=90112;}
  h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));
 }
 assert(!NufResourceAllowed(3,0x93000000,28672,1));
 pass("handoff_v2_22page_windows_7page_firmware_rejects_old_version_length_swap_and_old_acpi");
}

static void perf5_prepare_cases(void){
 U8 output[65536];U64 stored,guards;U32 issued;
 setup(0);runtime();assert(NufSessionOpen(&M.E));
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,65536));
 assert(M.IssueFirst==0xCC&&M.IssueLast==0xCC&&M.E.RequestResetBytes==388);
 stored=M.E.RequestResetBytes;guards=M.E.GuardCheckBytes;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,65536));
 assert(M.IssueFirst==M.Base[0]&&M.IssueLast==M.Base[65535]);
 assert(M.E.RequestResetBytes-stored==60&&M.E.GuardCheckBytes>guards&&!memcmp(output,M.Base,65536));
 stored=M.E.RequestResetBytes;M.Tag++;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,65536)&&M.E.RequestResetBytes-stored==68);
 stored=M.E.RequestResetBytes;M.Tag++;M.Lba++;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,65536)&&M.E.RequestResetBytes-stored==76);
 pass("perf5_read_destination_not_rewritten_full_guards_and_complete_output_retained");
 /* Transition to small READ must restore all newly inactive payload before
  * doorbell; fake HCI also validates every PRD through the full 2KiB region. */
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,4096));
 for(U32 i=4096;i<65536;i++)assert(M.D[20480+i]==0xCC);
 M.D[13312+52]=0x37;M.D[13312+1023]=0x79;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,4096));
 assert(M.D[13312+52]==0x37&&M.D[13312+1023]==0x79);
 pass("perf5_retired_tail_scrubbed_response_allocation_preserved_only_consumed_bytes_reset");
 /* Previous good response must not make an empty next response succeed. */
 M.Fault=21;memset(output,0xEA,sizeof(output));issued=M.R.Acknowledged;
 assert(!NufReadBlock(&M.E,M.Lba,M.Tag,output,4096)&&M.E.Quarantined&&M.R.Acknowledged==issued);
 for(U32 i=0;i<sizeof(output);i++)assert(output[i]==0xEA);
 for(U32 i=0;i<52;i++)assert(M.R.RawResponse[i]==0);
 pass("perf5_missing_response_cannot_reuse_previous_success_or_publish_stale_payload");
 /* First mismatching descriptor is still detected before delta stores can
  * overwrite it, even when tag/size/opcode would otherwise change. */
 setup(0);runtime();assert(NufSessionOpen(&M.E));assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,4096));
 M.D[4096+16]^=1;M.Tag++;stored=M.E.RequestResetBytes;issued=M.Submits;
 assert(!NufReadBlock(&M.E,M.Lba,M.Tag,output,65536)&&M.R.Reason==NufGuard);
 assert(M.E.RequestResetBytes==stored&&M.Submits==issued);
 pass("perf5_delta_descriptor_update_never_masks_corruption_before_reuse");
}
int main(void){setup(0);assert(NufRun(&M.E));assert(M.Submits==2&&M.R.Acknowledged==2&&M.R.Compared&&M.R.Retired&&!M.R.Quarantined);
 assert(M.Reg[0x60/4]==0&&M.Reg[0x50/4]==0x93101000&&M.R.ExpectedCrc==M.R.ReadCrc);pass("capacity_lba0_compare_exact_retire");
 const char *names[]={"","deadline_quarantines_no_abort","guard_quarantines_no_ack","tag_mismatch_no_ack","ocs_failure_no_ack",
 "ack_failure_no_reuse","sector_mismatch_retires","capacity_mismatch_no_read","stopped_clock_quarantines","backward_clock_quarantines",
 "stop_failure_keeps_owned_dma","fatal_is_quarantines","residual_refuses","format_drift_quarantines","ownership_drift_no_cleanup",
 "missing_completion_no_ack","prdt_immutable_quarantines","scsi_failure_no_ack","sense_length_refuses"};
 for(U32 f=1;f<=18;f++){setup(f);assert(!NufRun(&M.E));assert(M.R.FirstReason);
  if(f==6||f==7)assert(M.R.Retired&&!M.R.Quarantined);else assert(M.R.Quarantined&&!M.R.Retired);
  if(f==1||f==8||f==9)assert(M.R.Issued==1&&M.R.Acknowledged==0&&M.StopWrites==0);
  pass(names[f]);}
 setup(0);M.Reg[0x58/4]=2;assert(!NufRun(&M.E)&&!M.Writes);pass("busy_inherited_no_write");
 setup(0);M.E.Config.DmaBase=0x100000000ULL;assert(!NufRun(&M.E)&&!M.Writes);pass("high_dma_refused");
 setup(0);M.E.Config.OldTrlBase=M.E.Config.DmaBase;assert(!NufRun(&M.E)&&!M.Writes);pass("dma_alias_refused");
 setup(0);M.E.Config.Lun=1;assert(!NufRun(&M.E)&&!M.Writes);pass("unadmitted_lun_refused");
 for(U32 op=0;op<256;op++)if(op!=0x25&&op!=0x28)assert(!NufReadCommandAllowed(op,0,4096,0,2));pass("all_nonread_opcodes_refused");
 assert(NufReadCommandAllowed(0x28,0,4096,1,2));assert(!NufReadCommandAllowed(0x28,0,4096,0x100000000ULL,2));assert(!NufReadCommandAllowed(0x28,0,4096,0,0));assert(!NufReadCommandAllowed(0x28,0,4096,0,256));assert(NufReadCommandAllowed(0x28,0,8192,0,2));
 assert(!NufReadCommandAllowed(0x25,0,8,0,3));pass("read_bounds_and_tags");
 N976N_UFS_HANDOFF*h=lease();assert(!NufValidateLease(h,h->LeaseBase,h->DmaBase));assert(!NufValidateLeasePage(LeasePage));pass("released_lease_valid");
 h->Crc32^=1;assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("lease_crc_refused");
 h=lease();h->ProducerStage=2;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("pre_ebs_lease_refused");
 h=lease();h->PowerRaw=0x33;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("powerdown_lease_refused");
 h=lease();h->DmaBase=h->FirmwareDmaBase;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("old_new_dma_overlap_refused");
 h=lease();h->TrlDoorbell=1;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("pending_handoff_refused");
 h=lease();LeasePage[4000]=1;assert(NufValidateLeasePage(LeasePage));pass("lease_tail_guard_refused");
 h=lease();LeasePage[4096]^=1;assert(NufValidateLeasePage(LeasePage));pass("baseline_crc_refused");
 h=lease();h->HciBase=0x13D50000;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("neighbor_mmio_refused");
 h=lease();h->Reserved[0]=1;h->Crc32=NufLeaseCrc(h);assert(NufValidateLease(h,h->LeaseBase,h->DmaBase));pass("reserved_fields_refused");
 assert(NufResourceAllowed(0,0x13D60000,8192,1)&&NufResourceAllowed(1,0x13C10000,4096,1));
 assert(NufResourceAllowed(2,0x93200000,8192,1)&&NufResourceAllowed(3,0x93000000,NUF_DMA_BYTES,1));pass("exact_acpi_resource_contract");
 assert(!NufResourceAllowed(0,0x13D50000,8192,1)&&!NufResourceAllowed(0,0x13D60000,8192,0));
 assert(!NufResourceAllowed(4,0x93000000,4096,1)&&!NufResourceAllowed(3,0xFFFFFFFFFFFFF000ULL,NUF_DMA_BYTES,1));
 assert(!NufResourceAllowed(2,0x95FDD000,8192,1)&&!NufResourceAllowed(3,0x93000001,NUF_DMA_BYTES,1));pass("resource_kind_extra_overflow_alignment_refused");
 setup(0);assert(NufRun(&M.E));U32 writes=M.Writes;assert(!NufRun(&M.E)&&M.Writes==writes);pass("engine_replay_no_write");
 U8 output[4096];setup(0);M.Runtime=1;M.Lba=0x123456;M.Tag=255;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,output,sizeof(output))&&M.Submits==1&&M.R.Retired&&M.R.Acknowledged==1&&!memcmp(output,M.Base,4096));pass("runtime_read_last_lba_tag255_retired_copy");
 const U32 faults[]={1,2,3,4,5,8,9,10,11,12,13,14,15,16,17,18};
 for(U32 f=0;f<sizeof(faults)/sizeof(faults[0]);f++){
  setup(faults[f]);M.Runtime=1;M.Lba=13;M.Tag=37;memset(output,0xEA,sizeof(output));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,output,sizeof(output))&&M.R.FirstReason);
  for(U32 i=0;i<sizeof(output);i++)assert(output[i]==0xEA);
 }pass("runtime_all_safety_faults_never_publish_failed_buffer");
 setup(0);assert(!NufReadBlock(&M.E,0x123457,1,output,sizeof(output))&&!M.Writes);pass("runtime_last_lba_plus_one_refused");
 setup(0);assert(!NufReadBlock(&M.E,0,1,output,4095)&&!M.Writes);assert(!NufReadBlock(&M.E,0,1,NULL,4096)&&!M.Writes);pass("runtime_exact_output_span_required");
 setup(0);M.E.Ops.Read=NULL;M.E.Changed=1;assert(!NufRun(&M.E)&&!NufReadBlock(&M.E,0,1,output,sizeof(output))&&!M.Writes);pass("invalid_engine_callbacks_never_enter_cleanup");
 session_cases();wait_policy_cases();batch_cases();perf2_wait_cases();perf4_wait_cases();perf5_prepare_cases();return 0;}
