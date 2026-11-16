/* Complete production Windows runtime against bounded resource/MMIO/WDF stubs.
 * This is serialized callback execution, not kernel scheduling or MMIO proof. */
#include <stdio.h>
#include <stdlib.h>
#include "N976nDemoRuntime.h"
#include "Y771Event.h"
#include "demo_fixture.h"
static unsigned groups;
#define CHECK(x)do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(1);}}while(0)
#define GROUP(x)do{puts(x);++groups;}while(0)
static uint32_t regs[7][8192],*maps[7]={regs[0],regs[1],regs[2],regs[3],regs[4],regs[5],regs[6]};
static union {unsigned long long aligned;unsigned char bytes[4096];} page;
static unsigned mapped,unmapped,mapfail,mapping_protect[7],writes,reads;
static uint64_t clock100;
static unsigned currentCommand,messageLen,done,receive,txCount,boot,sense,functionValue,injectError,injectTimeout,runs;
static unsigned char tx[3];
static unsigned tail_fresh_hook,ready_hook;
static unsigned retry_faults,retry_active,retry_bits,retry_partial,retry_delay_count,retry_delay_mode,retry_late_bits;

static const uint64_t bases[7]={0x104B0000,0x10400000,0x10421000,0x10430000,0x1A240000,0x93000000,0x15850000};
static const unsigned sizes[7]={0x1000,0x8000,0x1000,0x1000,0x3000,4096,4096};
static int index_of(PVOID P){for(int i=0;i<7;++i)if(i!=5&&P==(PVOID)regs[i])return i;if(P==page.bytes)return 5;return -1;}
static unsigned mutate_snapshot,registry_calls;
static N976N_DEMO_DIAGNOSTIC registry_diagnostic;
static N976N_DEMO_LIFECYCLE registry_lifecycle;
static unsigned life_writes,life_present,life_type=REG_BINARY,life_bytes=sizeof(registry_lifecycle),life_read_fault,life_write_fault;
static unsigned id_fault,boot_fault;
static unsigned char startup_events[33][16];
static const unsigned char physical_fix5_packet[16]={0x1D,0x01,0x88,0xE7,0xA4,0xC6,0x08,0x1F,0x22,0x00,0x03,0xAD,0,0,0,0};
static unsigned startup_count,startup_index,startup_error_at,startup_clock_jump,startup_defer_jump;
static unsigned startup_error_after,startup_cancel_at,startup_drift_at;
static unsigned post_app_fault,post_function_fault,event_complete;
static unsigned command_counts[256],function_writes;
static unsigned runtime_cancel_after_clear;
static unsigned clear_seen,post_snapshot_done,fail_write_command,fail_write_retired,after_sense_cancel,after_sense_drift,after_clear_drift,after_write_jump;
static unsigned char post_packet[16],tail_packet[480];
static unsigned command_log[256],command_log_n;
static N976N_DEMO_RUNTIME *time_runtime;
#include "tail_timeout_fixture.inc"
void MockMemoryBarrier(void){if(mutate_snapshot){page.bytes[0]^=1;mutate_snapshot=0;}}
NTSTATUS MockRegistryAssignValue(WDFKEY K,UNICODE_STRING*N,ULONG Type,ULONG Bytes,const void*Value){
 CHECK(K==(void*)1&&Type==REG_BINARY);
 if(!wcscmp(N->Buffer,N976N_LIFECYCLE_VALUE)){
  CHECK(Bytes==sizeof(registry_lifecycle));if(life_write_fault)return STATUS_DEVICE_NOT_READY;
  memcpy(&registry_lifecycle,Value,Bytes);life_present=1;++life_writes;return 0;
 }
 CHECK(wcscmp(N->Buffer,L"TouchPrepareDiagnostic")==0&&Bytes==sizeof(registry_diagnostic));
 memcpy(&registry_diagnostic,Value,Bytes);++registry_calls;return 0;}
NTSTATUS MockRegistryQueryValue(WDFKEY K,UNICODE_STRING*N,ULONG Capacity,void*Value,ULONG*Bytes,ULONG*Type){
 CHECK(K==(void*)1&&!wcscmp(N->Buffer,N976N_LIFECYCLE_VALUE)&&Capacity==sizeof(registry_lifecycle));
 if(life_read_fault)return STATUS_DEVICE_NOT_READY;
 if(!life_present)return STATUS_OBJECT_NAME_NOT_FOUND;
 *Bytes=life_bytes;*Type=life_type;memcpy(Value,&registry_lifecycle,sizeof(registry_lifecycle));return 0;
}
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS A,size_t N,ULONG Protect){unsigned i;for(i=0;i<7;++i)if((uint64_t)A.QuadPart==bases[i])break;CHECK(i<7&&N==sizes[i]);++mapped;mapping_protect[i]=Protect;if(mapfail==i+1)return NULL;return i!=5?(void*)regs[i]:page.bytes;}
VOID MmUnmapIoSpace(PVOID P,size_t N){int i=index_of(P);CHECK(i>=0&&N==sizes[i]);++unmapped;}
ULONGLONG KeQueryInterruptTime(void){ULONGLONG V=clock100+=100;if(startup_defer_jump&&event_complete&&time_runtime&&time_runtime->Last.Retired){clock100+=64000000;startup_defer_jump=0;}return V;}
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG *Qpc){CHECK(Qpc!=NULL);*Qpc=clock100;return tail_clock(KeQueryInterruptTime());}
NTSTATUS KeDelayExecutionThread(int M,int A,LARGE_INTEGER*I){CHECK(M==KernelMode&&A==0&&I->QuadPart<0);clock100-=(uint64_t)I->QuadPart;
 if(I->QuadPart==-10000&&time_runtime&&time_runtime->Stage==29){
  ++retry_delay_count;
  if(retry_delay_mode==1)time_runtime->StopRequested=1;
  if(retry_delay_mode==2)((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState=2;
  if(retry_delay_mode==3)regs[3][0x20/4]^=0x10000;
  if(retry_delay_mode==4)return STATUS_CANCELLED;
 }return 0;}
static unsigned payload(unsigned I){
 switch(currentCommand){case 0x52:{unsigned b[]={0xAC,0x37,0x71};return b[I]^(id_fault&&I==2?1:0);}
 case 0x55:return boot_fault||(post_app_fault==1&&event_complete)||(post_app_fault==2&&clear_seen)?0x10:0x20;
 case 0x30:return ((functionValue^(((post_function_fault==1&&event_complete)||(post_function_fault==2&&clear_seen))?0x20:0))>>(8*I))&255;
 case 0x61:return tail_packet[I];
 case 0x60:
#ifndef N976N_EXP1_BASELINE_ONLY
  if(clear_seen&&!post_snapshot_done)return post_packet[I];
#endif
  if(!sense&&startup_count)return startup_index<startup_count?startup_events[startup_index][I]:0;
  if(boot)return I==0?9:I==2?0x20:0;if(sense){unsigned b[]={0x44,0x12,0x34,0x56};return I<4?b[I]:0;}return 0;
 default:CHECK(0);return 0;}}
static void tick(void){if(!messageLen)return;
 if(retry_active&&done>=retry_partial){regs[0][0x24/4]=retry_bits;
  if(retry_late_bits&&time_runtime&&time_runtime->Last.FirstFailure.Valid)regs[0][0x24/4]|=retry_late_bits;
  regs[0][0x50/4]=1;regs[0][0x30/4]=0x01000100;regs[0][0x44/4]&=~0x80000000U;return;}

 if(injectTimeout&&sense&&receive){regs[0][0x24/4]=0;regs[0][0x50/4]=0x80001;regs[0][0x30/4]=0x01000100;regs[0][0x44/4]&=~0x80000000U;return;}
 if(done<messageLen){regs[0][0x24/4]=0;regs[0][0x50/4]=0x2000A;regs[0][0x30/4]=receive?0x100:0x01000100;}
 else{regs[0][0x24/4]=0x80;regs[0][0x50/4]=1;regs[0][0x30/4]=0x01000100;regs[0][0x44/4]&=~0x80000000U;}
 tail_sample();
 if((fail_write_command&&!receive&&txCount&&tx[0]==fail_write_command)||(injectError&&sense&&receive)||(startup_error_at==startup_index+1&&currentCommand==0x60&&receive&&done>=startup_error_after)){
  regs[0][0x24/4]=0x200;regs[0][0x50/4]=0x2000A;regs[0][0x30/4]=0x100;
  if(fail_write_retired&&!receive&&done==messageLen){regs[0][0x50/4]=1;regs[0][0x30/4]=0x01000100;regs[0][0x44/4]&=~0x80000000U;}}}
ULONG MockReadRegister(PULONG P){++reads;
 if(ready_hook&&time_runtime&&P==&regs[6][0x24/4]){
  if(ready_hook==1)time_runtime->StopRequested=1;
  if(ready_hook==2)((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState=2;
  ready_hook=0;
 }

 if(tail_fresh_hook&&time_runtime&&currentCommand==0x61&&time_runtime->Last.Retired&&time_runtime->Last.FirstFailure.Interrupt==0x400){
  unsigned mode=tail_fresh_hook;tail_fresh_hook=0;
  if(mode==1)time_runtime->StopRequested=1;
  if(mode==2)((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState=2;
  if(mode==3)regs[3][0x20/4]^=0x10000;
 }
if(runtime_cancel_after_clear && time_runtime && currentCommand==0x62 &&
     time_runtime->Last.Retired && clear_seen>=2 && P==&regs[3][0x20/4]){
  runtime_cancel_after_clear=0;time_runtime->StopRequested=1;
 }
uintptr_t ptr=(uintptr_t)P,base=(uintptr_t)regs[0];
 if(ptr>=base&&ptr<base+sizeof(regs[0])){unsigned o=(unsigned)(ptr-base);if(o==0x24)tick();if(tail_mock.revoked)CHECK(0);if(o==0)return *P&~0xC0U;
  if(o==0x38){CHECK(receive&&done<messageLen&&done<480);unsigned v=payload(done++);tail_dequeue();return 0xF00D0000U|v;}}
 return *P;}
void MockWriteRegister(PULONG P,ULONG V){++writes;uintptr_t o=(uintptr_t)P-(uintptr_t)regs[0];
 CHECK(o==0||o==4||o==0x20||o==0x24||o==0x34||o==0x44||o==0x70);CHECK(!(o==0&&(V&0x80000000U)));
 /* Timed-out fixture is already idle; retirement masks its source and it stays idle. */
 if(o==0x20&&V==0&&injectTimeout&&receive&&!done)messageLen=0;
 if(o==0x34){CHECK(!receive&&done<messageLen&&txCount<3);tx[txCount++]=(uint8_t)V;++done;return;}
 if(tail_mock.revoked)CHECK(0);
 if(o==0x24&&tail_ack(V))return;
 if(o==0x24){CHECK(V==regs[0][0x24/4]&&(V==0x80||retry_active||(V==0x200&&fail_write_retired)));if(V==0x200)fail_write_command=fail_write_retired=0;regs[0][0x24/4]=0;
  if(!receive){currentCommand=tx[0];++command_counts[currentCommand];CHECK(command_log_n<256);command_log[command_log_n++]=currentCommand;if(currentCommand==0x10)sense=1;if(currentCommand==0x11)sense=0;
   if(currentCommand==0x62){++clear_seen;boot=0;if(after_clear_drift)regs[3][0x20/4]^=0x10000;}
   if(currentCommand==0x10){if(after_sense_cancel&&time_runtime)time_runtime->StopRequested=1;if(after_sense_drift)regs[3][0x20/4]^=0x10000;}
   if(currentCommand==after_write_jump)clock100+=64000000;if(currentCommand==0x30&&txCount==3){functionValue=tx[1]|(tx[2]<<8);++function_writes;}}
  else if(currentCommand==0x60&&!sense){boot=0;++startup_index;event_complete=1;clock100+=(uint64_t)startup_clock_jump*10;startup_clock_jump=0;
   if(startup_cancel_at==startup_index&&time_runtime)time_runtime->StopRequested=1;
   if(startup_drift_at==startup_index)regs[3][0x20/4]^=0x10000;}
  else if(currentCommand==0x60&&sense&&!post_snapshot_done){post_snapshot_done=1;++startup_index;event_complete=1;if(startup_cancel_at==2&&time_runtime)time_runtime->StopRequested=1;}
  else if(currentCommand==0x30&&event_complete&&((post_function_fault==1)||(post_function_fault==2&&clear_seen)))post_function_fault=0;
  messageLen=0;retry_active=0;return;}
 *P=V;if(o==0x44&&(V&0x80000000U)){++runs;messageLen=V&0xFFFF;done=0;receive=(V&0x10000U)!=0;txCount=0;
 if(receive&&(currentCommand==0x60||currentCommand==0x61)&&post_snapshot_done&&retry_faults){--retry_faults;retry_active=1;}}}
static void fixture(MOCK_LIST*A,MOCK_LIST*B){N976N_TOUCH_HANDOFF H;demo_fixture(&H);memset(regs,0,sizeof(regs));memset(&page,0,sizeof(page));demo_bind_regs(&H,maps);memcpy(page.bytes,&H,sizeof(H));*(uint64_t*)(page.bytes+4088)=N976N_TOUCH_HANDOFF_GUARD;
 memset(A,0,sizeof(*A));A->Count=7;for(unsigned i=0;i<7;++i){A->Item[i].Type=CmResourceTypeMemory;A->Item[i].ShareDisposition=i==4?CmResourceShareShared:CmResourceShareDeviceExclusive;A->Item[i].Flags=(i==0||i==5)?0:1;A->Item[i].u.Memory.Start.QuadPart=(int64_t)bases[i];A->Item[i].u.Memory.Length=sizes[i];}*B=*A;
 mapped=unmapped=mapfail=writes=reads=runs=injectError=injectTimeout=mutate_snapshot=registry_calls=0;
 memset(&tail_mock,0,sizeof(tail_mock));
 ready_hook=tail_fresh_hook=retry_faults=retry_active=retry_partial=retry_delay_count=retry_delay_mode=retry_late_bits=0;retry_bits=0x400;
 life_writes=life_present=life_read_fault=life_write_fault=id_fault=boot_fault=0;life_type=REG_BINARY;life_bytes=sizeof(registry_lifecycle);memset(&registry_lifecycle,0,sizeof(registry_lifecycle));memset(&registry_diagnostic,0,sizeof(registry_diagnostic));messageLen=done=receive=txCount=currentCommand=0;boot=1;sense=0;functionValue=0;clock100=0;
 runtime_cancel_after_clear=0;memset(startup_events,0,sizeof(startup_events));startup_count=startup_index=startup_error_at=startup_clock_jump=startup_defer_jump=post_app_fault=post_function_fault=event_complete=0;startup_error_after=startup_cancel_at=startup_drift_at=0;time_runtime=NULL;memset(command_counts,0,sizeof(command_counts));function_writes=0;clear_seen=post_snapshot_done=fail_write_command=fail_write_retired=after_sense_cancel=after_sense_drift=after_clear_drift=after_write_jump=command_log_n=0;memset(post_packet,0,sizeof(post_packet));memset(tail_packet,0,sizeof(tail_packet));}

/* The actual four Device.c callbacks are extracted by the existing harness. */
typedef int WDF_POWER_DEVICE_STATE;
typedef struct {N976N_DEMO_RUNTIME Runtime;void *PollTimer,*HoldTimer,*InputLock,*ManualQueue;
 LONG InputDrainActive,InputStopping,HoldTimerArmed;ULONGLONG LastDiagnosticTick;} CALLBACK_CONTEXT,*PDEVICE_CONTEXT;
#define GetDeviceContext(D) ((PDEVICE_CONTEXT)(D))
#define WDF_REL_TIMEOUT_IN_MS(N) (N)
static unsigned callback_joins,callback_purges;
static int WdfTimerStop(void *T,int Join){(void)T;CHECK(Join==TRUE);++callback_joins;return 1;}
static void WdfTimerStart(void *T,int Delay){(void)T;CHECK(Delay==20);}
static void WdfWaitLockAcquire(void *L,void *T){(void)L;CHECK(T==NULL);}
static void WdfWaitLockRelease(void *L){(void)L;}
static void WdfIoQueueStart(void *Q){(void)Q;}
static void WdfIoQueuePurgeSynchronously(void *Q){(void)Q;++callback_purges;}
static void TouchStopInput(PDEVICE_CONTEXT C){(void)C;}
static void TouchResetInputStateLocked(PDEVICE_CONTEXT C){(void)C;}
#include "runtime_callbacks.inc"
#ifdef N976N_EXP1_BASELINE_ONLY
int main(void){MOCK_LIST A,B;CALLBACK_CONTEXT C={0};N976N_DEMO_RUNTIME *R=&C.Runtime;fixture(&A,&B);(void)OnD0Exit;
 startup_count=33;for(unsigned i=0;i<33;++i){memcpy(startup_events[i],physical_fix5_packet,16);startup_events[i][3]=(unsigned char)(0xE7+i);}
 CHECK(OnPrepareHardware(&C,&A,&B)==0);
 CHECK(OnD0Entry(&C,0)==STATUS_DEVICE_DATA_ERROR&&R->Lifecycle.FirstStartFailure.Stage==25&&R->Id==0xAC3771);
 CHECK(R->Startup.Reason==N976nStartupReadLimit&&R->Startup.Reads==33&&R->Startup.NonEmpty==33);
 CHECK(R->Startup.UnknownVendorCount==33&&R->Startup.Remaining31Count==33&&!memcmp(R->Startup.First.Raw,physical_fix5_packet,16));
 CHECK(R->Lifecycle.FirstStartFailure.Hsi.Status==0&&R->Lifecycle.FirstStartFailure.Hsi.Retired==1&&R->Lifecycle.FirstStartFailure.Hsi.RxBytes==16&&!sense&&!clear_seen&&!R->Quarantined);
 CHECK(OnReleaseHardware(&C,&B)==0);
 GROUP("preserved_EXP1_actual_runtime_33_nonempty_observations_fail_read_cap_without_sense_clear");
 printf("PASS %u groups\n",groups);return 0;}
#else
#include "tail_timeout_cases.inc"
int main(void){MOCK_LIST A,B;N976N_DEMO_RUNTIME R={0},R2={0};NTSTATUS S;UCHAR E[16];
 GROUP("actual_prepare_exact_resources_NVS_WB_claim_and_fresh_state");fixture(&A,&B);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0);CHECK(R.Claimed&&R.Mapped&&mapped==7&&!writes);CHECK(mapping_protect[0]==(PAGE_READWRITE|PAGE_NOCACHE)&&mapping_protect[5]==PAGE_READWRITE&&mapping_protect[6]==(PAGE_READONLY|PAGE_NOCACHE)&&R.Lifecycle.NvsAddress==bases[5]);CHECK(((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==1);
 CHECK(mapping_protect[4]==(PAGE_READONLY|PAGE_NOCACHE));
 GROUP("actual_duplicate_owner_rejected_before_mapping");CHECK(N976nDemoPrepare(&R2,(void*)2,&A,&B)==STATUS_DEVICE_BUSY&&mapped==7);
 GROUP("actual_D0_start_ID_function_sense_and_input_event");CHECK(N976nDemoStart(&R)==0);CHECK(R.Id==0xAC3771&&R.Stage==29&&sense&&functionValue==0x61&&R.FunctionSaved&&R.FunctionChanged);CHECK(N976nDemoReadEvent(&R,E)==0);CHECK(E[0]==0x44&&E[1]==0x12&&E[2]==0x34&&R.Polls==1);
 GROUP("actual_stop_quiesces_sensor_restores_function_but_keeps_rails");CHECK(N976nDemoStop(&R)==0);CHECK(!sense&&!functionValue&&!R.FunctionSaved&&R.Stage==40&&!R.Quarantined);CHECK(((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==1);CHECK(N976nDemoStop(&R)==0);
 GROUP("actual_release_marks_permanent_current_boot_retirement_and_unmaps");N976nDemoRelease(&R);CHECK(unmapped==7&&!R.Claimed&&!R.Mapped&&((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==2);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)!=0);CHECK(!writes||runs>0);
 GROUP("each_wrong_resource_rejected_with_only_owned_map_cleanup");
 for(unsigned i=0;i<7;++i){fixture(&A,&B);B.Item[i].u.Memory.Start.QuadPart+=4;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)!=0);CHECK(mapped==i&&unmapped==i&&!writes);}
 GROUP("resource_type_share_length_flags_and_count_fail_closed");
 for(unsigned i=0;i<6;++i){fixture(&A,&B);switch(i){case 0:A.Count=5;break;case 1:A.Item[0].ShareDisposition=B.Item[0].ShareDisposition=3;break;case 2:A.Item[1].Type=B.Item[1].Type=CmResourceTypeInterrupt;break;case 3:A.Item[5].u.Memory.Length=B.Item[5].u.Memory.Length=8192;break;case 4:A.Item[0].Flags=B.Item[0].Flags=1;break;case 5:A.Item[5].Flags=B.Item[5].Flags=4;break;}CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)!=0);CHECK(mapped==unmapped&&!writes);}
 GROUP("clockshare_TOP_shared_required_other_maps_exclusive_and_flags_pair_exact");
 for(unsigned k=0;k<8;++k){fixture(&A,&B);memset(&R,0,sizeof(R));
  if(k<4){if(k&1)A.Item[4].ShareDisposition=CmResourceShareDeviceExclusive;if(!(k&1))B.Item[4].ShareDisposition=CmResourceShareDeviceExclusive;if(k>=2)A.Item[4].ShareDisposition=B.Item[4].ShareDisposition=CmResourceShareDeviceExclusive;}
  else if(k==4){A.Item[4].Flags=B.Item[4].Flags=CM_RESOURCE_MEMORY_PREFETCHABLE;}
  else if(k==5){A.Item[4].Flags=0;B.Item[4].Flags=1;}
  else if(k==6){A.Item[3].ShareDisposition=B.Item[3].ShareDisposition=CmResourceShareShared;}
  else {A.Item[6].ShareDisposition=B.Item[6].ShareDisposition=CmResourceShareShared;}
  CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR&&mapped==unmapped&&!writes);
 }
 GROUP("clockshare_TOP_flag_zero_preserved_but_mapping_stays_readonly");
 fixture(&A,&B);memset(&R,0,sizeof(R));A.Item[4].Flags=B.Item[4].Flags=0;
 CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&mapping_protect[4]==(PAGE_READONLY|PAGE_NOCACHE)&&!writes);
 CHECK(!N976nDemoStart(&R)&&!N976nDemoStop(&R));N976nDemoRelease(&R);
 GROUP("every_map_failure_unmaps_preceding_only");for(unsigned i=1;i<=7;++i){fixture(&A,&B);mapfail=i;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_INSUFFICIENT_RESOURCES);CHECK(mapped==i&&unmapped==i-1&&!writes);}
 GROUP("producer_corruption_and_guard_rejected_before_claim_or_io");
 for(unsigned i=0;i<3;++i){fixture(&A,&B);if(i==0)page.bytes[0]^=1;else if(i==1)page.bytes[4088]^=1;else ((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState=3;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)!=0);CHECK(mapped==7&&unmapped==7&&!writes);}
 GROUP("fresh_mutation_after_prepare_quarantines_before_commands");fixture(&A,&B);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0);regs[3][0x20/4]^=0x10000;CHECK(N976nDemoStart(&R)!=0);CHECK(R.Quarantined&&!writes);N976nDemoRelease(&R);CHECK(((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==3);
 GROUP("actual_unretired_RX_error_no_reset_or_cleanup_retry");fixture(&A,&B);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0&&N976nDemoStart(&R)==0);injectError=1;S=N976nDemoReadEvent(&R,E);CHECK(!NT_SUCCESS(S)&&R.Quarantined&&R.Stage==90);unsigned savedWrites=writes;CHECK(N976nDemoStop(&R)!=0&&writes==savedWrites);N976nDemoRelease(&R);CHECK(((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==3);
 GROUP("EXP3_runtime_poll_failure_origin_and_frozen_RX_wait_survive_stop");
 fixture(&A,&B);memset(&R,0,sizeof(R));CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0&&N976nDemoStart(&R)==0);injectTimeout=1;
 CHECK(N976nDemoReadEvent(&R,E)==STATUS_IO_TIMEOUT&&R.Stage==90&&!R.Quarantined);
 CHECK(R.Lifecycle.FirstFailure.Callback==N976nLifePoll&&R.Lifecycle.FirstFailure.Command==0x60);
 CHECK(R.Lifecycle.FirstFailure.Hsi.Wait.Exit==N976nWaitDeadline&&R.Lifecycle.FirstFailure.Hsi.Wait.Receive==1&&R.Lifecycle.FirstFailure.Hsi.Wait.Requested==16);
 CHECK(R.Lifecycle.FirstFailure.Hsi.Wait.Iterations==10000&&R.Lifecycle.FirstFailure.Hsi.Wait.ElapsedUs==100000&&N976nHsiWaitShape(&R.Lifecycle.FirstFailure.Hsi.Wait));
 N976N_HSI_WAIT frozen_wait=R.Lifecycle.FirstFailure.Hsi.Wait;
 injectTimeout=0;N976nDemoCallback(&R,N976nLifePollFailure);CHECK(N976nDemoStop(&R)==0);
 CHECK(!memcmp(&frozen_wait,&R.Lifecycle.FirstFailure.Hsi.Wait,sizeof(frozen_wait))&&!R.Quarantined);
 N976nDemoRecord(&R);CHECK(!memcmp(&frozen_wait,&registry_lifecycle.FirstFailure.Hsi.Wait,sizeof(frozen_wait)));N976nDemoRelease(&R);
 GROUP("cancellation_prevents_new_event_without_touching_MMIO");fixture(&A,&B);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0&&N976nDemoStart(&R)==0);R.StopRequested=1;savedWrites=writes;CHECK(N976nDemoReadEvent(&R,E)==STATUS_CANCELLED&&savedWrites==writes);CHECK(N976nDemoStop(&R)==0);N976nDemoRelease(&R);
 GROUP("resource_first_failure_original_raw_translated_operands_before_cleanup");
 fixture(&A,&B);A.Item[2].Flags=B.Item[2].Flags=0x20;
 CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR);
 CHECK(R.Stage==12&&R.Diagnostic.Valid==N976N_DIAGNOSTIC_VALID&&R.Diagnostic.Bucket==N976nDiagResource);
 CHECK(R.Diagnostic.Condition==N976nWhyFlagsMask&&R.Diagnostic.Index==2&&R.Diagnostic.MappedCount==2);
 CHECK(R.Diagnostic.RawFlags==0x20&&R.Diagnostic.TransFlags==0x20&&R.Diagnostic.RawStart==bases[2]&&R.Diagnostic.TransLength==sizes[2]);
 CHECK(unmapped==2&&!reads&&!writes);
 GROUP("first_refusal_survives_stop_release_record_and_is_published_once");
 N976N_DEMO_DIAGNOSTIC saved=R.Diagnostic;N976nDemoRecord(&R);CHECK(registry_calls==1&&!memcmp(&registry_diagnostic,&saved,sizeof(saved)));
 CHECK(N976nDemoStop(&R)==0);N976nDemoRecord(&R);N976nDemoRelease(&R);N976nDemoRecord(&R);
 CHECK(registry_calls==1&&!memcmp(&R.Diagnostic,&saved,sizeof(saved))&&!memcmp(&registry_diagnostic,&saved,sizeof(saved))&&R.Stage==12);
 GROUP("two_original_NVS_copies_report_first_changed_byte_without_third_copy");
 fixture(&A,&B);mutate_snapshot=1;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR);
 CHECK(R.Diagnostic.Bucket==N976nDiagNvs&&R.Diagnostic.Condition==N976nWhySnapshot&&R.Diagnostic.Offset==0);
 CHECK(R.Diagnostic.Expected==(N976N_TOUCH_HANDOFF_MAGIC&255)&&R.Diagnostic.Actual==((N976N_TOUCH_HANDOFF_MAGIC&255)^1)&&!reads&&!writes&&unmapped==7);
 GROUP("NVS_guard_claim_CRC_and_shape_failures_are_distinct_original_operands");
 for(unsigned i=0;i<4;++i){fixture(&A,&B);N976N_TOUCH_HANDOFF *H=(void*)page.bytes;
  if(i==0)*(uint64_t*)(page.bytes+4088)^=8;if(i==1)H->ClaimState=2;
  if(i==2)H->Crc32^=0x80;if(i==3){H->ProducerStage=1;H->Crc32=N976nDemoCrc(H);}
  CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR);
  CHECK(R.Diagnostic.Condition==((unsigned[]){N976nWhyPageGuard,N976nWhyReady,N976nWhyCrc,N976nWhyField})[i]);
  CHECK(R.Diagnostic.MappedCount==7&&!writes&&!reads&&unmapped==7);
  if(i==2)CHECK((R.Diagnostic.Expected^R.Diagnostic.Actual)==0x80);
  if(i==3)CHECK(R.Diagnostic.Offset==offsetof(N976N_TOUCH_HANDOFF,ProducerStage)&&R.Diagnostic.Expected==2&&R.Diagnostic.Actual==1);}
 GROUP("prepare_fresh_failure_records_first_MMIO_and_never_rereads_after_refusal");
 fixture(&A,&B);regs[1][0x2008/4]=0x10;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR);
 CHECK(R.Diagnostic.Bucket==N976nDiagFresh&&R.Diagnostic.Index==1&&R.Diagnostic.Offset==0x2008&&R.Diagnostic.Expected==0&&R.Diagnostic.Actual==0x10);
 CHECK(reads==1&&!writes&&unmapped==7&&R.Diagnostic.MappedCount==7);
 GROUP("map_failure_keeps_distinct_status_and_completed_map_count");
 fixture(&A,&B);mapfail=3;CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==STATUS_INSUFFICIENT_RESOURCES);
 CHECK(R.Diagnostic.Bucket==N976nDiagMap&&R.Diagnostic.Index==2&&R.Diagnostic.MappedCount==2&&unmapped==2&&!reads&&!writes);
 GROUP("successful_prepare_publishes_explicit_absence_not_a_zero_failure");
 fixture(&A,&B);CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)==0);N976nDemoRecord(&R);
 CHECK(registry_calls==1&&registry_diagnostic.Version==1&&registry_diagnostic.Bytes==sizeof(registry_diagnostic)&&!registry_diagnostic.Valid);N976nDemoRelease(&R);

 GROUP("actual_callbacks_start_failure_keeps_original_ID_HSI_before_cleanup_and_release");
 fixture(&A,&B);CALLBACK_CONTEXT C={0},C2={0};boot_fault=1;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_DEVICE_NOT_READY);
 CHECK(C.Runtime.Lifecycle.FirstStartFailure.Stage==22&&C.Runtime.Lifecycle.FirstStartFailure.Status==(unsigned)STATUS_DEVICE_NOT_READY);
 CHECK(C.Runtime.Lifecycle.FirstStartFailure.Id==0xAC3771&&C.Runtime.Lifecycle.FirstStartFailure.Command==0x55&&C.Runtime.Lifecycle.FirstStartFailure.HsiCurrent==1);
 CHECK(C.Runtime.Lifecycle.FirstStop.Stage==22&&C.Runtime.Lifecycle.FirstCleanup.CleanupStatus==0&&C.Runtime.Stage==40);
 N976N_LIFECYCLE_STATE initial_failure=C.Runtime.Lifecycle.FirstStartFailure;
 CHECK(OnReleaseHardware(&C,&B)==0&&((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==2);
 CHECK(C.Runtime.Lifecycle.PrepareCount==1&&C.Runtime.Lifecycle.StartCount==1&&C.Runtime.Lifecycle.StopCount==2&&C.Runtime.Lifecycle.ReleaseCount==1&&C.Runtime.Lifecycle.D0EntryCount==1);
 CHECK(registry_lifecycle.Crc32==N976nDemoLifecycleCrc(&registry_lifecycle));
 GROUP("same_context_reprepare_keeps_first_start_and_current_ready2_refusal_separate");
 unsigned oldreads=reads,oldwrites=writes;
 CHECK(OnPrepareHardware(&C,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR&&C.Runtime.Diagnostic.Condition==N976nWhyReady);
 CHECK(C.Runtime.Diagnostic.Actual==2&&C.Runtime.Lifecycle.PrepareCount==2&&C.Runtime.Lifecycle.FirstPrepareNumber==2);
 CHECK(!memcmp(&initial_failure,&C.Runtime.Lifecycle.FirstStartFailure,sizeof(initial_failure))&&C.Runtime.Lifecycle.Origin==N976nLifeOriginContext);
 CHECK(reads==oldreads&&writes==oldwrites&&C.Runtime.Lifecycle.Current.Stage==12&&C.Runtime.Lifecycle.Current.Id==0);
 GROUP("new_runtime_registry_restore_matches_boot_and_preserves_first_failure_counters");
 CHECK(OnPrepareHardware(&C2,&A,&B)==STATUS_DEVICE_CONFIGURATION_ERROR);
 CHECK(C2.Runtime.Lifecycle.Origin==N976nLifeOriginRegistry&&C2.Runtime.Lifecycle.RegistryState==N976nLifeRegistryRestored&&C2.Runtime.Lifecycle.PrepareCount==3);
 CHECK(!memcmp(&initial_failure,&C2.Runtime.Lifecycle.FirstStartFailure,sizeof(initial_failure))&&C2.Runtime.Lifecycle.FirstPrepareNumber==2&&reads==oldreads&&writes==oldwrites);
 N976N_DEMO_LIFECYCLE prior_boot=registry_lifecycle;
 GROUP("valid_new_boot_replaces_stale_record_without_importing_old_failures");
 fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;life_present=1;
 N976N_TOUCH_HANDOFF *NewH=(void*)page.bytes;NewH->BootCounter++;NewH->Crc32=N976nDemoCrc(NewH);
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&C.Runtime.Lifecycle.RegistryState==N976nLifeRegistryOtherBoot);
 CHECK(C.Runtime.Lifecycle.PrepareCount==1&&!C.Runtime.Lifecycle.FirstStartFailure.Valid&&registry_lifecycle.BootCounter==NewH->BootCounter);
 CHECK(OnReleaseHardware(&C,&B)==0);
 GROUP("malformed_registry_type_size_crc_or_query_failure_never_imports_or_overwrites");
 for(unsigned i=0;i<9;++i){
  fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;life_present=1;
  if(i==0)life_type=1;if(i==1)life_bytes--;if(i==2)registry_lifecycle.Crc32^=1;if(i==3)life_read_fault=1;
  if(i==4)registry_lifecycle.FirstStart.Valid=2;if(i==5)registry_lifecycle.FirstFailure.Callback=99;
  if(i==6)registry_lifecycle.FirstStart.HsiCurrent=2;if(i==7)registry_lifecycle.FirstStop.Reserved=1;
  if(i==8){registry_lifecycle.FirstPrepareFailure.Valid=N976N_DIAGNOSTIC_VALID;registry_lifecycle.FirstPrepareFailure.Version=0;}
  if(i>=4)registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  N976N_DEMO_LIFECYCLE Before=registry_lifecycle;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&!C.Runtime.Lifecycle.FirstStartFailure.Valid);
  CHECK(!C.Runtime.LifeCanPublish&&life_writes==0&&!memcmp(&Before,&registry_lifecycle,sizeof(Before)));
  CHECK(OnReleaseHardware(&C,&B)==0&&!life_writes&&!memcmp(&Before,&registry_lifecycle,sizeof(Before)));
 }
 GROUP("identity_unavailable_keeps_existing_boot_record_without_additional_MMIO");
 fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;life_present=1;page.bytes[0]^=1;
 CHECK(OnPrepareHardware(&C,&A,&B)!=0&&!C.Runtime.Lifecycle.IdentityValid&&!life_writes&&!reads&&!writes);
 CHECK(!memcmp(&prior_boot,&registry_lifecycle,sizeof(prior_boot)));
 GROUP("EXP3_CRC_valid_malformed_wait_evidence_never_imports");
 for(unsigned i=0;i<8;++i){
  fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;life_present=1;
  N976N_HSI_WAIT *W=&registry_lifecycle.FirstStart.Hsi.Wait;
  CHECK(W->Valid&&N976nHsiWaitShape(W));
  switch(i){case 0:W->Valid=2;break;case 1:W->MessageIndex=3;break;case 2:W->ClockChecks=20001;break;
   case 3:W->Last.Valid=7;break;case 4:W->Seen=32;break;case 5:W->Exit=N976nWaitDeadline;break;
   case 6:W->ClockStarted=0;break;case 7:W->Phase=4;break;}
  CHECK(!N976nHsiWaitShape(W));registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&C.Runtime.Lifecycle.RegistryState==N976nLifeRegistryMalformed&&!C.Runtime.LifeCanPublish);
  CHECK(OnReleaseHardware(&C,&B)==0&&!life_writes);
 }
 GROUP("EXP5_CRC_valid_malformed_boundary_never_imports");
 for(unsigned i=0;i<5;++i){
  fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;life_present=1;
  N976N_HSI_RESULT *H=&registry_lifecycle.FirstStart.Hsi;CHECK(N976nHsiEvidenceShape(H));
  switch(i){case 0:H->Boundary[1].ArmRead=0x80;break;case 1:H->Boundary[1].Valid&=~4U;break;
   case 2:H->Boundary[0].After=1;break;case 3:H->Boundary[2].Valid|=1;break;case 4:H->Boundary[1].Valid=0;break;}
  CHECK(!N976nHsiEvidenceShape(H));registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&C.Runtime.Lifecycle.RegistryState==N976nLifeRegistryMalformed&&!C.Runtime.LifeCanPublish);
  CHECK(OnReleaseHardware(&C,&B)==0&&!life_writes);
 }
 GROUP("registry_write_failure_keeps_in_context_original_start_evidence");
 fixture(&A,&B);memset(&C,0,sizeof(C));life_write_fault=1;boot_fault=1;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_DEVICE_NOT_READY&&!life_present);
 initial_failure=C.Runtime.Lifecycle.FirstStartFailure;CHECK(OnReleaseHardware(&C,&B)==0);
 CHECK(OnPrepareHardware(&C,&A,&B)!=0&&!memcmp(&initial_failure,&C.Runtime.Lifecycle.FirstStartFailure,sizeof(initial_failure))&&!life_present);
 GROUP("successful_actual_D0_exit_join_cleanup_and_release_counters");
 fixture(&A,&B);memset(&C,0,sizeof(C));callback_joins=callback_purges=0;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==0&&C.Runtime.Lifecycle.FirstStart.Stage==29);
 CHECK(OnD0Exit(&C,0)==0&&callback_joins==2&&callback_purges==1&&C.Runtime.Lifecycle.FirstStop.Callback==N976nLifeD0Exit);
 CHECK(C.Runtime.Lifecycle.FirstStop.Stage==29&&!C.Runtime.Lifecycle.FirstStartFailure.Valid&&OnReleaseHardware(&C,&B)==0);
 CHECK(C.Runtime.Lifecycle.D0EntryCount==1&&C.Runtime.Lifecycle.D0ExitCount==1&&C.Runtime.Lifecycle.ReleaseCount==1&&C.Runtime.Lifecycle.StopCount==2);
 GROUP("first_owned_failure_keeps_cleanup_quarantine_separate_and_no_retry");
 fixture(&A,&B);memset(&C,0,sizeof(C));CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==0);
 injectError=1;CHECK(N976nDemoReadEvent(&C.Runtime,E)!=0);N976nDemoCallback(&C.Runtime,N976nLifePollFailure);
 initial_failure=C.Runtime.Lifecycle.FirstFailure;savedWrites=writes;CHECK(OnD0Exit(&C,0)!=0&&writes==savedWrites);
 CHECK(C.Runtime.Lifecycle.FirstFailure.Stage==90&&C.Runtime.Lifecycle.FirstFailure.HsiCurrent==1&&C.Runtime.Lifecycle.FirstCleanupFailure.Valid);
 CHECK(!memcmp(&initial_failure,&C.Runtime.Lifecycle.FirstFailure,sizeof(initial_failure))&&OnReleaseHardware(&C,&B)==0&&writes==savedWrites);
 GROUP("lifecycle_counters_saturate_and_never_authorize_retired_reclaim");
 C.Runtime.Lifecycle.PrepareCount=0xFFFFFFFFU;CHECK(OnPrepareHardware(&C,&A,&B)!=0&&C.Runtime.Lifecycle.PrepareCount==0xFFFFFFFFU);
 CHECK(((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState==3&&writes==savedWrites);
 GROUP("EXP2_PRE_and_POST_only_SenseOn_then_Clear_once_with_live_state_checks");
 fixture(&A,&B);memset(&C,0,sizeof(C));startup_count=33;
 for(unsigned j=0;j<33;++j)memcpy(startup_events[j],physical_fix5_packet,16);
 memcpy(post_packet,physical_fix5_packet,16);post_packet[3]=0x07;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==0);
 CHECK(C.Runtime.Stage==29&&C.Runtime.Startup.Phase==N976nStartupComplete&&C.Runtime.Startup.InitPhase==N976nInitComplete);
 CHECK(C.Runtime.Startup.Reads==2&&C.Runtime.Startup.NonEmpty==2&&!C.Runtime.Startup.Empty&&C.Runtime.Startup.UnknownVendorCount==2&&C.Runtime.Startup.Remaining31Count==2);
 CHECK(C.Runtime.Startup.PreChecks==15&&C.Runtime.Startup.PostChecks==15&&C.Runtime.Startup.PreAppValue==0x20&&C.Runtime.Startup.AppValue==0x20&&C.Runtime.Startup.FunctionValue==0x61);
 CHECK(C.Runtime.Startup.SenseAttempted==1&&C.Runtime.Startup.SenseIssued==1&&C.Runtime.Startup.SenseCompleted==1);
 CHECK(C.Runtime.Startup.ClearAttempted==1&&C.Runtime.Startup.ClearIssued==1&&C.Runtime.Startup.ClearCompleted==1&&!C.Runtime.Startup.ClearStatus);
 CHECK(command_counts[0x60]==2&&command_counts[0x10]==1&&command_counts[0x62]==1&&sense&&!C.Runtime.Events&&!C.Runtime.Polls);
 const unsigned order[]={0x52,0x55,0x30,0x30,0x30,0x60,0x55,0x30,0x10,0x62,0x55,0x30,0x60};
 CHECK(command_log_n==sizeof(order)/sizeof(order[0])&&!memcmp(order,command_log,sizeof(order)));
 CHECK(!memcmp(C.Runtime.Startup.First.Raw,physical_fix5_packet,16)&&!memcmp(C.Runtime.Startup.Last.Raw,post_packet,16));
 N976N_STARTUP_EVIDENCE observed=C.Runtime.Lifecycle.FirstStartup;
 CHECK(N976nStartupShape(&observed)&&OnReleaseHardware(&C,&B)==0);
 GROUP("EXP2_initialization_and_raw_evidence_survive_reprepare_and_registry_restore");
 CHECK(OnPrepareHardware(&C,&A,&B)!=0&&!memcmp(&observed,&C.Runtime.Lifecycle.FirstStartup,sizeof(observed)));
 memset(&C2,0,sizeof(C2));CHECK(OnPrepareHardware(&C2,&A,&B)!=0&&C2.Runtime.Lifecycle.Origin==N976nLifeOriginRegistry);
 CHECK(!memcmp(&observed,&C2.Runtime.Lifecycle.FirstStartup,sizeof(observed))&&!C2.Runtime.Claimed);
 GROUP("EXP2_empty_is_observed_not_a_required_initialization_or_future_empty_claim");
 fixture(&A,&B);memset(&C,0,sizeof(C));boot=0;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==0&&C.Runtime.Startup.Empty==2&&C.Runtime.Startup.Reads==2&&clear_seen==1);
 CHECK(N976nDemoReadEvent(&C.Runtime,E)==0&&E[0]==0x44&&C.Runtime.Polls==1&&OnReleaseHardware(&C,&B)==0);
 GROUP("EXP2_PRE_BOOT_ACK_allowed_POST_BOOT_ACK_quarantines_without_chip_cleanup");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));startup_count=1;startup_events[0][0]=(unsigned char)(k?0x1D:9);startup_events[0][2]=0xE1;
  memcpy(post_packet,startup_events[0],16);
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_DEVICE_DATA_ERROR);
  CHECK(C.Runtime.Startup.Reason==N976nStartupPostBoot&&C.Runtime.Startup.Boot==2&&C.Runtime.Startup.Rejected.Ordinal==2&&C.Runtime.Quarantined&&C.Runtime.Startup.ClearCompleted);
  CHECK(!command_counts[0x11]&&function_writes==1);savedWrites=writes;
  CHECK(OnReleaseHardware(&C,&B)==0&&writes==savedWrites&&N976nStartupShape(&C.Runtime.Startup));
 }
 GROUP("EXP2_source_status_gesture_and_coordinates_retire_without_HID");
 const unsigned vendor[]={0x40,0x41,0x42,0x43,0x44,0x46,0x47,0x58,0x61,0x64,0x6A,0x6D};
 for(unsigned k=0;k<sizeof(vendor)/sizeof(vendor[0])+6;++k){fixture(&A,&B);memset(&C,0,sizeof(C));startup_count=1;
  if(k<sizeof(vendor)/sizeof(vendor[0])){startup_events[0][0]=0x1D;startup_events[0][1]=(unsigned char)vendor[k];startup_events[0][2]=0xA5;}
  else if(k==sizeof(vendor)/sizeof(vendor[0])+5){startup_events[0][0]=0x44;startup_events[0][1]=0x12;startup_events[0][2]=0x34;startup_events[0][3]=0x56;}
  else{unsigned g=k-(unsigned)(sizeof(vendor)/sizeof(vendor[0]));startup_events[0][0]=(unsigned char)(2|((unsigned[]){0,1,1,3,4}[g]<<2));startup_events[0][1]=(unsigned char)(g==2?1:g>2?0xFE:0);}
  memcpy(post_packet,startup_events[0],16);
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==0&&!C.Runtime.Events&&!C.Runtime.Polls&&C.Runtime.Startup.NonEmpty==2);
  CHECK(OnReleaseHardware(&C,&B)==0);
 }
 GROUP("EXP2_PRE_and_POST_ERROR_other_unknown_malformed_remain_strict");
 for(unsigned side=0;side<2;++side)for(unsigned k=0;k<8;++k){fixture(&A,&B);memset(&C,0,sizeof(C));startup_count=1;memcpy(startup_events[0],physical_fix5_packet,16);
  unsigned char *P=side?post_packet:startup_events[0];memset(P,0,16);P[0]=9;P[1]=1;
  switch(k){case 0:P[0]=5;P[7]=31;break;case 1:P[0]=0x15;break;case 2:P[0]=3;P[7]=31;break;case 3:P[0]=0x40;break;case 4:P[1]=0xFE;P[7]=31;break;case 5:P[0]=0x19;P[1]=0x45;break;case 6:P[0]=6;P[1]=2;break;case 7:P[0]=10;break;}
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_DEVICE_DATA_ERROR);
  unsigned why=(unsigned[]){N976nStartupChipError,N976nStartupUnknown,N976nStartupMalformed,N976nStartupMalformed,N976nStartupUnknown,N976nStartupUnknown,N976nStartupUnknown,N976nStartupUnknown}[k];
  CHECK(C.Runtime.Startup.Reason==why&&C.Runtime.Startup.Reads==side+1&&C.Runtime.Startup.ClearCompleted==side);
  if(!side&&(k==0||k==2))CHECK(!C.Runtime.Startup.ObservedPackets);
  CHECK(C.Runtime.Lifecycle.FirstStartupFailure.Rejected.Valid&&C.Runtime.Lifecycle.FirstStartupFailure.Rejected.Ordinal==side+1&&!memcmp(C.Runtime.Lifecycle.FirstStartupFailure.Rejected.Raw,P,16));
  N976N_STARTUP_EVIDENCE first=C.Runtime.Lifecycle.FirstStartupFailure;
  CHECK(OnReleaseHardware(&C,&B)==0&&OnPrepareHardware(&C,&A,&B)!=0&&!memcmp(&first,&C.Runtime.Lifecycle.FirstStartupFailure,sizeof(first)));
 }
 GROUP("EXP2_deadline_after_PRE_waits_retirement_no_sense_clear");
 fixture(&A,&B);memset(&C,0,sizeof(C));startup_clock_jump=6400000;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_IO_TIMEOUT);
 CHECK(C.Runtime.Startup.Reason==N976nStartupDeadline&&C.Runtime.Startup.Reads==1&&!C.Runtime.Startup.SenseAttempted&&!clear_seen&&!C.Runtime.Quarantined&&C.Runtime.Lifecycle.FirstStartFailure.Hsi.Retired==1);
 CHECK(OnReleaseHardware(&C,&B)==0);
 GROUP("EXP2_deadline_after_owned_sense_or_clear_keeps_completion_then_stops");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));after_write_jump=k?0x62:0x10;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_IO_TIMEOUT);
  CHECK(C.Runtime.Startup.Reason==N976nStartupDeadline&&C.Runtime.Startup.SenseCompleted==1&&C.Runtime.Startup.ClearCompleted==k&&!C.Runtime.Quarantined);
  CHECK(C.Runtime.Startup.Reads==1&&C.Runtime.Lifecycle.FirstStartFailure.Hsi.Retired==1&&OnReleaseHardware(&C,&B)==0);
 }
 GROUP("EXP2_PRE_partial_transfer_quarantine_preserves_original_bytes");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));startup_error_at=1;startup_error_after=k?5:0;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0);
  CHECK(C.Runtime.Startup.Reason==N976nStartupTransfer&&C.Runtime.Startup.Last.Bytes==startup_error_after&&C.Runtime.Quarantined&&!C.Runtime.Startup.SenseAttempted);
  savedWrites=writes;CHECK(OnReleaseHardware(&C,&B)==0&&writes==savedWrites);
 }
 GROUP("EXP2_clear_preflight_cancel_or_fresh_drift_distinguishes_attempted_not_issued");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));time_runtime=&C.Runtime;if(k)after_sense_drift=1;else after_sense_cancel=1;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0);
  CHECK(C.Runtime.Startup.Reason==N976nStartupClear&&C.Runtime.Startup.SenseCompleted==1&&C.Runtime.Startup.ClearAttempted==1&&!C.Runtime.Startup.ClearIssued&&!C.Runtime.Startup.ClearCompleted&&!clear_seen);
  if(k)CHECK(C.Runtime.Quarantined);CHECK(OnReleaseHardware(&C,&B)==0);
 }
 GROUP("EXP2_sense_or_clear_unretired_failure_no_retry_no_followup_chip_commands");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));fail_write_command=k?0x62:0x10;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0&&C.Runtime.Quarantined);
  CHECK(C.Runtime.Startup.Reason==(k?N976nStartupClear:N976nStartupSense)&&C.Runtime.Startup.Reads==1);
  CHECK((k?C.Runtime.Startup.ClearIssued:C.Runtime.Startup.SenseIssued)==1&&(k?C.Runtime.Startup.ClearCompleted:C.Runtime.Startup.SenseCompleted)==0);
  CHECK(!command_counts[0x11]);savedWrites=writes;CHECK(OnReleaseHardware(&C,&B)==0&&writes==savedWrites);
 }
 GROUP("EXP2_failed_sense_or_clear_but_retired_preserves_failure_and_bounded_cleanup");
 for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));fail_write_command=k?0x62:0x10;fail_write_retired=1;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0&&!C.Runtime.Quarantined);
  CHECK(C.Runtime.Startup.Reason==(k?N976nStartupClear:N976nStartupSense));
  CHECK((k?C.Runtime.Startup.ClearIssued:C.Runtime.Startup.SenseIssued)==1&&(k?C.Runtime.Startup.ClearCompleted:C.Runtime.Startup.SenseCompleted)==0);
  CHECK(C.Runtime.Lifecycle.FirstStartFailure.Hsi.Retired==1&&C.Runtime.Lifecycle.FirstStartFailure.Hsi.Status!=0&&C.Runtime.Startup.Reads==1);
  CHECK(command_counts[0x10]==1&&command_counts[0x62]==k&&command_counts[0x11]==1&&function_writes==2);
  CHECK(OnReleaseHardware(&C,&B)==0);
 }
 GROUP("EXP2_POST_partial_RX_keeps_PRE_and_clear_completion_separate_from_quarantine");
 fixture(&A,&B);memset(&C,0,sizeof(C));memcpy(post_packet,physical_fix5_packet,16);startup_error_at=2;startup_error_after=5;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0&&C.Runtime.Quarantined);
 CHECK(C.Runtime.Startup.InitPhase==N976nInitPost&&C.Runtime.Startup.ClearCompleted&&C.Runtime.Startup.Reads==2);
 CHECK(C.Runtime.Startup.First.Bytes==16&&C.Runtime.Startup.Rejected.Ordinal==2&&C.Runtime.Startup.Rejected.Bytes==5&&C.Runtime.Startup.Rejected.Decoded==-1);
 CHECK(!memcmp(C.Runtime.Startup.Rejected.Raw,physical_fix5_packet,5)&&!command_counts[0x11]);savedWrites=writes;
 CHECK(OnReleaseHardware(&C,&B)==0&&writes==savedWrites&&N976nStartupShape(&C.Runtime.Startup));
 GROUP("EXP2_live_app_function_checks_before_and_after_clear_fail_without_reset");
 for(unsigned side=1;side<=2;++side)for(unsigned k=0;k<2;++k){fixture(&A,&B);memset(&C,0,sizeof(C));if(k)post_function_fault=side;else post_app_fault=side;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0);
  CHECK(C.Runtime.Startup.Reason==(k?N976nStartupFunctionState:N976nStartupAppState)&&C.Runtime.Startup.ClearCompleted==side-1&&C.Runtime.Startup.Reads==1);
  CHECK((side==1?C.Runtime.Startup.PreChecks:C.Runtime.Startup.PostChecks)==(k?7U:1U));
  if(!k){CHECK(C.Runtime.Quarantined&&function_writes==1&&!command_counts[0x11]);savedWrites=writes;}
  else CHECK(!C.Runtime.Quarantined&&function_writes==2);
  CHECK(OnReleaseHardware(&C,&B)==0);if(!k)CHECK(writes==savedWrites);
 }
 GROUP("EXP2_fresh_clock_drift_after_clear_quarantines_before_post_IO");
 fixture(&A,&B);memset(&C,0,sizeof(C));after_clear_drift=1;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)!=0&&C.Runtime.Quarantined);
 CHECK(C.Runtime.Startup.ClearCompleted==1&&C.Runtime.Startup.Reason==N976nStartupAppState&&C.Runtime.Startup.PostChecks==1&&C.Runtime.Startup.Reads==1);
 savedWrites=writes;CHECK(OnReleaseHardware(&C,&B)==0&&writes==savedWrites);
 GROUP("EXP2_POST_cancellation_after_natural_retirement_never_activates_HID");
 fixture(&A,&B);memset(&C,0,sizeof(C));time_runtime=&C.Runtime;startup_cancel_at=2;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&OnD0Entry(&C,0)==STATUS_CANCELLED);
 CHECK(C.Runtime.Startup.InitPhase==N976nInitPost&&C.Runtime.Startup.ClearCompleted&&C.Runtime.Startup.Reads==2);
 CHECK(C.Runtime.Lifecycle.FirstStartFailure.Hsi.Retired==1&&C.Runtime.Lifecycle.FirstStartFailure.Stage==25&&!C.Runtime.Events&&!C.Runtime.Polls);
 CHECK(OnReleaseHardware(&C,&B)==0);
 GROUP("EXP2_shape_and_CRC_valid_registry_corruption_fail_closed");
 for(unsigned k=0;k<21;++k){N976N_STARTUP_EVIDENCE V=observed;
  switch(k){case 0:V.Reads=3;break;case 1:V.FirstObservedMask=4;break;case 2:V.FirstUnknownVendor.Valid=0;break;case 3:V.ClearIssued=0;break;case 4:V.ClearAttempted=0;break;
   case 5:V.ClearStatus=1;break;case 6:V.SenseCompleted=0;break;case 7:V.PreChecks=16;break;case 8:V.InitPhase=8;break;case 9:V.PostChecks=7;break;
   case 10:V.FirstUnknownVendor.Id=V.FirstUnknownVendor.Raw[1]=0x40;break;case 11:V.Empty=3;break;case 12:V.ClearCompleted=2;break;case 13:V.PreAppStatus=1;break;case 14:V.AppValue=0x10;break;
   case 15:V.FunctionValue^=2;break;case 16:V.FunctionStatus=1;break;case 17:V.TransferStatus=1;break;
   case 18:V.Last.Bytes=15;break;case 19:V.InitPhase=N976nInitPre;break;case 20:V.First.Ordinal=2;break;}
  CHECK(!N976nStartupShape(&V));fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;registry_lifecycle.FirstStartup=V;
  registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);life_present=1;N976N_DEMO_LIFECYCLE bad=registry_lifecycle;
  CHECK(OnPrepareHardware(&C,&A,&B)==0&&!C.Runtime.LifeCanPublish&&!life_writes);
  CHECK(OnReleaseHardware(&C,&B)==0&&!memcmp(&bad,&registry_lifecycle,sizeof(bad)));
 }
 GROUP("EXP2_old_lifecycle_version_preserved_without_import_or_overwrite");
 fixture(&A,&B);memset(&C,0,sizeof(C));registry_lifecycle=prior_boot;registry_lifecycle.Version=3;
 registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);life_present=1;N976N_DEMO_LIFECYCLE old=registry_lifecycle;
 CHECK(OnPrepareHardware(&C,&A,&B)==0&&!C.Runtime.LifeCanPublish&&!life_writes);
 CHECK(OnReleaseHardware(&C,&B)==0&&!memcmp(&old,&registry_lifecycle,sizeof(old)));

 GROUP("EXP6_single_and_double_retired_NODEV_recover_exact16_with_pending_gap");
 for(unsigned n=1;n<=2;++n){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));retry_faults=n;
  CHECK(!N976nDemoReadEvent(&R,E)&&R.Stage==29&&!R.Quarantined&&R.Polls==n+1);
  CHECK(retry_delay_count==n&&R.Lifecycle.Recovery.Retries==n&&R.Lifecycle.Recovery.Recovered==1&&R.Lifecycle.Recovery.GapPending);
  CHECK(R.Lifecycle.Recovery.FirstTransient.Hsi.FirstFailure.Interrupt==0x400&&R.Lifecycle.Recovery.LastAttempt.Hsi.RxBytes==16);
  CHECK(N976nRecoveryShape(&R.Lifecycle.Recovery));
  N976N_HSI_RESULT eligible=R.Lifecycle.Recovery.FirstTransient.Hsi;
  eligible.Boundary[0].Pending=0;eligible.Boundary[0].Valid&=~N976nBoundaryAckAttempt;CHECK(N976nEventNodev(&eligible));
  eligible.Boundary[2].Pending|=0x200;CHECK(!N976nEventNodev(&eligible));savedWrites=writes;
  CHECK(N976nDemoReadEvent(&R,E)==STATUS_DEVICE_BUSY&&writes==savedWrites&&R.Lifecycle.Recovery.GapPending);
  R.Lifecycle.Recovery.GapPending=0;N976nDemoRecord(&R);CHECK(registry_lifecycle.Recovery.Recovered==1);
  N976nDemoRelease(&R);
 }
 GROUP("EXP6_three_total_attempts_exhaust_preserves_first_and_last_without_reset");
 fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));retry_faults=9;
 CHECK(N976nDemoReadEvent(&R,E)==STATUS_DEVICE_HARDWARE_ERROR&&R.Stage==90&&!R.Quarantined);
 CHECK(R.Polls==3&&retry_delay_count==2&&retry_faults==6&&R.Lifecycle.Recovery.Exhausted==1&&!R.Lifecycle.Recovery.GapPending);
 CHECK(R.Lifecycle.FirstFailure.Hsi.FirstFailure.Interrupt==0x400&&N976nRecoveryShape(&R.Lifecycle.Recovery));
 N976N_LIFECYCLE_STATE transient=R.Lifecycle.Recovery.FirstTransient;N976nDemoRecord(&R);N976nDemoRelease(&R);
 CHECK(!memcmp(&transient,&R.Lifecycle.Recovery.FirstTransient,sizeof(transient)));
 GROUP("EXP6_partial_RX_other_mixed_and_late_retirement_errors_never_retry");
 for(unsigned k=0;k<5;++k){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));retry_faults=1;
  if(k==0)retry_partial=1;if(k==1)retry_bits=0x200;if(k==2)retry_bits=0x600;if(k==3)retry_late_bits=0x200;if(k==4)retry_bits=0x480;
  CHECK(N976nDemoReadEvent(&R,E)==STATUS_DEVICE_HARDWARE_ERROR&&R.Stage==90&&R.Polls==1&&!retry_delay_count&&!R.Lifecycle.Recovery.Faults);
  N976nDemoRelease(&R);
 }
 GROUP("EXP6_cancel_owner_drift_and_delay_failure_block_retry");
 for(unsigned k=1;k<=4;++k){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));retry_faults=1;retry_delay_mode=k;
  unsigned before=runs;CHECK(!NT_SUCCESS(N976nDemoReadEvent(&R,E))&&R.Stage==90&&runs==before+2&&retry_delay_count==1);
  CHECK(R.Lifecycle.Recovery.Outcome==N976nRecoveryAborted&&R.Lifecycle.Recovery.LastAttempt.HsiCurrent==0&&N976nRecoveryShape(&R.Lifecycle.Recovery));
  CHECK(R.Lifecycle.FirstFailure.Hsi.FirstFailure.Interrupt==0x400);
  retry_delay_mode=0;N976nDemoRelease(&R);
 }
 GROUP("EXP6_first_transient_immutable_across_later_recovery_and_terminal");
 fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));retry_faults=1;
 CHECK(!N976nDemoReadEvent(&R,E));transient=R.Lifecycle.Recovery.FirstTransient;R.Lifecycle.Recovery.GapPending=0;
 retry_faults=1;CHECK(!N976nDemoReadEvent(&R,E));R.Lifecycle.Recovery.GapPending=0;
 retry_faults=4;CHECK(!NT_SUCCESS(N976nDemoReadEvent(&R,E))&&R.Lifecycle.Recovery.Recovered==2&&R.Lifecycle.Recovery.Exhausted==1);
 CHECK(!memcmp(&transient,&R.Lifecycle.Recovery.FirstTransient,sizeof(transient))&&N976nRecoveryShape(&R.Lifecycle.Recovery));
 N976nDemoRecord(&R);N976nDemoRelease(&R);
 GROUP("EXP6_CRC_valid_malformed_recovery_refused_on_registry_import");
 N976N_DEMO_LIFECYCLE recovery_saved=registry_lifecycle;
 for(unsigned k=0;k<6;++k){fixture(&A,&B);memset(&R,0,sizeof(R));registry_lifecycle=recovery_saved;life_present=1;
  if(k==0)registry_lifecycle.Recovery.Attempt=4;if(k==1)registry_lifecycle.Recovery.GapPending=2;
  if(k==2)registry_lifecycle.Recovery.FirstTransient.Hsi.RxBytes=1;if(k==3)registry_lifecycle.Recovery.LastAttempt.Reserved=1;
  if(k==4)registry_lifecycle.Recovery.Outcome=99;if(k==5)registry_lifecycle.Version=7;
  registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&R.Lifecycle.RegistryState==N976nLifeRegistryMalformed);N976nDemoRelease(&R);
 }

 GROUP("EXP8_actual_runtime_tail16_and480_exact_owned_storage");
 for(unsigned n=1;n<=30;n+=29){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
  memset(((UCHAR*)R.EventBatch)+16,0xA5,480);for(unsigned j=0;j<n*16;++j)tail_packet[j]=(unsigned char)j;
  CHECK(!N976nDemoReadTail(&R,n)&&!memcmp(((UCHAR*)R.EventBatch)+16,tail_packet,n*16));
  CHECK(R.EventBatch[0][0]==0x44&&R.Last.RxBytes==n*16&&R.Last.Wait.Requested==n*16&&command_counts[0x61]==1);
  if(n<30)CHECK(R.EventBatch[n+1][0]==0xA5);
  CHECK(N976nEventServiceShape(&R.Lifecycle.Service));N976nDemoRelease(&R);
 }
 GROUP("EXP8_actual_runtime_tail_rejects0_31_and_pending_gap_before_MMIO");
 fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));
 savedWrites=writes;CHECK(N976nDemoReadTail(&R,0)==STATUS_INVALID_PARAMETER&&N976nDemoReadTail(&R,31)==STATUS_INVALID_PARAMETER&&writes==savedWrites);
 R.Lifecycle.Recovery.GapPending=1;CHECK(N976nDemoReadTail(&R,1)==STATUS_INVALID_PARAMETER&&N976nDemoClearEvents(&R)==STATUS_DEVICE_BUSY&&writes==savedWrites);R.Lifecycle.Recovery.GapPending=0;N976nDemoRelease(&R);
 GROUP("EXP8_actual_READ_ALL_NODEV0_deferred_partial_fatal_without_retry");
 for(unsigned partial=0;partial<=1;++partial){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
  R.EventBatch[0][7]=30;retry_faults=3;retry_partial=partial;CHECK(N976nDemoReadTail(&R,30)==STATUS_DEVICE_HARDWARE_ERROR&&R.Stage==(partial?90:29));
  CHECK(!retry_delay_count&&retry_faults==2&&command_counts[0x61]==1&&R.Last.RxBytes==partial);
  CHECK(R.Lifecycle.Tail.GapPending==!partial&&N976nTailRecoveryShape(&R.Lifecycle.Tail));
  if(partial)CHECK(R.Lifecycle.FirstFailure.Command==0x61&&R.Lifecycle.FirstFailure.Hsi.Wait.Requested==480);
  else CHECK(!R.Lifecycle.FirstFailure.Valid&&R.Lifecycle.Tail.FirstDeferred.State.Status==(ULONG)STATUS_DEVICE_HARDWARE_ERROR);
  N976nDemoRelease(&R);
 }
 GROUP("EXP8_actual_overflow_clear_is_one_checked_command_or_fatal_no_retry");
 for(unsigned fail=0;fail<2;++fail){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
  unsigned before=command_counts[0x62];if(fail){fail_write_command=0x62;fail_write_retired=1;}
  S=N976nDemoClearEvents(&R);CHECK(NT_SUCCESS(S)==!fail&&command_counts[0x62]==before+1&&!retry_delay_count);
  CHECK(R.Lifecycle.Service.ClearAttempts==1&&R.Lifecycle.Service.Cleared==!fail&&N976nEventServiceShape(&R.Lifecycle.Service));N976nDemoRelease(&R);
 }
 GROUP("EXP8_CRC_valid_service_shape_rejects_count_length_and_old_ABI");
 fixture(&A,&B);memset(&R,0,sizeof(R));CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0])&&!N976nDemoReadTail(&R,30));N976nDemoRecord(&R);N976nDemoRelease(&R);
 N976N_DEMO_LIFECYCLE service_saved=registry_lifecycle;
 for(unsigned k=0;k<5;++k){fixture(&A,&B);memset(&R,0,sizeof(R));registry_lifecycle=service_saved;life_present=1;
  if(k==0)registry_lifecycle.Service.LastCount=32;if(k==1)registry_lifecycle.Service.LastBytes=496;
  if(k==2)registry_lifecycle.Service.ReadAll=registry_lifecycle.Service.ReadOne+1;if(k==3)registry_lifecycle.Service.Cleared=2;if(k==4)registry_lifecycle.Version=8;
  registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&R.Lifecycle.RegistryState==N976nLifeRegistryMalformed);N976nDemoRelease(&R);
 }
 GROUP("EXP8_failed61_first2_defer_third_terminal_original_fault_distinct_no_replay");
 fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));
 N976N_TAIL_FAULT first_tail={0};
 for(unsigned k=1;k<=3;++k){
  CHECK(!N976nDemoReadEvent(&R,R.EventBatch[0]));R.EventBatch[0][7]=30;R.EventBatch[0][1]=(UCHAR)k;
  retry_faults=1;CHECK(N976nDemoReadTail(&R,30)==STATUS_DEVICE_HARDWARE_ERROR);
  CHECK(command_counts[0x61]==k&&!retry_delay_count&&R.Lifecycle.Tail.Streak==k&&R.Lifecycle.Tail.Faults==k);
  CHECK(R.Lifecycle.Tail.LastFailure.Ordinal==k&&R.Lifecycle.Tail.LastFailure.FirstPacket[1]==k&&N976nTailRecoveryShape(&R.Lifecycle.Tail));
  if(k==1)first_tail=R.Lifecycle.Tail.FirstDeferred;
  CHECK(!memcmp(&first_tail,&R.Lifecycle.Tail.FirstDeferred,sizeof(first_tail)));
  if(k<3){unsigned wr=writes;CHECK(R.Stage==29&&!R.Lifecycle.FirstFailure.Valid&&R.Lifecycle.Tail.GapPending);
   CHECK(N976nDemoReadEvent(&R,E)==STATUS_DEVICE_BUSY&&N976nDemoClearEvents(&R)==STATUS_DEVICE_BUSY&&writes==wr);
   R.Lifecycle.Tail.GapPending=0;
  }else CHECK(R.Stage==90&&R.Lifecycle.FirstFailure.Command==0x61&&R.Lifecycle.Tail.Deferred==2&&R.Lifecycle.Tail.Fatal==1&&R.Lifecycle.Tail.Decision==N976nTailLimit);
 }
 N976nDemoRecord(&R);N976N_DEMO_LIFECYCLE tail_saved=registry_lifecycle;N976nDemoRelease(&R);
 GROUP("EXP8_failed61_fresh_owner_cancel_rejections_are_terminal_and_owner_fresh_quarantine");
 for(unsigned k=1;k<=3;++k){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
  R.EventBatch[0][7]=1;retry_faults=1;tail_fresh_hook=k;
  CHECK(N976nDemoReadTail(&R,1)==STATUS_DEVICE_HARDWARE_ERROR&&R.Stage==90&&!R.Lifecycle.Tail.Deferred&&!R.Lifecycle.Tail.GapPending);
  CHECK(R.Lifecycle.Tail.Decision==(k==1?N976nTailCancelled:k==2?N976nTailOwner:N976nTailFresh));
  CHECK(R.Quarantined==(k!=1)&&N976nTailRecoveryShape(&R.Lifecycle.Tail));
  unsigned wr=writes;if(k!=1){CHECK(N976nDemoStop(&R)==STATUS_DEVICE_HARDWARE_ERROR&&writes==wr);}
  N976nDemoRelease(&R);
 }
 GROUP("EXP8_failed61_other_error_partial_late_error_timeout_never_defer");
 for(unsigned k=0;k<5;++k){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
  R.EventBatch[0][7]=2;retry_faults=k==4?0:1;retry_bits=k==0?0x200:k==1?0x480:0x400;
  retry_partial=k==2?1:0;retry_late_bits=k==3?0x200:0;injectTimeout=k==4;
  CHECK(N976nDemoReadTail(&R,2)!=0&&R.Stage==90&&!R.Lifecycle.Tail.Deferred&&!R.Lifecycle.Tail.GapPending&&command_counts[0x61]==1&&!retry_delay_count);
  CHECK(N976nTailRecoveryShape(&R.Lifecycle.Tail));N976nDemoRelease(&R);
 }
 GROUP("EXP8_validated_batch_resumption_resets_streak_only_at_explicit_producer_boundary");
 fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!N976nDemoReadEvent(&R,R.EventBatch[0]));
 R.EventBatch[0][7]=1;retry_faults=1;CHECK(N976nDemoReadTail(&R,1)!=0&&R.Lifecycle.Tail.Streak==1);
 N976nDemoValidatedBatch(&R);CHECK(R.Lifecycle.Tail.Streak==1&&!R.Lifecycle.Tail.Resumed);R.Lifecycle.Tail.GapPending=0;
 CHECK(!N976nDemoReadEvent(&R,R.EventBatch[0])&&R.Lifecycle.Tail.Streak==1);N976nDemoValidatedBatch(&R);
 CHECK(!R.Lifecycle.Tail.Streak&&R.Lifecycle.Tail.Resumed==1&&!R.Lifecycle.Tail.AwaitingFresh&&R.Lifecycle.Tail.ResumeOrdinal==2&&R.Status==0);
 CHECK(N976nTailRecoveryShape(&R.Lifecycle.Tail));N976nDemoValidatedBatch(&R);CHECK(R.Lifecycle.Tail.Resumed==1);N976nDemoRelease(&R);
 GROUP("EXP8_CRC_valid_tail_shape_rejects_partial_context_streak_gap_and_old_ABI");
 for(unsigned k=0;k<8;++k){fixture(&A,&B);memset(&R,0,sizeof(R));registry_lifecycle=tail_saved;life_present=1;
  if(k==0)registry_lifecycle.Tail.FirstDeferred.State.Hsi.RxBytes=1;
  if(k==1)registry_lifecycle.Tail.FirstDeferred.Requested=496;
  if(k==2)registry_lifecycle.Tail.LastFailure.FirstPacket[7]=0;
  if(k==3)registry_lifecycle.Tail.Streak=4;
  if(k==4)registry_lifecycle.Tail.GapPending=1;
  if(k==5)registry_lifecycle.Tail.Disposition=N976nTailResumed;
  if(k==6)registry_lifecycle.Tail.LastFailure.State.Command=0x60;
  if(k==7)registry_lifecycle.Version=9;
  registry_lifecycle.Crc32=N976nDemoLifecycleCrc(&registry_lifecycle);
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&R.Lifecycle.RegistryState==N976nLifeRegistryMalformed);N976nDemoRelease(&R);
 }
 GROUP("EXP9_alive_resource_requires_RO_NVS_stays_index5_and_old6_rejected");
 for(unsigned k=0;k<4;++k){fixture(&A,&B);memset(&R,0,sizeof(R));
  if(k==0)A.Count=B.Count=6;
  if(k==1)A.Item[6].Flags=B.Item[6].Flags=0;
  if(k==2)A.Item[6].u.Memory.Length=B.Item[6].u.Memory.Length=8192;
  if(k==3){N976N_TOUCH_HANDOFF *H=(void*)page.bytes;H->Version=1;H->Crc32=N976nDemoCrc(H);}
  CHECK(N976nDemoPrepare(&R,(void*)1,&A,&B)!=0&&mapped==unmapped&&!writes);
 }
 GROUP("EXP9_HIGH_skip_preserves_error_streak_and_has_no_I2C_or_DAT_startup_gate");
 fixture(&A,&B);memset(&R,0,sizeof(R));regs[6][0x24/4]=1;
 CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R)&&!R.Lifecycle.Ready.Checks);
 R.Status=STATUS_DEVICE_HARDWARE_ERROR;R.Lifecycle.Tail.Streak=1;BOOLEAN ready=TRUE;unsigned wr=writes,rdone=command_counts[0x60];
 CHECK(!N976nDemoEventReady(&R,&ready)&&!ready&&writes==wr&&command_counts[0x60]==rdone);
 CHECK(R.Status==(ULONG)STATUS_DEVICE_HARDWARE_ERROR&&R.Lifecycle.Tail.Streak==1&&!R.Lifecycle.Service.ReadOne&&R.Lifecycle.Ready.HighSkip==1&&N976nReadyShape(&R.Lifecycle.Ready));
 GROUP("EXP9_LOW_service_and_first_last_error_entry_samples_no_gate_inside_retry_or_tail");
 regs[6][0x24/4]=0x20;CHECK(!N976nDemoEventReady(&R,&ready)&&ready);R.Lifecycle.Tail.Streak=0;
 retry_faults=1;time_runtime=&R;CHECK(!N976nDemoReadEvent(&R,R.EventBatch[0])&&retry_delay_count==1&&R.Lifecycle.Ready.Checks==2);
 CHECK(R.Lifecycle.Ready.FirstErrorValid&&R.Lifecycle.Ready.FirstErrorRaw==0x20&&R.Lifecycle.Ready.LastErrorRaw==0x20);
 R.Lifecycle.Recovery.GapPending=0;R.EventBatch[0][7]=1;retry_faults=1;
 CHECK(N976nDemoReadTail(&R,1)==STATUS_DEVICE_HARDWARE_ERROR&&R.Lifecycle.Ready.Checks==2&&R.Lifecycle.Tail.GapPending);
 R.Lifecycle.Tail.GapPending=0;regs[6][0x24/4]=0x40;CHECK(!N976nDemoEventReady(&R,&ready)&&ready);
 retry_faults=1;CHECK(!N976nDemoReadEvent(&R,E)&&R.Lifecycle.Ready.FirstErrorRaw==0x20&&R.Lifecycle.Ready.LastErrorRaw==0x40&&N976nReadyShape(&R.Lifecycle.Ready));N976nDemoRelease(&R);
 GROUP("EXP9_gate_pre_cancel_and_pending_gap_do_not_read_or_write");
 fixture(&A,&B);memset(&R,0,sizeof(R));CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));
 unsigned re=reads;wr=writes;R.StopRequested=1;R.HsiCurrent=1;CHECK(N976nDemoEventReady(&R,&ready)==STATUS_CANCELLED&&!ready&&reads==re&&writes==wr&&R.HsiCurrent==0&&R.CurrentCommand==0x60);
 R.StopRequested=0;R.Lifecycle.Tail.GapPending=1;R.HsiCurrent=1;CHECK(N976nDemoEventReady(&R,&ready)==STATUS_DEVICE_BUSY&&reads==re&&writes==wr&&R.HsiCurrent==0);R.Lifecycle.Tail.GapPending=0;N976nDemoRelease(&R);
 GROUP("EXP9_gate_inaccessible_stale_owner_and_cancel_fail_closed_no_new_bus_writes");
 for(unsigned k=0;k<7;++k){fixture(&A,&B);memset(&R,0,sizeof(R));time_runtime=&R;
  CHECK(!N976nDemoPrepare(&R,(void*)1,&A,&B)&&!N976nDemoStart(&R));wr=writes;
  if(k==0)regs[6][0x24/4]=~0U;if(k==1)regs[6][0x20/4]=0;
  if(k==2)regs[6][0x28/4]=1;if(k==3)regs[6][0x904/4]=0;
  if(k==4)((N976N_TOUCH_HANDOFF*)page.bytes)->ClaimState=2;
  if(k>=5)ready_hook=k-4;
  CHECK(N976nDemoEventReady(&R,&ready)!=0&&!ready&&writes==wr&&R.Stage==90&&R.HsiCurrent==0&&R.Lifecycle.Ready.Rejected==1);
  CHECK(R.Quarantined==(k!=5)&&N976nReadyShape(&R.Lifecycle.Ready));
  if(k!=5){CHECK(N976nDemoStop(&R)!=0&&writes==wr);}N976nDemoRelease(&R);
 }
 GROUP("EXP9_ready_evidence_CRC_shape_rejects_impossible_sample_and_old_ABI");
 N976N_EVENT_READY rr={2,1,1,0,1,1,1,0x20,1,0x20};CHECK(N976nReadyShape(&rr));
 for(unsigned k=0;k<6;++k){N976N_EVENT_READY q=rr;if(k==0)q.Low=3;if(k==1)q.LastValid=0;if(k==2)q.LastRaw=~0U;if(k==3)q.FirstErrorRaw=1;if(k==4)q.LastErrorValid=2;if(k==5)q.Checks=0;CHECK(!N976nReadyShape(&q));}
 run_tail_timeout_cases();
 fprintf(stderr,"DIAGNOSTIC_SIZES %zu %zu %zu\n",sizeof(N976N_HSI_RESULT),sizeof(N976N_LIFECYCLE_STATE),sizeof(N976N_DEMO_LIFECYCLE));
 printf("PASS %u groups\n",groups);return 0;}
#endif
