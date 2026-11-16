/* Executes the actual generic transfer grammar, not a reimplemented engine. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "N976nHsi2c.h"
static unsigned groups;
#define CHECK(x)do{if(!(x)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#x);exit(1);}}while(0)
#define GROUP(x)do{puts(x);++groups;}while(0)
typedef struct{uint32_t r[64];unsigned len,done,read,runs,acks,tx,rx,writes,reads;uint8_t sent[3],received[480];uint64_t time;unsigned fail,mode,full_seen;}MODEL;
static void tick(MODEL*M){
 if(!M->len)return;
 if(M->done<M->len){M->r[0x24/4]=0;M->r[0x50/4]=0x2000A;M->r[0x30/4]=M->read?0x100:0x01000100;}
 else{M->r[0x24/4]=0x80;M->r[0x50/4]=1;M->r[0x30/4]=0x01000100;M->r[0x44/4]&=~0x80000000U;}
 if(M->mode==1&&M->read&&M->done==M->len-1){M->r[0x24/4]=0;M->r[0x30/4]=0x01000100;}
 if((M->mode==2||M->mode==4)&&M->read&&M->done==M->len)M->r[0x30/4]=0x100;
 /* Live SEC87 sample: request112, RX28, FULL+level64, no IRQ error.
  * Drain this 64-byte occupancy before the remaining20 arrive. This models
  * occupancy, not real controller timing or physical clock stretching. */
 if(M->mode>=3&&M->mode<=5&&M->read&&M->done>=28&&M->done<92){
  unsigned level=92-M->done;
  M->r[0x30/4]=0x100|(level<<16)|(level==64?0x800000:0);
  M->r[0x50/4]=0xA000B;
  if(level==64)++M->full_seen;
  if(M->mode==5&&M->done==28)M->r[0x24/4]=0x20; /* actual RX_OVERRUN */
 }
}
static int read32(void*C,uint32_t O,uint32_t*V){MODEL*M=C;++M->reads;CHECK(O<0x100&&!(O&3));if(O==0x24)tick(M);
 if(O==0x38){CHECK(M->read&&M->done<M->len&&M->done<480);*V=0xDEAD0000U|M->received[M->done++];++M->rx;return 1;}
 *V=M->r[O/4];return 1;}
static int write32(void*C,uint32_t O,uint32_t V){MODEL*M=C;++M->writes;CHECK(O==0||O==4||O==0x20||O==0x24||O==0x34||O==0x44||O==0x70);CHECK(!(O==0&&(V&0x80000000U)));
 if(O==0x34){CHECK(!M->read&&M->done<M->len&&M->tx<3);M->sent[M->tx++]=(uint8_t)V;++M->done;return 1;}
 if(O==0x24){CHECK(V==M->r[O/4]&&V==0x80);M->r[O/4]=0;M->len=0;++M->acks;return 1;}
 M->r[O/4]=V;if(O==0x44&&(V&0x80000000U)){CHECK(V&0x20000);M->len=V&0xFFFF;M->read=(V&0x10000)!=0;M->done=0;++M->runs;}return 1;}
static uint64_t now(void*C){return ((MODEL*)C)->time+=10;}
static int own(void*C,uint64_t G){(void)C;CHECK(G==17);return 1;}
static void setup(MODEL*M,N976N_HSI_IO*I,N976N_HSI_LEASE*L){memset(M,0,sizeof(*M));M->r[0x30/4]=0x01000100;M->r[0x50/4]=1;M->r[0x40/4]=0x80000000;M->r[0]=8;M->r[8/4]=0xFFFFFF;M->r[0x60/4]=0xFC0000;M->r[0x64/4]=0xF8;M->r[0x68/4]=0x3E0000;for(unsigned n=0;n<480;++n)M->received[n]=(uint8_t)(0x40+n);*I=(N976N_HSI_IO){M,read32,write32,now,own,NULL};*L=(N976N_HSI_LEASE){17,0x104B0000,0x1000,100000000,127,0x48,100000,0xFC0000,0xF8,0x3E0000,0,0xFFFFFF};}
int main(void){MODEL M;N976N_HSI_IO I;N976N_HSI_LEASE L;N976N_HSI_RESULT R;uint8_t D[482];
 GROUP("read_id_status_function_event_exact_lengths_and_two_STOPs");
 const unsigned command[]={0x52,0x55,0x30,0x60},length[]={3,1,2,16};
 for(unsigned n=0;n<4;++n){setup(&M,&I,&L);memset(D,0xA5,sizeof(D));CHECK(N976nHsiCommand(&I,&L,(uint8_t)command[n],1,D+1,length[n],&R)==0);CHECK(M.runs==2&&M.acks==2&&M.sent[0]==command[n]&&M.tx==1&&M.rx==length[n]&&R.Retired&&!R.Quarantined);CHECK(D[0]==0xA5&&D[length[n]+1]==0xA5);for(unsigned j=0;j<length[n];++j)CHECK(D[j+1]==0x40+j);}
 GROUP("function_write_exact_command_and_two_payload_bytes");setup(&M,&I,&L);D[0]=0x61;D[1]=0;
 CHECK(N976nHsiCommand(&I,&L,0x30,0,D,2,&R)==0);CHECK(M.runs==1&&M.acks==1&&M.tx==3&&M.sent[0]==0x30&&M.sent[1]==0x61&&M.sent[2]==0&&R.Retired);
 GROUP("sense_on_off_have_no_receive_or_payload");for(unsigned n=0x10;n<=0x11;++n){setup(&M,&I,&L);CHECK(N976nHsiCommand(&I,&L,(uint8_t)n,0,NULL,0,&R)==0);CHECK(M.runs==1&&M.tx==1&&M.rx==0&&M.sent[0]==n&&R.Retired);}
 GROUP("clear_event_stack_is_exact_one_command_byte_zero_payload_no_RX");setup(&M,&I,&L);
 CHECK(N976nHsiCommand(&I,&L,0x62,0,NULL,0,&R)==0);CHECK(M.runs==1&&M.acks==1&&M.tx==1&&!M.rx&&M.sent[0]==0x62&&R.MessagesIssued==1&&R.TxBytes==1&&!R.RxBytes&&R.Retired&&!R.Quarantined);
 GROUP("all_other_command_length_direction_tuples_rejected_without_IO");
 for(unsigned c=0;c<256;++c)for(unsigned dir=0;dir<3;++dir)for(unsigned n=0;n<=17;++n){
  unsigned ok=(dir==1&&((c==0x52&&n==3)||(c==0x55&&n==1)||(c==0x30&&n==2)||(c==0x60&&n==16)||(c==0x61&&n==16)))||(dir==0&&(((c==0x10||c==0x11||c==0x62)&&n==0)||(c==0x30&&n==2)));
  if(ok)continue;setup(&M,&I,&L);CHECK(N976nHsiCommand(&I,&L,(uint8_t)c,(int)dir,D,n,&R)==N976nHsiInvalid);CHECK(!M.reads&&!M.writes&&!M.runs);
 }
 GROUP("event_short_read_times_out_and_does_not_claim_success");setup(&M,&I,&L);M.mode=1;CHECK(N976nHsiCommand(&I,&L,0x60,1,D,16,&R)!=0);CHECK(R.RxBytes==15&&!R.IdValid);
 GROUP("event_excess_is_quarantined_without_extra_dequeue");setup(&M,&I,&L);M.mode=2;CHECK(N976nHsiCommand(&I,&L,0x60,1,D,16,&R)==N976nHsiExcess);CHECK(M.rx==16&&R.Quarantined);

 GROUP("EXP8_READ_ALL_exact16_to480_bytes_two_STOPs_canaries_and_min8_FIFO");
 for(unsigned count=16;count<=480;count+=16){setup(&M,&I,&L);memset(D,0xA5,sizeof(D));
  CHECK(!N976nHsiCommand(&I,&L,0x61,1,D+1,count,&R));
  CHECK(M.runs==2&&M.acks==2&&M.sent[0]==0x61&&R.TxBytes==1&&R.RxBytes==count&&R.Retired&&!R.Quarantined);
  CHECK(D[0]==0xA5&&D[count+1]==0xA5&&!memcmp(D+1,M.received,count));
  CHECK(M.r[4/4]==(3U|(8U<<4)|(8U<<16))&&(M.r[0x44/4]&65535)==count);
 }
 GROUP("EXP8_READ_ALL_bad_length_direction_rejected_before_buffer_or_IO");
 const unsigned bad[]={0,1,15,17,31,479,481,496,512,0xffffffffU};
 for(unsigned n=0;n<sizeof(bad)/sizeof(bad[0]);++n){setup(&M,&I,&L);memset(D,0xA5,sizeof(D));
  CHECK(N976nHsiCommand(&I,&L,0x61,1,D,bad[n],&R)==N976nHsiInvalid&&!M.reads&&!M.writes&&D[0]==0xA5);
 }
 GROUP("EXP8_READ_ALL_partial_timeout_and_excess_never_claim_full_completion");
 for(unsigned mode=1;mode<=2;++mode){setup(&M,&I,&L);M.mode=mode;
  CHECK(N976nHsiCommand(&I,&L,0x61,1,D,480,&R)!=0&&R.RxBytes==(mode==1?479:480)&&R.Quarantined);
 }
 GROUP("EXP8_existing16_byte_READ_ONE_uses_source_trigger8_not_transfer_length");
 setup(&M,&I,&L);CHECK(!N976nHsiCommand(&I,&L,0x60,1,D,16,&R));CHECK(M.r[4/4]==0x80083&&R.RxBytes==16);
 GROUP("SEC87_live112B_RX28_FULL64_drains_exact_payload_and_retires");
 setup(&M,&I,&L);M.mode=3;memset(D,0xA5,sizeof(D));
 CHECK(N976nHsiCommand(&I,&L,0x61,1,D+1,112,&R)==N976nHsiOk);
 CHECK(M.full_seen==1&&M.rx==112&&R.RxBytes==112&&M.acks==2&&R.Retired&&!R.Quarantined);
 CHECK(D[0]==0xA5&&D[113]==0xA5&&!memcmp(D+1,M.received,112));
 GROUP("SEC87_FULL_does_not_authorize_byte113_or_write_past_canary");
 setup(&M,&I,&L);M.mode=4;memset(D,0xA5,sizeof(D));
 CHECK(N976nHsiCommand(&I,&L,0x61,1,D+1,112,&R)==N976nHsiExcess);
 CHECK(M.full_seen==1&&M.rx==112&&R.RxBytes==112&&R.Quarantined&&!R.Retired);
 CHECK(D[0]==0xA5&&D[113]==0xA5&&!memcmp(D+1,(uint8_t[112]){0},112));
 GROUP("SEC87_FULL_with_real_RX_OVERRUN_stops_before_next_dequeue");
 setup(&M,&I,&L);M.mode=5;memset(D,0xA5,sizeof(D));
 CHECK(N976nHsiCommand(&I,&L,0x61,1,D+1,112,&R)==N976nHsiController);
 CHECK(M.full_seen&&M.rx==28&&R.RxBytes==28&&R.FirstFailure.Interrupt==0x20);
 CHECK(R.Quarantined&&!R.Retired&&M.acks==1&&D[29]==0&&D[113]==0xA5);
 printf("PASS %u groups\n",groups);return 0;}
