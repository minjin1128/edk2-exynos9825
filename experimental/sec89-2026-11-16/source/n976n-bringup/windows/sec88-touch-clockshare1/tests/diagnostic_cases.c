/* V2 admission diagnostics, immutable first refusal, and existing read-once
 * semantics. Legacy FIX1 must reject V2; no cross-version equivalence claim. */
#include <stdio.h>
#include <stdlib.h>
#include "demo_fixture.h"
int BaselineValidate(const N976N_TOUCH_HANDOFF *);
int BaselineFresh(const N976N_TOUCH_HANDOFF *,void *,N976N_DEMO_READ,N976N_HSI_LEASE *);
static unsigned groups;
#define CHECK(X) do{if(!(X)){fprintf(stderr,"FAIL %d %s\n",__LINE__,#X);exit(1);}}while(0)
#define GROUP(X) do{puts(X);++groups;}while(0)
static uint32_t regs[7][8192],*maps[7]={regs[0],regs[1],regs[2],regs[3],regs[4],regs[5],regs[6]};
typedef struct{unsigned n,fail,change;unsigned trace[128][2];}READS;
static int read_once(void *C,uint32_t M,uint32_t O,uint32_t *V){
 READS*T=C;CHECK(M<7&&M!=5&&O<sizeof(regs[0])&&!(O&3)&&T->n<128);
 T->trace[T->n][0]=M;T->trace[T->n][1]=O;++T->n;
 if(T->fail==T->n)return 0;
 *V=T->change==T->n?0xFFFFFFFFU:regs[M][O/4];return 1;
}
static void compare_shape(const N976N_TOUCH_HANDOFF *H){
 N976N_DEMO_DIAGNOSTIC D={0},Saved;
 int after=N976nDemoValidateHandoffEx(H,&D);
 CHECK(after==N976nDemoValidateHandoff(H));CHECK(after?!D.Valid:D.Valid==N976N_DIAGNOSTIC_VALID);
 if(!after){Saved=D;N976nDemoReject(&D,7,33,99,99,1,2,3,0);CHECK(!memcmp(&D,&Saved,sizeof(D)));}
}
int main(void){
 N976N_TOUCH_HANDOFF H,M;N976N_DEMO_DIAGNOSTIC D;N976N_HSI_LEASE A,B;READS X,Y;
 demo_fixture(&H);memset(regs,0,sizeof(regs));demo_bind_regs(&H,maps);
 GROUP("EXP9_V2_valid_and_legacy_FIX1_rejects_new_ABI");CHECK(N976nDemoValidateHandoff(&H)&&!BaselineValidate(&H));compare_shape(&H);compare_shape(NULL);
 GROUP("every_NVS_bit_CRC_acceptance_and_first_failure_immutable");
 for(unsigned i=0;i<sizeof(H);++i)for(unsigned bit=0;bit<8;++bit){M=H;((unsigned char*)&M)[i]^=1U<<bit;compare_shape(&M);}
 GROUP("every_NVS_bit_resealed_first_refusal_is_immutable");
 for(unsigned i=0;i<sizeof(H);++i)for(unsigned bit=0;bit<8;++bit){M=H;((unsigned char*)&M)[i]^=1U<<bit;M.Crc32=N976nDemoCrc(&M);compare_shape(&M);}
 GROUP("nonzero_64bit_reserved_reports_exact_byte_offset_and_width");
 M=H;M.Reserved[5]=1ULL<<63;M.Crc32=N976nDemoCrc(&M);memset(&D,0,sizeof(D));CHECK(!N976nDemoValidateHandoffEx(&M,&D));
 CHECK(D.Offset==offsetof(N976N_TOUCH_HANDOFF,Reserved)+5*8&&D.Actual==(1ULL<<63)&&D.Mask==~0ULL);
 GROUP("EXP9_V2_fresh_succeeds_and_old_ABI_consumer_reads_nothing");
 memset(&X,0,sizeof(X));memset(&Y,0,sizeof(Y));memset(&D,0,sizeof(D));
 CHECK(!BaselineFresh(&H,&X,read_once,&A)&&!X.n&&N976nDemoFreshEx(&H,&Y,read_once,&B,&D)==1);
 CHECK(!D.Valid&&B.Flags);unsigned reads=Y.n;READS original=Y;
 GROUP("each_original_read_failure_has_no_extra_MMIO_and_exact_operand_location");
 for(unsigned i=1;i<=reads;++i){memset(&X,0,sizeof(X));memset(&Y,0,sizeof(Y));memset(&D,0,sizeof(D));X.fail=Y.fail=i;
  CHECK(!N976nDemoFresh(&H,&X,read_once,&A)&&!N976nDemoFreshEx(&H,&Y,read_once,&B,&D));
  CHECK(!memcmp(&X,&Y,sizeof(X))&&X.n==i&&D.Bucket==N976nDiagFresh&&D.Condition==N976nWhyRead&&!D.ReadOk);
  CHECK(D.Index==X.trace[i-1][0]&&D.Offset==X.trace[i-1][1]);}
 GROUP("each_original_read_stale_value_has_same_trace_and_no_diagnostic_reread");
 for(unsigned i=1;i<=reads;++i){memset(&X,0,sizeof(X));memset(&Y,0,sizeof(Y));memset(&D,0,sizeof(D));X.change=Y.change=i;
  int con=original.trace[i-1][0]==6&&original.trace[i-1][1]==0x20;
  CHECK(N976nDemoFresh(&H,&X,read_once,&A)==con&&N976nDemoFreshEx(&H,&Y,read_once,&B,&D)==con);
  CHECK(!memcmp(&X,&Y,sizeof(X)));
  if(con)CHECK(X.n==reads&&!D.Valid); /* FFFFFFFF: eight valid EINT muxes. */
  else{CHECK(X.n==i&&D.Bucket==N976nDiagFresh&&D.ReadOk&&D.Actual==0xFFFFFFFFU);
   CHECK(D.Index==X.trace[i-1][0]&&D.Offset==X.trace[i-1][1]);}}
 printf("PASS %u groups\n",groups);return 0;
}
