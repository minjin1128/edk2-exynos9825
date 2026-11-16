/* Actual admission core; fixtures are synthetic register/state observations. */
#include <stdio.h>
#include <stdlib.h>
#include "demo_fixture.h"
static unsigned groups;
#define CHECK(x)do{if(!(x)){fprintf(stderr,"FAIL %s:%d %s\n",__FILE__,__LINE__,#x);exit(1);}}while(0)
#define GROUP(x)do{puts(x);++groups;}while(0)
static uint32_t space[7][8192],*maps[7]={space[0],space[1],space[2],space[3],space[4],space[5],space[6]};
static unsigned reads,badmap,badoffset;
static int read_map(void*C,uint32_t M,uint32_t O,uint32_t *V)
{(void)C;CHECK(M<7&&M!=5&&O<32768&&!(O&3));++reads;if(M==badmap&&O==badoffset)return 0;*V=maps[M][O/4];return 1;}
static void bind(N976N_TOUCH_HANDOFF*H){memset(space,0,sizeof(space));demo_bind_regs(H,maps);reads=0;badmap=99;}
static void seal(N976N_TOUCH_HANDOFF*H){H->Crc32=N976nDemoCrc(H);}
int main(void)
{
 N976N_TOUCH_HANDOFF H,B;N976N_HSI_LEASE L;
 GROUP("handoff_exact_wire_layout_crc_and_current_boot_stage");demo_fixture(&H);
 CHECK(offsetof(N976N_TOUCH_HANDOFF,ClaimState)==0x180);CHECK(sizeof(H)==400);
 CHECK(N976nDemoValidateHandoff(&H));B=H;B.ProducerStage=1;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));
 GROUP("handoff_crc_covers_every_immutable_byte");
 for(unsigned i=0;i<offsetof(N976N_TOUCH_HANDOFF,ClaimState);++i){B=H;((uint8_t*)&B)[i]^=1;CHECK(!N976nDemoValidateHandoff(&B));}
 GROUP("mutable_claim_outside_crc_guard_remains_mandatory");B=H;B.ClaimState=3;CHECK(N976nDemoValidateHandoff(&B));B.Guard^=1;CHECK(!N976nDemoValidateHandoff(&B));
 GROUP("metadata_version_size_reserved_and_generation_rejected");
 for(unsigned i=0;i<13;++i){B=H;switch(i){case 0:B.Magic=0;break;case 1:B.Version=1;break;case 2:B.Bytes++;break;case 3:B.ImmutableBytes++;break;case 4:B.BootCounter=0;break;case 5:B.CounterHz=0;break;case 6:B.Profile=1;break;case 7:B.ChipId++;break;case 8:B.BusHz=400000;break;case 9:B.Reserved[5]=1;break;case 10:B.PowerRetired=0;break;case 11:B.PowerResponses--;break;case 12:B.ProducerChecks=7;break;}seal(&B);CHECK(!N976nDemoValidateHandoff(&B));}
 GROUP("cold_rails_enable_only_and_irq_retirement_required");
 for(unsigned i=0;i<8;++i){B=H;switch(i){case 0:B.LdoBefore|=0x80;break;case 1:B.LdoEnabled^=1;break;case 2:B.LdoEnabled&=~0x4000;break;case 3:B.LdoEnabled|=0x10000;break;case 4:B.Gic45Disabled=0;break;case 5:B.Gic420Disabled=0;break;case 6:B.Eint8Masked=0;break;case 7:B.PowerRequests=B.PowerResponses=0;break;}seal(&B);CHECK(!N976nDemoValidateHandoff(&B));}
 GROUP("clock_is_computed_from_source_not_declared_frequency");B=H;B.InputHz=100000000;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));
 B=H;B.Cmu[11]=0x10;B.ClockCount=7;uint32_t off[]={0x20C0,0x10BC,0x18A8,0x10DC,0x18CC,0x18D4,0x160};
 for(unsigned i=0;i<7;++i)B.ClockOffsets[i]=off[i];seal(&B);CHECK(N976nDemoValidateHandoff(&B));
 B.ClockOffsets[6]=0x100;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));
 GROUP("clock_duplicate_unused_and_unbounded_offsets_rejected");
 B=H;B.ClockCount=1;B.ClockOffsets[0]=0xDEAD;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));
 B=H;B.ClockOffsets[11]=4;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));B=H;B.ClockCount=13;seal(&B);CHECK(!N976nDemoValidateHandoff(&B));
 GROUP("timing_pin_mode_and_controller_preparation_are_bound");
 for(unsigned i=0;i<10;++i){B=H;switch(i){case 0:B.TimingFs[0]^=0x10000;break;case 1:B.TimingFs[1]^=1;break;case 2:B.TimingFs[2]^=0x10000;break;case 3:B.UsiMode=2;break;case 4:B.UsiControl=1;break;case 5:B.GppCon=0;break;case 6:B.GppPull=0x10000;break;case 7:B.HsiCtl=0x80000008;break;case 8:B.HsiConf=0;break;case 9:B.HsiAuto|=0x80000000;break;}seal(&B);CHECK(!N976nDemoValidateHandoff(&B));}
 GROUP("fresh_admission_outputs_real_lease_and_reads_bounded_offsets");bind(&H);CHECK(N976nDemoFresh(&H,NULL,read_map,&L));CHECK(L.Generation==17&&L.InputHz==26000000&&L.SpeedHz==100000&&L.Flags==127&&reads>20);
 GROUP("changed_fresh_registers_fail_and_zero_lease");
 for(unsigned i=0;i<13;++i){bind(&H);maps[1][fixture_cmu_offsets[i]/4]^=1;memset(&L,0xA5,sizeof(L));CHECK(!N976nDemoFresh(&H,NULL,read_map,&L));CHECK(L.Generation==0&&L.Flags==0);}
 GROUP("fresh_idle_fifo_irq_auto_guards_reject_before_IO");
 const unsigned offsets[]={0x24,0x20,0x50,0x30,0x44,0xC4,0x60};
 const uint32_t values[]={0x80,0x80,0xA,0x01000101,0x80030003,1,0};
 for(unsigned i=0;i<7;++i){bind(&H);maps[0][offsets[i]/4]=values[i];CHECK(!N976nDemoFresh(&H,NULL,read_map,&L));}
 GROUP("read_failure_no_fake_zero_or_fallback");bind(&H);badmap=3;badoffset=0x20;CHECK(!N976nDemoFresh(&H,NULL,read_map,&L));
 GROUP("EXP9_GPA1_snapshot_mux_pull_mask_and_reserved_fail_closed");
 for(unsigned i=0;i<7;++i){B=H;switch(i){case 0:B.Gpa1Con=2;break;case 1:B.Gpa1Con=3;break;case 2:B.Gpa1Pull=2;break;case 3:B.Gpa1Pull=~0U;break;case 4:B.Gpa1EintMask=0;break;case 5:B.Gpa1EintMask=~0U;break;case 6:B.Gpa1Reserved=1;break;}seal(&B);CHECK(!N976nDemoValidateHandoff(&B));}
 for(unsigned con=0;con<=15;con+=15)for(unsigned pull=0;pull<=3;++pull){B=H;B.Gpa1Con=con;B.Gpa1Pull=pull;seal(&B);CHECK(N976nDemoValidateHandoff(&B)==(pull!=2));}
 GROUP("EXP9_live_pin0_fields_exact_other_pins_unowned_and_DAT_dynamic");
 bind(&H);maps[6][0x20/4]^=0x100;maps[6][0x28/4]^=0x100;maps[6][0x904/4]|=2;maps[6][0x24/4]=1;
 CHECK(N976nDemoFresh(&H,NULL,read_map,&L));
 for(unsigned i=0;i<6;++i){bind(&H);unsigned off=i<2?0x20:i<4?0x28:0x904;maps[6][off/4]=i%2?~0U:(i<2?0:i<4?1:0);CHECK(N976nDemoFresh(&H,NULL,read_map,&L)==(i==1));if(i!=1)CHECK(!L.Flags);}
 B=H;B.Gpa1Con=~0U;seal(&B);CHECK(N976nDemoValidateHandoff(&B));bind(&B);CHECK(N976nDemoFresh(&B,NULL,read_map,&L));
 GROUP("EXP9_live_ALIVE_read_failures_keep_exact_refusal_and_zero_lease");
 for(unsigned i=0;i<3;++i){bind(&H);badmap=6;badoffset=((unsigned[]){0x20,0x28,0x904})[i];CHECK(!N976nDemoFresh(&H,NULL,read_map,&L)&&!L.Flags);}
 printf("PASS %u groups\n",groups);return 0;
}
