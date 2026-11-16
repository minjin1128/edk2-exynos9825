/* Actual core with the preserved fake HCI. No alternative storage body. */
#define main preserved_full_policy_main
#include "core_cases.c"
#undef main
static U8 Out[65536],Saved[NUF_DMA_BYTES];
static void prod(void){
 setup(0);runtime();M.E.GuardPolicy=NUF_GUARD_CYCLIC;
 M.E.Config.LastLba=0x3B94A04;M.E.Config.WriteEnabled=1;
 M.E.Config.WriteFirst=NUF_WRITE_REGION_FIRST;M.E.Config.WriteBlocks=NUF_WRITE_REGION_BLOCKS;
 M.E.Config.SystemWriteFirst=NUF_SYSTEM_PARTITION_START;M.E.Config.SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;
 M.Lba=(U32)M.E.Config.WriteFirst;
 assert(NufSessionOpen(&M.E));
}
static void warm(void){prod();assert(NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096));}
static void untouched(U32 submits,U32 writes,U64 reset){
 assert(M.Submits==submits&&M.Writes==writes&&M.E.RequestResetBytes==reset);
 assert(!memcmp(Saved,M.D,NUF_DMA_BYTES));
}
static void output_blocked(U32 bytes){for(U32 i=0;i<bytes;i++)assert(Out[i]==0xEA);}
int main(void){
 /* Both boundaries of the first command still check the whole arena. */
 for(U32 post=0;post<2;post++){
  prod();U32 off=20480+15*4096+4095;
  if(post){M.Fault=20;M.CorruptOffset=off;}else M.D[off]^=0x81;
  memset(Out,0xEA,sizeof(Out));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096));
  assert(M.R.FirstReason==NufGuard&&M.R.GuardOffset==off&&M.E.Quarantined);
  assert(M.Submits==post&&!M.AckWrites);output_blocked(4096);
 }
 pass("prod1_first_request_full_before_reset_and_after_dma");
 /* Stable inactive corruption: every cursor position, every inactive page,
  * first lanes/interior/last byte; report clearing cannot restart the sweep. */
 for(U32 cursor=0;cursor<16;cursor++)for(U32 page=1;page<16;page++)for(U32 lane=0;lane<10;lane++){
  warm();M.E.GuardCursor=cursor;
  U32 off=20480+page*4096+(lane<8?128+lane:lane==8?2048:4095);
  M.D[off]^=0x81;U32 due=(page+16-cursor)%16+1;
  U64 steps=M.E.GuardSweepSteps;U32 ack=M.AckWrites;
  for(U32 n=1;n<=due;n++){
   memset(&M.R,0,sizeof(M.R));memset(Out,0xEA,4096);
   int ok=NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096);
   assert(ok==(n<due));assert(M.E.GuardSweepSteps==steps+n);
   assert(M.E.GuardCursor==(cursor+n)%16);
   if(ok)assert(!memcmp(Out,M.Base,4096));
   else {assert(M.R.FirstReason==NufGuard&&M.R.GuardOffset==off&&M.R.GuardExpected==0xCC&&M.R.GuardActual==(0xCC^0x81));
    assert(M.E.Quarantined&&!M.E.RequestRetired&&!M.R.Acknowledged);output_blocked(4096);}
  }
  assert(M.AckWrites==ack+due-1&&M.D[off]==(0xCC^0x81));
 }
 pass("prod1_persistent_inactive_fault_all_pages_cursors_lanes_detected_within_16_post_opportunities");
 /* A no-data command makes page zero inactive too. It must not be skipped. */
 warm();M.Lba=0;assert(NufFlushCache(&M.E,M.Tag));M.E.GuardCursor=1;
 M.D[20480+128]^=0x81;U32 flushAck=M.AckWrites;
 for(U32 n=1;n<=16;n++){
  memset(&M.R,0,sizeof(M.R));int ok=NufFlushCache(&M.E,M.Tag);
  assert(ok==(n<16)&&M.E.GuardCursor==(1+n)%16);
 }
 assert(M.R.FirstReason==NufGuard&&M.R.GuardOffset==20480+128&&M.E.Quarantined&&!M.E.RequestRetired);
 assert(M.AckWrites==flushAck+15&&!M.R.Acknowledged);
 pass("prod1_flush_inactive_page_zero_not_skipped_detected_at_16th_post_without_ack");
 /* All mandatory immutable areas remain immediate, both pre and post. */
 const U32 regions[][2]={{0,4096},{4096,8},{4105,23},{4128,4064},{8192,4096},{12288,32},{12320,992},{14336,272},{14608,1776},{16384,4096},{24576,64},{86016,4096}};
 for(U32 post=0;post<2;post++)for(U32 n=0;n<sizeof(regions)/sizeof(*regions);n++)for(U32 lane=0;lane<10;lane++){
  warm();U32 off=regions[n][0]+(lane<8?lane:lane==8?regions[n][1]/2:regions[n][1]-1);
  U8 expect=M.D[off];U32 ack=M.AckWrites,submits=M.Submits,writes=M.Writes;U64 reset=M.E.RequestResetBytes;
  if(post){M.Fault=20;M.CorruptOffset=off;}else M.D[off]^=0x81;
  memcpy(Saved,M.D,sizeof(Saved));memset(Out,0xEA,4096);memset(&M.R,0,sizeof(M.R));
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096)&&M.E.Quarantined);
  assert(M.R.FirstReason==NufGuard&&M.R.GuardOffset==off&&M.R.GuardExpected==expect&&M.R.GuardActual==(U8)(expect^0x81));
  assert(M.AckWrites==ack);output_blocked(4096);
  if(!post)untouched(submits,writes,reset);
 }
 pass("prod1_mandatory_regions_and_boundary_immediate_pre_post_no_ack_or_output");
 /* Growth must refuse even a new WRITE before it erases the evidence. */
 for(U32 write=0;write<2;write++)for(U32 size=8192;size<=65536;size*=8)for(U32 lane=0;lane<3;lane++){
  warm();U32 off=20480+(lane==0?4096+64:lane==1?size/2+127:size-1);
  M.D[off]^=0x81;memcpy(Saved,M.D,sizeof(Saved));
  U32 submits=M.Submits,writes=M.Writes;U64 reset=M.E.RequestResetBytes;
  memset(Out,0xEA,sizeof(Out));
  int ok=write?NufWriteBlock(&M.E,M.Lba,M.Tag,M.Base,size):NufReadBlock(&M.E,M.Lba,M.Tag,Out,size);
  assert(!ok&&M.E.Quarantined&&M.R.GuardOffset==off);untouched(submits,writes,reset);output_blocked(size);
  assert(M.E.DataCapacity==4096&&M.E.RequestRetired);
 }
 pass("prod1_growth_read_write_full_new_region_before_any_store_state_or_doorbell");
 /* Shrink clears only previously active bytes, never latent far-tail faults. */
 warm();assert(NufReadBlock(&M.E,M.Lba,M.Tag,Out,8192));
 U32 far=20480+15*4096+333;M.D[far]^=0x81;
 assert(NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096));assert(M.D[far]==(0xCC^0x81));
 for(U32 i=4096;i<8192;i++)assert(M.D[20480+i]==0xCC);
 assert(!NufReadBlock(&M.E,M.Lba,M.Tag,Out,65536)&&M.R.GuardOffset==far);
 pass("prod1_shrink_preserves_old_inactive_evidence_then_growth_detects");
 /* DATA_OUT remains fully immutable before shrink and after DMA. */
 for(U32 post=0;post<2;post++){
  warm();assert(NufWriteBlock(&M.E,M.Lba,M.Tag,M.Base,65536));
  U32 off=20480+32769,ack=M.AckWrites;
  if(post){M.Fault=20;M.CorruptOffset=off;assert(!NufWriteBlock(&M.E,M.Lba,M.Tag,M.Base,65536));}
  else {M.D[off]^=0x81;memcpy(Saved,M.D,sizeof(Saved));U32 submits=M.Submits,writes=M.Writes;U64 reset=M.E.RequestResetBytes;
   assert(!NufFlushCache(&M.E,M.Tag));untouched(submits,writes,reset);}
  assert(M.R.GuardOffset==off&&M.E.Quarantined&&M.AckWrites==ack);
 }
 pass("prod1_active_write_full_check_and_flush_transition_preserve_evidence");
 for(U32 mode=0;mode<4;mode++){
  warm();if(mode>=2)assert(NufSessionStop(&M.E));
  M.D[far]^=0x81;U32 writes=M.Writes,clocks=M.ClockCalls;memcpy(Saved,M.D,sizeof(Saved));
  int ok=mode==0?NufSessionStop(&M.E):mode==2?NufSessionRestart(&M.E):NufSessionClose(&M.E);
  assert(!ok&&M.E.Quarantined&&M.R.GuardOffset==far&&M.Writes==writes&&M.ClockCalls==clocks);
  assert(!memcmp(Saved,M.D,sizeof(Saved)));
 }
 pass("prod1_stop_restart_close_and_stopped_close_full_without_erasing_latent_fault");
 for(U32 bad=0;bad<5;bad++){
  warm();if(bad<3)M.E.GuardPolicy=bad==0?0:bad==1?3:~0U;else M.E.GuardCursor=bad==3?16:~0U;
  memcpy(Saved,M.D,sizeof(Saved));U32 submits=M.Submits,writes=M.Writes;U64 reset=M.E.RequestResetBytes;
  assert(!NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096)&&M.E.Quarantined&&M.R.FirstReason==NufOwnership);
  untouched(submits,writes,reset);
 }
 setup(0);M.E.GuardPolicy=3;assert(!NufSessionOpen(&M.E)&&!M.Writes&&!M.E.DmaInitBytes);
 pass("prod1_invalid_policy_cursor_fail_closed_before_initialization_or_reuse");
 /* Active-page skips still advance: 64K read/write, 0K flush, mixed sizes. */
 warm();U32 cursor=M.E.GuardCursor;U64 steps=M.E.GuardSweepSteps;
 for(U32 i=0;i<64;i++){
  U32 size=i%3==0?4096:i%3==1?8192:65536;int ok;
  if(i%4==0){M.Lba=0;ok=NufFlushCache(&M.E,M.Tag);M.Lba=(U32)M.E.Config.WriteFirst;}
  else if(i%4==1)ok=NufWriteBlock(&M.E,M.Lba,M.Tag,M.Base,size);
  else ok=NufReadBlock(&M.E,M.Lba,M.Tag,Out,size);
  assert(ok&&NufRequestRetired(&M.E)&&M.E.GuardCursor==(cursor+i+1)%16&&M.E.GuardSweepSteps==steps+i+1);
 }
 assert(NufSessionStop(&M.E)&&NufSessionRestart(&M.E)&&NufSessionClose(&M.E));
 pass("prod1_mixed_4k_8k_64k_read_write_flush_cursor_progress_and_retirement");
 warm();U64 scanned=M.E.GuardCheckBytes;
 for(U32 i=0;i<16;i++)assert(NufReadBlock(&M.E,M.Lba,M.Tag,Out,4096));
 assert(M.E.GuardCheckBytes-scanned==16ULL*51070ULL);
 pass("prod1_steady_4k_read_exact_16_command_scan_budget_817120_bytes");
 return 0;
}
