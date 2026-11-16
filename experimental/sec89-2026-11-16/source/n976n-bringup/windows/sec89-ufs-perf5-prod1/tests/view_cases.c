#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "../N976nGptVolumeView.h"
static NUV_VIEW View;static NUV_POLICY Policy;
static unsigned char Headers[2][4096],Arrays[2][16384],Out[4096],Before[4096];
#define LAST 0x3B94FFFULL
#define START 0x222200ULL
#define RAW 0x3972800ULL
#define BLOCKS 0x1000000ULL
static void w32(unsigned char*p,unsigned v){for(unsigned n=0;n<4;n++)p[n]=(unsigned char)(v>>(8*n));}
static void w64(unsigned char*p,NV_U64 v){for(unsigned n=0;n<8;n++)p[n]=(unsigned char)(v>>(8*n));}
static unsigned r32(const unsigned char*p){return p[0]|(unsigned)p[1]<<8|(unsigned)p[2]<<16|(unsigned)p[3]<<24;}
static NV_U64 r64(const unsigned char*p){return r32(p)|((NV_U64)r32(p+4)<<32);}
static unsigned crc(const unsigned char*p,unsigned n){unsigned c=~0U;while(n--){c^=*p++;for(unsigned b=0;b<8;b++)c=(c>>1)^((0U-(c&1))&0xEDB88320U);}return ~c;}
static void hc(unsigned side){w32(Headers[side]+16,0);w32(Headers[side]+16,crc(Headers[side],r32(Headers[side]+12)));}
static void ac(void){for(unsigned s=0;s<2;s++){w32(Headers[s]+88,crc(Arrays[s],16384));hc(s);}}
static void fixture(unsigned index){NuvViewReset(&View);memset(&Policy,0,sizeof(Policy));memset(Headers,0,sizeof(Headers));memset(Arrays,0,sizeof(Arrays));
 Policy.DiskGuid[0]=1;Policy.PartitionGuid[0]=2;Policy.Start=START;Policy.RawBlocks=RAW;Policy.ViewBlocks=BLOCKS;
 unsigned char *e=Arrays[0]+index*128;unsigned char basic[]={0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7};memcpy(e,basic,16);memcpy(e+16,Policy.PartitionGuid,16);w64(e+32,START);w64(e+40,START+RAW-1);for(unsigned j=0;j<8;j++)e[56+j*2]=(unsigned char)"userdata"[j];
 /* Independent SYSTEM-shaped entry must remain byte-identical. */
 unsigned other=index==0?1:0;unsigned char*q=Arrays[0]+other*128;memcpy(q,basic,16);q[16]=3;w64(q+32,0x17A00);w64(q+40,0x199DFF);q[56]='s';
 memcpy(Arrays[1],Arrays[0],16384);
 for(unsigned s=0;s<2;s++){unsigned char*h=Headers[s];memcpy(h,"EFI PART",8);w32(h+8,0x10000);w32(h+12,512);w64(h+24,s?LAST:1);w64(h+32,s?1:LAST);w64(h+40,6);w64(h+48,LAST-5);memcpy(h+56,Policy.DiskGuid,16);w64(h+72,s?LAST-4:2);w32(h+80,128);w32(h+84,128);}ac();
}
static void capture(void){assert(NuvViewCapture(&View,LAST,LAST,Headers[1],4096));for(unsigned s=0;s<2;s++)for(unsigned b=0;b<4;b++)assert(NuvViewCapture(&View,LAST,(s?LAST-4:2)+b,Arrays[s]+b*4096,4096));assert(NuvViewCapture(&View,LAST,1,Headers[0],4096));}
static void seal(unsigned index){fixture(index);capture();assert(NuvViewSeal(&View,&Policy));}
static void pass(const char *s){puts(s);}
int main(void){NV_U32 changed;
 seal(63);assert(View.Ready==1&&View.TargetIndex==63&&View.Policy.RawBlocks==RAW&&View.Policy.ViewBlocks==BLOCKS);pass("raw_primary_backup_identity_and_ntfs_policy_seal");
 for(unsigned side=0;side<2;side++){
  unsigned char table[16384];memcpy(table,Arrays[side],16384);
  for(int block=3;block>=0;block--){changed=99;assert(NuvViewApply(&View,(side?LAST-4:2)+(unsigned)block,table+block*4096,4096,&changed));assert(changed==((unsigned)block==1));}
  unsigned char expected[16384];memcpy(expected,Arrays[side],16384);w64(expected+63*128+40,START+BLOCKS-1);assert(!memcmp(expected,table,16384));
  memcpy(Out,Headers[side],4096);assert(NuvViewApply(&View,side?LAST:1,Out,4096,&changed)&&changed);assert(r32(Out+12)==92&&r32(Out+88)==crc(table,16384));unsigned hcvalue=r32(Out+16);w32(Out+16,0);assert(hcvalue==crc(Out,92));w32(Out+16,hcvalue);
  memcpy(Before,Headers[side],4096);w32(Before+12,92);w32(Before+16,hcvalue);w32(Before+88,crc(table,16384));assert(!memcmp(Before,Out,4096));
 }pass("both_gpt_arrays_headers_crc_and_other_bytes_exact");
 assert(r64(Arrays[0]+63*128+40)==START+RAW-1&&r32(Headers[0]+12)==512);pass("raw_snapshots_unchanged_no_media_write");
 for(unsigned i=0;i<4;i++){memcpy(Out,Arrays[1]+4096,4096);assert(NuvViewApply(&View,LAST-3,Out,4096,&changed)&&r64(Out+31*128+40)==START+BLOCKS-1);}pass("entry_block_repeat_and_backup_first_independent");
 for(unsigned i=0;i<128;i+=31){seal(i);memcpy(Out,Arrays[0]+(i/32)*4096,4096);assert(NuvViewApply(&View,2+i/32,Out,4096,&changed)&&r64(Out+(i%32)*128+40)==START+BLOCKS-1);}seal(127);pass("entry_positions_across_all_array_blocks");
 memset(Out,0x71,4096);memcpy(Before,Out,4096);assert(NuvViewApply(&View,START,Out,4096,&changed)&&!changed&&!memcmp(Out,Before,4096));pass("nonmetadata_payload_and_old_tail_unchanged");
 memcpy(Out,Headers[0],4096);memcpy(Before,Out,4096);assert(!NuvViewApply(&View,1,Out,512,&changed)&&!memcmp(Out,Before,4096));pass("partial_sector_apply_refused_without_mutation");
 Out[200]=1;memcpy(Before,Out,4096);assert(!NuvViewApply(&View,1,Out,4096,&changed)&&!memcmp(Out,Before,4096));memcpy(Out,Arrays[0],4096);Out[300]^=1;memcpy(Before,Out,4096);assert(!NuvViewApply(&View,2,Out,4096,&changed)&&!memcmp(Out,Before,4096));pass("fresh_header_and_array_drift_refused_before_mutation");
 fixture(63);capture();View.Mask&=~(1U<<9);assert(!NuvViewSeal(&View,&Policy)&&!View.Ready);pass("missing_backup_array_block_refused");
 fixture(63);Headers[0][16]^=1;capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Headers[1][16]^=1;capture();assert(!NuvViewSeal(&View,&Policy));pass("both_original_header_crc_failures_refused");
 fixture(63);Arrays[0][100]^=1;capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Arrays[1][100]^=1;ac();capture();assert(!NuvViewSeal(&View,&Policy));pass("array_crc_and_crc_valid_pair_mismatch_refused");
 fixture(63);Policy.PartitionGuid[0]++;capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Policy.DiskGuid[0]++;capture();assert(!NuvViewSeal(&View,&Policy));pass("exact_disk_and_partition_identity_required");
 fixture(63);Policy.RawBlocks--;capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Policy.ViewBlocks=RAW+1;capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Policy.Start=~0ULL-2;capture();assert(!NuvViewSeal(&View,&Policy));pass("raw_extent_mismatch_enlargement_and_overflow_refused");
 fixture(63);Arrays[0][63*128+48]=1;memcpy(Arrays[1],Arrays[0],16384);ac();capture();assert(!NuvViewSeal(&View,&Policy));fixture(63);Arrays[0][63*128+56]='U';memcpy(Arrays[1],Arrays[0],16384);ac();capture();assert(!NuvViewSeal(&View,&Policy));pass("attributes_and_exact_name_required");
 fixture(63);w64(Arrays[0]+40,START);memcpy(Arrays[1],Arrays[0],16384);ac();capture();assert(!NuvViewSeal(&View,&Policy));pass("raw_partition_overlap_refused");
 fixture(63);Headers[0][92]=1;hc(0);capture();assert(!NuvViewSeal(&View,&Policy));pass("unknown_header_extension_refused");
 fixture(63);w32(Headers[0]+12,92);w32(Headers[1]+12,92);hc(0);hc(1);capture();assert(NuvViewSeal(&View,&Policy));memcpy(Out,Headers[0],4096);assert(NuvViewApply(&View,1,Out,4096,&changed));pass("uefi_canonical_92_byte_snapshot_supported");
 static unsigned char projection[10][4096];
 seal(63);for(unsigned side=0;side<2;side++){
  memcpy(projection[side*5],Headers[side],4096);assert(NuvViewApply(&View,side?LAST:1,projection[side*5],4096,&changed));
  for(unsigned block=0;block<4;block++){memcpy(projection[side*5+1+block],Arrays[side]+block*4096,4096);assert(NuvViewApply(&View,(side?LAST-4:2)+block,projection[side*5+1+block],4096,&changed));}
 }
 fixture(63);w32(Headers[0]+12,92);w32(Headers[1]+12,92);hc(0);hc(1);capture();assert(NuvViewSeal(&View,&Policy));
 for(unsigned side=0;side<2;side++){
  memcpy(Out,Headers[side],4096);assert(NuvViewApply(&View,side?LAST:1,Out,4096,&changed)&&!memcmp(Out,projection[side*5],4096));
  for(unsigned block=0;block<4;block++){memcpy(Out,Arrays[side]+block*4096,4096);assert(NuvViewApply(&View,(side?LAST-4:2)+block,Out,4096,&changed)&&!memcmp(Out,projection[side*5+1+block],4096));}
 }pass("windows_512_and_uefi_92_inputs_produce_identical_both_headers_and_arrays");
 fixture(63);assert(NuvViewCapture(&View,LAST,1,Headers[0],4096));assert(NuvViewCapture(&View,LAST,1,Headers[0],4096));Headers[0][100]=1;assert(!NuvViewCapture(&View,LAST,1,Headers[0],4096));pass("repeated_capture_requires_exact_raw_match");
 seal(63);assert(!NuvViewCapture(&View,LAST,1,Headers[0],4096)&&View.Ready);assert(!NuvViewSeal(&View,&Policy)&&View.Ready);pass("sealed_state_cannot_be_rebuilt");
 for(unsigned f=0;f<8;f++){seal(63);if(f==0)View.Ready=2;if(f==1)View.EntryCount=~0U;if(f==2)View.ArrayBlocks=8;if(f==3)View.TargetIndex=~0U;if(f==4)View.EntryLba[0]=~0ULL;if(f==5)View.LastLba=1;if(f==6)View.Policy.Start=~0ULL;if(f==7)View.Header[1][72]^=1;memcpy(Out,Arrays[0],4096);memcpy(Before,Out,4096);assert(!NuvViewApply(&View,2,Out,4096,&changed)&&!memcmp(Out,Before,4096));assert(!NuvViewContains(&View,2));}pass("sealed_scalar_corruption_refused_before_addressing");
 seal(63);assert(!NuvViewApply(&View,1,View.Header[0],4096,&changed));memcpy(Out,Headers[0],4096);memcpy(Before,Out,4096);assert(!NuvViewApply(&View,1,Out,4096,(void*)Out)&&!memcmp(Out,Before,4096));assert(!NuvViewApply(&View,1,Out,4096,&View.Ready));fixture(63);assert(!NuvViewCapture(&View,LAST,1,View.Header[0],4096));capture();assert(!NuvViewSeal(&View,&View.Policy));pass("view_buffer_policy_and_changed_alias_refused");
 static unsigned char span[65536],expected[65536],unchanged[65536];NUV_SPAN_RESULT result;
 for(unsigned side=0;side<2;side++)for(unsigned target=0;target<128;target+=31){
  seal(target);NV_U64 start=side?LAST-5:0;memset(span,0x71,sizeof(span));
  if(side){memcpy(span+4096,Arrays[1],16384);memcpy(span+5*4096,Headers[1],4096);}
  else{memcpy(span+4096,Headers[0],4096);memcpy(span+2*4096,Arrays[0],16384);}
  memcpy(expected,span,sizeof(span));unsigned candidates=0,changes=0;
  for(unsigned n=0;n<6;n++){
   if(NuvViewContains(&View,start+n))candidates|=1U<<n;
   assert(NuvViewApply(&View,start+n,expected+n*4096,4096,&changed));if(changed)changes|=1U<<n;
  }
  assert(NuvViewApplySpan(&View,start,span,6*4096,&result));
  assert(result.Candidates==candidates&&result.Changed==changes&&!memcmp(span,expected,sizeof(span)));
 }
 pass("span_primary_backup_header_array_and_payload_match_independent_single_sector_oracle");
 seal(63);memset(span,0x82,sizeof(span));memcpy(span+4096,Headers[0],4096);memcpy(span+8192,Arrays[0],16384);
 span[5*4096+9]^=1;memcpy(unchanged,span,sizeof(span));result=(NUV_SPAN_RESULT){0x99,0x88};
 assert(!NuvViewApplySpan(&View,0,span,65536,&result)&&!memcmp(span,unchanged,sizeof(span))&&result.Candidates==0x99&&result.Changed==0x88);
 pass("span_late_metadata_drift_leaves_entire_buffer_and_result_unchanged");
 memset(span,0x82,sizeof(span));memcpy(unchanged,span,sizeof(span));
 assert(NuvViewApplySpan(&View,START,span,65536,&result)&&!result.Candidates&&!result.Changed&&!memcmp(span,unchanged,sizeof(span)));
 for(unsigned f=0;f<4;f++){
  seal(63);if(f==0)View.Ready=0;if(f==1)View.EntryCount=~0U;if(f==2)View.EntryLba[1]=~0ULL;if(f==3)View.Policy.Start=~0ULL;
  assert(!NuvViewApplySpan(&View,START,span,65536,&result)&&!memcmp(span,unchanged,sizeof(span)));
 }
 pass("span_nonmetadata_still_validates_seal_and_preserves_payload");
 seal(63);
 assert(!NuvViewApplySpan(&View,START,span,0,&result));assert(!NuvViewApplySpan(&View,START,span,65537,&result));
 assert(!NuvViewApplySpan(&View,LAST,span,8192,&result));assert(!NuvViewApplySpan(&View,~0ULL,span,4096,&result));
 assert(!NuvViewApplySpan(&View,1,View.Header[0],4096,&result));
 assert(!NuvViewApplySpan(&View,START,span,65536,(void*)(span+65532)));
 assert(!NuvViewApplySpan(&View,START,span,65536,(void*)&View.Ready));
 assert(!NuvViewApplySpan(&View,START,(void*)(~(NV_U64)0-8191),16384,&result));
 assert(!memcmp(span,unchanged,sizeof(span)));
 pass("span_whole_extent_overflow_alias_and_1_to_16_block_bounds_fail_before_mutation");
 return 0;
}
