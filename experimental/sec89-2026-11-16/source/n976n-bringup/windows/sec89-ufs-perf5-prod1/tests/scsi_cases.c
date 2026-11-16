/* Independent wire-format oracles for the production scoped SCSI planner. */
#include "N976nUfsScsi.h"
#include <assert.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
static U8 c[16],b[65538];
static NUF_SCSI_RESULT r;
static void setup(U8 op){memset(c,0,16);memset(b,0xEA,sizeof(b));c[0]=op;}
static void run(U32 n,U32 dir,U32 bytes){r=NufScsiPlan(c,n,dir,b+1,bytes,(c[0]==0x2A||c[0]==0x8A)?0x3B94A04:0x123456);assert(b[0]==0xEA&&b[65537]==0xEA);}
static void pass(const char *p){puts(p);}
static void good(void){assert(r.Disposition==NufScsiDone);}
static void reject(U8 key,U8 asc){assert(r.Disposition==NufScsiCheck&&r.Key==key&&r.Asc==asc);}
/* Test wire builders use independent numeric protocol offsets and capacities. */
static void wire32(unsigned off,U32 value){for(unsigned i=0;i<4;i++)c[off+i]=(U8)(value>>(24-8*i));}
static unsigned data_cdb(U8 op,U32 lba,U32 blocks){
 setup(op);
 if(op==8){c[1]=(U8)(lba>>16);c[2]=(U8)(lba>>8);c[3]=(U8)lba;c[4]=(U8)blocks;return 6;}
 if(op==0x28||op==0x2A){wire32(2,lba);c[7]=(U8)(blocks>>8);c[8]=(U8)blocks;return 10;}
 if(op==0xA8){wire32(2,lba);wire32(6,blocks);return 12;}
 wire32(6,lba);wire32(10,blocks);return 16;
}
static void untouched(void){for(unsigned j=0;j<sizeof(b);j++)assert(b[j]==0xEA);}
int main(void){
 setup(0);run(6,0,0);good();pass("tur_ready_no_buffer");
 setup(0x12);c[4]=96;run(6,1,96);good();assert(r.Bytes==36&&b[1]==0&&b[3]==6&&!memcmp(b+9,"N976N   ",8)&&!memcmp(b+17,"UFS SCOPED RW   ",16));pass("standard_inquiry_real_single_direct_disk");
 for(unsigned i=0;i<3;i++){setup(0x12);c[1]=1;c[2]=(U8[]){0,0x80,0x83}[i];c[4]=96;run(6,1,96);good();assert(b[2]==c[2]&&r.Bytes==b[4]+4);}pass("vpd_supported_serial_device_identifier_lengths");
 setup(0x12);c[4]=5;run(6,1,3);good();assert(r.Bytes==3&&b[4]==0xEA);pass("metadata_truncation_obeys_allocation_and_cpu_span");
 setup(0x25);run(10,1,8);good();assert(r.Bytes==8&&!memcmp(b+1,"\0\x12\x34\x56\0\0\x10\0",8));pass("capacity10_exact_admitted_geometry");
 setup(0x9E);c[1]=0x10;c[13]=32;run(16,1,32);good();assert(r.Bytes==32&&!memcmp(b+1,"\0\0\0\0\0\x12\x34\x56\0\0\x10\0",12));pass("capacity16_same_geometry_and_block_size");
 for(unsigned i=0;i<2;i++){setup(i?0x5A:0x1A);c[2]=0x3F;if(i)c[8]=96;else c[4]=96;run(i?10:6,1,96);good();
 assert(b[1+(i?3:2)]==0&&b[1+(i?7:3)]==8&&b[1+(i?16:12)]==8&&b[1+(i?18:14)]==4);}
 pass("mode_sense6_10_writeback_cache_without_false_read_fua_or_dpo_support");
 setup(0xA0);c[9]=16;run(12,1,16);good();assert(r.Bytes==16&&b[4]==8&&b[9]==0);pass("report_luns_only_lun_zero");
 setup(3);c[4]=18;run(6,1,18);good();assert(r.Bytes==18&&b[1]==0x70&&b[3]==0&&b[8]==10);pass("request_sense_fixed_format_no_sense");
 setup(0x28);c[4]=0x12;c[5]=0x34;c[8]=1;run(10,1,4096);assert(r.Disposition==NufScsiRead&&r.Lba==0x1234&&r.Blocks==1&&r.Bytes==4096&&b[1]==0xEA);pass("read10_plan_does_not_fabricate_or_copy_sectors");
 setup(0x88);c[7]=0x12;c[8]=0x34;c[9]=0x56;c[13]=1;run(16,1,4096);assert(r.Disposition==NufScsiRead&&r.Lba==0x123456);pass("read16_last_sector_safe_translation");
 setup(8);c[3]=7;c[4]=1;run(6,1,4096);assert(r.Disposition==NufScsiRead&&r.Lba==7);setup(0xA8);c[5]=9;c[9]=1;run(12,1,4096);assert(r.Disposition==NufScsiRead&&r.Lba==9);pass("read6_12_single_sector_compatibility");
 setup(0x28);run(10,0,0);good();setup(0x88);run(16,0,0);good();setup(0xA8);run(12,0,0);good();pass("zero_block_reads_are_noop_without_data_direction");
 setup(0x28);c[4]=0x34;c[3]=0x12;c[5]=0x57;c[8]=1;run(10,1,4096);reject(5,0x21);
 setup(0x88);c[2]=0x80;c[13]=1;run(16,1,4096);reject(5,0x21);pass("range_and_64bit_overflow_refused");
 setup(0x28);c[8]=2;run(10,1,4096);reject(5,0x24);setup(8);run(6,1,4096);reject(5,0x24);pass("count_size_mismatch_and_read6_zero_256_refused");
 setup(0x28);c[8]=1;run(10,0,4096);reject(5,0x24);run(10,1,4095);reject(5,0x24);
 r=NufScsiPlan(c,10,1,NULL,4096,0x123456);reject(5,0x24);pass("data_direction_exact_span_and_null_mapping_refused");
 const U8 ops[]={4,0xA,0x15,0x2E,0x3B,0x41,0x42,0x48,0x55,0x89,0x8B,0x8E,0x93,0xAA,0xAE};
 for(unsigned i=0;i<sizeof(ops);i++){setup(ops[i]);run(16,0,0);reject(7,0x27);assert(r.WriteDenied&&b[1]==0xEA);}
 setup(0x12);run(6,2,16);reject(7,0x27);pass("nonallowlisted_media_mutations_and_data_out_write_protected");
 for(unsigned op=0;op<256;op++){setup((U8)op);run(16,0,0);assert(r.Disposition!=NufScsiRead);}pass("all_opcode_scan_cannot_expand_hardware_read_whitelist");
 setup(0xFF);run(16,0,0);reject(5,0x20);pass("unsupported_opcode_device_check_condition");
 setup(0x28);c[8]=1;c[1]=1;run(10,1,4096);reject(5,0x24);c[1]=0x18;run(10,1,4096);reject(5,0x24);pass("read_fua_dpo_refused_not_silently_discarded");
 setup(0x25);c[8]=1;run(10,1,8);reject(5,0x24);setup(0x9E);c[1]=0x11;run(16,1,32);reject(5,0x24);pass("service_action_and_reserved_field_validation");

 /* New write shape oracles deliberately use the admitted NTFS start literal,
  * rather than the production macro, to catch a changed fence constant. */
 for(unsigned i=0;i<2;i++){
  setup(i?0x8A:0x2A);if(i){c[7]=0x22;c[8]=0x22;c[13]=1;}else{c[3]=0x22;c[4]=0x22;c[8]=1;}
  run(i?16:10,2,4096);assert(r.Disposition==NufScsiWrite&&r.Lba==0x222200&&r.Blocks==1&&r.Bytes==4096&&!r.Flags);
  for(unsigned j=1;j<4097;j++)assert(b[j]==0xEA);
 }pass("write10_16_ntfs_start_payload_is_never_mutated_by_planner");
 for(unsigned i=0;i<2;i++){
  setup(i?0x8A:0x2A);c[1]=8;if(i){c[7]=0x22;c[8]=0x22;c[13]=1;}else{c[3]=0x22;c[4]=0x22;c[8]=1;}
  run(i?16:10,2,4096);assert(r.Disposition==NufScsiWrite&&r.Flags==NUF_SCSI_FUA);
 }pass("write_fua_explicit_flag_requires_device_flush_before_success");
 for(unsigned i=0;i<2;i++)for(unsigned f=0;f<256;f++){
  setup(i?0x8A:0x2A);c[1]=(U8)f;if(i){c[7]=0x22;c[8]=0x22;c[13]=1;}else{c[3]=0x22;c[4]=0x22;c[8]=1;}
  run(i?16:10,2,4096);if(f==0||f==8)assert(r.Disposition==NufScsiWrite);else{reject(5,0x24);assert(r.WriteDenied);}
 }pass("write_reserved_protection_dpo_fua_nv_flags_refused_exhaustively");
 for(unsigned i=0;i<2;i++)for(unsigned field=0;field<2;field++){
  setup(i?0x8A:0x2A);if(i){c[7]=0x22;c[8]=0x22;c[13]=1;c[field?15:14]=1;}else{c[3]=0x22;c[4]=0x22;c[8]=1;c[field?9:6]=1;}
  run(i?16:10,2,4096);reject(5,0x24);
 }pass("write_group_control_linked_commands_refused");
 for(unsigned i=0;i<2;i++)for(unsigned n=0;n<=16;n++){
  setup(i?0x8A:0x2A);if(i){c[7]=0x22;c[8]=0x22;c[13]=1;}else{c[3]=0x22;c[4]=0x22;c[8]=1;}
  run(n,2,4096);if(n==(i?16U:10U))assert(r.Disposition==NufScsiWrite);else reject(5,0x24);
 }pass("write_exact_cdb_length_required");
 for(unsigned dir=0;dir<4;dir++){
  setup(0x2A);c[3]=0x22;c[4]=0x22;c[8]=1;run(10,dir,4096);
  if(dir==2)assert(r.Disposition==NufScsiWrite);else reject(5,0x24);
 }pass("write_unidirectional_data_out_required");
 setup(0x2A);c[3]=0x22;c[4]=0x22;c[8]=1;run(10,2,4095);reject(5,0x24);run(10,2,4097);reject(5,0x24);
 r=NufScsiPlan(c,10,2,NULL,4096,0x3B94A04);reject(5,0x24);
 pass("write_exact_mapped_cpu_payload_required");
 setup(0x2A);c[3]=0x22;c[4]=0x22;c[8]=2;run(10,2,4096);reject(5,0x24);
 setup(0x8A);c[7]=0x22;c[8]=0x22;c[10]=0xFF;run(16,2,4096);reject(5,0x21);
 pass("write_count_size_mismatch_and_overflow_never_expand_fence");
 for(unsigned i=0;i<2;i++){
  setup(0x2A);c[2]=i?1:0;c[3]=0x22;c[4]=i?0x22:0x21;c[5]=i?0:0xFF;c[8]=1;
  run(10,2,4096);reject(7,0x27);assert(r.WriteDenied&&b[1]==0xEA);
 }pass("write_ntfs_extent_neighbors_denied_before_runtime_admission");
 for(unsigned i=0;i<2;i++){
  setup(i?0x8A:0x2A);unsigned off=i?6:2;c[off]=1;c[off+1]=0x22;c[off+2]=0x21;c[off+3]=0xFF;c[i?13:8]=1;
  run(i?16:10,2,4096);assert(r.Disposition==NufScsiWrite&&r.Lba==0x12221FF&&r.Blocks==1);
 }pass("write10_16_64g_final_backup_sector_admitted_without_truncation");
 setup(0x2A);c[8]=1;run(10,2,4096);reject(7,0x27);
 setup(0x8A);c[6]=3;c[7]=0xB9;c[8]=0x4A;c[9]=4;c[13]=1;run(16,2,4096);reject(7,0x27);
 pass("write_gpt_and_disk_tail_denied");
 setup(0x8A);c[2]=0x80;c[13]=1;run(16,2,4096);reject(5,0x21);
 pass("write64_high_lba_cannot_truncate_into_allowed_target");
 setup(0x2A);c[3]=0x22;c[4]=0x22;run(10,2,0);good();run(10,0,0);good();run(10,2,4096);reject(5,0x24);
 setup(0x8A);run(16,0,0);good();run(16,1,0);reject(5,0x24);
 pass("write_zero_count_is_no_media_operation_and_has_no_payload");
 for(unsigned i=0;i<2;i++){
  setup(i?0x91:0x35);run(i?16:10,0,0);assert(r.Disposition==NufScsiFlush&&!r.Blocks&&!r.Lba&&!r.Bytes&&b[1]==0xEA);
 }pass("sync10_16_zero_count_is_real_whole_device_flush_not_noop");
 for(unsigned i=0;i<2;i++){
  setup(i?0x91:0x35);if(i){c[7]=0x12;c[8]=0x34;c[9]=0x56;c[13]=1;}else{c[3]=0x12;c[4]=0x34;c[5]=0x56;c[8]=1;}
  run(i?16:10,0,0);assert(r.Disposition==NufScsiFlush&&r.Lba==0x123456&&r.Blocks==1);
 }pass("sync_valid_final_lba_range_requires_actual_completion");
 for(unsigned i=0;i<2;i++){
  setup(i?0x91:0x35);if(i){c[7]=0x12;c[8]=0x34;c[9]=0x56;c[13]=2;}else{c[3]=0x12;c[4]=0x34;c[5]=0x56;c[8]=2;}
  run(i?16:10,0,0);reject(5,0x21);
 }pass("sync_extent_exceeding_capacity_refused");
 setup(0x91);c[2]=0x80;run(16,0,0);reject(5,0x21);
 pass("sync64_out_of_range_zero_count_refused");
 for(unsigned i=0;i<2;i++)for(unsigned f=1;f<256;f++){
  setup(i?0x91:0x35);c[1]=(U8)f;run(i?16:10,0,0);reject(5,0x24);
 }pass("sync_immed_sync_nv_and_reserved_flags_refused_exhaustively");
 for(unsigned i=0;i<2;i++)for(unsigned field=0;field<2;field++){
  setup(i?0x91:0x35);c[i?(field?15:14):(field?9:6)]=1;run(i?16:10,0,0);reject(5,0x24);
 }pass("sync_group_and_control_refused");
 for(unsigned i=0;i<2;i++)for(unsigned n=0;n<=16;n++){
  setup(i?0x91:0x35);run(n,0,0);if(n==(i?16U:10U))assert(r.Disposition==NufScsiFlush);else reject(5,0x24);
 }pass("sync_exact_cdb_length_required");
 setup(0x35);run(10,0,1);reject(5,0x24);run(10,1,0);reject(5,0x24);run(10,2,0);reject(7,0x27);run(10,3,0);reject(7,0x27);
 pass("sync_no_payload_or_dma_direction_allowed");
 for(unsigned i=0;i<2;i++)for(unsigned pc=0;pc<4;pc++)for(unsigned dbd=0;dbd<2;dbd++){
  setup(i?0x5A:0x1A);c[1]=(U8)(dbd?8:0);c[2]=(U8)((pc<<6)|8);if(i)c[8]=96;else c[4]=96;run(i?10:6,1,96);
  if(pc!=0&&pc!=2)reject(5,0x24);else{good();unsigned header=i?8:4, off=1+header+(dbd?0:8);assert(b[off]==8&&b[off+1]==18&&b[off+2]==4&&b[1+(i?3:2)]==0);}
 }pass("cache_current_default_dbd_writeback_and_no_mutable_policy");
 for(unsigned i=0;i<2;i++)for(unsigned f=1;f<256;f++){
  setup(i?0x88:0x28);c[1]=(U8)f;c[i?13:8]=1;run(i?16:10,1,4096);reject(5,0x24);
 }pass("read_flags_never_claim_unimplemented_physical_cache_semantics");

 const U8 readops[]={8,0x28,0xA8,0x88};
 for(unsigned i=0;i<sizeof(readops);i++)for(U32 blocks=1;blocks<=16;blocks++){
  unsigned n=data_cdb(readops[i],7,blocks);run(n,1,blocks*4096);
  assert(r.Disposition==NufScsiRead&&r.Lba==7&&r.Blocks==blocks&&r.Bytes==blocks*4096);untouched();
 }pass("read6_10_12_16_all_bounded_counts_one_through_sixteen");
 for(unsigned i=0;i<sizeof(readops);i++){
  unsigned n=data_cdb(readops[i],0x123447,16);run(n,1,65536);assert(r.Disposition==NufScsiRead&&r.Bytes==65536);
  n=data_cdb(readops[i],0x123448,16);run(n,1,65536);reject(5,0x21);untouched();
 }pass("read_full_64k_final_disk_span_and_one_block_overrun");
 for(unsigned i=0;i<sizeof(readops);i++){
  unsigned n=data_cdb(readops[i],7,17);run(n,1,65536);reject(5,0x24);
  n=data_cdb(readops[i],7,16);run(n,1,65535);reject(5,0x24);run(n,1,65537);reject(5,0x24);
  r=NufScsiPlan(c,n,1,NULL,65536,0x123456);reject(5,0x24);untouched();
 }pass("read_64k_cap_exact_cpu_span_and_null_refused");
 for(unsigned i=0;i<sizeof(readops);i++)for(unsigned dir=0;dir<4;dir++){
  unsigned n=data_cdb(readops[i],7,16);run(n,dir,65536);
  if(dir==1)assert(r.Disposition==NufScsiRead);else if(dir&2)reject(7,0x27);else reject(5,0x24);
 }pass("read_multiblock_direction_contract_unchanged");
 for(unsigned i=0;i<2;i++)for(U32 blocks=1;blocks<=16;blocks++){
  unsigned n=data_cdb(i?0x8A:0x2A,0x222200,blocks);run(n,2,blocks*4096);
  assert(r.Disposition==NufScsiWrite&&r.Lba==0x222200&&r.Blocks==blocks&&r.Bytes==blocks*4096);untouched();
 }pass("write10_16_all_bounded_counts_payload_untouched");
 for(unsigned i=0;i<2;i++){
  unsigned n=data_cdb(i?0x8A:0x2A,0x12221F0,16);c[1]=8;run(n,2,65536);
  assert(r.Disposition==NufScsiWrite&&r.Blocks==16&&r.Flags==NUF_SCSI_FUA);
  n=data_cdb(i?0x8A:0x2A,0x12221F1,16);run(n,2,65536);reject(7,0x27);
  n=data_cdb(i?0x8A:0x2A,0x2221FF,16);run(n,2,65536);reject(7,0x27);untouched();
 }pass("write_64k_entire_span_inside_ntfs_fence_and_fua_preserved");
 for(unsigned i=0;i<2;i++){
  unsigned n=data_cdb(i?0x8A:0x2A,0x222200,17);run(n,2,65536);reject(5,0x24);
  n=data_cdb(i?0x8A:0x2A,0x222200,16);run(n,2,65535);reject(5,0x24);run(n,2,65537);reject(5,0x24);
  r=NufScsiPlan(c,n,2,NULL,65536,0x3B94A04);reject(5,0x24);untouched();
 }pass("write_64k_cap_exact_cpu_span_and_null_refused");
 for(unsigned i=0;i<2;i++){
  unsigned n=data_cdb(i?0x88:0xA8,7,0xFFFFFFFF);run(n,1,0xFFFFF000);reject(5,0x21);
 }
 unsigned n=data_cdb(0x8A,0x222200,0xFFFFFFFF);run(n,2,0xFFFFF000);reject(5,0x21);
 n=data_cdb(0x88,7,0x100000);run(n,1,0);reject(5,0x24);
 n=data_cdb(0x8A,0x222200,0x100000);run(n,2,0);reject(5,0x24);untouched();
 pass("count_multiplication_wrap_and_large_32bit_counts_refused");
 for(unsigned i=0;i<2;i++){
  unsigned n=data_cdb(i?0x2A:0x28,i?0x222200:7,16);
  r=NufScsiPlan(c,n,i?2:1,(U8*)(UINTPTR_MAX-65534U),65536,i?0x3B94A04:0x123456);reject(5,0x24);
  n=data_cdb(i?0x8A:0x88,i?0x222200:7,1);
  r=NufScsiPlan(c,n,i?2:1,(U8*)UINTPTR_MAX,4096,i?0x3B94A04:0x123456);reject(5,0x24);
 }pass("cpu_address_span_wrap_refused_before_worker_pointer_arithmetic");
 for(unsigned kind=0;kind<2;kind++)for(unsigned blocks=1;blocks<=16;blocks++)for(unsigned fua=0;fua<2;fua++){
  unsigned n=data_cdb(kind?0x8A:0x2A,0x17A00,blocks);c[1]=(U8)(fua?8:0);run(n,2,blocks*4096);
  assert(r.Disposition==NufScsiWrite&&r.Lba==0x17A00&&r.Blocks==blocks&&r.Bytes==blocks*4096&&r.Flags==(fua?NUF_SCSI_FUA:0));untouched();
 }pass("system_write10_16_all_bounded_counts_and_fua_preserved_without_payload_mutation");
 for(unsigned kind=0;kind<2;kind++){
  unsigned n=data_cdb(kind?0x8A:0x2A,0x579FF,1);run(n,2,4096);assert(r.Disposition==NufScsiWrite);
  n=data_cdb(kind?0x8A:0x2A,0x579F0,16);run(n,2,65536);assert(r.Disposition==NufScsiWrite);
  n=data_cdb(kind?0x8A:0x2A,0x579F1,16);run(n,2,65536);reject(7,0x27);
  n=data_cdb(kind?0x8A:0x2A,0x179FF,2);run(n,2,8192);reject(7,0x27);
 }pass("system_entire_span_fits_one_gib_prefix_or_is_rejected_before_any_command");
 const U32 systemDenied[]={0,1,5,0x179FF,0x57A00,0x199DFF,0x199E00,0x2221FF,0x1222200,0x3B94A04};
 for(unsigned kind=0;kind<2;kind++)for(unsigned j=0;j<sizeof(systemDenied)/sizeof(*systemDenied);j++){
  unsigned n=data_cdb(kind?0x8A:0x2A,systemDenied[j],1);run(n,2,4096);reject(7,0x27);assert(r.WriteDenied);untouched();
 }pass("system_partition_tail_gap_gpt_neighbors_and_other_partitions_are_write_protected");
 return 0;
}
