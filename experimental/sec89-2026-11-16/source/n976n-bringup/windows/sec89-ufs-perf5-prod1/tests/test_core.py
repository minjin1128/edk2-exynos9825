#!/usr/bin/env python3
"""Actual persistent UFS core/lease parser and ARM64 NC access code generation."""
import argparse, hashlib, json, os, re, subprocess, tempfile, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REQUIRED='''capacity_lba0_compare_exact_retire deadline_quarantines_no_abort guard_quarantines_no_ack tag_mismatch_no_ack ocs_failure_no_ack ack_failure_no_reuse sector_mismatch_retires capacity_mismatch_no_read stopped_clock_quarantines backward_clock_quarantines stop_failure_keeps_owned_dma fatal_is_quarantines residual_refuses format_drift_quarantines ownership_drift_no_cleanup missing_completion_no_ack prdt_immutable_quarantines scsi_failure_no_ack sense_length_refuses busy_inherited_no_write high_dma_refused dma_alias_refused unadmitted_lun_refused all_nonread_opcodes_refused read_bounds_and_tags released_lease_valid lease_crc_refused pre_ebs_lease_refused powerdown_lease_refused old_new_dma_overlap_refused pending_handoff_refused lease_tail_guard_refused baseline_crc_refused neighbor_mmio_refused reserved_fields_refused exact_acpi_resource_contract resource_kind_extra_overflow_alignment_refused engine_replay_no_write runtime_read_last_lba_tag255_retired_copy runtime_all_safety_faults_never_publish_failed_buffer runtime_last_lba_plus_one_refused runtime_exact_output_span_required invalid_engine_callbacks_never_enter_cleanup'''.split()
REQUIRED+='''persistent_admission_and_16_reads_initialize_once_keep_list_until_close stop_restart_no_clock_pause_or_dma_initialization every_immutable_region_and_word_lane_checked_before_reset_report_clear_cannot_hide_fault stop_rechecks_all_guards_before_any_controller_write restart_rejects_corruption_without_erasing_arena immediate_stop_failure_quarantines_without_wait_or_list_restore immediate_restart_failure_quarantines_without_wait restart_controller_drift_quarantines_before_writes cleared_report_cannot_reuse_unacknowledged_quarantined_slot stop_refuses_pending_doorbell_ack_or_lost_ownership_without_writes duplicate_open_and_terminal_close_replay_never_reinitialize aligned_word_access_byte_prologue_tail_and_unaligned_cpu_buffers data_out_page_remains_immutable_until_session_close no_data_page_remains_immutable_at_stop'''.split()
REQUIRED.insert(REQUIRED.index('persistent_admission_and_16_reads_initialize_once_keep_list_until_close')+1,'expanded_arena_exact_scan_coverage_with_reduced_prepare_stores')
REQUIRED.insert(REQUIRED.index('every_immutable_region_and_word_lane_checked_before_reset_report_clear_cannot_hide_fault')+1,'every_immutable_region_after_dma_checked_before_ack_or_output_publication')
REQUIRED.append('dual_physical_fences_require_exact_admitted_extents_and_refuse_neighbors_wrap_or_configuration_drift')
REQUIRED += ['command_specific_read_write_flush_budgets_and_passive_yield','write_flush_deadlines_and_stopped_backward_clock_preserve_quarantine','immediate_completion_and_dirql_stop_restart_never_sleep']
REQUIRED += ['read_1_2_16_blocks_and_large_small_large_exact_prdt_payload_and_output_canaries', 'multi_block_write_read_flush_transitions_reset_prior_tail_without_erasing_corruption', 'multi_block_zero_17_unaligned_wrap_and_exact_physical_write_end_fences', 'full_64k_fault_matrix_never_publishes_failed_buffer', 'full_prdt_zero_suffix_padding_and_final_guard_checked_before_ack', '64k_batch_reduces_16_commands_ack_and_nc_scans_with_exact_bounded_reset_counts', 'handoff_v2_22page_windows_7page_firmware_rejects_old_version_length_swap_and_old_acpi']
REQUIRED += ['perf2_actual_core_short_read_window_avoids_quantized_sleep_at_4k_and_64k_without_extra_dma', 'perf2_longer_read_reverts_to_passive_wait_and_records_actual_sleep_and_completion_interval', 'perf2_sleep_return_ownership_fatal_and_clock_regression_fail_closed_without_publication', 'perf2_missing_stall_callback_keeps_legacy_window_without_unbounded_busy_poll', 'perf2_fast_window_does_not_extend_read_deadline_or_replay_timed_out_request']
REQUIRED += ['perf4_write4k_64k_flush_short_completion_and_unsampled_policy_preserve_real_commands','perf4_write_flush_after_one_ms_yield_and_record_observation','perf4_write_flush_stall_and_wake_ownership_fatal_clock_fail_closed','perf4_write_flush_missing_stall_keeps_legacy_bounded_fallback']
REQUIRED += ['perf5_read_destination_not_rewritten_full_guards_and_complete_output_retained','perf5_retired_tail_scrubbed_response_allocation_preserved_only_consumed_bytes_reset','perf5_missing_response_cannot_reuse_previous_success_or_publish_stale_payload','perf5_delta_descriptor_update_never_masks_corruption_before_reuse']
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 if not os.environ.get('N976N_RAM_SCRATCH_PATH'):raise SystemExit('run through tools/ram_scratch.py')
 a.out.mkdir(parents=True,exist_ok=False);start=time.monotonic()
 source=['N976nUfsSystem.h','N976nUfsNtfsExpected.h','N976nUfsCore.c','N976nUfsCore.h','N976nUfsLease.c','N976nUfsLease.h','N976nUfsHandoff.h','tests/core_cases.c','tests/test_core.py']
 checks=[];passed=False;assembly={}
 with tempfile.TemporaryDirectory(prefix='ufs-core-') as tmp:
  temp=Path(tmp)
  cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-I',str(ROOT),str(ROOT/'N976nUfsCore.c'),str(ROOT/'N976nUfsLease.c'),str(ROOT/'tests/core_cases.c'),'-o',str(temp/'cases')]
  b=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(a.out/'compile.log').write_text(b.stdout+b.stderr)
  if b.returncode==0:
   r=subprocess.run([str(temp/'cases')],text=True,capture_output=True,timeout=60)
   (a.out/'run.log').write_text(r.stdout+r.stderr);checks=r.stdout.splitlines();passed=r.returncode==0 and checks==REQUIRED
  (temp/'stddef.h').write_text('typedef __SIZE_TYPE__ size_t;\n#define NULL ((void*)0)\n')
  (temp/'string.h').write_text('#include <stddef.h>\nvoid *memcpy(void*,const void*,size_t);\nvoid *memset(void*,int,size_t);\n')
  acmd=['clang','-target','aarch64-none-elf','-std=c11','-O2','-ffreestanding','-fno-inline','-nostdinc','-I',str(temp),'-I',str(ROOT),'-S',str(ROOT/'N976nUfsCore.c'),'-o',str(temp/'core.s')]
  ab=subprocess.run(acmd,text=True,capture_output=True,timeout=60);(a.out/'arm64-compile.log').write_text(ab.stdout+ab.stderr)
  if ab.returncode==0:
   asm=(temp/'core.s').read_text();(a.out/'core-arm64.s').write_text(asm)
   for name,op,reg in [('ncword','ldr','w'),('ncput','str','w'),('ncguard64','ldr','x'),('ncput64','str','x')]:
    match=re.search(r'^'+name+r':.*?^\.Lfunc_end\d+:',asm,re.M|re.S)
    body=match.group(0) if match else ''
    assembly[name]={'scalar_word':bool(re.search(r'\b'+op+r'\s+'+reg+r'\d+,\s*\[x0\]',body)),
     'no_unaligned_pair_vector':not bool(re.search(r'\b(?:ldur|stur|ldp|stp|ld1|st1)\b|\b[qdsv]\d+\b',body)), 'body':body}
   assembly['passed']=all(v['scalar_word'] and v['no_unaligned_pair_vector'] for v in assembly.values()) and len(assembly)==4
  else:assembly['passed']=False
 report={'milestone':'SEC89 UFS PERF5','passed':passed and assembly.get('passed',False),'checks':checks,'required_cases':REQUIRED,'arm64_nc_access':assembly,'operation_counts':{'small_read_arena_bytes':90112,'same_read_command_reset_bytes':60,'small_read_18_command_reset_bytes':1208,'small_read_18_command_scanned_bytes':3064797,'note':'checked inactive payload tail increases small-command scan cost; batching reduces scans per transferred byte; hardware throughput unverified'},'source_sha256':{str((ROOT/s).relative_to(ROOT.parents[1])):hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in source},'hardware_verified':False,'elapsed_seconds':time.monotonic()-start,'scope':'actual persistent core and lease parser; exact byte guards, lifecycle, errors and aligned ARM64 scalar code generation; not Windows PnP or physical DMA'}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'passed':report['passed'],'checks':len(checks),'assembly':assembly.get('passed',False),'report':str(a.out/'report.json')}));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
