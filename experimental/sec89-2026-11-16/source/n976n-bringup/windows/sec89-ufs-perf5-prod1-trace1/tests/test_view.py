#!/usr/bin/env python3
"""Compile the unchanged shared immutable GPT CPU view with refusal oracles."""
import argparse, hashlib, json, os, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
REQUIRED=['raw_primary_backup_identity_and_ntfs_policy_seal', 'both_gpt_arrays_headers_crc_and_other_bytes_exact', 'raw_snapshots_unchanged_no_media_write', 'entry_block_repeat_and_backup_first_independent', 'entry_positions_across_all_array_blocks', 'nonmetadata_payload_and_old_tail_unchanged', 'partial_sector_apply_refused_without_mutation', 'fresh_header_and_array_drift_refused_before_mutation', 'missing_backup_array_block_refused', 'both_original_header_crc_failures_refused', 'array_crc_and_crc_valid_pair_mismatch_refused', 'exact_disk_and_partition_identity_required', 'raw_extent_mismatch_enlargement_and_overflow_refused', 'attributes_and_exact_name_required', 'raw_partition_overlap_refused', 'unknown_header_extension_refused', 'uefi_canonical_92_byte_snapshot_supported', 'windows_512_and_uefi_92_inputs_produce_identical_both_headers_and_arrays', 'repeated_capture_requires_exact_raw_match', 'sealed_state_cannot_be_rebuilt', 'sealed_scalar_corruption_refused_before_addressing', 'view_buffer_policy_and_changed_alias_refused']
REQUIRED += ['span_primary_backup_header_array_and_payload_match_independent_single_sector_oracle','span_late_metadata_drift_leaves_entire_buffer_and_result_unchanged','span_nonmetadata_still_validates_seal_and_preserves_payload','span_whole_extent_overflow_alias_and_1_to_16_block_bounds_fail_before_mutation']

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 a.out.mkdir(parents=True,exist_ok=False);start=time.monotonic()
 source=['N976nGptVolumeView.c','N976nGptVolumeView.h','tests/view_cases.c','tests/test_view.py']
 binding=lambda:{str((ROOT/s).relative_to(ROOT.parents[1])):hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in source}
 before=binding()
 cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined',str(ROOT/'N976nGptVolumeView.c'),str(ROOT/'tests/view_cases.c'),'-o',str(a.out/'cases')]
 b=subprocess.run(cmd,text=True,capture_output=True,timeout=60);(a.out/'compile.log').write_text(b.stdout+b.stderr)
 checks=[];passed=False
 if b.returncode==0:
  r=subprocess.run([str(a.out/'cases')],text=True,capture_output=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1','ASAN_OPTIONS':'abort_on_error=1'})
  (a.out/'run.log').write_text(r.stdout+r.stderr);checks=r.stdout.splitlines();passed=r.returncode==0 and checks==REQUIRED
 passed=passed and before==binding()
 report={'milestone':'SEC86 inherited GPT view','passed':passed,'checks':checks,'required_cases':REQUIRED,'source_sha256':before,'hardware_verified':False,'elapsed_seconds':time.monotonic()-start,'scope':'Actual shared immutable GPT view core; no hardware or physical Windows proof'}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
