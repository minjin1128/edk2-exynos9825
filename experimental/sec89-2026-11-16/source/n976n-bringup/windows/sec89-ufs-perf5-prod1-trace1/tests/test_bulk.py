#!/usr/bin/env python3
import argparse, hashlib, json, os, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 assert os.environ.get('N976N_RAM_SCRATCH_PATH');a.out.mkdir(exist_ok=False,parents=True);start=time.monotonic();checks=[]
 for kind,flags in [('sanitized',['-O1','-fsanitize=address,undefined']),('optimized',['-O2'])]:
  command=['clang','-std=c11','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',*flags,str(ROOT/'tests/bulk_cases.c'),'-o',str(a.out/'cases')]
  b=subprocess.run(command,capture_output=True,text=True,timeout=60);(a.out/(kind+'-compile.log')).write_text(b.stdout+b.stderr)
  if b.returncode:break
  v=subprocess.run([str(a.out/'cases')],capture_output=True,text=True,timeout=60,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1','ASAN_OPTIONS':'abort_on_error=1'})
  (a.out/(kind+'-run.log')).write_text(v.stdout+v.stderr)
  if v.returncode or v.stdout.strip()!='scalar64_alignment_tail_exact_bounds_and_first_mismatch_7304_cases':break
  checks.append(kind+'_7304_alignment_bounds_mismatch_cases')
 report={'passed':len(checks)==2,'checks':checks,'elapsed_seconds':time.monotonic()-start,'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'N976nUfsCore.c',ROOT/'N976nUfsCore.h',ROOT/'tests/bulk_cases.c']},'physical_hardware_verified':False}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
