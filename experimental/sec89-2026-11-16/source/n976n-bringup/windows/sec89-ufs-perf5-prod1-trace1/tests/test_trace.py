#!/usr/bin/env python3
"""Compile actual SEC88 PERF2 miniport with fake DDI; exercise mapping/cancel lifetime."""
import argparse, hashlib, json, os, subprocess, time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
import re
REQUIRED=re.findall(r'pass\("([^"\n]+)"\)',(ROOT/'tests/trace_cases.c').read_text())

def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);p.add_argument('--policy',type=int,choices=(1,2),default=1);a=p.parse_args()
 if not os.environ.get('N976N_RAM_SCRATCH_PATH'):raise SystemExit('run through tools/ram_scratch.py')
 a.out.mkdir(parents=True,exist_ok=False);start=time.monotonic()
 binary=Path(os.environ['N976N_RAM_SCRATCH_PATH'])/('ufs-lifecycle-'+str(os.getpid()))
 source=['N976nUfsTrace.h','N976nUfsSystem.h','tests/system_fat_boot.h','N976nGptVolumeView.c','N976nGptVolumeView.h','N976nUfsScope.c','N976nUfsScope.h','N976nUfsNtfsExpected.h','N976nUfsGpt.c','N976nUfsGpt.h','N976nUfs.c','N976nUfsCore.c','N976nUfsCore.h','N976nUfsScsi.c','N976nUfsScsi.h','N976nUfsGptView.c','N976nUfsGptView.h','N976nUfsLease.c','N976nUfsLease.h','N976nUfsHandoff.h','tests/lifecycle_cases.c','tests/trace_cases.c','tests/test_trace.py','tests/fake-ddi/ntddk.h','tests/fake-ddi/ntddscsi.h','tests/fake-ddi/storport.h']
 binding=lambda:{str((ROOT/s).relative_to(ROOT.parents[1])):hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in source}
 before=binding()
 cmd=['clang','-DNUF_RUNTIME_GUARD_POLICY='+str(a.policy),'-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-I',str(ROOT/'tests/fake-ddi'),'-I',str(ROOT),str(ROOT/'N976nUfsCore.c'),str(ROOT/'N976nUfsLease.c'),str(ROOT/'N976nUfsScsi.c'),str(ROOT/'N976nUfsGptView.c'),str(ROOT/'N976nGptVolumeView.c'),str(ROOT/'N976nUfsScope.c'),str(ROOT/'N976nUfsGpt.c'),str(ROOT/'tests/trace_cases.c'),'-o',str(binary)]
 checks=[];passed=False
 env={**os.environ,'N976N_TRACE_EVIDENCE':str(a.out.resolve()),'UBSAN_OPTIONS':'halt_on_error=1','ASAN_OPTIONS':'abort_on_error=1'}
 b=subprocess.run(cmd,text=True,capture_output=True,timeout=60)
 (a.out/'compile.log').write_text(b.stdout+b.stderr)
 if b.returncode==0:
  r=subprocess.run([str(binary)],text=True,capture_output=True,timeout=60,env=env)
  (a.out/'run.log').write_text(r.stdout+r.stderr);checks+=[x for x in r.stdout.splitlines() if not x.startswith("ABI ")]
  (a.out/"abi.txt").write_text("\n".join(x for x in r.stdout.splitlines() if x.startswith("ABI "))+"\n")
  passed=r.returncode==0 and checks==REQUIRED
 passed=passed and before==binding()
 binary.unlink(missing_ok=True)
 report={'guard_policy':a.policy,'milestone':'SEC89 UFS PERF5','passed':passed,'checks':checks,'required_cases':REQUIRED,'source_sha256':before,'hardware_verified':False,'elapsed_seconds':time.monotonic()-start,'scope':'Actual SEC88 PERF2 miniport/Core/Scope/GPT/SCSI/lease with fake DDI and bounded sparse media. No stub admission or write body. Target28000 Running/Queued/deferred-free worker model retains fixed ownership checks. Version3 exact real SYSTEM ESP/FAT prefix plus USERDATA admission, write-back completion, whole-SRB FUA, explicit barriers and cache-dirty stop/removal are exercised. Preserved FIX1 legacy-busy replay is not rerun. Not actual Windows scheduling, physical DMA, NTFS driver operation or power-loss durability'}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ("passed","elapsed_seconds","checks")}));return 0 if passed else 1
if __name__=='__main__':raise SystemExit(main())
