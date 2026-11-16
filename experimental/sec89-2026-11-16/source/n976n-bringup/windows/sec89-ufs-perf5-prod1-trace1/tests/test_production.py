#!/usr/bin/env python3
"""Cyclic policy fault injection and actual miniport integration, managed RAM only."""
import argparse,hashlib,json,os,re,subprocess,sys,time
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',type=Path,required=True);a=p.parse_args()
 ram=Path(os.environ['N976N_RAM_SCRATCH_PATH']);a.out.mkdir(parents=True,exist_ok=False);start=time.monotonic()
 sources=['N976nUfsCore.c','N976nUfsCore.h','N976nUfsLease.c','N976nUfsLease.h','N976nUfsHandoff.h','N976nUfsSystem.h','N976nUfsNtfsExpected.h','tests/core_cases.c','tests/production_cases.c','tests/test_production.py']
 binding=lambda:{s:hashlib.sha256((ROOT/s).read_bytes()).hexdigest() for s in sources}
 before=binding();binary=ram/'production-cases'
 required=re.findall(r'pass\("([^"\n]+)"\)',(ROOT/'tests/production_cases.c').read_text())
 cmd=['clang','-std=c11','-O1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation','-fsanitize=address,undefined','-I',str(ROOT),str(ROOT/'N976nUfsCore.c'),str(ROOT/'N976nUfsLease.c'),str(ROOT/'tests/production_cases.c'),'-o',str(binary)]
 b=subprocess.run(cmd,capture_output=True,text=True,timeout=60);(a.out/'compile.log').write_text(b.stdout+b.stderr)
 checks=[];passed=False
 if b.returncode==0:
  r=subprocess.run([str(binary)],capture_output=True,text=True,timeout=120,env={**os.environ,'ASAN_OPTIONS':'abort_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'})
  (a.out/'run.log').write_text(r.stdout+r.stderr);checks=r.stdout.splitlines();passed=r.returncode==0 and checks==required
 binary.unlink(missing_ok=True)
 r=subprocess.run([sys.executable,'-B',str(ROOT/'tests/test_lifecycle.py'),'--out',str(a.out/'lifecycle'),'--policy','2'],capture_output=True,text=True,timeout=120)
 (a.out/'lifecycle-runner.log').write_text(r.stdout+r.stderr)
 lifecycle=json.loads((a.out/'lifecycle/report.json').read_text())
 report={'milestone':'SEC89 UFS PERF5 PROD1','guard_policy':2,'passed':passed and r.returncode==0 and lifecycle['passed'] and before==binding(),'checks':checks+lifecycle['checks'],'required_core_cases':required,'core_passed':passed,'lifecycle_passed':lifecycle['passed'],'source_sha256':before,'elapsed_seconds':time.monotonic()-start,'hardware_verified':False,'scope':'Actual core sanitizer fault matrices; 16-page sweep, growth and shrink evidence, mandatory immediate checks, retained lifecycle, real miniport with fake DDI. Not physical DMA, timing, Windows scheduling or durability.'}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({k:report[k] for k in ('passed','core_passed','lifecycle_passed','elapsed_seconds')}));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
