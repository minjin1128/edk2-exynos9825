#!/usr/bin/env python3
import argparse,hashlib,json,os,platform,subprocess,time
from pathlib import Path
from render_ranges import render
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser();p.add_argument('--out',required=True,type=Path);a=p.parse_args()
 assert os.environ.get('N976N_RAM_SCRATCH_PATH') and platform.machine()=='arm64' and platform.system()=='Darwin'
 a.out.mkdir(parents=True,exist_ok=False);start=time.monotonic();checks=[];results=[]
 asm=a.out/'ranges.S';asm.write_text(render(ROOT/'N976nNcRanges.asm'))
 obj=a.out/'ranges.o';b=subprocess.run(['clang','-c',str(asm),'-o',str(obj)],capture_output=True,text=True,timeout=60)
 (a.out/'asm-build.log').write_text(b.stdout+b.stderr)
 if b.returncode==0:
  for name,source,flags in [('bulk-sanitized','bulk_cases.c',['-O1','-fsanitize=address,undefined']),('bulk-optimized','bulk_cases.c',['-O2']),('core','core_cases.c',['-O1','-fsanitize=address,undefined']),('pages','ranges_pages.c',['-O2'])]:
   command=['clang','-std=c11','-DNUF_NC_RANGES=1','-Wall','-Wextra','-Werror','-Wno-misleading-indentation',*flags,'-I',str(ROOT),str(ROOT/'tests'/source),str(obj)]
   if name=='core':command += [str(ROOT/'N976nUfsCore.c'),str(ROOT/'N976nUfsLease.c')]
   command += ['-o',str(a.out/'cases')]
   r=subprocess.run(command,capture_output=True,text=True,timeout=60);(a.out/(name+'-compile.log')).write_text(r.stdout+r.stderr)
   if r.returncode:results.append({'test':name,'compile':r.returncode});break
   r=subprocess.run([str(a.out/'cases')],capture_output=True,text=True,timeout=90,env={**os.environ,'UBSAN_OPTIONS':'halt_on_error=1','ASAN_OPTIONS':'abort_on_error=1'})
   (a.out/(name+'-run.log')).write_text(r.stdout+r.stderr);results.append({'test':name,'exit_code':r.returncode})
   if r.returncode:break
   if name=='core':
    from test_core import REQUIRED
    assert r.stdout.splitlines()==REQUIRED
   checks.append(name)
 report={'passed':len(checks)==4,'checks':checks,'results':results,'elapsed_seconds':time.monotonic()-start,'source_sha256':{str(p.relative_to(ROOT)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [ROOT/'N976nNcRanges.asm',ROOT/'N976nUfsCore.c',ROOT/'tests/render_ranges.py',ROOT/'tests/ranges_pages.c']},'scope':'Actual scalar ARM64 instructions executed on local ARM64 CPU using managed RAM. WB host pages, not device DMA/NC performance. Native ARMASM object and final SYS binding checked separately. Assembly is not ASan-instrumented; exact-end protected pages supplement C sanitizer.'}
 (a.out/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps(report));return 0 if report['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
