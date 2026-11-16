#!/usr/bin/env python3
"""Actual WDF ADC adapter callback and wait fault injection; local managed RAM, no device I/O."""
import argparse, hashlib, json, os, platform, re, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from ram_scratch import RamScratch

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise SystemExit('Preserve prior evidence: choose a new output')
    control=ROOT/'n976n-bringup/common/sec89-charge-win1'
    core=ROOT/'n976n-bringup/common/sec89-charge-adcwin1'
    thermal=ROOT/'n976n-bringup/common/sec89-charge-thermal1'
    inputs=[HERE/'adc-wdf-tests.c',Path(__file__),HERE.parent/'AdcWdf.c',HERE.parent/'AdcWdf.h',
            HERE/'adc_mocks/ntddk.h',HERE/'adc_mocks/wdf.h',core/'Adc.c',core/'Adc.h',thermal/'Thermal.h',control/'ChargeControl.h']
    hashes=lambda:{str(f.relative_to(ROOT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in inputs}
    before=hashes();r={'passed':False,'hardware_verified':False,'production_adapter_connected':False,
      'host':platform.platform(),'source_sha256':before,'runs':[],
      'omitted':['Real ADC/HSI/PMIC/USB-C/watchdog','Physical ADC producer and Windows IRQ/lifetime integration','Parallels WDK driver build','Charging candidate packaging','Physical writes']}
    scratch=RamScratch(64);start=time.monotonic()
    try:
      with scratch:
        env=dict(os.environ,TMPDIR=str(scratch.path))
        for name,flags in [('O2',['-O2']),('asan-ubsan',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'])]:
          binary=scratch.path/name
          cmd=['clang','-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(HERE/'adc_mocks'),'-I'+str(core),'-I'+str(control),'-I'+str(thermal),str(HERE/'adc-wdf-tests.c'),str(core/'Adc.c'),'-o',str(binary)]
          b=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
          row={'name':name,'compile_exit':b.returncode,'compile_stderr':b.stderr};r['runs'].append(row)
          if b.returncode:raise RuntimeError('compile failed')
          x=subprocess.run([str(binary)],capture_output=True,text=True,env=env,timeout=30)
          row.update(exit_code=x.returncode,stdout=x.stdout,stderr=x.stderr)
          if x.returncode:raise RuntimeError('test failed')
          row['assertions']=int(re.search(r'PASS (\d+) assertions',x.stdout).group(1))
        scratch.check()
        if hashes()!=before:raise RuntimeError('source changed during tests')
        r['passed']=True
    except Exception as e:r['error']=repr(e)
    r['ram']=scratch.info;r['seconds']=time.monotonic()-start
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
