#!/usr/bin/env python3
"""Actual three-channel thermal producer under fault injection; local managed RAM, no device I/O."""
import argparse, hashlib, json, os, platform, re, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(ROOT/'tools'))
from ram_scratch import RamScratch

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise SystemExit('Preserve prior evidence: choose a new output')
    control=ROOT/'n976n-bringup/common/sec89-charge-control3'
    thermal=ROOT/'n976n-bringup/common/sec89-charge-thermal1'
    common=ROOT/'n976n-bringup/common/sec88-battery1'
    inputs=[HERE/'thermal-bridge-tests.c',Path(__file__),control/'tests/twrp_dt_fixture.h',
            HERE.parent/'ThermalBridge.c',HERE.parent/'ThermalBridge.h',HERE.parent/'Charge.c',HERE.parent/'Charge.h',
            thermal/'Thermal.c',thermal/'Thermal.h',control/'ChargeControl.c',control/'ChargeControl.h',common/'N976nBattery.h']
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
          cmd=['clang','-std=c11','-Wall','-Wextra','-Werror',*flags,'-I'+str(HERE.parent),'-I'+str(control),'-I'+str(thermal),'-I'+str(common),str(HERE/'thermal-bridge-tests.c'),str(HERE.parent/'ThermalBridge.c'),str(HERE.parent/'Charge.c'),str(thermal/'Thermal.c'),str(control/'ChargeControl.c'),'-o',str(binary)]
          b=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
          row={'name':name,'compile_exit':b.returncode,'compile_stderr':b.stderr};r['runs'].append(row)
          if b.returncode:raise RuntimeError('compile failed')
          x=subprocess.run([str(binary)],capture_output=True,text=True,env=env,timeout=30)
          row.update(exit_code=x.returncode,stdout=x.stdout,stderr=x.stderr)
          if x.returncode:raise RuntimeError('test failed')
          row['assertions']=int(re.search(r'PASS (\d+) assertions',x.stdout).group(1))
        for name,target in [('aarch64-elf','aarch64-none-elf'),('arm64-windows','aarch64-pc-windows-msvc')]:
          cmd=['clang','--target='+target,'-ffreestanding','-std=c11','-Wall','-Wextra','-Werror','-O2',
               '-I'+str(control),'-I'+str(thermal),'-I'+str(common),'-c',str(HERE.parent/'ThermalBridge.c'),'-o',str(scratch.path/(name+'.o'))]
          x=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
          r['runs'].append({'name':name,'compile_exit':x.returncode,'stderr':x.stderr})
          if x.returncode:raise RuntimeError('freestanding compile failed')
        scratch.check()
        if hashes()!=before:raise RuntimeError('source changed during tests')
        r['passed']=True
    except Exception as e:r['error']=repr(e)
    r['ram']=scratch.info;r['seconds']=time.monotonic()-start
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps(r));return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
