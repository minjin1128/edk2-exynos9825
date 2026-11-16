#!/usr/bin/env python3
"""Actual repeated Windows battery transport on managed RAM; no device/VM."""
import argparse, hashlib, json, os, platform, re, subprocess, sys, time
from pathlib import Path
HERE=Path(__file__).resolve().parent
PROJECT=HERE.parents[2]
sys.path.insert(0,str(PROJECT.parent/'tools'))
from ram_scratch import RamScratch

def main():
    p=argparse.ArgumentParser();p.add_argument('--output',type=Path,required=True);a=p.parse_args()
    if a.output.exists():raise SystemExit('Choose a new evidence output')
    base=HERE.parent;common=PROJECT/'common/sec88-battery1'
    firmware=PROJECT/'edk2/sec89-power/N976nPlatformPkg/Include'
    edk=PROJECT/'references/edk2/MdePkg/Include'
    inputs=[PROJECT/'common/sec89-charge-control3/ChargeControl.h']+[base/x for x in ['Bus.c','Bus.h','Backend.c','Backend.h','Lease.c','Lease.h','Charge.c','Charge.h']]+[HERE/'control_bus_cases.c',HERE/'charge_cases.c',HERE/'d0_cases.c',HERE/'bus_cases.c',HERE/'lifecycle_cases.c',HERE/'uefi_adapter_cases.c',HERE/'lease_cases.c',Path(__file__),common/'N976nBattery.c',common/'N976nBattery.h',firmware/'N976nBatteryTypes.h',edk/'Uefi.h',edk/'Base.h',edk/'AArch64/ProcessorBind.h']
    hashes=lambda:{str(f.relative_to(PROJECT)):hashlib.sha256(f.read_bytes()).hexdigest() for f in inputs}
    before=hashes();r={'passed':False,'hardware_verified':False,'source_sha256':before,'host':platform.platform(),'runs':[],
      'coverage':'Actual portable transport: dormant capture/ownership, Samsung-order initialization, initialized FIFO checks, pre-config and post-config failures, repeated exact restoration; existing 9 register pairs, DONE/ACK, binding drift, cancellation/deadlines and quarantine.',
      'omitted':['Physical MMIO/clock behavior','ACPI resource translation','EBS/GIC lease','Battc/PnP lifecycle','Parallels ARM64 build']}
    scratch=RamScratch(64);start=time.monotonic()
    try:
      with scratch:
        t=scratch.path;env=dict(os.environ,TMPDIR=str(t))
        variants=[('control-O2',['-O2'],'control_bus_cases.c'),('control-asan-ubsan',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'],'control_bus_cases.c'),('charge-O2',['-O2'],'charge_cases.c'),('charge-asan-ubsan-O1',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'],'charge_cases.c'),('d0-O2',['-O2'],'d0_cases.c'),('d0-asan-ubsan-O1',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'],'d0_cases.c'),('lifecycle-O2',['-O2'],'lifecycle_cases.c'),('lifecycle-asan-ubsan-O1',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'],'lifecycle_cases.c'),('warnings-O2',['-O2'],'bus_cases.c'),('asan-ubsan-O1',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'],'bus_cases.c'),('uefi-adapter-O2',['-O2','-fshort-wchar'],'uefi_adapter_cases.c'),('lease-O2',['-O2'],'lease_cases.c'),('uefi-lease-O2',['-O2','-fshort-wchar','-DN976N_TEST_UEFI_TYPES'],'lease_cases.c')]
        includes=['-I',str(PROJECT/'common/sec89-charge-adcwin1'),'-I',str(PROJECT/'common/sec89-charge-thermal1'),'-I',str(PROJECT/'common/sec89-charge-control3'),'-I',str(common),'-I',str(firmware),'-I',str(edk),'-I',str(edk/'AArch64')]
        for name,flags,source in variants:
          cmd=['clang','-std=c11','-Wall','-Wextra','-Werror',*flags,*includes,str(HERE/source),'-o',str(t/name)]
          b=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
          run={'name':name,'compile_return':b.returncode,'compile_stderr':b.stderr};r['runs'].append(run)
          if b.returncode:raise RuntimeError('compile failed')
          c=subprocess.run([str(t/name)],capture_output=True,text=True,env=env,timeout=30)
          run.update(exit_code=c.returncode,stdout=c.stdout,stderr=c.stderr)
          if c.returncode:raise RuntimeError('test failed')
          run['cases']=int(re.search(r'PASS (\d+) cases',c.stdout).group(1))
        for source in ['Bus','Lease']:
          cmd=['clang','--target=aarch64-none-elf','-ffreestanding','-fshort-wchar','-std=c11','-Wall','-Wextra','-Werror','-O2',*includes,'-include','N976nBatteryTypes.h','-c',str(base/(source+'.c')),'-o',str(t/(source+'-uefi-aarch64.o'))]
          b=subprocess.run(cmd,capture_output=True,text=True,env=env,timeout=60)
          r['runs'].append({'name':'uefi-aarch64-freestanding-'+source,'compile_return':b.returncode,'compile_stderr':b.stderr})
          if b.returncode:raise RuntimeError('UEFI freestanding actual source compile failed')
        scratch.check()
        if hashes()!=before:raise RuntimeError('source changed during tests')
        r['passed']=True
    except Exception as e:r['error']=repr(e)
    r['ram']=scratch.info;r['seconds']=time.monotonic()-start
    a.output.parent.mkdir(parents=True,exist_ok=True)
    with a.output.open('x') as f:json.dump(r,f,indent=2);f.write('\n')
    print(json.dumps({'passed':r['passed'],'output':str(a.output),'runs':[(x['name'],x.get('exit_code',x.get('compile_return'))) for x in r['runs']]}))
    return 0 if r['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
