#!/usr/bin/env python3
"""Exact resource delta and actual RX1 runtime regression in managed RAM."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

HERE=Path(__file__).resolve().parent
SRC=HERE.parent
PROJECT=SRC.parents[1]
ROOT=PROJECT.parent
sys.path.insert(0,str(ROOT/'tools'))
from ram_scratch import RamScratch

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    a=argparse.ArgumentParser();a.add_argument('--output',type=Path,required=True);args=a.parse_args()
    if args.output.exists():raise SystemExit('new evidence path required')
    baseline=PROJECT/'windows/sec88-touch-rx1'
    battery=PROJECT/'windows/sec88-battery-live1'
    names=['ClockShare.h','ClockShare.c','Device.c','N976nDemoRuntime.c','N976nY771Touch.inf',
           'N976nY771Touch.vcxproj','tests/clockshare_cases.c','tests/runtime_cases.c',
           'tests/runtime_mocks/clockshare_mocks.inc','tests/runtime_mocks/wdf.h',
           'tests/runtime_mocks/ntddk.h','tests/test_sec76_portable.py',
           'tests/run-clockshare-tests.py']
    before={n:digest(SRC/n) for n in names}
    result={'passed':False,'hardware_verified':False,'source_sha256':before,'runs':[],
            'omitted':['Actual WDK ARM64 compilation','Windows resource arbitration',
                       'Physical shared TOP observation','Paired installation/deployment']}
    scratch=RamScratch(64);start=time.monotonic()
    try:
        for name in ('ClockShare.h','ClockShare.c'):
            assert (SRC/name).read_bytes()==(battery/name).read_bytes(),'helper copies differ'
        changed_production={'Device.c','N976nDemoRuntime.c','N976nY771Touch.vcxproj',
                            'N976nY771Touch.inf','Build-Sec76.ps1','build-local-parallels.py'}
        checked=[]
        for f in baseline.iterdir():
            if not f.is_file() or f.suffix not in {'.c','.h','.inf','.vcxproj','.ps1','.py'}:continue
            if f.name not in changed_production:
                assert f.read_bytes()==(SRC/f.name).read_bytes(),f'out-of-scope change: {f.name}'
                checked.append(f.name)
        runtime=(SRC/'N976nDemoRuntime.c').read_text()
        old=(baseline/'N976nDemoRuntime.c').read_text()
        # The entire runtime outside Prepare is byte-identical except include.
        def without_prepare(text):
            text=text.replace('#include "ClockShare.h"\n','')
            start=text.index('NTSTATUS N976nDemoPrepare(')
            brace=text.index('{',start);depth=1;i=brace+1
            while depth:
                depth+=(text[i]=='{')-(text[i]=='}');i+=1
            return text[:start]+text[i:]
        assert without_prepare(runtime)==without_prepare(old),'non-Prepare transport/runtime changed'
        device=(SRC/'Device.c').read_text()
        expect=(baseline/'Device.c').read_text().replace('#include "N976nWdfResources.h"',
          '#include "N976nWdfResources.h"\n#include "ClockShare.h"').replace('WdfFdoInitSetFilter(DeviceInit);',
          'WdfFdoInitSetFilter(DeviceInit);\n\t/* Only exact observational TOP is shared with the battery frontend. */\n\tN976nClockShareRegister(DeviceInit);')
        assert device==expect,'Device delta exceeds filter registration'
        assert 'Protection=(I==0||I==5)?PAGE_READWRITE:PAGE_READONLY;' in runtime
        assert 'if(I!=N976nMapHandoff)Protection|=PAGE_NOCACHE;' in runtime
        assert runtime.count('WRITE_REGISTER_ULONG(')==1
        write=runtime[runtime.index('static int WriteHsi('):runtime.index('static N976N_U64 NowUs(')]
        assert 'WRITE_REGISTER_ULONG((PULONG)(R->Map[0]+O),V)' in write
        assert 'DriverVer = 11/04/2026,0.0.88.4' in (SRC/'N976nY771Touch.inf').read_text()
        assert 'ACPI\\NNTC0076' in (SRC/'N976nY771Touch.inf').read_text()
        result['delta_checks']={'unchanged_production_files':checked,'only_Device_registration':True,
          'non_Prepare_runtime_byte_identical':True,'TOP_map_readonly_nocache':True,
          'single_MMIO_write_sink_HSI0_only':True,'same_HID_service_version_increased':True,
          'battery_and_touch_helper_identical':True}
        with scratch:
            env=dict(os.environ,TMPDIR=str(scratch.path),N976N_RAM_SCRATCH_PATH=str(scratch.path))
            for name,flags in [('O2',['-O2']),('ASan-UBSan',['-O1','-g','-fsanitize=address,undefined','-fno-sanitize-recover=all'])]:
                binary=scratch.path/name
                cmd=['clang','-std=c11','-Wall','-Wextra','-Werror',*flags,
                     '-I',str(HERE/'runtime_mocks'),'-I',str(SRC),str(SRC/'ClockShare.c'),
                     str(HERE/'clockshare_cases.c'),'-o',str(binary)]
                b=subprocess.run(cmd,env=env,capture_output=True,text=True,timeout=60)
                run={'name':name,'compile_return':b.returncode,'compile_stderr':b.stderr};result['runs'].append(run)
                if b.returncode:raise RuntimeError('clockshare compile failed')
                r=subprocess.run([str(binary)],env=env,capture_output=True,text=True,timeout=30)
                run.update(exit_code=r.returncode,stdout=r.stdout,stderr=r.stderr)
                if r.returncode:raise RuntimeError('clockshare test failed')
                run['cases']=int(re.search(r'PASS (\d+) cases',r.stdout).group(1))
            runtime_out=scratch.path/'runtime.json'
            r=subprocess.run([sys.executable,str(HERE/'test_sec76_portable.py'),'--suites','runtime',
                              '--output',str(runtime_out)],env=env,capture_output=True,text=True,timeout=90)
            result['runtime']=json.loads(runtime_out.read_text()) if runtime_out.exists() else {}
            if r.returncode:raise RuntimeError('runtime failed: '+r.stdout+r.stderr)
            scratch.check()
        assert before=={n:digest(SRC/n) for n in names},'inputs changed during tests'
        result['passed']=True
    except Exception as e:result['error']=repr(e)
    result['ram']=scratch.info;result['seconds']=time.monotonic()-start
    args.output.parent.mkdir(parents=True,exist_ok=True)
    with args.output.open('x') as f:json.dump(result,f,indent=2);f.write('\n')
    print(json.dumps({'passed':result['passed'],'resource_cases':[r.get('cases') for r in result['runs']],
                      'runtime_groups':len(result.get('runtime',{}).get('suites',{}).get('runtime',{}).get('checks',[])),
                      'error':result.get('error')}))
    return 0 if result['passed'] else 1

if __name__=='__main__':raise SystemExit(main())
