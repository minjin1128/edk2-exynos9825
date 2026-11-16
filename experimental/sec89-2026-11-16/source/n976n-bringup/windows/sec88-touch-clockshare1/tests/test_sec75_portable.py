#!/usr/bin/env python3
"""Focused SEC76 resource, parser and HID helper checks; managed RAM only."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time

FUNCTIONS = ['TouchResetInputStateLocked', 'TouchInitializeReport', 'TouchAppendContact',
 'TouchBuildCurrentReportLocked', 'TouchBeginRecoveryLocked', 'TouchCommitReportLocked',
 'TouchReportCanCoalesce', 'TouchEnqueueReportLocked', 'TouchQueueCurrentReportLocked',
 'TouchApplyDecodedEventLocked', 'RequestCopyFromBuffer', 'TouchDrainInputReports',
 'TouchAnyContactActiveLocked', 'TouchArmHoldTimer', 'TouchHoldTimerFunc',
 'TouchQueueAllUpReport', 'TouchStopInput']

def no_comments(text):
    return re.sub(r'/\*.*?\*/|//[^\n]*', '', text, flags=re.S)

def function(source, name):
    m = re.search(r'(?m)^(?:static\n)?(?:VOID|BOOLEAN|NTSTATUS)\n'+name+r'\(',source)
    assert m, name
    start = source.index('{',m.start()); level=0
    for i in range(start,len(source)):
        if source[i]=='{':level+=1
        if source[i]=='}':
            level-=1
            if level==0:return source[m.start():i+1]
    raise AssertionError(name)

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--output',type=Path,required=True)
    a=ap.parse_args()
    if a.output.exists():raise SystemExit('Use a fresh evidence path')
    scratch=os.environ.get('N976N_RAM_SCRATCH_PATH')
    if not scratch or not Path(scratch).is_dir():raise SystemExit('Managed RAM scratch required')
    project=Path(__file__).resolve().parents[3];port=project/'windows/sec76'
    files=[p for p in port.rglob('*') if p.is_file() and p.suffix in ('.c','.h','.py','.vcxproj','.inf','.asl')]
    def bindings():return {str(p.relative_to(port)):hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
    before=bindings();tick=time.monotonic()
    result=dict(milestone='SEC76',passed=False,checks=[],suites={},source_sha256=before,
        hardware_verified=False,coverage_complete=False,
        omitted=['Real Windows/PnP/SPBCx/GpioClx scheduling, cancellation and interrupts',
                 'MMIO mapping or electrical transfer; actual power handoff and firmware producer',
                 'Installation/signing/WIM/firmware deployment, full historical suite'],
        sanitizers=['address','undefined'])
    try:
        source=(port/'Device.c').read_text()
        old=project/'windows/sec74'
        prior=json.loads((project/'references/sec74/portable-attempt2.json').read_text())
        assert prior['passed']
        bodies={name:function(source,name) for name in FUNCTIONS}
        identity={n:hashlib.sha256(b.encode()).hexdigest() for n,b in bodies.items()}
        assert identity==prior['extracted_production_functions_sha256']
        reused=['Y771Event.c','Y771Event.h','N976nResources.c','N976nResources.h','N976nWdfResources.c','N976nWdfResources.h']
        # Only milestone comments changed in inherited preparation sources.
        for name in reused:
            assert (port/name).read_text().replace('SEC76','SEC74')==(old/name).read_text()
        for name in ('OnPrepareHardware','OnD0Entry','OnReleaseHardware'):
            assert no_comments(function(source,name))==no_comments(function((old/'Device.c').read_text(),name))
        assert 'MmMapIoSpace' not in source and 'WdfIoTargetCreate(' not in no_comments(function(source,'OnPrepareHardware'))
        result['checks']+=['17_queue_helpers_match_preserved_SEC74_receipt','inherited_resource_parser_and_adapter_exact_binding','Prepare_D0_refusal_and_metadata_release_unchanged']
        result['reused_evidence']={'receipt':'references/sec74/portable-attempt2.json','queue_functions':identity,
                                  'parser_resource_adapter_files':reused,'historical_checks_rerun':False}
        asl=(port/'acpi/N976nTouchResources.asl').read_text()
        assert no_comments(asl)==no_comments((old/'acpi/N976nTouchResources.asl').read_text().replace('SEC74','SEC76'))
        assert asl.count('Return (Zero)')==3 and 'OperationRegion' not in no_comments(asl)
        result['checks'].append('ACPI_semantics_unchanged_three_STA_zero')
        result['reused_acpi']='references/sec74/acpi-attempt1/result.json; only OEM table revision changes from74 to75 if applicable; no runtime activation'
        inf=(port/'N976nY771Touch.inf').read_text()
        assert 'ROOT\\N976N_SEC76_BUILD_ONLY' in inf
        assert '<SignMode>Off</SignMode>' in (port/'N976nY771Touch.vcxproj').read_text()
        result['checks'].append('build_only_identity_unsigned')
        with tempfile.TemporaryDirectory(prefix='sec76-',dir=scratch) as td:
            tmp=Path(td)
            suites=[('hsi',['N976nHsi2c.c']),('platform',['N976nPlatform.c']),('id_path',['N976nIdPath.c','N976nHsi2c.c','N976nPlatform.c','N976nResources.c'])]
            for name,modules in suites:
                exe=tmp/name
                cmd=['clang','-std=c11','-O1','-g','-fno-omit-frame-pointer','-fsanitize=address,undefined','-Wall','-Wextra','-Werror','-I',str(port),str(port/'tests'/(name+'_cases.c'))]+[str(port/m) for m in modules]+['-o',str(exe)]
                t=time.monotonic();b=subprocess.run(cmd,capture_output=True,text=True,timeout=60);ct=time.monotonic()-t
                if b.returncode:raise AssertionError(name+' compile: '+b.stdout+b.stderr)
                t=time.monotonic();r=subprocess.run([str(exe)],capture_output=True,text=True,timeout=30,env={**os.environ,'ASAN_OPTIONS':'detect_leaks=0:halt_on_error=1','UBSAN_OPTIONS':'halt_on_error=1'});rt=time.monotonic()-t
                if r.returncode:raise AssertionError(name+' run: '+r.stdout+r.stderr)
                lines=r.stdout.splitlines()
                assert lines and lines[-1]==f'PASS {len(lines)-1} groups',r.stdout
                result['checks']+=[name+':'+line for line in lines[:-1]]
                result['suites'][name]={'compile_seconds':ct,'run_seconds':rt,'checks':lines[:-1],'execution_output':r.stdout}
        assert bindings()==before,'Source changed during check'
        result['passed']=True
    except Exception as e:result['error']=str(e)
    result['elapsed_seconds']=time.monotonic()-tick
    result['check_count']=len(result['checks'])
    a.output.parent.mkdir(parents=True,exist_ok=True)
    a.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps({k:result.get(k) for k in ('passed','check_count','elapsed_seconds','error')}))
    return 0 if result['passed'] else 1
if __name__=='__main__':raise SystemExit(main())
