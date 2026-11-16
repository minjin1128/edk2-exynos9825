#!/usr/bin/env python3
"""SEC76: compile a disabled resource SSDT in an existing managed RAM lease.
Run on the local Mac's Orb Ubuntu via tools/ram_scratch.py; no package install.
"""
import argparse, hashlib, json, os, shutil, subprocess, tempfile, time
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
args=parser.parse_args()
out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
start=time.monotonic(); steps=[]; report={'milestone':'SEC76','passed':False,'installed':False,'firmware_changed':False,'execution_scope':'ACPICA interpreter on local Orb VM, no hardware access'}
src=Path(__file__).resolve().parent/'N976nTouchResources.asl'
scratch=Path(tempfile.mkdtemp(prefix='sec76-acpi-'))
def run(name, argv, timeout=120):
    t=time.monotonic();r=subprocess.run(argv,cwd=scratch,capture_output=True,text=True,timeout=timeout)
    (out/(name+'.log')).write_text(r.stdout+r.stderr)
    steps.append({'name':name,'command':argv,'exit_code':r.returncode,'seconds':time.monotonic()-t})
    if r.returncode: raise RuntimeError(name+' failed')
    return r.stdout+r.stderr
try:
    # Reuse the same unmodified Ubuntu package version as SEC67. Bulk files stay
    # on the launcher's verified RAM storage, never apt install or a disk cache.
    run('download',['apt-get','download','acpica-tools=20200925-6'])
    deb=scratch/'acpica-tools_20200925-6_amd64.deb'
    report['package']={'name':deb.name,'sha256':hashlib.sha256(deb.read_bytes()).hexdigest()}
    assert report['package']['sha256']=='3a7ad820f8c35d392176f91a1e293e346f45df5cb516f2e551f87915bc3c7d08'
    run('extract',['dpkg-deb','-x',str(deb),str(scratch/'tools')])
    iasl=str(scratch/'tools/usr/bin/iasl'); ae=str(scratch/'tools/usr/bin/acpiexec')
    report['compiler']=run('version',[iasl,'-v']).strip()
    shutil.copyfile(src,scratch/'N976nTouchResources.asl')
    run('compile',[iasl,'-we','N976nTouchResources.asl'])
    aml=(scratch/'N976nTouchResources.aml').read_bytes()
    assert aml[:4]==b'SSDT' and int.from_bytes(aml[4:8],'little')==len(aml) and sum(aml)%256==0
    run('disassemble',[iasl,'-d','N976nTouchResources.aml'])
    run('roundtrip',[iasl,'-we','-p','roundtrip','N976nTouchResources.dsl'])
    assert (scratch/'roundtrip.aml').read_bytes()==aml
    commands=';'.join('evaluate '+r'\_SB.'+node+'._STA' for node in ['I2C0','GPA0','TSP0'])
    log=run('sta-evaluation',[ae,'-b',commands,'N976nTouchResources.aml'])
    assert log.count('[Integer] = 0000000000000000')==3,log
    # Bounds and exact descriptors are independently checked in the portable
    # SEC76 contract suite. This check proves ASL syntax, AML checksum/roundtrip
    # and absent-device methods, not Windows enumeration or GPIO ownership.
    for name in ['N976nTouchResources.asl','N976nTouchResources.aml','N976nTouchResources.dsl']:
        shutil.copyfile(scratch/name,out/name)
    report.update(passed=True,asl_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),aml_bytes=len(aml),aml_sha256=hashlib.sha256(aml).hexdigest(),sta_results={'I2C0':0,'GPA0':0,'TSP0':0},roundtrip_identical=True)
except Exception as e:
    report['error']=str(e)
finally:
    shutil.rmtree(scratch)
    report['steps']=steps;report['elapsed_seconds']=time.monotonic()-start
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report.get(k) for k in ['passed','error','elapsed_seconds','aml_bytes']}))
raise SystemExit(0 if report['passed'] else 1)
