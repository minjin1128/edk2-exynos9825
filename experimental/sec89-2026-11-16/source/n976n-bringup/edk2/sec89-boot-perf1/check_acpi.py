#!/usr/bin/env python3
"""SEC78: compile a disabled resource SSDT in an existing managed RAM lease.
Run on the local Mac's Orb Ubuntu via tools/ram_scratch.py; no package install.
"""
import argparse, hashlib, json, os, shutil, subprocess, tempfile, time
from pathlib import Path

parser=argparse.ArgumentParser()
parser.add_argument('--output', type=Path, required=True)
parser.add_argument('--diagnostic-mode',choices=('a',),required=True)
parser.add_argument('--generate-header',action='store_true',help='Emit a compiled header in the output directory only; do not verify or modify the firmware header')
args=parser.parse_args()
out=args.output.resolve();out.mkdir(parents=True,exist_ok=False)
start=time.monotonic(); steps=[]; report={'milestone':'SEC89 CONTROL1','diagnostic_mode':1,'passed':False,'installed':False,'firmware_changed':False,'execution_scope':'ACPICA interpreter on local Orb VM, no hardware access'}
lib=Path(__file__).resolve().parent/'N976nPlatformPkg/Library/PlatformBootManagerLib'
src=lib/('AcpiBspDsdt.asl' if args.diagnostic_mode=='a' else 'AcpiBspDsdtSec77.asl')
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
    shutil.copyfile(src,scratch/'AcpiBspDsdt.asl')
    run('compile',[iasl,'-we','AcpiBspDsdt.asl'])
    aml=(scratch/'AcpiBspDsdt.aml').read_bytes()
    assert aml[:4]==b'DSDT' and int.from_bytes(aml[4:8],'little')==len(aml) and sum(aml)%256==0
    run('disassemble',[iasl,'-d','AcpiBspDsdt.aml'])
    run('roundtrip',[iasl,'-we','-p','roundtrip','AcpiBspDsdt.dsl'])
    assert (scratch/'roundtrip.aml').read_bytes()==aml
    assert aml.count(bytes.fromhex('00f0ad8b'))==1
    assert aml.count(bytes.fromhex('085f5354410ada'))==1
    expected_resources=[(1,0x104B0000,0x1000),(0,0x10400000,0x8000),
      (0,0x10421000,0x1000),(0,0x10430000,0x1000),
      (0,0x1A240000,0x3000),(1,0x8BADF000,0x1000),(0,0x15850000,0x1000)]
    descriptors=b''.join(b'\x86\x09\x00'+bytes([rw])+base.to_bytes(4,'little')+
      size.to_bytes(4,'little') for rw,base,size in expected_resources)+b'\x79\x00'
    assert aml.count(descriptors)==1, 'exact seven resources, order and access flags'
    if args.diagnostic_mode=='a':
        ufs_resources=[(1,0x13D60000,0x2000),(0,0x13C10000,0x1000),(1,0x8BADB000,0x2000),(1,0x8BADC000,0x16000)]
        irq_descriptor=bytes.fromhex('890600010119010000')
        ufs_descriptors=b''.join(b'\x86\x09\x00'+bytes([rw])+base.to_bytes(4,'little')+size.to_bytes(4,'little') for rw,base,size in ufs_resources)+irq_descriptor+b'\x79\x00'
        assert aml.count(ufs_descriptors)==1
        assert aml.count(irq_descriptor)==1 and b'_CCA' not in aml
        assert aml.count(bytes.fromhex('00b0ad8b'))==1 and aml.count(bytes.fromhex('00c0ad8b'))==1
        assert aml.count(bytes.fromhex('085f5354410adb'))==1
        usta=aml.index(bytes.fromhex('085f5354410adb'))+6
        ulease=aml.index(bytes.fromhex('00b0ad8b'));udma=aml.index(bytes.fromhex('00c0ad8b'))
        report['ufs_resource_contract']={'count':5,'memory_count':4,'hid':'NNUF0078','lease_index':2,'dma_index':3,'dma_uc':True,'writes':False,'interrupt_count':1,'gsiv':281,'spi':249,'trigger':'level','polarity':'active-high','sharing':'exclusive','cca_unchanged_absent':True}
    else:
        assert b'UFS0' not in aml and b'NNUF0078' not in aml
        report['ufs_resource_contract']={'count':0,'device_absent':True,'same_aml_for_modes':[2,3]}
    battery_resources=[(1,0x15D60000,0x1000),(1,0x15C22030,4),(1,0x15C0304C,4),
      (1,0x15C30180,16),(1,0x15C301A0,16),(0,0x15C00100,4),(0,0x15C01020,4),
      (0,0x15C01824,4),(0,0x15800100,0x44),(0,0x15801004,4),(0,0x15801804,4),
      (0,0x1580200C,4),(0,0x15C02010,4),(0,0x15C0206C,4),(0,0x15C0205C,4),
      (0,0x15C02088,4),(0,0x15C0208C,4),(0,0x1A240000,0x3000),(1,0x15C40000,0x100),
      *[(0,a,4) for a in (0x15C01000,0x15C01800,0x15C01804,0x15C02004,0x15C02008,0x15C03000,0x15C03008,0x15C0300C)],(1,0x8BADE000,0x1000)]
    battery_descriptors=b''.join(b'\x86\x09\x00'+bytes([rw])+base.to_bytes(4,'little')+
      size.to_bytes(4,'little') for rw,base,size in battery_resources)+bytes.fromhex('890600010174000000')+b'\x79\x00'
    assert aml.count(battery_descriptors)==1 and aml.count(b'NNBT0089')==1
    assert aml.count(bytes.fromhex('00e0ad8b'))==1
    assert aml.count(bytes.fromhex('085f5354410adf'))==1
    bsta=aml.index(bytes.fromhex('085f5354410adf'))+6
    blease=aml.index(bytes.fromhex('00e0ad8b'))
    report['battery_resource_contract']={'count':29,'memory_count':28,'top_index':17,'adc_index':18,'nvs_index':27,
      'interrupt_count':1,'gsiv':116,'gic114_must_remain_masked':True,
      'top_shared_by_paired_windows_requirement_filters':True,'live_read_only':True,
      'resources':battery_resources}
    report['resource_contract']={'count':7,'nvs_index':5,'alive_index':6,
      'alive_base':0x15850000,'alive_bytes':0x1000,'alive_read_only':True,
      'existing_indices_preserved':True,'interrupt_descriptor_added':False}
    staoff=aml.index(bytes.fromhex('085f5354410ada'))+6
    addr=aml.index(bytes.fromhex('00f0ad8b'))
    cpu_offsets=[aml.index(bytes.fromhex('085f5354410a')+bytes([0xDC+i]))+6 for i in range(3)]
    assert all(aml.count(bytes.fromhex('085f5354410a')+bytes([0xDC+i]))==1 for i in range(3))
    variants={}
    for mode,sta,address in [('absent',0,0),('released',15,0x95000000)]:
        variant=bytearray(aml);variant[staoff]=sta
        for offset in cpu_offsets: variant[offset]=sta
        variant[addr:addr+4]=address.to_bytes(4,'little')
        variant[bsta]=sta
        variant[blease:blease+4]=(address+0x40000 if address else 0).to_bytes(4,'little')
        if args.diagnostic_mode=='a':
            variant[usta]=sta
            variant[ulease:ulease+4]=(address+0x10000 if address else 0).to_bytes(4,'little')
            variant[udma:udma+4]=(address+0x20000 if address else 0).to_bytes(4,'little')
        variant[9]=0;variant[9]=(-sum(variant))&255
        name='AcpiBspDsdt-'+mode+'.aml';(scratch/name).write_bytes(variant)
        commands=r'evaluate \_SB.TSP0._STA;evaluate \_SB.TSP0._CRS'
        if args.diagnostic_mode=='a':commands+=r';evaluate \_SB.UFS0._STA;evaluate \_SB.UFS0._CRS'
        commands+=r';evaluate \_SB.BAT0._STA;evaluate \_SB.BAT0._CRS'
        commands+=';'+ ';'.join(r'evaluate \_SB.CPU%d._STA'%i for i in range(4))
        log=run('sta-'+mode,[ae,'-b',commands,name])
        assert '[Integer] = '+f'{sta:016X}' in log,log
        variants[mode]={'sta':sta,'page':address,'sha256':hashlib.sha256(variant).hexdigest()}
    report['patch_offsets']={'sta':staoff,'address':addr,'battery_sta':bsta,'battery_lease':blease}
    if args.diagnostic_mode=='a':report['patch_offsets'].update(ufs_sta=usta,ufs_lease=ulease,ufs_dma=udma)
    report['variants']=variants
    # Bounds and exact descriptors are independently checked in the portable
    # SEC76 contract suite. This check proves ASL syntax, AML checksum/roundtrip
    # and absent-device methods, not Windows enumeration or GPIO ownership.
    for name in ['AcpiBspDsdt.asl','AcpiBspDsdt.aml','AcpiBspDsdt.dsl']:
        shutil.copyfile(scratch/name,out/name)
    header=['/* SPDX-License-Identifier: MIT; generated by SEC76 check_acpi.py */','#ifndef N976N_ACPI_BSP_DSDT_H_','#define N976N_ACPI_BSP_DSDT_H_',f'#define N976N_TOUCH_DSDT_STA_OFFSET {staoff}U',f'#define N976N_TOUCH_DSDT_ADDRESS_OFFSET {addr}U',*([f'#define N976N_UFS_DSDT_STA_OFFSET {usta}U',f'#define N976N_UFS_DSDT_LEASE_OFFSET {ulease}U',f'#define N976N_UFS_DSDT_DMA_OFFSET {udma}U'] if args.diagnostic_mode=='a' else []),'STATIC CONST UINT8 mAcpiBspDsdt[] = {']
    header[3:3]=[f'#define N976N_BAT_DSDT_STA_OFFSET {bsta}U',f'#define N976N_BAT_DSDT_LEASE_OFFSET {blease}U']
    header[3:3]=[f'#define N976N_CPU{i+1}_DSDT_STA_OFFSET {offset}U' for i,offset in enumerate(cpu_offsets)]
    header += ['  '+','.join('0x%02X'%v for v in aml[i:i+12])+',' for i in range(0,len(aml),12)]
    header += ['};','#endif','']
    (out/'AcpiBspDsdt.h').write_text('\n'.join(header))
    report['header_generation_only']=args.generate_header
    report['header_matches_firmware']='\n'.join(header)==(lib/('AcpiBspDsdt.h' if args.diagnostic_mode=='a' else 'AcpiBspDsdtSec77.h')).read_text()
    if not args.generate_header:
        assert report['header_matches_firmware'], 'Compiled header must match selected firmware bytes'
    report.update(passed=True,asl_sha256=hashlib.sha256(src.read_bytes()).hexdigest(),aml_bytes=len(aml),aml_sha256=hashlib.sha256(aml).hexdigest(),sta_results={'absent':0,'released':15},roundtrip_identical=True)
except Exception as e:
    report['error']=str(e)
finally:
    shutil.rmtree(scratch)
    report['steps']=steps;report['elapsed_seconds']=time.monotonic()-start
    (out/'result.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({k:report.get(k) for k in ['passed','error','elapsed_seconds','aml_bytes']}))
raise SystemExit(0 if report['passed'] else 1)
