# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
"""Assemble SEC68 Android entry + audited PhoneSec + standard FV in RAM scratch."""
from __future__ import annotations
import argparse
import hashlib
import io
import tarfile
import json
import os
from pathlib import Path
import shutil
import struct
import subprocess
import tempfile
import time
import zlib
from pe import prepare_pe
from elf import extract_elf

TOOLS = Path(__file__).resolve().parent
ROOT = TOOLS.parent / "entry"

def digest(p): return hashlib.sha256(p.read_bytes()).hexdigest()

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--edk2-build',type=Path,required=True)
    ap.add_argument('--out',type=Path,required=True)
    ap.add_argument('--machine',default='ubuntu-amd64')
    args=ap.parse_args(); start=time.monotonic()
    build=args.edk2_build.resolve(); out=args.out.resolve()
    if out.exists(): raise SystemExit('New output directory required; preserve previous builds')
    scratch=os.environ.get('N976N_RAM_SCRATCH_PATH')
    if not scratch or Path(tempfile.gettempdir()).resolve()!=Path(scratch).resolve():
        raise SystemExit('Use tools/ram_scratch.py; disk temporary fallback prohibited')
    provenance=json.loads((build/'provenance.json').read_text())
    if provenance.get('milestone') != 'SEC68' or provenance.get('profile') not in ('n976n','qemu'):
        raise ValueError('Use the isolated SEC68 EDK2 build for the selected profile')
    experiment = provenance.get('ufs_experiment')
    sequence = provenance.get('query_sequence')
    if sequence != 'system-windows' or experiment != 13:
        raise ValueError('Compiled system-windows provenance missing or invalid')
    sources={str(p):digest(p) for p in [*(ROOT/n for n in ('sec68_start.S','sec68_loader.c','sec68.ld','sec68_framebuffer.inc')), *(TOOLS/n for n in ('build_entry.py','elf.py','pe.py'))]}
    for name in ('N976nPhoneSec.efi','DXE.Fv'):
        if digest(build/name)!=provenance['artifacts_sha256'][name]: raise ValueError('EDK2 artifact source binding changed')
    payload, pe=prepare_pe((build/'N976nPhoneSec.efi').read_bytes())
    fv=(build/'DXE.Fv').read_bytes()
    if len(fv)!=0x900000: raise ValueError('9MiB FV required')
    imagebase=struct.unpack_from('<I',payload,60)[0]+24+24
    cfg=[f'#define SEC_PE_SIZE {len(payload)}',f'#define SEC_PE_ENTRY {pe["entry_rva"]}',f'#define SEC_PE_FIXUP_COUNT {len(pe["fixups"])}',
         f'#define SEC_PE_IMAGEBASE_OFFSET {imagebase}',f'#define SEC_FV_SIZE {len(fv)}',
         f'#define SEC_PE_CRC {zlib.crc32(payload)}U',f'#define SEC_FV_CRC {zlib.crc32(fv)}U',
         'static int sec_pe_writable(uint64_t rva,uint64_t size) { return '+ ' || '.join(f'(rva >= {b} && rva <= {e} && size <= {e}-rva)' for b,e in pe['writable_ranges'])+'; }',
         'static int sec_pe_address(uint64_t rva) { return '+ ' || '.join(f'(rva >= {s["rva"]} && rva < {s["rva"]+s["virtual_size"]})' for s in pe['sections'])+'; }']
    clang=shutil.which('clang'); lld=shutil.which('ld.lld')
    if not clang: raise ValueError('Clang required')
    prefix=[lld] if lld else ['orb','-m',args.machine,'ld.lld']
    out.mkdir(parents=True)
    with tempfile.TemporaryDirectory(prefix='sec68-build-') as tmp:
        tmp=Path(tmp)
        (tmp/'sec.mapped').write_bytes(payload);(tmp/'DXE.Fv').write_bytes(fv)
        (tmp/'sec_payload_config.h').write_text('\n'.join(cfg)+'\n')
        (tmp/'payload.S').write_text(''.join(f'.type {n},%object\n' for n in ('sec_payload_begin','sec_payload_end','dxe_fv_begin','dxe_fv_end','sec_fixups_begin','sec_fixups_end'))+'.section .secimage,"a"\n.balign 4096\n.global sec_payload_begin,sec_payload_end\nsec_payload_begin:\n.incbin "sec.mapped"\nsec_payload_end:\n'
          +'.section .rodata.fixups,"a"\n.balign 4\n.global sec_fixups_begin,sec_fixups_end\nsec_fixups_begin:\n'+''.join(f'.long {n}\n' for n in pe['fixups'])+'sec_fixups_end:\n'
          +'.section .bootpayload,"a"\n.balign 4096\n.global dxe_fv_begin,dxe_fv_end\ndxe_fv_begin:\n.incbin "DXE.Fv"\ndxe_fv_end:\n')
        common=[clang,'--target=aarch64-none-elf','-march=armv8-a','-I',str(tmp)]
        cflags=['-std=c11','-O1','-ffreestanding','-fno-builtin','-fno-common','-fno-stack-protector','-fno-unwind-tables','-fno-asynchronous-unwind-tables','-fno-omit-frame-pointer','-fno-optimize-sibling-calls','-mgeneral-regs-only','-mstrict-align','-ffixed-x18','-fpie','-fvisibility=hidden','-Wall','-Wextra','-Werror']
        commands=[common+['-c',str(ROOT/'sec68_start.S'),'-o',str(tmp/'start.o')],common+cflags+['-c',str(ROOT/'sec68_loader.c'),'-o',str(tmp/'loader.o')],common+['-c',str(tmp/'payload.S'),'-o',str(tmp/'payload.o')]]
        for command in commands: subprocess.run(command,cwd=tmp,check=True)
        if lld:
            link=prefix+['-m','aarch64elf','--static','--no-undefined','--no-relax','--emit-relocs','--build-id=none','-T',str(ROOT/'sec68.ld'),'-Map='+str(tmp/'probe.map'),'-o',str(tmp/'probe.elf')]+[str(tmp/n) for n in ('start.o','loader.o','payload.o')]
            subprocess.run(link,check=True)
        else:
            # A newly mounted Mac RAM disk is not reliably visible through
            # Orb's /mnt/mac. Stream objects into Orb tmpfs, never disk fallback.
            orb=['orb','-m',args.machine]
            remote=subprocess.check_output(orb+['python3','-c',"import subprocess,tempfile; assert subprocess.check_output(['stat','-f','-c','%T','/dev/shm']).strip()==b'tmpfs'; print(tempfile.mkdtemp(prefix='n976n-sec68-link-',dir='/dev/shm'))"],text=True).strip()
            try:
                buf=io.BytesIO()
                with tarfile.open(fileobj=buf,mode='w') as archive:
                    for n in ('start.o','loader.o','payload.o'): archive.add(tmp/n,arcname=n)
                    archive.add(ROOT/'sec68.ld',arcname='sec68.ld')
                subprocess.run(orb+['tar','-xf','-','-C',remote],input=buf.getvalue(),check=True)
                link=prefix+['-m','aarch64elf','--static','--no-undefined','--no-relax','--emit-relocs','--build-id=none','-T',remote+'/sec68.ld','-Map='+remote+'/probe.map','-o',remote+'/probe.elf']+[remote+'/'+n for n in ('start.o','loader.o','payload.o')]
                subprocess.run(link,check=True)
                for n in ('probe.elf','probe.map'): (tmp/n).write_bytes(subprocess.check_output(orb+['cat',remote+'/'+n]))
            finally:
                subprocess.run(orb+['python3','-c','import shutil,sys; shutil.rmtree(sys.argv[1])',remote],check=True)
        for name in ('probe.elf','probe.map'): shutil.copyfile(tmp/name,out/name)
        image,symbols,audit=extract_elf((tmp/'probe.elf').read_bytes())
        if image[symbols['sec_payload_begin']:symbols['sec_payload_end']]!=payload or image[symbols['dxe_fv_begin']:symbols['dxe_fv_end']]!=fv: raise ValueError('Raw payload binding')
        (out/'Image').write_bytes(image)
        for name in ('probe.elf','probe.map','sec_payload_config.h'): shutil.copyfile(tmp/name,out/name)
    if sources!={name:digest(Path(name)) for name in sources}: raise ValueError('Wrapper changed during build')
    manifest=dict(milestone='SEC68',profile=provenance['profile'],query_sequence=sequence,ufs_experiment=experiment,development_candidate=True,final_qualified=False,hardware_verified=False,public_extraction_rebuild=True,
        image_path=str(out/'Image'),sha256=digest(out/'Image'),size=len(image),symbols=symbols,pe=pe,
        sec_pe_path=str(build/'N976nPhoneSec.efi'),edk2_build=str(build),edk2_provenance_sha256=digest(build/'provenance.json'),
        sources_sha256=sources,elf_audit=audit,crc32=dict(sec=zlib.crc32(payload),fv=zlib.crc32(fv)),
        coverage='Build/static ELF/PE admission only; separate targeted execution evidence required.',build_seconds=time.monotonic()-start)
    (out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n')
    print(json.dumps({'manifest':str(out/'manifest.json'),'bytes':len(image),'seconds':manifest['build_seconds']}))
if __name__=='__main__': main()
