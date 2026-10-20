"""Authenticated metadata-only SEC66 file-extent observation contract.

Reads the preserved regular FAT image without modifying/copying it. Every
metadata chunk is checked against the existing ordered SHA256 seal. No full
SDI/WIM rehash is performed. Offsets are diagnostic only, never I/O admission.
"""
import hashlib
import json
import re
import struct
from pathlib import Path


def generate(image: Path, seal_dir: Path):
    image, seal_dir = Path(image), Path(seal_dir)
    if not image.is_file() or image.is_symlink() or image.stat().st_size != 0x40000000:
        raise ValueError('Expected preserved regular 1GiB FAT image')
    manifest = json.loads((seal_dir / 'seal-manifest.json').read_text())
    inc = (seal_dir / 'SystemVolumeSealData.inc').read_text()
    table = bytes(int(x, 16) for x in re.findall(r'0x([0-9a-fA-F]{2})\b', inc))
    if len(table) != 0x40000:
        raise ValueError('Ordered seal length')
    header = (seal_dir / 'SystemVolumeSeal.h').read_text()
    table_match = re.search(r'mN976nSystemSealTableSha256\[32\]\s*=\s*\{([^}]+)', header)
    expected = bytes(int(x,16) for x in re.findall(r'0x([0-9a-fA-F]{2})',table_match[1]))
    if hashlib.sha256(table).digest() != expected:
        raise ValueError('Ordered seal binding')
    chunks = {}
    with image.open('rb') as source:
        def read(offset, length):
            if length <= 0 or offset < 0 or offset + length > 0x40000000:
                raise ValueError('Metadata read range')
            result = bytearray()
            while length:
                index, inside = divmod(offset, 0x20000)
                if index not in chunks:
                    source.seek(index * 0x20000)
                    data = source.read(0x20000)
                    if len(data) != 0x20000 or hashlib.sha256(data).digest() != table[index*32:(index+1)*32]:
                        raise ValueError(f'Sealed metadata chunk {index} mismatch')
                    chunks[index] = data
                take = min(length, 0x20000-inside)
                result.extend(chunks[index][inside:inside+take])
                offset += take; length -= take
            return bytes(result)
        boot=read(0,512)
        u16=lambda n: struct.unpack_from('<H',boot,n)[0]
        u32=lambda n: struct.unpack_from('<I',boot,n)[0]
        if boot[510:512]!=b'\x55\xaa' or (u16(11),boot[13],u16(14),boot[16],u32(32),u32(36),u32(44))!=(512,8,32,2,2097152,2048,2):
            raise ValueError('Pinned FAT32 geometry')
        fat=read(0x4000,0x100000)
        if fat!=read(0x104000,0x100000):
            raise ValueError('FAT mirror mismatch')
        def chain(first):
            current=first; seen=set(); result=[]
            while current<0x0ffffff8:
                if current<2 or current>=261630 or current in seen:
                    raise ValueError('Cluster bounds/cycle')
                seen.add(current);result.append(current)
                current=struct.unpack_from('<I',fat,current*4)[0]&0x0fffffff
            return result
        def lookup(directory, short):
            found=[]
            for cluster in chain(directory):
                data=read(0x204000+(cluster-2)*4096,4096)
                for at in range(0,4096,32):
                    e=data[at:at+32]
                    if e[0] in (0,0xe5) or e[11]==0xf:continue
                    if e[:11]==short:
                        found.append((e[11],struct.unpack_from('<H',e,20)[0]<<16|struct.unpack_from('<H',e,26)[0],struct.unpack_from('<I',e,28)[0]))
            if len(found)!=1:raise ValueError('Unique short-name path')
            return found[0]
        outputs={}
        for kind,directory,short,path in [('SDI',b'BOOT       ',b'BOOT    SDI','boot/boot.sdi'),('WIM',b'SOURCES    ',b'BOOT    WIM','sources/boot.wim')]:
            attr,directory_cluster,_=lookup(2,directory)
            if not attr&0x10:raise ValueError('Expected directory')
            attr,first,size=lookup(directory_cluster,short)
            if attr&0x10 or size!=manifest['files'][path]['bytes']:raise ValueError('Expected regular payload length')
            clusters=chain(first)
            if len(clusters)!=(size+4095)//4096 or clusters!=list(range(first,first+len(clusters))):
                raise ValueError('Observation mapping requires preserved contiguous sealed file')
            outputs[kind]={'path':path,'offset':0x204000+(first-2)*4096,'bytes':size,'first_cluster':first,'clusters':len(clusters)}
    text='/* Generated from authenticated preserved FAT metadata; diagnostic offsets only. */\n#ifndef N976N_SYSTEM_RUNTIME_FILES_H_\n#define N976N_SYSTEM_RUNTIME_FILES_H_\n'
    for kind,item in outputs.items():text+=f'#define N976N_SYSTEM_{kind}_OFFSET 0x{item["offset"]:x}ULL\n'
    text+='#endif\n'
    receipt={'schema':1,'purpose':'runtime overlap observations only; not permission, media admission, or whole-file coverage','seal_table_sha256':expected.hex(),'metadata_chunk_indices':sorted(chunks),'authenticated_metadata_bytes':len(chunks)*0x20000,'files':outputs,'full_payload_rehashed':False}
    return text.encode('ascii'),receipt
