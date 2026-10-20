# SPDX-License-Identifier: MIT
"""Unchanged pure FV/PE/DEPEX readers used by the SEC68 static checker."""
import hashlib
import struct
import uuid
PAGE = 4096
FFS2 = uuid.UUID('8c8ce578-8a3d-4f1c-9935-896185c32dd3').bytes_le
EXECUTE, WRITE = 0x20000000, 0x80000000

def align(value, amount):
    return (value+amount-1)&-amount

def u24(data, offset):
    return int.from_bytes(data[offset:offset+3], 'little')

def inspect_pe32(data):
    """Parse architecture, section spans and entry independently of the builder."""
    assert len(data) >= 64 and data[:2] == b'MZ'
    nt = struct.unpack_from('<I', data, 60)[0]
    assert nt+24 <= len(data) and data[nt:nt+4] == b'PE\0\0'
    machine, count = struct.unpack_from('<HH', data, nt+4)
    optional_size = struct.unpack_from('<H', data, nt+20)[0]
    optional = nt+24
    assert machine == 0xAA64 and 0 < count <= 32
    assert optional+optional_size+40*count <= len(data)
    assert struct.unpack_from('<H', data, optional)[0] == 0x20B
    entry = struct.unpack_from('<I', data, optional+16)[0]
    preferred = struct.unpack_from('<Q', data, optional+24)[0]
    image_size = struct.unpack_from('<I', data, optional+56)[0]
    sections = []
    for index in range(count):
        offset = optional+optional_size+40*index
        name, virtual, rva, raw_size, raw_offset = struct.unpack_from('<8sIIII', data, offset)
        flags = struct.unpack_from('<I', data, offset+36)[0]
        assert rva+max(virtual, raw_size) <= image_size
        assert raw_offset+raw_size <= len(data)
        sections.append({'name': name.rstrip(b'\0').decode('ascii'), 'rva': rva,
                         'virtual_size': virtual, 'raw_size': raw_size,
                         'raw_offset': raw_offset, 'flags': flags})
    assert any(s['flags'] & 0x20000000 and s['rva'] <= entry < s['rva']+s['virtual_size']
               for s in sections), 'DXE entry must lie in executable code'
    return {'size': image_size, 'entry': entry, 'preferred': preferred, 'subsystem': struct.unpack_from('<H',data,optional+68)[0], 'sections': sections,
            'sha256': hashlib.sha256(data).hexdigest()}

def inspect_dir64(data, pe):
    """Decode relocation blocks from raw PE sections without builder helpers."""
    nt = struct.unpack_from('<I', data, 60)[0]
    rva, size = struct.unpack_from('<II', data, nt+24+112+5*8)
    assert pe['preferred'] == 0 and size >= 8 and rva
    def raw(address, length):
        candidates = [section for section in pe['sections']
                      if section['rva'] <= address and address+length <= section['rva']+section['raw_size']]
        assert len(candidates) == 1
        section = candidates[0]
        offset = section['raw_offset']+address-section['rva']
        return data[offset:offset+length]
    table = raw(rva, size)
    cursor, targets = 0, []
    while cursor < len(table):
        assert cursor+8 <= len(table)
        page, extent = struct.unpack_from('<II', table, cursor)
        assert page%4096 == 0 and extent >= 8 and extent%2 == 0 and cursor+extent <= len(table)
        for position in range(cursor+8, cursor+extent, 2):
            entry = struct.unpack_from('<H', table, position)[0]
            kind, target = entry>>12, page+(entry&4095)
            if kind == 0:
                continue
            assert kind == 10 and target%8 == 0 and target not in targets
            owners = [section for section in pe['sections']
                      if section['rva'] <= target and target+8 <= section['rva']+section['virtual_size']]
            assert len(owners) == 1 and owners[0]['flags']&0x80000000 and not owners[0]['flags']&0x20000000
            value = struct.unpack('<Q', raw(target, 8))[0]
            assert 0 <= value < pe['size']
            targets.append(target)
        cursor += extent
    assert cursor == len(table) and targets
    return {'directory_rva':rva, 'directory_size':size, 'dir64_targets':targets,
            'all_fixups_unique_aligned_writable_nonexecuting_in_image':True}

def inspect_fv(blob):
    """Walk PI FV, FFS and section headers with checksums independently."""
    assert len(blob) >= 64 and blob[40:44] == b'_FVH'
    length = struct.unpack_from('<Q', blob, 32)[0]
    attributes = struct.unpack_from('<I', blob, 44)[0]
    header_length = struct.unpack_from('<H', blob, 48)[0]
    assert length == len(blob) and 56 <= header_length <= length
    assert header_length % 2 == 0 and blob[55] == 2
    assert sum(struct.unpack_from('<'+'H'*(header_length//2), blob)) & 0xFFFF == 0
    total, pos = 0, 56
    while True:
        count, size = struct.unpack_from('<II', blob, pos)
        pos += 8
        assert pos <= header_length
        if (count, size) == (0, 0):
            break
        assert count and size
        total += count*size
    assert total == length, 'FV block map does not cover FV'
    erase = 0xFF if attributes & 0x800 else 0
    cursor, files = align(header_length, 8), []
    while cursor+24 <= length:
        if blob[cursor:cursor+24] == bytes([erase])*24:
            assert blob[cursor:] == bytes([erase])*(length-cursor)
            break
        header = blob[cursor:cursor+24]
        kind, attrs, size, state = header[18], header[19], u24(header, 20), header[23]
        assert size != 0xFFFFFF and 24 <= size <= length-cursor
        assert (sum(header)-header[17]-state) & 255 == 0, 'Invalid FFS header checksum'
        body = blob[cursor+24:cursor+size]
        if attrs & 0x40:
            assert (sum(body)+header[17]) & 255 == 0
        else:
            assert header[17] == 0xAA
        logical_state = state ^ erase
        assert logical_state & 4 and not logical_state & (8|16|32)
        sections, offset = [], cursor+24
        if kind != 0xF0:  # Padding files carry arbitrary filler, not sections.
            while offset+4 <= cursor+size:
                extent, section_type = u24(blob, offset), blob[offset+3]
                assert extent != 0xFFFFFF and 4 <= extent <= cursor+size-offset
                payload = blob[offset+4:offset+extent]
                sections.append({'offset': offset, 'size': extent, 'type': section_type,
                                 'pe': inspect_pe32(payload) if section_type == 0x10 else None})
                offset = align(offset+extent, 4)
            assert cursor+size <= offset <= align(cursor+size, 4)
        files.append({'offset': cursor, 'size': size, 'type': kind,
                      'guid_bytes': header[:16].hex(), 'sections': sections})
        cursor = align(cursor+size, 8)
    cores = [file for file in files if file['type'] == 5]
    assert len(cores) == 1, 'Expected exactly one FFS DXE_CORE file'
    images = [section for section in cores[0]['sections'] if section['type'] == 0x10]
    assert len(images) == 1, 'Expected uncompressed DXE_CORE PE32 section'
    return {'fv_size': length, 'header_size': header_length, 'files': files,
            'core_file': cores[0], 'core_pe': images[0]['pe']}

def inspect_depex(data):
    """Validate PI postfix syntax; no protocol availability/scheduling claims."""
    assert data, 'empty DEPEX'
    if data[0] in (0, 1):
        # Pinned BaseTools GenDepex emits BEFORE/AFTER GUID END.
        assert len(data) == 18 and data[-1] == 8, 'DEPEX ordering expression'
        return {'form': 'before' if data[0] == 0 else 'after',
                'guids': [str(uuid.UUID(bytes_le=bytes(data[1:17])))]}
    cursor, depth, peak, guids = 0, 0, 0, []
    while cursor < len(data):
        position, opcode = cursor, data[cursor]
        cursor += 1
        if opcode == 2:
            assert cursor + 16 <= len(data), 'DEPEX GUID truncated'
            guids.append(str(uuid.UUID(bytes_le=bytes(data[cursor:cursor + 16]))))
            cursor += 16
            depth += 1
        elif opcode in (6, 7):
            depth += 1
        elif opcode in (3, 4):
            assert depth >= 2, 'DEPEX stack underflow'
            depth -= 1
        elif opcode == 5:
            assert depth >= 1, 'DEPEX stack underflow'
        elif opcode == 9:
            assert position == 0, 'DEPEX SOR position'
        elif opcode == 8:
            assert depth == 1 and cursor == len(data), 'DEPEX END/stack'
            return {'form': 'postfix', 'guids': guids, 'maximum_stack': peak}
        else:
            raise AssertionError('DEPEX invalid opcode/ordering position')
        peak = max(peak, depth)
    raise AssertionError('DEPEX missing END')

def repair_ffs(blob, file):
    offset, size = file['offset'], file['size']
    blob[offset + 17] = (-sum(blob[offset + 24:offset + size])) & 255 if blob[offset + 19] & 0x40 else 0xAA
    blob[offset + 16] = 0
    blob[offset + 16] = (-sum(blob[offset:offset + 24]) + blob[offset + 17] + blob[offset + 23]) & 255

READERS = {name: globals()[name] for name in ('align','u24','inspect_pe32','inspect_dir64','inspect_fv')}
