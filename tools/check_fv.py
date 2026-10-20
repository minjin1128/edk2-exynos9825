# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
"""SEC49 inventory-bound FV/PE/resource admission and targeted host corruptions.

Reuses frozen FV readers and extends independent image checks for exact Windows
PE data, certificate framing and executable DIR64 while preserving W^X bounds.
No historical test or firmware artifact is modified by this checker.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import struct
import time
import uuid
import fv_readers as baseline

READERS = baseline.READERS
PAGE, FFS2, EXECUTE, WRITE = baseline.PAGE, baseline.FFS2, baseline.EXECUTE, baseline.WRITE
align = baseline.align
inspect_depex = baseline.inspect_depex
repair_ffs = baseline.repair_ffs
RESOURCE_GUID = 'f904cc73-d2c6-4798-83ac-7cba37c24401'
APPLICATION_GUID = 'e656f212-16f9-42d7-a70b-7911482c4401'
WINDOWS_GUID = '6e5c45af-ef14-4637-a71b-e2815d9b4502'
MEDIA_GUID = '6e5c45af-ef14-4637-a71b-e2815d9b4503'

def raw_offset(pe, rva, size):
    """Only initialized bytes exist at an RVA; raw file padding is not an image."""
    assert size > 0, 'empty directory'
    owners = [section for section in pe['sections']
              if section['rva'] <= rva and
              rva + size <= section['rva'] + min(section['virtual_size'], section['raw_size'])]
    assert len(owners) == 1, 'directory is not uniquely initialized/file backed'
    return owners[0]['raw_offset'] + rva - owners[0]['rva']


def inspect_dir64(data, pe, allow_code=False):
    """Independent bounded DIR64 decode; Windows code pointers relocate before RX publication."""
    nt = struct.unpack_from('<I', data, 60)[0]
    rva, size = struct.unpack_from('<II', data, nt + 24 + 152)
    assert size >= 8 and rva, 'relocation directory required'
    start = raw_offset(pe, rva, size)
    directories = [struct.unpack_from('<II', data, nt + 24 + 112 + index * 8)
                   for index in range(16) if index != 4]
    cursor, targets, readonly, executable = start, [], [], []
    while cursor < start + size:
        assert cursor + 8 <= start + size, 'truncated relocation block'
        page, extent = struct.unpack_from('<II', data, cursor)
        assert page % PAGE == 0 and extent >= 8 and extent % 4 == 0 and cursor + extent <= start + size, 'relocation block geometry'
        for offset in range(cursor + 8, cursor + extent, 2):
            entry = struct.unpack_from('<H', data, offset)[0]
            kind, target = entry >> 12, page + (entry & 4095)
            if kind == 0:
                continue
            assert kind == 10 and target % 8 == 0, 'only aligned DIR64 permitted'
            assert not targets or target >= targets[-1] + 8, 'duplicate/overlapping/unordered relocation'
            assert target + 8 <= rva or rva + size <= target, 'relocation targets relocation directory'
            assert all(not length or target + 8 <= address or address + length <= target
                       for address, length in directories), 'relocation overlaps image directory'
            owners = [section for section in pe['sections']
                      if section['rva'] <= target and target + 8 <= section['rva'] + min(section['virtual_size'], section['raw_size'])]
            assert len(owners) == 1 and (allow_code or not owners[0]['flags'] & EXECUTE), 'relocation target must be backed nonexecuting data'
            value = struct.unpack_from('<Q', data, raw_offset(pe, target, 8))[0]
            assert pe['preferred'] <= value < pe['preferred'] + pe['size'], 'preferred relocation value outside image'
            targets.append(target)
            if not owners[0]['flags'] & WRITE:
                readonly.append(target)
            if owners[0]['flags'] & EXECUTE:
                executable.append(target)
        cursor += extent
    assert cursor == start + size and targets, 'relocation directory incomplete/empty'
    return {'directory_rva': rva, 'directory_size': size, 'dir64_targets': targets,
            'readonly_data_target_count': len(readonly) - len(executable),
            'immutable_target_count': len(readonly),
            'executable_target_count': len(executable),
            'all_fixups_ordered_unique_aligned_backed_in_image': True,
            'executable_section_fixups_permitted': allow_code,
            'nonwindows_no_code_fixups_is_stricter_pinned_module_profile': not allow_code}


def inspect_image(data, module, maximum):
    assert 256 <= len(data) <= 0x400000, 'PE source byte budget'
    pe = READERS['inspect_pe32'](data)
    nt = struct.unpack_from('<I', data, 60)[0]
    opt = nt + 24
    count, optional_size, characteristics = (struct.unpack_from('<H', data, nt + n)[0]
                                             for n in (6, 20, 22))
    assert nt >= 64 and 0 < count <= 24 and optional_size == 240 and not characteristics & 1 and characteristics & 2, 'PE header/relocations stripped'
    assert pe['subsystem'] == module['subsystem'], 'PE subsystem differs from inventory'
    windows = module.get('binary', False)
    assert pe['preferred'] == (0x10000000 if windows else 0), 'preferred image base'
    section_align, file_align = struct.unpack_from('<II', data, opt + 32)
    assert section_align == PAGE and file_align in (512, 1024, 2048, 4096), 'PE alignment'
    assert windows or file_align == PAGE, 'upstream module file alignment'
    assert struct.unpack_from('<I', data, opt + 108)[0] == 16, 'PE directory count'
    header_size = struct.unpack_from('<I', data, opt + 60)[0]
    assert PAGE <= pe['size'] <= maximum and pe['size'] % PAGE == 0, 'PE image budget'
    assert opt + optional_size + 40 * count <= header_size <= min(len(data), pe['size'])
    assert header_size % file_align == 0, 'PE header alignment'
    virtual, raw, entry_owners = [], [], []
    previous_end = align(header_size, PAGE)
    for section in pe['sections']:
        rva, extent = section['rva'], max(section['virtual_size'], section['raw_size'])
        start, length = section['raw_offset'], section['raw_size']
        flags = section['flags']
        assert section['virtual_size'] > 0 and rva >= previous_end and rva % PAGE == 0, 'section RVA/extent/order'
        assert flags & 0x40000000, 'section must be readable'
        assert not (flags & EXECUTE and flags & WRITE), 'writable executable section'
        end = align(rva + extent, PAGE)
        assert end <= pe['size'], 'rounded section exceeds image'
        assert all(end <= a or b <= rva for a, b in virtual), 'overlapping virtual sections'
        virtual.append((rva, end))
        previous_end = end
        if length:
            assert start >= header_size and (start | length) % file_align == 0, 'raw section alignment'
            assert all(start + length <= a or b <= start for a, b in raw), 'overlapping raw sections'
            raw.append((start, start + length))
        if rva <= pe['entry'] < rva + section['virtual_size']:
            entry_owners.append(section)
    assert len(entry_owners) == 1 and entry_owners[0]['flags'] & EXECUTE, 'entry ownership'
    assert pe['entry'] + 4 <= entry_owners[0]['rva'] + entry_owners[0]['raw_size'], 'entry not file backed'
    assert pe['entry'] % 4 == 0, 'AArch64 entry alignment'
    directories = []
    for index in range(16):
        rva, size = struct.unpack_from('<II', data, opt + 112 + index * 8)
        if rva == size == 0:
            continue
        assert rva and size, 'half-empty PE directory'
        assert index in (0, 2, 3, 4, 5, 6), 'unsupported PE directory'
        if index == 4:
            assert windows and rva % 8 == 0 and size % 8 == 0 and size >= 8 and rva + size == len(data), 'certificate suffix bounds'
            assert rva >= max([header_size] + [end for _, end in raw]), 'certificate overlaps image'
            cursor = rva
            while cursor < len(data):
                assert cursor + 8 <= len(data), 'certificate header bounds'
                length, revision, kind = struct.unpack_from('<IHH', data, cursor)
                assert 8 <= length <= len(data) - cursor and revision == 0x200 and kind == 2, 'certificate framing'
                following = align(cursor + length, 8)
                assert following <= len(data) and data[cursor + length:following] == bytes(following - cursor - length), 'certificate padding'
                cursor = following
        else:
            address = raw_offset(pe, rva, size)
            if index == 6:
                assert size % 28 == 0, 'debug directory geometry'
                for offset in range(address, address + size, 28):
                    length, target = struct.unpack_from('<II', data, offset + 16)
                    if length:
                        raw_offset(pe, target, length)
        directories.append(index)
    try:
        relocations = inspect_dir64(data, pe, allow_code=windows)
    except (AssertionError, struct.error) as error:
        raise AssertionError('DIR64 relocation contract: ' + str(error)) from error
    pe['file_alignment'] = file_align
    pe['header_bytes'] = header_size
    pe['certificate_authenticated'] = False
    pe['directories'] = directories
    pe['relocations'] = relocations
    return pe




def inventory_modules(inventory):
    assert inventory['schema'] == 3, 'unsupported inventory schema'
    for key in ('fv_max_bytes', 'image_max_bytes'):
        assert type(inventory[key]) is int and inventory[key] >= PAGE, key
        assert inventory[key] % PAGE == 0, key + ' alignment'
    modules, names = {}, set()
    for module in inventory['modules']:
        name = module['name']
        guid = str(uuid.UUID(module['guid']))
        assert isinstance(name, str) and name and name not in names, 'duplicate module name'
        assert guid not in modules, 'duplicate inventory GUID'
        assert module['file_type'] in (5, 7, 9), 'unsupported inventory file type'
        assert module['subsystem'] in (10, 11, 12), 'unsupported inventory subsystem'
        assert type(module['expected_depex']) is int and module['expected_depex'] in (0, 1)
        if module['file_type'] == 5:
            assert module['subsystem'] == 11 and module['expected_depex'] == 0
        if module['file_type'] == 9:
            assert module['subsystem'] == 10 and module['expected_depex'] == 0, 'application kind/subsystem/depex mismatch'
        else:
            assert module['subsystem'] in (11, 12), 'driver/core subsystem mismatch'
        if module.get('binary', False):
            assert guid == WINDOWS_GUID and name == 'WindowsBootManager', 'unreviewed binary module'
            assert type(module['payload_bytes']) is int and 0 < module['payload_bytes'] <= 0x400000
            assert len(bytes.fromhex(module['payload_sha256'])) == 32
        assert module.get('binary', False) is (guid == WINDOWS_GUID), 'Windows must carry reviewed binary binding'
        names.add(name)
        modules[guid] = module
    assert sum(m['file_type'] == 5 for m in modules.values()) == 1, 'one core required'
    assert len(modules) == 28, 'SEC49 executable inventory count'
    applications = [(guid, module) for guid, module in modules.items() if module['file_type'] == 9]
    assert {g: m['name'] for g, m in applications} == {APPLICATION_GUID: 'N976nBootTest', WINDOWS_GUID: 'WindowsBootManager'}, 'exact reviewed applications required'
    return modules


def inventory_resources(inventory):
    entries = inventory.get('resources', [])
    expected = {RESOURCE_GUID: ('BootInfo.txt', PAGE), MEDIA_GUID: ('BootMedia.fat', 3 * 1024 * 1024)}
    assert len(entries) == len(expected), 'reviewed boot resources required'
    result = {}
    for resource in entries:
        guid = resource['guid']
        assert guid in expected and guid not in result, 'unknown/duplicate resource'
        name, maximum = expected[guid]
        assert resource['name'] == name and resource['file_type'] == 2
        assert type(resource['payload_bytes']) is int and 0 < resource['payload_bytes'] <= maximum
        assert len(bytes.fromhex(resource['payload_sha256'])) == 32
        result[guid] = resource
    return result

def inspect(blob, inventory):
    approved = inventory_modules(inventory)
    resources = inventory_resources(inventory)
    assert not set(approved) & set(resources), 'resource/executable GUID overlap'
    resource_results = []
    assert 0 < len(blob) <= inventory['fv_max_bytes'] and len(blob) % PAGE == 0, 'FV size budget'
    assert blob[16:32] == FFS2, 'FV is not FFS2'
    assert struct.unpack_from('<H', blob, 52)[0] == 0, 'unsupported FV extension header'
    fv = READERS['inspect_fv'](blob)
    last = fv['files'][-1]
    erase = 255 if struct.unpack_from('<I', blob, 44)[0] & 0x800 else 0
    tail = blob[align(last['offset'] + last['size'], 8):]
    assert tail == bytes([erase]) * len(tail), 'non-erased FV tail'
    guids = [str(uuid.UUID(bytes_le=bytes.fromhex(f['guid_bytes'])))
             for f in fv['files'] if f['type'] != 0xF0]
    assert len(guids) == len(set(guids)), 'duplicate FV module GUID'
    seen, modules = set(), []
    for file in fv['files']:
        if file['type'] == 0xF0:
            continue
        guid = str(uuid.UUID(bytes_le=bytes.fromhex(file['guid_bytes'])))
        assert guid not in seen, 'duplicate FV module GUID'
        assert guid in approved or guid in resources, 'unknown FV module GUID'
        seen.add(guid)
        if guid in resources:
            resource = resources[guid]
            assert file['type'] == 2, 'resource FFS type differs from inventory'
            assert not blob[file['offset'] + 19] & 0x81, 'large/reserved FFS attributes'
            sections = file['sections']
            assert sorted(s['type'] for s in sections) == [0x15, 0x19], 'resource requires exact UI and RAW sections'
            payload_section = next(s for s in sections if s['type'] == 0x19)
            payload = blob[payload_section['offset'] + 4:payload_section['offset'] + payload_section['size']]
            ui = next(s for s in sections if s['type'] == 0x15)
            filename = blob[ui['offset'] + 4:ui['offset'] + ui['size']]
            assert filename == (resource['name'] + '\0').encode('utf-16-le'), 'resource filename differs from inventory'
            assert len(payload) == resource['payload_bytes'], 'resource byte count differs from inventory'
            assert hashlib.sha256(payload).hexdigest() == resource['payload_sha256'], 'resource payload differs from inventory'
            resource_results.append(dict(resource, file_offset=file['offset'], exact_payload_and_name=True))
            continue
        module = approved[guid]
        assert file['type'] == module['file_type'], 'FFS type differs from inventory'
        assert not blob[file['offset'] + 19] & 0x81, 'large/reserved FFS attributes'
        sections = file['sections']
        assert all(s['type'] in (0x10, 0x13, 0x14, 0x15, 0x19) for s in sections), 'unsupported FFS section'
        images = [s for s in sections if s['type'] == 0x10]
        dependencies = [s for s in sections if s['type'] == 0x13]
        assert len(images) == 1, 'one PE32 section required per module'
        assert len(dependencies) == module['expected_depex'], 'DEPEX count differs from inventory'
        image = images[0]
        # Pinned BaseTools GenFfs emits a zero RAW section to satisfy this
        # FDF's PE32 Align=4K. Do not admit arbitrary raw resources here.
        padding = [s for s in sections if s['type'] == 0x19]
        assert len(padding) <= 1 and (image['offset'] + 4) % PAGE == 0, 'PE section FV alignment'
        for section in padding:
            payload = blob[section['offset'] + 4:section['offset'] + section['size']]
            assert section['size'] <= PAGE and section['offset'] + section['size'] == image['offset'], 'RAW alignment section placement'
            assert payload == bytes(len(payload)), 'RAW alignment padding is not zero'
        data = blob[image['offset'] + 4:image['offset'] + image['size']]
        pe = inspect_image(data, module, inventory['image_max_bytes'])
        if module.get('binary', False):
            # Inspect semantics first so malformed-format tests reach their
            # predicates; then bind all original bytes, including certificates
            # and nonexecuting metadata, to the reviewed source inventory.
            assert len(data) == module['payload_bytes'], 'binary payload byte count differs from inventory'
            assert hashlib.sha256(data).hexdigest() == module['payload_sha256'], 'binary payload differs from inventory'
            pe['exact_inventory_payload'] = True
        depex = [inspect_depex(blob[s['offset'] + 4:s['offset'] + s['size']])
                 for s in dependencies]
        modules.append({'name': module['name'], 'guid': guid, 'file_type': file['type'],
                        'file_offset': file['offset'], 'pe': pe, 'depex': depex,
                        'zero_alignment_raw_sections': len(padding)})
    assert seen == set(approved) | set(resources), 'missing approved FV module'
    return {'fv_size': len(blob), 'fv_and_ffs_checksums_verified': True,
            'exact_module_inventory': True, 'modules': modules, 'resources': resource_results}

def corruptions(blob, inventory):
    """Repair enclosing FFS checksums so semantic faults reach their checker."""
    fv = READERS['inspect_fv'](blob)
    files = [f for f in fv['files'] if f['type'] != 0xF0]
    core = fv['core_file']
    driver = next(f for f in files if f['type'] == 7)
    image = next(s for s in core['sections'] if s['type'] == 0x10)
    start = image['offset'] + 4
    pe = image['pe']
    nt = start + struct.unpack_from('<I', blob, start + 60)[0]
    section_headers = nt + 24 + struct.unpack_from('<H', blob, nt + 20)[0]
    executable = next(i for i, s in enumerate(pe['sections']) if s['flags'] & EXECUTE)
    nonexecuting = next(s for s in pe['sections'] if not s['flags'] & EXECUTE)
    dependency_file = next(f for f in files if any(s['type'] == 0x13 for s in f['sections']))
    dependency = next(s for s in dependency_file['sections'] if s['type'] == 0x13)
    reloc_rva, reloc_size = struct.unpack_from('<II', blob, nt + 24 + 152)
    reloc_start = start + raw_offset(pe, reloc_rva, reloc_size)
    cursor, relocation_entry = reloc_start, None
    while cursor < reloc_start + reloc_size and relocation_entry is None:
        block_size = struct.unpack_from('<I', blob, cursor + 4)[0]
        relocation_entry = next((p for p in range(cursor + 8, cursor + block_size, 2)
                                 if struct.unpack_from('<H', blob, p)[0] >> 12 == 10), None)
        cursor += block_size
    assert relocation_entry is not None, 'mutation requires initialized DIR64 target'
    cases = []

    def add(name, changed, file=None, expected=None):
        if file is not None:
            repair_ffs(changed, file)
        began = time.monotonic()
        try:
            inspect(bytes(changed), inventory)
        except (AssertionError, ValueError, struct.error) as error:
            reason = str(error) or type(error).__name__
            assert expected is None or expected in reason, name + ' failed at unintended predicate: ' + reason
            cases.append({'name': name, 'rejected': True, 'reason': reason,
                          'seconds': time.monotonic() - began})
        else:
            raise AssertionError(name + ' corruption was accepted')

    changed = bytearray(blob); changed[50] ^= 1
    add('fv_header_checksum', changed)
    changed = bytearray(blob); changed[driver['offset'] + 16] ^= 1
    add('ffs_header_checksum', changed, expected='FFS header checksum')
    changed = bytearray(blob); changed[driver['offset']:driver['offset'] + 16] = bytes(16)
    add('unapproved_module_guid', changed, driver, 'unknown FV module GUID')
    changed = bytearray(blob); changed[driver['offset']:driver['offset'] + 16] = blob[core['offset']:core['offset'] + 16]
    add('duplicate_module_guid', changed, driver, 'duplicate FV module GUID')
    changed = bytearray(blob); changed[driver['offset'] + 18] = 0xF0
    add('missing_approved_module', changed, driver, 'missing approved FV module')
    changed = bytearray(blob); changed[image['offset']:image['offset'] + 3] = (core['size']).to_bytes(3, 'little')
    add('section_outside_ffs', changed, core)
    changed = bytearray(blob); flag_offset = section_headers + executable * 40 + 36
    struct.pack_into('<I', changed, flag_offset, struct.unpack_from('<I', changed, flag_offset)[0] | WRITE)
    add('writable_executable_section', changed, core, 'writable executable section')
    changed = bytearray(blob); struct.pack_into('<I', changed, nt + 24 + 16, nonexecuting['rva'])
    add('entry_in_nonexecuting_section', changed, core, 'entry must lie in executable code')
    changed = bytearray(blob); struct.pack_into('<I', changed, nt + 24 + 32, PAGE // 2)
    add('wrong_section_alignment', changed, core, 'PE alignment')
    changed = bytearray(blob); struct.pack_into('<H', changed, relocation_entry,
                                               (struct.unpack_from('<H', changed, relocation_entry)[0] & 4095) | 0x3000)
    add('unsupported_relocation_kind', changed, core, 'DIR64 relocation contract')
    changed = bytearray(blob); changed[dependency['offset'] + 4] = 3
    add('depex_stack_underflow', changed, dependency_file, 'DEPEX stack underflow')
    padding = next(s for s in core['sections'] if s['type'] == 0x19)
    changed = bytearray(blob); changed[padding['offset'] + 4] = 1
    add('raw_alignment_payload_not_zero', changed, core, 'RAW alignment padding is not zero')
    changed = bytearray(blob)
    struct.pack_into('<I', changed, reloc_start, pe['sections'][executable]['rva'])
    struct.pack_into('<H', changed, relocation_entry, 0xA000)
    add('relocation_into_executable_code', changed, core, 'relocation target must be backed nonexecuting data')
    cases[-1]['coverage_note'] = ('Stricter pinned non-Windows module profile; production SEC49 '
                                  'allows exact source RX fixups while staging remains RW-XN.')
    changed = bytearray(blob)
    assert relocation_entry + 4 <= reloc_start + struct.unpack_from('<I', blob, reloc_start + 4)[0]
    struct.pack_into('<H', changed, relocation_entry + 2, struct.unpack_from('<H', changed, relocation_entry)[0])
    add('duplicate_relocation_target', changed, core, 'duplicate/overlapping/unordered relocation')
    application = next(f for f in files if str(uuid.UUID(bytes_le=bytes.fromhex(f['guid_bytes']))) == APPLICATION_GUID)
    app_image = next(s for s in application['sections'] if s['type'] == 0x10)
    app_start = app_image['offset'] + 4
    app_nt = app_start + struct.unpack_from('<I', blob, app_start + 60)[0]
    changed = bytearray(blob); struct.pack_into('<H', changed, app_nt + 24 + 68, 11)
    add('application_with_driver_subsystem', changed, application, 'PE subsystem differs from inventory')
    changed = bytearray(blob); changed[application['offset'] + 18] = 7
    add('application_with_driver_ffs_kind', changed, application, 'FFS type differs from inventory')
    app_pe = app_image['pe']
    app_headers = app_nt + 24 + struct.unpack_from('<H', blob, app_nt + 20)[0]
    app_code = next(i for i, s in enumerate(app_pe['sections']) if s['flags'] & EXECUTE)
    changed = bytearray(blob); app_flags = app_headers + app_code * 40 + 36
    struct.pack_into('<I', changed, app_flags, struct.unpack_from('<I', changed, app_flags)[0] | WRITE)
    add('application_writable_executable_section', changed, application, 'writable executable section')
    resource = next(f for f in files if str(uuid.UUID(bytes_le=bytes.fromhex(f['guid_bytes']))) == RESOURCE_GUID)
    resource_raw = next(s for s in resource['sections'] if s['type'] == 0x19)
    changed = bytearray(blob); changed[resource_raw['offset'] + 4] ^= 1
    add('resource_payload_not_reviewed_bytes', changed, resource, 'resource payload differs from inventory')
    changed = bytearray(blob); changed[resource['offset'] + 18] = 9
    add('resource_mislabelled_executable', changed, resource, 'resource FFS type differs from inventory')
    windows = next(f for f in files if str(uuid.UUID(bytes_le=bytes.fromhex(f['guid_bytes']))) == WINDOWS_GUID)
    win_image = next(s for s in windows['sections'] if s['type'] == 0x10)
    win_start, win_pe = win_image['offset'] + 4, win_image['pe']
    win_opt = win_start + struct.unpack_from('<I', blob, win_start + 60)[0] + 24
    cert_directory = win_opt + 112 + 4 * 8
    cert_offset, cert_bytes = struct.unpack_from('<II', blob, cert_directory)
    cert_start = win_start + cert_offset
    changed = bytearray(blob); struct.pack_into('<I', changed, win_opt + 36, 768)
    add('windows_non_power_of_two_file_alignment', changed, windows, 'PE alignment')
    changed = bytearray(blob); struct.pack_into('<I', changed, win_opt + 60, 1025)
    add('windows_misaligned_header', changed, windows, 'PE header alignment')
    changed = bytearray(blob); struct.pack_into('<I', changed, cert_directory + 4, cert_bytes - 8)
    add('windows_certificate_incomplete_suffix', changed, windows, 'certificate suffix bounds')
    changed = bytearray(blob)
    win_headers = struct.unpack_from('<I', blob, win_opt + 60)[0]
    struct.pack_into('<II', changed, cert_directory, win_headers, win_image['size'] - 4 - win_headers)
    add('windows_certificate_section_overlap', changed, windows, 'certificate overlaps image')
    changed = bytearray(blob); struct.pack_into('<I', changed, cert_start, cert_bytes + 1)
    add('windows_certificate_record_overrun', changed, windows, 'certificate framing')
    changed = bytearray(blob); struct.pack_into('<I', changed, cert_start, cert_bytes - 1)
    changed[cert_start + cert_bytes - 1] = 1
    add('windows_certificate_nonzero_padding', changed, windows, 'certificate padding')
    win_reloc_rva, win_reloc_bytes = struct.unpack_from('<II', blob, win_opt + 152)
    win_reloc_start = win_start + raw_offset(win_pe, win_reloc_rva, win_reloc_bytes)
    cursor, rx_item, rx_target, rx_block = win_reloc_start, None, None, None
    while cursor < win_reloc_start + win_reloc_bytes and rx_item is None:
        page, extent = struct.unpack_from('<II', blob, cursor)
        for item in range(cursor + 8, cursor + extent, 2):
            value = struct.unpack_from('<H', blob, item)[0]
            target = page + (value & 4095)
            if value >> 12 == 10 and any(s['flags'] & EXECUTE and s['rva'] <= target and
                target + 8 <= s['rva'] + min(s['virtual_size'], s['raw_size']) for s in win_pe['sections']):
                rx_item, rx_target, rx_block = item, target, cursor
                break
        cursor += extent
    assert rx_item is not None, 'Windows fixture requires RX DIR64 pointers'
    changed = bytearray(blob)
    struct.pack_into('<H', changed, rx_item, struct.unpack_from('<H', blob, rx_item)[0] | 1)
    add('windows_rx_fixup_unaligned', changed, windows, 'only aligned DIR64 permitted')
    assert rx_item + 4 <= rx_block + struct.unpack_from('<I', blob, rx_block + 4)[0]
    changed = bytearray(blob)
    struct.pack_into('<H', changed, rx_item + 2, struct.unpack_from('<H', blob, rx_item)[0])
    add('windows_rx_fixup_duplicate', changed, windows, 'duplicate/overlapping/unordered relocation')
    changed = bytearray(blob); struct.pack_into('<II', changed, win_opt + 112, rx_target, 8)
    add('windows_rx_fixup_directory_overlap', changed, windows, 'relocation overlaps image directory')
    changed = bytearray(blob)
    # This changes code without changing its PE/relocation geometry. An exact
    # inventory binding must reject it even though format checks can still pass.
    code = next(s for s in win_pe['sections'] if s['flags'] & EXECUTE)
    changed[win_start + code['raw_offset']] ^= 1
    add('windows_unreviewed_code_bytes', changed, windows, 'binary payload differs from inventory')
    changed = bytearray(blob); changed[cert_start + 8] ^= 1
    add('windows_unreviewed_opaque_certificate_bytes', changed, windows, 'binary payload differs from inventory')
    return cases

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--fv', required=True, type=Path)
    parser.add_argument('--inventory', required=True, type=Path)
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    assert __debug__, 'Run with assertions enabled'
    assert not args.output.exists(), 'Preserve existing evidence'
    started = time.monotonic()
    blob, inventory_bytes = args.fv.read_bytes(), args.inventory.read_bytes()
    inventory = json.loads(inventory_bytes)
    report = {'baseline': 'SEC68 source extraction', 'passed': False, 'static_only': True,
              'hardware_verified': False, 'windows_executed': False,
              'comprehensive_regression_performed': False,
              'fv_sha256': hashlib.sha256(blob).hexdigest(),
              'inventory_sha256': hashlib.sha256(inventory_bytes).hexdigest(),
              'sources_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                  for p in (Path(__file__).resolve(), Path(baseline.__file__))},
              'scope': 'Inventory-bound FV/FFS/PE/DEPEX, Windows certificate framing and ordered DIR64, W^X; host-only format corruption cases.',
              'independent_profile_restrictions': [
                  'Pinned non-Windows modules retain 4KiB file alignment and no RX relocation targets; production permits the reviewed Windows format for exact FV sources.',
                  'Preferred relocation values must point inside the image in this source inventory; production verifies exact source value plus load delta.'],
              'omitted': ['Firmware execution and actual page tables', 'Physical entry, cache, IRQ and scanout', 'Windows and historical whole-path regression']}
    try:
        assert len(inventory['modules']) > 1, 'Reviewed multi-module source inventory required'
        report['normal'] = inspect(blob, inventory)
        report['corruptions'] = corruptions(blob, inventory)
        assert len(report['corruptions']) == 30
        report['passed'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
    report['seconds'] = time.monotonic() - started
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'passed': report['passed'], 'seconds': report['seconds'],
                      'report': str(args.output), 'error': report.get('error')}))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
