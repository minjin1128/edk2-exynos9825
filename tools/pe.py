# SPDX-License-Identifier: MIT
"""AArch64 PE admission; unchanged function extracted from the SEC68 helper."""
import hashlib
import struct

def prepare_pe(data: bytes) -> tuple[bytes, dict]:
    def need(offset, size):
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("PE file bounds")
    def u16(at):
        need(at, 2)
        return struct.unpack_from("<H", data, at)[0]
    def u32(at):
        need(at, 4)
        return struct.unpack_from("<I", data, at)[0]
    need(0, 64)
    if data[:2] != b"MZ":
        raise ValueError("Expected an EDK2 PE/COFF image with DOS header")
    pe = u32(60)
    need(pe, 24)
    if data[pe:pe+4] != b"PE\0\0" or u16(pe+4) != 0xAA64:
        raise ValueError("Expected AArch64 PE")
    nsec, optsize, characteristics = u16(pe+6), u16(pe+20), u16(pe+22)
    opt = pe + 24
    need(opt, optsize)
    if not 1 <= nsec <= 16 or optsize != 240 or u16(opt) != 0x20B:
        raise ValueError("Expected PE32+ standard optional header")
    if characteristics & 1:
        raise ValueError("PE relocation records were stripped")
    entry, base = u32(opt+16), struct.unpack_from("<Q", data, opt+24)[0]
    salign, falign = u32(opt+32), u32(opt+36)
    size, headers = u32(opt+56), u32(opt+60)
    if base or salign != 4096 or falign != 4096:
        raise ValueError("Require ImageBase=0, 4 KiB section/file alignment")
    if not 0 < headers <= size <= 0x80000 or size % 4096 or headers % 4096:
        raise ValueError("Invalid PE Image/header size")
    need(0, headers)
    if opt + optsize + nsec * 40 > headers or entry % 4:
        raise ValueError("Section table/header size or entry alignment")
    if u32(opt+108) != 16:
        raise ValueError("Expected sixteen PE data directories")
    directories = [struct.unpack_from("<II", data, opt+112+i*8) for i in range(16)]
    # Exception and debug data are retained but never interpreted by the shim.
    if any(rva or length for i, (rva, length) in enumerate(directories) if i not in (3,5,6)):
        raise ValueError("Unsupported imports/exports/TLS or other PE directory")
    mapped = bytearray(size)
    mapped[:headers] = data[:headers]
    sections, occupied, file_ranges = [], [(0, headers)], [(0, headers)]
    for i in range(nsec):
        at = opt + optsize + i*40
        need(at, 40)
        name = data[at:at+8].split(b"\0",1)[0].decode("ascii")
        vs, rva, raw, ptr = struct.unpack_from("<4I", data, at+8)
        flags = u32(at+36)
        extent = max(vs, raw)
        if not vs or rva % 4096 or rva < headers or rva+extent > size:
            raise ValueError(f"Invalid PE section {name}")
        if any(rva < end and begin < rva+extent for begin,end in occupied):
            raise ValueError("Overlapping PE sections")
        if flags & 0x20000000 and flags & 0x80000000:
            raise ValueError("Executable/writable PE section")
        if raw:
            need(ptr, raw)
            if ptr % 4096 or raw % 4096 or any(ptr < e and b < ptr+raw for b,e in file_ranges):
                raise ValueError("Invalid PE file section placement")
            mapped[rva:rva+raw] = data[ptr:ptr+raw]
            file_ranges.append((ptr,ptr+raw))
        occupied.append((rva,rva+extent))
        sections.append(dict(name=name, rva=rva, virtual_size=vs, raw_size=raw,
                             raw_offset=ptr, characteristics=flags))
    def section_range(rva, length, flag=0):
        return any(s["rva"] <= rva and length <= s["rva"]+s["virtual_size"]-rva
                   and (not flag or s["characteristics"] & flag) for s in sections)
    if not section_range(entry, 4, 0x20000000):
        raise ValueError("PE entry is not inside executable section")
    for rva,length in directories:
        if bool(rva) != bool(length) or (length and not section_range(rva,length)):
            raise ValueError("PE directory bounds")
    reloc, relsize = directories[5]
    if not relsize:
        raise ValueError("Missing relocation evidence")
    pos, limit, fixups = reloc, reloc+relsize, []
    while pos < limit:
        if limit-pos < 8:
            raise ValueError("Truncated PE relocation block")
        page, block = struct.unpack_from("<II", mapped, pos)
        if page % 4096 or block < 8 or block % 4 or block > limit-pos:
            raise ValueError("Invalid PE relocation block")
        for off in range(pos+8,pos+block,2):
            value = struct.unpack_from("<H",mapped,off)[0]
            kind, target = value >> 12, page+(value&4095)
            if kind == 0:
                continue
            if kind != 10 or target % 8 or not section_range(target,8,0x80000000):
                raise ValueError("Only aligned DIR64 in writable PE data is permitted")
            old = struct.unpack_from("<Q",mapped,target)[0]
            if not section_range(old,1):
                raise ValueError("DIR64 pointer must refer to the same PE allocation")
            fixups.append(target)
        pos += block
    if not fixups or len(fixups) != len(set(fixups)):
        raise ValueError("Missing or duplicate DIR64 fixups")
    return bytes(mapped), {
        "preferred_base":base, "entry_rva":entry, "size_of_image":size,
        "sections":sections, "fixups":sorted(fixups),
        "writable_ranges":[[s["rva"],s["rva"]+s["virtual_size"]] for s in sections if s["characteristics"]&0x80000000],
        "zero_fill_ranges":[[s["rva"]+s["raw_size"],s["rva"]+s["virtual_size"]] for s in sections if s["virtual_size"]>s["raw_size"]],
        "sha256":hashlib.sha256(data).hexdigest(),
        "mapped_sha256":hashlib.sha256(mapped).hexdigest(),
    }
