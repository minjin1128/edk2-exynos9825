#!/usr/bin/env python3
"""SEC21 ELF auditor, derived from the frozen PROBE6 auditor with a 8 MiB cap.

The compiler runs locally. If ld.lld is not available locally, an existing
Orb Ubuntu VM supplies the ELF linker through its /mnt/mac shared filesystem.
No libc, dynamic loader, objcopy, runtime relocation or filesystem is required
by the phone. Retained static relocations are audited before emitting Image.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import shutil
import struct
import subprocess


MAX_IMAGE = 0xC00000
ALLOCATED_NAMES = {".text", ".rodata", ".data", ".bss", ".stack", ".bootpayload"}
RELOCATIONS = {
    260: "R_AARCH64_PREL64", 261: "R_AARCH64_PREL32", 262: "R_AARCH64_PREL16",
    273: "R_AARCH64_LD_PREL_LO19", 274: "R_AARCH64_ADR_PREL_LO21",
    275: "R_AARCH64_ADR_PREL_PG_HI21", 276: "R_AARCH64_ADR_PREL_PG_HI21_NC",
    277: "R_AARCH64_ADD_ABS_LO12_NC", 278: "R_AARCH64_LDST8_ABS_LO12_NC",
    279: "R_AARCH64_TSTBR14", 280: "R_AARCH64_CONDBR19",
    282: "R_AARCH64_JUMP26", 283: "R_AARCH64_CALL26",
    284: "R_AARCH64_LDST16_ABS_LO12_NC", 285: "R_AARCH64_LDST32_ABS_LO12_NC",
    286: "R_AARCH64_LDST64_ABS_LO12_NC", 299: "R_AARCH64_LDST128_ABS_LO12_NC",
}


def extract_elf(data: bytes) -> tuple[bytes, dict[str, int], dict]:
    """Validate linked ELF and return raw Image, exported symbols and audit data.

Unlike build_probe.extract_elf this accepts ET_EXEC, materializes multiple
allocated sections and NOBITS, and validates --emit-relocs static records.
The one permitted ABS64 is the header's absolute *size*, never a pointer.
"""
    def take(offset: int, size: int) -> bytes:
        if offset < 0 or size < 0 or offset + size > len(data):
            raise ValueError("ELF range extends outside file")
        return data[offset:offset + size]

    header = struct.unpack("<16sHHIQQQIHHHHHH", take(0, 64))
    if header[0][:7] != b"\x7fELF\x02\x01\x01" or header[1:4] != (2, 183, 1):
        raise ValueError("Expected linked little-endian AArch64 ELF64 ET_EXEC")
    if header[8] != 64 or header[11] != 64 or not header[12]:
        raise ValueError("Unsupported ELF section/header sizes")
    sections = [struct.unpack("<IIQQQQIIQQ", take(header[6] + i * 64, 64))
                for i in range(header[12])]
    if header[13] >= len(sections):
        raise ValueError("Missing ELF section name table")
    names_section = sections[header[13]]
    section_strings = take(names_section[4], names_section[5])

    def string(table: bytes, offset: int) -> str:
        if not 0 <= offset < len(table):
            raise ValueError("Invalid ELF string index")
        try:
            return table[offset:table.index(0, offset)].decode("utf-8")
        except (ValueError, UnicodeDecodeError) as error:
            raise ValueError("Invalid ELF string") from error

    section_names = [string(section_strings, sec[0]) for sec in sections]
    symbol_tables = {}
    symbols = {}
    for index, section in enumerate(sections):
        name = section_names[index]
        if (section[1] in (6, 11) or name.startswith((".got", ".plt", ".dyn", ".interp",
                                                       ".relr", ".rela.dyn", ".rela.plt"))):
            raise ValueError(f"Dynamic/GOT/PLT sections are forbidden: {name}")
        if section[2] & 2 and name not in ALLOCATED_NAMES:
            raise ValueError(f"Unexpected allocated section {name}")
        if name == ".bootpayload" and (section[1] != 1 or section[2] != 2 or section[8] != 4096):
            raise ValueError("Boot payload must be page-aligned readonly nonexecuting PROGBITS")
        if section[1] != 2:
            continue
        if section[9] != 24 or section[5] % 24 or section[6] >= len(sections):
            raise ValueError("Malformed ELF symbol table")
        string_section = sections[section[6]]
        strings = take(string_section[4], string_section[5])
        entries = []
        for at in range(section[4], section[4] + section[5], 24):
            name_offset, info, other, shndx, value, size = struct.unpack("<IBBHQQ", take(at, 24))
            symbol_name = string(strings, name_offset)
            entries.append((symbol_name, info, other, shndx, value, size))
            if shndx == 0 and symbol_name:
                raise ValueError(f"Undefined ELF symbol {symbol_name}")
            # LLD localizes hidden C globals/functions in ET_EXEC. Keep these
            # named symbols too so tests can inspect the compiled C path.
            exported = info >> 4 in (1, 2) or (other & 3 == 2 and info & 15 in (1, 2))
            if exported and shndx != 0 and symbol_name:
                if symbol_name in symbols and symbols[symbol_name] != value:
                    raise ValueError(f"Ambiguous ELF symbol {symbol_name}")
                symbols[symbol_name] = value
        symbol_tables[index] = entries

    required = ("image_start", "image_end", "image_size", "probe_entry", "probe_halt",
                "__data_start", "__data_end", "__bss_start", "__bss_end",
                "__writable_start", "__writable_end")
    if any(name not in symbols for name in required):
        raise ValueError("Missing required layout/entry symbols")
    length = symbols["image_end"]
    if (symbols["image_start"] != 0 or symbols["image_size"] != length
            or symbols["probe_entry"] != 64 or header[4] != 64
            or not 0 < length <= MAX_IMAGE or length % 4096):
        raise ValueError("Invalid Image size, alignment or entry layout")
    ordered = [symbols[name] for name in ("__writable_start", "__data_start", "__data_end",
                                          "__bss_start", "__bss_end", "__writable_end")]
    if ordered != sorted(ordered) or not 64 <= ordered[0] <= ordered[-1] <= length:
        raise ValueError("Invalid writable Image ranges")
    if any(symbols[name] % 16 for name in ("__bss_start", "__bss_end")):
        raise ValueError("BSS bounds must have 16-byte alignment")

    image = bytearray(length)
    allocated = []
    occupied = []
    for index, section in enumerate(sections):
        if not section[2] & 2 or not section[5]:
            continue
        name = section_names[index]
        address, size = section[3], section[5]
        if section[1] not in (1, 8) or address + size > length:
            raise ValueError(f"Invalid allocated section {name}")
        if any(address < end and start < address + size for start, end in occupied):
            raise ValueError(f"Overlapping allocated section {name}")
        if section[2] & 1 and not ordered[0] <= address <= address + size <= ordered[-1]:
            raise ValueError(f"Writable section outside declared writable region: {name}")
        if name == ".text" and not section[2] & 4:
            raise ValueError("Text section is not executable")
        if section[1] == 1:
            image[address:address + size] = take(section[4], size)
        occupied.append((address, address + size))
        allocated.append({"name": name, "offset": address, "size": size,
                          "writable": bool(section[2] & 1), "nobits": section[1] == 8})

    relocation_counts = Counter()
    header_size_constants = 0
    for index, section in enumerate(sections):
        if section[1] not in (4, 9) or not section[5]:
            continue
        if (section[1] != 4 or section[9] != 24 or section[5] % 24
                or section[6] not in symbol_tables or section[7] >= len(sections)):
            raise ValueError("Only well-formed ELF64 RELA static relocations are supported")
        source = sections[section[7]]
        if not source[2] & 2:
            raise ValueError("Unexpected relocation in non-allocated section")
        entries = symbol_tables[section[6]]
        for at in range(section[4], section[4] + section[5], 24):
            offset, info, addend = struct.unpack("<QQq", take(at, 24))
            symbol_index, kind = info >> 32, info & 0xffffffff
            if symbol_index >= len(entries) or not source[3] <= offset < source[3] + source[5]:
                raise ValueError("Invalid relocation offset or symbol")
            symbol = entries[symbol_index]
            if (kind == 257 and offset == 16 and symbol[0] == "image_size"
                    and symbol[3] == 0xfff1 and symbol[4] == length and addend == 0):
                header_size_constants += 1
                relocation_counts["R_AARCH64_ABS64_header_size_constant"] += 1
                continue
            if kind not in RELOCATIONS:
                raise ValueError(f"Forbidden relocation type {kind} at Image+{offset:#x} ({symbol[0]})")
            if not 0 < symbol[3] < len(sections) or not sections[symbol[3]][2] & 2:
                raise ValueError(f"Relative relocation target is not Image-owned: {symbol[0]}")
            if not 0 <= symbol[4] + addend <= length:
                raise ValueError("Relative relocation target exceeds Image")
            relocation_counts[RELOCATIONS[kind]] += 1
    if not relocation_counts:
        raise ValueError("Missing retained relocations; link with --emit-relocs")
    if header_size_constants > 1:
        raise ValueError("Duplicate header size relocations")
    if (image[56:60] != b"ARM\x64" or struct.unpack_from("<Q", image, 16)[0] != length
            or struct.unpack_from("<Q", image, 8)[0] != 0x80000
            or struct.unpack_from("<Q", image, 24)[0] != 0x0a
            or struct.unpack_from("<Q", image, 40)[0] != 0xecefecef
            or struct.unpack_from("<I", image, 0)[0] != 0x14000010):
        raise ValueError("Incorrect ARM64 Image header")
    metadata = {"allocated_sections": allocated,
                "static_relocations": dict(sorted(relocation_counts.items())),
                "header_absolute_size_constants": header_size_constants,
                "runtime_relocations": 0, "minimum_load_alignment": 4096,
                "nobits_and_padding_materialized": True}
    return bytes(image), symbols, metadata


extract_linked_elf = extract_elf

