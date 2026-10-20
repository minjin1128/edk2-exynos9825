"""SEC49 bounded FAT12 packaging, adapted from SEC41 FIX5's deterministic builder.

Only the fixed directory tree and original Windows, BCD and three font files
are supplied. SEC49 adds the two fonts actually requested by Windows error UI.
The tiny SEC44 self-test application remains in the firmware volume.
No physical disk or writable filesystem is involved.
"""
from __future__ import annotations
import hashlib
import re
import struct

SECTOR = 512
SECTORS = 6144
CLUSTER_SECTORS = 2
CLUSTER_BYTES = SECTOR * CLUSTER_SECTORS
RESERVED_SECTORS = 2
FAT_SECTORS = 9
ROOT_ENTRIES = 64
ROOT_SECTORS = ROOT_ENTRIES * 32 // SECTOR
DATA_SECTOR = RESERVED_SECTORS + 2 * FAT_SECTORS + ROOT_SECTORS
FILE_CLUSTER = 4
FILE_OFFSET = DATA_SECTOR * SECTOR + (FILE_CLUSTER - 2) * CLUSTER_BYTES
WINDOWS_OFFSET = 0x7F000
WINDOWS_BYTES = 2622896
WINDOWS_CLUSTER = (WINDOWS_OFFSET - DATA_SECTOR * SECTOR) // CLUSTER_BYTES + 2
WINDOWS_NAME = 'WINBOOT.EFI'
FONT_PATH = '\\EFI\\Microsoft\\Boot\\Fonts\\wgl4_boot.ttf'
FONT_BYTES = 50004
BCD_PATH = '\\EFI\\Microsoft\\Boot\\BCD'
DATA_CLUSTERS = (SECTORS - DATA_SECTOR) // CLUSTER_SECTORS
DISPLAY_FONTS = (
    ('segoe_slboot.ttf', 'segoe', 102920, b'SEGOE_~1TTF'),
    ('segmono_boot.ttf', 'segmono', 45892, b'SEGMON~1TTF'),
)


def lfn_entries(name: str, short: bytes) -> bytes:
    """Encode only the one/two-slot ASCII VFAT names needed by this medium."""
    if (not isinstance(name, str) or not re.fullmatch(r'[A-Za-z0-9_.]{1,26}', name) or
            name in ('.', '..') or not isinstance(short, bytes) or len(short) != 11):
        raise ValueError('SEC49 fixed VFAT names must fit one or two slots')
    units = list(name.encode('ascii'))
    count = (len(units) + 12) // 13
    if len(units) % 13:
        units += [0] + [0xffff] * (count * 13 - len(units) - 1)
    checksum = 0
    for byte in short:
        checksum = (((checksum & 1) << 7) + (checksum >> 1) + byte) & 0xff
    result = bytearray()
    for ordinal in range(count, 0, -1):
        slot = bytearray(32)
        slot[0] = ordinal | (0x40 if ordinal == count else 0)
        slot[11:14] = bytes((0x0f, 0, checksum))
        chunk = units[(ordinal - 1) * 13:ordinal * 13]
        struct.pack_into('<5H', slot, 1, *chunk[:5])
        struct.pack_into('<6H', slot, 14, *chunk[5:11])
        struct.pack_into('<H2H', slot, 26, 0, *chunk[11:])
        result += slot
    return bytes(result)


def make_volume(*, boot_bcd: bytes, boot_payload: bytes | None = None,
                boot_font: bytes | None = None,
                boot_display_fonts: dict[str, bytes] | None = None) -> tuple[bytes, dict]:
    if boot_payload is None or len(boot_payload) != WINDOWS_BYTES:
        raise ValueError('SEC49 requires the inspected 2622896-byte Windows EFI')
    if boot_font is not None and len(boot_font) != FONT_BYTES:
        raise ValueError('SEC49 requires the observed50004-byte wgl4 boot font')
    if (boot_font is None or not isinstance(boot_display_fonts, dict) or
            set(boot_display_fonts) != {item[1] for item in DISPLAY_FONTS}):
        raise ValueError('SEC49 requires exactly the three observed Windows fonts')
    for name, key, size, short in DISPLAY_FONTS:
        data = boot_display_fonts[key]
        if not isinstance(data, bytes) or len(data) != size or data[:4] != b'\x00\x01\x00\x00':
            raise ValueError('SEC49 display font size/header differs: ' + name)
    if (not isinstance(boot_bcd, bytes) or len(boot_bcd) < 8192 or
            len(boot_bcd) % 4096 or boot_bcd[:4] != b'regf'):
        raise ValueError('SEC49 requires a nonempty, page-sized registry hive BCD')
    files = [(WINDOWS_NAME, boot_payload)]
    if len(files) > CLUSTER_BYTES // 32 - 2 or len({name for name, _ in files}) != len(files):
        raise ValueError('EFI/BOOT directory capacity or duplicate name')
    if not (0 < DATA_CLUSTERS < 4085 and FAT_SECTORS * SECTOR * 2 // 3 >= DATA_CLUSTERS + 2):
        raise ValueError('FAT12 cluster count or allocation table capacity')
    metadata = []
    next_cluster = FILE_CLUSTER
    resource_start = None
    for name, data in files:
        if not re.fullmatch(r'[A-Z0-9_]{1,8}\.[A-Z0-9_]{1,3}', name) or not data:
            raise ValueError('Nonempty file and uppercase 8.3 name required')
        count = (len(data) + CLUSTER_BYTES - 1) // CLUSTER_BYTES
        if name == WINDOWS_NAME:
            resource_start = next_cluster
            next_cluster = WINDOWS_CLUSTER
        offset = DATA_SECTOR * SECTOR + (next_cluster - 2) * CLUSTER_BYTES
        limit = SECTORS * SECTOR if name == WINDOWS_NAME else WINDOWS_OFFSET
        if offset + count * CLUSTER_BYTES > limit or next_cluster + count > DATA_CLUSTERS + 2:
            raise ValueError('Files exceed their disjoint SEC49 FAT allocation ranges')
        metadata.append({'path': '\\EFI\\BOOT\\' + name, 'file_cluster': next_cluster,
                         'file_clusters': count, 'file_offset': offset,
                         'file_bytes': len(data), 'file_sha256': hashlib.sha256(data).hexdigest()})
        next_cluster += count
    windows = metadata[-1]
    directories = []
    resources = []
    # Keep every existing EFI and font cluster fixed. Only the free gap after
    # the ordinary EFI payloads may hold the existing directory/font resources
    # and the additional BCD. The Windows source offset remains immutable.
    directory_paths = ['\\EFI\\Microsoft', '\\EFI\\Microsoft\\Boot']
    if boot_font is not None:
        directory_paths.append('\\EFI\\Microsoft\\Boot\\Fonts')
    for index, path in enumerate(directory_paths):
        cluster = resource_start + index
        directories.append({'path': path, 'cluster': cluster,
                            'offset': DATA_SECTOR * SECTOR + (cluster - 2) * CLUSTER_BYTES})
    bcd_cluster = resource_start + len(directories)
    if boot_font is not None:
        font_cluster = resource_start + 3
        font_clusters = (len(boot_font) + CLUSTER_BYTES - 1) // CLUSTER_BYTES
        if font_cluster + font_clusters > WINDOWS_CLUSTER:
            raise ValueError('Boot font and directory tree overlap fixed Windows source')
        font = {'path': FONT_PATH, 'file_cluster': font_cluster,
                'file_clusters': font_clusters,
                'file_offset': DATA_SECTOR * SECTOR + (font_cluster - 2) * CLUSTER_BYTES,
                'file_bytes': len(boot_font), 'file_sha256': hashlib.sha256(boot_font).hexdigest()}
        metadata.append(font)
        resources.append(font)
        bcd_cluster = font_cluster + font_clusters
    bcd_clusters = (len(boot_bcd) + CLUSTER_BYTES - 1) // CLUSTER_BYTES
    if bcd_cluster + bcd_clusters > WINDOWS_CLUSTER:
        raise ValueError('BCD and directory tree overlap fixed Windows source')
    bcd = {'path': BCD_PATH, 'file_cluster': bcd_cluster,
           'file_clusters': bcd_clusters,
           'file_offset': DATA_SECTOR * SECTOR + (bcd_cluster - 2) * CLUSTER_BYTES,
           'file_bytes': len(boot_bcd), 'file_sha256': hashlib.sha256(boot_bcd).hexdigest()}
    metadata.append(bcd)
    resources.append(bcd)
    # The existing font, BCD and Windows positions stay fixed. Add only the two
    # observed fonts into the formerly unused gap, with one owner per cluster.
    display_fonts = []
    cursor = bcd_cluster + bcd_clusters
    for name, key, size, short in DISPLAY_FONTS:
        data = boot_display_fonts[key]
        count = (size + CLUSTER_BYTES - 1) // CLUSTER_BYTES
        if cursor + count > WINDOWS_CLUSTER:
            raise ValueError('Display fonts overlap the fixed Windows source')
        item = {'path': '\\EFI\\Microsoft\\Boot\\Fonts\\' + name,
                'file_cluster': cursor, 'file_clusters': count,
                'file_offset': DATA_SECTOR * SECTOR + (cursor - 2) * CLUSTER_BYTES,
                'file_bytes': size, 'file_sha256': hashlib.sha256(data).hexdigest()}
        display_fonts.append(item)
        metadata.append(item)
        resources.append(item)
        cursor += count
    image = bytearray(SECTORS * SECTOR)
    image[:11] = b'\xeb\x3c\x90MSDOS5.0'
    struct.pack_into('<HBHBHHBHHHII', image, 11, SECTOR, CLUSTER_SECTORS, RESERVED_SECTORS, 2,
                     ROOT_ENTRIES, SECTORS, 0xF8, FAT_SECTORS, 32, 64, 0, 0)
    image[36:39] = b'\x80\x00\x29'
    struct.pack_into('<I', image, 39, 0x2236374E)
    image[43:54] = b'N976NSEC49 '
    image[54:62] = b'FAT12   '
    image[510:512] = b'\x55\xaa'
    fat = bytearray(FAT_SECTORS * SECTOR)

    def link(cluster: int, value: int):
        offset = cluster * 3 // 2
        pair = int.from_bytes(fat[offset:offset+2], 'little')
        if cluster & 1:
            pair = (pair & 0x000F) | (value << 4)
        else:
            pair = (pair & 0xF000) | value
        fat[offset:offset+2] = pair.to_bytes(2, 'little')

    link(0, 0xFF8)
    link(1, 0xFFF)
    link(2, 0xFFF)
    link(3, 0xFFF)
    for directory in directories:
        link(directory['cluster'], 0xFFF)
    for item in metadata:
        first, count = item['file_cluster'], item['file_clusters']
        for cluster in range(first, first + count):
            link(cluster, cluster + 1 if cluster + 1 < first + count else 0xFFF)
    fat_start = RESERVED_SECTORS * SECTOR
    image[fat_start:fat_start + len(fat)] = fat
    image[fat_start + len(fat):fat_start + 2 * len(fat)] = fat

    def entry(offset: int, name: bytes, attributes: int, cluster: int, size: int = 0):
        if len(name) != 11:
            raise ValueError('FAT short name must be exactly eleven bytes')
        image[offset:offset+11] = name
        image[offset+11] = attributes
        # Fixed valid FAT date, 2026-10-13; no host time or personal metadata.
        struct.pack_into('<H', image, offset+24, ((2026-1980) << 9) | (10 << 5) | 13)
        struct.pack_into('<HI', image, offset+26, cluster, size)

    def long_entry(offset: int, name: str, short: bytes):
        encoded = lfn_entries(name, short)
        if offset < 0 or offset + len(encoded) > len(image):
            raise ValueError('VFAT entry escapes media')
        image[offset:offset + len(encoded)] = encoded
        return len(encoded)

    root = (RESERVED_SECTORS + 2 * FAT_SECTORS) * SECTOR
    efi = DATA_SECTOR * SECTOR
    boot = efi + CLUSTER_BYTES
    entry(root, b'N976NSEC49 ', 0x08, 0)
    entry(root+32, b'EFI        ', 0x10, 2)
    entry(efi, b'.          ', 0x10, 2)
    entry(efi+32, b'..         ', 0x10, 0)
    entry(efi+64, b'BOOT       ', 0x10, 3)
    entry(boot, b'.          ', 0x10, 3)
    entry(boot+32, b'..         ', 0x10, 2)
    for i, ((name, content), item) in enumerate(zip(files, metadata)):
        stem, suffix = name.split('.')
        short = (stem.ljust(8) + suffix.ljust(3)).encode('ascii')
        entry(boot + 64 + i * 32, short, 0x01, item['file_cluster'], len(content))
        offset = item['file_offset']
        image[offset:offset + len(content)] = content
    microsoft, microsoft_boot = directories[:2]
    short = b'MICROS~1   '
    long_entry(efi + 96, 'Microsoft', short)
    entry(efi + 128, short, 0x10, microsoft['cluster'])
    for directory, parent in ((microsoft, 2), (microsoft_boot, microsoft['cluster'])):
        entry(directory['offset'], b'.          ', 0x10, directory['cluster'])
        entry(directory['offset'] + 32, b'..         ', 0x10, parent)
    entry(microsoft['offset'] + 64, b'BOOT       ', 0x10, microsoft_boot['cluster'])
    bcd_entry_offset = microsoft_boot['offset'] + 64
    if boot_font is not None:
        fonts = directories[2]
        entry(fonts['offset'], b'.          ', 0x10, fonts['cluster'])
        entry(fonts['offset'] + 32, b'..         ', 0x10, microsoft_boot['cluster'])
        entry(microsoft_boot['offset'] + 64, b'FONTS      ', 0x10, fonts['cluster'])
        font_short = b'WGL4_B~1TTF'
        long_entry(fonts['offset'] + 64, 'wgl4_boot.ttf', font_short)
        entry(fonts['offset'] + 96, font_short, 0x01, font['file_cluster'], len(boot_font))
        image[font['file_offset']:font['file_offset'] + len(boot_font)] = boot_font
        slot = fonts['offset'] + 128
        for (name, key, size, short), item in zip(DISPLAY_FONTS, display_fonts):
            entries = lfn_entries(name, short)
            # Keep a zero end marker as well as every complete LFN/short entry.
            if slot + len(entries) + 64 > fonts['offset'] + CLUSTER_BYTES:
                raise ValueError('Display font names exceed the fixed directory')
            slot += long_entry(slot, name, short)
            entry(slot, short, 0x01, item['file_cluster'], size)
            slot += 32
            image[item['file_offset']:item['file_offset'] + size] = boot_display_fonts[key]
        bcd_entry_offset += 32
    entry(bcd_entry_offset, b'BCD        ', 0x01, bcd['file_cluster'], len(boot_bcd))
    image[bcd['file_offset']:bcd['file_offset'] + len(boot_bcd)] = boot_bcd
    # Canonical Microsoft boot path shares the original file's cluster chain.
    # This is one Windows payload with two directory names, not a second copy.
    windows_short = b'BOOTMG~1EFI'
    long_entry(bcd_entry_offset + 32, 'bootmgfw.efi', windows_short)
    entry(bcd_entry_offset + 64, windows_short, 0x01,
          windows['file_cluster'], windows['file_bytes'])
    alias = {**windows, 'path': '\\EFI\\Microsoft\\Boot\\bootmgfw.efi',
             'alias_of': windows['path']}
    metadata.append(alias)
    data = bytes(image)
    return data, {
        'filesystem': 'FAT12', 'bytes': len(data), 'sector_size': SECTOR,
        'sectors': SECTORS, 'fat_sectors': FAT_SECTORS, 'fat_copies': 2,
        'reserved_sectors': RESERVED_SECTORS, 'cluster_sectors': CLUSTER_SECTORS,
        'cluster_bytes': CLUSTER_BYTES, 'data_clusters': DATA_CLUSTERS,
        'root_entries': ROOT_ENTRIES, 'data_sector': DATA_SECTOR,
        **metadata[0], 'files': metadata,
        'windows': windows, 'windows_canonical': alias, 'bcd': bcd, 'resources': resources, 'directories': directories,
        'display_fonts': display_fonts,
        'unchanged_windows_offset': WINDOWS_OFFSET,
        'remaining_resource_gap_bytes': (WINDOWS_CLUSTER - cursor) * CLUSTER_BYTES,
        'sha256': hashlib.sha256(data).hexdigest(),
        'delivery': 'Immutable RAW firmware-volume resource, exposed by read-only BlockIo and upstream FAT',
        'read_only': True,
    }


WINDOWS_GUID = "6e5c45af-ef14-4637-a71b-e2815d9b4502"
MEDIA_GUID = "6e5c45af-ef14-4637-a71b-e2815d9b4503"
INPUTS = {
    "windows": ("bootaa64.efi", 2622896,
                "a6a54c95f5d1c393553737ffeb00bd83e30f4b5b727111a047b878e7d4ef95f1"),
    "bcd": ("BCD", 16384,
            "91b58da5c1209c669face3b5373cf3184ee7cda8226c3bf111a47d74a838486f"),
    "font": ("wgl4_boot.ttf", 50004,
             "6c32f0cbf870cacee03391651e001f01ab6f915a087732b896dea0384f8b94e4"),
    "segoe": ("segoe_slboot.ttf", 102920,
              "e94b650d9ad7cd610870b2d2e23a2c2f4bb99c3cb61169d768d1447081cee42e"),
    "segmono": ("segmono_boot.ttf", 45892,
                "42df39308f70c3945d5f630f0ec0bb71234c690e7a7c8171ef062113190eac7c"),
}


def prepare(project):
    """Bind the five exact supplied inputs once for this candidate build."""
    import zlib
    inputs, provenance = {}, {}
    for name, (relative, size, expected) in INPUTS.items():
        data = (project / relative).read_bytes()
        actual = hashlib.sha256(data).hexdigest()
        if len(data) != size or actual != expected:
            raise ValueError(f"SEC49 supplied {name} does not match its pinned input")
        inputs[name] = data
        provenance[name] = {"path": relative, "bytes": size, "sha256": actual}
    volume, metadata = make_volume(boot_bcd=inputs["bcd"],
                                  boot_payload=inputs["windows"],
                                  boot_font=inputs["font"],
                                  boot_display_fonts={key: inputs[key] for key in ('segoe', 'segmono')})
    metadata["inputs"] = provenance
    metadata["crc32"] = zlib.crc32(volume)
    metadata["reference_builder"] = "tools/boot_media.py:make_volume"
    metadata["windows_catalog_duplicate"] = (
        "The unchanged binary is also a sealed-FV APPLICATION source for image admission; "
        "the duplicate avoids a new source trust boundary or wrapper/HOB ABI.")
    metadata["omitted"] = ["physical storage", "boot.sdi", "boot.wim", "OS handoff"]
    header = ("/* Generated from exact SEC49 boot media; do not hand edit. */\n"
              "#ifndef N976N_BOOT_MEDIA_MANIFEST_H_\n#define N976N_BOOT_MEDIA_MANIFEST_H_\n"
              f"#define N976N_BOOT_MEDIA_EXPECTED_CRC32  0x{metadata['crc32']:08X}U\n"
              f"#define N976N_BOOT_WINDOWS_EXPECTED_CRC32  0x{zlib.crc32(inputs['windows']):08X}U\n"
              "#endif\n")
    return {"BootMedia/WindowsBootManager.efi": inputs["windows"],
            "BootMedia/BootMedia.fat": volume,
            "Include/N976nBootMediaManifest.h": header.encode()}, metadata
