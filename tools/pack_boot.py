# SPDX-License-Identifier: MIT
#!/usr/bin/env python3
"""Package a raw ARM64 probe as a separate, hardware-unvalidated boot candidate.

This deliberately supports the supplied N976N LineageOS template only: Android
header v1, 2048-byte pages, no second stage/recovery DTBO, a 55 MiB partition,
and an unsigned AVB blob with one salted SHA256 boot hash plus properties.
The ramdisk and header metadata are preserved. The Android SHA1 ID, AVB boot
digest/image size, and footer offsets are regenerated. No device is accessed.

Format references (read as specifications; no downloaded tools are executed):
https://android.googlesource.com/platform/system/tools/mkbootimg/+/refs/heads/main/mkbootimg.py
https://android.googlesource.com/platform/external/avb/+/refs/heads/main/avbtool.py
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import struct
import tempfile


PARTITION_SIZE = 55 * 1024 * 1024
BOOT_PAGE_SIZE = 2048
AVB_BLOCK_SIZE = 4096
HEADER_SIZE = 1648


def align(value, alignment):
    return (value + alignment - 1) // alignment * alignment


def android_v1_id(kernel, ramdisk):
    """AOSP update_sha: each component's bytes followed by its LE uint32 size."""
    digest = hashlib.sha1()
    # Even absent second-stage and recovery-DTBO components contribute a size.
    for component in (kernel, ramdisk, b"", b""):
        digest.update(component)
        digest.update(struct.pack("<I", len(component)))
    return digest.digest() + bytes(12)


def parse_template(data):
    """Validate the supported layout and hashes before preserving any bytes."""
    if len(data) != PARTITION_SIZE or data[:8] != b"ANDROID!":
        raise ValueError("Template must be a raw 55 MiB Android boot image")
    kernel_size, _, ramdisk_size, _, second_size, _, _, page, version, _ = (
        struct.unpack_from("<10I", data, 8)
    )
    recovery_size, recovery_offset, header_size = struct.unpack_from(
        "<IQI", data, 1632
    )
    if (version != 1 or page != BOOT_PAGE_SIZE or header_size != HEADER_SIZE
            or second_size or recovery_size or recovery_offset):
        raise ValueError("Expected v1/2048-byte pages without second stage or recovery DTBO")
    if not kernel_size or not ramdisk_size:
        raise ValueError("Template kernel and ramdisk must both be present")
    ramdisk_start = align(page + kernel_size, page)
    body_end = align(ramdisk_start + ramdisk_size, page)
    if body_end > len(data) - AVB_BLOCK_SIZE:
        raise ValueError("Template component sizes exceed the partition")
    kernel = data[page:page + kernel_size]
    ramdisk = data[ramdisk_start:ramdisk_start + ramdisk_size]
    if data[576:608] != android_v1_id(kernel, ramdisk):
        raise ValueError("Template Android v1 SHA1 ID does not match its components")

    magic, major, minor, original_size, offset, size = struct.unpack_from(
        ">4sIIQQQ", data, len(data) - 64
    )
    if magic != b"AVBf" or (major, minor) != (1, 0):
        raise ValueError("Expected an AVB footer version 1.0")
    if original_size != body_end:
        raise ValueError("Unexpected data outside the Android components; refusing to discard it")
    if (offset != align(original_size, AVB_BLOCK_SIZE) or size < 256
            or offset + align(size, AVB_BLOCK_SIZE) > len(data) - AVB_BLOCK_SIZE):
        raise ValueError("Invalid or unsupported AVB placement")
    vbmeta = data[offset:offset + size]
    if vbmeta[:4] != b"AVB0":
        raise ValueError("Missing AVB0 header")
    auth_size, aux_size, algorithm = struct.unpack_from(">QQI", vbmeta, 12)
    hash_size = struct.unpack_from(">Q", vbmeta, 40)[0]
    signature_size = struct.unpack_from(">Q", vbmeta, 56)[0]
    key_size = struct.unpack_from(">Q", vbmeta, 72)[0]
    key_metadata_size = struct.unpack_from(">Q", vbmeta, 88)[0]
    if algorithm != 0 or any((auth_size, hash_size, signature_size, key_size, key_metadata_size)):
        raise ValueError("Only unsigned AVB NONE is supported; signed metadata cannot be preserved")
    if aux_size % 64 or 256 + aux_size != size:
        raise ValueError("Invalid AVB auxiliary block size")
    desc_offset, desc_size = struct.unpack_from(">QQ", vbmeta, 96)
    if desc_offset % 8 or desc_size % 8 or desc_offset + desc_size > aux_size:
        raise ValueError("Invalid AVB descriptor bounds")
    position = 256 + desc_offset
    end = position + desc_size
    boot_hash = None
    properties = []
    while position < end:
        if position + 16 > end:
            raise ValueError("Truncated AVB descriptor header")
        tag, following = struct.unpack_from(">QQ", vbmeta, position)
        next_position = position + 16 + following
        if following % 8 or next_position > end:
            raise ValueError("Invalid AVB descriptor length")
        descriptor = vbmeta[position:next_position]
        if tag == 0:
            if len(descriptor) < 32:
                raise ValueError("Truncated AVB property")
            key_len, value_len = struct.unpack_from(">QQ", descriptor, 16)
            value_start = 32 + key_len + 1
            value_end = value_start + value_len
            if (value_end >= len(descriptor) or descriptor[value_start - 1] != 0
                    or descriptor[value_end] != 0):
                raise ValueError("Invalid AVB property string bounds")
            properties.append(descriptor)
        elif tag == 2:
            if boot_hash is not None or len(descriptor) < 132:
                raise ValueError("Expected exactly one complete AVB hash descriptor")
            image_size = struct.unpack_from(">Q", descriptor, 16)[0]
            hash_algorithm = descriptor[24:56].split(b"\0", 1)[0]
            name_len, salt_len, digest_len, _ = struct.unpack_from(">IIII", descriptor, 56)
            salt_start = 132 + name_len
            digest_start = salt_start + salt_len
            if digest_start + digest_len > len(descriptor):
                raise ValueError("Truncated AVB hash payload")
            if (descriptor[132:salt_start] != b"boot" or hash_algorithm != b"sha256"
                    or digest_len != 32 or image_size != original_size):
                raise ValueError("Expected a SHA256 boot descriptor covering the entire original image")
            salt = descriptor[salt_start:digest_start]
            digest = descriptor[digest_start:digest_start + digest_len]
            if hashlib.sha256(salt + data[:image_size]).digest() != digest:
                raise ValueError("Template AVB boot hash is stale or invalid")
            boot_hash = {
                "image_size_offset": position + 16,
                "digest_offset": position + digest_start,
                "salt": salt,
            }
        else:
            raise ValueError(f"Unsupported AVB descriptor tag {tag}; refusing to copy unknown integrity data")
        position = next_position
    if boot_hash is None:
        raise ValueError("No AVB boot hash descriptor")
    return {
        "header": data[:page], "kernel": kernel, "ramdisk": ramdisk,
        "vbmeta": vbmeta, "hash": boot_hash, "properties": properties,
        "body_end": body_end,
    }


def validate_probe(kernel):
    if len(kernel) < 64 or kernel[56:60] != b"ARM\x64":
        raise ValueError("Probe must be a raw uncompressed ARM64 Image with its 64-byte header")
    text_offset, image_size, flags = struct.unpack_from("<QQQ", kernel, 8)
    if flags & 1:
        raise ValueError("This packer expects a little-endian ARM64 probe")
    if text_offset % 4096:
        raise ValueError("Probe text_offset must be page aligned")
    if not image_size or image_size < len(kernel):
        raise ValueError("Probe image_size must be nonzero and cover all supplied bytes")
    if len(kernel) > PARTITION_SIZE:
        raise ValueError("Probe exceeds the entire boot partition size")


def package_probe(template_data, kernel):
    validate_probe(kernel)
    template = parse_template(template_data)
    ramdisk = template["ramdisk"]
    header = bytearray(template["header"])
    struct.pack_into("<I", header, 8, len(kernel))
    header[576:608] = android_v1_id(kernel, ramdisk)
    body = header + kernel
    body.extend(bytes(align(len(body), BOOT_PAGE_SIZE) - len(body)))
    body.extend(ramdisk)
    body.extend(bytes(align(len(body), BOOT_PAGE_SIZE) - len(body)))
    vbmeta = bytearray(template["vbmeta"])
    hash_info = template["hash"]
    struct.pack_into(">Q", vbmeta, hash_info["image_size_offset"], len(body))
    digest = hashlib.sha256(hash_info["salt"] + body).digest()
    digest_offset = hash_info["digest_offset"]
    vbmeta[digest_offset:digest_offset + 32] = digest
    vbmeta_offset = align(len(body), AVB_BLOCK_SIZE)
    if vbmeta_offset + align(len(vbmeta), AVB_BLOCK_SIZE) > PARTITION_SIZE - AVB_BLOCK_SIZE:
        raise ValueError("Probe and preserved ramdisk do not leave room for AVB metadata/footer")
    candidate = bytearray(PARTITION_SIZE)
    candidate[:len(body)] = body
    candidate[vbmeta_offset:vbmeta_offset + len(vbmeta)] = vbmeta
    struct.pack_into(">4sIIQQQ28x", candidate, PARTITION_SIZE - 64,
                     b"AVBf", 1, 0, len(body), vbmeta_offset, len(vbmeta))
    # Reparse the complete candidate before making it available to the caller.
    checked = parse_template(candidate)
    if checked["ramdisk"] != ramdisk or checked["properties"] != template["properties"]:
        raise ValueError("Internal error: preserved ramdisk or AVB properties changed")
    if checked["kernel"] != kernel:
        raise ValueError("Internal error: packaged kernel differs from the supplied probe")
    report = {
        "partition_size": PARTITION_SIZE,
        "kernel_size": len(kernel),
        "ramdisk_preserved": True,
        "ramdisk_sha256": hashlib.sha256(ramdisk).hexdigest(),
        "android_v1_id_sha1": bytes(header[576:596]).hex(),
        "original_image_size": len(body),
        "vbmeta_offset": vbmeta_offset,
        "vbmeta_size": len(vbmeta),
        "avb_algorithm": "NONE",
        "boot_hash_algorithm": "sha256",
        "boot_salt_preserved": True,
        "boot_digest": digest.hex(),
        "boot_hash_verified": True,
        "property_descriptors_preserved": len(template["properties"]),
        "candidate_sha256": hashlib.sha256(candidate).hexdigest(),
        "hardware_validated": False,
        "scope": "Offline candidate with internally consistent hashes; device trust/acceptance and execution are untested.",
    }
    return candidate, report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("probe", type=Path, help="raw probe.Image to substitute for the kernel")
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, help="new output path; existing files are never overwritten")
    args = parser.parse_args()
    template_path = args.template.expanduser().resolve()
    probe_path = args.probe.expanduser().resolve()
    output = args.output or probe_path.with_name(probe_path.stem + "-boot-candidate.img")
    output = output.expanduser().absolute()
    try:
        if output.resolve() in (template_path, probe_path):
            raise ValueError("Output must be separate from both input files")
        if output.exists() or output.is_symlink():
            raise ValueError("Output already exists; choose a new filename")
        template_data = template_path.read_bytes()
        expected = json.loads((Path(__file__).resolve().parents[1] / "config/reference-inputs.json").read_text())["boot_template"]
        if len(template_data) != expected["bytes"] or hashlib.sha256(template_data).hexdigest() != expected["sha256"]:
            raise ValueError("The exact supported LineageOS boot template is required")
        kernel = probe_path.read_bytes()
        candidate, report = package_probe(template_data, kernel)
        report.update({
            "template": str(template_path),
            "template_sha256": hashlib.sha256(template_data).hexdigest(),
            "probe": str(probe_path),
            "probe_sha256": hashlib.sha256(kernel).hexdigest(),
            "output": str(output),
        })
        # Publish only a fully written image. link() refuses an existing target,
        # including one that appears after the earlier collision check.
        with tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{output.name}.", suffix=".tmp", dir=output.parent
        ) as destination:
            destination.write(candidate)
            destination.flush()
            os.fsync(destination.fileno())
            os.link(destination.name, output)
        print(json.dumps(report, indent=2))
    except (OSError, ValueError, struct.error) as error:
        parser.exit(2, f"pack_probe.py: {error}\n")


if __name__ == "__main__":
    main()
