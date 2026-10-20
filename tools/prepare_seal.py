# SPDX-License-Identifier: MIT
"""Check one exact reference FAT image and generate its local authentication inputs.

Reads a regular host file once with bounded buffers. Does not copy the volume,
build a different FAT, format anything, package Odin media or contact a phone.
"""
import argparse
import hashlib
import json
from pathlib import Path
import sys
import time

from inputs import SYSTEM, SEAL_NAMES, public_manifest, regular


def c_array(name, digest):
    return f"STATIC CONST UINT8 {name}[32] = {{ " + ", ".join(f"0x{x:02x}" for x in bytes.fromhex(digest)) + " };\n"


def make_header(table_hash):
    result = "/* Generated SEC63 sealed SYSTEM contract. Host preparation is not flash authorization. */\n"
    result += "#ifndef N976N_SYSTEM_VOLUME_SEAL_H_\n#define N976N_SYSTEM_VOLUME_SEAL_H_\n"
    values = {"CHUNK_BYTES": 131072, "CHUNK_COUNT": 8192, "IMAGE_BYTES": 1073741824,
              "TABLE_BYTES": 262144, "BLOCK_BYTES": 4096, "START_LBA": 0x17A00,
              "BLOCK_COUNT": 0x182400, "PARTITION_NUMBER": 0x1A}
    for key, value in values.items():
        result += f"#define N976N_SYSTEM_SEAL_{key} 0x{value:x}ULL\n"
    for key, count in (("BCD", 16384), ("SDI", 3170304), ("WIM", 940090097)):
        result += f"#define N976N_SYSTEM_{key}_BYTES {count}ULL\n"
    result += c_array("mN976nSystemSealTableSha256", table_hash)
    result += c_array("mN976nSystemSealImageSha256", SYSTEM["image_sha256"])
    result += c_array("mN976nSystemBcdSha256", "91b58da5c1209c669face3b5373cf3184ee7cda8226c3bf111a47d74a838486f")
    result += c_array("mN976nSystemSdiHeaderSha256", SYSTEM["header_sha256"]["sdi"])
    result += c_array("mN976nSystemWimHeaderSha256", SYSTEM["header_sha256"]["wim"])
    return (result + "#endif\n").encode()


def make_data(table):
    lines = ["/* Generated ordered SHA256(128KiB volume chunk); authenticate before caller copy. */",
             "STATIC CONST UINT8 mN976nSystemChunkSha256[N976N_SYSTEM_SEAL_CHUNK_COUNT][32] = {"]
    for offset in range(0, len(table), 32):
        lines.append("  { " + ", ".join(f"0x{x:02x}" for x in table[offset:offset + 32]) + " },")
    return ("\n".join(lines) + "\n};\n").encode()


def prepare(image, output):
    image, output = Path(image), Path(output)
    if output.exists() or output.is_symlink():
        raise ValueError("Choose a new output directory")
    before = regular(image, SYSTEM["image_bytes"])
    digest, table, count = hashlib.sha256(), bytearray(), 0
    with image.open("rb") as source:
        while chunk := source.read(SYSTEM["seal"]["chunk_bytes"]):
            if len(chunk) != SYSTEM["seal"]["chunk_bytes"]:
                raise ValueError("Truncated image chunk")
            digest.update(chunk)
            table.extend(hashlib.sha256(chunk).digest())
            count += len(chunk)
    if regular(image, SYSTEM["image_bytes"]) != before:
        raise ValueError("Source image changed during preparation")
    if count != SYSTEM["image_bytes"] or digest.hexdigest() != SYSTEM["image_sha256"]:
        raise ValueError("Only the exact reference FAT is supported; different media needs a separately validated port")
    table_hash = hashlib.sha256(table).hexdigest()
    files = {"SystemVolumeSeal.h": make_header(table_hash), "SystemVolumeSealData.inc": make_data(table),
             "system-block-sha256.bin": table}
    for name in SEAL_NAMES:
        entry = SYSTEM["artifacts"][name]
        if len(files[name]) != entry["bytes"] or hashlib.sha256(files[name]).hexdigest() != entry["sha256"]:
            raise ValueError("Generated seal differs from the pinned reference: " + name)
    output.mkdir(parents=True)
    for name, data in files.items():
        (output / name).write_bytes(data)
    (output / "seal-manifest.json").write_text(json.dumps(public_manifest(), indent=2) + "\n")
    return {"full_image_sha256_verified": digest.hexdigest(), "source_bytes_read": count,
            "generated_artifacts": {n: SYSTEM["artifacts"][n] for n in SEAL_NAMES},
            "image_copied": False, "device_accessed": False, "hardware_verified": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--system-image", type=Path, required=True)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    start = time.monotonic()
    try:
        report = prepare(args.system_image, args.out)
        report["seconds"] = time.monotonic() - start
        (args.out / "preparation.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(report, indent=2))
    except (OSError, ValueError) as error:
        parser.exit(2, str(error) + "\n")


if __name__ == "__main__":
    main()
