# SPDX-License-Identifier: MIT
"""Pinned SEC68 input admission without private research-report dependencies.

The firmware's expected bytes and all runtime checks remain unchanged. This
adapter accepts the original seal bundle or a newly checked public manifest.
It does not accept arbitrary Windows media or manufacture hardware evidence.
"""
import hashlib
import json
from pathlib import Path
import re
import stat

ROOT = Path(__file__).resolve().parents[1]
CONTRACT_PATH = ROOT / "config/reference-inputs.json"
CONTRACT = json.loads(CONTRACT_PATH.read_text())
SYSTEM = CONTRACT["system"]
SEAL_NAMES = ("SystemVolumeSeal.h", "SystemVolumeSealData.inc", "system-block-sha256.bin")


def regular(path, expected_bytes=None):
    path = Path(path)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode):
        raise ValueError(f"Regular non-symlink input required: {path.name}")
    if expected_bytes is not None and info.st_size != expected_bytes:
        raise ValueError(f"Input length differs: {path.name}")
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def read_pinned(path, entry):
    before = regular(path, entry["bytes"])
    data = Path(path).read_bytes()
    if hashlib.sha256(data).hexdigest() != entry["sha256"]:
        raise ValueError(f"Pinned input digest differs: {Path(path).name}")
    if regular(path, entry["bytes"]) != before:
        raise ValueError("Input changed while being read")
    return data


def public_manifest():
    return {
        "schema": 1, "format": "n976n-public-seal-v1",
        "source_image": {"bytes": SYSTEM["image_bytes"], "sha256": SYSTEM["image_sha256"]},
        "seal": SYSTEM["seal"], "physical_gpt": SYSTEM["physical_gpt"],
        "files": SYSTEM["full_files"],
        "artifacts": {name: SYSTEM["artifacts"][name] for name in SEAL_NAMES},
    }


def validate_manifest(raw):
    if len(raw) > 65536:
        raise ValueError("Seal manifest is not bounded metadata")
    manifest = json.loads(raw)
    retained = hashlib.sha256(raw).hexdigest() == SYSTEM["seal_manifest_sha256"]
    if not retained and manifest != public_manifest():
        raise ValueError("Unrecognized seal manifest or modified input contract")
    if manifest["seal"] != SYSTEM["seal"]:
        raise ValueError("Seal geometry/identity differs")
    for name in SEAL_NAMES:
        if manifest["artifacts"][name] != SYSTEM["artifacts"][name]:
            raise ValueError("Seal artifact declaration differs")
    for name, entry in SYSTEM["full_files"].items():
        if manifest["files"][name] != entry:
            raise ValueError("SDI/WIM identity differs")
    if retained:
        original = manifest["physical_gpt"]
        expected = dict(SYSTEM["physical_gpt"], unique_guid=SYSTEM["historical_manifest_unique_guid"])
        if {k: original[k] for k in expected} != expected:
            raise ValueError("Retained manifest physical identity differs")
    return manifest, retained


def system_seal(directory):
    directory = Path(directory).resolve(strict=True)
    path = directory / "seal-manifest.json"
    regular(path)
    if path.stat().st_size > 65536:
        raise ValueError("Seal manifest size")
    raw = path.read_bytes()
    _, retained = validate_manifest(raw)
    data = {name: read_pinned(directory / name, SYSTEM["artifacts"][name]) for name in SEAL_NAMES}
    table = data["system-block-sha256.bin"]
    literal = bytes(int(n, 16) for n in re.findall(r"0x([0-9A-Fa-f]{2})(?![0-9A-Fa-f])", data["SystemVolumeSealData.inc"].decode("ascii")))
    if literal != table or len(table) != SYSTEM["seal"]["table_bytes"]:
        raise ValueError("Compiled seal array differs from ordered binary table")
    generated = {"Include/" + name: data[name] for name in SEAL_NAMES[:2]}
    header = ["/* SEC68: derived from preserved SEC61 complete-file SHA256 readback. */",
              "#ifndef N976N_SYSTEM_FULL_FILES_H", "#define N976N_SYSTEM_FULL_FILES_H"]
    for path, macro, symbol in (("boot/boot.sdi", "SDI", "Sdi"), ("sources/boot.wim", "WIM", "Wim")):
        entry = SYSTEM["full_files"][path]
        header += [f"#define N976N_SYSTEM_FULL_{macro}_BYTES {entry['bytes']}ULL",
                   f"STATIC CONST UINT8 mN976nSystem{symbol}Sha256[32] = {{" +
                   ",".join(f"0x{byte:02X}" for byte in bytes.fromhex(entry["sha256"])) + "};"]
    header += ["#endif", ""]
    generated["Include/SystemFullFiles.h"] = "\n".join(header).encode("ascii")
    binding = {
        "manifest_sha256": hashlib.sha256(raw).hexdigest(),
        "manifest_kind": "retained-reference" if retained else "public-preparation",
        "seal": SYSTEM["seal"], "artifacts": {n: SYSTEM["artifacts"][n] for n in SEAL_NAMES},
        "physical_gpt": SYSTEM["physical_gpt"], "full_files": SYSTEM["full_files"],
        "bulk_media_read_or_copied": False,
        "hardware_verified": False,
    }
    return generated, binding
