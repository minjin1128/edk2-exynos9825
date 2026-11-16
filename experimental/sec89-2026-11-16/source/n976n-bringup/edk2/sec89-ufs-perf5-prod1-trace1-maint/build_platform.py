#!/usr/bin/env python3
"""Build the isolated SEC86 standard DXE platform in the local Orb RAM stage.

This exports module/FV evidence, never an Odin or Android boot package.
Both profiles use the N976N DT-gated PhoneSec adapter; QEMU substitutes GIC/UART PCDs.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib.util
import io
import json
import re
import subprocess
import tarfile
import time
import zlib
from pathlib import Path

HERE = Path(__file__).resolve().parent
EDK2 = HERE.parent.parent / "references/edk2"
PIN = "870158586f14dbf9d57e312ea6ea87141a1b0699"
FDT_PIN = "f48b96548e2d8baef79ae2d5a2a2f8de3382260f"
STAGE = "/dev/shm/n976n-edk2-sec89-ufs-perf5-prod1-trace1-maint"
BUILD_MILESTONE = 'SEC89 UFS PERF5 PROD1 TRACE1 MAINT'
PACKAGES = ["BaseTools", "MdePkg", "MdeModulePkg", "ArmPkg", "ArmPlatformPkg",
            "EmbeddedPkg", "UefiCpuPkg", "SecurityPkg", "FatPkg", "CryptoPkg",
            "edksetup.sh", "License.txt"]

# Reuse the established RAM capacity checks and source-streaming helper.
spec = importlib.util.spec_from_file_location("sec63_ram_build_helpers", HERE.parent / "sec41-fix5/build_dxe.py")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)
helper.STAGE = STAGE
media_spec = importlib.util.spec_from_file_location("sec63_boot_media", HERE / "boot_media.py")
media_builder = importlib.util.module_from_spec(media_spec)
media_spec.loader.exec_module(media_builder)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def system_seal(directory: Path) -> tuple[dict, dict]:
    """Use the explicit SEC89 media-data contract; no historical producer import."""
    source = HERE.parent.parent / "references/sec89-ufs-perf5-prod1-trace1/maintenance-media/media_common.py"
    spec = importlib.util.spec_from_file_location("mq1_media_contract", source)
    contract = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(contract)
    expected = contract.RETURN_MEDIA if "RETURN" in BUILD_MILESTONE else contract.MEDIA
    if directory.resolve(strict=True) != expected.resolve(strict=True):
        raise ValueError("Wrong media role for this firmware")
    return contract.firmware_binding(directory, HERE)


def inventory(media: dict | None = None) -> dict:
    if media is None:
        raise ValueError("SEC85 inventory requires the exact candidate media")
    fdf = HERE / "N976nPlatformPkg/N976nPlatformPkg.fdf"
    modules = []
    for inf in re.findall(r"^\s*INF\s+(\S+\.inf)\s*$", fdf.read_text(), re.M):
        path = (HERE if inf.startswith("N976nPlatformPkg/") else EDK2) / inf
        contents = path.read_text()
        def field(name):
            return re.search(r"^\s*" + name + r"\s*=\s*([^\s#]+)", contents, re.M).group(1)
        kind = field("MODULE_TYPE")
        if kind not in ("DXE_CORE", "DXE_DRIVER", "DXE_RUNTIME_DRIVER", "UEFI_DRIVER", "UEFI_APPLICATION"):
            raise ValueError(f"Unexpected module in the sealed DXE FV: {inf}: {kind}")
        modules.append({"name": field("BASE_NAME"), "guid": field("FILE_GUID").lower(),
                        "file_type": 5 if kind == "DXE_CORE" else (9 if kind == "UEFI_APPLICATION" else 7),
                        "subsystem": 12 if kind == "DXE_RUNTIME_DRIVER" else (10 if kind == "UEFI_APPLICATION" else 11),
                        "expected_depex": int(kind in ("DXE_DRIVER", "DXE_RUNTIME_DRIVER")),
                        "inf": inf})
    if not modules or len({m["guid"] for m in modules}) != len(modules):
        raise ValueError("Empty or duplicate source module inventory")
    upstream_disk_io = []
    for name in ("DiskIo.c", "DiskIo.h", "ComponentName.c"):
        local = HERE / "N976nPlatformPkg/Library/PlatformBootManagerLib/UpstreamDiskIo" / name
        upstream = EDK2 / "MdeModulePkg/Universal/Disk/DiskIoDxe" / name
        if local.read_bytes() != upstream.read_bytes():
            raise ValueError("Vendored DiskIo source differs from pinned upstream: " + name)
        upstream_disk_io.append({"local": str(local.relative_to(HERE)),
                                 "upstream": str(upstream.relative_to(EDK2)),
                                 "sha256": digest(local), "bytes": local.stat().st_size})
    upstream_fat = []
    for name in ("Fat.h", "FatFileSystem.h"):
        local = HERE / "N976nPlatformPkg/Library/PlatformBootManagerLib/UpstreamFat" / name
        upstream = EDK2 / "FatPkg/EnhancedFatDxe" / name
        if local.read_bytes() != upstream.read_bytes():
            raise ValueError("Vendored FAT header differs from pinned upstream: " + name)
        upstream_fat.append({"local": str(local.relative_to(HERE)),
                             "upstream": str(upstream.relative_to(EDK2)),
                             "sha256": digest(local), "bytes": local.stat().st_size})
    windows = media["inputs"]["windows"]
    modules.append({"name": "WindowsBootManager", "guid": media_builder.WINDOWS_GUID,
                    "file_type": 9, "subsystem": 10, "expected_depex": 0,
                    "binary": True, "source": windows["path"],
                    "payload_bytes": windows["bytes"], "payload_sha256": windows["sha256"]})
    resource = HERE / "N976nPlatformPkg/Applications/N976nBootTest/BootInfo.txt"
    header = HERE / "N976nPlatformPkg/Include/N976nBootFiles.h"
    expected = re.search(r'^#define N976N_BOOT_INFO_CONTENT (".*")$', header.read_text(), re.M)
    if expected is None or ast.literal_eval(expected.group(1)).encode("ascii") != resource.read_bytes():
        raise ValueError("BootInfo.txt differs from the exact bytes required by the EFI file/application self-test")
    return {"schema": 3, "fv_max_bytes": 0x930000, "image_max_bytes": 0x400000,
            "modules": modules, "vendored_upstream_sources": upstream_disk_io + upstream_fat,
            "resources": [{"name": "BootInfo.txt", "guid": "f904cc73-d2c6-4798-83ac-7cba37c24401",
                           "file_type": 2, "payload_sha256": digest(resource),
                           "payload_bytes": resource.stat().st_size},
                          {"name": "BootMedia.fat", "guid": media_builder.MEDIA_GUID,
                           "file_type": 2, "payload_sha256": media["sha256"],
                           "payload_bytes": media["bytes"]}]}


def stage_generated(files: dict[str, bytes]) -> None:
    """Send generated immutable inputs directly to the existing RAM build stage."""
    archive = io.BytesIO()
    with tarfile.open(fileobj=archive, mode="w") as tar:
        for name, data in files.items():
            info = tarfile.TarInfo("N976nPlatformPkg/" + name)
            info.size = len(data)
            info.mode = 0o644
            info.mtime = 0
            tar.addfile(info, io.BytesIO(data))
    subprocess.run(["orb", "-m", helper.MACHINE, "tar", "-xf", "-", "-C", STAGE],
                   input=archive.getvalue(), check=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=("qemu", "n976n"), required=True)
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--reuse-stage", action="store_true")
    parser.add_argument("--query-sequence", choices=("touch-windows",), required=True)
    parser.add_argument("--system-seal-directory", type=Path, required=True)
    parser.add_argument("--diagnostic-mode", choices=("a",), required=True)
    parser.add_argument("--gop-viewport", choices=("full", "inset160"), default="full")
    args = parser.parse_args()
    gop_inset = {"full": 0, "inset160": 160}[args.gop_viewport]
    diagnostic_mode={"a":1,"b":2,"c":3}[args.diagnostic_mode]
    experiment = 13
    epoch_record = json.loads((HERE / "candidate-build-epoch.json").read_text())
    build_epoch = epoch_record["epoch"]
    if not isinstance(build_epoch, int) or not 1767225600 <= build_epoch < 2147483647:
        raise ValueError("SEC78 current fixed compilation RTC epoch is missing or invalid")
    started = time.monotonic()
    out = args.out.resolve()
    if out.exists():
        raise SystemExit("Choose a new output directory; existing evidence is preserved")
    if helper.run("git", "-C", str(EDK2), "rev-parse", "HEAD", capture=True) != PIN:
        raise SystemExit("EDK2 revision differs from the project pin")
    helper.run("git", "-C", str(EDK2), "diff", "--quiet", "HEAD", "--", *PACKAGES)
    fdt = EDK2 / "MdePkg/Library/BaseFdtLib/libfdt"
    if helper.run("git", "-C", str(fdt), "rev-parse", "HEAD", capture=True) != FDT_PIN:
        raise SystemExit("libfdt differs from the pinned upstream submodule")
    helper.run("git", "-C", str(fdt), "diff", "--quiet", "HEAD", "--", "libfdt")
    sources = {str(p.relative_to(HERE)): digest(p) for p in HERE.rglob("*")
               if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}
    generated, media = media_builder.prepare(HERE.parent.parent, args.system_seal_directory)
    sealed_generated, sealed_binding = system_seal(args.system_seal_directory)
    generated.update(sealed_generated)
    # Native4Kn boot geometry is an independent immutable input. The writable
    # installed volume itself is deliberately not represented as a sealed disk.
    seed_dir = HERE.parent.parent / "references/sec85/image-seed"
    seed_path = seed_dir / "ntfs-seed.json"
    seed = json.loads(seed_path.read_text())
    ntfs_header_path = args.system_seal_directory / "UserdataNtfsManifest.h"
    ntfs_header = ntfs_header_path.read_bytes()
    ntfs_hash = hashlib.sha256(ntfs_header).hexdigest()
    if (not seed.get("passed") or seed.get("milestone") != "SEC85" or
            seed["ntfs"]["sector_bytes"] != 4096 or seed["ntfs"]["cluster_bytes"] != 4096 or
            seed["ntfs"]["hidden_sectors"] != 0x222200 or seed["ntfs"]["image_blocks"] != 0x1000000 or
            seed["ntfs"]["bpb_number_of_sectors"] != 0xFFFFFF or
            seed["ntfs"]["backup_relative_lba"] != 0xFFFFFF or
            ntfs_hash != seed["artifacts"]["UserdataNtfsManifest.h"]["sha256"] or
            ntfs_header != (seed_dir / "UserdataNtfsManifest.h").read_bytes() or
            seed["artifacts"]["ntfs-primary-boot.bin"]["sha256"] != seed["artifacts"]["ntfs-backup-boot.bin"]["sha256"]):
        raise ValueError("SEC85 native NTFS boot/backup geometry or firmware manifest binding differs")
    # Runtime volume identity is the OEM/BPB/extended BPB, not mutable boot code.
    boot_sector = (seed_dir / "ntfs-primary-boot.bin").read_bytes()
    if len(boot_sector) != 4096 or hashlib.sha256(boot_sector).hexdigest() != seed["artifacts"]["ntfs-primary-boot.bin"]["sha256"]:
        raise ValueError("Exact NTFS source BPB binding differs")
    bpb = "STATIC CONST UINT8 mN976nUserdataBpb[77] = {" + ",".join(str(v) for v in boot_sector[3:80]) + "};\n"
    if not ntfs_header.endswith(b"#endif\n"):
        raise ValueError("NTFS manifest include guard differs")
    generated["Include/UserdataNtfsManifest.h"] = ntfs_header[:-7] + bpb.encode("ascii") + b"#endif\n"
    boot_manifest = json.loads((args.system_seal_directory / "seal-manifest.json").read_bytes())
    native_boot = boot_manifest.get("purpose") == "installed Windows boot"
    generated["Include/N976nBootFilePolicy.h"] = ("#define N976N_NATIVE_BOOT_POLICY " + str(int(native_boot)) + "\n").encode("ascii")
    userdata_binding = {"seed_path": str(seed_path), "seed_sha256": digest(seed_path),
                        "manifest_sha256": ntfs_hash, "geometry": seed["ntfs"],
                        "boot_sha256": seed["artifacts"]["ntfs-primary-boot.bin"]["sha256"]}
    mode_header=(HERE/"N976nPlatformPkg/Include/N976nSec78DiagnosticMode.h").read_text()
    if mode_header.count("#define N976N_SEC78_DIAG_MODE 1")!=1:
        raise ValueError("Diagnostic source default must be exact mode A")
    generated["Include/N976nSec78DiagnosticMode.h"]=mode_header.replace(
        "#define N976N_SEC78_DIAG_MODE 1",f"#define N976N_SEC78_DIAG_MODE {diagnostic_mode}").encode("ascii")
    runtime_spec = importlib.util.spec_from_file_location("sec76_runtime_files", HERE / "runtime_files.py")
    runtime = importlib.util.module_from_spec(runtime_spec)
    runtime_spec.loader.exec_module(runtime)
    runtime_header, runtime_binding = runtime.generate(
        Path(sealed_binding["image_path"]), args.system_seal_directory)
    generated["Include/SystemRuntimeFiles.h"] = runtime_header
    sealed_binding["runtime_file_map"] = runtime_binding
    generated["Include/N976nSystemProfile.h"] = (
        "/* Build-selected fixture profile; source-bound in provenance. */\n"
        f"#define N976N_SYSTEM_FIXTURE_QEMU {int(args.profile == 'qemu')}\n").encode("ascii")
    # Bind additional consumer constants without changing the existing FAT builder
    # or the byte-for-byte media object used by preserved component evidence.
    bcd = media["bcd"]
    bcd_bytes = generated["BootMedia/BootMedia.fat"][bcd["file_offset"]:bcd["file_offset"] + bcd["file_bytes"]]
    if (not 8192 <= len(bcd_bytes) <= 65536 or len(bcd_bytes) % 4096 or
            len(bcd_bytes) != media["inputs"]["bcd"]["bytes"] or
            hashlib.sha256(bcd_bytes).hexdigest() != media["inputs"]["bcd"]["sha256"]):
        raise ValueError("SEC85 BCD consumer constants require the exact bounded complete file")
    windows = media["windows_canonical"]
    windows_bytes = generated["BootMedia/BootMedia.fat"][windows["file_offset"]:windows["file_offset"] + windows["file_bytes"]]
    boot_header = (HERE / "N976nPlatformPkg/Include/N976nBootMedia.h").read_text()
    declared_bytes = re.search(r"^#define N976N_BOOT_WINDOWS_BYTES\s+(\d+)ULL$", boot_header, re.M)
    if (declared_bytes is None or not 4096 <= len(windows_bytes) <= media_builder.WINDOWS_MAX_BYTES or
            len(windows_bytes) != media["inputs"]["windows"]["bytes"] or
            windows["path"] != "\\EFI\\Microsoft\\Boot\\bootmgfw.efi" or
            hashlib.sha256(windows_bytes).hexdigest() != media["inputs"]["windows"]["sha256"]):
        raise ValueError("SEC85 Windows stream constants require the exact bounded complete canonical file")
    generated["Include/N976nBootMedia.h"] = re.sub(
        r"^#define N976N_BOOT_WINDOWS_BYTES\s+\d+ULL$",
        f"#define N976N_BOOT_WINDOWS_BYTES {len(windows_bytes)}ULL", boot_header, count=1, flags=re.M).encode("ascii")
    font_macros = ""
    for macro, filename, input_key in (("FONT", "wgl4_boot.ttf", "font"),
            ("SEGOE", "segoe_slboot.ttf", "segoe"), ("SEGMONO", "segmono_boot.ttf", "segmono")):
        entries = [entry for entry in media["resources"] if entry["path"].endswith("\\" + filename)]
        if len(entries) != 1:
            raise ValueError("Missing/duplicate runtime font extent: " + filename)
        entry = entries[0]
        resource = generated["BootMedia/BootMedia.fat"][entry["file_offset"]:entry["file_offset"] + entry["file_bytes"]]
        if (len(resource) != media["inputs"][input_key]["bytes"] or
                hashlib.sha256(resource).hexdigest() != media["inputs"][input_key]["sha256"]):
            raise ValueError("Runtime font extent differs from pinned resource: " + filename)
        font_macros += f"#define N976N_BOOT_{macro}_OFFSET  0x{entry['file_offset']:X}U\n"
        font_macros += f"#define N976N_BOOT_{macro}_BYTES  0x{entry['file_bytes']:X}U\n"
    manifest_key = "Include/N976nBootMediaManifest.h"
    generated[manifest_key] = generated[manifest_key].replace(b"#endif\n", (
        f"#define N976N_BOOT_BCD_OFFSET  0x{bcd['file_offset']:X}U\n"
        f"#define N976N_BOOT_BCD_BYTES  0x{len(bcd_bytes):X}U\n"
        f"#define N976N_BOOT_BCD_CRC32  0x{zlib.crc32(bcd_bytes):08X}U\n"
        f"#define N976N_BOOT_WINDOWS_OFFSET  0x{windows['file_offset']:X}U\n"
        + font_macros + "#endif\n").encode())
    selected = inventory(media)
    ram_before = helper.check_ram_stage(require_free=True)
    out.mkdir(parents=True)
    phases = {}
    try:
        phase_start = time.monotonic()
        if args.reuse_stage:
            if helper.orb("cat", STAGE + "/edk2-revision", capture=True) != PIN:
                raise RuntimeError("The RAM stage has a different EDK2 revision")
        else:
            helper.orb("python3", "-c", "from pathlib import Path; import shutil; "
                       f"p=Path({STAGE!r}); shutil.rmtree(p,ignore_errors=True); (p/'edk2').mkdir(parents=True)")
            helper.stream_tree(EDK2, STAGE + "/edk2", PACKAGES)
            helper.orb("python3", "-c", f"from pathlib import Path; Path({(STAGE + '/edk2-revision')!r}).write_text({PIN!r})")
        brotli = EDK2 / "BaseTools/Source/C/BrotliCompress/brotli"
        brotli_stage = STAGE + "/edk2/MdeModulePkg/Library/BrotliCustomDecompressLib/brotli"
        helper.orb("mkdir", "-p", brotli_stage)
        helper.stream_tree(brotli, brotli_stage, ["c"])
        helper.orb("python3", "-c", "from pathlib import Path; import shutil; "
                   f"p=Path({STAGE!r}); shutil.rmtree(p/'N976nPlatformPkg',ignore_errors=True); "
                   "shutil.rmtree(p/'edk2/Build/N976nPlatform/DEBUG_CLANGPDB/AARCH64/N976nPlatformPkg',ignore_errors=True)")
        helper.stream_tree(HERE, STAGE, ["N976nPlatformPkg"])
        stage_generated(generated)
        # Restore this one upstream file on incremental builds, then apply the
        # explicit preserved NX overlay. The reference checkout is untouched.
        helper.stream_tree(EDK2, STAGE + "/edk2", ["MdeModulePkg/Core/Dxe/Misc/MemoryProtection.c"])
        overlay = HERE / "patches/code_allocation_nx.py"
        helper.orb("python3", "-c", overlay.read_text(), STAGE + "/edk2")
        phases["stage_seconds"] = time.monotonic() - phase_start
        script = f'''#!/bin/bash
set -euo pipefail
cd {STAGE}/edk2
export PYTHON_COMMAND=python3 CLANG_BIN=/usr/bin/ CLANGPDB_DLL=/usr/bin/
export WORKSPACE=$PWD PACKAGES_PATH=$PWD:{STAGE}
export TMPDIR={STAGE}/tmp SOURCE_DATE_EPOCH={build_epoch} PYTHONHASHSEED=0 LC_ALL=C
mkdir -p "$TMPDIR" Conf
set +u
source edksetup.sh BaseTools
set -u
if [ ! -x BaseTools/Source/C/bin/GenFv ]; then make -C BaseTools/Source/C -j8; fi
build -a AARCH64 -t CLANGPDB -b DEBUG -p N976nPlatformPkg/N976nPlatformPkg.dsc -n 8 -D N976N_QEMU={int(args.profile == 'qemu')} -D N976N_UFS_QUERY_EXPERIMENT={experiment} -D N976N_GOP_Y_INSET={gop_inset}
'''
        helper.orb("python3", "-c", f"from pathlib import Path; Path({(STAGE + '/build.sh')!r}).write_text({script!r})")
        phase_start = time.monotonic()
        with (out / "build.log").open("w") as log:
            result = subprocess.run(["orb", "-m", helper.MACHINE, "bash", STAGE + "/build.sh"], stdout=log, stderr=subprocess.STDOUT)
        phases["build_seconds"] = time.monotonic() - phase_start
        if result.returncode:
            print((out / "build.log").read_text()[-5000:])
            raise RuntimeError(f"Build failed ({result.returncode}); log preserved at {out}")
        if sources != {str(p.relative_to(HERE)): digest(p) for p in HERE.rglob("*")
                       if p.is_file() and "__pycache__" not in p.parts and p.suffix != ".pyc"}:
            raise RuntimeError("SEC78 sources changed during the build")
        if system_seal(args.system_seal_directory)[1] != {
                key: value for key, value in sealed_binding.items()
                if key != "runtime_file_map"}:
            raise RuntimeError("SEC78 seal inputs changed during the build")
        phase_start = time.monotonic()
        # Upstream output directory is fixed by the platform DSC.
        build_root = STAGE + "/edk2/Build/N976nPlatform/DEBUG_CLANGPDB"
        names = [m["name"] for m in selected["modules"] if not m.get("binary")] + ["N976nPhoneSec"]
        listing = json.loads(helper.orb("python3", "-c",
            "import json,pathlib,sys; p=pathlib.Path(sys.argv[1]); names=json.loads(sys.argv[2]); result={}; "
            "\nfor n in names:\n for suffix in ('.efi','.map'):\n  rows=list(p.rglob(n+suffix)); "
            "rows.sort(key=lambda q:(len(q.parts),str(q))); "
            "result[n+suffix]=str(rows[0]) if rows else None\n"
            "print(json.dumps(result))", build_root + "/AARCH64", json.dumps(names), capture=True))
        listing["DXE.Fv"] = build_root + "/FV/DXE.Fv"
        for name, source in listing.items():
            if source is None:
                raise RuntimeError(f"Missing compiled artifact: {name}")
            with (out / name).open("wb") as dst:
                subprocess.run(["orb", "-m", helper.MACHINE, "cat", source], stdout=dst, check=True)
        # Binary/resource exports are the exact in-memory inputs staged above;
        # FV inspection independently compares their encapsulated bytes.
        for relative, data in generated.items():
            name = Path(relative).name
            (out / name).write_bytes(data)
            listing[name] = "generated-input:" + relative
        (out / "boot-media.json").write_text(json.dumps(media, indent=2) + "\n")
        (out / "inventory.json").write_text(json.dumps(selected, indent=2) + "\n")
        phases["export_seconds"] = time.monotonic() - phase_start
        (out / "provenance.json").write_text(json.dumps({
            "milestone": BUILD_MILESTONE,
            "libfdt_commit": FDT_PIN,
            "gop_viewport": {"name": args.gop_viewport, "y_inset": gop_inset,
                "physical_base": 0xCA000000, "physical_bytes": 0x10B3000, "pitch_bytes": 5760,
                "view_base": 0xCA000000 + gop_inset * 5760, "width": 1440, "height": 3040 - 2 * gop_inset,
                "view_bytes": (3040 - 2 * gop_inset) * 5760}, "diagnostic_mode": diagnostic_mode, "profile": args.profile, "edk2_commit": PIN,
            "query_sequence": args.query_sequence, "ufs_experiment": experiment,
            "sources_sha256": sources, "artifacts_sha256": {name: digest(out/name) for name in listing},
            "boot_media": media,
            "compilation_rtc_epoch": epoch_record,
            "system_seal": sealed_binding,
            "userdata_boot": userdata_binding,
            "ram_stage": helper.check_ram_stage(), "ram_before": ram_before,
            "hardware_flashable": False, "hardware_verified": False,
            "scope": 'MQ1 maintenance: exact selected media, PROD1 runtime 88KiB/v2 UFS, UART kernel debugging and touch; MQ1 offline payload only; no device execution or final qualification.'

        }, indent=2) + "\n")
    finally:
        phases["total_seconds"] = time.monotonic() - started
        (out / "timing.json").write_text(json.dumps(phases, indent=2) + "\n")
    print(json.dumps({"out": str(out), "profile": args.profile, "timing": phases}))


if __name__ == "__main__":
    main()
