# Building the source snapshot

## Supported workflow

The tested host workflow is **macOS + an existing OrbStack Ubuntu machine**.
The default machine name is `ubuntu-amd64`; use `--machine NAME` for an existing
equivalent machine. The tools do not install software or modify VM settings.
Native Linux firmware building has not been validated by this extraction.

Required on the Mac: Python 3, Clang with the AArch64 bare-metal target, Git and
OrbStack's `orb` command. Required in Ubuntu: Python 3, GCC/G++, make, Clang,
LLVM/lld and uuid development headers. QEMU is not needed for the build/static
checks described here. A new build needs 4GiB of checked free guest tmpfs
headroom and sufficient host RAM for the managed scratch launcher.

Run the Python tools with assertions enabled, without `-O` or `PYTHONOPTIMIZE`;
the preserved static format verifiers use assertions for refusal conditions.

```sh
git clone https://github.com/minjin1128/edk2-exynos9825.git
cd edk2-exynos9825
git submodule update --init external/edk2
git -C external/edk2 submodule update --init \
  BaseTools/Source/C/BrotliCompress/brotli \
  MdePkg/Library/MipiSysTLib/mipisyst
```

The build checks the pinned EDK2 revision and requires unchanged upstream
sources. Do not update the submodule to the latest branch for this snapshot.

## External inputs

No Windows media is downloaded or supplied. Provide the five exact files
listed in [reference-inputs.json](../config/reference-inputs.json) in a private
directory, for example `.inputs/boot/`:

```text
bootaa64.efi
BCD
wgl4_boot.ttf
segoe_slboot.ttf
segmono_boot.ttf
```

Also provide the **exact preserved 1GiB FAT image** identified in that contract.
It contains the boot files, `boot/boot.sdi` and `sources/boot.wim`. A newly
formatted FAT containing the same files is not necessarily byte-identical.
Different Windows images require a separate porting/validation change: image
identities, file layout, sizes, read budgets and other firmware constants are
not generic configuration switches.

Generate authentication inputs from that regular host file once:

```sh
python3 tools/prepare_seal.py \
  --system-image /absolute/private/reference-fat.img \
  --out .inputs/seal
```

This streams the complete 1GiB image once, verifies its pinned SHA256, and
generates the exact ordered 128KiB chunk table and C headers. It copies no
volume and contacts no device. The output directory must be new. A mismatched
image is rejected without creating accepted outputs.

An unchanged original seal bundle is also accepted: `seal-manifest.json`,
`SystemVolumeSeal.h`, `SystemVolumeSealData.inc`, `system-block-sha256.bin`.
No old host paths, photos, qualification logs or private source tree are needed.
The adapter pins the original manifest identity, applies the independently
confirmed SYSTEM GUID, and validates the artifacts. It never rewrites the old
manifest or treats it as new hardware proof.

Each build rechecks the small inputs and authenticates the required FAT
metadata chunks. It does **not** repeat the full 1GiB hash or full WIM replay.
The running firmware continues authenticating each admitted media chunk.

## Build and static checks

```sh
python3 tools/ram_scratch.py --size-mib 1024 \
  --report build/phone-ram.json -- \
  python3 -B tools/build.py --profile n976n \
  --inputs .inputs/boot \
  --system-image /absolute/private/reference-fat.img \
  --seal-directory .inputs/seal \
  --out build/phone
```

Use a new report/output path for another build. For the QEMU profile, select
`--profile qemu` and separate output paths. That profile substitutes virtual
GIC/UART settings; building it does not execute QEMU or prove phone behavior.

Every platform build creates a unique `n976n-public-*` directory in the
guest's verified `/dev/shm` tmpfs and cleans only that owned directory. It never
uses a private development stage or writes the upstream checkout. The copied
RAM launcher keeps bulk temporary host I/O in verified RAM storage, with
capacity/memory/swap guards. Persistent outputs are intentionally written to
`build/`; sampled guards are not a promise of zero SSD writes.

Outputs include module EFI files/maps, `DXE.Fv`, source/input provenance,
`entry/Image`, ELF audit and `fv-check.json`. The FV checker validates the
source inventory and 30 deliberately corrupted formats. These are build/static
results; inspect [validation scope](VALIDATION.md) before using them as evidence.

## Optional offline Android container

`tools/pack_boot.py` retains the Android v1/2048-byte-page/55MiB/AVB-NONE
template parser, hash regeneration, preserved-ramdisk checks and readback.
It additionally requires the exact supported private LineageOS template.
It does not support arbitrary stock boot images or add signed AVB trust.

```sh
python3 tools/pack_boot.py build/phone/entry/Image \
  --template /absolute/private/original-lineage-boot.img \
  --output build/phone/boot-development.img
```

This creates a **local, hardware-unvalidated** image, never an automatic flash
or qualified release. Its ramdisk/header metadata come from the user's private
template. No Odin/SYSTEM deployment or partition-modification tool is included.

## Host tests

```sh
python3 tools/ram_scratch.py --size-mib 1024 \
  --report build/input-tests-ram.json -- \
  python3 -B -m unittest discover -s tests -v
```

These tests need no private media. They cover input identity, changed GUID/
geometry/file declarations, bounds, symlinks, the independent reference header
digest and invalid executable refusal. They do not execute firmware.
