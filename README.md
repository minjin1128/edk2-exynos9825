# EDK2 for Exynos 9825 — SM-N976N

Experimental ARM64 UEFI firmware for the **Samsung Galaxy Note10+ 5G, SM-N976N
(Exynos 9825)**. The original SEC68 development candidate reached a **physical
Windows PE desktop on 2026-10-20**.

This repository contains one selected source snapshot, its build tools and
design documentation. It has a fresh Git history and does not contain the
private research archive. The firmware sources retain their original checks;
the host tools have been separated from historical build paths and reports.

## Status

The table describes the published **SEC68** snapshot. Later research has reached
a Full Windows desktop with four CPUs and touch responses, with intermittent
input stalls and storage performance work still open. Those later sources and
their private deployment environment are not included here; see the dated
[research progress note](docs/PROGRESS.md) for the observation limits.

| Area | Scope |
| --- | --- |
| UEFI / display | EDK2 DXE/BDS, inherited framebuffer GOP and console |
| Storage | Bounded, authenticated **read-only** UFS/SYSTEM FAT access before OS handoff |
| RAM | Existing low heap/private DMA and one admitted 2GiB high bank; not all device RAM |
| ACPI | N976N-specific MADT/GTDT, BSP-only CPU publication |
| Windows PE | Original SEC68 candidate: physical user-mode and desktop entry confirmed |
| Input / reliability | Usable touch/input, desktop responsiveness and long-term stability unverified |
| Public rebuild | Build/static-check status is recorded separately in [validation](docs/VALIDATION.md) |

UEFI storage access is **not a Windows storage driver**. This is not a complete
Windows installation, a universal Exynos port or a SystemReady compliance claim.
The later touch diagnostic is not included in this SEC68 snapshot.

## Build

Start with [BUILDING.md](docs/BUILDING.md). The current build path is macOS with
an existing OrbStack Ubuntu machine, using isolated RAM scratch/staging. The
upstream EDK2 revision is pinned. There is no automatic dependency installation,
phone access or flashing.

**Windows binaries, fonts, BCD, the reference SYSTEM FAT and Android boot
template are not redistributed.** This first snapshot supports the exact
reference input identities in [reference-inputs.json](config/reference-inputs.json),
not arbitrary ISO/WIM files. The public seal preparer can independently validate
an already available exact FAT and generate its authentication inputs locally;
private experiment receipts are not required.

## Source map

| Path | Purpose |
| --- | --- |
| [N976nPlatformPkg](N976nPlatformPkg/) | SEC adapter, GOP, boot policy, memory, UFS/FAT and ACPI integration |
| [entry](entry/) | Android ARM64 Image entry, offline-mapped SEC PE and audited ELF wrapper |
| [tools](tools/) | Pinned-input admission, isolated build, PE/ELF/FV checks and offline boot packaging |
| [patches](patches/) | Exact-hash-guarded upstream overlay preserving non-executable code staging |
| [tests](tests/) | Public input-contract and refusal-path tests |
| [ARCHITECTURE.md](docs/ARCHITECTURE.md) | Execution flow, trust boundaries and reference structure |

## Origins and licenses

The primary platform reference is [NTDEV's Exynos 9810 port](https://github.com/ntdevlabs/exynos9810-woa/tree/6e2cacf15f6b99b198ed12ad242da69eb2259bac),
with upstream [EDK2](https://github.com/tianocore/edk2/tree/870158586f14dbf9d57e312ea6ea87141a1b0699)
and Mu-Silicium structure informing the N976N adaptation. Reference hardware
behavior is not N976N hardware evidence.

Original project code and documentation use [MIT](LICENSE). Files with other
SPDX/copyright notices retain those licenses, including BSD-2-Clause-Patent
EDK2 code and dual-licensed Mbed TLS. See [NOTICE](NOTICE) and
[ORIGINS.md](docs/ORIGINS.md). No Microsoft or Samsung binary license is granted.
