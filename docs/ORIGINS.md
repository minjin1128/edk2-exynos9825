# Origins and attribution

This is a fresh, selected source publication of the SEC68 N976N platform. The
original candidate reached a physical WinPE GUI on 2026-10-20. Its private Git
history, personal conversations, build archives and raw hardware photographs
are not part of this repository. No historical commits have been reconstructed.

| Reference | Pinned revision / role |
| --- | --- |
| [TianoCore EDK2](https://github.com/tianocore/edk2) | `870158586f14dbf9d57e312ea6ea87141a1b0699`; actual build source |
| EDK2 Brotli | `e230f474b87134e8c6c85b630084c612057f253e` |
| EDK2 MipiSysT | `370b5944c046bab043dd8b133727b2135af7747a` |
| [NTDEV Exynos 9810](https://github.com/ntdevlabs/exynos9810-woa) | `6e2cacf15f6b99b198ed12ad242da69eb2259bac`; primary platform/reference structure |
| [Mu-Silicium](https://github.com/Project-Silicium/Mu-Silicium) | `3ec9169f308c01030a7e698072aca5acb2c0a144`; Samsung platform/SEC structure reference |
| [ilyatbn Exynos fork](https://github.com/ilyatbn/exynos-woa) | `13481b4a0b2a92e9efdb56348d7a08ecee495bf8`; comparison reference, distinct from NTDEV |

The comparison references are not build dependencies. N976N facts also came
from the actual runtime DT, Samsung open-source platform code and physical
experiments. No complete Samsung source tree or proprietary firmware is copied
into this publication.

## What changed during extraction

Runtime C/assembly/header/INF/DSC/FDF source bytes, the NX overlay and pure
PE/ELF/FV readers are preserved. Package overview documentation is refreshed.
Host tools use the public layout, explicit input paths and a unique RAM stage.
The old receipt graph is represented by immutable pinned input identities and
a validated local seal adapter. Android packaging requires an explicit template.
These changes have new build provenance and do not inherit hardware validation.

The file map records original relative source names for traceability, not a
dependency on those directories. Older numbers inside unchanged source strings
do not require restoring the old milestone archive.

## Licenses

Original project code, new host adapters and documentation use MIT as stated in
[LICENSE](../LICENSE). Existing notices take precedence for third-party files:

- `UpstreamDiskIo` and `UpstreamFat` retain EDK2 BSD-2-Clause-Patent notices.
- `UpstreamSha256` retains the Mbed TLS `Apache-2.0 OR GPL-2.0-or-later`
  expressions and the complete accompanying license file.
- Pinned EDK2 and its submodules retain their own full notices and licenses.
- NTDEV's reference license/notice is retained under `LICENSES/`. That reference
  notice covers its own wider project; it does not assert that its drivers or
  binary packages are bundled here.

See [NOTICE](../NOTICE). No blanket relicensing of third-party code occurs.
Windows media, boot fonts, BCD, FAT images and Samsung/Lineage boot inputs must
be provided and handled separately under their applicable terms.
