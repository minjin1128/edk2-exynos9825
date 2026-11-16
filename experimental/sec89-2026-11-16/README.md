# SEC89 development sources — 2026-11-16

This is a selected **source-only snapshot** of the later SM-N976N / Exynos 9825
project. Technical status is recorded through **2026-11-14**. The supported root
build remains the separate [SEC68 snapshot](../../README.md). These sources are
not integrated into that build, and a fresh standalone SEC89 build/test graph
has not been exported or verified.

## What is included

Original relative paths are retained below `source/`. The [manifest](manifest.json)
records every included file's origin, byte identity, role and raw license marker,
plus omissions. Selected source bytes were copied unchanged.

| Source location under `source/n976n-bringup/` | Role / recorded status |
| --- | --- |
| `edk2/sec89-boot-perf1/N976nPlatformPkg/` | Preserved Full Windows return firmware; a different role from maintenance PE |
| `edk2/sec89-ufs-perf5-prod1-trace1-maint/N976nPlatformPkg/` | Latest TRACE1 maintenance platform source; host-prepared candidate |
| `windows/sec89-ufs-perf5-prod1/` | PROD1 UFS 0.89.2.5, the latest user-reported device baseline |
| `windows/sec88-touch-clockshare1/` | Touch source used by later development; sustained reliability remains open |
| `windows/sec89-charge-control3-fix1/` and `...-viewer/` | Battery 0.606 and viewer; intermittent recurrence remains unresolved |
| `windows/sec89-ufs-perf5-prod1-trace1/` | Instrumented UFS 0.89.2.6, host-prepared and not physically applied |
| `windows/sec89-ufs-perf5-prod1-trace1-reader/` and `...-maint/` | Auxiliary query and maintenance-installer source |
| `common/` selected files | Direct battery/charging/thermal/ADC source dependencies |
| `references/sec89-ufs-perf5-prod1-trace1/kd/` | RAM snapshot decoder and its test source; no captured device logs |

Selected original producer/helper and RAM-wrapper sources are included for
inspection. Their historical path imports are preserved; they are not a complete
public build recipe. No SYS/EXE/PDB/CAT, signing key, WIM/ISO/BCD/font, boot/disk
image, maintenance package, device dump, photo or raw debugger log is included.

## Recorded state, with evidence limits

As of the last 2026-11-14 report, the device had been rolled back to **PROD1
0.89.2.5** and the user reported normal touch/battery behavior with UART/WinDbg
detached. This publication does not establish a fresh device observation.
**TRACE1 0.89.2.6** has host/ARM64/fixture/package validation in the development
project; physical installation, trace overhead, performance and durability have
not been confirmed. The MQ1/FIX1 concurrent-I/O experiment remains on hold after
a reported regression. It is not selected as this snapshot's operating baseline.
See [progress and reported measurements](../../docs/PROGRESS.md) and
[measurement boundaries](../../docs/UFS_MEASUREMENT_NOTES.md).

## Dependencies and omitted inputs

- Recorded build references are EDK2 `870158586f14dbf9d57e312ea6ea87141a1b0699`
  and libfdt `f48b96548e2d8baef79ae2d5a2a2f8de3382260f`. They are external
  dependencies, not a complete description of the historical helper graph.
- Native Windows builds require an external ARM64 SDK/WDK/MSVC environment.
  Source compilation and fresh test signing do not reproduce the bytes of a
  previously signed binary.
- `N976nUfsNtfsExpected.h` contains a Windows NTFS boot-sector array and
  `tests/system_fat_boot.h` contains a generated FAT boot-sector array. Both
  are deliberately omitted from each UFS tree. They are external/generated
  input dependencies; missing files must not be replaced with dummy values or
  used as a reason to remove identity/integrity checks.
- Private device/Windows inputs, media seals and historical build receipts are
  not provided. Original README/provenance files with inherited versions or
  local paths are omitted; this README and manifest describe the publication.
- Battery and touch tests have additional historical fixtures/imports outside
  the selected direct product dependencies. Analyzer tests also expect three
  generated fake-DDI trace fixtures; their bytes are not shipped. The original
  trace fixture generator source is present, but the full generation/test graph
  has not been reconstructed. No new tests were run for publication.

## Keep the two firmware roles distinct

The preserved Full Windows return used BOOT PERF1 plus UART1 SYSTEM and an
SEC86-return compile seal. Its producer references still include SEC85-era
contracts. **SEC85 is obsolete for new development**; this source archive does
not execute that producer or establish an SEC85-independent return build.
The newer maintenance producer uses an independent `media_common` path and an
improved PROD1 UFS runtime with UART kernel debugging. Its bootstrap, BCD,
firmware handoff, DMA/ACPI and integrity bindings must stay matched.

The PROD1/TRACE1 path uses the existing **88KiB lease v2**. The separate 352KiB
MQ1 return must not be mixed into it. This source publication supplies no new
flashing or installation package.

## Publication checks and licenses

Checks cover source-byte equivalence, explicit selection, known credential
patterns, omitted embedded-input headers, license-carrier preservation and local
document links. They do not constitute a firmware build, hardware test or final
qualification. Historical host, emulation and physical results are separate.

[Original license context](LICENSES.md) applies. This tree contains GPL, BSD,
MIT and Mbed TLS notices; it is **not blanket-relicensed under the root MIT
license**. Original source comments and accompanying license files are retained.
