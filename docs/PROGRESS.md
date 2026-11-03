# Research progress — 2026-11-04

This repository publishes the selected **SEC68** source snapshot and its
documented build tools. Its input identities, EDK2 pin, runtime source and
validation records have not been replaced by later experimental code.

## Physical observations in later development

In the separate development project, later SEC88-family candidates have reached
a **Full Windows desktop**, enumerated **four Cortex-A55 CPUs**, and produced
working touch responses on the SM-N976N. The native UFS PERF1 driver was also
loaded on the device and followed by desktop entry. These observations come
from physical-device debugger records and user reports; they are not results
from executing this repository's public rebuild.

Touch can still stop intermittently. Storage latency and performance are under
investigation, and sustained input, power/display behavior and long-term
multicore stability remain open. Desktop entry and CPU enumeration do not
establish a qualified release or SystemReady compliance.

## Relation to the public source

- The original SEC68 development candidate reached a physical **WinPE desktop
  on 2026-10-20**. The public extraction's separate build/static-check coverage
  and hardware limits remain in [VALIDATION.md](VALIDATION.md).
- The public snapshot still uses the documented read-only firmware storage
  path, admitted memory banks and BSP-only ACPI CPU publication. It does not
  contain the later native Windows storage/touch drivers or SMP firmware.
- Reproducing later Full Windows observations requires additional source,
  inputs and deployment contracts. The SEC68 build instructions and manifests
  must not be interpreted as instructions for that later environment.
- Later source extraction will need its own provenance, dependencies, license
  review and validation scope before publication. This note is a status update,
  not a claim that such an extraction has been completed.

Microsoft/Samsung binary inputs, signing keys, disk images, maintenance or
recovery packages, and raw hardware logs/photos are not distributed here.
This update performs no new firmware build, emulation or device experiment.
