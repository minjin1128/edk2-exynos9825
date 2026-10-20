# Validation scope

This source publication separates **the original hardware result** from
**the new public extraction's host checks**. Machine-readable scope is in
[validation.json](validation.json).

## Original physical checkpoint

On 2026-10-20, the original SEC68 final phone platform/wrapper dev2 candidate
(deployment label `n976n-sec68-dev1`) reached the SM-N976N's Windows PE desktop.
The user reported the progress ring, cmd/PE initialization and boot success;
the retained phone photograph shows wallpaper, desktop icons and taskbar/tray.
This establishes physical kernel execution and PE user-mode/GUI entry without
claiming an instrumented kernel-entry PC or exact handoff fields.

Usable input, desktop responsiveness, startup duration and long-term stability
were not measured. A subsequent apparent off event was not distinguished from
display-off; its cause is unknown. The old synchronous diagnostic shutdown
loop is not a timer running behind Windows after successful ExitBootServices.
The original photograph and raw research evidence remain private.

## Public extraction checks, 2026-10-20

- **Source comparison:** 98 package files, excluding the refreshed overview,
  and four entry source files match the original bytes. Twelve extracted pure
  helper functions match the original ASTs. The NX overlay is preserved.
- **Host input tests:** eight test methods pass, including changed identity/
  geometry refusal, wrong digests, symlinks, bounds, an independent reference
  header digest and invalid executable refusal.
- **Phone profile:** full EDK2 build, entry PE/ELF audit, normal FV admission
  and 30 format-corruption refusal cases pass; approximately 110.206 seconds
  for this build/static-check invocation.
- **QEMU profile:** the corresponding build/static checks and 30 corruption
  cases pass; approximately 127.248 seconds. **QEMU was not executed.**
- **Public input preparation:** one bounded-buffer pass over the exact 1GiB
  reference FAT verified its whole-image hash and regenerated all three seal
  artifacts with the pinned identities. The volume was not copied or changed.
  A normal build does not repeat this full pass.
- **Offline Android packaging:** the new phone Image was packed with the
  exact private template, then its Android/AVB hashes and preserved ramdisk
  were checked by the retained parser. This was not a flash or device test.
- **Temporary I/O:** all six managed RAM runs completed cleanup, as did both
  unique public Orb tmpfs stages. Raw host paths/logs and generated binaries
  remain excluded from Git.

One profile used the original pinned seal manifest; the other used the new
public format with identical artifact bytes. Neither public build required
old SEC source directories, historical qualification receipts or photo paths.
External private media remained explicit inputs, not repository contents.

The public firmware has **not been flashed or booted on hardware**. There was
no new Windows replay, comprehensive historical regression, whole-bank cell
test, arbitrary-media validation or native Linux build test. These host checks
do not promote the snapshot to a final qualified release.

Generated full logs/provenance and local test artifacts are under ignored
`build/`. They are not a public binary release or a backup of the original
research archive. Public checkout/link/content checks are publication checks,
not additional firmware execution evidence.

## Standalone checkout check

A fresh local clone of the initial public source commit loaded all seven
command-line tools and their imports, with the expected pinned EDK2 gitlink.
It contained no private inputs, build outputs or old milestone directories.
[Checkout result](checkout-smoke.json). This verifies source packaging and CLI
dependency closure; it did not initialize or rebuild EDK2 again, execute QEMU
or boot a phone.
