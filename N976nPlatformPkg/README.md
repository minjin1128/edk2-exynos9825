# N976N platform package

This is the SEC68 runtime source snapshot used for the original physical WinPE
GUI entry. It includes PhoneSec/HOB setup, GOP, standard DXE/BDS integration,
guarded read-only SYSTEM supply, high-RAM ownership and ACPI/OS handoff policy.

Build using the root tools and [build instructions](../docs/BUILDING.md).
See [architecture](../docs/ARCHITECTURE.md) for the memory/image/DMA boundaries
and the intentional relationship between the image policy and NX overlay.
Historical identifiers in otherwise unchanged source are retained for comparison.
