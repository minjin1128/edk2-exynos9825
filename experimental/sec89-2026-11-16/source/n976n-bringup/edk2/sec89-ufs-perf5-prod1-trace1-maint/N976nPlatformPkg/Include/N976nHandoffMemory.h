/* SPDX-License-Identifier: MIT */
#ifndef N976N_HANDOFF_MEMORY_H_
#define N976N_HANDOFF_MEMORY_H_
#include <Uefi.h>

#define N976N_HANDOFF_MEMORY_MAGIC 0x38364D454D464F48ULL
#define N976N_HANDOFF_MAP_BYTES    0x40000U
#define N976N_HANDOFF_MEMORY_ALL   0xFFULL

/* Phase 1: prepared; 2: checking; 8: successful BeforeEBS memory check;
 * E0: refused; 9: released before handoff. This is not EBS completion.
 * Checks: workspace, map, high bank, runtime ownership/permissions,
 * runtime relocation targets, ACPI, system/runtime tables, final guards.
 * The map is a snapshot only; its key is never substituted into Windows' call.
 */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 MapAddress, MapCapacity, MapBytes, DescriptorSize, MapKey;
  UINT64 DescriptorCount, RuntimeDescriptors, RuntimeImages, RuntimeFixups;
  UINT64 HighBytes, AcpiChecks, Guards, Attempts;
  UINT64 WorkspaceBase, WorkspacePages, Detail, RequiredBytes;
} N976N_HANDOFF_MEMORY_REPORT;
STATIC_ASSERT (sizeof (N976N_HANDOFF_MEMORY_REPORT) == 192, "SEC68 memory report ABI");
extern volatile N976N_HANDOFF_MEMORY_REPORT mN976nHandoffMemoryReport;

/* Prepare after ACPI installation, at TPL_APPLICATION and before StartImage.
 * Check is allocation/free/MMU-write free and may run in BeforeExitBootServices.
 * Once Check begins, Release is prohibited even if validation fails. A rejected
 * map stays rejected; the caller must not continue the hardware handoff.
 */
EFI_STATUS N976nPrepareHandoffMemory (VOID);
EFI_STATUS N976nCheckHandoffMemory (VOID);
EFI_STATUS N976nReleaseHandoffMemory (VOID);
#endif
