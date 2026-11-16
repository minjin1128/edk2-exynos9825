/* SPDX-License-Identifier: MIT */
#ifndef N976N_ACPI_PLATFORM_H_
#define N976N_ACPI_PLATFORM_H_

#include <N976nPlatform.h>
#include <IndustryStandard/Acpi65.h>

#define N976N_ACPI_ADMISSION_MAGIC  0x3736444149504341ULL
#define N976N_ACPI_REPORT_MAGIC     0x3736545049504341ULL
#define N976N_ACPI_ABI_VERSION      1ULL
#define N976N_ACPI_MAX_CPUS         8U
#define N976N_ACPI_ADMISSION_CHECKS 0xFFULL
#define N976N_ACPI_GICD             0U
#define N976N_ACPI_GICC             1U
#define N976N_ACPI_GICH             2U
#define N976N_ACPI_GICV             3U
#define N976N_ACPI_TIMER_SECURE     0U
#define N976N_ACPI_TIMER_NONSECURE  1U
#define N976N_ACPI_TIMER_VIRTUAL    2U
#define N976N_ACPI_TIMER_HYP        3U

/* SEC-owned immutable facts, admitted from the runtime DT and current CPU.
 * TimerFlags use GTDT polarity/mode bits; GicMaintenanceFlags is the GICC
 * maintenance interrupt mode bit (0 = level). Always-on is admitted only
 * for the QEMU timer. No SMP claim.
 * Unused CPU and reserved entries are zero. GICH/GICV can be absent only in
 * the independently described QEMU profile. No MMIO is performed here. */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Admitted, Reason, Checks;
  UINT64 BspMpidr, CpuCount, CpuMpidr[N976N_ACPI_MAX_CPUS];
  UINT64 GicVersion, GicBase[4], GicBytes[4];
  UINT64 GicMaintenanceGsiv, GicMaintenanceFlags;
  UINT64 TimerGsiv[4], TimerFlags[4], CounterFrequency, PsciUseHvc;
  UINT64 BspInterfaceNumber, Reserved;
} N976N_ACPI_ADMISSION;

/* CpuCount is admitted DT inventory; EnabledMask selects its BSP index.
 * PublishedCpuCount counts actual enabled MADT/namespace CPUs (one, UID0).
 * Ownership/attribute bits0..5: RSDP, XSDT, FADT, DSDT, MADT, GTDT. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Profile, Reason;
  UINT64 Admission, BspMpidr, CpuCount, EnabledMask, Madt, MadtBytes;
  UINT64 Gtdt, GtdtBytes, OwnershipChecks, AttributeChecks, InstallCount;
  UINT64 PublishedCpuCount;
} N976N_ACPI_REPORT;

#pragma pack (1)
typedef struct {
  EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER Header;
  EFI_ACPI_6_5_GIC_STRUCTURE Gicc;
  EFI_ACPI_6_5_GIC_DISTRIBUTOR_STRUCTURE Gicd;
} N976N_ACPI_MADT;
#pragma pack ()

STATIC_ASSERT (sizeof (N976N_ACPI_ADMISSION) == 320, "SEC67 ACPI admission ABI");
STATIC_ASSERT (sizeof (N976N_ACPI_REPORT) == 160, "SEC67 ACPI report ABI");

extern EFI_GUID gN976nAcpiAdmissionGuid;
extern volatile N976N_ACPI_REPORT mN976nAcpiReport;

BOOLEAN EFIAPI N976nValidateAcpiAdmission (
  CONST N976N_ACPI_ADMISSION *Admission,
  UINT64 Profile
  );

/* Pure builders. One measured BSP is published; CpuCount is the admitted DT
 * inventory, not permission to start secondary CPUs. ACPI UID0 names the BSP
 * in both MADT and the minimal CPU namespace. */
EFI_STATUS EFIAPI N976nBuildAcpiTables (
  CONST N976N_ACPI_ADMISSION *Admission,
  N976N_ACPI_MADT *Madt,
  EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE *Gtdt
  );

EFI_STATUS N976nInstallBootAcpi (UINT64 Profile);

#endif
