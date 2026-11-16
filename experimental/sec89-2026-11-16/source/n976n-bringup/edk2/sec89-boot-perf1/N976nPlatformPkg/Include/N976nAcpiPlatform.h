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
 * PublishedCpuCount counts actual enabled MADT/namespace CPUs (BSP or
 * SMP2 four-A55 publication after live entry/GIC checks).
 * Ownership/attribute bits0..6: RSDP, XSDT, FADT, DSDT, MADT, GTDT, PPTT.
 * TOPO1 extends these masks without changing the report layout. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Profile, Reason;
  UINT64 Admission, BspMpidr, CpuCount, EnabledMask, Madt, MadtBytes;
  UINT64 Gtdt, GtdtBytes, OwnershipChecks, AttributeChecks, InstallCount;
  UINT64 PublishedCpuCount;
} N976N_ACPI_REPORT;

/* Separate from the established 160-byte report ABI. Populated only after
 * installed-table verification; consumed by the existing EBS snapshot. */
typedef struct {
  UINT64 Address, Bytes, CoreCount;
} N976N_ACPI_PPTT_REPORT;

#pragma pack (1)
typedef struct {
  EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_HEADER Header;
  EFI_ACPI_6_5_GIC_STRUCTURE Gicc;
  EFI_ACPI_6_5_GIC_STRUCTURE GiccAp[3];
  EFI_ACPI_6_5_GIC_DISTRIBUTOR_STRUCTURE Gicd;
} N976N_ACPI_MADT;

/* Type-0 only: one physical package and the actually enabled cores. The
 * transmitted length excludes unused Core entries in the single-CPU profile.
 * Explicit integer flags avoid a compiler-specific bitfield representation. */
typedef struct {
  UINT8 Type, Length;
  UINT16 Reserved;
  UINT32 Flags, Parent, AcpiProcessorId, NumberOfPrivateResources;
} N976N_ACPI_PPTT_NODE;

typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER Header;
  N976N_ACPI_PPTT_NODE Package;
  N976N_ACPI_PPTT_NODE Core[4];
} N976N_ACPI_PPTT;
#pragma pack ()

STATIC_ASSERT (sizeof (N976N_ACPI_ADMISSION) == 320, "SEC67 ACPI admission ABI");
STATIC_ASSERT (sizeof (N976N_ACPI_REPORT) == 160, "SEC67 ACPI report ABI");
STATIC_ASSERT (sizeof (N976N_ACPI_PPTT_NODE) == 20, "ACPI PPTT type-0 wire size");
STATIC_ASSERT (sizeof (N976N_ACPI_PPTT_NODE) == sizeof (EFI_ACPI_6_5_PPTT_STRUCTURE_PROCESSOR), "upstream PPTT type-0 size");
STATIC_ASSERT (sizeof (N976N_ACPI_PPTT) == 136, "four-core PPTT capacity");

extern EFI_GUID gN976nAcpiAdmissionGuid;
extern volatile N976N_ACPI_REPORT mN976nAcpiReport;
extern volatile N976N_ACPI_PPTT_REPORT mN976nPpttReport;

BOOLEAN EFIAPI N976nValidateAcpiAdmission (
  CONST N976N_ACPI_ADMISSION *Admission,
  UINT64 Profile
  );

/* Pure builders. BSP is enabled initially; AP entries start disabled. CpuCount is the admitted DT
 * inventory of Samsung CPU_ON selectors, not observed MPIDRs or permission
 * to start secondary CPUs. SMP2 replaces AP table values only after witness validation. ACPI UID0 names the BSP
 * in both MADT and the minimal CPU namespace. */
EFI_STATUS EFIAPI N976nBuildAcpiTables (
  CONST N976N_ACPI_ADMISSION *Admission,
  N976N_ACPI_MADT *Madt,
  EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE *Gtdt
  );

/* Called only after the existing power/SMP producers have finalized MADT.
 * This pure serializer cannot enable a CPU or alter its MPIDR/mailbox. */
EFI_STATUS EFIAPI N976nBuildAcpiPptt (
  UINT64 Profile,
  CONST N976N_ACPI_MADT *Madt,
  N976N_ACPI_PPTT *Pptt
  );

EFI_STATUS N976nInstallBootAcpi (UINT64 Profile);
EFI_STATUS N976nPreparePowerHandoff(UINT64 Profile,N976N_ACPI_MADT *Madt);
BOOLEAN N976nPowerHandoffMap(CONST EFI_MEMORY_DESCRIPTOR *Map,UINTN Bytes,UINTN Stride);

#endif
