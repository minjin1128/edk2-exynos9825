/* SPDX-License-Identifier: MIT
 * SEC67: standard table construction from independently admitted platform facts.
 * Uses pinned upstream ACPI structures and the NTDEV GICC/GICD/GTDT arrangement.
 * The pure builder enables BSP only; SMP2 separately fills AP entries from
 * completed entry/GIC witnesses. No register writes or Windows hooks.
 */
#include <N976nAcpiPlatform.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

STATIC CONST UINT64 mPhoneCpuMpidr[N976N_ACPI_MAX_CPUS] = {
  0, 1, 2, 3, 4, 5, 0x100, 0x101
};
STATIC CONST UINT64 mPhoneGicBase[4] = {
  0x10101000, 0x10102000, 0x10104000, 0x10106000
};
STATIC CONST UINT64 mPhoneGicBytes[4] = { 0x1000, 0x1000, 0x2000, 0x2000 };
STATIC CONST UINT64 mQemuGicBase[4] = { 0x08000000, 0x08010000, 0, 0 };
STATIC CONST UINT64 mQemuGicBytes[4] = { 0x10000, 0x10000, 0, 0 };
STATIC CONST UINT64 mTimerGsiv[4] = { 29, 30, 27, 26 };

BOOLEAN EFIAPI N976nValidateAcpiAdmission (
  CONST N976N_ACPI_ADMISSION *A,
  UINT64 Profile
  )
{
  if (A == NULL || Profile > N976N_PLATFORM_PROFILE_QEMU ||
      A->Magic != N976N_ACPI_ADMISSION_MAGIC || A->Version != N976N_ACPI_ABI_VERSION ||
      A->Size != sizeof (*A) || A->Profile != Profile || A->Admitted != 1 ||
      A->Reason != 0 || A->Checks != N976N_ACPI_ADMISSION_CHECKS ||
      A->GicVersion != EFI_ACPI_6_5_GIC_V2 || A->Reserved != 0 ||
      A->GicMaintenanceFlags != 0 || A->BspInterfaceNumber > 7) {
    return FALSE;
  }
  BOOLEAN Phone = Profile == N976N_PLATFORM_PROFILE_PHONE;
  UINT64 ExpectedCount = Phone ? N976N_ACPI_MAX_CPUS : 1;
  if (A->CpuCount != ExpectedCount ||
      A->CounterFrequency != (Phone ? 26000000ULL : 62500000ULL) ||
      A->GicMaintenanceGsiv != (Phone ? 25ULL : 0ULL) ||
      A->PsciUseHvc != (Phone ? 0ULL : 1ULL) ||
      (!Phone && A->BspInterfaceNumber != 0)) {
    return FALSE;
  }
  UINTN BspMatches = 0;
  for (UINTN Index = 0; Index < N976N_ACPI_MAX_CPUS; ++Index) {
    UINT64 Expected = Phone ? mPhoneCpuMpidr[Index] : 0;
    if (A->CpuMpidr[Index] != Expected) { return FALSE; }
    if (Index < A->CpuCount && A->CpuMpidr[Index] == A->BspMpidr) { ++BspMatches; }
  }
  for (UINTN Index = 0; Index < 4; ++Index) {
    if (A->GicBase[Index] != (Phone ? mPhoneGicBase[Index] : mQemuGicBase[Index]) ||
        A->GicBytes[Index] != (Phone ? mPhoneGicBytes[Index] : mQemuGicBytes[Index]) ||
        A->TimerGsiv[Index] != mTimerGsiv[Index] ||
        A->TimerFlags[Index] != (Phone ? EFI_ACPI_6_5_GTDT_TIMER_FLAG_TIMER_INTERRUPT_POLARITY :
          EFI_ACPI_6_5_GTDT_TIMER_FLAG_ALWAYS_ON_CAPABILITY)) {
      return FALSE;
    }
  }
  return BspMatches == 1;
}

STATIC VOID PlatformAcpiHeader (
  EFI_ACPI_DESCRIPTION_HEADER *Header,
  UINT32 Signature,
  UINT32 Bytes,
  UINT8 Revision
  )
{
  Header->Signature = Signature;
  Header->Length = Bytes;
  Header->Revision = Revision;
  CopyMem (Header->OemId, "N976N ", sizeof (Header->OemId));
  CopyMem (&Header->OemTableId, "SEC67   ", sizeof (Header->OemTableId));
  Header->OemRevision = 1;
  Header->CreatorId = SIGNATURE_32 ('N', '9', '7', '6');
  Header->CreatorRevision = 1;
  Header->Checksum = CalculateCheckSum8 ((CONST UINT8 *)Header, Bytes);
}

STATIC BOOLEAN PlatformAcpiOverlap (CONST VOID *A, UINTN An, CONST VOID *B, UINTN Bn)
{
  UINTN Av = (UINTN)A, Bv = (UINTN)B;
  return Av > MAX_UINTN - An || Bv > MAX_UINTN - Bn ||
    (Av < Bv + Bn && Bv < Av + An);
}

EFI_STATUS EFIAPI N976nBuildAcpiTables (
  CONST N976N_ACPI_ADMISSION *A,
  N976N_ACPI_MADT *Madt,
  EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE *Gtdt
  )
{
  if (A == NULL || Madt == NULL || Gtdt == NULL ||
      !N976nValidateAcpiAdmission (A, A->Profile) ||
      PlatformAcpiOverlap (A, sizeof (*A), Madt, sizeof (*Madt)) ||
      PlatformAcpiOverlap (A, sizeof (*A), Gtdt, sizeof (*Gtdt)) ||
      PlatformAcpiOverlap (Madt, sizeof (*Madt), Gtdt, sizeof (*Gtdt))) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem (Madt, sizeof (*Madt));
  ZeroMem (Gtdt, sizeof (*Gtdt));

  Madt->Gicc.Type = EFI_ACPI_6_5_GIC;
  Madt->Gicc.Length = sizeof (Madt->Gicc);
  Madt->Gicc.CPUInterfaceNumber = (UINT32)A->BspInterfaceNumber;
  Madt->Gicc.AcpiProcessorUid = 0;
  Madt->Gicc.Flags = EFI_ACPI_6_5_GIC_ENABLED;
  Madt->Gicc.PhysicalBaseAddress = A->GicBase[N976N_ACPI_GICC];
  Madt->Gicc.GICV = A->GicBase[N976N_ACPI_GICV];
  Madt->Gicc.GICH = A->GicBase[N976N_ACPI_GICH];
  Madt->Gicc.VGICMaintenanceInterrupt = (UINT32)A->GicMaintenanceGsiv;
  Madt->Gicc.MPIDR = A->BspMpidr;
  /* PMU, SPE/TRBE, parking protocol, redistributor and online capability remain
   * zero: this milestone has not admitted those facilities or secondary CPUs. */
  for(UINTN I=0;I<3;++I) {
    Madt->GiccAp[I].Type=EFI_ACPI_6_5_GIC;
    Madt->GiccAp[I].Length=sizeof(Madt->GiccAp[I]);
    Madt->GiccAp[I].AcpiProcessorUid=(UINT32)I+1;
  }
  Madt->Gicd.Type = EFI_ACPI_6_5_GICD;
  Madt->Gicd.Length = sizeof (Madt->Gicd);
  Madt->Gicd.PhysicalBaseAddress = A->GicBase[N976N_ACPI_GICD];
  Madt->Gicd.GicVersion = EFI_ACPI_6_5_GIC_V2;
  PlatformAcpiHeader (&Madt->Header.Header,
    EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE,
    sizeof (*Madt), EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_REVISION);

  /* No invented memory-mapped counter frame. The admitted architectural
   * system-register timers are described directly, as in the NTDEV default. */
  Gtdt->CntControlBasePhysicalAddress = MAX_UINT64;
  Gtdt->CntReadBasePhysicalAddress = MAX_UINT64;
  Gtdt->SecurePL1TimerGSIV = (UINT32)A->TimerGsiv[N976N_ACPI_TIMER_SECURE];
  Gtdt->SecurePL1TimerFlags = (UINT32)A->TimerFlags[N976N_ACPI_TIMER_SECURE];
  Gtdt->NonSecurePL1TimerGSIV = (UINT32)A->TimerGsiv[N976N_ACPI_TIMER_NONSECURE];
  Gtdt->NonSecurePL1TimerFlags = (UINT32)A->TimerFlags[N976N_ACPI_TIMER_NONSECURE];
  Gtdt->VirtualTimerGSIV = (UINT32)A->TimerGsiv[N976N_ACPI_TIMER_VIRTUAL];
  Gtdt->VirtualTimerFlags = (UINT32)A->TimerFlags[N976N_ACPI_TIMER_VIRTUAL];
  Gtdt->NonSecurePL2TimerGSIV = (UINT32)A->TimerGsiv[N976N_ACPI_TIMER_HYP];
  Gtdt->NonSecurePL2TimerFlags = (UINT32)A->TimerFlags[N976N_ACPI_TIMER_HYP];
  PlatformAcpiHeader (&Gtdt->Header,
    EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE_SIGNATURE,
    sizeof (*Gtdt), EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE_REVISION);
  return EFI_SUCCESS;
}

/* ACPI 6.5 5.2.30, and pinned 9820 Pptt.aslc's type-0/parent-offset pattern.
 * Keep the minimal facts: one SoC package, four admitted A55 cores (one in the
 * generic QEMU profile), no SMT and no invented cache/cluster geometry. MPIDR's
 * MT bit is not an assertion that an A55 core has multiple hardware threads.
 * Physical CPU startup remains entirely owned by the existing SMP producer. */
EFI_STATUS EFIAPI N976nBuildAcpiPptt (
  UINT64 Profile,
  CONST N976N_ACPI_MADT *Madt,
  N976N_ACPI_PPTT *Pptt
  )
{
  if (Profile > N976N_PLATFORM_PROFILE_QEMU || Madt == NULL || Pptt == NULL ||
      PlatformAcpiOverlap (Madt, sizeof (*Madt), Pptt, sizeof (*Pptt))) {
    return EFI_INVALID_PARAMETER;
  }
  if (Madt->Header.Header.Signature != EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE ||
      Madt->Header.Header.Revision != EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_REVISION ||
      Madt->Header.Header.Length != sizeof (*Madt) ||
      CalculateSum8 ((CONST UINT8 *)Madt, sizeof (*Madt)) != 0) {
    return EFI_COMPROMISED_DATA;
  }
  UINTN Count = Profile == N976N_PLATFORM_PROFILE_PHONE ? 4 : 1;
  CONST EFI_ACPI_6_5_GIC_STRUCTURE *Cpu[4] = {
    &Madt->Gicc, &Madt->GiccAp[0], &Madt->GiccAp[1], &Madt->GiccAp[2]
  };
  for (UINTN I = 0; I < ARRAY_SIZE (Cpu); ++I) {
    /* UID0..3 are the unchanged DSDT binding. Refuse partial/unprepared phone
     * publication and enabled QEMU APs instead of creating extra topology. */
    if (Cpu[I]->Type != EFI_ACPI_6_5_GIC || Cpu[I]->Length != sizeof (*Cpu[I]) ||
        Cpu[I]->AcpiProcessorUid != I ||
        Cpu[I]->Flags != (I < Count ? EFI_ACPI_6_5_GIC_ENABLED : 0)) {
      return EFI_COMPROMISED_DATA;
    }
    for (UINTN J = 0; J < I && I < Count; ++J) {
      if (Cpu[J]->MPIDR == Cpu[I]->MPIDR) { return EFI_COMPROMISED_DATA; }
    }
  }
  ZeroMem (Pptt, sizeof (*Pptt));
  Pptt->Package.Type = EFI_ACPI_6_5_PPTT_TYPE_PROCESSOR;
  Pptt->Package.Length = sizeof (Pptt->Package);
  Pptt->Package.Flags = BIT0; /* physical package, no ACPI namespace ID */
  for (UINTN I = 0; I < Count; ++I) {
    Pptt->Core[I].Type = EFI_ACPI_6_5_PPTT_TYPE_PROCESSOR;
    Pptt->Core[I].Length = sizeof (Pptt->Core[I]);
    Pptt->Core[I].Flags = BIT1 | BIT3; /* valid UID, core leaf, not a thread */
    Pptt->Core[I].Parent = (UINT32)OFFSET_OF (N976N_ACPI_PPTT, Package);
    Pptt->Core[I].AcpiProcessorId = Cpu[I]->AcpiProcessorUid;
  }
  UINT32 Bytes = (UINT32)(OFFSET_OF (N976N_ACPI_PPTT, Core) + Count * sizeof (Pptt->Core[0]));
  PlatformAcpiHeader (&Pptt->Header,
    EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_STRUCTURE_SIGNATURE,
    Bytes, EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_REVISION);
  CopyMem (&Pptt->Header.OemTableId, "SEC88TP1", sizeof (Pptt->Header.OemTableId));
  Pptt->Header.Checksum = 0;
  Pptt->Header.Checksum = CalculateCheckSum8 ((CONST UINT8 *)Pptt, Bytes);
  return EFI_SUCCESS;
}
