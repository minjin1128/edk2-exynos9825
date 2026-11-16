/* SPDX-License-Identifier: MIT
 * SEC67: install standard ACPI through upstream AcpiTableDxe, then independently
 * verify the resulting links, exact bytes, typed allocation and CPU permissions.
 * Pool pages may be shared with upstream allocation metadata. Do not make those
 * pages read-only behind the allocator's back; retain and check readable/XN.
 */
#include <PiDxe.h>
#include <N976nAcpiPlatform.h>
#include <N976nBatterySnapshot.h>
#include <N976nA55Probe.h>
#include <N976nWindowsBoot.h>
#include <N976nTouchLease.h>
#include <N976nBatteryLive.h>
#include <N976nUfsWindowsLease.h>
#include <N976nUartKd.h>
#include <N976nWindowsConnection.h>
#include <Guid/Acpi.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/MemoryAttribute.h>
#include "AcpiBspDsdtSelect.h"

volatile N976N_ACPI_REPORT mN976nAcpiReport;
volatile N976N_ACPI_PPTT_REPORT mN976nPpttReport;
volatile N976N_BATTERY_SNAPSHOT_REPORT mN976nBatterySnapshotReport;
STATIC UINT8 mInstalledDsdt[sizeof(mAcpiBspDsdt)];

typedef struct {
  EFI_MEMORY_DESCRIPTOR *Map;
  UINTN Bytes;
  UINTN Stride;
} ACPI_MEMORY_SNAPSHOT;

STATIC BOOLEAN AcpiHeapContains (UINT64 Address, UINT64 Bytes)
{
  return Address >= N976N_BOOTSTRAP_HEAP_BASE && Address < N976N_BOOTSTRAP_HEAP_END &&
    Bytes != 0 && Bytes <= N976N_BOOTSTRAP_HEAP_END - Address;
}

STATIC EFI_STATUS AcpiMemorySnapshot (ACPI_MEMORY_SNAPSHOT *Snapshot)
{
  UINTN Bytes = 0, Key = 0, Stride = 0;
  UINT32 Version = 0;
  EFI_STATUS Status = gBS->GetMemoryMap (&Bytes, NULL, &Key, &Stride, &Version);
  ZeroMem (Snapshot, sizeof (*Snapshot));
  for (UINTN Attempt = 0; Attempt < 3; ++Attempt) {
    if (Status != EFI_BUFFER_TOO_SMALL || Stride < sizeof (EFI_MEMORY_DESCRIPTOR) ||
        Bytes == 0 || Bytes > MAX_UINTN - 8 * sizeof (EFI_MEMORY_DESCRIPTOR) ||
        Stride > (MAX_UINTN - Bytes) / 8) {
      return EFI_COMPROMISED_DATA;
    }
    UINTN Capacity = Bytes + 8 * Stride;
    Snapshot->Map = AllocatePool (Capacity);
    if (Snapshot->Map == NULL) { return EFI_OUT_OF_RESOURCES; }
    Bytes = Capacity;
    Status = gBS->GetMemoryMap (&Bytes, Snapshot->Map, &Key, &Stride, &Version);
    if (!EFI_ERROR (Status)) {
      if (Version != EFI_MEMORY_DESCRIPTOR_VERSION || Stride < sizeof (EFI_MEMORY_DESCRIPTOR) ||
          Bytes == 0 || Bytes > Capacity || Bytes % Stride != 0) {
        FreePool (Snapshot->Map); Snapshot->Map = NULL;
        return EFI_COMPROMISED_DATA;
      }
      Snapshot->Bytes = Bytes;
      Snapshot->Stride = Stride;
      return EFI_SUCCESS;
    }
    FreePool (Snapshot->Map); Snapshot->Map = NULL;
    if (Status != EFI_BUFFER_TOO_SMALL) { return Status; }
  }
  return EFI_ABORTED;
}

/* All bytes must be covered once by ACPI reclaim allocation, with no overlapping
 * descriptor and no runtime ownership. The snapshot is taken after installation
 * so it describes upstream's allocations, not the temporary builder buffers. */
STATIC BOOLEAN AcpiOwned (
  CONST ACPI_MEMORY_SNAPSHOT *Snapshot,
  UINT64 Address,
  UINT64 Bytes
  )
{
  if (!AcpiHeapContains (Address, Bytes) || Snapshot->Map == NULL ||
      Snapshot->Stride < sizeof (EFI_MEMORY_DESCRIPTOR) ||
      Snapshot->Bytes == 0 || Snapshot->Bytes % Snapshot->Stride != 0) { return FALSE; }
  UINT64 Covered = 0;
  for (UINTN Offset = 0; Offset < Snapshot->Bytes; Offset += Snapshot->Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D = (CONST VOID *)((CONST UINT8 *)Snapshot->Map + Offset);
    if (D->NumberOfPages == 0 || D->NumberOfPages > MAX_UINT64 / EFI_PAGE_SIZE ||
        (D->PhysicalStart & EFI_PAGE_MASK) != 0) { return FALSE; }
    UINT64 Length = D->NumberOfPages * EFI_PAGE_SIZE;
    if (D->PhysicalStart > MAX_UINT64 - Length) { return FALSE; }
    UINT64 End = D->PhysicalStart + Length;
    if (D->PhysicalStart >= Address + Bytes || End <= Address) { continue; }
    if (D->Type != EfiACPIReclaimMemory || (D->Attribute & EFI_MEMORY_RUNTIME) != 0) { return FALSE; }
    /* Check descriptors overlapping this owned span, including duplicate or
     * otherwise conflicting ownership that a mere byte-total could conceal. */
    for (UINTN Other = Offset + Snapshot->Stride; Other < Snapshot->Bytes; Other += Snapshot->Stride) {
      CONST EFI_MEMORY_DESCRIPTOR *E = (CONST VOID *)((CONST UINT8 *)Snapshot->Map + Other);
      if (E->NumberOfPages == 0 || E->NumberOfPages > MAX_UINT64 / EFI_PAGE_SIZE ||
          E->PhysicalStart > MAX_UINT64 - E->NumberOfPages * EFI_PAGE_SIZE) { return FALSE; }
      UINT64 OtherEnd = E->PhysicalStart + E->NumberOfPages * EFI_PAGE_SIZE;
      if (MAX (D->PhysicalStart, MAX (E->PhysicalStart, Address)) <
          MIN (End, MIN (OtherEnd, Address + Bytes))) { return FALSE; }
    }
    UINT64 Part = MIN (End, Address + Bytes) - MAX (D->PhysicalStart, Address);
    if (Part > Bytes - Covered) { return FALSE; }
    Covered += Part;
  }
  return Covered == Bytes;
}

STATIC BOOLEAN AcpiReadableXn (
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory,
  UINT64 Address,
  UINT64 Bytes
  )
{
  if (!AcpiHeapContains (Address, Bytes)) { return FALSE; }
  UINT64 Attributes = 0;
  UINT64 Page = Address & ~(UINT64)EFI_PAGE_MASK;
  UINT64 End = ALIGN_VALUE (Address + Bytes, EFI_PAGE_SIZE);
  return !EFI_ERROR (Memory->GetMemoryAttributes (Memory, Page, End - Page, &Attributes)) &&
    (Attributes == EFI_MEMORY_XP || Attributes == (EFI_MEMORY_XP | EFI_MEMORY_RO));
}

STATIC BOOLEAN AcpiAdmitRange (
  CONST ACPI_MEMORY_SNAPSHOT *Snapshot,
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory,
  UINT64 Address,
  UINT64 Bytes,
  UINTN Index
  )
{
  if (!AcpiOwned (Snapshot, Address, Bytes)) { return FALSE; }
  if (!AcpiReadableXn (Memory, Address, Bytes)) { return FALSE; }
  mN976nAcpiReport.OwnershipChecks |= LShiftU64 (1, Index);
  mN976nAcpiReport.AttributeChecks |= LShiftU64 (1, Index);
  return TRUE;
}

STATIC VOID AcpiFadt (
  CONST N976N_ACPI_ADMISSION *Admission,
  EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE *Fadt
  )
{
  ZeroMem (Fadt, sizeof (*Fadt));
  Fadt->Header.Signature = EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE;
  Fadt->Header.Length = sizeof (*Fadt);
  Fadt->Header.Revision = EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_REVISION;
  CopyMem (Fadt->Header.OemId, "N976N ", 6);
  CopyMem (&Fadt->Header.OemTableId, "SEC67   ", 8);
  Fadt->Header.OemRevision = 1;
  Fadt->Header.CreatorId = SIGNATURE_32 ('N', '9', '7', '6');
  Fadt->Header.CreatorRevision = 1;
  Fadt->PreferredPmProfile = EFI_ACPI_6_5_PM_PROFILE_TABLET;
  Fadt->Flags = EFI_ACPI_6_5_HW_REDUCED_ACPI;
  /* Samsung legacy arm,psci does not provide SYSTEM_RESET/OFF. Advertising
   * PSCI0.2 made Windows bypass ResetSystem and fail with A0/BEEF/8004.
   * Phone uses the real BSP mailbox + UEFI runtime power provider instead. */
  if (Admission->Profile == N976N_PLATFORM_PROFILE_QEMU) {
    Fadt->ArmBootArch = EFI_ACPI_6_5_ARM_PSCI_COMPLIANT;
    if (Admission->PsciUseHvc != 0) { Fadt->ArmBootArch |= EFI_ACPI_6_5_ARM_PSCI_USE_HVC; }
  }
  /* Preserve the established conservative FADT6.0 subset. */
  Fadt->MinorVersion = 0;
  Fadt->Header.Checksum = CalculateCheckSum8 ((UINT8 *)Fadt, sizeof (*Fadt));
}

STATIC EFI_STATUS AcpiVerifyInstalled (
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory,
  CONST N976N_ACPI_MADT *ExpectedMadt,
  CONST EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE *ExpectedGtdt,
  CONST EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE *ExpectedFadt,
  CONST N976N_ACPI_PPTT *ExpectedPptt,
  CONST N976N_BATTERY_SNAPSHOT *ExpectedBattery,
  CONST N976N_UART_DBG2 *ExpectedDbg2
  )
{
  ACPI_MEMORY_SNAPSHOT Snapshot;
  EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER *Rsdp = NULL;
  EFI_ACPI_DESCRIPTION_HEADER *Xsdt = NULL;
  EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE *Fadt = NULL;
  N976N_ACPI_MADT *Madt = NULL;
  EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE *Gtdt = NULL;
  N976N_ACPI_PPTT *Pptt = NULL;
  N976N_BATTERY_SNAPSHOT *Battery = NULL;
  N976N_UART_DBG2 *Dbg2 = NULL;
  UINTN TableCount = ExpectedDbg2 == NULL ? 5 : 6;
  EFI_STATUS Status = AcpiMemorySnapshot (&Snapshot);
  if (EFI_ERROR (Status)) { return Status; }
  Status = EFI_COMPROMISED_DATA;
  for (UINTN Index = 0; Index < gST->NumberOfTableEntries; ++Index) {
    if (CompareGuid (&gST->ConfigurationTable[Index].VendorGuid, &gEfiAcpi20TableGuid)) {
      if (Rsdp != NULL) { goto Done; }
      Rsdp = gST->ConfigurationTable[Index].VendorTable;
    }
  }
  if (!AcpiAdmitRange (&Snapshot, Memory, (UINTN)Rsdp, sizeof (*Rsdp), 0) ||
      Rsdp->Signature != EFI_ACPI_6_5_ROOT_SYSTEM_DESCRIPTION_POINTER_SIGNATURE ||
      Rsdp->Revision != 2 || Rsdp->Length != sizeof (*Rsdp) ||
      CalculateSum8 ((UINT8 *)Rsdp, 20) != 0 || CalculateSum8 ((UINT8 *)Rsdp, sizeof (*Rsdp)) != 0 ||
      !AcpiAdmitRange (&Snapshot, Memory, Rsdp->XsdtAddress, sizeof (*Xsdt) + TableCount * sizeof (UINT64), 1)) {
    goto Done;
  }
  Xsdt = (VOID *)(UINTN)Rsdp->XsdtAddress;
  if (Xsdt->Signature != EFI_ACPI_6_5_EXTENDED_SYSTEM_DESCRIPTION_TABLE_SIGNATURE ||
      Xsdt->Revision != EFI_ACPI_6_5_EXTENDED_SYSTEM_DESCRIPTION_TABLE_REVISION ||
      Xsdt->Length != sizeof (*Xsdt) + TableCount * sizeof (UINT64) ||
      CalculateSum8 ((UINT8 *)Xsdt, Xsdt->Length) != 0) { goto Done; }
  mN976nAcpiReport.Checks |= BIT3;
  mN976nAcpiReport.Reason = 6;
  for (UINTN Index = 0; Index < TableCount; ++Index) {
    UINT64 Address = ReadUnaligned64 ((UINT64 *)((UINT8 *)Xsdt + sizeof (*Xsdt) + Index * 8));
    if (!AcpiOwned (&Snapshot, Address, sizeof (EFI_ACPI_DESCRIPTION_HEADER)) ||
        !AcpiReadableXn (Memory, Address, sizeof (EFI_ACPI_DESCRIPTION_HEADER))) { goto Done; }
    EFI_ACPI_DESCRIPTION_HEADER *Header = (VOID *)(UINTN)Address;
    if (Header->Signature == EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE_SIGNATURE && Fadt == NULL) {
      Fadt = (VOID *)Header;
      if (!AcpiAdmitRange (&Snapshot, Memory, Address, sizeof (*Fadt), 2)) { goto Done; }
    } else if (Header->Signature == EFI_ACPI_6_5_MULTIPLE_APIC_DESCRIPTION_TABLE_SIGNATURE && Madt == NULL) {
      Madt = (VOID *)Header;
      if (!AcpiAdmitRange (&Snapshot, Memory, Address, sizeof (*Madt), 4)) { goto Done; }
    } else if (Header->Signature == EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE_SIGNATURE && Gtdt == NULL) {
      Gtdt = (VOID *)Header;
      if (!AcpiAdmitRange (&Snapshot, Memory, Address, sizeof (*Gtdt), 5)) { goto Done; }
    } else if (Header->Signature == EFI_ACPI_6_5_PROCESSOR_PROPERTIES_TOPOLOGY_TABLE_STRUCTURE_SIGNATURE && Pptt == NULL) {
      Pptt = (VOID *)Header;
      /* Only the independently generated profile length is read, never an
       * unchecked installed-table length. QEMU publishes one leaf, not four. */
      if (!AcpiAdmitRange (&Snapshot, Memory, Address, ExpectedPptt->Header.Length, 6)) { goto Done; }
    } else if (Header->Signature == N976N_BATTERY_SNAPSHOT_SIGNATURE && Battery == NULL) {
      Battery = (VOID *)Header;
      if (!AcpiOwned (&Snapshot, Address, sizeof (*Battery)) ||
          !AcpiReadableXn (Memory, Address, sizeof (*Battery))) { goto Done; }
    } else if (Header->Signature == EFI_ACPI_6_5_DEBUG_PORT_2_TABLE_SIGNATURE &&
        ExpectedDbg2 != NULL && Dbg2 == NULL) {
      Dbg2 = (VOID *)Header;
      if (!AcpiOwned (&Snapshot, Address, sizeof (*Dbg2)) ||
          !AcpiReadableXn (Memory, Address, sizeof (*Dbg2))) { goto Done; }
    } else { goto Done; }
  }
  if (Fadt == NULL || Madt == NULL || Gtdt == NULL || Pptt == NULL || Battery == NULL ||
      CompareMem (Madt, ExpectedMadt, sizeof (*Madt)) != 0 ||
      CompareMem (Gtdt, ExpectedGtdt, sizeof (*Gtdt)) != 0 ||
      Pptt->Header.Length != ExpectedPptt->Header.Length ||
      CalculateSum8 ((CONST UINT8 *)Pptt, ExpectedPptt->Header.Length) != 0 ||
      CompareMem (Pptt, ExpectedPptt, ExpectedPptt->Header.Length) != 0 ||
      CompareMem (Battery, ExpectedBattery, sizeof (*Battery)) != 0 ||
      CalculateSum8 ((CONST UINT8 *)Battery, sizeof (*Battery)) != 0 ||
      (ExpectedDbg2 != NULL && (Dbg2 == NULL ||
        CompareMem (Dbg2, ExpectedDbg2, sizeof (*Dbg2)) != 0)) ||
      !AcpiAdmitRange (&Snapshot, Memory, Fadt->XDsdt, sizeof (mAcpiBspDsdt), 3) ||
      CompareMem ((VOID *)(UINTN)Fadt->XDsdt, mInstalledDsdt, sizeof (mInstalledDsdt)) != 0) { goto Done; }
  EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE LinkedFadt;
  CopyMem (&LinkedFadt, ExpectedFadt, sizeof (LinkedFadt));
  /* Pinned upstream supplies both low32 and extended pointers for a low DSDT,
   * and recalculates only the header checksum. All other bytes remain exact. */
  LinkedFadt.Dsdt = (UINT32)Fadt->XDsdt;
  LinkedFadt.XDsdt = Fadt->XDsdt;
  LinkedFadt.Header.Checksum = 0;
  LinkedFadt.Header.Checksum = CalculateCheckSum8 ((UINT8 *)&LinkedFadt, sizeof (LinkedFadt));
  if (CompareMem (Fadt, &LinkedFadt, sizeof (*Fadt)) != 0 ||
      mN976nAcpiReport.OwnershipChecks != 0x7F ||
      mN976nAcpiReport.AttributeChecks != 0x7F) { goto Done; }
  mN976nAcpiReport.Checks |= BIT4 | BIT5 | BIT6;
  mN976nAcpiReport.Madt = (UINTN)Madt;
  mN976nAcpiReport.MadtBytes = sizeof (*Madt);
  mN976nAcpiReport.Gtdt = (UINTN)Gtdt;
  mN976nAcpiReport.GtdtBytes = sizeof (*Gtdt);
  mN976nPpttReport.Address = (UINTN)Pptt;
  mN976nPpttReport.Bytes = ExpectedPptt->Header.Length;
  mN976nPpttReport.CoreCount =
    (ExpectedPptt->Header.Length - OFFSET_OF (N976N_ACPI_PPTT, Core)) / sizeof (ExpectedPptt->Core[0]);
  mN976nBatterySnapshotReport.Address = (UINTN)Battery;
  mN976nBatterySnapshotReport.Bytes = sizeof (*Battery);
  mN976nBatterySnapshotReport.OwnershipChecks = 1;
  mN976nBatterySnapshotReport.AttributeChecks = 1;
  mN976nBatterySnapshotReport.Published = 1;
  mN976nWindowsReport.Rsdp = (UINTN)Rsdp;
  mN976nWindowsReport.Xsdt = (UINTN)Xsdt;
  mN976nWindowsReport.Fadt = (UINTN)Fadt;
  mN976nWindowsReport.Dsdt = Fadt->XDsdt;
  if (Dbg2 != NULL) {
    mN976nUartDbg2Report.Address = (UINTN)Dbg2;
    mN976nUartDbg2Report.Bytes = sizeof (*Dbg2);
    mN976nUartDbg2Report.OwnershipChecks = 1;
    mN976nUartDbg2Report.AttributeChecks = 1;
    mN976nUartDbg2Report.Published = 1;
  }
  Status = EFI_SUCCESS;
Done:
  FreePool (Snapshot.Map);
  return Status;
}

EFI_STATUS N976nInstallBootAcpi (UINT64 Profile)
{
  N976N_ACPI_ADMISSION Admission;
  N976N_ACPI_MADT Madt;
  EFI_ACPI_6_5_GENERIC_TIMER_DESCRIPTION_TABLE Gtdt;
  EFI_ACPI_6_5_FIXED_ACPI_DESCRIPTION_TABLE Fadt;
  N976N_ACPI_PPTT Pptt;
  N976N_BATTERY_SNAPSHOT Battery;
  N976N_UART_DBG2 Dbg2;
  EFI_ACPI_TABLE_PROTOCOL *Acpi = NULL;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory = NULL;
  UINTN Keys[7] = { 0 }, Installed = 0;
  BOOLEAN PublishDbg2 = N976N_WINDOWS_UART_DEBUG && Profile == N976N_PLATFORM_PROFILE_PHONE;
  EFI_STATUS Status = EFI_COMPROMISED_DATA;
  ZeroMem ((VOID *)&mN976nAcpiReport, sizeof (mN976nAcpiReport));
  ZeroMem ((VOID *)&mN976nPpttReport, sizeof (mN976nPpttReport));
  ZeroMem ((VOID *)&mN976nBatterySnapshotReport, sizeof (mN976nBatterySnapshotReport));
  ZeroMem ((VOID *)&mN976nUartDbg2Report, sizeof (mN976nUartDbg2Report));
  mN976nAcpiReport.Magic = N976N_ACPI_REPORT_MAGIC;
  mN976nAcpiReport.Version = N976N_ACPI_ABI_VERSION;
  mN976nAcpiReport.Size = sizeof (mN976nAcpiReport);
  mN976nAcpiReport.Profile = Profile;
  mN976nAcpiReport.Phase = 1;
  mN976nAcpiReport.Status = EFI_NOT_READY;
  mN976nAcpiReport.Reason = 1;
  VOID *Hob = GetFirstGuidHob (&gN976nAcpiAdmissionGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (Admission) ||
      GetNextGuidHob (&gN976nAcpiAdmissionGuid, GET_NEXT_HOB (Hob)) != NULL) { goto Done; }
  CopyMem (&Admission, GET_GUID_HOB_DATA (Hob), sizeof (Admission));
  mN976nAcpiReport.Admission = (UINTN)GET_GUID_HOB_DATA (Hob);
  mN976nAcpiReport.BspMpidr = Admission.BspMpidr;
  mN976nAcpiReport.CpuCount = Admission.CpuCount;
  if (!N976nValidateAcpiAdmission (&Admission, Profile)) {
    /* A structurally authentic failed SEC admission retains its precise DT /
     * CPU / banked-GIC reason. Malformed HOBs retain generic reason1. */
    if (Admission.Magic == N976N_ACPI_ADMISSION_MAGIC &&
        Admission.Version == N976N_ACPI_ABI_VERSION && Admission.Size == sizeof (Admission) &&
        Admission.Profile == Profile && Profile <= N976N_PLATFORM_PROFILE_QEMU &&
        Admission.Admitted == 0 && Admission.Reserved == 0 &&
        Admission.Reason >= 0x670 && Admission.Reason <= 0x677) {
      mN976nAcpiReport.Reason = Admission.Reason;
    }
    goto Done;
  }
  mN976nAcpiReport.Checks = BIT0;
  if (PublishDbg2) {
    /* Do not advertise a debug port until this boot owns its live UART path. */
    mN976nAcpiReport.Reason = 0x85A;
    if (!N976nUartKdReady ()) { Status = EFI_NOT_READY; goto Done; }
    Status = N976nBuildUartDbg2 (&Dbg2);
    if (EFI_ERROR (Status)) { goto Done; }
  }
  for (UINTN Index = 0; Index < Admission.CpuCount; ++Index) {
    if (Admission.CpuMpidr[Index] == Admission.BspMpidr) {
      mN976nAcpiReport.EnabledMask = LShiftU64 (1, Index);
    }
  }
  mN976nAcpiReport.Phase = 2;
  mN976nAcpiReport.Reason = 2;
  Status = N976nBuildAcpiTables (&Admission, &Madt, &Gtdt);
  if (EFI_ERROR (Status)) { goto Done; }
  Status = N976nPreparePowerHandoff(Profile,&Madt);
  if (EFI_ERROR(Status)) { mN976nAcpiReport.Reason=0x871; goto Done; }
  Status=N976nA55PublishAcpi(Profile,&Madt);
  if(EFI_ERROR(Status)) {mN976nAcpiReport.Reason=0x881;goto Done;}
  Status=N976nBuildAcpiPptt(Profile,&Madt,&Pptt);
  if(EFI_ERROR(Status)) {mN976nAcpiReport.Reason=0x882;goto Done;}
  Status=N976nBuildBatterySnapshot(Profile,&Battery);
  if(EFI_ERROR(Status)) {mN976nAcpiReport.Reason=0x883;goto Done;}
  AcpiFadt (&Admission, &Fadt);
  if (CalculateSum8 (mAcpiBspDsdt, sizeof (mAcpiBspDsdt)) != 0) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Status=N976nUfsWindowsPublish(Profile);
  if(EFI_ERROR(Status)) goto Done;
  CopyMem (mInstalledDsdt, mAcpiBspDsdt, sizeof(mInstalledDsdt));
  UINT64 LeaseAddress = N976nTouchLeaseAddress ();
  if (Profile == N976N_PLATFORM_PROFILE_PHONE &&
      (!LeaseAddress || EFI_ERROR(N976nTouchLeaseCheck()))) {
    Status=EFI_SECURITY_VIOLATION; goto Done;
  }
  if (Profile == N976N_PLATFORM_PROFILE_QEMU && LeaseAddress) {
    Status=EFI_SECURITY_VIOLATION; goto Done;
  }
  /* These offsets are compiler-derived and source-bound. The unique sentinel
   * and descriptor framing are checked again before any replacement. */
  if (N976N_TOUCH_DSDT_ADDRESS_OFFSET+4 > sizeof(mInstalledDsdt) ||
      N976N_TOUCH_DSDT_STA_OFFSET >= sizeof(mInstalledDsdt) ||
      ReadUnaligned32((UINT32 *)(mInstalledDsdt+N976N_TOUCH_DSDT_ADDRESS_OFFSET))!=0x8BADF000U ||
      mInstalledDsdt[N976N_TOUCH_DSDT_STA_OFFSET]!=0xDA) {
    Status=EFI_COMPROMISED_DATA; goto Done;
  }
  WriteUnaligned32((UINT32 *)(mInstalledDsdt+N976N_TOUCH_DSDT_ADDRESS_OFFSET),(UINT32)LeaseAddress);
  mInstalledDsdt[N976N_TOUCH_DSDT_STA_OFFSET] = LeaseAddress ? 0x0F : 0;
  /* All modes validate their real producer state. B keeps the complete lease
   * while exposing no UFS node; C proves that no new lease/DMA exists. */
  if (EFI_ERROR(N976nUfsWindowsLeaseCheck())) {Status=EFI_SECURITY_VIOLATION;goto Done;}
#if N976N_SEC78_DIAG_MODE == 1
  UINT64 UfsLease=N976nUfsWindowsLeaseAddress(), UfsDma=N976nUfsWindowsDmaAddress();
  if ((Profile==0 && (!UfsLease||!UfsDma||EFI_ERROR(N976nUfsWindowsLeaseCheck()))) ||
      (Profile==1 && (UfsLease||UfsDma)) ||
      N976N_UFS_DSDT_LEASE_OFFSET+4>sizeof(mInstalledDsdt) ||
      N976N_UFS_DSDT_DMA_OFFSET+4>sizeof(mInstalledDsdt) ||
      N976N_UFS_DSDT_STA_OFFSET>=sizeof(mInstalledDsdt) ||
      ReadUnaligned32((UINT32 *)(mInstalledDsdt+N976N_UFS_DSDT_LEASE_OFFSET))!=0x8BADB000U ||
      ReadUnaligned32((UINT32 *)(mInstalledDsdt+N976N_UFS_DSDT_DMA_OFFSET))!=0x8BADC000U ||
      mInstalledDsdt[N976N_UFS_DSDT_STA_OFFSET]!=0xDB) {
    Status=EFI_SECURITY_VIOLATION;goto Done;
  }
  WriteUnaligned32((UINT32 *)(mInstalledDsdt+N976N_UFS_DSDT_LEASE_OFFSET),(UINT32)UfsLease);
  WriteUnaligned32((UINT32 *)(mInstalledDsdt+N976N_UFS_DSDT_DMA_OFFSET),(UINT32)UfsDma);
  mInstalledDsdt[N976N_UFS_DSDT_STA_OFFSET]=UfsLease?0x0F:0;
#else
  if (N976N_SEC78_DIAG_MODE==2 && Profile==0 &&
      (!N976nUfsWindowsLeaseAddress()||!N976nUfsWindowsDmaAddress())) {
    Status=EFI_SECURITY_VIOLATION;goto Done;
  }
  if ((N976N_SEC78_DIAG_MODE==3 || Profile==1) &&
      (N976nUfsWindowsLeaseAddress()||N976nUfsWindowsDmaAddress())) {
    Status=EFI_SECURITY_VIOLATION;goto Done;
  }
#endif
  UINT64 BatteryLease=N976nBatteryLiveAddress();
  if (EFI_ERROR(N976nBatteryLiveCheck()) || (Profile==1 && BatteryLease) ||
      N976N_BAT_DSDT_LEASE_OFFSET+4>sizeof(mInstalledDsdt) ||
      N976N_BAT_DSDT_STA_OFFSET>=sizeof(mInstalledDsdt) ||
      ReadUnaligned32((UINT32 *)(mInstalledDsdt+N976N_BAT_DSDT_LEASE_OFFSET))!=0x8BADE000U ||
      mInstalledDsdt[N976N_BAT_DSDT_STA_OFFSET]!=0xDF) {
    Status=EFI_SECURITY_VIOLATION;goto Done;
  }
  WriteUnaligned32((UINT32 *)(mInstalledDsdt+N976N_BAT_DSDT_LEASE_OFFSET),(UINT32)BatteryLease);
  mInstalledDsdt[N976N_BAT_DSDT_STA_OFFSET]=BatteryLease?15:0;
  CONST UINTN CpuSta[3]={N976N_CPU1_DSDT_STA_OFFSET,N976N_CPU2_DSDT_STA_OFFSET,N976N_CPU3_DSDT_STA_OFFSET};
  for(UINTN I=0;I<3;++I) {
    if(CpuSta[I]>=sizeof(mInstalledDsdt) || mInstalledDsdt[CpuSta[I]]!=0xDC+I) {
      Status=EFI_COMPROMISED_DATA;goto Done;
    }
    mInstalledDsdt[CpuSta[I]]=Profile==N976N_PLATFORM_PROFILE_PHONE?15:0;
  }
  mInstalledDsdt[9]=0;
  mInstalledDsdt[9]=CalculateCheckSum8(mInstalledDsdt,sizeof(mInstalledDsdt));
  mN976nAcpiReport.Checks |= BIT1 | BIT7;
  mN976nAcpiReport.PublishedCpuCount = Profile==N976N_PLATFORM_PROFILE_PHONE?4:1;
  if(Profile==N976N_PLATFORM_PROFILE_PHONE)mN976nAcpiReport.EnabledMask=15;
  mN976nAcpiReport.Phase = 3;
  mN976nAcpiReport.Reason = 3;
  Status = gBS->LocateProtocol (&gEfiAcpiTableProtocolGuid, NULL, (VOID **)&Acpi);
  if (EFI_ERROR (Status)) { goto Done; }
  if (Acpi == NULL || Acpi->InstallAcpiTable == NULL ||
      Acpi->UninstallAcpiTable == NULL) { Status = EFI_COMPROMISED_DATA; goto Done; }
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&Memory);
  if (EFI_ERROR (Status)) { goto Done; }
  if (Memory == NULL || Memory->GetMemoryAttributes == NULL) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  CONST VOID *Tables[7] = { mInstalledDsdt, &Fadt, &Madt, &Gtdt, &Pptt, &Battery, &Dbg2 };
  CONST UINTN Lengths[7] = { sizeof (mAcpiBspDsdt), sizeof (Fadt), sizeof (Madt), sizeof (Gtdt), Pptt.Header.Length, sizeof (Battery), sizeof (Dbg2) };
  mN976nAcpiReport.Reason = 4;
  for (UINTN Index = 0; Index < (PublishDbg2 ? ARRAY_SIZE (Tables) : ARRAY_SIZE (Tables) - 1); ++Index) {
    Status = Acpi->InstallAcpiTable (Acpi, (VOID *)Tables[Index], Lengths[Index], &Keys[Index]);
    if (EFI_ERROR (Status)) { goto Done; }
    ++Installed;
    mN976nAcpiReport.InstallCount = Installed;
  }
  mN976nAcpiReport.Checks |= BIT2;
  mN976nAcpiReport.Phase = 4;
  mN976nAcpiReport.Reason = 5;
  Status = AcpiVerifyInstalled (Memory, &Madt, &Gtdt, &Fadt, &Pptt, &Battery, PublishDbg2 ? &Dbg2 : NULL);
Done:
  if (EFI_ERROR (Status)) {
    while (Installed > 0) {
      EFI_STATUS Cleanup = Acpi->UninstallAcpiTable (Acpi, Keys[--Installed]);
      if (EFI_ERROR (Cleanup)) { mN976nAcpiReport.Reason = 7; Status = Cleanup; }
    }
    mN976nAcpiReport.Phase = 0xE0;
  } else {
    mN976nAcpiReport.Phase = 8;
    mN976nAcpiReport.Reason = 0;
  }
  mN976nAcpiReport.Status = Status;
  return Status;
}
