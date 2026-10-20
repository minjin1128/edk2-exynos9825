/* SPDX-License-Identifier: MIT */
#ifndef N976N_ACPI_ADMISSION_H_
#define N976N_ACPI_ADMISSION_H_
#include <N976nAcpiPlatform.h>

/* Parses only already admitted DT memory. Does not access MMIO or enable CPUs.
 * A successful parse yields Checks=7F/Admitted=0 until the read-only banked
 * distributor facts complete the independent CPU-interface identity check. */
BOOLEAN EFIAPI N976nAdmitAcpi (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  UINT64 RawMpidr, UINT64 CounterFrequency, N976N_ACPI_ADMISSION *Out);
BOOLEAN EFIAPI N976nCompleteAcpiAdmission (
  N976N_ACPI_ADMISSION *Out, UINT32 GicTyper, UINT32 TargetMask);
#endif
