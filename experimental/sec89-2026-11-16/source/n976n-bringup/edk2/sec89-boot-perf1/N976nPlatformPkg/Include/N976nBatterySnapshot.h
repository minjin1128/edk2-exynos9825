/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_SNAPSHOT_H_
#define N976N_BATTERY_SNAPSHOT_H_
#include <Uefi.h>
#include <IndustryStandard/Acpi65.h>

/* OEM diagnostic only: sequential observations from this boot, never _BST,
 * live battery state, charging control or a callable firmware interface.
 * Payloads contain integers/raw samples only; no pointer is followed by the
 * consumer. Offsets and byte lengths are versioned independently of C ABI. */
#define N976N_BATTERY_SNAPSHOT_SIGNATURE SIGNATURE_32 ('O', 'E', 'M', 'B')
#define N976N_BATTERY_SNAPSHOT_VERSION 1U
#define N976N_BATTERY_SNAPSHOT_BOOT_ONLY 1U
#define N976N_BATTERY_SNAPSHOT_PROBE_BYTES 224U
#define N976N_BATTERY_SNAPSHOT_BUS_BYTES 608U
#pragma pack (1)
typedef struct {
  EFI_ACPI_DESCRIPTION_HEADER Header;
  UINT32 FormatVersion, Profile, Flags;
  UINT8 Probe[N976N_BATTERY_SNAPSHOT_PROBE_BYTES];
  UINT8 Bus[N976N_BATTERY_SNAPSHOT_BUS_BYTES];
} N976N_BATTERY_SNAPSHOT;
#pragma pack ()
STATIC_ASSERT (sizeof (N976N_BATTERY_SNAPSHOT) == 880, "BAT2 snapshot wire size");
STATIC_ASSERT (OFFSET_OF (N976N_BATTERY_SNAPSHOT, Probe) == 48, "BAT2 probe offset");
STATIC_ASSERT (OFFSET_OF (N976N_BATTERY_SNAPSHOT, Bus) == 272, "BAT2 bus offset");

typedef struct {
  UINT64 Address, Bytes, OwnershipChecks, AttributeChecks, Published;
} N976N_BATTERY_SNAPSHOT_REPORT;
extern volatile N976N_BATTERY_SNAPSHOT_REPORT mN976nBatterySnapshotReport;
EFI_STATUS N976nBuildBatterySnapshot (UINT64 Profile, N976N_BATTERY_SNAPSHOT *Table);
#endif
