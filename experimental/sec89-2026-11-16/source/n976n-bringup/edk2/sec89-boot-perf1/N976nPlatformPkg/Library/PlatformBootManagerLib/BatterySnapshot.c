/* SPDX-License-Identifier: MIT */
#include <PiDxe.h>
#include <N976nPlatform.h>
#include <N976nBatteryProbe.h>
#include <N976nBatterySnapshot.h>
#include "BatteryBus.h"
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

STATIC_ASSERT (sizeof (N976N_BATTERY_PROBE_REPORT) == N976N_BATTERY_SNAPSHOT_PROBE_BYTES,
               "BAT2 requires explicit versioning when probe ABI changes");
STATIC_ASSERT (sizeof (N976N_BATTERY_BUS_REPORT) == N976N_BATTERY_SNAPSHOT_BUS_BYTES,
               "BAT2 requires explicit versioning when bus ABI changes");

EFI_STATUS N976nBuildBatterySnapshot (UINT64 Profile, N976N_BATTERY_SNAPSHOT *Table)
{
  N976N_BATTERY_PROBE_REPORT Probe;
  N976N_BATTERY_BUS_REPORT Bus;
  if (Table == NULL) return EFI_INVALID_PARAMETER;
  ZeroMem (Table, sizeof (*Table));
  if (Profile != N976N_PLATFORM_PROFILE_PHONE && Profile != N976N_PLATFORM_PROFILE_QEMU)
    return EFI_INVALID_PARAMETER;
  /* The synchronous producer ran before UART. This makes no new bus access.
   * Failed/skipped/partial observations remain diagnostic records; absence of
   * the producer or unsafe ownership may never become an installable table. */
  CopyMem (&Probe, (CONST VOID *)&mN976nBatteryReport, sizeof (Probe));
  CopyMem (&Bus, (CONST VOID *)&mN976nBatteryBusReport, sizeof (Bus));
  if (Probe.Magic != 0x315442415438384EULL || Probe.Version != 1 ||
      Probe.Size != sizeof (Probe) || Probe.SafeToContinue != 1 ||
      Probe.Attempted > 1 || Bus.Quarantine != 0 ||
      (Probe.Attempted && Bus.NoMutation != 1 && Bus.Restored != 1))
    return EFI_SECURITY_VIOLATION;
  if (Profile == N976N_PLATFORM_PROFILE_QEMU &&
      (Probe.Attempted != 0 || Probe.Phase != 1 || Probe.Status != EFI_UNSUPPORTED || Probe.Reason != 1))
    return EFI_COMPROMISED_DATA;
  Table->Header.Signature = N976N_BATTERY_SNAPSHOT_SIGNATURE;
  Table->Header.Length = sizeof (*Table);
  Table->Header.Revision = 1;
  CopyMem (Table->Header.OemId, "N976N ", 6);
  CopyMem (&Table->Header.OemTableId, "BATSNP01", 8);
  Table->Header.OemRevision = 1;
  Table->Header.CreatorId = SIGNATURE_32 ('N', '9', '7', '6');
  Table->Header.CreatorRevision = 1;
  Table->FormatVersion = N976N_BATTERY_SNAPSHOT_VERSION;
  Table->Profile = (UINT32)Profile;
  Table->Flags = N976N_BATTERY_SNAPSHOT_BOOT_ONLY;
  CopyMem (Table->Probe, &Probe, sizeof (Probe));
  CopyMem (Table->Bus, &Bus, sizeof (Bus));
  Table->Header.Checksum = CalculateCheckSum8 ((UINT8 *)Table, sizeof (*Table));
  return EFI_SUCCESS;
}
