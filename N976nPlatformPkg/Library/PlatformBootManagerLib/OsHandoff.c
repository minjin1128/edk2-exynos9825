/* SPDX-License-Identifier: MIT
 * The upstream DXE core owns ExitBootServices, map-key validation, interrupt
 * shutdown and Runtime.AtRuntime. These notifications never replace its
 * return value, edit its memory map or call Boot Services after termination.
 */
#include <PiDxe.h>
#include <N976nPlatform.h>
#include <N976nOsHandoff.h>
#include <N976nHandoffMemory.h>
#include <N976nSystemVolume.h>
#include <N976nUfs.h>
#include <Library/ArmLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/TimerLib.h>

volatile N976N_OS_HANDOFF_REPORT mN976nOsHandoffReport;
STATIC BOOLEAN mAttempted;

BOOLEAN N976nOsHandoffAttempted (VOID) { return mAttempted; }

STATIC EFI_STATUS Refuse (UINT64 Reason, EFI_STATUS Status)
{
  mN976nOsHandoffReport.Phase = 0xE0;
  mN976nOsHandoffReport.Reason = Reason;
  mN976nOsHandoffReport.Status = Status;
  MemoryFence ();
  return Status;
}

EFI_STATUS N976nPrepareOsHandoff (UINT64 Profile)
{
  EFI_STATUS Status;
  if (mAttempted || mN976nOsHandoffReport.Magic != 0 ||
      Profile > N976N_PLATFORM_PROFILE_QEMU) { return EFI_ACCESS_DENIED; }
  ZeroMem ((VOID *)&mN976nOsHandoffReport, sizeof (mN976nOsHandoffReport));
  mN976nOsHandoffReport.Magic = N976N_OS_HANDOFF_MAGIC;
  mN976nOsHandoffReport.Version = 1;
  mN976nOsHandoffReport.Size = sizeof (mN976nOsHandoffReport);
  mN976nOsHandoffReport.Profile = Profile;
  Status = N976nPrepareHandoffMemory ();
  if (EFI_ERROR (Status)) { return Refuse (0x690, Status); }
  mN976nOsHandoffReport.Checks = 1;
  mN976nOsHandoffReport.Phase = 1;
  return EFI_SUCCESS;
}

EFI_STATUS N976nBeginOsHandoff (VOID)
{
  EFI_STATUS Status;
  /* Latch before validation. Failure cannot make storage or ordinary cleanup
   * usable again after ExitBootServices has begun partially shutting down. */
  if (mAttempted) { return Refuse (0x694, EFI_ACCESS_DENIED); }
  mAttempted = TRUE;
  mN976nOsHandoffReport.BeforeCount++;
  if (mN976nOsHandoffReport.Phase != 1 ||
      mN976nOsHandoffReport.Checks != 1) { return Refuse (0x694, EFI_NOT_READY); }
  mN976nOsHandoffReport.Phase = 2;
  Status = N976nSystemVolumeFreezeForExit ();
  if (EFI_ERROR (Status)) { return Refuse (0x691, Status); }
  mN976nOsHandoffReport.Checks |= 2;
  Status = N976nCheckHandoffMemory ();
  if (EFI_ERROR (Status)) { return Refuse (0x692, Status); }
  mN976nOsHandoffReport.Checks |= 4;
  Status = N976nUfsQuiesceForExit ();
  if (EFI_ERROR (Status)) { return Refuse (0x693, Status); }
  mN976nOsHandoffReport.Checks |= 8;
  mN976nOsHandoffReport.Counter = GetPerformanceCounter ();
  mN976nOsHandoffReport.Phase = 3;
  MemoryFence ();
  return EFI_SUCCESS;
}

EFI_STATUS N976nFailedOsHandoff (VOID)
{
  if (!mAttempted || (mN976nOsHandoffReport.Phase != 3 &&
      mN976nOsHandoffReport.Phase != 4) ||
      mN976nOsHandoffReport.Checks != 0xF ||
      mN976nOsHandoffReport.ExitCount != 0) {
    return Refuse (0x694, EFI_COMPROMISED_DATA);
  }
  /* A stale map key is retryable. Do not reopen DMA, allocate or restart the
   * timer: the upstream core has already disabled its periodic tick. */
  mN976nOsHandoffReport.FailedCount++;
  mN976nOsHandoffReport.Phase = 4;
  mN976nOsHandoffReport.Status = EFI_INVALID_PARAMETER;
  return EFI_SUCCESS;
}

EFI_STATUS N976nObserveExitBootServices (VOID)
{
  if (!mAttempted || (mN976nOsHandoffReport.Phase != 3 &&
      mN976nOsHandoffReport.Phase != 4) ||
      mN976nOsHandoffReport.Checks != 0xF ||
      mN976nOsHandoffReport.ExitCount != 0 ||
      !N976nSystemVolumeExitFrozen () || !N976nUfsExitQuiesced () ||
      mN976nHandoffMemoryReport.Magic != N976N_HANDOFF_MEMORY_MAGIC ||
      mN976nHandoffMemoryReport.Version != 1 ||
      mN976nHandoffMemoryReport.Size != sizeof (mN976nHandoffMemoryReport) ||
      mN976nHandoffMemoryReport.Phase != 8 ||
      mN976nHandoffMemoryReport.Status != EFI_SUCCESS ||
      mN976nHandoffMemoryReport.Reason != 0 ||
      mN976nHandoffMemoryReport.Guards != 3 ||
      mN976nHandoffMemoryReport.Checks != N976N_HANDOFF_MEMORY_ALL) {
    return Refuse (0x694, EFI_COMPROMISED_DATA);
  }
  /* Both admitted profiles use ArmGenericTimerPhyCounterLib. The upstream
   * core calls SetTimerPeriod(0) before accepting its map. Check ENABLE, not
   * merely IMASK; do not alter timer/GIC state owned by upstream callbacks. */
  mN976nOsHandoffReport.TimerControl = ArmReadCntpCtl ();
  if ((mN976nOsHandoffReport.TimerControl & 1) != 0) {
    return Refuse (0x695, EFI_DEVICE_ERROR);
  }
  mN976nOsHandoffReport.TimerChecks = 1;
  mN976nOsHandoffReport.Checks |= 0x30;
  mN976nOsHandoffReport.ExitCount = 1;
  mN976nOsHandoffReport.Counter = GetPerformanceCounter ();
  mN976nOsHandoffReport.Status = EFI_SUCCESS;
  mN976nOsHandoffReport.Phase = 8;
  MemoryFence ();
  return EFI_SUCCESS;
}
