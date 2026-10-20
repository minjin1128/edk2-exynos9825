/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC56: read-only UFS service lease with separate Disk I/O consumer.
 * No descriptor-format guesses, unowned DMA capacity or media writes.
 * Packet layouts: upstream EDK2 870158586f14dbf9d57e312ea6ea87141a1b0699,
 * Ufs.h/UfsHci.h and UfsPassThruHci.c. Exynos adaptations: N976N kernel
 * byte-granular UTRD and the preserved single-entry PRDT layout. Samsung's
 * configured FMP descriptor length is not inferred from inherited registers.
 * N976N stock sboot PRD builder (file0xdfd30) declares4096 bytes per entry
 * while the command path (file0xe2874) retains the logical UPIU length.
 * Use our already-owned, guarded page as that bounce capacity. Samsung Linux
 * instead uses DWORD padding in its separately configured DMA/FMP environment.
 * NTDEV 6e2cacf15f6b99b198ed12ad242da69eb2259bac supplies the platform
 * architecture/nexus precedent. No cold initialization or generic caller memory.
 */
#include <PiDxe.h>
#include <N976nUfs.h>
#include <N976nHighRam.h>
#include <N976nUfsDiag.h>
#include <N976nGpt.h>
#include <N976nSystemProbe.h>
#include <N976nSystemVolume.h>
#include <N976nUfsBlock.h>
#include <N976nUfsService.h>
#include <N976nUfsFileSystem.h>
#include <N976nUfsImage.h>
#include <N976nWindowsBoot.h>
#include <N976nBootMedia.h>
#include <IndustryStandard/Ufs.h>
#include <IndustryStandard/UfsHci.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/PcdLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>
#include "UfsDmaMapping.h"

#define UFS_PAGES 7U
#define UFS_BYTES (UFS_PAGES * 4096U)
#define RESPONSE_OFFSET 0x400U
#define PRDT_OFFSET 0x800U
/* Samsung ALIGNED_UPIU_SIZE and NTDEV DW6=0x04000400 reserve a full
   1024-byte DMA response window. This is not the 52-byte parsed UPIU size.
   RuL/RuO/PrdtO use bytes on this controller, not upstream DWORD units. */
#define RESPONSE_BYTES 1024U
#define PRDT_STORAGE_BYTES 128U
#define VENDOR_NEXUS 0x40U
#define VENDOR_REORDER 0x60U
#define FATAL_IS (BIT7 | BIT11 | BIT12 | BIT16 | BIT17 | BIT18)
#define POLL_US 100U
#define CONTROL_TIMEOUT_US 250000U
#define REQUEST_SENSE_TIMEOUT_US 1000000U
#define START_STOP_TIMEOUT_US 10000000U
#define QUERY_FLAG_TIMEOUT_US 600000U
#define QUERY_ATTR_TIMEOUT_US 1500000U
#define QUERY_READY_TIMEOUT_US 50000U
#define UFS_POWER_ACTIVE_RAW 0x11U
#define UFS_POWER_SLEEP_RAW  0x22U
#define UFS_POWER_DOWN_RAW   0x33U
#define UFS_INTERRUPT_AGGREGATION 0x4CU
#define VENDOR_AXI_BURST 0x6CU
#define OWNED_TRANSFER_COMPLETION BIT0

STATIC_ASSERT (sizeof (UTP_TRD) == 32, "upstream UTRD layout");
STATIC_ASSERT (sizeof (UTP_COMMAND_UPIU) == 32, "upstream command layout");
STATIC_ASSERT (sizeof (UTP_RESPONSE_UPIU) == 52, "upstream response layout");
STATIC_ASSERT (sizeof (UTP_TR_PRD) == 16, "upstream standard PRDT layout");
STATIC_ASSERT (OFFSET_OF (UTP_COMMAND_UPIU, Cdb) == 16, "CDB offset");
STATIC_ASSERT (OFFSET_OF (UTP_RESPONSE_UPIU, SenseData) == 34, "sense offset");
STATIC_ASSERT (sizeof (UTP_COMMAND_UPIU) <= RESPONSE_OFFSET, "command before response");
STATIC_ASSERT (sizeof (UTP_RESPONSE_UPIU) <= RESPONSE_BYTES, "parsed response within DMA window");
STATIC_ASSERT (RESPONSE_OFFSET < PRDT_OFFSET && RESPONSE_BYTES <= PRDT_OFFSET - RESPONSE_OFFSET,
               "response does not overlap PRDT");
STATIC_ASSERT (PRDT_OFFSET + PRDT_STORAGE_BYTES <= 4096U, "UCD within owned page");
STATIC_ASSERT ((RESPONSE_OFFSET & 127U) == 0 && (PRDT_OFFSET & 127U) == 0, "aligned UCD regions");
STATIC_ASSERT (RESPONSE_BYTES <= 0xFFFFU && RESPONSE_OFFSET <= 0xFFFFU && PRDT_OFFSET <= 0xFFFFU,
               "byte-unit UTRD fields fit without truncation");

volatile N976N_UFS_REPORT mN976nUfsReport;
volatile N976N_UFS_DIAG mN976nUfsDiag;
volatile N976N_UFS_EXIT_REPORT mN976nUfsExitReport;
STATIC BOOLEAN mUfsExitClosing, mUfsExitStopped;
STATIC CONST N976N_PLATFORM_HANDOFF *mUfsHandoff;
STATIC N976N_UFS_ADMISSION mAdmission;
STATIC UINT8 *mDma;
STATIC UTP_TRD mExpectedTrd;
STATIC UTP_COMMAND_UPIU mExpectedCommand;
STATIC UINT8 mExpectedPrdt[PRDT_STORAGE_BYTES];
STATIC BOOLEAN mControllerTouched;
STATIC BOOLEAN mIssued;
STATIC UINT8 mQueryOpcode, mQueryIdn, mSsuMode;
STATIC BOOLEAN mPowerChanged;
STATIC UINT32 mQueryExperiment;
STATIC UINT32 mReadLba;
STATIC BOOLEAN mGptReadActive, mSystemReadActive;
STATIC UINTN mSystemReads;
STATIC BOOLEAN mVolumeSessionActive, mVolumeReadActive;
STATIC UINTN mVolumeReads;
STATIC BOOLEAN mPartitionSessionActive, mPartitionReadActive, mServiceLease;
STATIC UINT64 mPartitionStart, mPartitionBlocks;
STATIC UINTN mPartitionReads;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mPartitionMemory;
#define MAX_COMMANDS 64U
STATIC UINTN PartitionDataLimit (VOID) {
  if (mQueryExperiment == 9) { return N976nUfsBootDataLimit (N976N_BOOT_WINDOWS_BYTES); }
  if (mQueryExperiment == 8) { return N976nUfsStreamDataLimit (N976N_BOOT_WINDOWS_BYTES); }
  return mQueryExperiment == 7 ? N976N_FILE_SERVICE_MAX_DATA_BLOCKS :
    (mQueryExperiment == 6 ? N976N_SERVICE_MAX_DATA_BLOCKS : 3);
}
STATIC UINTN CommandLimit (VOID) {
  if ((mQueryExperiment == 12 || mQueryExperiment == 13)) return MAX_COMMANDS + N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS;
  return (mQueryExperiment == 8 || mQueryExperiment == 9) ? MAX_COMMANDS + PartitionDataLimit () : MAX_COMMANDS;
}
STATIC UINT8 NextTaskTag (VOID) {
  /* Total command accounting never resets. A single outstanding slot must
   * retire its exact response/ACK before this nonzero8-bit identity is reused. */
  return (mQueryExperiment == 8 || mQueryExperiment == 9 || (mQueryExperiment == 12 || mQueryExperiment == 13)) ? (UINT8)(mN976nUfsReport.CommandCount % 255U + 1U) :
    (UINT8)(mN976nUfsReport.CommandCount + 1U);
}

STATIC UINT32 HRead (UINTN Offset) { return MmioRead32 ((UINTN)mAdmission.Hci + Offset); }
STATIC VOID HWrite (UINTN Offset, UINT32 Value) {
  MmioWrite32 ((UINTN)mAdmission.Hci + Offset, Value); MemoryFence ();
}
STATIC UINT32 VRead (UINTN Offset) { return MmioRead32 ((UINTN)mAdmission.Vendor + Offset); }
STATIC VOID VWrite (UINTN Offset, UINT32 Value) {
  MmioWrite32 ((UINTN)mAdmission.Vendor + Offset, Value); MemoryFence ();
}
STATIC UINT32 Be32 (CONST UINT8 *P) {
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) | ((UINT32)P[2] << 8) | P[3];
}
STATIC UINT64 Be64 (CONST UINT8 *P) {
  return ((UINT64)Be32 (P) << 32) | Be32 (P + 4);
}
STATIC VOID ResetDiagnostic (VOID) {
  ZeroMem ((VOID *)&mN976nUfsDiag, sizeof (mN976nUfsDiag));
  mN976nUfsDiag.Magic = N976N_UFS_DIAG_MAGIC;
  mN976nUfsDiag.Version = N976N_UFS_DIAG_VERSION;
  mN976nUfsDiag.Size = sizeof (mN976nUfsDiag);
}
STATIC VOID BeginDiagnostic (UINT8 Lun, UINT8 Opcode, UINT32 Bytes, UINT8 Tag) {
  UINT64 Init = mN976nUfsDiag.InitFlag, Initial = mN976nUfsDiag.PowerInitial;
  UINT64 Final = mN976nUfsDiag.PowerFinal, Prep = mN976nUfsDiag.Prepare;
  UINT64 PowerRestore = mN976nUfsDiag.PowerRestore;
  UINT64 Accepted = mN976nUfsDiag.QueryAccepted, Acks = mN976nUfsDiag.AckCount;
  ResetDiagnostic ();
  mN976nUfsDiag.InitFlag = Init; mN976nUfsDiag.PowerInitial = Initial;
  mN976nUfsDiag.PowerFinal = Final; mN976nUfsDiag.Prepare = Prep;
  mN976nUfsDiag.PowerRestore = PowerRestore;
  mN976nUfsDiag.Experiment = mQueryExperiment;
  mN976nUfsDiag.QueryAccepted = Accepted; mN976nUfsDiag.AckCount = Acks;
  if (Opcode == 0x16) {
    mN976nUfsDiag.QueryOpcode = mQueryOpcode; mN976nUfsDiag.QueryIdn = mQueryIdn;
  }
  mN976nUfsDiag.Opcode = Opcode; mN976nUfsDiag.RequestedBytes = Bytes;
  mN976nUfsDiag.ExpectedLun = Lun; mN976nUfsDiag.ExpectedTag = Tag;
  /* These report fields belong to the current attempt, unlike its cumulative
     checks and counters. An early refusal must not display a previous reply. */
  mN976nUfsReport.Ocs = 0; mN976nUfsReport.Response = 0;
  mN976nUfsReport.ScsiStatus = 0; mN976nUfsReport.Residual = 0;
  mN976nUfsReport.SenseBytes = 0; mN976nUfsReport.SenseKey = 0;
  mN976nUfsReport.Asc = 0; mN976nUfsReport.Ascq = 0;
  mN976nUfsReport.LastDoorbell = 0;
  mN976nUfsDiag.Snapshot = 1;
}
STATIC BOOLEAN BytesAre (CONST UINT8 *P, UINTN Count, UINT8 Value) {
  for (UINTN I = 0; I < Count; ++I) { if (P[I] != Value) { return FALSE; } }
  return TRUE;
}
STATIC BOOLEAN Contains (UINT64 Base, UINT64 Size, UINT64 Address, UINT64 Bytes) {
  return Size <= MAX_UINT64 - Base && Address >= Base && Address - Base <= Size &&
    Bytes <= Size - (Address - Base);
}
STATIC BOOLEAN FormatStillSame (VOID) {
  /* Preserve the inherited prefetch and coherency configuration. Explicit
     cache maintenance supports either admitted coherency mode, but never a
     mode change while these pages are owned by the controller. */
  return VRead (0) == mN976nUfsReport.TxPrdt &&
    VRead (4) == mN976nUfsReport.RxPrdt &&
    VRead (VENDOR_REORDER) == mN976nUfsReport.Reorder &&
    MmioRead32 ((UINTN)mAdmission.Coherency) == mN976nUfsReport.CoherencyValue;
}
STATIC BOOLEAN InheritedStillIdle (VOID) {
  /* Do not take ownership if inherited state changed while allocating RAM. */
  return HRead (UFS_HC_ENABLE_OFFSET) == mN976nUfsReport.Hce &&
    HRead (UFS_HC_STATUS_OFFSET) == mN976nUfsReport.Hcs &&
    HRead (UFS_HC_IS_OFFSET) == mN976nUfsReport.Is &&
    HRead (UFS_HC_IE_OFFSET) == mN976nUfsReport.Ie &&
    HRead (UFS_HC_AHIT_OFFSET) == mN976nUfsReport.Ahit &&
    HRead (UFS_HC_UTRLBA_OFFSET) == mN976nUfsReport.TrlBase &&
    HRead (UFS_HC_UTRLBAU_OFFSET) == mN976nUfsReport.TrlBaseUpper &&
    HRead (UFS_HC_UTRLRSR_OFFSET) == mN976nUfsReport.TrlRun &&
    HRead (UFS_HC_UTMRLRSR_OFFSET) == mN976nUfsReport.TmRun &&
    HRead (UFS_HC_UTRLDBR_OFFSET) == 0 && HRead (UFS_HC_UTMRLDBR_OFFSET) == 0 &&
    FormatStillSame () && VRead (VENDOR_NEXUS) == mN976nUfsReport.Nexus;
}
STATIC VOID Publish (VOID) {
  N976nHighRamScreen (); /* Captured state only; no allocation or MMIO. */
}
/* Terminal observation only. Copy already recorded state; never MMIO, cache
 * maintenance, Boot Services, retirement or power restoration at TPL_NOTIFY. */
VOID N976nPublishUfsObservation (VOID) {
  if (mUfsHandoff != NULL) { Publish (); }
}
STATIC VOID RecordWait (UINT64 Start, UINT64 Exit) {
  UINT64 Elapsed = GetPerformanceCounter () - Start;
  mN976nUfsDiag.WaitUs = Elapsed > MAX_UINT64 / 1000000U ? MAX_UINT64 :
    (Elapsed * 1000000U) / mN976nUfsReport.Frequency;
  mN976nUfsDiag.WaitExit = Exit;
}
STATIC BOOLEAN WaitValueUs (UINTN Offset, UINT32 Mask, UINT32 Value, UINT32 TimeoutUs) {
  UINT64 Start = GetPerformanceCounter ();
  /* Frequency is admitted in [1,1GHz]; this product cannot overflow. Both
     elapsed time and an iteration ceiling bound a stopped/broken counter. */
  UINT64 Ticks = (mN976nUfsReport.Frequency * TimeoutUs + 999999U) / 1000000U;
  for (UINTN I = 0; I < TimeoutUs / POLL_US; ++I) {
    if (GetPerformanceCounter () - Start >= Ticks) {
      if (Offset == UFS_HC_UTRLDBR_OFFSET) { RecordWait (Start, 2); }
      return FALSE;
    }
    if ((HRead (Offset) & Mask) == Value) {
      if (Offset == UFS_HC_UTRLDBR_OFFSET) { RecordWait (Start, 1); }
      return TRUE;
    }
    MicroSecondDelay (POLL_US);
  }
  if (Offset == UFS_HC_UTRLDBR_OFFSET) { RecordWait (Start, 3); }
  return FALSE;
}

STATIC VOID ObserveTransferRegisters (BOOLEAN Before) {
  /* All are ordinary reads in the admitted HCI/vendor windows. Do not read
     clear-on-read UIC error latches or issue a UIC command to infer link state. */
  UINT32 Dbr = HRead (UFS_HC_UTRLDBR_OFFSET), Is = HRead (UFS_HC_IS_OFFSET);
  UINT32 Hcs = HRead (UFS_HC_STATUS_OFFSET), Iacr = HRead (UFS_INTERRUPT_AGGREGATION);
  UINT32 Axi = VRead (VENDOR_AXI_BURST);
  if (Before) {
    mN976nUfsDiag.PreDbr = Dbr; mN976nUfsDiag.PreIs = Is; mN976nUfsDiag.PreHcs = Hcs;
    mN976nUfsDiag.PreIacr = Iacr; mN976nUfsDiag.PreAxi = Axi;
    mN976nUfsDiag.ObservationFlags |= BIT0;
  } else {
    mN976nUfsDiag.PostDbr = Dbr; mN976nUfsDiag.PostIs = Is; mN976nUfsDiag.PostHcs = Hcs;
    mN976nUfsDiag.PostIacr = Iacr; mN976nUfsDiag.PostAxi = Axi;
    mN976nUfsDiag.ObservationFlags |= BIT1;
  }
}

STATIC VOID ObservePendingDma (VOID) {
  /* Terminal, potentially racing observation only. These complete pages were
     clean before submission and are never CPU-written while DMA owns them.
     Full-page alignment prevents boundary clean/invalidate operations. NEVER
     clean/write back here: that could overwrite an in-progress device write.
     Do not parse, guard-check, retry, restore or release based on this sample. */
  CONST volatile UINT32 *Ring = (CONST volatile UINT32 *)(mDma + 4096);
  CONST volatile UINT32 *Response = (CONST volatile UINT32 *)(mDma + 3 * 4096 + RESPONSE_OFFSET);
  UINT32 R0, R1, R2, R3;
  MemoryFence ();
  InvalidateDataCacheRange (mDma + 4096, 4096);
  InvalidateDataCacheRange (mDma + 3 * 4096, 4096);
  MemoryFence ();
  mN976nUfsDiag.ObservedOcs = Ring[2] & 0xFFU;
  R0 = Response[0]; R1 = Response[1]; R2 = Response[2]; R3 = Response[3];
  mN976nUfsDiag.ObservedHeader0 = ((UINT64)SwapBytes32 (R0) << 32) | SwapBytes32 (R1);
  mN976nUfsDiag.ObservedHeader1 = ((UINT64)SwapBytes32 (R2) << 32) | SwapBytes32 (R3);
  mN976nUfsDiag.ObservationFlags |= BIT2;
}
STATIC BOOLEAN WaitValue (UINTN Offset, UINT32 Mask, UINT32 Value) {
  return WaitValueUs (Offset, Mask, Value, CONTROL_TIMEOUT_US);
}
STATIC VOID Quarantine (UINT64 Reason) {
  /* A pending device may still write its owned pages. Never free them, change
     its base, fake completion, or continue into Windows. BDS stops on return. */
  mN976nUfsReport.Quarantined = 1;
  mN976nUfsReport.Outcome = N976N_UFS_QUARANTINED;
  mN976nUfsReport.Reason = Reason;
  mN976nUfsReport.Status = EFI_TIMEOUT;
  mN976nUfsReport.Phase = 0xE0;
}
STATIC VOID CompletionHold (UINT64 Reason) {
  Quarantine (Reason);
  mN976nUfsReport.Status = EFI_DEVICE_ERROR;
  mN976nUfsReport.Phase = 0xE2;
}

STATIC BOOLEAN OwnedIdle (VOID) {
  return HRead (UFS_HC_UTRLDBR_OFFSET) == 0 && HRead (UFS_HC_UTMRLDBR_OFFSET) == 0 &&
    HRead (UFS_HC_UTRLRSR_OFFSET) == 1 && HRead (UFS_HC_ENABLE_OFFSET) == 1 &&
    HRead (UFS_HC_UTRLBA_OFFSET) == (UINTN)(mDma + 4096) &&
    HRead (UFS_HC_UTRLBAU_OFFSET) == 0 && HRead (UFS_HC_IE_OFFSET) == 0 &&
    HRead (UFS_HC_AHIT_OFFSET) == 0 && FormatStillSame ();
}

STATIC EFI_STATUS QueryReady (VOID) {
  UINT64 Start = GetPerformanceCounter ();
  UINT64 Ticks = (mN976nUfsReport.Frequency * QUERY_READY_TIMEOUT_US + 999999U) / 1000000U;
  /* Samsung waits up to 50ms for its software link-active state. UEFI has no
     Linux PM state machine: only passively wait for the existing DP/list/UIC
     readiness contract, with AHIT=0. HCS does NOT prove link-active. Never
     issue UIC/PHY/clock operations to manufacture readiness. */
  for (UINTN I = 0; I < QUERY_READY_TIMEOUT_US / POLL_US; ++I) {
    if (GetPerformanceCounter () - Start >= Ticks) { break; }
    if ((HRead (UFS_HC_IS_OFFSET) & FATAL_IS) != 0) {
      CompletionHold (0x46); return EFI_DEVICE_ERROR;
    }
    if (!OwnedIdle ()) { CompletionHold (0x4A); return EFI_DEVICE_ERROR; }
    if ((HRead (UFS_HC_STATUS_OFFSET) & 0xB) == 0xB) { return EFI_SUCCESS; }
    MicroSecondDelay (POLL_US);
  }
  mN976nUfsReport.Reason = 0x47;
  return EFI_NOT_READY;
}

STATIC BOOLEAN ValidateCompletionState (VOID) {
  UINT32 Pending = HRead (UFS_HC_IS_OFFSET);
  /* DBR plus owned descriptors establish completion, never the sticky IS bit.
     ACK is a separate operation after strict response validation below. */
  if (((Pending | (UINT32)mN976nUfsDiag.CompletionIs) & FATAL_IS) != 0) {
    mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_FATAL_IS;
    CompletionHold (0x46); return FALSE;
  }
  if (!OwnedIdle ()) { CompletionHold (0x4A); return FALSE; }
  return TRUE;
}

STATIC VOID PublishAck (VOID) {
  /* Full-file mode retains every ACK state/check, but renders a bounded
     progress breadcrumb per16MiB. No command, cache or safety check is skipped. */
  if ((mQueryExperiment == 12 || mQueryExperiment == 13) && mVolumeReadActive) {
    if ((mVolumeReads & 4095U) == 0 && mUfsHandoff != NULL && mUfsHandoff->Screen != 0) {
      typedef VOID (EFIAPI *SCREEN)(UINT64 Field, UINT64 Value);
      SCREEN Screen = (SCREEN)(UINTN)mUfsHandoff->Screen;
      if (mQueryExperiment == 13) {
        Screen (27, mN976nUfsReport.Phase); Screen (31, N976nSystemWindowsProgress ());
      } else {
        Screen (28, mN976nUfsReport.Phase); Screen (15, mVolumeReads);
      }
    }
    return;
  }
  if (mQueryExperiment < 8 || !mPartitionReadActive) { Publish (); return; }
  if (mUfsHandoff == NULL || mUfsHandoff->Screen == 0) { return; }
  typedef VOID (EFIAPI *SCREEN)(UINT64 Field, UINT64 Value);
  SCREEN Screen = (SCREEN)(UINTN)mUfsHandoff->Screen;
  Screen (26, mN976nUfsReport.Phase); Screen (28, mN976nUfsReport.ReadCount);
}
STATIC EFI_STATUS AckCompletion (VOID) {
  UINT32 Before, After;
  UINT64 Phase = mN976nUfsReport.Phase;
  /* Samsung acknowledges completion before reusing its slot. NTDEV Windows
     polls real DBR clear then acknowledges IS. Its UEFI force-clear/retry hook
     is NOT copied. Only a strictly validated, owned, idle request reaches here;
     valid CHECK CONDITION remains a failed command after its completion ACK. */
  if (mN976nUfsReport.Quarantined || mN976nUfsDiag.Snapshot != 4 ||
      (mN976nUfsDiag.ObservationFlags & BIT3) == 0 || !mIssued) {
    CompletionHold (0x4C); return EFI_DEVICE_ERROR;
  }
  if (!OwnedIdle ()) { CompletionHold (0x4A); return EFI_DEVICE_ERROR; }
  Before = HRead (UFS_HC_IS_OFFSET);
  mN976nUfsDiag.AckBefore = Before;
  if ((Before & FATAL_IS) != 0) { CompletionHold (0x46); return EFI_DEVICE_ERROR; }
  if ((Before & OWNED_TRANSFER_COMPLETION) == 0) {
    CompletionHold (0x4C); return EFI_DEVICE_ERROR;
  }
  /* An MMIO write itself cannot be bounded by a software timeout. Persist a
     screen breadcrumb before/after it (phase/count only during streams); never claim physical ACK safety from
     the component model. No interrupt enable, list clear or reset is added. */
  mN976nUfsDiag.AckPhase = 1; mN976nUfsReport.Phase = 0xA1; PublishAck ();
  HWrite (UFS_HC_IS_OFFSET, OWNED_TRANSFER_COMPLETION);
  mN976nUfsDiag.AckPhase = 2; mN976nUfsReport.Phase = 0xA2; PublishAck ();
  After = HRead (UFS_HC_IS_OFFSET); mN976nUfsDiag.AckAfter = After;
  if ((After & FATAL_IS) != 0) { CompletionHold (0x46); return EFI_DEVICE_ERROR; }
  if ((After & OWNED_TRANSFER_COMPLETION) != 0) {
    CompletionHold (0x4D); return EFI_DEVICE_ERROR;
  }
  if ((After & (Before & ~OWNED_TRANSFER_COMPLETION)) !=
      (Before & ~OWNED_TRANSFER_COMPLETION)) {
    CompletionHold (0x4E); return EFI_DEVICE_ERROR;
  }
  if (!OwnedIdle ()) { CompletionHold (0x4A); return EFI_DEVICE_ERROR; }
  mN976nUfsDiag.AckPhase = 3; mN976nUfsDiag.AckCount++;
  mN976nUfsReport.Phase = Phase;
  return EFI_SUCCESS;
}

STATIC BOOLEAN Guards (VOID) {
  for (UINTN Page = 0; Page < UFS_PAGES; Page += 2) {
    if (!BytesAre (mDma + Page * 4096, 4096, 0xA5)) { return FALSE; }
  }
  return TRUE;
}
/* Revalidate existing low private DMA after high RAM publication. This is
   read-only and cannot create/recover a controller lease or issue a command. */
BOOLEAN N976nUfsWindowsDmaReady (VOID) {
  if (mQueryExperiment == 13) return N976nUfsVolumeDmaReady ();
  if (mUfsHandoff == NULL || mQueryExperiment != 9 ||
      mN976nUfsReport.Quarantined != 0 || mN976nUfsDiag.ImmutableMask != 0) return FALSE;
  if (mUfsHandoff->Profile == N976N_PLATFORM_PROFILE_QEMU) {
    /* Explicit file fixture: no controller/DMA hardware was exercised. */
    return mDma == NULL && !mServiceLease && !mControllerTouched &&
      !mPartitionSessionActive && !mPartitionReadActive &&
      mN976nUfsReport.Outcome == N976N_UFS_NOT_TESTED &&
      mN976nUfsReport.Phase == 0xF0 && mN976nUfsReport.Status == EFI_UNSUPPORTED;
  }
  if (mUfsHandoff->Profile != N976N_PLATFORM_PROFILE_PHONE || mDma == NULL ||
      !mServiceLease || !mControllerTouched || !mPartitionSessionActive ||
      mPartitionReadActive || mGptReadActive || mN976nUfsReport.Restore != 0 ||
      mN976nUfsReport.Buffer != (UINTN)mDma || mN976nUfsReport.BufferBytes != UFS_BYTES ||
      mN976nUfsReport.Status != EFI_SUCCESS ||
      mN976nUfsReport.Outcome != N976N_UFS_FILESYSTEM) return FALSE;
  return UfsDmaMappingValid (mUfsHandoff, (UINTN)mDma, UFS_BYTES) &&
    OwnedIdle () && (HRead (UFS_HC_IS_OFFSET) & FATAL_IS) == 0 && Guards ();
}

/* SEC66: publication must leave the already-owned low DMA/ring unchanged.
   This only inspects the current scoped session; no command or recovery. */
BOOLEAN N976nUfsVolumeDmaReady (VOID) {
  if (mUfsHandoff == NULL || (mQueryExperiment != 12 && mQueryExperiment != 13) || !N976nHighRamPublished () ||
      mN976nUfsReport.Quarantined || mN976nUfsDiag.ImmutableMask ||
      mServiceLease || mPartitionSessionActive || mPartitionReadActive ||
      mGptReadActive || mSystemReadActive || mVolumeReadActive) return FALSE;
  if (mUfsHandoff->Profile == N976N_PLATFORM_PROFILE_QEMU)
    return mDma == NULL && !mControllerTouched && !mVolumeSessionActive &&
      mN976nUfsReport.Outcome == N976N_UFS_NOT_TESTED &&
      mN976nUfsReport.Phase == 0xF0 && mN976nUfsReport.Status == EFI_UNSUPPORTED;
  if (mUfsHandoff->Profile != N976N_PLATFORM_PROFILE_PHONE || mDma == NULL ||
      !mControllerTouched || !mVolumeSessionActive || mN976nUfsReport.Restore ||
      mN976nUfsReport.Buffer != (UINTN)mDma || mN976nUfsReport.BufferBytes != UFS_BYTES ||
      mN976nUfsReport.Status != EFI_SUCCESS ||
      mN976nUfsDiag.AckCount != mN976nUfsReport.CommandCount) return FALSE;
  return UfsDmaMappingValid (mUfsHandoff, (UINTN)mDma, UFS_BYTES) && Guards () &&
    OwnedIdle () && (HRead (UFS_HC_IS_OFFSET) & (FATAL_IS | OWNED_TRANSFER_COMPLETION)) == 0;
}

STATIC UINT32 DmaTransferBytes (UINT32 Bytes) {
  /* Match the target stock loader: a nonempty PRD owns one complete page,
     not a short logical payload rounded to DWORDs. The seven-page allocation
     and page5 bounds were independently admitted before this function runs.
     CDB/UPIU/residual/parser limits still use Bytes, NEVER this capacity.
     Unsupported lengths cannot wrap, add another PRD or escape page5. */
  return Bytes != 0 && Bytes <= 4096U ? 4096U : 0;
}
STATIC VOID CheckImmutableRange (UINT64 Mask, CONST UINT8 *Actual,
  CONST UINT8 *Expected, UINTN Count, UINT8 Fill) {
  for (UINTN I = 0; I < Count; ++I) {
    UINT8 Want = Expected != NULL ? Expected[I] : Fill;
    if (Actual[I] != Want) {
      if (mN976nUfsDiag.ImmutableMask == 0) {
        mN976nUfsDiag.ImmutableOffset = (UINTN)(Actual + I - mDma);
        mN976nUfsDiag.ImmutableExpectedActual = ((UINT64)Want << 8) | Actual[I];
      }
      mN976nUfsDiag.ImmutableMask |= Mask;
      if (Mask == BIT12) {
        /* Inspect only the already-owned data page, never a device-provided
           length. This measures an error, not permission for a wider DMA. */
        mN976nUfsDiag.DataTailChanged++;
        mN976nUfsDiag.DataTailLast = (UINTN)(Actual + I - (mDma + 5 * 4096));
      } else {
        break;
      }
    }
  }
}
STATIC BOOLEAN Immutable (UINT32 Bytes) {
  UINT8 *Ring = mDma + 4096;
  UINT8 *Command = mDma + 3 * 4096;
  UINT32 DmaBytes = DmaTransferBytes (Bytes);
  mN976nUfsDiag.ImmutableMask = 0;
  mN976nUfsDiag.ImmutableOffset = 0;
  mN976nUfsDiag.ImmutableExpectedActual = 0;
  mN976nUfsDiag.DataTailChanged = 0;
  mN976nUfsDiag.DataTailLast = 0;
  if (Bytes > 4096U) {
    mN976nUfsDiag.ImmutableMask = BIT13;
    mN976nUfsDiag.ImmutableOffset = MAX_UINT64;
    return FALSE;
  }
  /* The controller owns only OCS byte8, response [0x400,0x800), and the
     explicitly declared data page for nonzero transfers. REQUEST SENSE
     parses only18 payload bytes. Zero-data requests own no data bytes.
     Every byte outside these owned regions stays immutable.
     The response-to-PRDT gap is empty in this layout; PRDT itself and all
     surrounding bytes remain immutable. Response parsing stays bounded to
     UTP_RESPONSE_UPIU and its original sense/data-segment limits. */
  for (UINTN Page = 0; Page < UFS_PAGES; Page += 2) {
    CheckImmutableRange (1ULL << (Page / 2), mDma + Page * 4096, NULL, 4096, 0xA5);
  }
  CheckImmutableRange (BIT4, Ring, (CONST UINT8 *)&mExpectedTrd, 8, 0);
  CheckImmutableRange (BIT5, Ring + 9, (CONST UINT8 *)&mExpectedTrd + 9, sizeof (mExpectedTrd) - 9, 0);
  CheckImmutableRange (BIT6, Ring + sizeof (mExpectedTrd), NULL, 4096 - sizeof (mExpectedTrd), 0);
  CheckImmutableRange (BIT7, Command, (CONST UINT8 *)&mExpectedCommand, sizeof (mExpectedCommand), 0);
  CheckImmutableRange (BIT8, Command + sizeof (mExpectedCommand), NULL, RESPONSE_OFFSET - sizeof (mExpectedCommand), 0);
  CheckImmutableRange (BIT9, Command + RESPONSE_OFFSET + RESPONSE_BYTES, NULL, PRDT_OFFSET - RESPONSE_OFFSET - RESPONSE_BYTES, 0);
  CheckImmutableRange (BIT10, Command + PRDT_OFFSET, mExpectedPrdt, sizeof (mExpectedPrdt), 0);
  CheckImmutableRange (BIT11, Command + PRDT_OFFSET + PRDT_STORAGE_BYTES, NULL, 4096 - PRDT_OFFSET - PRDT_STORAGE_BYTES, 0);
  CheckImmutableRange (BIT12, mDma + 5 * 4096 + DmaBytes, NULL, 4096 - DmaBytes, 0xCC);
  return mN976nUfsDiag.ImmutableMask == 0;
}

STATIC EFI_STATUS UfsExitFail (EFI_STATUS Status, UINT64 Reason) {
  mN976nUfsExitReport.Status=Status; mN976nUfsExitReport.Reason=Reason;
  mN976nUfsExitReport.Phase=0xE0; mUfsExitStopped=FALSE;
  /* Retain the private pages and never resume a failed handoff attempt. */
  mN976nUfsReport.Quarantined=1;
  return Status;
}
STATIC BOOLEAN UfsExitPhoneAdmitted (VOID) {
  return mUfsHandoff && mUfsHandoff->Profile==N976N_PLATFORM_PROFILE_PHONE &&
    mAdmission.Magic==N976N_UFS_ADMISSION_MAGIC && mAdmission.Version==1 &&
    mAdmission.Size==sizeof(mAdmission) && mAdmission.Admitted==1 && !mAdmission.Reason &&
    mAdmission.Hci==0x13D60000 && mAdmission.Vendor==0x13D61100 && mAdmission.Coherency==0x13C10700;
}
STATIC BOOLEAN UfsExitWaitStopped (UINTN Offset) {
  UINT64 Start=GetPerformanceCounter();
  UINT64 Ticks=(mN976nUfsReport.Frequency*CONTROL_TIMEOUT_US+999999U)/1000000U;
  /* Independent finite poll count, with no delay routine that could itself
   * wait forever on a stopped counter. An MMIO bus transaction can still stall
   * physically; software cannot promise a deadline for such a hardware fault. */
  for (UINTN Count=0; Count<CONTROL_TIMEOUT_US*16U; ++Count) {
    if ((HRead(Offset)&1U)==0) return TRUE;
    if (GetPerformanceCounter()-Start>=Ticks) return FALSE;
    CpuPause();
  }
  return FALSE;
}
STATIC BOOLEAN UfsExitStoppedState (VOID) {
  UINT32 Trl=HRead(UFS_HC_UTRLRSR_OFFSET), Tm=HRead(UFS_HC_UTMRLRSR_OFFSET);
  UINT32 Dbr=HRead(UFS_HC_UTRLDBR_OFFSET), TmDbr=HRead(UFS_HC_UTMRLDBR_OFFSET);
  mN976nUfsExitReport.PostQueues=((UINT64)Tm<<32)|Trl;
  mN976nUfsExitReport.Doorbells=((UINT64)TmDbr<<32)|Dbr;
  return Trl==0 && Tm==0 && Dbr==0 && TmDbr==0 &&
    HRead(UFS_HC_ENABLE_OFFSET)==1 && HRead(UFS_HC_IE_OFFSET)==0 &&
    HRead(UFS_HC_AHIT_OFFSET)==0 &&
    HRead(UFS_HC_UTRLBA_OFFSET)==(UINTN)(mDma+4096) &&
    HRead(UFS_HC_UTRLBAU_OFFSET)==0 &&
    (HRead(UFS_HC_IS_OFFSET)&(FATAL_IS|OWNED_TRANSFER_COMPLETION))==0 &&
    FormatStillSame();
}
BOOLEAN N976nUfsExitQuiesced (VOID) {
  /* Cached local state only: no pointer walk, controller, cache or BS access
   * after CoreTerminateMemoryMap has committed the successful map key. */
  return mUfsExitClosing && mUfsExitStopped &&
    mN976nUfsExitReport.Magic==N976N_UFS_EXIT_MAGIC &&
    mN976nUfsExitReport.Version==1 && mN976nUfsExitReport.Size==sizeof(mN976nUfsExitReport) &&
    mN976nUfsExitReport.Phase==8 && mN976nUfsExitReport.Status==EFI_SUCCESS &&
    mN976nUfsExitReport.Reason==0 &&
    ((mN976nUfsExitReport.Profile==N976N_PLATFORM_PROFILE_PHONE &&
      mN976nUfsExitReport.Checks==N976N_UFS_EXIT_PHONE_CHECKS) ||
     (mN976nUfsExitReport.Profile==N976N_PLATFORM_PROFILE_QEMU &&
      mN976nUfsExitReport.Checks==N976N_UFS_EXIT_FIXTURE_CHECKS));
}
EFI_STATUS N976nUfsQuiesceForExit (VOID) {
  if (mUfsExitClosing) {
    if (mN976nUfsExitReport.Attempts==MAX_UINT64) return UfsExitFail(EFI_COMPROMISED_DATA,0x687);
    ++mN976nUfsExitReport.Attempts;
    if (!N976nUfsExitQuiesced()) return EFI_ERROR(mN976nUfsExitReport.Status) ?
      mN976nUfsExitReport.Status : UfsExitFail(EFI_COMPROMISED_DATA,0x687);
    if (!N976nSystemVolumeExitFrozen()) return UfsExitFail(EFI_ACCESS_DENIED,0x680);
    if (mN976nUfsExitReport.Profile==N976N_PLATFORM_PROFILE_QEMU) {
      return mUfsHandoff && mUfsHandoff->Profile==N976N_PLATFORM_PROFILE_QEMU &&
        N976nUfsVolumeDmaReady() ? EFI_SUCCESS : UfsExitFail(EFI_ACCESS_DENIED,0x680);
    }
    /* Repeated before-EBS calls are read-only; never rearm either queue. */
    if (!UfsExitPhoneAdmitted()) return UfsExitFail(EFI_SECURITY_VIOLATION,0x681);
    if (!UfsExitStoppedState()) return UfsExitFail(EFI_DEVICE_ERROR,0x685);
    return EFI_SUCCESS;
  }
  mUfsExitClosing=TRUE;
  ZeroMem((VOID*)&mN976nUfsExitReport,sizeof(mN976nUfsExitReport));
  mN976nUfsExitReport.Magic=N976N_UFS_EXIT_MAGIC;
  mN976nUfsExitReport.Version=1; mN976nUfsExitReport.Size=sizeof(mN976nUfsExitReport);
  mN976nUfsExitReport.Phase=1; mN976nUfsExitReport.Status=EFI_NOT_READY;
  mN976nUfsExitReport.Checks=BIT1; mN976nUfsExitReport.Attempts=1;
  mN976nUfsExitReport.Profile=mUfsHandoff?mUfsHandoff->Profile:MAX_UINT64;
  MemoryFence();
  if (!N976nSystemVolumeExitFrozen() || !mUfsHandoff || mQueryExperiment!=13 ||
      mUfsHandoff->Magic!=N976N_PLATFORM_HANDOFF_MAGIC ||
      mUfsHandoff->Version!=N976N_PLATFORM_ABI_VERSION || mUfsHandoff->Size!=sizeof(*mUfsHandoff) ||
      mUfsHandoff->Reserved ||
      mN976nUfsReport.Magic!=N976N_UFS_REPORT_MAGIC || mN976nUfsReport.Version!=1 ||
      mN976nUfsReport.Size!=sizeof(mN976nUfsReport) ||
      mUfsHandoff->Profile>N976N_PLATFORM_PROFILE_QEMU ||
      mN976nUfsReport.Profile!=mUfsHandoff->Profile) {
    return UfsExitFail(EFI_ACCESS_DENIED,0x680);
  }
  /* Validate the physical MMIO identity before the readiness helper can touch
   * it. The QEMU fixture deliberately has no physical admission/HCI access. */
  if (mUfsHandoff->Profile==N976N_PLATFORM_PROFILE_PHONE &&
      !UfsExitPhoneAdmitted()) {
    return UfsExitFail(EFI_SECURITY_VIOLATION,0x681);
  }
  if (!N976nUfsVolumeDmaReady()) return UfsExitFail(EFI_ACCESS_DENIED,0x680);
  mN976nUfsExitReport.Checks|=BIT0;
  if (mUfsHandoff->Profile==N976N_PLATFORM_PROFILE_QEMU) {
    /* Modeled file provider: no controller/guard/cache operation or DMA claim. */
    mN976nUfsExitReport.Checks|=BIT7|BIT8;
    mN976nUfsExitReport.Phase=8; mN976nUfsExitReport.Status=EFI_SUCCESS;
    mUfsExitStopped=TRUE; return EFI_SUCCESS;
  }
  if (mUfsHandoff->Profile!=N976N_PLATFORM_PROFILE_PHONE ||
      mN976nUfsReport.Frequency==0 || mN976nUfsReport.Frequency>1000000000ULL ||
      !mIssued || mN976nUfsReport.CommandCount==0 ||
      mN976nUfsDiag.AckCount!=mN976nUfsReport.CommandCount ||
      mN976nUfsDiag.Snapshot!=4 || mN976nUfsDiag.AckPhase!=3 ||
      mN976nUfsDiag.RequestedBytes>4096 || mN976nUfsDiag.ImmutableMask ||
      mN976nUfsReport.Restore!=0) return UfsExitFail(EFI_SECURITY_VIOLATION,0x681);
  mN976nUfsExitReport.Checks|=BIT5;
  mN976nUfsExitReport.Phase=2;
  UINT32 Trl=HRead(UFS_HC_UTRLRSR_OFFSET), Tm=HRead(UFS_HC_UTMRLRSR_OFFSET);
  mN976nUfsExitReport.PreQueues=((UINT64)Tm<<32)|Trl;
  mN976nUfsExitReport.Doorbells=((UINT64)HRead(UFS_HC_UTMRLDBR_OFFSET)<<32)|HRead(UFS_HC_UTRLDBR_OFFSET);
  if (Trl!=1 || Tm>1 || Tm!=mN976nUfsReport.TmRun ||
      mN976nUfsExitReport.Doorbells ||
      (HRead(UFS_HC_IS_OFFSET)&(FATAL_IS|OWNED_TRANSFER_COMPLETION))!=0) {
    return UfsExitFail(EFI_DEVICE_ERROR,0x682);
  }
  mN976nUfsExitReport.Checks|=BIT2;
  /* Standard list-stop semantics, after proving no request remains. Keep the
   * controller enabled, IRQs gated and bases untouched. This is not the normal
   * return-to-firmware Restore() path, which would restart an inherited queue. */
  mN976nUfsExitReport.Phase=3;
  HWrite(UFS_HC_UTMRLRSR_OFFSET,0);
  if (!UfsExitWaitStopped(UFS_HC_UTMRLRSR_OFFSET)) return UfsExitFail(EFI_TIMEOUT,0x683);
  mN976nUfsExitReport.Phase=4;
  HWrite(UFS_HC_UTRLRSR_OFFSET,0);
  if (!UfsExitWaitStopped(UFS_HC_UTRLRSR_OFFSET)) return UfsExitFail(EFI_TIMEOUT,0x684);
  mN976nUfsExitReport.Checks|=BIT3;
  if (!UfsExitStoppedState()) return UfsExitFail(EFI_DEVICE_ERROR,0x685);
  mN976nUfsExitReport.Checks|=BIT4;
  mN976nUfsExitReport.Phase=5;
  MemoryFence(); InvalidateDataCacheRange(mDma,UFS_BYTES); MemoryFence();
  if (!UfsDmaMappingValid(mUfsHandoff,(UINTN)mDma,UFS_BYTES) ||
      !Immutable((UINT32)mN976nUfsDiag.RequestedBytes) || !UfsExitStoppedState()) {
    return UfsExitFail(EFI_SECURITY_VIOLATION,0x686);
  }
  mN976nUfsExitReport.Checks|=BIT6|BIT7;
  mN976nUfsExitReport.Phase=8; mN976nUfsExitReport.Status=EFI_SUCCESS;
  mUfsExitStopped=TRUE;
  return EFI_SUCCESS;
}

STATIC VOID ObserveDataPadding (UINT32 Bytes) {
  /* Post-completion evidence inside the newly declared page capacity, not
     a tail exception. Keep the former DWORD boundary as a comparison point
     with FIX9. The immutable scan still protects every byte OUTSIDE capacity.
     No bytes from this observational padding are parsed or returned as data. */
  if (Bytes == 0 || Bytes > 4096U) { return; }
  mN976nUfsDiag.DataTailChanged = 0;
  mN976nUfsDiag.DataTailLast = 0;
  for (UINT32 I = (Bytes + 3U) & ~3U; I < 4096U; ++I) {
    if (mDma[5 * 4096 + I] != 0xCC) {
      mN976nUfsDiag.DataTailChanged++;
      mN976nUfsDiag.DataTailLast = I;
    }
  }
}

STATIC BOOLEAN PreparedDmaValid (VOID) {
  /* No request is in flight. Every data byte must still be the CPU'sCC fill,
     and the response/OCS must be exactly their constructed initial values.
     Use the same immutable scan and capture contract as completion checks. */
  mN976nUfsDiag.DataTail = Be64 (mDma + 5 * 4096 + 16);
  Immutable (0);
  CheckImmutableRange (BIT14, mDma + 3 * 4096 + RESPONSE_OFFSET, NULL, RESPONSE_BYTES, 0);
  CheckImmutableRange (BIT15, mDma + 4096 + 8, (CONST UINT8 *)&mExpectedTrd + 8, 1, 0);
  return mN976nUfsDiag.ImmutableMask == 0;
}

/* Decode only complete, bounded sense. Deferred errors remain evidence and
   cannot authorize a new command. Byte0's VALID bit is not a format bit. */
STATIC BOOLEAN DecodeSense (CONST UINT8 *Sense, UINT32 Bytes) {
  UINT8 Code;
  UINT32 Length;
  if (Bytes == 0 || Bytes > 18) { return FALSE; }
  Code = Sense[0] & 0x7F; mN976nUfsDiag.SenseFormat = Code;
  if (Code < 0x70 || Code > 0x73 || Bytes < 8) { return FALSE; }
  Length = 8U + Sense[7];
  if (Length > Bytes) { return FALSE; }
  if (Code < 0x72) {
    if (Length < 14) { return FALSE; }
    mN976nUfsReport.SenseKey = Sense[2] & 0xF;
    mN976nUfsReport.Asc = Sense[12]; mN976nUfsReport.Ascq = Sense[13];
  } else {
    mN976nUfsReport.SenseKey = Sense[1] & 0xF;
    mN976nUfsReport.Asc = Sense[2]; mN976nUfsReport.Ascq = Sense[3];
  }
  mN976nUfsDiag.SenseFormat |= BIT8;
  if (Code == 0x70 || Code == 0x72) { mN976nUfsDiag.SenseFormat |= BIT9; }
  return TRUE;
}
STATIC VOID CaptureSense (CONST UINT8 *Sense) {
  mN976nUfsDiag.RawSense0 = Be64 (Sense);
  mN976nUfsDiag.RawSense1 = Be64 (Sense + 8);
  mN976nUfsDiag.RawSense2 = ((UINT64)Sense[16] << 56) | ((UINT64)Sense[17] << 48);
}
/* Only the metadata windows needed by the bounded4Kn GPT observer. The
   device-provided entry pointer can never authorize arbitrary sector reads. */
STATIC BOOLEAN GptReadAllowed (UINT8 Lun, UINT32 Bytes, UINT64 Lba) {
  UINT64 Last = mN976nUfsReport.LastLba;
  return (mQueryExperiment >= 4 && mQueryExperiment <= 13) && mGptReadActive &&
    !mSystemReadActive && !mVolumeSessionActive && !mVolumeReadActive &&
    !mPartitionSessionActive && Lun < 8 &&
    Lun == mN976nUfsReport.Lun && Bytes == 4096 && mN976nUfsReport.BlockBytes == 4096 &&
    (mN976nUfsReport.Checks & 0x10) != 0 && Last >= 16 && Last < MAX_UINT32 &&
    Lba <= Last && (Lba <= 5 || Lba >= Last - 4) &&
    mN976nUfsReport.CommandCount < CommandLimit () - 3;
}
/* Private session capability, copied from the independently accepted GPT.
   Media fields and caller pointers never authorize a different partition. */
STATIC BOOLEAN PartitionReadAllowed (UINT8 Lun, UINT32 Bytes, UINT64 Lba) {
  UINT64 Last = mN976nUfsReport.LastLba;
  return (mQueryExperiment >= 5 && mQueryExperiment <= 9) && mPartitionSessionActive && mPartitionReadActive &&
    !mGptReadActive && !mSystemReadActive && !mVolumeSessionActive && !mVolumeReadActive && Lun < 8 && Lun == mN976nUfsReport.Lun && Bytes == 4096 &&
    mN976nUfsReport.BlockBytes == 4096 && (mN976nUfsReport.Checks & 0x10) != 0 &&
    N976nGptEntries () != NULL && mN976nGptReport.Phase == 8 &&
    mN976nGptReport.Status == EFI_SUCCESS && mN976nGptReport.Checks == 0xFF &&
    Last >= 16 && Last < MAX_UINT32 && mPartitionStart >= 6 &&
    mPartitionStart <= Last - 5 && mPartitionBlocks >= 2 &&
    mPartitionBlocks <= Last - 4 - mPartitionStart &&
    Lba >= mPartitionStart && Lba - mPartitionStart < mPartitionBlocks &&
    mPartitionReads < PartitionDataLimit () &&
    mN976nUfsReport.CommandCount < CommandLimit () - 3;
}
/* A separate private capability for exactly two SYSTEM blocks; no PIT reads.
   Only SystemProbe's pending owned CPU destination admits an actual transfer. */
STATIC BOOLEAN SystemReadAllowed (UINT8 Lun, UINT32 Bytes, UINT64 Lba) {
  return (mQueryExperiment == 10 || (mQueryExperiment == 12 || mQueryExperiment == 13)) && mSystemReadActive && !mGptReadActive &&
    !mVolumeSessionActive && !mVolumeReadActive &&
    !mPartitionSessionActive && !mPartitionReadActive && !mServiceLease &&
    Lun < 8 && Lun == mN976nUfsReport.Lun && Bytes == 4096 &&
    mN976nUfsReport.BlockBytes == 4096 && (mN976nUfsReport.Checks & 0x10) != 0 &&
    mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
    mN976nGptReport.Checks == 0xFF && N976nGptEntries () != NULL &&
    mSystemReads < 2 && Lba <= mN976nUfsReport.LastLba && Lba < MAX_UINT32 &&
    mN976nUfsReport.CommandCount < MAX_COMMANDS - 3 && N976nSystemLbaAllowed (Lba);
}
/* The supply-volume consumer owns one exact pending CPU page. This separate
 * capability cannot widen the retained two-page SYSTEM diagnostic or the old
 * BOOT service. DMA still transfers one guarded low4KiB page per command. */
STATIC BOOLEAN VolumeReadAllowed (UINT8 Lun, UINT32 Bytes, UINT64 Lba) {
  CONST EFI_PARTITION_ENTRY *Entry = N976nSystemEntry ();
  return (mQueryExperiment == 12 || mQueryExperiment == 13) && mVolumeSessionActive && mVolumeReadActive &&
    !mGptReadActive && !mSystemReadActive && !mPartitionSessionActive &&
    !mPartitionReadActive && !mServiceLease && Lun < 8 && Lun == mN976nUfsReport.Lun &&
    Bytes == 4096 && mN976nUfsReport.BlockBytes == 4096 &&
    (mN976nUfsReport.Checks & 0x10) != 0 && Entry != NULL &&
    mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
    mN976nGptReport.Checks == 0xFF && N976nGptEntries () != NULL &&
    N976nSystemProbeClosed () && mN976nSystemReport.Phase == 8 &&
    mN976nSystemReport.Status == EFI_SUCCESS && mN976nSystemReport.Checks == N976N_SYSTEM_CHECKS &&
    Lba >= Entry->StartingLBA && Lba <= Entry->EndingLBA &&
    Lba - Entry->StartingLBA < N976N_SYSTEM_IMAGE_BYTES / 4096 &&
    Lba <= mN976nUfsReport.LastLba && Lba < MAX_UINT32 &&
    mVolumeReads < N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS &&
    mN976nUfsReport.CommandCount < CommandLimit () - 3 &&
    N976nSystemVolumeLbaAllowed (Lba);
}
STATIC EFI_STATUS MakeRequest (UINT8 Lun, UINT8 Opcode, UINT32 Bytes, UINT8 Tag) {
  UTP_TRD *Trd = (UTP_TRD *)(mDma + 4096);
  UTP_COMMAND_UPIU *Command = (UTP_COMMAND_UPIU *)(mDma + 3 * 4096);
  UTP_TR_PRD *Prd = (UTP_TR_PRD *)((UINT8 *)Command + PRDT_OFFSET);
  BOOLEAN Query = Opcode == 0x16;
  /* Closed CDB/query whitelist: no arbitrary command or caller-supplied LBA. */
  if (Tag == 0 || ((mQueryExperiment < 8 || mQueryExperiment == 10) && Tag > MAX_COMMANDS) ||
      !((Lun < 8 && ((Opcode == 0x00 && Bytes == 0) ||
         (Opcode == 0x25 && Bytes == 8) ||
         (Opcode == 0x28 && (Bytes == 512 || Bytes == 4096)))) ||
        (Lun == 0xD0 && ((Opcode == 0x03 && Bytes == 18) ||
         (Opcode == 0x1B && Bytes == 0 &&
          (mSsuMode == 1 || mSsuMode == 2 || mSsuMode == 3)))) ||
        (Query && Lun == 0 && Bytes == 0 &&
         ((mQueryOpcode == 5 && mQueryIdn == 1) || (mQueryOpcode == 3 && mQueryIdn == 2))))) {
    return EFI_INVALID_PARAMETER;
  }
  if (Opcode == 0x28 && ((mQueryExperiment >= 4 &&
      !GptReadAllowed (Lun, Bytes, mReadLba) && !PartitionReadAllowed (Lun, Bytes, mReadLba) &&
      !SystemReadAllowed (Lun, Bytes, mReadLba) && !VolumeReadAllowed (Lun, Bytes, mReadLba)) ||
      (mQueryExperiment < 4 && mReadLba != 0))) { return EFI_INVALID_PARAMETER; }
  ZeroMem (Trd, 4096); ZeroMem (Command, 4096);
  SetMem (mDma + 5 * 4096, 4096, 0xCC);
  if (Query) {
    UINT8 *Q = (UINT8 *)Command;
    Q[0] = 0x16; Q[3] = Tag; Q[5] = 1;
    Q[12] = mQueryOpcode; Q[13] = mQueryIdn;
  } else {
    Command->TransCode = 1; Command->Flags = BIT0 | (Bytes != 0 ? BIT6 : 0);
    Command->Lun = Lun; Command->TaskTag = Tag;
    Command->ExpDataTranLen = SwapBytes32 (Bytes); Command->Cdb[0] = Opcode;
    if (Opcode == 0x28) {
      Command->Cdb[2] = (UINT8)(mReadLba >> 24); Command->Cdb[3] = (UINT8)(mReadLba >> 16);
      Command->Cdb[4] = (UINT8)(mReadLba >> 8); Command->Cdb[5] = (UINT8)mReadLba;
      Command->Cdb[8] = 1;
    }
    if (Opcode == 0x03) { Command->Cdb[4] = 18; }
    if (Opcode == 0x1B) { Command->Cdb[4] = mSsuMode << 4; }
  }
  Trd->Int = 1; Trd->Dd = Bytes != 0 ? UfsDataIn : UfsNoData;
  Trd->Ct = UFS_STORAGE_COMMAND_TYPE; Trd->Ocs = UFS_HC_TRD_OCS_INIT_VALUE;
  Trd->UcdBa = (UINT32)((UINTN)Command >> 7);
  Trd->UcdBaU = (UINT32)((UINT64)(UINTN)Command >> 32);
  Trd->RuL = RESPONSE_BYTES; Trd->RuO = RESPONSE_OFFSET; Trd->PrdtO = PRDT_OFFSET;
  if (Bytes != 0) {
    Trd->PrdtL = sizeof (UTP_TR_PRD) + 16;
    Prd->DbAddr = (UINT32)((UINTN)(mDma + 5 * 4096) >> 2);
    Prd->DbAddrU = (UINT32)((UINT64)(UINTN)(mDma + 5 * 4096) >> 32);
    Prd->DbCount = DmaTransferBytes (Bytes) - 1;
  }
  mN976nUfsDiag.DmaCapacity = DmaTransferBytes (Bytes);
  CopyMem (&mExpectedTrd, Trd, sizeof (*Trd));
  CopyMem (&mExpectedCommand, Command, sizeof (*Command));
  CopyMem (mExpectedPrdt, Prd, sizeof (mExpectedPrdt));
  return EFI_SUCCESS;
}

STATIC EFI_STATUS Transfer (UINT8 Lun, UINT8 Opcode, UINT32 Bytes) {
  if (mUfsExitClosing) { return EFI_ACCESS_DENIED; }
  EFI_STATUS Status;
  BOOLEAN ImageValid;
  UTP_TRD *Trd = (UTP_TRD *)(mDma + 4096);
  UTP_RESPONSE_UPIU *Response = (UTP_RESPONSE_UPIU *)(mDma + 3 * 4096 + RESPONSE_OFFSET);
  UINT8 Tag = NextTaskTag ();
  UINT32 Nexus = Opcode == 0x16 ? ((UINT32)mN976nUfsReport.Nexus & ~1U) :
    ((UINT32)mN976nUfsReport.Nexus | 1U);
  BeginDiagnostic (Lun, Opcode, Bytes, Tag);
  if (mN976nUfsReport.CommandCount >= CommandLimit ()) { return EFI_OUT_OF_RESOURCES; }
  if (mQueryExperiment >= 8 && mN976nUfsDiag.AckCount != mN976nUfsReport.CommandCount) {
    CompletionHold (0x77); return EFI_DEVICE_ERROR;
  }
  UINT32 Pending = HRead (UFS_HC_IS_OFFSET);
  if ((Pending & FATAL_IS) != 0) { CompletionHold (0x46); return EFI_DEVICE_ERROR; }
  if ((Pending & OWNED_TRANSFER_COMPLETION) != 0) {
    CompletionHold (0x4C); return EFI_DEVICE_ERROR;
  }
  if (!FormatStillSame ()) { CompletionHold (0x44); return EFI_DEVICE_ERROR; }
  if (!OwnedIdle ()) { return EFI_NOT_READY; }
  if (Opcode == 0x16) {
    Status = QueryReady ();
    if (EFI_ERROR (Status)) { return Status; }
  }
  if (!OwnedIdle () || (HRead (UFS_HC_STATUS_OFFSET) & 0xB) != 0xB) { return EFI_NOT_READY; }
  Status = MakeRequest (Lun, Opcode, Bytes, Tag);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nUfsDiag.DmaPhase = 1;
  if (!PreparedDmaValid ()) { return EFI_SECURITY_VIOLATION; }
  mN976nUfsDiag.DmaPreChecks = BIT0;
  /* A post-DMA mismatch alone cannot distinguish bad initialization/cache
     visibility from a transfer-side change. Prove the full prepared image
     survives the same clean/invalidate path BEFORE handing it to hardware.
     This is CPU readback evidence, not an independent physical-memory view. */
  WriteBackInvalidateDataCacheRange (mDma, UFS_BYTES); MemoryFence ();
  mN976nUfsDiag.DmaPhase = 2;
  if (!PreparedDmaValid ()) { return EFI_SECURITY_VIOLATION; }
  mN976nUfsDiag.DmaPreChecks |= BIT1;
  /* The readback populated clean cache lines. Re-seal all isolated pages,
     then do not CPU-read/write them again until completion or quarantine. */
  WriteBackInvalidateDataCacheRange (mDma, UFS_BYTES); MemoryFence ();
  mN976nUfsDiag.DmaPreChecks |= BIT2;
  mN976nUfsDiag.DmaPhase = 3;
  if (!OwnedIdle ()) { CompletionHold (0x4A); return EFI_DEVICE_ERROR; }
  VWrite (VENDOR_NEXUS, Nexus);
  if (VRead (VENDOR_NEXUS) != Nexus) {
    return EFI_DEVICE_ERROR;
  }
  ObserveTransferRegisters (TRUE);
  /* Do not submit after the added observation has revealed a busy/faulted
     controller. This is evidence of drift, not permission to clear or retry. */
  if (mN976nUfsDiag.PreDbr != 0 ||
      (mN976nUfsDiag.PreIs & (FATAL_IS | OWNED_TRANSFER_COMPLETION)) != 0 ||
      (mN976nUfsDiag.PreHcs & 0xB) != 0xB) {
    CompletionHold (0x4B); return EFI_DEVICE_ERROR;
  }
  mN976nUfsReport.CommandCount++;
  mIssued = TRUE;
  mN976nUfsDiag.Snapshot = 2;
  HWrite (UFS_HC_UTRLDBR_OFFSET, 1);
  /* Samsung's SSU is 10 seconds and REQUEST SENSE 1 second. Preserve bounded
     elapsed-time AND iteration limits, but do not copy Linux's retries. */
  UINT32 TimeoutUs = Opcode == 0x16 ?
    (mQueryOpcode == 5 ? QUERY_FLAG_TIMEOUT_US : QUERY_ATTR_TIMEOUT_US) :
    (Opcode == 0x1B ? START_STOP_TIMEOUT_US :
     (Opcode == 0x03 ? REQUEST_SENSE_TIMEOUT_US : CONTROL_TIMEOUT_US));
  if (!WaitValueUs (UFS_HC_UTRLDBR_OFFSET, 1, 0, TimeoutUs)) {
    mN976nUfsReport.LastDoorbell = HRead (UFS_HC_UTRLDBR_OFFSET);
    ObserveTransferRegisters (FALSE);
    Quarantine (0x41);
    ObservePendingDma ();
    return EFI_TIMEOUT;
  }
  ObserveTransferRegisters (FALSE);
  mN976nUfsReport.LastDoorbell = HRead (UFS_HC_UTRLDBR_OFFSET);
  if (mN976nUfsReport.LastDoorbell != 0 || HRead (UFS_HC_UTMRLDBR_OFFSET) != 0) {
    Quarantine (0x42); return EFI_TIMEOUT;
  }
  if (!FormatStillSame ()) { CompletionHold (0x45); return EFI_DEVICE_ERROR; }
  mN976nUfsDiag.Snapshot = 3;
  MemoryFence (); InvalidateDataCacheRange (mDma, UFS_BYTES); MemoryFence ();
  mN976nUfsDiag.DmaPhase = 4;
  mN976nUfsDiag.DataTail = Be64 (mDma + 5 * 4096 + 16);
  ImageValid = Immutable (Bytes);
  ObserveDataPadding (Bytes);
  if (!ImageValid) {
    /* Bounded raw evidence after DBR retirement, never a validated reply.
       Keep Snapshot3, no BIT3, no response parsing, ACK or follow-up command. */
    mN976nUfsDiag.ObservedOcs = Trd->Ocs;
    mN976nUfsDiag.ObservedHeader0 = Be64 ((CONST UINT8 *)Response);
    mN976nUfsDiag.ObservedHeader1 = Be64 ((CONST UINT8 *)Response + 8);
    mN976nUfsDiag.ObservationFlags |= BIT4;
    return EFI_SECURITY_VIOLATION;
  }
  mN976nUfsReport.Checks |= 0x40;
  mN976nUfsReport.Ocs = Trd->Ocs;
  mN976nUfsReport.Response = Response->Response;
  mN976nUfsReport.ScsiStatus = Response->Status;
  mN976nUfsReport.Residual = SwapBytes32 (Response->ResTranCount);
  mN976nUfsReport.SenseBytes = SwapBytes16 (Response->SenseDataLen);
  CaptureSense (Response->SenseData);
  mN976nUfsDiag.RawHeader0 = Be64 ((CONST UINT8 *)Response);
  mN976nUfsDiag.RawHeader1 = Be64 ((CONST UINT8 *)Response + 8);
  /* Capture raw status; sticky IS is evidence, never proof of completion. */
  mN976nUfsDiag.CompletionIs = HRead (UFS_HC_IS_OFFSET);
  mN976nUfsDiag.Snapshot = 4;
  mN976nUfsDiag.ObservedOcs = Trd->Ocs;
  mN976nUfsDiag.ObservedHeader0 = mN976nUfsDiag.RawHeader0;
  mN976nUfsDiag.ObservedHeader1 = mN976nUfsDiag.RawHeader1;
  mN976nUfsDiag.ObservationFlags |= BIT3;
  if ((mN976nUfsDiag.CompletionIs & FATAL_IS) != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_FATAL_IS; }
  if (Trd->Ocs != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_OCS; }
  if (Response->TaskTag != Tag) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_TAG; }
  if (!ValidateCompletionState ()) { return EFI_DEVICE_ERROR; }
  if (Opcode == 0x16) {
    CONST UINT8 *Q = (CONST UINT8 *)Response;
    /* READ_FLAG/READ_ATTR return their value inside the response UPIU, not
       through PRDT. Identity, read function, echoed selector and all reserved
       bytes are checked before the value can authorize a power operation. */
    if (Q[0] != 0x36 || Q[1] != 0 || Q[2] != 0 || Q[4] != 0 || Q[5] != 1 ||
        Q[6] != 0 || !BytesAre (Q + 7, 5, 0) || Q[12] != mQueryOpcode ||
        Q[13] != mQueryIdn || !BytesAre (Q + 14, 6, 0) || !BytesAre (Q + 24, 8, 0)) {
      mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_QUERY;
    }
    return mN976nUfsDiag.FailureMask == 0 ? AckCompletion () : EFI_DEVICE_ERROR;
  }
  if (Response->TransCode != 0x21) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_TRANS_CODE; }
  if (Response->Lun != Lun) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_LUN; }
  if (Response->Response != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_RESPONSE; }
  if (Response->EhsLen != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_EHS; }
  if (Response->CmdSet != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_CMD_SET; }
  if (Response->Dd != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_DD; }
  if (Response->Hd != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_HD; }
  if (mN976nUfsReport.SenseBytes > sizeof (Response->SenseData)) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_LEN_OVERFLOW; }
  if (SwapBytes16 (Response->DataSegLen) > sizeof (Response->SenseData) + 2) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_DATA_SEG_OVERFLOW; }
  if (mN976nUfsReport.SenseBytes != 0 && SwapBytes16 (Response->DataSegLen) != mN976nUfsReport.SenseBytes + 2) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_SEGMENT_MISMATCH; }
  if (mN976nUfsReport.Residual > Bytes) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_RESIDUAL_EXCEEDS; }
  if (mN976nUfsReport.SenseBytes != 0 && !DecodeSense (Response->SenseData, (UINT32)mN976nUfsReport.SenseBytes)) {
    mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_FORMAT;
  }
  if (Response->Status == 2) {
    if ((mN976nUfsDiag.SenseFormat & BIT8) == 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_FORMAT; }
    /* Samsung reports valid CHECK CONDITION responses with OCS7/Response1.
       They remain failed commands. Only recognized current sense can select
       a bounded recovery or absent-LU branch; no data is accepted from them. */
    UINT64 Transport = mN976nUfsDiag.FailureMask & ~(N976N_UFS_DIAG_OCS | N976N_UFS_DIAG_RESPONSE);
    BOOLEAN ErrorPair = (Trd->Ocs == 0 && Response->Response == 0) ||
      (Trd->Ocs == 7 && Response->Response == 1);
    if (Transport != 0 || !ErrorPair || Response->Flags != 0 ||
        (mN976nUfsDiag.SenseFormat & (BIT8 | BIT9)) != (BIT8 | BIT9)) { return EFI_DEVICE_ERROR; }
    Status = AckCompletion ();
    if (EFI_ERROR (Status)) { return Status; }
    if (Lun < 8 && mN976nUfsReport.SenseKey == 5 && mN976nUfsReport.Asc == 0x25 &&
        mN976nUfsReport.Ascq == 0) { return EFI_NOT_FOUND; }
    if (mN976nUfsReport.SenseKey == 2 || mN976nUfsReport.SenseKey == 6) { return EFI_NOT_READY; }
    return EFI_DEVICE_ERROR;
  }
  if (mN976nUfsDiag.FailureMask != 0) { return EFI_DEVICE_ERROR; }
  if (Response->Status != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_STATUS; }
  if (mN976nUfsReport.Residual != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_RESIDUAL; }
  if (Response->Flags != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_FLAGS; }
  if (mN976nUfsReport.SenseBytes != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_LEN; }
  if (SwapBytes16 (Response->DataSegLen) != 0) { mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_DATA_SEG; }
  return mN976nUfsDiag.FailureMask == 0 ? AckCompletion () : EFI_DEVICE_ERROR;
}

STATIC EFI_STATUS EFIAPI ReadGptBlock (VOID *Context, UINT64 Lba, UINT8 *Block) {
  EFI_STATUS Status;
  UINT8 Lun = (UINT8)mN976nUfsReport.Lun;
  if (Context != &mN976nUfsReport || Block == NULL || mGptReadActive || mVolumeSessionActive || mVolumeReadActive ||
      Lba > MAX_UINT32) { return EFI_INVALID_PARAMETER; }
  mGptReadActive = TRUE;
  if (!GptReadAllowed (Lun, 4096, Lba)) {
    mGptReadActive = FALSE; return EFI_INVALID_PARAMETER;
  }
  mReadLba = (UINT32)Lba;
  Status = Transfer (Lun, 0x28, 4096);
  mReadLba = 0; mGptReadActive = FALSE;
  if (EFI_ERROR (Status)) { return Status; }
  /* Transfer has verified quiescence, ownership, cache invalidation, guards,
     exact logical completion and ACK. Copy to CPU-only parser storage now. */
  CopyMem (Block, mDma + 5 * 4096, 4096);
  mN976nUfsReport.ReadCount++; mN976nUfsReport.Checks |= 0x20;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI ReadSystemBlock (VOID *Context, UINT64 Lba, UINT8 *Block) {
  EFI_STATUS Status;
  UINT8 Lun = (UINT8)mN976nUfsReport.Lun;
  if (Context != &mN976nUfsReport || mSystemReadActive || mGptReadActive || mVolumeSessionActive || mVolumeReadActive ||
      !N976nSystemReadAllowed (Lba, Block)) return EFI_INVALID_PARAMETER;
  mSystemReadActive = TRUE;
  if (!SystemReadAllowed (Lun, 4096, Lba)) {
    mSystemReadActive = FALSE; return EFI_ACCESS_DENIED;
  }
  mReadLba = (UINT32)Lba;
  Status = Transfer (Lun, 0x28, 4096);
  mReadLba = 0; mSystemReadActive = FALSE;
  if (EFI_ERROR (Status)) return Status;
  /* Completed/ACKed, idle, invalidated and guarded private DMA; the pending
     parser capability still requires the exact destination and LBA. */
  if (!N976nSystemReadAllowed (Lba, Block)) return EFI_SECURITY_VIOLATION;
  CopyMem (Block, mDma + 5 * 4096, 4096);
  ++mSystemReads; ++mN976nUfsReport.ReadCount; mN976nUfsReport.Checks |= 0x20;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI ReadVolumeBlock (VOID *Context, UINT64 Lba, UINT8 *Block) {
  if (mUfsExitClosing) { return EFI_ACCESS_DENIED; }
  EFI_STATUS Status;
  UINT8 Lun = (UINT8)mN976nUfsReport.Lun;
  if (Context != &mN976nUfsReport || !mVolumeSessionActive || mVolumeReadActive ||
      mSystemReadActive || mGptReadActive || !N976nSystemVolumeReadAllowed (Lba, Block) ||
      !N976nUfsCpuRangeAllowed (Block, 4096)) return EFI_INVALID_PARAMETER;
  mVolumeReadActive = TRUE;
  if (!VolumeReadAllowed (Lun, 4096, Lba)) {
    mVolumeReadActive = FALSE; return EFI_ACCESS_DENIED;
  }
  mReadLba = (UINT32)Lba;
  Status = Transfer (Lun, 0x28, 4096);
  mReadLba = 0; mVolumeReadActive = FALSE;
  if (EFI_ERROR (Status)) return Status;
  if (!N976nSystemVolumeReadAllowed (Lba, Block) || !N976nUfsCpuRangeAllowed (Block, 4096))
    return EFI_SECURITY_VIOLATION;
  CopyMem (Block, mDma + 5 * 4096, 4096);
  if (!N976nSystemVolumeReadAllowed (Lba, Block) || !N976nUfsCpuRangeAllowed (Block, 4096) ||
      CompareMem (Block, mDma + 5 * 4096, 4096) != 0) return EFI_SECURITY_VIOLATION;
  ++mVolumeReads; ++mN976nUfsReport.ReadCount; mN976nUfsReport.Checks |= 0x20;
  return EFI_SUCCESS;
}
STATIC BOOLEAN EFIAPI CheckPartitionBuffer (VOID *Context, VOID *Buffer, UINTN Bytes) {
  UINT64 Address = (UINT64)(UINTN)Buffer, Attr;
  if (Context != &mN976nUfsReport || (mQueryExperiment < 5 || mQueryExperiment > 9) || !mPartitionSessionActive ||
      mPartitionMemory == NULL || mDma == NULL || Bytes == 0 ||
      Address > MAX_UINT64 - Bytes ||
      (mQueryExperiment >= 6 ?
       (!N976nServiceBufferOwned (Buffer, Bytes) && !N976nServiceStorageOwned (Buffer, Bytes)) :
       (!N976nBlockBufferOwned (Buffer, Bytes) && !N976nBlockStorageOwned (Buffer, Bytes))) ||
      !Contains (mUfsHandoff->HeapBase, mUfsHandoff->HeapSize, Address, Bytes) ||
      (Address < (UINT64)(UINTN)mDma + UFS_BYTES && (UINT64)(UINTN)mDma < Address + Bytes)) {
    return FALSE;
  }
  for (UINT64 Page = Address & ~4095ULL; Page <= ((Address + Bytes - 1) & ~4095ULL); Page += 4096) {
    if (EFI_ERROR (mPartitionMemory->GetMemoryAttributes (mPartitionMemory, Page, 4096, &Attr)) ||
        (Attr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) { return FALSE; }
  }
  return TRUE;
}
/* CPU destination permission is necessary but not sufficient. The filesystem
 * adapter separately admits only its own storage, one mount stack object and
 * the exact cache allocation of the pinned FAT instance. No general heap API. */
BOOLEAN N976nUfsCpuRangeAllowed (CONST VOID *Buffer, UINTN Bytes) {
  UINT64 Address = (UINT64)(UINTN)Buffer, Attr;
  if (mUfsHandoff == NULL || Buffer == NULL || Bytes == 0 || Address > MAX_UINT64 - Bytes ||
      (!Contains (mUfsHandoff->HeapBase, mUfsHandoff->HeapSize, Address, Bytes) &&
       !Contains (mUfsHandoff->StackBase, mUfsHandoff->StackSize, Address, Bytes)) ||
      (mDma != NULL && Address < (UINT64)(UINTN)mDma + UFS_BYTES &&
       (UINT64)(UINTN)mDma < Address + Bytes)) { return FALSE; }
  if (mPartitionMemory == NULL && EFI_ERROR (gBS->LocateProtocol (
      &gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mPartitionMemory))) { return FALSE; }
  for (UINT64 Page = Address & ~4095ULL; Page <= ((Address + Bytes - 1) & ~4095ULL); Page += 4096) {
    if (EFI_ERROR (mPartitionMemory->GetMemoryAttributes (mPartitionMemory, Page, 4096, &Attr)) ||
        (Attr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) { return FALSE; }
  }
  return TRUE;
}
STATIC UINTN EFIAPI PartitionBudget (VOID *Context) {
  UINTN Limit = PartitionDataLimit ();
  if (Context != &mN976nUfsReport || !mPartitionSessionActive || mPartitionReads >= Limit ||
      mN976nUfsReport.CommandCount >= CommandLimit () - 3) { return 0; }
  UINTN Left = (UINTN)(CommandLimit () - 3 - mN976nUfsReport.CommandCount);
  return MIN (Left, Limit - mPartitionReads);
}
STATIC EFI_STATUS EFIAPI ReadPartitionBlock (VOID *Context, UINT64 Lba, UINT8 *Block) {
  EFI_STATUS Status;
  if (mPartitionReadActive || mGptReadActive || Lba > MAX_UINT32 ||
      (mQueryExperiment >= 6 ? !N976nServiceBufferOwned (Block, 4096) :
       !N976nBlockBufferOwned (Block, 4096)) ||
      !CheckPartitionBuffer (Context, Block, 4096)) { return EFI_INVALID_PARAMETER; }
  mPartitionReadActive = TRUE;
  if (!PartitionReadAllowed ((UINT8)mN976nUfsReport.Lun, 4096, Lba)) {
    mPartitionReadActive = FALSE; return EFI_INVALID_PARAMETER;
  }
  mReadLba = (UINT32)Lba;
  Status = Transfer ((UINT8)mN976nUfsReport.Lun, 0x28, 4096);
  mReadLba = 0; mPartitionReadActive = FALSE;
  if (EFI_ERROR (Status)) { return Status; }
  /* Same guarded DMA bounce page: caller addresses are never put in PRDT. */
  CopyMem (Block, mDma + 5 * 4096, 4096);
  ++mPartitionReads; ++mN976nUfsReport.ReadCount;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS Query (UINT8 Opcode, UINT8 Idn, UINT32 *Value) {
  EFI_STATUS Status;
  mQueryOpcode = Opcode; mQueryIdn = Idn;
  Status = Transfer (0, 0x16, 0);
  if (!EFI_ERROR (Status)) {
    *Value = Be32 (mDma + 3 * 4096 + RESPONSE_OFFSET + 20);
    mN976nUfsDiag.QueryAccepted++;
  }
  return Status;
}
STATIC EFI_STATUS QueryExperiment (VOID) {
  UINT32 Value = 0;
  EFI_STATUS Status;
  if (mQueryExperiment == 1) {
    for (UINTN I = 0; I < 2; ++I) {
      Status = Query (5, 1, &Value);
      if (EFI_ERROR (Status)) { return Status; }
      mN976nUfsDiag.InitFlag = Value;
      if (Value != 0) { return EFI_NOT_READY; }
    }
  } else if (mQueryExperiment == 2) {
    Status = Query (3, 2, &Value);
    if (EFI_ERROR (Status)) { return Status; }
    mN976nUfsDiag.PowerInitial = Value; mN976nUfsDiag.PowerFinal = Value;
    if (Value != UFS_POWER_ACTIVE_RAW && Value != UFS_POWER_SLEEP_RAW) { return EFI_UNSUPPORTED; }
  } else {
    return EFI_INVALID_PARAMETER;
  }
  /* Transport/query observation only: neither mode issues a power transition,
     TUR, capacity or media command, or establishes that the link is ACTIVE. */
  mN976nUfsReport.Outcome = N976N_UFS_QUERY_OBSERVED;
  return EFI_SUCCESS;
}
STATIC EFI_STATUS SetPower (UINT8 Mode) {
  EFI_STATUS Status;
  UINT32 Value = 0;
  UINT32 Expected;
  /* CDB power conditions are 1/2/3, whereas bCurrentPowerMode encodes
     0x11/0x22/0x33. An unknown condition must issue no command. */
  switch (Mode) {
    case 1: Expected = UFS_POWER_ACTIVE_RAW; break;
    case 2: Expected = UFS_POWER_SLEEP_RAW; break;
    case 3: Expected = UFS_POWER_DOWN_RAW; break;
    default: return EFI_INVALID_PARAMETER;
  }
  mSsuMode = Mode;
  Status = Transfer (0xD0, 0x1B, 0);
  if (EFI_ERROR (Status)) { return Status; }
  Status = Query (3, 2, &Value);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nUfsDiag.PowerFinal = Value;
  return Value == Expected ? EFI_SUCCESS : EFI_DEVICE_ERROR;
}
STATIC EFI_STATUS PrepareDevice (VOID) {
  EFI_STATUS Status;
  UINT32 Value = 0;
  Status = Query (5, 1, &Value);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nUfsDiag.InitFlag = Value;
  if (Value != 0) { return EFI_NOT_READY; } /* Never SET fDeviceInit here. */
  mN976nUfsDiag.Prepare |= 1;
  Status = Query (3, 2, &Value);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nUfsDiag.PowerInitial = Value; mN976nUfsDiag.PowerFinal = Value;
  if (Value != UFS_POWER_ACTIVE_RAW && Value != UFS_POWER_SLEEP_RAW &&
      Value != UFS_POWER_DOWN_RAW) { return EFI_UNSUPPORTED; }
  mN976nUfsDiag.Prepare |= 2;
  if (Value == UFS_POWER_ACTIVE_RAW) { mN976nUfsDiag.Prepare |= 0x10; return EFI_SUCCESS; }
  /* The UFS device WLUN owns device power. REQUEST SENSE clears its pending
     unit attention before SSU, matching Samsung's power transition order.
     A current 02/04/02 from a known sleeping/powered-down WLUN describes the
     need for initialization; it permits only the SSU attempt, not ready/data
     success. Active state still requires a successful SSU and exact query. */
  Status = Transfer (0xD0, 0x03, 18);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nUfsReport.SenseBytes = 18;
  CaptureSense (mDma + 5 * 4096);
  if (!DecodeSense (mDma + 5 * 4096, 18) ||
      (mN976nUfsDiag.SenseFormat & BIT9) == 0 ||
      !((mN976nUfsReport.SenseKey == 0 && mN976nUfsReport.Asc == 0 && mN976nUfsReport.Ascq == 0) ||
        (mN976nUfsReport.SenseKey == 6 && mN976nUfsReport.Asc == 0x29 && mN976nUfsReport.Ascq == 0) ||
        (mN976nUfsReport.SenseKey == 2 && mN976nUfsReport.Asc == 4 && mN976nUfsReport.Ascq == 2 &&
         (mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
          mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)))) {
    mN976nUfsDiag.FailureMask |= N976N_UFS_DIAG_SENSE_FORMAT;
    return EFI_DEVICE_ERROR;
  }
  mN976nUfsDiag.Prepare |= 4;
  /* Mark before issue: an ambiguous completion may already have changed power. */
  mPowerChanged = TRUE; mN976nUfsDiag.PowerRestore = 1;
  mN976nUfsDiag.PowerFinal = 0xFF; mN976nUfsDiag.Prepare |= 8;
  Status = SetPower (1);
  if (!EFI_ERROR (Status)) { mN976nUfsDiag.Prepare |= 0x10; }
  return Status;
}
STATIC EFI_STATUS ReadyLun (UINT8 Lun) {
  EFI_STATUS Status = Transfer (Lun, 0, 0);
  /* Only one current power-on/reset unit attention retry; NOT READY is never
     treated as an absent LU or cured by unbounded polling. */
  if (Status == EFI_NOT_READY && mN976nUfsReport.SenseKey == 6 &&
      mN976nUfsReport.Asc == 0x29 && mN976nUfsReport.Ascq == 0) {
    Status = Transfer (Lun, 0, 0);
  }
  if (!EFI_ERROR (Status)) { mN976nUfsDiag.Prepare |= 0x20; }
  return Status;
}
STATIC BOOLEAN RestorePower (VOID) {
  if (mUfsExitClosing) { return FALSE; }
  EFI_STATUS Status;
  N976N_UFS_REPORT SavedReport;
  N976N_UFS_DIAG SavedDiag;
  UINT64 Count, Checks, RestoreBits, Accepted, Acks;
  UINT32 Value = 0;
  UINT64 Original = mN976nUfsDiag.PowerInitial;
  if (!mPowerChanged) { return TRUE; }
  if (mN976nUfsReport.Quarantined || mN976nUfsReport.Status == EFI_SECURITY_VIOLATION) {
    CompletionHold (0x61); return FALSE;
  }
  if (Original != UFS_POWER_SLEEP_RAW && Original != UFS_POWER_DOWN_RAW) {
    CompletionHold (0x62); return FALSE;
  }
  /* Preserve the operation's result after successful cleanup. On cleanup
     failure retain the failing restoration command and terminal hold instead. */
  CopyMem (&SavedReport, (CONST VOID *)&mN976nUfsReport, sizeof (SavedReport));
  CopyMem (&SavedDiag, (CONST VOID *)&mN976nUfsDiag, sizeof (SavedDiag));
  mN976nUfsDiag.PowerFinal = 0xFF;
  Status = Query (3, 2, &Value);
  if (EFI_ERROR (Status)) { CompletionHold (0x62); return FALSE; }
  mN976nUfsDiag.PowerFinal = Value;
  /* Restore only the exact state observed before our wake attempt. If it is
     already restored, do not send SSU. A third state is unexplained drift,
     not permission to guess a transition or downgrade PowerDown to Sleep. */
  if (Value != UFS_POWER_ACTIVE_RAW && Value != Original) {
    CompletionHold (0x62); return FALSE;
  }
  if (Value == UFS_POWER_ACTIVE_RAW) {
    mN976nUfsDiag.PowerRestore |= 2;
    Status = SetPower (Original == UFS_POWER_SLEEP_RAW ? 2 : 3);
    if (EFI_ERROR (Status)) { CompletionHold (0x62); return FALSE; }
  }
  RestoreBits = mN976nUfsDiag.PowerRestore | 4;
  Count = mN976nUfsReport.CommandCount; Checks = mN976nUfsReport.Checks;
  Accepted = mN976nUfsDiag.QueryAccepted; Acks = mN976nUfsDiag.AckCount;
  CopyMem ((VOID *)&mN976nUfsReport, &SavedReport, sizeof (SavedReport));
  CopyMem ((VOID *)&mN976nUfsDiag, &SavedDiag, sizeof (SavedDiag));
  mN976nUfsReport.CommandCount = Count; mN976nUfsReport.Checks = Checks;
  mN976nUfsDiag.PowerFinal = Original; mN976nUfsDiag.PowerRestore = RestoreBits;
  mN976nUfsDiag.QueryAccepted = Accepted; mN976nUfsDiag.AckCount = Acks;
  mPowerChanged = FALSE;
  return TRUE;
}

STATIC BOOLEAN Restore (VOID) {
  if (mUfsExitClosing) { return FALSE; }
  UINT32 Pending;
  if (!mControllerTouched) { return TRUE; }
  if (mN976nUfsReport.Quarantined || HRead (UFS_HC_UTRLDBR_OFFSET) != 0 ||
      HRead (UFS_HC_UTMRLDBR_OFFSET) != 0) { Quarantine (0x51); return FALSE; }
  if (!FormatStillSame ()) { CompletionHold (0x58); return FALSE; }
  HWrite (UFS_HC_UTRLRSR_OFFSET, 0);
  if (!WaitValue (UFS_HC_UTRLRSR_OFFSET, 1, 0)) { Quarantine (0x52); return FALSE; }
  if (HRead (UFS_HC_UTRLDBR_OFFSET) != 0 || HRead (UFS_HC_UTMRLDBR_OFFSET) != 0 ||
      HRead (UFS_HC_ENABLE_OFFSET) != 1) {
    Quarantine (0x54); return FALSE;
  }
  if (!FormatStillSame ()) { CompletionHold (0x58); return FALSE; }
  if ((HRead (UFS_HC_IS_OFFSET) & FATAL_IS) != 0) {
    CompletionHold (0x56); return FALSE;
  }
  mN976nUfsReport.Restore |= 1;
  /* UTRLBA's reserved low bits are opaque bootloader state, not a pointer we
     may round down or dereference. Restore the exact captured register pair;
     the separate, page-aligned ring we used was allocated and validated here. */
  HWrite (UFS_HC_UTRLBA_OFFSET, (UINT32)mN976nUfsReport.TrlBase);
  HWrite (UFS_HC_UTRLBAU_OFFSET, (UINT32)mN976nUfsReport.TrlBaseUpper);
  VWrite (VENDOR_NEXUS, (UINT32)mN976nUfsReport.Nexus);
  HWrite (UFS_HC_AHIT_OFFSET, (UINT32)mN976nUfsReport.Ahit);
  HWrite (UFS_HC_UTRLRSR_OFFSET, (UINT32)mN976nUfsReport.TrlRun);
  if (HRead (UFS_HC_UTRLBA_OFFSET) != mN976nUfsReport.TrlBase ||
      HRead (UFS_HC_UTRLBAU_OFFSET) != mN976nUfsReport.TrlBaseUpper ||
      HRead (UFS_HC_UTRLRSR_OFFSET) != mN976nUfsReport.TrlRun ||
      HRead (UFS_HC_IE_OFFSET) != 0 ||
      HRead (UFS_HC_AHIT_OFFSET) != mN976nUfsReport.Ahit ||
      VRead (VENDOR_NEXUS) != mN976nUfsReport.Nexus ||
      HRead (UFS_HC_UTRLDBR_OFFSET) != 0 || HRead (UFS_HC_UTMRLDBR_OFFSET) != 0) {
    Quarantine (0x53); return FALSE;
  }
  mN976nUfsReport.Restore |= 2;
  if (!FormatStillSame ()) { CompletionHold (0x58); return FALSE; }
  Pending = HRead (UFS_HC_IS_OFFSET);
  /* Only validated owned completions were acknowledged. Preserve all other
     pending evidence; never expose new interrupts through the inherited mask. */
  if ((Pending & FATAL_IS) != 0 ||
      (Pending & ~(UINT32)mN976nUfsReport.Is & (UINT32)mN976nUfsReport.Ie) != 0) {
    CompletionHold (0x55); return FALSE;
  }
  HWrite (UFS_HC_IE_OFFSET, (UINT32)mN976nUfsReport.Ie);
  if (HRead (UFS_HC_IE_OFFSET) != mN976nUfsReport.Ie) {
    HWrite (UFS_HC_IE_OFFSET, 0);
    CompletionHold (0x57); return FALSE;
  }
  if (mDma != NULL) {
    MemoryFence (); InvalidateDataCacheRange (mDma, UFS_BYTES); MemoryFence ();
    if (!Guards ()) { mN976nUfsReport.Status = EFI_SECURITY_VIOLATION; return FALSE; }
  }
  mN976nUfsReport.Restore |= 4;
  mN976nUfsReport.Checks |= 0x80;
  return TRUE;
}

STATIC VOID CleanupUfs (VOID) {
  if (mUfsExitClosing) { return; }
  if (!mN976nUfsReport.Quarantined && !RestorePower ()) {
    mN976nUfsReport.Outcome = N976N_UFS_QUARANTINED;
  }
  if (!mN976nUfsReport.Quarantined && !Restore ()) {
    mN976nUfsReport.Outcome = N976N_UFS_FAILED;
  }
}
/* Native error return is an observed Windows result, not a transport error.
 * Successful transport retirement still requires exact source/image revocation
 * and no live execution dependency. Runtime counters prove partial reads only. */
STATIC BOOLEAN SystemWindowsRetired (VOID) {
  UINT64 Checks = 1;
  if (N976nUfsExecutionActive () || N976nSystemVolumeExecutionActive () ||
      !N976nUfsImageClosed () || !N976nHighRamPublished () ||
      mN976nUfsImageReport.Magic != N976N_UFS_IMAGE_MAGIC ||
      mN976nUfsImageReport.Version != 1 || mN976nUfsImageReport.Size != sizeof (mN976nUfsImageReport) ||
      mN976nUfsImageReport.Phase != 8 || mN976nUfsImageReport.Status != EFI_SUCCESS ||
      mN976nUfsImageReport.Checks != N976N_UFS_IMAGE_CHECKS ||
      mN976nUfsImageReport.CloseChecks != N976N_UFS_IMAGE_CLOSE_CHECKS ||
      mN976nUfsImageReport.SourceBytes != N976N_BOOT_WINDOWS_BYTES ||
      mN976nUfsImageReport.StagedBytes != N976N_BOOT_WINDOWS_BYTES ||
      mN976nUfsImageReport.FreedAttributes != EFI_MEMORY_XP ||
      mN976nWindowsReport.Magic != N976N_WINDOWS_MAGIC || mN976nWindowsReport.Version != 1 ||
      mN976nWindowsReport.Size != sizeof (mN976nWindowsReport) ||
      mN976nWindowsReport.Outcome != N976N_WINDOWS_OUTCOME_RETURNED ||
      mN976nWindowsReport.Stage != 7 || mN976nWindowsReport.Checks != 0xF9 ||
      mN976nWindowsReport.LoadCount != 1 || mN976nWindowsReport.StartCount != 1 ||
      mN976nWindowsReport.LoadStatus != EFI_SUCCESS ||
      mN976nWindowsReport.Status != mN976nWindowsReport.StartStatus ||
      mN976nWindowsReport.AutoUnloadStatus != EFI_INVALID_PARAMETER ||
      mN976nWindowsReport.FreedAttributes != EFI_MEMORY_XP ||
      mN976nSystemRunReport.Magic != SIGNATURE_64('N','9','7','6','R','U','N','1') ||
      mN976nSystemRunReport.Version != 1 || mN976nSystemRunReport.Size != sizeof (mN976nSystemRunReport) ||
      mN976nSystemRunReport.Phase != 3 ||
      mN976nSystemRunReport.HighCalls > mN976nSystemRunReport.Calls ||
      mN976nSystemRunReport.HighBytes > mN976nSystemRunReport.Bytes ||
      mN976nSystemRunReport.WimBytes > mN976nSystemRunReport.Bytes ||
      mN976nSystemRunReport.SdiBytes > mN976nSystemRunReport.Bytes - mN976nSystemRunReport.WimBytes ||
      ((mN976nSystemRunReport.Calls == 0) != (mN976nSystemRunReport.Bytes == 0)) ||
      ((mN976nSystemRunReport.HighCalls == 0) != (mN976nSystemRunReport.HighBytes == 0))) return FALSE;
  if (mN976nSystemRunReport.Calls) Checks |= 2;
  if (mN976nSystemRunReport.SdiBytes) Checks |= 4;
  if (mN976nSystemRunReport.WimBytes) Checks |= 8;
  if (mN976nSystemRunReport.HighCalls) Checks |= 16;
  if (mN976nSystemRunReport.Checks != Checks) return FALSE;
  if (mN976nSystemRunReport.Rejected)
    return mN976nSystemRunReport.Reason == 1 && EFI_ERROR (mN976nSystemRunReport.Status);
  return mN976nSystemRunReport.Reason == 0 &&
    mN976nSystemRunReport.Status == (mN976nSystemRunReport.Calls ? EFI_SUCCESS : EFI_NOT_READY);
}
STATIC VOID FinalizeUfsReport (VOID) {
  if (mN976nUfsReport.Quarantined) { mN976nUfsReport.Outcome = N976N_UFS_QUARANTINED; }
  else if (mN976nUfsReport.Outcome == N976N_UFS_VOLUME &&
           mQueryExperiment == 12 && mN976nUfsReport.Status == EFI_SUCCESS &&
           mN976nUfsReport.Checks == 0xFF && mN976nUfsReport.Restore == 7 &&
           !mPowerChanged && !mServiceLease && !mPartitionSessionActive &&
           !mPartitionReadActive && !mGptReadActive && !mSystemReadActive &&
           !mVolumeSessionActive && !mVolumeReadActive && N976nSystemVolumeClosed () &&
           N976nSystemProbeClosed () && mN976nSystemReport.Phase == 8 &&
           mN976nSystemReport.Status == EFI_SUCCESS && mN976nSystemReport.Checks == N976N_SYSTEM_CHECKS &&
           mN976nSystemReport.ReadCount == 2 && mSystemReads == 2 &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS && mN976nGptReport.Checks == 0xFF &&
           mN976nSystemVolumeReport.Magic == N976N_SYSTEM_VOLUME_MAGIC &&
           mN976nSystemVolumeReport.Version == 2 && mN976nSystemVolumeReport.Size == sizeof (mN976nSystemVolumeReport) &&
           mN976nSystemVolumeReport.Phase == 8 && mN976nSystemVolumeReport.Status == EFI_SUCCESS &&
           mN976nSystemVolumeReport.Checks == N976N_SYSTEM_VOLUME_CHECKS &&
           mN976nSystemVolumeReport.Reason == 0 &&
           mN976nSystemVolumeReport.PartitionIndex == mN976nSystemReport.SystemIndex &&
           mN976nSystemVolumeReport.BudgetBlocks == N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS &&
           mN976nSystemVolumeReport.OwnerChecks == N976N_SYSTEM_VOLUME_OWNER_CHECKS &&
           mN976nSystemVolumeReport.CloseChecks == N976N_SYSTEM_VOLUME_CLOSE_CHECKS &&
           mN976nSystemVolumeReport.FileChecks == N976N_SYSTEM_VOLUME_FILE_CHECKS &&
           mN976nSystemVolumeReport.TableChecks == N976N_SYSTEM_VOLUME_TABLE_CHECKS &&
           mN976nSystemVolumeReport.SystemStart == mN976nSystemReport.SystemStart &&
           mN976nSystemVolumeReport.SystemBlocks == mN976nSystemReport.SystemBlocks &&
           mN976nSystemVolumeReport.VolumeBytes == N976N_SYSTEM_IMAGE_BYTES &&
           mN976nSystemVolumeReport.ReadCount == mVolumeReads && mVolumeReads > 0 &&
           mVolumeReads <= N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS &&
           mN976nSystemVolumeReport.ChunkLoads > 0 &&
           mN976nSystemVolumeReport.ChunkLoads <= N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS &&
           mVolumeReads == mN976nSystemVolumeReport.ChunkLoads * (N976N_SYSTEM_VOLUME_CHUNK_BYTES / 4096) &&
           mN976nSystemVolumeReport.AuthenticatedBytes == mN976nSystemVolumeReport.ChunkLoads * N976N_SYSTEM_VOLUME_CHUNK_BYTES &&
           mN976nSystemVolumeReport.BcdBytes == 16384 && mN976nSystemVolumeReport.SdiBytes == N976N_SYSTEM_VOLUME_SDI_BYTES &&
           mN976nSystemVolumeReport.WimBytes == N976N_SYSTEM_VOLUME_WIM_BYTES && mN976nSystemVolumeReport.Reserved0 == 0 &&
           mN976nSystemVolumeReport.Reserved1 == 0 &&
           N976nHighRamPublished () && mN976nHighRamStageReport[0] == 8 &&
           mN976nHighRamStageReport[1] == EFI_SUCCESS && mN976nHighRamStageReport[2] == 7 &&
           mN976nHighRamStageReport[3] == 0 &&
           mN976nHighRamStageReport[6] == N976N_SYSTEM_VOLUME_SDI_BYTES &&
           mN976nHighRamStageReport[7] == N976N_SYSTEM_VOLUME_WIM_BYTES &&
           mN976nHighRamStageReport[8] == 2 && mN976nHighRamStageReport[9] == 2 &&
           mN976nHighRamStageReport[10] == 3 && mN976nHighRamStageReport[11] == 3 &&
           mN976nHighRamStageReport[14] == 0 && mN976nHighRamStageReport[15] == 0 &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mSystemReads + mVolumeReads &&
           mN976nUfsDiag.AckCount == mN976nUfsReport.CommandCount &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW || mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)) {
    mN976nUfsReport.Phase = 0x10;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_VOLUME &&
           mQueryExperiment == 13 && mN976nUfsReport.Status == EFI_SUCCESS &&
           mN976nUfsReport.Checks == 0xFF && mN976nUfsReport.Restore == 7 &&
           !mPowerChanged && !mServiceLease && !mPartitionSessionActive &&
           !mPartitionReadActive && !mGptReadActive && !mSystemReadActive &&
           !mVolumeSessionActive && !mVolumeReadActive && N976nSystemVolumeClosed () &&
           N976nSystemProbeClosed () && mN976nSystemReport.Phase == 8 &&
           mN976nSystemReport.Status == EFI_SUCCESS && mN976nSystemReport.Checks == N976N_SYSTEM_CHECKS &&
           mN976nSystemReport.ReadCount == 2 && mSystemReads == 2 &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS && mN976nGptReport.Checks == 0xFF &&
           mN976nSystemVolumeReport.Magic == N976N_SYSTEM_VOLUME_MAGIC &&
           mN976nSystemVolumeReport.Version == 3 && mN976nSystemVolumeReport.Size == sizeof (mN976nSystemVolumeReport) &&
           mN976nSystemVolumeReport.Phase == 8 && mN976nSystemVolumeReport.Status == EFI_SUCCESS &&
           mN976nSystemVolumeReport.Checks == N976N_SYSTEM_VOLUME_CHECKS &&
           mN976nSystemVolumeReport.Reason == 0 &&
           mN976nSystemVolumeReport.PartitionIndex == mN976nSystemReport.SystemIndex &&
           mN976nSystemVolumeReport.BudgetBlocks == N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS &&
           mN976nSystemVolumeReport.OwnerChecks == N976N_SYSTEM_VOLUME_OWNER_CHECKS &&
           mN976nSystemVolumeReport.CloseChecks == N976N_SYSTEM_VOLUME_CLOSE_CHECKS &&
           mN976nSystemVolumeReport.FileChecks == N976N_SYSTEM_VOLUME_FILE_CHECKS &&
           mN976nSystemVolumeReport.TableChecks == N976N_SYSTEM_VOLUME_TABLE_CHECKS &&
           mN976nSystemVolumeReport.SystemStart == mN976nSystemReport.SystemStart &&
           mN976nSystemVolumeReport.SystemBlocks == mN976nSystemReport.SystemBlocks &&
           mN976nSystemVolumeReport.VolumeBytes == N976N_SYSTEM_IMAGE_BYTES &&
           mN976nSystemVolumeReport.ReadCount == mVolumeReads && mVolumeReads > 0 &&
           mVolumeReads <= N976N_SYSTEM_VOLUME_MAX_DATA_BLOCKS &&
           mN976nSystemVolumeReport.ChunkLoads > 0 &&
           mN976nSystemVolumeReport.ChunkLoads <= N976N_SYSTEM_VOLUME_MAX_CHUNK_LOADS &&
           mVolumeReads == mN976nSystemVolumeReport.ChunkLoads * (N976N_SYSTEM_VOLUME_CHUNK_BYTES / 4096) &&
           mN976nSystemVolumeReport.AuthenticatedBytes == mN976nSystemVolumeReport.ChunkLoads * N976N_SYSTEM_VOLUME_CHUNK_BYTES &&
           mN976nSystemVolumeReport.BcdBytes == 16384 && mN976nSystemVolumeReport.SdiBytes == 4096 &&
           mN976nSystemVolumeReport.WimBytes == 4096 && mN976nSystemVolumeReport.Reserved0 == 0 &&
           mN976nSystemVolumeReport.Reserved1 == 0 &&
           SystemWindowsRetired () &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mSystemReads + mVolumeReads &&
           mN976nUfsDiag.AckCount == mN976nUfsReport.CommandCount &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW || mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)) {
    mN976nUfsReport.Phase = 0x11;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_SYSTEM &&
           mQueryExperiment == 10 && mN976nUfsReport.Status == EFI_SUCCESS &&
           mN976nUfsReport.Checks == 0xFF && mN976nUfsReport.Restore == 7 &&
           !mPowerChanged && !mServiceLease && !mPartitionSessionActive &&
           !mPartitionReadActive && !mGptReadActive && !mSystemReadActive &&
           !mVolumeSessionActive && !mVolumeReadActive && N976nSystemVolumeClosed () &&
           N976nSystemProbeClosed () && mN976nSystemReport.Phase == 8 &&
           mN976nSystemReport.Magic == N976N_SYSTEM_MAGIC && mN976nSystemReport.Version == 2 &&
           mN976nSystemReport.Size == sizeof (mN976nSystemReport) &&
           mN976nSystemReport.Status == EFI_SUCCESS && mN976nSystemReport.Checks == N976N_SYSTEM_CHECKS &&
           mN976nSystemReport.MapChecks == 0 && mN976nSystemReport.StockChecks == 0 &&
           mN976nSystemReport.ReadCount == 2 && mSystemReads == 2 &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
           mN976nGptReport.Checks == 0xFF &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mSystemReads &&
           mN976nUfsDiag.AckCount == mN976nUfsReport.CommandCount &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)) {
    mN976nUfsReport.Phase = 0xF;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_FILESYSTEM &&
           mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xFF &&
           mN976nUfsReport.Restore == 7 && !mPowerChanged && !mServiceLease &&
           !mPartitionSessionActive && !mPartitionReadActive && !mGptReadActive &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW) &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
           mN976nGptReport.Checks == 0xFF && mN976nServiceReport.Phase == 8 &&
           mN976nServiceReport.Status == EFI_SUCCESS && N976nUfsServiceClosed () &&
           mN976nServiceReport.Checks == 0x83 && mN976nServiceReport.LifeChecks == 8 &&
           mN976nServiceReport.DataBlocks == mPartitionReads &&
           mN976nServiceReport.PartitionStart == mPartitionStart &&
           mN976nServiceReport.PartitionBlocks == mPartitionBlocks &&
           N976nUfsFileSystemClosed () && mN976nFileSystemReport.Phase == 8 &&
           mN976nFileSystemReport.Status == EFI_SUCCESS && mN976nFileSystemReport.Checks == 0xFF &&
           mN976nFileSystemReport.OwnerChecks == 0xF && mN976nFileSystemReport.CloseChecks == 0xF &&
           mN976nFileSystemReport.FileBytes == (mQueryExperiment >= 8 ? N976N_BOOT_WINDOWS_BYTES : 16384) &&
           mN976nFileSystemReport.VerifiedBytes == mN976nFileSystemReport.FileBytes &&
           mN976nFileSystemReport.MissingWim == EFI_NOT_FOUND &&
           mPartitionReads > 0 && mPartitionReads <= PartitionDataLimit () &&
           (mQueryExperiment < 8 || (mPartitionReads > 255 &&
            mN976nUfsDiag.AckCount == mN976nUfsReport.CommandCount)) &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mPartitionReads) {
    mN976nUfsReport.Phase = 0xE;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_SERVICE &&
           mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xFF &&
           mN976nUfsReport.Restore == 7 && !mPowerChanged && !mServiceLease &&
           !mPartitionSessionActive && !mPartitionReadActive && !mGptReadActive &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW) &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
           mN976nGptReport.Checks == 0xFF && mN976nServiceReport.Phase == 8 &&
           mN976nServiceReport.Status == EFI_SUCCESS && mN976nServiceReport.Checks == N976N_SERVICE_CHECKS &&
           mN976nServiceReport.LifeChecks == N976N_SERVICE_LIFE_CHECKS &&
           mN976nServiceReport.RejectChecks == N976N_SERVICE_REJECT_CHECKS &&
           mN976nServiceReport.BlockCalls == 6 && mN976nServiceReport.DiskCalls == 4 &&
           mN976nServiceReport.DataBlocks == N976N_SERVICE_EXPECTED_DATA_BLOCKS &&
           mPartitionReads == N976N_SERVICE_EXPECTED_DATA_BLOCKS &&
           mN976nServiceReport.PartitionStart == mPartitionStart &&
           mN976nServiceReport.PartitionBlocks == mPartitionBlocks &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mPartitionReads) {
    mN976nUfsReport.Phase = 0xD;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_BLOCK &&
           mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xFF &&
           mN976nUfsReport.Restore == 7 && !mPowerChanged &&
           !mPartitionSessionActive && !mPartitionReadActive && !mGptReadActive &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW) &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
           mN976nGptReport.Checks == 0xFF && mN976nBlockReport.Phase == 8 &&
           mN976nBlockReport.Status == EFI_SUCCESS && mN976nBlockReport.Checks == 0xFF &&
           mN976nBlockReport.RejectChecks == 0xFF && mN976nBlockReport.ReadCalls == 2 &&
           mN976nBlockReport.ReadBlocks == 3 && mPartitionReads == 3 &&
           mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount + mPartitionReads) {
    mN976nUfsReport.Phase = 0xC;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_GPT &&
           mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xFF &&
           mN976nUfsReport.Restore == 7 && !mPowerChanged &&
           (mN976nUfsDiag.Prepare & 0x30) == 0x30 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW) &&
           mN976nGptReport.Phase == 8 && mN976nGptReport.Status == EFI_SUCCESS &&
           mN976nGptReport.Checks == 0xFF && mN976nUfsReport.ReadCount == mN976nGptReport.ReadCount) {
    mN976nUfsReport.Phase = 0xB;
  }
  else if (mN976nUfsReport.Outcome == N976N_UFS_READ &&
           mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xFF &&
           mN976nUfsReport.ReadCount == 1 && mN976nUfsReport.Restore == 7 &&
           !mPowerChanged && (mN976nUfsDiag.Prepare & 0x10) != 0 &&
           mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
           (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
            mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)) {
    mN976nUfsReport.Phase = 8;
  } else if (mN976nUfsReport.Outcome == N976N_UFS_QUERY_OBSERVED &&
             mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xCF &&
             mN976nUfsReport.Restore == 7) {
    mN976nUfsReport.Phase = 9;
  } else if (mN976nUfsReport.Outcome == N976N_UFS_POWER_OBSERVED &&
             mN976nUfsReport.Status == EFI_SUCCESS && mN976nUfsReport.Checks == 0xCF &&
             mN976nUfsReport.Restore == 7 && !mPowerChanged &&
             (mN976nUfsDiag.Prepare & 0x10) != 0 &&
             mN976nUfsDiag.PowerFinal == mN976nUfsDiag.PowerInitial &&
             (mN976nUfsDiag.PowerInitial == UFS_POWER_ACTIVE_RAW ||
              mN976nUfsDiag.PowerInitial == UFS_POWER_SLEEP_RAW ||
              mN976nUfsDiag.PowerInitial == UFS_POWER_DOWN_RAW)) {
    mN976nUfsReport.Phase = 0xA;
  } else if (mIssued || mControllerTouched) {
    if ((mN976nUfsReport.Outcome == N976N_UFS_SERVICE ||
         mN976nUfsReport.Outcome == N976N_UFS_FILESYSTEM ||
         (mN976nUfsReport.Outcome == N976N_UFS_SYSTEM || mN976nUfsReport.Outcome == N976N_UFS_VOLUME)) && mN976nUfsReport.Status == EFI_SUCCESS) {
      mN976nUfsReport.Status = EFI_COMPROMISED_DATA;
    }
    mN976nUfsReport.Outcome = N976N_UFS_FAILED; mN976nUfsReport.Phase = 0xE1;
  }
  if (mN976nUfsReport.Frequency != 0) { mN976nUfsReport.CounterEnd = GetPerformanceCounter (); }
  Publish ();
}
/* Terminal power-off gate: no private DMA/callback remains active. An early
 * pre-allocation refusal never took controller ownership. A completed lease
 * must prove exact restoration and fresh idle/guards before power removal. */
BOOLEAN N976nUfsShutdownSafe (VOID) {
  if (mUfsExitClosing) { return FALSE; }
  if (mUfsHandoff == NULL || (mQueryExperiment != 10 && (mQueryExperiment != 12 && mQueryExperiment != 13)) || mServiceLease ||
      mPartitionSessionActive || mPartitionReadActive || mGptReadActive ||
      mSystemReadActive || !N976nSystemProbeClosed () ||
      mVolumeSessionActive || mVolumeReadActive || !N976nSystemVolumeClosed () ||
      (mQueryExperiment == 12 && mN976nHighRamStageReport[14] != 0) ||
      (mQueryExperiment == 13 && (N976nUfsExecutionActive () ||
       N976nSystemVolumeExecutionActive () || !N976nUfsImageClosed ())) ||
      mN976nUfsReport.Quarantined != 0) return FALSE;
  if (mDma == NULL && !mControllerTouched && !mIssued) return TRUE;
  if (mUfsHandoff->Profile != N976N_PLATFORM_PROFILE_PHONE || mDma == NULL ||
      mN976nUfsReport.Restore != 7 || mPowerChanged ||
      mN976nUfsDiag.PowerFinal != mN976nUfsDiag.PowerInitial ||
      (mN976nUfsDiag.Prepare & 0x30) != 0x30 ||
      mN976nUfsDiag.ImmutableMask != 0) return FALSE;
  return UfsDmaMappingValid (mUfsHandoff, (UINTN)mDma, UFS_BYTES) && Guards () &&
    HRead (UFS_HC_UTRLDBR_OFFSET) == 0 && HRead (UFS_HC_UTMRLDBR_OFFSET) == 0 &&
    (HRead (UFS_HC_IS_OFFSET) & (FATAL_IS | OWNED_TRANSFER_COMPLETION)) == 0 &&
    HRead (UFS_HC_UTRLBA_OFFSET) == mN976nUfsReport.TrlBase &&
    HRead (UFS_HC_UTRLBAU_OFFSET) == mN976nUfsReport.TrlBaseUpper &&
    HRead (UFS_HC_UTRLRSR_OFFSET) == mN976nUfsReport.TrlRun;
}
BOOLEAN N976nUfsServiceOpen (VOID) { return mServiceLease; }
EFI_STATUS N976nFinishUfsService (EFI_STATUS ConsumerStatus) {
  if (mUfsExitClosing) { return EFI_ACCESS_DENIED; }
  EFI_STATUS CloseStatus;
  if (!mServiceLease || (mQueryExperiment != 6 && mQueryExperiment != 7 && mQueryExperiment != 8 && mQueryExperiment != 9)) { return EFI_NOT_STARTED; }
  /* Close public callbacks before touching power or restoring inherited rings.
     A failed uninstall leaves a closed static tombstone, never a live lease. */
  if (mQueryExperiment >= 7 && !N976nUfsFileSystemClosed ()) { return EFI_NOT_READY; }
  CloseStatus = N976nStopUfsService ();
  if (!N976nUfsServiceClosed ()) { return EFI_NOT_READY; }
  mServiceLease = FALSE;
  mPartitionSessionActive = FALSE; mPartitionReadActive = FALSE; mReadLba = 0;
  if (!EFI_ERROR (ConsumerStatus)) { ConsumerStatus = CloseStatus; }
  mN976nUfsReport.Status = ConsumerStatus;
  mN976nUfsReport.LunStatus[mN976nUfsReport.Lun] = ConsumerStatus;
  CleanupUfs ();
  FinalizeUfsReport ();
  return mN976nUfsReport.Status;
}

VOID N976nRunUfsProbe (CONST N976N_PLATFORM_HANDOFF *Handoff) {
  VOID *Hob;
  EFI_STATUS Status;
  EFI_PHYSICAL_ADDRESS Address = 0;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Attributes = NULL;
  UINT64 Attr, CounterMin, CounterMax;
  if (mUfsExitClosing || mServiceLease || mVolumeSessionActive || mVolumeReadActive || !N976nSystemVolumeClosed ()) { return; } /* Never reset an outstanding storage lease. */
  mUfsHandoff = Handoff; mDma = NULL; mControllerTouched = FALSE; mIssued = FALSE;
  mPowerChanged = FALSE; mQueryOpcode = 0; mQueryIdn = 0; mSsuMode = 0;
  mReadLba = 0; mGptReadActive = FALSE; N976nResetGpt ();
  mSystemReadActive = FALSE; mSystemReads = 0; N976nResetSystemProbe ();
  mVolumeSessionActive = FALSE; mVolumeReadActive = FALSE; mVolumeReads = 0; N976nResetSystemVolume ();
  mPartitionSessionActive = FALSE; mPartitionReadActive = FALSE;
  mPartitionStart = 0; mPartitionBlocks = 0; mPartitionReads = 0; mPartitionMemory = NULL;
  N976nResetBlockProbe (); N976nResetUfsService (); N976nResetUfsFileSystem ();
  mQueryExperiment = PcdGet32 (PcdN976nUfsQueryExperiment);
  ZeroMem ((VOID *)&mN976nUfsReport, sizeof (mN976nUfsReport));
  ResetDiagnostic ();
  mN976nUfsDiag.Experiment = mQueryExperiment;
  mN976nUfsDiag.InitFlag = 0xFF; mN976nUfsDiag.PowerInitial = 0xFF; mN976nUfsDiag.PowerFinal = 0xFF;
  mN976nUfsReport.Magic = N976N_UFS_REPORT_MAGIC;
  mN976nUfsReport.Version = 1; mN976nUfsReport.Size = sizeof (mN976nUfsReport);
  mN976nUfsReport.Profile = Handoff->Profile;
  mN976nUfsReport.Outcome = N976N_UFS_NOT_READY;
  mN976nUfsReport.Status = EFI_NOT_READY; mN976nUfsReport.Phase = 1;
  for (UINTN I = 0; I < 8; ++I) { mN976nUfsReport.LunStatus[I] = EFI_NOT_STARTED; }
  if (mQueryExperiment > 13 || mQueryExperiment == 11) {
    mN976nUfsReport.Status = EFI_INVALID_PARAMETER;
    mN976nUfsReport.Reason = 0x70; Publish (); return;
  }
  if (Handoff->Profile == N976N_PLATFORM_PROFILE_QEMU) {
    mN976nUfsReport.Outcome = N976N_UFS_NOT_TESTED;
    mN976nUfsReport.Status = EFI_UNSUPPORTED; mN976nUfsReport.Phase = 0xF0;
    Publish (); return; /* No real UFS MMIO on QEMU virt. */
  }
  Hob = GetFirstGuidHob (&gN976nUfsAdmissionGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (mAdmission)) {
    mN976nUfsReport.Reason = 1; goto Done;
  }
  CopyMem (&mAdmission, GET_GUID_HOB_DATA (Hob), sizeof (mAdmission));
  if (mAdmission.Magic != N976N_UFS_ADMISSION_MAGIC || mAdmission.Version != 1 ||
      mAdmission.Size != sizeof (mAdmission) || mAdmission.Admitted != 1 || mAdmission.Reason != 0 ||
      mAdmission.Hci != 0x13D60000 || mAdmission.Vendor != 0x13D61100 ||
      mAdmission.Coherency != 0x13C10700 || Handoff->Profile != 0) {
    mN976nUfsReport.Reason = 2; goto Done;
  }
  mN976nUfsReport.Checks |= 1;
  mN976nUfsReport.Hci = mAdmission.Hci; mN976nUfsReport.Vendor = mAdmission.Vendor;
  mN976nUfsReport.Coherency = mAdmission.Coherency;
  mN976nUfsReport.Cap = HRead (UFS_HC_CAP_OFFSET);
  mN976nUfsReport.VersionReg = HRead (UFS_HC_VER_OFFSET);
  mN976nUfsReport.Hce = HRead (UFS_HC_ENABLE_OFFSET);
  mN976nUfsReport.Hcs = HRead (UFS_HC_STATUS_OFFSET);
  mN976nUfsReport.Is = HRead (UFS_HC_IS_OFFSET);
  mN976nUfsReport.Ie = HRead (UFS_HC_IE_OFFSET);
  mN976nUfsReport.Ahit = HRead (UFS_HC_AHIT_OFFSET);
  mN976nUfsReport.TrlBase = HRead (UFS_HC_UTRLBA_OFFSET);
  mN976nUfsReport.TrlBaseUpper = HRead (UFS_HC_UTRLBAU_OFFSET);
  mN976nUfsReport.TrlDoorbell = HRead (UFS_HC_UTRLDBR_OFFSET);
  mN976nUfsReport.TrlRun = HRead (UFS_HC_UTRLRSR_OFFSET);
  mN976nUfsReport.TmDoorbell = HRead (UFS_HC_UTMRLDBR_OFFSET);
  mN976nUfsReport.TmRun = HRead (UFS_HC_UTMRLRSR_OFFSET);
  mN976nUfsReport.TxPrdt = VRead (0); mN976nUfsReport.RxPrdt = VRead (4);
  mN976nUfsReport.Reorder = VRead (VENDOR_REORDER);
  mN976nUfsReport.Nexus = VRead (VENDOR_NEXUS);
  mN976nUfsReport.CoherencyValue = MmioRead32 ((UINTN)mAdmission.Coherency);
  mN976nUfsReport.Phase = 2; Publish ();
  if (mN976nUfsReport.Hce != 1 || (mN976nUfsReport.Hcs & 0xB) != 0xB ||
      mN976nUfsReport.TrlDoorbell != 0 || mN976nUfsReport.TmDoorbell != 0 ||
      mN976nUfsReport.TrlRun > 1 || mN976nUfsReport.TmRun > 1 ||
      (mN976nUfsReport.TrlBase == 0 && mN976nUfsReport.TrlBaseUpper == 0) ||
      (mN976nUfsReport.Is & FATAL_IS) != 0 || mN976nUfsReport.Cap == MAX_UINT32 ||
      mN976nUfsReport.VersionReg < 0x200 || mN976nUfsReport.VersionReg > 0x300) {
    mN976nUfsReport.Reason = 3; goto Done;
  }
  /* A pre-existing transfer-completion bit is not ours to acknowledge. Fail
     before allocating DMA or modifying the inherited controller state. */
  if ((mN976nUfsReport.Is & OWNED_TRANSFER_COMPLETION) != 0) {
    mN976nUfsDiag.AckBefore = mN976nUfsReport.Is;
    mN976nUfsReport.Reason = 0x71; goto Done;
  }
  /* Samsung TX bit31 enables PRDT prefetch, not WLU. Both exact values have
     the same 4096-byte data-unit size (log2=12), not a descriptor stride.
     Keep the inherited value unchanged; reject any unknown bits.
     The two coherency bits may both be clear (observed 0x11) or both set.
     Mixed modes are unvalidated. Neither path writes SYSREG coherency. */
  if ((mN976nUfsReport.TxPrdt != 0xC && mN976nUfsReport.TxPrdt != 0x8000000C) ||
      mN976nUfsReport.RxPrdt != 0xC ||
      mN976nUfsReport.Reorder != 0xA ||
      mN976nUfsReport.CoherencyValue == MAX_UINT32 ||
      ((mN976nUfsReport.CoherencyValue & 0xC00000) != 0 &&
       (mN976nUfsReport.CoherencyValue & 0xC00000) != 0xC00000)) {
    mN976nUfsReport.Reason = 4; goto Done;
  }
  mN976nUfsReport.Checks |= 2;
  mN976nUfsReport.Frequency = GetPerformanceCounterProperties (&CounterMin, &CounterMax);
  if (mN976nUfsReport.Frequency == 0 || mN976nUfsReport.Frequency > 1000000000ULL ||
      CounterMin != 0 || CounterMax != MAX_UINT64) {
    mN976nUfsReport.Reason = 5; goto Done;
  }
  mN976nUfsReport.CounterStart = GetPerformanceCounter ();
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&Attributes);
  if (EFI_ERROR (Status) || Attributes == NULL) {
    mN976nUfsReport.Status = EFI_ERROR (Status) ? Status : EFI_NOT_FOUND; goto Done;
  }
  mPartitionMemory = Attributes;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData, UFS_PAGES, &Address);
  if (EFI_ERROR (Status)) { mN976nUfsReport.Status = Status; goto Done; }
  /* Retained through the terminal observation screen, including failure paths.
     Never freeing these seven pages makes lifetime independent of DMA outcome. */
  mN976nUfsReport.Buffer = Address; mN976nUfsReport.BufferBytes = UFS_BYTES;
  if ((Address & 4095) != 0 || !Contains (Handoff->HeapBase, Handoff->HeapSize, Address, UFS_BYTES) ||
      Address > MAX_UINT32 - UFS_BYTES) {
    mN976nUfsReport.Status = EFI_SECURITY_VIOLATION; mN976nUfsReport.Reason = 6; goto Done;
  }
  for (UINTN Page = 0; Page < UFS_PAGES; ++Page) {
    Status = Attributes->GetMemoryAttributes (Attributes, Address + Page * 4096, 4096, &Attr);
    if (EFI_ERROR (Status) || (Attr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
      mN976nUfsReport.Status = EFI_SECURITY_VIOLATION; mN976nUfsReport.Reason = 7; goto Done;
    }
  }
  mN976nUfsReport.BufferAttributes = Attr;
  if (!UfsDmaMappingValid (Handoff, Address, UFS_BYTES)) {
    mN976nUfsReport.Status = EFI_SECURITY_VIOLATION;
    mN976nUfsReport.Reason = 0xA; goto Done;
  }
  mDma = (UINT8 *)(UINTN)Address; ZeroMem (mDma, UFS_BYTES);
  for (UINTN Page = 0; Page < UFS_PAGES; Page += 2) { SetMem (mDma + Page * 4096, 4096, 0xA5); }
  mN976nUfsReport.Checks |= 4; mN976nUfsReport.Phase = 3; Publish ();
  if (!InheritedStillIdle ()) { mN976nUfsReport.Reason = 8; goto Done; }
  mControllerTouched = TRUE;
  HWrite (UFS_HC_IE_OFFSET, 0); HWrite (UFS_HC_AHIT_OFFSET, 0);
  HWrite (UFS_HC_UTRLRSR_OFFSET, 0);
  if (!WaitValue (UFS_HC_UTRLRSR_OFFSET, 1, 0)) { Quarantine (0x31); goto Done; }
  if (HRead (UFS_HC_UTRLDBR_OFFSET) != 0 || HRead (UFS_HC_UTMRLDBR_OFFSET) != 0 ||
      HRead (UFS_HC_ENABLE_OFFSET) != 1 ||
      HRead (UFS_HC_UTRLBA_OFFSET) != mN976nUfsReport.TrlBase ||
      HRead (UFS_HC_UTRLBAU_OFFSET) != mN976nUfsReport.TrlBaseUpper ||
      HRead (UFS_HC_IE_OFFSET) != 0 || HRead (UFS_HC_AHIT_OFFSET) != 0 ||
      !FormatStillSame ()) {
    Quarantine (0x32); goto Done;
  }
  WriteBackInvalidateDataCacheRange (mDma, UFS_BYTES); MemoryFence ();
  HWrite (UFS_HC_UTRLBA_OFFSET, (UINT32)(Address + 4096));
  HWrite (UFS_HC_UTRLBAU_OFFSET, 0);
  HWrite (UFS_HC_UTRLRSR_OFFSET, 1);
  if (HRead (UFS_HC_UTRLBA_OFFSET) != Address + 4096 || HRead (UFS_HC_UTRLBAU_OFFSET) != 0 ||
      HRead (UFS_HC_IE_OFFSET) != 0 || HRead (UFS_HC_AHIT_OFFSET) != 0 ||
      !WaitValue (UFS_HC_UTRLRSR_OFFSET, 1, 1)) {
    mN976nUfsReport.Status = EFI_DEVICE_ERROR; mN976nUfsReport.Reason = 9; goto Cleanup;
  }
  mN976nUfsReport.Checks |= 8;
  if (mQueryExperiment == 1 || mQueryExperiment == 2) {
    Status = QueryExperiment (); mN976nUfsReport.Status = Status;
    goto Cleanup;
  }
  Status = PrepareDevice (); mN976nUfsReport.Status = Status;
  if (EFI_ERROR (Status)) { goto Cleanup; }
  if (mQueryExperiment == 3) {
    /* Terminal power preparation/restore experiment. No logical-unit scan,
       capacity, sector read or media write is reached in this legacy mode. */
    mN976nUfsReport.Outcome = N976N_UFS_POWER_OBSERVED;
    goto Cleanup;
  }
  for (UINT8 Lun = 0; Lun < 8; ++Lun) {
    UINT8 *Data = mDma + 5 * 4096;
    /* Capacity belongs to this LU. If a previously ready LU disappears at
       READ(10), never display its capacity as belonging to the next LU. */
    mN976nUfsReport.LastLba = 0; mN976nUfsReport.BlockBytes = 0;
    mN976nUfsReport.Checks &= ~0x10ULL;
    mN976nUfsReport.Lun = Lun; mN976nUfsReport.Phase = 4; Publish ();
    Status = ReadyLun (Lun);
    mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
    if (Status == EFI_NOT_FOUND) { continue; }
    if (EFI_ERROR (Status)) { break; }
    Status = Transfer (Lun, 0x25, 8);
    mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
    if (Status == EFI_NOT_FOUND) { continue; }
    if (EFI_ERROR (Status)) { break; }
    mN976nUfsReport.LastLba = Be32 (Data); mN976nUfsReport.BlockBytes = Be32 (Data + 4);
    if (mN976nUfsReport.LastLba == 0 || mN976nUfsReport.LastLba == MAX_UINT32 ||
        (mN976nUfsReport.BlockBytes != 512 && mN976nUfsReport.BlockBytes != 4096)) {
      mN976nUfsReport.Status = EFI_UNSUPPORTED; mN976nUfsReport.Reason = 0x43; break;
    }
    mN976nUfsReport.Checks |= 0x10; mN976nUfsReport.Phase = 5; Publish ();
    if (mQueryExperiment >= 4 && mQueryExperiment <= 13) {
      Status = N976nObserveGpt (mN976nUfsReport.LastLba, (UINT32)mN976nUfsReport.BlockBytes,
        ReadGptBlock, (VOID *)&mN976nUfsReport);
      mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
      if (!EFI_ERROR (Status)) { mN976nUfsReport.Outcome = N976N_UFS_GPT; }
      if (!EFI_ERROR (Status) && (mQueryExperiment == 10 || (mQueryExperiment == 12 || mQueryExperiment == 13))) {
        Status = N976nProbeSystem (mN976nUfsReport.LastLba, (UINT32)mN976nUfsReport.BlockBytes,
          ReadSystemBlock, (VOID *)&mN976nUfsReport);
        mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
        if (!EFI_ERROR (Status)) mN976nUfsReport.Outcome = N976N_UFS_SYSTEM;
        if (!N976nSystemProbeClosed () || mSystemReadActive) {
          CompletionHold (0x78); goto Done;
        }
      }
      if (!EFI_ERROR (Status) && (mQueryExperiment == 12 || mQueryExperiment == 13)) {
        mVolumeSessionActive = TRUE;
        Status = N976nConsumeSystemVolume (Handoff, ReadVolumeBlock, (VOID *)&mN976nUfsReport);
        mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
        if (!N976nSystemVolumeClosed () || mVolumeReadActive ||
            (mQueryExperiment == 13 && (N976nUfsExecutionActive () ||
             N976nSystemVolumeExecutionActive () || !N976nUfsImageClosed ()))) {
          CompletionHold (0x79); goto Done;
        }
        mVolumeSessionActive = FALSE;
        if (!EFI_ERROR (Status)) mN976nUfsReport.Outcome = N976N_UFS_VOLUME;
      }
      if (!EFI_ERROR (Status) && (mQueryExperiment >= 5 && mQueryExperiment <= 9)) {
        Status = N976nSelectBootPartition (mN976nUfsReport.LastLba, &mPartitionStart, &mPartitionBlocks);
        if (!EFI_ERROR (Status)) {
          mPartitionSessionActive = TRUE;
          if (mQueryExperiment == 6 || mQueryExperiment == 7 || mQueryExperiment == 8 || mQueryExperiment == 9) {
            if (mQueryExperiment == 9) {
              Status = N976nStartUfsBootService (mPartitionStart, mPartitionBlocks,
                ReadPartitionBlock, CheckPartitionBuffer, PartitionBudget, (VOID *)&mN976nUfsReport,
                N976N_BOOT_WINDOWS_BYTES);
            } else if (mQueryExperiment == 8) {
              Status = N976nStartUfsStreamService (mPartitionStart, mPartitionBlocks,
                ReadPartitionBlock, CheckPartitionBuffer, PartitionBudget, (VOID *)&mN976nUfsReport,
                N976N_BOOT_WINDOWS_BYTES);
            } else if (mQueryExperiment == 7) {
              Status = N976nStartUfsFileService (mPartitionStart, mPartitionBlocks,
                ReadPartitionBlock, CheckPartitionBuffer, PartitionBudget, (VOID *)&mN976nUfsReport);
            } else {
              Status = N976nStartUfsService (mPartitionStart, mPartitionBlocks,
                ReadPartitionBlock, CheckPartitionBuffer, PartitionBudget, (VOID *)&mN976nUfsReport);
            }
            if (!EFI_ERROR (Status)) {
              mServiceLease = TRUE;
              mN976nUfsReport.Outcome = mQueryExperiment >= 7 ? N976N_UFS_FILESYSTEM : N976N_UFS_SERVICE;
              mN976nUfsReport.Status = EFI_SUCCESS;
              mN976nUfsReport.LunStatus[Lun] = EFI_SUCCESS;
              Publish ();
              return; /* Separate BDS consumer now owns use/close sequencing. */
            }
            /* Installation may fail after partial publication. Close every
               callback before restoration, even when Start returned error. */
            N976nStopUfsService ();
            if (!N976nUfsServiceClosed ()) {
              mServiceLease = TRUE;
              mN976nUfsReport.Status = Status;
              mN976nUfsReport.Reason = 0x71;
              Publish (); return;
            }
          } else {
            Status = N976nProbeBootBlocks (mPartitionStart, mPartitionBlocks,
              ReadPartitionBlock, CheckPartitionBuffer, PartitionBudget, (VOID *)&mN976nUfsReport);
          }
          /* The adapter retires before restoration, even on a partial read or
             failed protocol removal. No stale callback may reuse this lease. */
          mPartitionSessionActive = FALSE; mPartitionReadActive = FALSE; mReadLba = 0;
        }
        mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
        if (!EFI_ERROR (Status)) { mN976nUfsReport.Outcome = N976N_UFS_BLOCK; }
      }
      break; /* A malformed/unsupported GPT is not an absent-LU permission. */
    }
    Status = Transfer (Lun, 0x28, (UINT32)mN976nUfsReport.BlockBytes);
    mN976nUfsReport.LunStatus[Lun] = Status; mN976nUfsReport.Status = Status;
    if (Status == EFI_NOT_FOUND) { continue; }
    if (EFI_ERROR (Status)) { break; }
    UINT32 Crc = 0;
    Status = gBS->CalculateCrc32 (Data, (UINTN)mN976nUfsReport.BlockBytes, &Crc);
    if (EFI_ERROR (Status)) { mN976nUfsReport.Status = Status; break; }
    mN976nUfsReport.DataCrc32 = Crc;
    CopyMem ((VOID *)&mN976nUfsReport.FirstQword, Data, sizeof (UINT64));
    mN976nUfsReport.ReadCount = 1; mN976nUfsReport.Checks |= 0x20;
    mN976nUfsReport.Outcome = N976N_UFS_READ; break;
  }
Cleanup:
  CleanupUfs ();
Done:
  FinalizeUfsReport ();
}
