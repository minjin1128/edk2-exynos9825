/* SPDX-License-Identifier: MIT */
#ifndef N976N_WINDOWS_BOOT_H_
#define N976N_WINDOWS_BOOT_H_

#include <Uefi.h>

#define N976N_WINDOWS_MAGIC  0x534543343557494EULL
#define N976N_WINDOWS_PATH   L"\\EFI\\Microsoft\\Boot\\bootmgfw.efi"
#define N976N_WINDOWS_DEADLINE_SECONDS  10ULL
/* SEC66: authenticated SYSTEM reads may take minutes. These are observation
 * limits, not success/failure criteria or a watchdog if IRQ delivery is lost. */
#define N976N_WINDOWS_UFS_DEADLINE_SECONDS  900ULL
#define N976N_WINDOWS_UFS_IDLE_SECONDS       30ULL

#define N976N_WINDOWS_OUTCOME_NONE      0ULL
#define N976N_WINDOWS_OUTCOME_RETURNED  1ULL
#define N976N_WINDOWS_OUTCOME_DEADLINE  2ULL
#define N976N_WINDOWS_OUTCOME_RESET     3ULL
#define N976N_WINDOWS_OUTCOME_EBS       4ULL
#define N976N_WINDOWS_OUTCOME_FAILED    5ULL
#define N976N_WINDOWS_OUTCOME_IDLE      6ULL
/* Exit notification observed; original EBS return/kernel entry need separate
 * evidence. The firmware stops observing when Boot Services ownership ends. */
#define N976N_WINDOWS_OUTCOME_HANDOFF   7ULL

/* These bits prove bounded setup/lifecycle checks, not Windows boot success.
   01 media, 02 BCD, 04 font, 08 boot-only ACPI, 10 DXE phase + stop notifications,
   20 admitted image attributes, 40 native StartImage entered,
   80 application returned and its executable allocation was revoked. */
typedef struct {
  UINT64 Magic, Version, Size, Stage, Status, Outcome, Checks;
  UINT64 MediaHandle, MediaBase, MediaBytes, MediaAttributes;
  UINT64 BcdBytes, FontBytes;
  UINT64 AcpiStatus, Rsdp, Xsdt, Fadt, Dsdt;
  UINT64 ArmStatus, LoadStatus, StartStatus;
  UINT64 ImageHandle, ImageBase, ImageBytes;
  UINT64 HeaderAttributes, CodeAttributes, DataAttributes;
  UINT64 FreedAttributes, AutoUnloadStatus;
  UINT64 CounterStart, CounterEnd, Frequency, DeadlineSeconds;
  UINT64 ResetType, ResetStatus, ExitDataBytes, LoadCount, StartCount;
  /* SEC66 UFS observation: last sampled successful authenticated runtime bytes and
   * idle observation seconds. Neither is full-file coverage or cleanup proof. */
  UINT64 Reserved[2];
} N976N_WINDOWS_REPORT;

STATIC_ASSERT (sizeof (N976N_WINDOWS_REPORT) == 320, "SEC49 Windows report ABI");
extern volatile N976N_WINDOWS_REPORT mN976nWindowsReport;

EFI_STATUS RunWindowsBoot (EFI_HANDLE Parent, UINT64 Profile);
/* Standard PI phase transition shared by external image load callers. */
EFI_STATUS N976nCompleteDxePhase (VOID);
/* UFS path: prepare trusted boot setup before LoadImage, then start exactly
 * the already validated native child. The caller owns child/source retirement. */
EFI_STATUS N976nPrepareUfsWindows (EFI_HANDLE Fs, UINT64 Profile);
EFI_STATUS N976nStartUfsWindows (EFI_HANDLE Parent, EFI_HANDLE Fs, EFI_HANDLE Child);
EFI_STATUS N976nCancelUfsWindows (VOID);
BOOLEAN N976nUfsExecutionActive (VOID);
/* Direct local state/framebuffer snapshot only; no Boot Services or UFS I/O. */
VOID EFIAPI N976nUfsWindowsObserved (VOID);
VOID EFIAPI N976nWindowsPreflightCheckpoint (VOID);
VOID EFIAPI N976nWindowsLoadedCheckpoint (VOID);
VOID EFIAPI N976nWindowsScreen (UINT64 Outcome, UINT64 Status, UINT64 Checks);

#endif
