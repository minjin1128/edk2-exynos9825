/* SPDX-License-Identifier: MIT
 * SEC49 uses the upstream filesystem, PE loader, image lifecycle and services.
 * These checks admit the sealed original Windows application and bound this
 * boot-only experiment. They do not replace or intercept Windows service calls.
 */
#include <PiDxe.h>
#include <N976nPlatform.h>
#include <N976nBootMedia.h>
#include <N976nWindowsBoot.h>
#include <N976nAcpiPlatform.h>
#include <N976nHighRam.h>
#include <N976nSystemVolume.h>
#include <N976nOsHandoff.h>
#include <N976nHandoffMemory.h>
#include <Guid/Acpi.h>
#include <Guid/EventGroup.h>
#include <Guid/EventExitBootServiceFailed.h>
#include <Guid/FileInfo.h>
#include <IndustryStandard/Acpi65.h>
#include <IndustryStandard/PeImage.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/DevicePathLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>
#include <Protocol/AcpiTable.h>
#include <Protocol/DxeSmmReadyToLock.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/ResetNotification.h>
#include <Protocol/SimpleFileSystem.h>

volatile N976N_WINDOWS_REPORT mN976nWindowsReport;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mWindowsAttributes;
STATIC EFI_RESET_NOTIFICATION_PROTOCOL *mResetNotification;
STATIC EFI_EVENT mBeforeExitEvent, mObservationEvent;
STATIC EFI_EVENT mExitEvent, mExitFailedEvent;
STATIC volatile BOOLEAN mWindowsActive;
STATIC BOOLEAN mUfsWindows, mUfsWindowsPrepared, mResetRegistered;
STATIC volatile BOOLEAN mUfsExecutionActive;
STATIC UINT64 mObservationProgress, mObservationProgressCounter;
STATIC UINT64 mUfsWindowsProfile;

BOOLEAN N976nUfsExecutionActive (VOID) { return mUfsExecutionActive; }

__attribute__((noinline)) VOID EFIAPI N976nWindowsPreflightCheckpoint (VOID)
{
  MemoryFence ();
}

__attribute__((noinline)) VOID EFIAPI N976nWindowsLoadedCheckpoint (VOID)
{
  MemoryFence ();
}

STATIC BOOLEAN HeapContains (UINT64 Address, UINT64 Bytes)
{
  return Address >= 0x92001000ULL && Address < 0x95FDE000ULL &&
    Bytes != 0 && Bytes <= 0x95FDE000ULL - Address;
}

/* The notification path intentionally uses only local RAM, CPU registers,
   direct diagnostic framebuffer writes and the configured serial DebugLib.
   There are no ConsoleOut or Boot Services calls at TPL_NOTIFY. */
STATIC __attribute__((noreturn)) VOID WindowsObserved (UINT64 Outcome, EFI_STATUS Status)
{
  DisableInterrupts ();
  mWindowsActive = FALSE;
  mN976nWindowsReport.CounterEnd = GetPerformanceCounter ();
  mN976nWindowsReport.Outcome = Outcome;
  mN976nWindowsReport.Status = Status;
  mN976nWindowsReport.Stage = 8;
  mN976nBdsReport.Stage = 8;
  mN976nBdsReport.Complete = N976N_BDS_COMPLETE;
  if (mUfsWindows) { N976nUfsWindowsObserved (); }
  else { N976nWindowsScreen (Outcome, Status, mN976nWindowsReport.Checks); }
  MemoryFence ();
  DEBUG ((DEBUG_ERROR, "SEC49 WINDOWS outcome=%Lu status=%r checks=%Lx image=%Lx bytes=%Lx\n",
    Outcome, Status, mN976nWindowsReport.Checks,
    mN976nWindowsReport.ImageBase, mN976nWindowsReport.ImageBytes));
  N976nBdsStop (EFI_SUCCESS);
  UNREACHABLE ();
}

STATIC VOID EFIAPI BeforeExitBootServices (EFI_EVENT Event, VOID *Context)
{
  (VOID)Event;
  (VOID)Context;
  if (mWindowsActive) {
    EFI_STATUS Status;
    /* The legacy embedded-medium diagnostic retains its bounded stop. Only
     * the admitted SYSTEM path has prepared the OS handoff contracts. */
    if (!mUfsWindows) {
      WindowsObserved (N976N_WINDOWS_OUTCOME_EBS, EFI_UNSUPPORTED);
    }
    Status = N976nBeginOsHandoff ();
    if (EFI_ERROR (Status)) { WindowsObserved (N976N_WINDOWS_OUTCOME_FAILED, Status); }
    N976nUfsWindowsObserved ();
    /* Return to the original core. It validates Windows' original map key. */
  }
}

STATIC VOID EFIAPI ExitBootServicesFailed (EFI_EVENT Event, VOID *Context)
{
  EFI_STATUS Status;
  (VOID)Event;
  (VOID)Context;
  if (!mWindowsActive || !mUfsWindows) { return; }
  Status = N976nFailedOsHandoff ();
  if (EFI_ERROR (Status)) { WindowsObserved (N976N_WINDOWS_OUTCOME_FAILED, Status); }
  N976nUfsWindowsObserved ();
}

STATIC VOID EFIAPI ExitBootServicesObserved (EFI_EVENT Event, VOID *Context)
{
  EFI_STATUS Status;
  (VOID)Event;
  (VOID)Context;
  if (!mWindowsActive || !mUfsWindows) { return; }
  Status = N976nObserveExitBootServices ();
  if (EFI_ERROR (Status)) { WindowsObserved (N976N_WINDOWS_OUTCOME_FAILED, Status); }
  mWindowsActive = FALSE;
  mUfsExecutionActive = FALSE;
  mN976nWindowsReport.Outcome = N976N_WINDOWS_OUTCOME_HANDOFF;
  mN976nWindowsReport.Status = EFI_SUCCESS;
  mN976nWindowsReport.CounterEnd = GetPerformanceCounter ();
  mN976nWindowsReport.Stage = 8;
  mN976nBdsReport.Stage = 8;
  mN976nBdsReport.Complete = N976N_BDS_COMPLETE;
  /* Last local framebuffer snapshot. No Boot Services, protocol query,
   * allocation or deferred repaint is allowed once this callback returns.
   * This marker is an exit notification, not a kernel-entry marker. */
  N976nUfsWindowsObserved ();
  MemoryFence ();
}

STATIC VOID EFIAPI BeforeReset (EFI_RESET_TYPE ResetType, EFI_STATUS ResetStatus,
  UINTN DataSize, VOID *ResetData)
{
  (VOID)DataSize;
  (VOID)ResetData;
  if (mWindowsActive) {
    mN976nWindowsReport.ResetType = ResetType;
    mN976nWindowsReport.ResetStatus = ResetStatus;
    /* ResetSystemRuntimeDxe invokes this before its PSCI reset implementation. */
    WindowsObserved (N976N_WINDOWS_OUTCOME_RESET, ResetStatus);
  }
}

STATIC VOID EFIAPI ObservationDeadline (EFI_EVENT Event, VOID *Context)
{
  UINT64 Counter, Progress;
  (VOID)Event;
  (VOID)Context;
  if (mWindowsActive && !N976nOsHandoffAttempted ()) {
    if (mUfsWindows) {
      /* The linked ArmArchTimerLib is an upward, full-width counter. Its
       * properties are independently admitted before starting Windows.
       * Unsigned subtraction also handles one counter rollover. */
      Counter = GetPerformanceCounter ();
      if (Counter - mN976nWindowsReport.CounterStart >=
          N976N_WINDOWS_UFS_DEADLINE_SECONDS * mN976nWindowsReport.Frequency) {
        WindowsObserved (N976N_WINDOWS_OUTCOME_DEADLINE, EFI_TIMEOUT);
      }
      /* Local monotonic accounting only: no filesystem call, allocation,
       * GetMemoryMap, controller polling or ownership release at TPL_NOTIFY. */
      Progress = N976nSystemWindowsProgress ();
      if (Progress < mObservationProgress) {
        WindowsObserved (N976N_WINDOWS_OUTCOME_FAILED, EFI_COMPROMISED_DATA);
      }
      if (Progress != mObservationProgress) {
        mObservationProgress = Progress;
        mObservationProgressCounter = Counter;
        mN976nWindowsReport.Reserved[0] = Progress;
      }
      if (Counter - mObservationProgressCounter >=
          N976N_WINDOWS_UFS_IDLE_SECONDS * mN976nWindowsReport.Frequency) {
        WindowsObserved (N976N_WINDOWS_OUTCOME_IDLE, EFI_TIMEOUT);
      }
      return;
    }
    /* This is a bounded observation, not proof of an error loop or a watchdog
       guarantee when the application disables interrupts or raises its TPL. */
    WindowsObserved (N976N_WINDOWS_OUTCOME_DEADLINE, EFI_TIMEOUT);
  }
}

STATIC EFI_STATUS ArmObservation (VOID)
{
  EFI_STATUS Status = gBS->CreateEventEx (EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
    BeforeExitBootServices, NULL, &gEfiEventBeforeExitBootServicesGuid, &mBeforeExitEvent);
  if (EFI_ERROR (Status)) { return Status; }
  if (mUfsWindows) {
    Status = gBS->CreateEventEx (EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
      ExitBootServicesFailed, NULL, &gEventExitBootServicesFailedGuid, &mExitFailedEvent);
    if (EFI_ERROR (Status)) { return Status; }
    Status = gBS->CreateEventEx (EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
      ExitBootServicesObserved, NULL, &gEfiEventExitBootServicesGuid, &mExitEvent);
    if (EFI_ERROR (Status)) { return Status; }
  }
  Status = gBS->LocateProtocol (&gEfiResetNotificationProtocolGuid, NULL, (VOID **)&mResetNotification);
  if (EFI_ERROR (Status) || mResetNotification == NULL) {
    return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
  }
  Status = mResetNotification->RegisterResetNotify (mResetNotification, BeforeReset);
  if (EFI_ERROR (Status)) { return Status; }
  mResetRegistered = TRUE;
  return gBS->CreateEvent (EVT_TIMER | EVT_NOTIFY_SIGNAL, TPL_NOTIFY,
    ObservationDeadline, NULL, &mObservationEvent);
}

EFI_STATUS N976nCompleteDxePhase (VOID)
{
  EFI_HANDLE ReadyToLock = NULL;
  /* Upstream ArmPlatformBootManager signals EndOfDxe before third-party EFI
     execution. Publish the PI resource-lock phase immediately afterwards,
     as required by SecurityStubDxe; do not bypass its deferred-image checks.
     This platform has no SMM implementation, and this phase marker does not
     claim one. Callers finish trusted FV setup before loading external images. */
  EFI_STATUS Status = EfiEventGroupSignal (&gEfiEndOfDxeEventGroupGuid);
  if (EFI_ERROR (Status)) { return Status; }
  return gBS->InstallProtocolInterface (&ReadyToLock,
    &gEfiDxeSmmReadyToLockProtocolGuid, EFI_NATIVE_INTERFACE, NULL);
}

STATIC EFI_STATUS CheckResource (EFI_FILE_PROTOCOL *Root, CHAR16 *Path,
  UINT64 ExpectedBytes, UINT32 Signature, UINT64 *ActualBytes)
{
  EFI_FILE_PROTOCOL *File = NULL;
  union { EFI_FILE_INFO Info; UINT8 Bytes[512]; } InfoBuffer;
  UINT8 Header[4];
  EFI_FILE_INFO *Info = &InfoBuffer.Info;
  UINTN Bytes = sizeof (InfoBuffer);
  EFI_STATUS Close, Status = Root->Open (Root, &File, Path, EFI_FILE_MODE_READ, 0);
  if (EFI_ERROR (Status)) { return Status; }
  Status = File->GetInfo (File, &gEfiFileInfoGuid, &Bytes, Info);
  if (EFI_ERROR (Status) || Bytes < SIZE_OF_EFI_FILE_INFO ||
      Info->FileSize != ExpectedBytes || (Info->Attribute & EFI_FILE_DIRECTORY) != 0) {
    Status = EFI_COMPROMISED_DATA; goto Done;
  }
  Bytes = sizeof (Header);
  Status = File->Read (File, &Bytes, Header);
  if (!EFI_ERROR (Status) && (Bytes != sizeof (Header) || ReadUnaligned32 ((UINT32 *)Header) != Signature)) {
    Status = EFI_COMPROMISED_DATA;
  }
  if (!EFI_ERROR (Status)) { *ActualBytes = Info->FileSize; }
Done:
  Close = File->Close (File);
  return EFI_ERROR (Status) ? Status : Close;
}

STATIC EFI_STATUS ConnectBootMedia (EFI_HANDLE *Handle)
{
  EFI_HANDLE *Handles = NULL;
  N976N_BOOT_MEDIA_PROTOCOL *Media = NULL;
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *Fs = NULL;
  EFI_FILE_PROTOCOL *Root = NULL;
  UINTN Count = 0;
  UINT64 Attributes = 0, Bytes = 0;
  EFI_STATUS Status = gBS->LocateHandleBuffer (ByProtocol, &gN976nBootMediaProtocolGuid, NULL, &Count, &Handles);
  if (EFI_ERROR (Status)) { return Status; }
  if (Count != 1) { FreePool (Handles); return EFI_COMPROMISED_DATA; }
  *Handle = Handles[0];
  FreePool (Handles);
  Status = gBS->HandleProtocol (*Handle, &gN976nBootMediaProtocolGuid, (VOID **)&Media);
  if (EFI_ERROR (Status) || Media == NULL || Media->Magic != N976N_BOOT_MEDIA_MAGIC ||
      Media->Version != 1 || Media->Size != sizeof (*Media) || Media->Checks != 0xF ||
      Media->Bytes != 0x300000 || ((Media->Base | Media->Bytes) & 4095) != 0 ||
      !HeapContains (Media->Base, Media->Bytes) ||
      EFI_ERROR (mWindowsAttributes->GetMemoryAttributes (mWindowsAttributes, Media->Base, Media->Bytes, &Attributes)) ||
      (Attributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != (EFI_MEMORY_RO | EFI_MEMORY_XP) ||
      (Media->Attributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != (EFI_MEMORY_RO | EFI_MEMORY_XP)) {
    return EFI_SECURITY_VIOLATION;
  }
  mN976nWindowsReport.MediaHandle = (UINTN)*Handle;
  mN976nWindowsReport.MediaBase = Media->Base;
  mN976nWindowsReport.MediaBytes = Media->Bytes;
  mN976nWindowsReport.MediaAttributes = Attributes;
  Status = gBS->ConnectController (*Handle, NULL, NULL, TRUE);
  if (EFI_ERROR (Status)) { return Status; }
  /* The supplied medium is a FAT superfloppy. FatDxe installs its filesystem
     on this exact BlockIo handle; unrelated filesystems are never selected. */
  Status = gBS->HandleProtocol (*Handle, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&Fs);
  if (EFI_ERROR (Status) || Fs == NULL) { return EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA; }
  Status = Fs->OpenVolume (Fs, &Root);
  if (EFI_ERROR (Status)) { return Status; }
  mN976nWindowsReport.Checks |= 1;
  Status = CheckResource (Root, L"\\EFI\\Microsoft\\Boot\\BCD", 16384, SIGNATURE_32 ('r', 'e', 'g', 'f'), &Bytes);
  if (!EFI_ERROR (Status)) {
    mN976nWindowsReport.BcdBytes = Bytes;
    mN976nWindowsReport.Checks |= 2;
    Status = CheckResource (Root, L"\\EFI\\Microsoft\\Boot\\Fonts\\wgl4_boot.ttf", 50004, 0x00000100, &Bytes);
  }
  if (!EFI_ERROR (Status)) { mN976nWindowsReport.FontBytes = Bytes; mN976nWindowsReport.Checks |= 4; }
  EFI_STATUS Close = Root->Close (Root);
  return EFI_ERROR (Status) ? Status : Close;
}

STATIC EFI_STATUS CheckWindowsImage (EFI_HANDLE Handle, EFI_HANDLE Parent, EFI_HANDLE Fs)
{
  EFI_LOADED_IMAGE_PROTOCOL *Image = NULL;
  EFI_IMAGE_DOS_HEADER *Dos;
  EFI_IMAGE_NT_HEADERS64 *Nt;
  EFI_IMAGE_SECTION_HEADER *Section;
  UINT64 Base, Size, PeOffset, TableOffset, HeaderAttr, CodeAttr, DataAttr = 0;
  BOOLEAN HaveData = FALSE;
  EFI_STATUS Status = gBS->HandleProtocol (Handle, &gEfiLoadedImageProtocolGuid, (VOID **)&Image);
  if (EFI_ERROR (Status) || Image == NULL || Image->ParentHandle != Parent ||
      Image->DeviceHandle != Fs || Image->ImageCodeType != EfiLoaderCode ||
      Image->ImageDataType != EfiLoaderData || Image->LoadOptions != NULL || Image->LoadOptionsSize != 0) {
    return EFI_COMPROMISED_DATA;
  }
  Base = (UINTN)Image->ImageBase;
  Size = Image->ImageSize;
  if (!HeapContains (Base, Size) || ((Base | Size) & 4095) != 0 || Size < sizeof (*Dos)) {
    return EFI_SECURITY_VIOLATION;
  }
  Dos = (VOID *)(UINTN)Base;
  PeOffset = Dos->e_lfanew;
  if (Dos->e_magic != EFI_IMAGE_DOS_SIGNATURE || PeOffset > Size || sizeof (*Nt) > Size - PeOffset) {
    return EFI_COMPROMISED_DATA;
  }
  Nt = (VOID *)(UINTN)(Base + PeOffset);
  if (Nt->Signature != EFI_IMAGE_NT_SIGNATURE ||
      Nt->FileHeader.Machine != IMAGE_FILE_MACHINE_ARM64 ||
      Nt->OptionalHeader.Magic != EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC ||
      Nt->OptionalHeader.Subsystem != EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION ||
      Nt->OptionalHeader.AddressOfEntryPoint >= Size ||
      Nt->FileHeader.NumberOfSections == 0 || Nt->FileHeader.NumberOfSections > 32) {
    return EFI_COMPROMISED_DATA;
  }
  TableOffset = PeOffset + sizeof (UINT32) + sizeof (EFI_IMAGE_FILE_HEADER) + Nt->FileHeader.SizeOfOptionalHeader;
  if (TableOffset > Size || Nt->FileHeader.NumberOfSections * sizeof (*Section) > Size - TableOffset) {
    return EFI_COMPROMISED_DATA;
  }
  Section = (VOID *)(UINTN)(Base + TableOffset);
  Status = mWindowsAttributes->GetMemoryAttributes (mWindowsAttributes, Base, 4096, &HeaderAttr);
  if (EFI_ERROR (Status)) { return Status; }
  Status = mWindowsAttributes->GetMemoryAttributes (mWindowsAttributes,
    (Base + Nt->OptionalHeader.AddressOfEntryPoint) & ~4095ULL, 4096, &CodeAttr);
  if (EFI_ERROR (Status)) { return Status; }
  for (UINTN Index = 0; Index < Nt->FileHeader.NumberOfSections; Index++) {
    if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_WRITE) == 0) { continue; }
    if ((Section[Index].Characteristics & EFI_IMAGE_SCN_MEM_EXECUTE) != 0 ||
        Section[Index].VirtualAddress >= Size ||
        Section[Index].Misc.VirtualSize > Size - Section[Index].VirtualAddress) { return EFI_SECURITY_VIOLATION; }
    Status = mWindowsAttributes->GetMemoryAttributes (mWindowsAttributes,
      (Base + Section[Index].VirtualAddress) & ~4095ULL, 4096, &DataAttr);
    if (EFI_ERROR (Status)) { return Status; }
    HaveData = TRUE;
    break;
  }
  if (!HaveData ||
      (HeaderAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != (EFI_MEMORY_RO | EFI_MEMORY_XP) ||
      (CodeAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_RO ||
      (DataAttr & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
    return EFI_SECURITY_VIOLATION;
  }
  mN976nWindowsReport.ImageHandle = (UINTN)Handle;
  mN976nWindowsReport.ImageBase = Base;
  mN976nWindowsReport.ImageBytes = Size;
  mN976nWindowsReport.HeaderAttributes = HeaderAttr;
  mN976nWindowsReport.CodeAttributes = CodeAttr;
  mN976nWindowsReport.DataAttributes = DataAttr;
  return EFI_SUCCESS;
}

/* SEC56 shares the proven native observation boundary, not the RAM media
 * connector. No firmware pre-read of BCD/font is counted as a Windows read. */
EFI_STATUS N976nCancelUfsWindows (VOID)
{
  EFI_STATUS Status, First = EFI_SUCCESS;
  if (N976nOsHandoffAttempted ()) { return EFI_ACCESS_DENIED; }
  if (EfiGetCurrentTpl () != TPL_APPLICATION || mWindowsActive) { return EFI_NOT_READY; }
  if (mObservationEvent != NULL) {
    Status = gBS->SetTimer (mObservationEvent, TimerCancel, 0);
    if (EFI_ERROR (Status)) { First = Status; }
    Status = gBS->CloseEvent (mObservationEvent);
    if (EFI_ERROR (Status)) { if (!EFI_ERROR (First)) { First = Status; } }
    else { mObservationEvent = NULL; }
  }
  if (mResetRegistered) {
    Status = mResetNotification->UnregisterResetNotify (mResetNotification, BeforeReset);
    if (EFI_ERROR (Status)) { if (!EFI_ERROR (First)) { First = Status; } }
    else { mResetRegistered = FALSE; }
  }
  if (mBeforeExitEvent != NULL) {
    Status = gBS->CloseEvent (mBeforeExitEvent);
    if (EFI_ERROR (Status)) { if (!EFI_ERROR (First)) { First = Status; } }
    else { mBeforeExitEvent = NULL; }
  }
  if (mExitFailedEvent != NULL) {
    Status = gBS->CloseEvent (mExitFailedEvent);
    if (EFI_ERROR (Status)) { if (!EFI_ERROR (First)) { First = Status; } }
    else { mExitFailedEvent = NULL; }
  }
  if (mExitEvent != NULL) {
    Status = gBS->CloseEvent (mExitEvent);
    if (EFI_ERROR (Status)) { if (!EFI_ERROR (First)) { First = Status; } }
    else { mExitEvent = NULL; }
  }
  if (mN976nHandoffMemoryReport.Phase != 0 && mN976nHandoffMemoryReport.Phase != 9) {
    Status = N976nReleaseHandoffMemory ();
    if (EFI_ERROR (Status) && !EFI_ERROR (First)) { First = Status; }
  }
  return First;
}

EFI_STATUS N976nPrepareUfsWindows (EFI_HANDLE Fs, UINT64 Profile)
{
  EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = NULL;
  EFI_STATUS Status;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (mUfsWindows || mWindowsActive || Fs == NULL || Profile > N976N_PLATFORM_PROFILE_QEMU) {
    return EFI_ACCESS_DENIED;
  }
  mUfsWindows = TRUE;
  mUfsWindowsProfile = Profile;
  ZeroMem ((VOID *)&mN976nWindowsReport, sizeof (mN976nWindowsReport));
  mN976nWindowsReport.Magic = N976N_WINDOWS_MAGIC;
  mN976nWindowsReport.Version = 1;
  mN976nWindowsReport.Size = sizeof (mN976nWindowsReport);
  mN976nWindowsReport.Stage = 1;
  mN976nWindowsReport.Status = EFI_NOT_STARTED;
  mN976nWindowsReport.StartStatus = EFI_NOT_STARTED;
  mN976nWindowsReport.LoadStatus = EFI_NOT_STARTED;
  mN976nWindowsReport.DeadlineSeconds = N976N_WINDOWS_UFS_DEADLINE_SECONDS;
  mN976nWindowsReport.Reserved[1] = N976N_WINDOWS_UFS_IDLE_SECONDS;
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mWindowsAttributes);
  if (EFI_ERROR (Status) || mWindowsAttributes == NULL) { Status = EFI_UNSUPPORTED; goto Failed; }
  Status = gBS->HandleProtocol (Fs, &gEfiSimpleFileSystemProtocolGuid, (VOID **)&FileSystem);
  if (EFI_ERROR (Status) || FileSystem == NULL) { Status = EFI_COMPROMISED_DATA; goto Failed; }
  mN976nWindowsReport.MediaHandle = (UINTN)Fs;
  mN976nWindowsReport.Checks = 1;
  mN976nWindowsReport.Stage = 2;
  Status = N976nInstallBootAcpi (Profile);
  mN976nWindowsReport.AcpiStatus = Status;
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Checks |= 8;
  mN976nWindowsReport.Stage = 3;
  Status = ArmObservation ();
  mN976nWindowsReport.ArmStatus = Status;
  if (EFI_ERROR (Status)) { goto Failed; }
  mUfsWindowsPrepared = TRUE;
  return EFI_SUCCESS;
Failed:
  /* Keep the first setup error. Cancellation is attempted only at application
   * TPL, and inactive callbacks cannot start I/O or claim retirement. */
  mN976nWindowsReport.Status = Status;
  mN976nWindowsReport.Outcome = N976N_WINDOWS_OUTCOME_FAILED;
  N976nCancelUfsWindows ();
  return Status;
}

EFI_STATUS N976nStartUfsWindows (EFI_HANDLE Parent, EFI_HANDLE Fs, EFI_HANDLE Child)
{
  CHAR16 *ExitData = NULL;
  UINTN ExitBytes = 0;
  UINT64 CounterFirst = 0, CounterLast = 0;
  EFI_STATUS Status, Returned;
  if (EfiGetCurrentTpl () != TPL_APPLICATION) { return EFI_NOT_READY; }
  if (!mUfsWindowsPrepared || !N976nHighRamPublished () || mWindowsActive || Parent == NULL || Child == NULL ||
      (UINTN)Fs != mN976nWindowsReport.MediaHandle || mN976nWindowsReport.StartCount != 0) {
    return EFI_ACCESS_DENIED;
  }
  mN976nWindowsReport.LoadStatus = EFI_SUCCESS;
  mN976nWindowsReport.LoadCount = 1;
  mN976nWindowsReport.Checks |= 16;
  Status = CheckWindowsImage (Child, Parent, Fs);
  if (EFI_ERROR (Status)) { goto Failed; }
  /* ImageLoad publishes the high bank after its early filesystem/ACPI/event
   * preparation. Capture the complete OS memory contract only now, with that
   * bank published and the actual child admitted, still before StartImage. */
  Status = N976nPrepareOsHandoff (mUfsWindowsProfile);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Checks |= 32;
  mN976nWindowsReport.Stage = 5;
  N976nWindowsLoadedCheckpoint ();
  mN976nWindowsReport.Frequency = GetPerformanceCounterProperties (&CounterFirst, &CounterLast);
  if (mN976nWindowsReport.Frequency == 0 || mN976nWindowsReport.Frequency > 1000000000ULL ||
      CounterFirst != 0 || CounterLast != MAX_UINT64) {
    Status = EFI_UNSUPPORTED; goto Failed;
  }
  Status = gBS->SetWatchdogTimer (0, 0, 0, NULL);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.CounterStart = GetPerformanceCounter ();
  mObservationProgress = N976nSystemWindowsProgress ();
  mObservationProgressCounter = mN976nWindowsReport.CounterStart;
  mN976nWindowsReport.Reserved[0] = mObservationProgress;
  Status = gBS->SetTimer (mObservationEvent, TimerPeriodic, 10000000ULL);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Stage = 6;
  mN976nWindowsReport.StartCount = 1;
  mN976nWindowsReport.Checks |= 64;
  mWindowsActive = TRUE;
  MemoryFence ();
  mUfsExecutionActive = TRUE;
  MemoryFence ();
  Returned = gBS->StartImage (Child, &ExitBytes, &ExitData);
  if (N976nOsHandoffAttempted ()) {
    /* Core may already have partially shut down. Never free/unload/reopen
     * storage or return to BDS after any attempt, including a stale-map retry. */
    mN976nOsHandoffReport.Reason = 0x696;
    mN976nOsHandoffReport.Status = Returned;
    mN976nOsHandoffReport.Phase = 0xE0;
    WindowsObserved (N976N_WINDOWS_OUTCOME_FAILED, Returned);
  }
  mUfsExecutionActive = FALSE;
  mWindowsActive = FALSE;
  mN976nWindowsReport.CounterEnd = GetPerformanceCounter ();
  mN976nWindowsReport.StartStatus = Returned;
  mN976nWindowsReport.Status = Returned;
  mN976nWindowsReport.ExitDataBytes = ExitBytes;
  mN976nWindowsReport.Outcome = N976N_WINDOWS_OUTCOME_RETURNED;
  mN976nWindowsReport.Stage = 7;
  Status = N976nCancelUfsWindows ();
  if (ExitData != NULL) {
    if (ExitBytes == 0 || (!HeapContains ((UINTN)ExitData, ExitBytes) &&
        !N976nHighRamOwnedCpuRange (ExitData, ExitBytes, 1U << EfiBootServicesData))) {
      Status = EFI_COMPROMISED_DATA;
    } else { FreePool (ExitData); }
  } else if (ExitBytes != 0) { Status = EFI_COMPROMISED_DATA; }
  if (EFI_ERROR (Status)) { goto Failed; }
  /* CoreStartImage normally auto-unloads an EFI application on return. The
   * UFS owner independently proves disappearance and all-page XN before free. */
  return EFI_SUCCESS;
Failed:
  mWindowsActive = FALSE;
  mN976nWindowsReport.Status = Status;
  mN976nWindowsReport.Outcome = N976N_WINDOWS_OUTCOME_FAILED;
  N976nCancelUfsWindows ();
  return Status;
}

EFI_STATUS RunWindowsBoot (EFI_HANDLE Parent, UINT64 Profile)
{
  EFI_HANDLE Fs = NULL, Child = NULL;
  EFI_DEVICE_PATH_PROTOCOL *Path = NULL;
  EFI_LOADED_IMAGE_PROTOCOL *Gone = NULL;
  CHAR16 *ExitData = NULL;
  UINTN ExitBytes = 0;
  UINT64 Freed = 0;
  EFI_STATUS Status, Returned;
  ZeroMem ((VOID *)&mN976nWindowsReport, sizeof (mN976nWindowsReport));
  mN976nWindowsReport.Magic = N976N_WINDOWS_MAGIC;
  mN976nWindowsReport.Version = 1;
  mN976nWindowsReport.Size = sizeof (mN976nWindowsReport);
  mN976nWindowsReport.Stage = 1;
  mN976nWindowsReport.Status = EFI_NOT_STARTED;
  mN976nWindowsReport.StartStatus = EFI_NOT_STARTED;
  mN976nWindowsReport.LoadStatus = EFI_NOT_STARTED;
  mN976nWindowsReport.DeadlineSeconds = N976N_WINDOWS_DEADLINE_SECONDS;
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mWindowsAttributes);
  if (EFI_ERROR (Status) || mWindowsAttributes == NULL) { Status = EFI_UNSUPPORTED; goto Failed; }
  Status = ConnectBootMedia (&Fs);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Stage = 2;
  Status = N976nInstallBootAcpi (Profile);
  mN976nWindowsReport.AcpiStatus = Status;
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Checks |= 8;
  mN976nWindowsReport.Stage = 3;
  Status = N976nCompleteDxePhase ();
  mN976nWindowsReport.ArmStatus = Status;
  if (EFI_ERROR (Status)) { goto Failed; }
  Status = ArmObservation ();
  mN976nWindowsReport.ArmStatus = Status;
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Checks |= 16;
  Path = FileDevicePath (Fs, N976N_WINDOWS_PATH);
  if (Path == NULL) { Status = EFI_OUT_OF_RESOURCES; goto Failed; }
  mN976nWindowsReport.Stage = 4;
  Status = gBS->LoadImage (FALSE, Parent, Path, NULL, 0, &Child);
  mN976nWindowsReport.LoadStatus = Status;
  FreePool (Path); Path = NULL;
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.LoadCount++;
  Status = CheckWindowsImage (Child, Parent, Fs);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Checks |= 32;
  mN976nWindowsReport.Stage = 5;
  N976nWindowsLoadedCheckpoint ();
  mN976nWindowsReport.Frequency = GetPerformanceCounterProperties (NULL, NULL);
  if (mN976nWindowsReport.Frequency == 0 || mN976nWindowsReport.Frequency > 1000000000ULL) {
    Status = EFI_DEVICE_ERROR; goto Failed;
  }
  Status = gBS->SetWatchdogTimer (0, 0, 0, NULL);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.CounterStart = GetPerformanceCounter ();
  Status = gBS->SetTimer (mObservationEvent, TimerRelative, N976N_WINDOWS_DEADLINE_SECONDS * 10000000ULL);
  if (EFI_ERROR (Status)) { goto Failed; }
  mN976nWindowsReport.Stage = 6;
  mN976nWindowsReport.StartCount++;
  mN976nWindowsReport.Checks |= 64;
  mWindowsActive = TRUE;
  MemoryFence ();
  Returned = gBS->StartImage (Child, &ExitBytes, &ExitData);
  mWindowsActive = FALSE;
  mN976nWindowsReport.StartStatus = Returned;
  mN976nWindowsReport.ExitDataBytes = ExitBytes;
  Status = gBS->SetTimer (mObservationEvent, TimerCancel, 0);
  if (ExitData != NULL) { FreePool (ExitData); ExitData = NULL; }
  if (EFI_ERROR (Status)) { Child = NULL; goto Failed; }
  mN976nWindowsReport.Stage = 7;
  Status = gBS->HandleProtocol (Child, &gEfiLoadedImageProtocolGuid, (VOID **)&Gone);
  Child = NULL;
  mN976nWindowsReport.AutoUnloadStatus = Status;
  if (Status != EFI_INVALID_PARAMETER || Gone != NULL) { Status = EFI_COMPROMISED_DATA; goto Failed; }
  Status = mWindowsAttributes->GetMemoryAttributes (mWindowsAttributes,
    mN976nWindowsReport.ImageBase, mN976nWindowsReport.ImageBytes, &Freed);
  mN976nWindowsReport.FreedAttributes = Freed;
  if (EFI_ERROR (Status) || (Freed & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
    Status = EFI_SECURITY_VIOLATION; goto Failed;
  }
  mN976nWindowsReport.Checks |= 128;
  /* A native EFI error return is evidence, not a firmware self-test failure. */
  WindowsObserved (N976N_WINDOWS_OUTCOME_RETURNED, Returned);
Failed:
  mWindowsActive = FALSE;
  if (Path != NULL) { FreePool (Path); }
  if (ExitData != NULL) { FreePool (ExitData); }
  if (Child != NULL) { gBS->UnloadImage (Child); }
  mN976nWindowsReport.Status = Status;
  mN976nWindowsReport.Outcome = N976N_WINDOWS_OUTCOME_FAILED;
  N976nWindowsScreen (mN976nWindowsReport.Outcome, Status, mN976nWindowsReport.Checks);
  DEBUG ((DEBUG_ERROR, "SEC49 WINDOWS setup failed stage=%Lu status=%r checks=%Lx\n",
    mN976nWindowsReport.Stage, Status, mN976nWindowsReport.Checks));
  return Status;
}
