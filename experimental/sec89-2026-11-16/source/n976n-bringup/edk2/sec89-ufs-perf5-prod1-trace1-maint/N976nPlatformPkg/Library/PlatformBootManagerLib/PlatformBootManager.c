/* SPDX-License-Identifier: MIT
 * SEC49 exercises the real BdsDxe entry and standard services. There is no
 * Windows service replacement, caller-PC allowlist or simulated arch protocol.
 */
#include <PiDxe.h>
#include <N976nPlatform.h>
#include <N976nBootFiles.h>
#include <N976nWindowsBoot.h>
#include <N976nOsHandoff.h>
#include <N976nHandoffMemory.h>
#include <N976nFramebuffer.h>
#include <N976nGopViewport.h>
#include <N976nUfs.h>
#include <N976nUfsDiag.h>
#include <N976nGpt.h>
#include <N976nUfsBlock.h>
#include <N976nUfsService.h>
#include <N976nUfsFileSystem.h>
#include <N976nBootMedia.h>
#include <N976nUfsImage.h>
#include <N976nAcpiPlatform.h>
#include <N976nHighRam.h>
#include <N976nSystemProbe.h>
#include <N976nSystemVolume.h>
#include <N976nSystemVolumeFixture.h>
#include <N976nPowerOff.h>
#include <N976nTouchLease.h>
#include <N976nUartKd.h>
#include <N976nUartDiag.h>
#include <Library/UefiLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PcdLib.h>
#include <Library/PlatformBootManagerLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiBootManagerLib.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Protocol/Bds.h>
#include <N976nEbsCheckpoint.h>
#include <N976nSec78DiagnosticMode.h>
#include <Protocol/Capsule.h>
#include <Protocol/Cpu.h>
#include <Protocol/LoadedImage.h>
#include <Protocol/DevicePath.h>
#include <Protocol/GraphicsOutput.h>
#include <Protocol/SimpleTextOut.h>
#include <Protocol/MemoryAttribute.h>
#include <Protocol/Metronome.h>
#include <Protocol/MonotonicCounter.h>
#include <Protocol/RealTimeClock.h>
#include <Protocol/Reset.h>
#include <Protocol/Runtime.h>
#include <Protocol/Security.h>
#include <Protocol/Timer.h>
#include <Protocol/Variable.h>
#include <Protocol/VariableWrite.h>
#include <Protocol/WatchdogTimer.h>

volatile N976N_BDS_REPORT mN976nBdsReport;
STATIC N976N_PLATFORM_HANDOFF mHandoff;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mMemoryAttribute;
STATIC EFI_HANDLE mGopHandle;
STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL *mGop;
STATIC N976N_PLATFORM_FB_INFO mMarginFb;
STATIC BOOLEAN mMarginsReady, mMarginsCleared;
STATIC BOOLEAN mTerminalReady;
typedef VOID (EFIAPI *N976N_SCREEN)(UINT64 Event, UINT64 Value);
STATIC N976N_SCREEN mScreen;

STATIC VOID Screen (UINT64 Event, UINT64 Value)
{
  if (mScreen != NULL) { mScreen (Event, Value); }
}

/* FIX1 replaces timing-only display slots with cached EBS checkpoints.
 * The remaining progress, memory, DMA and integrity fields are unchanged. */
VOID N976nSystemScreen (VOID)
{
  UINT64 Values[24] = {
    mN976nWindowsReport.Outcome, mN976nWindowsReport.Status, mN976nOsHandoffReport.Phase,
    mN976nOsHandoffReport.Reason, N976nSec78DiagnosticMode,
    mN976nEbsCheckpointReport.Mark, mN976nOsHandoffReport.BeforeCount,
    mN976nOsHandoffReport.ExitCount,
    mN976nSystemRunReport.Calls, mN976nSystemRunReport.Bytes,
    mN976nSystemRunReport.SdiBytes, mN976nSystemRunReport.WimBytes,
    mN976nEbsCheckpointReport.PauseExit, mN976nEbsCheckpointReport.Count,
    mN976nSystemRunReport.Rejected,
    mN976nOsHandoffReport.Checks, mN976nHandoffMemoryReport.Checks,
    mN976nHighRamReport[2], mN976nUfsReport.Phase, mN976nUfsReport.Status,
    mN976nUfsExitReport.Checks, mN976nEbsCheckpointReport.Seen,
    N976nSystemWindowsProgress (), mN976nOsHandoffReport.FailedCount
  };
  for (UINTN I = 0; I < ARRAY_SIZE (Values); I++) Screen (9 + I, Values[I]);
}

/* Captured RAM/volume progress only; never allocate or touch the controller. */
VOID N976nHighRamScreen (VOID) { N976nSystemScreen (); }

STATIC EFI_STATUS BlackScreen (VOID)
{
  if (mGop == NULL || !N976nGopViewModeValid (mGop->Mode)) return EFI_SECURITY_VIOLATION;
  return mGop->SetMode (mGop, 0);
}

/* Accepted-EBS final paint may have touched physical pixels below the public
 * view. Use only the pre-admitted cached HOB; no protocol, allocation, timer or
 * Boot Services call is permitted here. The full maintenance view is a no-op. */
VOID N976nClearDisplayMarginsForExit (VOID)
{
  if (N976N_GOP_Y_INSET == 0 || !mMarginsReady || mMarginsCleared ||
      !N976nFbInfoValid (&mMarginFb)) return;
  mMarginsCleared = TRUE;
  UINT32 Black = (UINT32)mMarginFb.ReservedByteValue << 24;
  UINTN Pixels = (UINTN)(N976N_GOP_Y_INSET * mMarginFb.PitchBytes / 4);
  volatile UINT32 *Top = (volatile UINT32 *)(UINTN)mMarginFb.Base;
  volatile UINT32 *Bottom = (volatile UINT32 *)(UINTN)
    (mMarginFb.Base + mMarginFb.VisibleBytes - (UINT64)Pixels * 4);
  for (UINTN I = 0; I < Pixels; ++I) { Top[I] = Black; Bottom[I] = Black; }
  __asm__ __volatile__ ("dsb sy" ::: "memory");
}

VOID EFIAPI N976nWindowsScreen (UINT64 Outcome, UINT64 Status, UINT64 Checks)
{
  (VOID)Outcome; (VOID)Status; (VOID)Checks;
  N976nHighRamScreen ();
}
VOID N976nUfsWindowsObserved (VOID)
{
  /* The native observer has recorded its outcome. These values describe live
     storage; absence of a returned child never claims successful retirement. */
  N976nPublishUfsObservation ();
}
STATIC CONST EFI_GUID mProbeVariableGuid =
  {0x76bade54,0xcf8d,0x4289,{0xac,0x02,0xcd,0x23,0x57,0x5a,0x1d,0x31}};
STATIC CHAR16 mProbeVariableName[] = L"N976nSec43BdsProbe";

STATIC BOOLEAN Span (UINT64 Base, UINT64 Size)
{
  return Base != 0 && Size != 0 && ((Base | Size) & 4095) == 0 && Size <= MAX_UINT64 - Base;
}

STATIC BOOLEAN Contains (UINT64 Base, UINT64 Size, UINT64 Address, UINT64 Bytes)
{
  return Address >= Base && Address - Base <= Size && Bytes <= Size - (Address - Base);
}

STATIC BOOLEAN Overlap (UINT64 A, UINT64 An, UINT64 B, UINT64 Bn)
{
  return A < B + Bn && B < A + An;
}

__attribute__((noinline, noreturn))
VOID EFIAPI N976nBdsStop (EFI_STATUS Status)
{
  mN976nBdsReport.Status = Status;
  __asm__ __volatile__ ("mrs %0, sctlr_el1" : "=r" (mN976nBdsReport.Sctlr));
  __asm__ __volatile__ ("mrs %0, mair_el1" : "=r" (mN976nBdsReport.Mair));
  __asm__ __volatile__ ("mrs %0, daif" : "=r" (mN976nBdsReport.Daif));
  DisableInterrupts ();
  Screen (1, mN976nBdsReport.Stage);
  Screen (2, mN976nBdsReport.Status);
  Screen (3, mN976nBdsReport.Checks);
  Screen (4, mN976nBdsReport.ArchMask);
  Screen (8, mN976nBdsReport.Complete);
  MemoryFence ();
  if (mTerminalReady) {
    N976nPreparePowerOff (&mHandoff, N976nUfsShutdownSafe ());
    N976nSystemScreen ();
  }
  /* The terminal marker also commits the final diagnostic rendering. */
  DEBUG ((DEBUG_ERROR, "SEC49 BDS STOP status=%r stage=%Lu checks=%Lx arch=%Lx\n",
          Status, mN976nBdsReport.Stage, mN976nBdsReport.Checks, mN976nBdsReport.ArchMask));
  if (mTerminalReady) {
    N976nPowerOffWait (&mHandoff, N976nUfsShutdownSafe (), BlackScreen, N976nSystemScreen);
  }
  for (;;) { CpuDeadLoop (); }
}

STATIC VOID ReadHandoff (VOID)
{
  VOID *Hob = GetFirstGuidHob (&gN976nPlatformHandoffGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (mHandoff)) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  CopyMem (&mHandoff, GET_GUID_HOB_DATA (Hob), sizeof (mHandoff));
  if (mHandoff.Magic != N976N_PLATFORM_HANDOFF_MAGIC ||
      mHandoff.Version != N976N_PLATFORM_ABI_VERSION || mHandoff.Size != sizeof (mHandoff) ||
      mHandoff.Profile != PcdGet32 (PcdN976nPlatformProfile) || mHandoff.Profile > 1 ||
      mHandoff.Reserved != 0 || !Span (mHandoff.FirmwareBase, mHandoff.FirmwareSize) ||
      !Span (mHandoff.HeapBase, mHandoff.HeapSize) || !Span (mHandoff.StackBase, mHandoff.StackSize) ||
      Overlap (mHandoff.FirmwareBase, mHandoff.FirmwareSize, mHandoff.HeapBase, mHandoff.HeapSize) ||
      Overlap (mHandoff.FirmwareBase, mHandoff.FirmwareSize, mHandoff.StackBase, mHandoff.StackSize) ||
      Overlap (mHandoff.HeapBase, mHandoff.HeapSize, mHandoff.StackBase, mHandoff.StackSize) ||
      !Span (mHandoff.ImageBase, mHandoff.ImageSize) || (mHandoff.Screen & 3) != 0 ||
      !Contains (mHandoff.ImageBase, mHandoff.ImageSize, mHandoff.Screen, 4) ||
      !Contains (mHandoff.ImageBase, mHandoff.ImageSize, mHandoff.ReportAddress, 512)) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  /* The SEC admitted this callback as part of the owned wrapper image. Check
     its current permissions before it becomes an error-reporting path. */
  UINT64 ScreenAttributes, ReportAttributes;
  EFI_STATUS Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mMemoryAttribute);
  if (EFI_ERROR (Status) || mMemoryAttribute == NULL ||
      EFI_ERROR (mMemoryAttribute->GetMemoryAttributes (mMemoryAttribute,
        mHandoff.Screen & ~4095ULL, 4096, &ScreenAttributes)) ||
      EFI_ERROR (mMemoryAttribute->GetMemoryAttributes (mMemoryAttribute,
        mHandoff.ReportAddress, 512, &ReportAttributes)) ||
      (ScreenAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_RO ||
      (ReportAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP | EFI_MEMORY_RP)) != EFI_MEMORY_XP) {
    N976nBdsStop (EFI_SECURITY_VIOLATION);
  }
  mScreen = (N976N_SCREEN)(UINTN)mHandoff.Screen;
  mN976nBdsReport.Profile = mHandoff.Profile;
  mN976nBdsReport.Checks |= 1;
}

STATIC VOID CheckArch (VOID)
{
  EFI_GUID *Protocols[] = {
    &gEfiSecurityArchProtocolGuid, &gEfiCpuArchProtocolGuid, &gEfiMetronomeArchProtocolGuid,
    &gEfiTimerArchProtocolGuid, &gEfiBdsArchProtocolGuid, &gEfiWatchdogTimerArchProtocolGuid,
    &gEfiRuntimeArchProtocolGuid, &gEfiVariableArchProtocolGuid, &gEfiVariableWriteArchProtocolGuid,
    &gEfiCapsuleArchProtocolGuid, &gEfiMonotonicCounterArchProtocolGuid,
    &gEfiResetArchProtocolGuid, &gEfiRealTimeClockArchProtocolGuid
  };
  VOID *Interface;
  for (UINTN I = 0; I < ARRAY_SIZE (Protocols); I++) {
    Interface = NULL;
    EFI_STATUS Status = gBS->LocateProtocol (Protocols[I], NULL, &Interface);
    /* Variable/reset/etc. architectural protocols legitimately have NULL interfaces. */
    if (EFI_ERROR (Status)) { N976nBdsStop (Status); }
    mN976nBdsReport.ArchMask |= LShiftU64 (1, I);
  }
  mN976nBdsReport.Checks |= 2;
}

STATIC BOOLEAN TableCrc (EFI_TABLE_HEADER *Header, UINT64 Signature, UINTN Size)
{
  UINT8 Copy[512];
  UINT32 Crc;
  if (Header == NULL || Header->Signature != Signature || Header->HeaderSize != Size ||
      Size > sizeof (Copy) || Header->Reserved != 0) { return FALSE; }
  CopyMem (Copy, Header, Size);
  ((EFI_TABLE_HEADER *)Copy)->CRC32 = 0;
  return !EFI_ERROR (gBS->CalculateCrc32 (Copy, Size, &Crc)) && Crc == Header->CRC32;
}

STATIC VOID CheckTables (VOID)
{
  if (gST->BootServices != gBS || gST->RuntimeServices != gRT ||
      !TableCrc (&gST->Hdr, EFI_SYSTEM_TABLE_SIGNATURE, sizeof (*gST)) ||
      !TableCrc (&gBS->Hdr, EFI_BOOT_SERVICES_SIGNATURE, sizeof (*gBS)) ||
      !TableCrc (&gRT->Hdr, EFI_RUNTIME_SERVICES_SIGNATURE, sizeof (*gRT))) {
    N976nBdsStop (EFI_CRC_ERROR);
  }
  mN976nBdsReport.Checks |= 4;
}

STATIC VOID CheckVariables (VOID)
{
  CONST UINT64 Expected[2] = {0x5345433432424453ULL, 0xFEDCBA9876543210ULL};
  UINT64 Actual[2] = {0, 0};
  UINT32 Attributes = 0;
  UINTN Size = sizeof (Actual);
  EFI_STATUS Status = gRT->GetVariable (mProbeVariableName, (EFI_GUID *)&mProbeVariableGuid,
                                      &Attributes, &Size, Actual);
  if (Status != EFI_NOT_FOUND) { mN976nBdsReport.VariableStatus = Status; N976nBdsStop (EFI_COMPROMISED_DATA); }
  Status = gRT->SetVariable (mProbeVariableName, (EFI_GUID *)&mProbeVariableGuid,
                            EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS,
                            sizeof (Expected), (VOID *)Expected);
  if (EFI_ERROR (Status)) { mN976nBdsReport.VariableStatus = Status; N976nBdsStop (Status); }
  Size = sizeof (Actual);
  Status = gRT->GetVariable (mProbeVariableName, (EFI_GUID *)&mProbeVariableGuid,
                            &Attributes, &Size, Actual);
  BOOLEAN Valid = !EFI_ERROR (Status) && Size == sizeof (Expected) &&
    Attributes == (EFI_VARIABLE_BOOTSERVICE_ACCESS | EFI_VARIABLE_RUNTIME_ACCESS) &&
    CompareMem (Actual, Expected, sizeof (Expected)) == 0;
  EFI_STATUS Delete = gRT->SetVariable (mProbeVariableName, (EFI_GUID *)&mProbeVariableGuid, 0, 0, NULL);
  if (!Valid || EFI_ERROR (Delete)) {
    mN976nBdsReport.VariableStatus = Valid ? Delete : EFI_COMPROMISED_DATA;
    N976nBdsStop ((EFI_STATUS)mN976nBdsReport.VariableStatus);
  }
  Size = sizeof (Actual);
  Status = gRT->GetVariable (mProbeVariableName, (EFI_GUID *)&mProbeVariableGuid, NULL, &Size, Actual);
  mN976nBdsReport.VariableStatus = Status;
  if (Status != EFI_NOT_FOUND) { N976nBdsStop (EFI_COMPROMISED_DATA); }
  mN976nBdsReport.Checks |= 8;
}

STATIC EFI_STATUS Attributes (UINT64 Address, UINT64 *Value)
{
  return mMemoryAttribute->GetMemoryAttributes (mMemoryAttribute, Address & ~4095ULL, 4096, Value);
}

STATIC VOID CheckMemory (VOID)
{
  EFI_LOADED_IMAGE_PROTOCOL *Loaded = NULL;
  UINT64 StackObject = 0, Code, Data, Stack;
  EFI_STATUS Status = gBS->HandleProtocol (gImageHandle, &gEfiLoadedImageProtocolGuid, (VOID **)&Loaded);
  if (EFI_ERROR (Status) || Loaded == NULL ||
      !Contains (mHandoff.HeapBase, mHandoff.HeapSize, (UINT64)(UINTN)Loaded->ImageBase, Loaded->ImageSize) ||
      !Contains ((UINT64)(UINTN)Loaded->ImageBase, Loaded->ImageSize, (UINT64)(UINTN)CheckMemory, 4) ||
      !Contains ((UINT64)(UINTN)Loaded->ImageBase, Loaded->ImageSize, (UINT64)(UINTN)&mN976nBdsReport, sizeof (mN976nBdsReport)) ||
      !Contains (mHandoff.StackBase, mHandoff.StackSize, (UINT64)(UINTN)&StackObject, sizeof (StackObject))) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  mN976nBdsReport.ImageBase = (UINT64)(UINTN)Loaded->ImageBase;
  mN976nBdsReport.ImageSize = Loaded->ImageSize;
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&mMemoryAttribute);
  if (EFI_ERROR (Status) || mMemoryAttribute == NULL) { N976nBdsStop (EFI_UNSUPPORTED); }
  if (EFI_ERROR (Attributes ((UINT64)(UINTN)CheckMemory, &Code)) ||
      EFI_ERROR (Attributes ((UINT64)(UINTN)&mN976nBdsReport, &Data)) ||
      EFI_ERROR (Attributes ((UINT64)(UINTN)&StackObject, &Stack))) { N976nBdsStop (EFI_DEVICE_ERROR); }
  mN976nBdsReport.CodeAttributes = Code;
  mN976nBdsReport.DataAttributes = Data;
  mN976nBdsReport.StackAttributes = Stack;
  if ((Code & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_RO ||
      (Data & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_XP ||
      (Stack & (EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_XP) {
    N976nBdsStop (EFI_SECURITY_VIOLATION);
  }
  mN976nBdsReport.Checks |= 0x20;
  EFI_PHYSICAL_ADDRESS Page = 0;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesData, 1, &Page);
  mN976nBdsReport.MemoryStatus = Status;
  if (EFI_ERROR (Status)) { N976nBdsStop (Status); }
  mN976nBdsReport.AllocationAddress = Page;
  UINT64 PageAttributes = 0;
  BOOLEAN Valid = Contains (mHandoff.HeapBase, mHandoff.HeapSize, Page, 4096) &&
    !EFI_ERROR (Attributes (Page, &PageAttributes)) &&
    (PageAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP)) == EFI_MEMORY_XP;
  mN976nBdsReport.AllocationAttributes = PageAttributes;
  Status = gBS->FreePages (Page, 1);
  mN976nBdsReport.MemoryStatus = Status;
  if (!Valid || EFI_ERROR (Status)) { N976nBdsStop (EFI_SECURITY_VIOLATION); }
  mN976nBdsReport.Checks |= 0x40;

  /* A code allocation is writable storage until the sealed-image loader has
     validated and published its individual executable sections. */
  Page = 0;
  Status = gBS->AllocatePages (AllocateAnyPages, EfiBootServicesCode, 1, &Page);
  mN976nBdsReport.CodeAllocationStatus = Status;
  if (EFI_ERROR (Status)) { N976nBdsStop (Status); }
  mN976nBdsReport.CodeAllocationAddress = Page;
  PageAttributes = 0;
  Valid = (Page & 4095) == 0 &&
    Contains (mHandoff.HeapBase, mHandoff.HeapSize, Page, 4096) &&
    !EFI_ERROR (Attributes (Page, &PageAttributes)) &&
    (PageAttributes & (EFI_MEMORY_RO | EFI_MEMORY_XP)) == EFI_MEMORY_XP;
  mN976nBdsReport.CodeAllocationAttributes = PageAttributes;
  Status = gBS->FreePages (Page, 1);
  mN976nBdsReport.CodeAllocationStatus = Status;
  if (!Valid || EFI_ERROR (Status)) { N976nBdsStop (EFI_SECURITY_VIOLATION); }
  mN976nBdsReport.Checks |= 0x80;
}

STATIC VOID CheckTimer (VOID)
{
  EFI_EVENT Event = NULL;
  UINT64 Frequency = GetPerformanceCounterProperties (NULL, NULL);
  mN976nBdsReport.Frequency = Frequency;
  if (Frequency == 0 || Frequency > 1000000000ULL) { N976nBdsStop (EFI_DEVICE_ERROR); }
  EFI_STATUS Status = gBS->CreateEvent (EVT_TIMER, TPL_CALLBACK, NULL, NULL, &Event);
  if (EFI_ERROR (Status)) { mN976nBdsReport.TimerStatus = Status; N976nBdsStop (Status); }
  UINT64 Start = GetPerformanceCounter ();
  mN976nBdsReport.CounterStart = Start;
  Status = gBS->SetTimer (Event, TimerRelative, 100000); /* 10ms, actual interrupt-driven event. */
  if (!EFI_ERROR (Status)) {
    Status = EFI_TIMEOUT;
    for (UINTN Poll = 0; Poll < 2000000; Poll++) {
      EFI_STATUS Check = gBS->CheckEvent (Event);
      UINT64 Now = GetPerformanceCounter ();
      mN976nBdsReport.TimerPolls = Poll + 1;
      mN976nBdsReport.CounterEnd = Now;
      if (Check == EFI_SUCCESS) { Status = EFI_SUCCESS; break; }
      if (Check != EFI_NOT_READY) { Status = Check; break; }
      if (Now - Start >= 2 * Frequency) { break; }
      CpuPause ();
    }
  }
  EFI_STATUS Cancel = gBS->SetTimer (Event, TimerCancel, 0);
  EFI_STATUS Close = gBS->CloseEvent (Event);
  if (!EFI_ERROR (Status) && EFI_ERROR (Cancel)) { Status = Cancel; }
  if (!EFI_ERROR (Status) && EFI_ERROR (Close)) { Status = Close; }
  mN976nBdsReport.TimerStatus = Status;
  if (EFI_ERROR (Status) || mN976nBdsReport.CounterEnd <= Start) {
    N976nBdsStop (EFI_ERROR (Status) ? Status : EFI_DEVICE_ERROR);
  }
  mN976nBdsReport.Checks |= 0x10;
}

/* NTDEV's narrow console pattern: publish the actual GOP device path as
 * ConOut, then let standard BDS connect GraphicsConsole/ConSplitter. The boot
 * file self-check is separate; no SoC reset or reference-platform MMIO is used. */
STATIC VOID RegisterConsole (VOID)
{
  EFI_HANDLE *Handles = NULL;
  UINTN Count = 0;
  EFI_STATUS Status = gBS->LocateHandleBuffer (ByProtocol, &gEfiGraphicsOutputProtocolGuid,
                                              NULL, &Count, &Handles);
  if (EFI_ERROR (Status) || Count != 1 || Handles == NULL) {
    if (Handles != NULL) { gBS->FreePool (Handles); }
    mN976nBdsReport.GopStatus = EFI_ERROR (Status) ? Status : EFI_COMPROMISED_DATA;
    N976nBdsStop ((EFI_STATUS)mN976nBdsReport.GopStatus);
  }
  mGopHandle = Handles[0];
  gBS->FreePool (Handles);
  EFI_GRAPHICS_OUTPUT_PROTOCOL *Gop = NULL;
  EFI_DEVICE_PATH_PROTOCOL *Path = NULL;
  Status = gBS->HandleProtocol (mGopHandle, &gEfiGraphicsOutputProtocolGuid, (VOID **)&Gop);
  if (EFI_ERROR (Status) || Gop == NULL || !N976nGopViewModeValid (Gop->Mode)) {
    mN976nBdsReport.GopStatus = EFI_COMPROMISED_DATA; N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info = NULL;
  UINTN Size = 0;
  Status = Gop->QueryMode (Gop, 0, &Size, &Info);
  mN976nBdsReport.GopStatus = Status;
  BOOLEAN Valid = !EFI_ERROR (Status) && Info != NULL && Size == sizeof (*Info) &&
    N976nGopViewInfoValid (Info);
  if (Info != NULL && EFI_ERROR (gBS->FreePool (Info))) { Valid = FALSE; }
  if (!Valid) { N976nBdsStop (EFI_COMPROMISED_DATA); }
  VOID *FbHob = GetFirstGuidHob (&gN976nFramebufferHobGuid);
  if (FbHob == NULL || GET_GUID_HOB_DATA_SIZE (FbHob) != sizeof (N976N_PLATFORM_FB_REPORT)) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  CONST N976N_PLATFORM_FB_REPORT *FbReport = GET_GUID_HOB_DATA (FbHob);
  if (FbReport->Raw[0] != 0xFF || FbReport->Raw[1] != 0 || FbReport->Raw[2] != 0 ||
      FbReport->Raw[31] != 0 || !N976nFbInfoValid (&FbReport->Info)) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  CopyMem (&mMarginFb, &FbReport->Info, sizeof (mMarginFb));
  mMarginsReady = TRUE;
  mGop = Gop;
  mN976nBdsReport.ConsoleChecks |= 1;
  Status = gBS->HandleProtocol (mGopHandle, &gEfiDevicePathProtocolGuid, (VOID **)&Path);
  if (!EFI_ERROR (Status) && Path != NULL) { Status = EfiBootManagerUpdateConsoleVariable (ConOut, Path, NULL); }
  else if (!EFI_ERROR (Status)) { Status = EFI_COMPROMISED_DATA; }
  mN976nBdsReport.ConsoleStatus = Status;
  if (EFI_ERROR (Status)) { N976nBdsStop (Status); }
}

STATIC VOID CheckConsole (VOID)
{
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Native = NULL;
  EFI_STATUS Status = gBS->HandleProtocol (mGopHandle, &gEfiSimpleTextOutProtocolGuid, (VOID **)&Native);
  if (EFI_ERROR (Status) || Native == NULL || gST->ConOut == NULL || gST->ConOut->Mode == NULL ||
      gST->ConOut->Mode->Mode < 0 || gST->ConOut->Mode->Mode >= gST->ConOut->Mode->MaxMode) {
    mN976nBdsReport.ConsoleStatus = EFI_NOT_READY; N976nBdsStop (EFI_NOT_READY);
  }
  mN976nBdsReport.ConsoleChecks |= 2;
  Status = gST->ConOut->SetAttribute (gST->ConOut, EFI_WHITE | EFI_BACKGROUND_BLACK);
  if (!EFI_ERROR (Status)) { Status = gST->ConOut->ClearScreen (gST->ConOut); }
  if (!EFI_ERROR (Status)) {
    Status = gST->ConOut->OutputString (gST->ConOut,
      L"\r\n  N976N SEC85 UART FIX1 - Standard UEFI\r\n"
      L"  DXE / BDS graphics console connected.\r\n"
      L"  Checking variables, timer and memory protection.\r\n");
  }
  mN976nBdsReport.ConsoleStatus = Status;
  if (EFI_ERROR (Status)) { N976nBdsStop (Status); }
  /* Pixel output is observed independently by the local test and on hardware;
     this bit records the actual standard console call's successful return. */
  mN976nBdsReport.ConsoleChecks |= 4;
}

VOID EFIAPI PlatformBootManagerBeforeConsole (VOID)
{
  ZeroMem ((VOID *)&mN976nBdsReport, sizeof (mN976nBdsReport));
  mN976nBdsReport.Magic = N976N_BDS_REPORT_MAGIC;
  mN976nBdsReport.Version = N976N_PLATFORM_ABI_VERSION;
  mN976nBdsReport.Size = sizeof (mN976nBdsReport);
  mN976nBdsReport.Stage = 1;
  mN976nBdsReport.Status = EFI_NOT_STARTED;
  ReadHandoff ();
  Screen (1, 1);
  RegisterConsole ();
}

/* Diagnostic display consumes the validated in-memory SYSTEM identity and
   completed probe report only. It does not obtain a new read capability. */
STATIC EFI_STATUS ShowSystemResult (VOID)
{
  /* Terminal display must not call readiness predicates or re-read MMIO.
   * Keep the first UART/mux stop after cleanup, instead of erasing its detail. */
  if (mHandoff.Profile == N976N_PLATFORM_PROFILE_PHONE && N976nUartKdReport ()->Phase != 0) {
    CONST N976N_UART_DIAG_CONTEXT Context = {
      mN976nWindowsReport.Outcome, mN976nWindowsReport.Status,
      mN976nWindowsReport.Stage, mN976nWindowsReport.StartCount,
      mN976nAcpiReport.Phase, mN976nOsHandoffReport.BeforeCount, mN976nOsHandoffReport.ExitCount,
      mN976nUfsReport.Phase, mN976nUfsReport.Status, mN976nUfsReport.Restore, mN976nUfsReport.Quarantined
    };
    return N976nShowUartDiagnostics (&Context);
  }
  UINTN Columns = 0, Rows = 0;
  EFI_STATUS Status = gST->ConOut->QueryMode (gST->ConOut,
    (UINTN)gST->ConOut->Mode->Mode, &Columns, &Rows);
  if (EFI_ERROR (Status)) return Status;
  if (Columns < 80 || Rows < 25) return EFI_UNSUPPORTED;
  Status = gST->ConOut->ClearScreen (gST->ConOut);
  if (EFI_ERROR (Status)) return Status;
  Print (L"SEC85: SYSTEM FAT Windows execution result\r\n");
  Print (L"Windows outcome %Lx status %r stage %Lx; start %Lx\r\n",
    mN976nWindowsReport.Outcome, (EFI_STATUS)mN976nWindowsReport.Status,
    mN976nWindowsReport.Stage, mN976nWindowsReport.StartCount);
  Print (L"Volume %r reason %Lx checks %Lx; UFS restore %Lx\r\n",
    (EFI_STATUS)mN976nSystemVolumeReport.Status, mN976nSystemVolumeReport.Reason,
    mN976nSystemVolumeReport.Checks, mN976nUfsReport.Restore);
  Print (L"ACPI phase %Lx status %r reason %Lx checks %Lx\r\n",
    mN976nAcpiReport.Phase, (EFI_STATUS)mN976nAcpiReport.Status,
    mN976nAcpiReport.Reason, mN976nAcpiReport.Checks);
  Print (L"UFS reason %Lx quarantine %Lx; RAM phase %Lx status %r\r\n",
    mN976nUfsReport.Reason, mN976nUfsReport.Quarantined,
    mN976nHighRamReport[0], (EFI_STATUS)mN976nHighRamReport[1]);
  Print (L"Windows reads %Lx bytes %Lx; SDI %Lx WIM %Lx\r\n",
    mN976nSystemRunReport.Calls, mN976nSystemRunReport.Bytes,
    mN976nSystemRunReport.SdiBytes, mN976nSystemRunReport.WimBytes);
  Print (L"Read counters include repeated file extents; not a full-file hash.\r\n");
  Print (L"High CPU reads %Lx bytes %Lx; rejected %Lx\r\n",
    mN976nSystemRunReport.HighCalls, mN976nSystemRunReport.HighBytes,
    mN976nSystemRunReport.Rejected);
  if (mHandoff.Profile == N976N_PLATFORM_PROFILE_QEMU)
    Print (L"QEMU host-file fixture only; physical UFS NOT TESTED.\r\n");
  Print (L"Read-only SYSTEM; no partition writes or completed OS handoff.\r\n"
         L"After safe cleanup: unplug USB/charger and release Power.\r\n"
         L"Safe shutdown: Photo120s or VolumeDown2s then release.\r\n"
         L"If shutdown is refused, diagnostics remain visible; no power request.\r\n");
  return EFI_SUCCESS;
}

VOID EFIAPI PlatformBootManagerAfterConsole (VOID)
{
  if (mN976nBdsReport.Stage != 1 || mN976nBdsReport.Checks != 1) { N976nBdsStop (EFI_COMPROMISED_DATA); }
  CheckConsole ();
  mN976nBdsReport.Stage = 2;
  Screen (1, 2);
  CheckArch ();
  mN976nBdsReport.Stage = 3;
  Screen (1, 3);
  CheckTables ();
  mN976nBdsReport.Stage = 4;
  Screen (1, 4);
  CheckVariables ();
  mN976nBdsReport.Stage = 5;
  Screen (1, 5);
  CheckMemory ();
  mN976nBdsReport.Stage = 6;
  Screen (1, 6);
  CheckTimer ();
  if (mN976nBdsReport.Checks != N976N_BDS_CHECKS_ALL || mN976nBdsReport.ArchMask != 0x1FFF || mN976nBdsReport.ConsoleChecks != 7) {
    N976nBdsStop (EFI_COMPROMISED_DATA);
  }
  mN976nBdsReport.Stage = 7;
  Screen (1, 7);
  EFI_STATUS BootStatus = RunBootFiles (gImageHandle);
  if (EFI_ERROR (BootStatus)) { N976nBdsStop (BootStatus); }
  BootStatus = gST->ConOut->OutputString (gST->ConOut,
    L"  Boot files: READ ONLY / EFI execution: PASS\r\n"
    L"  Application returned; executable pages released.\r\n"
    L"  SEC85: low-DMA setup before high-RAM publication.\r\n"
    L"  Read-only SYSTEM; native PE and private polling touch demo.\r\n");
  if (EFI_ERROR (BootStatus)) { N976nBdsStop (BootStatus); }
  BootStatus = N976nTouchLeasePublish (mHandoff.Profile);
  if (EFI_ERROR (BootStatus)) { N976nBdsStop (BootStatus); }
  N976nResetSystemProbe ();
  N976nRunUfsProbe (&mHandoff);
  if (mHandoff.Profile == N976N_PLATFORM_PROFILE_QEMU) {
    N976nRunSystemVolumeFixture (&mHandoff);
  }
  /* Rendering failure keeps its error status but must not bypass the unchanged
     storage-safe terminal shutdown gate after the probe has returned. */
  mTerminalReady = TRUE;
  BootStatus = ShowSystemResult ();
  if (EFI_ERROR (BootStatus)) { N976nBdsStop (BootStatus); }
  N976nSystemScreen ();
  mN976nBdsReport.Stage = 8;
  mN976nBdsReport.Complete = N976N_BDS_COMPLETE;
  N976nBdsStop (EFI_SUCCESS);
}

VOID EFIAPI PlatformBootManagerWaitCallback (UINT16 TimeoutRemain)
{
  (VOID)TimeoutRemain;
  /* This milestone stops in AfterConsole, before the boot-option loop. */
  N976nBdsStop (EFI_ABORTED);
}

VOID EFIAPI PlatformBootManagerUnableToBoot (VOID)
{
  N976nBdsStop (EFI_NOT_FOUND);
}
