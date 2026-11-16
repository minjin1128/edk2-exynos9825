/* SPDX-License-Identifier: MIT
 * Frozen UART failure survives the terminal ClearScreen. Use upstream text
 * mode80x50 when available; its 950-pixel height ends above the retained band
 * in the admitted inset160 1440x2720 GOP view. The 80x25 fallback is compact.
 * No new MMIO, timer polling, allocation or transaction is done for display.
 */
#include <N976nUartDiag.h>
#include <N976nUartKd.h>
#include <N976nUartMux.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>

EFI_STATUS N976nShowUartDiagnostics (CONST N976N_UART_DIAG_CONTEXT *C)
{
  CONST volatile N976N_UART_KD_REPORT *U = N976nUartKdReport ();
  CONST volatile N976N_UART_MUX_REPORT *M = &mN976nUartMuxReport;
  if (C == NULL || gST == NULL || gST->ConOut == NULL ||
      gST->ConOut->Mode == NULL) return EFI_INVALID_PARAMETER;
  EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *Out = gST->ConOut;
  if (Out->Mode->Mode < 0 || Out->Mode->Mode >= Out->Mode->MaxMode)
    return EFI_NOT_READY;
  if (U->Phase == 0) return EFI_NOT_STARTED;
  UINTN Columns = 0, Rows = 0;
  EFI_STATUS Status;
  /* Query rather than assume mode1 exists. Do not select an arbitrary native
   * fullscreen mode which would place diagnostics under the band or punchhole. */
  if (Out->Mode->MaxMode > 1 &&
      !EFI_ERROR (Out->QueryMode (Out, 1, &Columns, &Rows)) &&
      Columns == 80 && Rows == 50 && Out->Mode->Mode != 1) {
    Status = Out->SetMode (Out, 1);
    if (EFI_ERROR (Status)) return Status;
  }
  Status = Out->QueryMode (Out, (UINTN)Out->Mode->Mode, &Columns, &Rows);
  if (EFI_ERROR (Status)) return Status;
  if (Columns != 80 || (Rows != 25 && Rows != 50)) return EFI_UNSUPPORTED;
  Status = Out->ClearScreen (Out);
  if (EFI_ERROR (Status)) return Status;
  BOOLEAN Full = Columns == 80 && Rows == 50;

  Print (L"SEC85 UART FIX1 / cached first failure and cleanup\r\n");
  Print (L"UART phase %Lx status %016Lx reason %Lx\r\n", U->Phase, U->Status, U->Reason);
  Print (L"FIRST phase %Lx check %Lx CAP %Lx\r\n", U->FailurePhase, U->Check, U->Captured);
  Print (L"AT %08x MASK/LIMIT %016Lx\r\n", (UINT32)U->Address, U->Mask);
  Print (L"EXP %016Lx GOT %016Lx\r\n", U->Expected, U->Actual);
  Print (L"Hz %Lu baud %Lu DIV/FRAC %Lx/%Lx marker %Lx\r\n",
    U->InputHz, U->ActualBaud, U->Divider, U->Fraction, U->MarkerBytes);
  Print (L"GATES seen %Lx: %08x %08x %08x %08x\r\n", U->GateSeen,
    (UINT32)U->GateValue[0], (UINT32)U->GateValue[1], (UINT32)U->GateValue[2], (UINT32)U->GateValue[3]);
  if (Full) {
    Print (L"GATES last:   %08x %08x %08x %08x\r\n",
      (UINT32)U->GateLast[0], (UINT32)U->GateLast[1], (UINT32)U->GateLast[2], (UINT32)U->GateLast[3]);
    Print (L"CMU local M/D %08x/%08x readback %08x/%08x valid %Lx\r\n",
      (UINT32)U->ClockMux, (UINT32)U->ClockDiv,
      (UINT32)U->ClockMuxObserved, (UINT32)U->ClockDivObserved, U->ClockLocalObservedMask);
    Print (L"TOP count %Lx compared %Lx; pairs ADDRESS:INITIAL:OBSERVED\r\n",
      U->ClockCount, U->ClockObservedMask);
    for (UINTN I = 0; I < 12; I += 2) {
      Print (L" %08x:%08x:%08x   %08x:%08x:%08x\r\n",
        (UINT32)U->ClockAddress[I], (UINT32)U->ClockValue[I], (UINT32)U->ClockObserved[I],
        (UINT32)U->ClockAddress[I+1], (UINT32)U->ClockValue[I+1], (UINT32)U->ClockObserved[I+1]);
    }
    Print (L"UART inherited QCH %08x USI %08x/%08x\r\n",
      (UINT32)U->QchBefore, (UINT32)U->UsiBefore, (UINT32)U->UsiOptionBefore);
    Print (L"PIN/PULL %08x/%08x UCON/FIFO/FLOW %08x/%08x/%08x\r\n",
      (UINT32)U->PinBefore, (UINT32)U->PullBefore, (UINT32)U->UconBefore,
      (UINT32)U->FifoBefore, (UINT32)U->FlowBefore);
  }
  Print (L"TX UTR/FIFO %08x/%08x wait %Lx disabled %Lx\r\n",
    (UINT32)U->Utrstat, (UINT32)U->Ufstat, U->WaitExit, U->DisabledOnFailure);
  Print (L"CLEAN tried/drained %Lx/%Lx wait %Lx captured %Lx\r\n",
    U->CleanupAttempted, U->CleanupDrained, U->CleanupWaitExit, U->CleanupCaptured);
  if (Full)
    Print (L"CLEAN UTR/FIFO/UCON %08x/%08x/%08x\r\n", (UINT32)U->CleanupUtrstat,
      (UINT32)U->CleanupUfstat, (UINT32)U->CleanupUcon);

  Print (L"MUX phase %Lx status %016Lx reason %Lx first %Lx\r\n",
    M->Phase, M->Status, M->Reason, M->FailurePhase);
  Print (L"MUX valid %Lx compare %Lx at %08x\r\n",
    M->CaptureValid, M->FirstCompare, (UINT32)M->FirstAddress);
  Print (L"MUX EXP %08x GOT %08x MASK %08x\r\n",
    (UINT32)M->FirstExpected, (UINT32)M->FirstActual, (UINT32)M->FirstMask);
  Print (L"PIN ph/fail %Lx/%Lx out/changed/rest %Lx/%Lx/%Lx DAT valid %Lx\r\n",
    M->PinPhase, M->PinFailurePhase, M->PinOutputMask,
    M->PinChangedMask, M->PinRestoredMask, M->PinDataValid);
  Print (L"CON old SCL/SDA %08x/%08x DAT before %08x/%08x\r\n",
    (UINT32)M->InheritedPin[0], (UINT32)M->InheritedPin[3],
    (UINT32)M->PinDataBefore[0], (UINT32)M->PinDataBefore[1]);
  Print (L"DAT released %08x/%08x ready %08x/%08x\r\n",
    (UINT32)M->PinDataReleased[0], (UINT32)M->PinDataReleased[1],
    (UINT32)M->PinDataReady[0], (UINT32)M->PinDataReady[1]);
  Print (L"DAT restored %08x/%08x latest %016Lx\r\n",
    (UINT32)M->PinDataRestored[0], (UINT32)M->PinDataRestored[1], M->Input);
  if (Full) {
    Print (L"MUX gate %08x:%08x clock %08x:%08x\r\n", (UINT32)M->GateAddress,
      (UINT32)M->GateValue, (UINT32)M->ClockAddress, (UINT32)M->ClockValue);
    Print (L"MUX QCH %08x mode %08x Hz %Lu\r\n",
      (UINT32)M->InheritedQch, (UINT32)M->InheritedMode, M->InputHz);
    Print (L"PUD/DRV old SCL %08x/%08x SDA %08x/%08x\r\n",
      (UINT32)M->InheritedPin[1], (UINT32)M->InheritedPin[2],
      (UINT32)M->InheritedPin[4], (UINT32)M->InheritedPin[5]);
    Print (L"HSI old CTL/FIFO/IE %08x/%08x/%08x USI %08x/%08x\r\n",
      (UINT32)M->InheritedControl, (UINT32)M->InheritedFifoControl,
      (UINT32)M->InheritedInterruptEnable, (UINT32)M->InheritedUsiControl, (UINT32)M->InheritedUsiOption);
    Print (L"FIRST I/T/F/A %08x %08x %08x %08x\r\n", (UINT32)M->FirstInterrupt,
      (UINT32)M->FirstTransfer, (UINT32)M->FirstFifo, (UINT32)M->FirstAuto);
    Print (L"FIRST us/exit %Lx/%Lx xfer/TX/RX %Lx/%Lx/%Lx\r\n",
      M->FirstWaitUs, M->FirstWaitExit, M->FirstTransfers, M->FirstTxBytes, M->FirstRxBytes);
    Print (L"FINAL I/T/F/A %08x %08x %08x %08x\r\n", (UINT32)M->Interrupt,
      (UINT32)M->Transfer, (UINT32)M->Fifo, (UINT32)M->Auto);
    Print (L"FINAL us/exit %Lx/%Lx xfer/TX/RX %Lx/%Lx/%Lx\r\n",
      M->WaitUs, M->WaitExit, M->Transfers, M->TxBytes, M->RxBytes);
    Print (L"CMD/reply %Lx/%Lx before/after %Lx/%Lx count %Lx\r\n",
      M->Opcode, M->Reply, M->Before, M->After, M->Opcodes);
    Print (L"UIC before/seen %Lx/%Lx VBUS/BC/CC %Lx/%Lx/%Lx\r\n",
      M->UicBefore, M->UicSeen, M->VbusAdc, M->BcStatus, M->CcStatus);
    Print (L"SETUP off %Lx exp/got %08x/%08x diff %Lx\r\n",
      M->SetupOffset, (UINT32)M->SetupExpected, (UINT32)M->SetupActual, M->SetupDiff);
  }
  Print (L"MUX retired/restored/quarantine %Lx/%Lx/%Lx\r\n", M->Retired, M->Restored, M->Quarantine);
  Print (L"WINDOWS outcome %Lx status %016Lx stage/start %Lx/%Lx\r\n",
    C->WinOutcome, C->WinStatus, C->WinStage, C->WinStart);
  Print (L"ACPI phase %Lx EBS before/exit %Lx/%Lx; zero phase = NOT RUN\r\n", C->AcpiPhase, C->EbsBefore, C->EbsExit);
  Print (L"UFS phase %Lx status %016Lx restore/Q %Lx/%Lx\r\n",
    C->UfsPhase, C->UfsStatus, C->UfsRestore, C->UfsQuarantine);
  Print (L"No capture bit = UNOBSERVED; zero alone is not a PASS.\r\n");
  if (Full) Print (L"Registers/counters hex; Hz/baud decimal. Samples are not atomic.\r\n");
  Print (L"Photo120s / VolumeDown2s release: safe shutdown. No media writes.\r\n");
  return EFI_SUCCESS;
}
