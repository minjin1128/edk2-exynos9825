/* SPDX-License-Identifier: MIT */
#ifndef N976N_UART_DIAG_H_
#define N976N_UART_DIAG_H_
#include <Uefi.h>

/* Terminal context only. This renderer never owns or samples a peripheral. */
typedef struct {
  UINT64 WinOutcome, WinStatus, WinStage, WinStart;
  UINT64 AcpiPhase, EbsBefore, EbsExit;
  UINT64 UfsPhase, UfsStatus, UfsRestore, UfsQuarantine;
} N976N_UART_DIAG_CONTEXT;
EFI_STATUS N976nShowUartDiagnostics (CONST N976N_UART_DIAG_CONTEXT *Context);
#endif
