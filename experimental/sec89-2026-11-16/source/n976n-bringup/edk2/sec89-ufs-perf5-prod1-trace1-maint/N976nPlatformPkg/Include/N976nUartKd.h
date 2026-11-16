/* SPDX-License-Identifier: MIT */
#ifndef N976N_UART_KD_H_
#define N976N_UART_KD_H_

#include <N976nPlatform.h>
#include <IndustryStandard/Acpi65.h>
#include <IndustryStandard/DebugPort2Table.h>

#define N976N_UART_KD_BASE   0x10440000ULL
#define N976N_UART_KD_BYTES  0x100U
/* Microsoft DBG2 Table 3; this subtype is absent from the pinned EDK2 header. */
#define N976N_UART_KD_SAM5250 0x000AU

#pragma pack (1)
typedef struct {
  EFI_ACPI_DEBUG_PORT_2_DESCRIPTION_TABLE Table;
  EFI_ACPI_DBG2_DEBUG_DEVICE_INFORMATION_STRUCT Device;
  EFI_ACPI_6_5_GENERIC_ADDRESS_STRUCTURE Register;
  UINT32 AddressSize;
  CHAR8 Namespace[2];
} N976N_UART_DBG2;
#pragma pack ()

STATIC_ASSERT (sizeof (N976N_UART_DBG2) == 84, "DBG2 one SAM5250 port");
STATIC_ASSERT (OFFSET_OF (N976N_UART_DBG2, Device) == 44, "DBG2 device offset");
STATIC_ASSERT (OFFSET_OF (N976N_UART_DBG2, Register) == 66, "DBG2 GAS offset");

/* Kept separate from the established ACPI report ABI. Published is set only
 * after exact installed-table, allocation ownership and XN checks succeed. */
typedef struct {
  UINT64 Published, Address, Bytes, OwnershipChecks, AttributeChecks;
} N976N_UART_DBG2_REPORT;

extern volatile N976N_UART_DBG2_REPORT mN976nUartDbg2Report;

/* Captured means an existing access was observed, not that its value passed.
 * A zero word without its bit is unobserved. No renderer may sample hardware.
 */
#define N976N_UART_KD_CAP_CLOCK_LOCAL   BIT0
#define N976N_UART_KD_CAP_CLOCK_TOP     BIT1
#define N976N_UART_KD_CAP_QCH           BIT2
#define N976N_UART_KD_CAP_GATES         BIT3
#define N976N_UART_KD_CAP_UART          BIT4
#define N976N_UART_KD_CAP_PINS          BIT5
#define N976N_UART_KD_CAP_WAIT          BIT6
#define N976N_UART_KD_CAP_BAUD          BIT7
#define N976N_UART_KD_CAP_FAILURE       BIT8
#define N976N_UART_KD_CAP_DETAIL        BIT9
#define N976N_UART_KD_CAP_CLEANUP       BIT10
#define N976N_UART_KD_CAP_CLOCK_COMPARE BIT11
#define N976N_UART_KD_CAP_TIMER         BIT12
#define N976N_UART_KD_CAP_COMPUTED_HZ   BIT13

#define N976N_UART_KD_CHECK_EQUAL       1U
#define N976N_UART_KD_CHECK_NOT_EQUAL   2U
#define N976N_UART_KD_CHECK_DMA_MODE    3U
#define N976N_UART_KD_CHECK_PLL         4U
#define N976N_UART_KD_CHECK_RANGE       5U
#define N976N_UART_KD_CHECK_WAIT        6U

typedef struct {
  /* Original fields retained. Address/Expected/Actual now denote the first
   * refused predicate only, valid with CAP_DETAIL, never a last unrelated read.
   * EQUAL/NOT_EQUAL apply Mask. RANGE uses Expected/Mask as inclusive lower/
   * upper limits; other Check values describe a compound predicate.
   */
  UINT64 Phase, Status, Reason, Address, Expected, Actual;
  UINT64 InputHz, ActualBaud, Divider, Fraction, MarkerBytes, WaitExit;
  UINT64 UconBefore, FifoBefore, PinBefore, PullBefore, QchBefore;
  UINT64 Utrstat, Ufstat, DisabledOnFailure, UsiBefore, UsiOptionBefore;
  UINT64 Captured, FailurePhase, Check, Mask;
  UINT64 GateSeen, GateValue[4], GateLast[4];
  UINT64 ClockCount, ClockAddress[12], ClockValue[12], ClockObserved[12];
  UINT64 ClockObservedMask, ClockMux, ClockDiv;
  UINT64 ClockMuxObserved, ClockDivObserved, ClockLocalObservedMask;
  UINT64 ComputedHz, TimerHz, TimerStart, TimerEnd, FlowBefore;
  UINT64 CleanupAttempted, CleanupDrained, CleanupWaitExit;
  UINT64 CleanupUtrstat, CleanupUfstat, CleanupUcon, CleanupCaptured;
} N976N_UART_KD_REPORT;

/* Returns cached bytes only; no readiness recheck, clock or MMIO access. */
CONST volatile N976N_UART_KD_REPORT *N976nUartKdReport (VOID);

/* Supplied by the UART handoff implementation. A TWRP byte exchange alone is
 * not readiness for this boot: clock/pin/mux ownership must already be ready. */
BOOLEAN N976nUartKdReady (VOID);
EFI_STATUS N976nUartKdPrepare (UINT64 Profile);

/* Pure serialization; the installer separately requires physical readiness. */
EFI_STATUS N976nBuildUartDbg2 (N976N_UART_DBG2 *Dbg2);

#endif
