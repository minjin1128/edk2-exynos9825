/* SPDX-License-Identifier: MIT */
#ifndef N976N_UART_ADMISSION_H_
#define N976N_UART_ADMISSION_H_
#include <N976nPlatform.h>

#define N976N_UART_ADMISSION_MAGIC   0x3538444154524155ULL
#define N976N_UART_ADMISSION_CHECKS  0xFFULL
#define N976N_UART_BASE             0x10440000ULL
#define N976N_UART_BYTES            0x100ULL
#define N976N_UART_GPIO_PERIC0       0x10430000ULL
#define N976N_UART_HSI2C             0x15D60000ULL
#define N976N_UART_GPIO_CMGP         0x15C30000ULL
#define N976N_UART_SYSREG_CMGP       0x15C22030ULL
#define N976N_UART_CMU_PERIC0        0x10400000ULL
#define N976N_UART_CMU_CMGP          0x15C00000ULL
#define N976N_UART_CMU_ALIVE         0x15800000ULL
#define N976N_UART_CMU_TOP           0x1A240000ULL
#define N976N_UART_CMU_BYTES         0x8000ULL

/* Pure runtime-DT admission. CMU_TOP is a DT resource; the other CMU regions
 * are Samsung N976N CAL source ranges selected by the exact SoC and consumer
 * clock identities. This is not a measured clock, active owner or ready-port
 * assertion. DXE must validate this singleton HOB and live state before MMIO.
 * Rejection leaves all hardware facts zero. No opcode endpoint is invented in
 * DT: Samsung's MAX77705 MFD creates address 0x25 from admitted parent 0x66. */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Admitted, Reason, Checks;
  UINT64 Uart, UartBytes, GpioPeric0, GpioPeric0Bytes;
  UINT64 Hsi2c, Hsi2cBytes, GpioCmgp, GpioCmgpBytes;
  UINT64 SysregCmgp, SysregCmgpBytes;
  UINT64 CmuPeric0, CmuPeric0Bytes, CmuCmgp, CmuCmgpBytes;
  UINT64 CmuAlive, CmuAliveBytes, CmuTop, CmuTopBytes;
  UINT64 UartClockIds[2], HsiClockIds[2];
} N976N_UART_ADMISSION;
STATIC_ASSERT (sizeof (N976N_UART_ADMISSION)==232, "SEC85 UART admission ABI");
extern EFI_GUID gN976nUartAdmissionGuid;

/* Dtb/bytes are the bounded runtime input already accepted by ParseRuntimeDtb.
 * This function also checks its FDT layout before any upstream FdtLib lookup.
 * No allocation, hardware access, device request or mapping is performed. */
BOOLEAN EFIAPI N976nAdmitUart (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_UART_ADMISSION *Admission
  );
#endif
