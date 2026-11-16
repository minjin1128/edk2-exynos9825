/* SPDX-License-Identifier: MIT */
#ifndef N976N_TOUCH_H_
#define N976N_TOUCH_H_
#include <N976nPlatform.h>

#define N976N_TOUCH_ADMISSION_MAGIC 0x3936444148435554ULL
#define N976N_TOUCH_ADMISSION_CHECKS 0xFFULL
#define N976N_TOUCH_HSI2C           0x104B0000ULL
#define N976N_TOUCH_GPIO_ALIVE      0x15850000ULL
#define N976N_TOUCH_GPIO_PERIC0     0x10430000ULL
#define N976N_TOUCH_SYSREG_USI      0x1042101CULL
/* Samsung N976N CAL source address; this is not a DT reg property. The DT
 * clock-controller describes CMU_TOP and supplies the exact peripheral IDs. */
#define N976N_TOUCH_CMU_PERIC0      0x10400000ULL

/* Pure DT/source admission, not physical accessibility, power or input proof.
 * BootOn records the DT expectation only. EventBytes is from Samsung's Y771
 * driver selected by the exact firmware identity, not a measured device ID.
 * QEMU carries phone DT facts for validation; its consumer must skip MMIO.
 * Rejection leaves every hardware address and fact zero. */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Admitted, Reason, Checks;
  UINT64 Hsi2c, Hsi2cBytes, GpioAlive, GpioAliveBytes;
  UINT64 GpioPeric0, GpioPeric0Bytes, SysregUsi, SysregUsiBytes;
  UINT64 CmuPeric0, CmuPeric0Bytes;
  UINT64 I2cAddress, I2cGsiv, ClockHz, ClockIds[2];
  UINT64 IrqPin, IrqGsiv, IrqFlags, SclPin, SdaPin, PinFunction;
  UINT64 MaxX, MaxY, EventBytes, BootOn;
} N976N_TOUCH_ADMISSION;
STATIC_ASSERT (sizeof (N976N_TOUCH_ADMISSION)==256, "SEC70 touch admission ABI");
extern EFI_GUID gN976nTouchAdmissionGuid;

/* Dtb is already bounded by ParseRuntimeDtb. This function still validates
 * the complete token tree, critical properties and cross-node relationships.
 * It performs no MMIO, allocation, device operation or memory mapping. */
BOOLEAN EFIAPI N976nAdmitTouch (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_TOUCH_ADMISSION *Admission
  );
#endif
