/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_ADMISSION_H_
#define N976N_BATTERY_ADMISSION_H_

#include <N976nPlatform.h>

#define N976N_BATTERY_ADMISSION_MAGIC  0x3138444154544142ULL
#define N976N_BATTERY_ADMISSION_VERSION 1ULL
#define N976N_BATTERY_ADMISSION_CHECKS 3ULL

#define N976N_BATTERY_FACTOR_UNCHECKED   0ULL
#define N976N_BATTERY_FACTOR_KNOWN       1ULL
#define N976N_BATTERY_FACTOR_MISSING     2ULL
#define N976N_BATTERY_FACTOR_MALFORMED   3ULL
#define N976N_BATTERY_FACTOR_UNSUPPORTED 4ULL
#define N976N_BATTERY_FACTOR_DISABLED    5ULL
#define N976N_BATTERY_FACTOR_AMBIGUOUS   6ULL

/* Independent bounded runtime-DT result. Checks bit0: exact HSI45/MFD resource
 * admission using the real UART DT parser. Bit1: calibration lookup completed
 * (including an explicitly unknown factor). FactorStatus=KNOWN alone permits
 * use of Factor (2 or 5). Other statuses leave Factor=0 while admitting only
 * the transport facts needed for SOC/voltage/status observations.
 * No live clock, bus ownership, gauge response or charging claim is made.
 */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Admitted, Reason, Checks;
  UINT64 Factor, FactorStatus;
} N976N_BATTERY_ADMISSION;

STATIC_ASSERT(sizeof(N976N_BATTERY_ADMISSION)==72,"SEC88 battery admission ABI");
extern EFI_GUID gN976nBatteryAdmissionGuid;

/* Pure validation; no allocation or MMIO. Pointer overflow, unaligned output
 * or input/output overlap is rejected without touching output or input.
 * Other failures publish a rejected header with no scale or admitted facts.
 * QEMU has no MAX77705 and is refused, even with a phone DT fixture.
 */
BOOLEAN EFIAPI N976nAdmitBattery (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_BATTERY_ADMISSION *Admission
  );

#endif
