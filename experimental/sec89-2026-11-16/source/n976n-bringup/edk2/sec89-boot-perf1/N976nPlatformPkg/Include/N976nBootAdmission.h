/* SPDX-License-Identifier: MIT */
#ifndef N976N_BOOT_ADMISSION_H
#define N976N_BOOT_ADMISSION_H
#include <N976nUartAdmission.h>
#include <N976nBatteryAdmission.h>
#include <N976nChargeObservation.h>
#include <N976nAdcPreflight.h>
#include <N976nThermalAdmission.h>

typedef struct {
  N976N_UART_ADMISSION Uart;
  N976N_BATTERY_ADMISSION Battery;
  N976N_CHARGE_ADMISSION Charge;
  N976N_ADC_ADMISSION Adc;
  N976N_THERMAL_ADMISSION Thermal;
} N976N_BOOT_ADMISSION;

/* Pure, synchronous SEC operation. The caller owns the entire immutable DT
 * span for this call. No cached authority survives the call, reaches a HOB,
 * or is supplied by the caller. TRUE means output and DT address/overlap preflight passed; each
 * member retains its independent Admitted/Reason result, including failures.
 * Standalone admission APIs continue to validate independently. */
BOOLEAN EFIAPI N976nAdmitBootDevices (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_BOOT_ADMISSION *Out);
#endif
