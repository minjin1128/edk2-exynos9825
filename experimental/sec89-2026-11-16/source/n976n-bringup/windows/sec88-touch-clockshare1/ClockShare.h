/* SPDX-License-Identifier: MIT
 * Shared resource contract for observational access to CMU_TOP. This helper
 * does not grant write authority or change addresses, flags, clocks or power.
 */
#ifndef N976N_CLOCK_SHARE_H
#define N976N_CLOCK_SHARE_H
#include <ntddk.h>
#include <wdf.h>

#define N976N_CLOCK_SHARE_BASE 0x1A240000ULL
#define N976N_CLOCK_SHARE_BYTES 0x3000U
#define N976N_CLOCK_SHARE_END (N976N_CLOCK_SHARE_BASE + N976N_CLOCK_SHARE_BYTES - 1)

EVT_WDF_DEVICE_FILTER_RESOURCE_REQUIREMENTS N976nClockShareFilter;

/* Register before WdfDeviceCreate. If the caller already owns FDO callbacks,
 * assign N976nClockShareFilter into that structure instead of replacing it. */
VOID N976nClockShareRegister(PWDFDEVICE_INIT DeviceInit);

/* Exact TOP pair only. Raw/translated must both be shared and agree in flags.
 * Windows descriptors may carry 0 (RW) or READ_ONLY: preserve either encoding;
 * the driver must still map TOP PAGE_READONLY|PAGE_NOCACHE and never write it.
 * Other resources do not use this admission function and stay exclusive.
 */
int N976nClockSharePreparePair(PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw,
                             PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated);
#endif
