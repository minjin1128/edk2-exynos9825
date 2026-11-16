/* SPDX-License-Identifier: MIT */
#ifndef N976N_WINDOWS_CONNECTION_H
#define N976N_WINDOWS_CONNECTION_H
/* UART1 requires the paired kernel-debug BCD and a VBUS-free UART cable
 * from boot. This profile does not auto-detect a cable or restore hotplug mux. */
#define N976N_WINDOWS_UART_DEBUG 1
#endif
