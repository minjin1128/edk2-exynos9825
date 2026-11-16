/* SPDX-License-Identifier: MIT
 * WDK build supplies exact kernel types; do not mix user CRT stdint with km CRT.
 * Portable host and firmware builds provide their own exact-width definitions.
 */
#ifndef N976N_BATTERY_KERNEL_TYPES_H
#define N976N_BATTERY_KERNEL_TYPES_H
#include <ntifs.h>
#define N976N_BATTERY_EXTERNAL_TYPES 1
typedef UINT8 N976N_BAT_U8;
typedef UINT16 N976N_BAT_U16;
typedef UINT32 N976N_BAT_U32;
typedef UINT64 N976N_BAT_U64;
typedef INT32 N976N_BAT_I32;
#endif
