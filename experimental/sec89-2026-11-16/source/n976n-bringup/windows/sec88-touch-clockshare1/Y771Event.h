/* SPDX-License-Identifier: GPL-2.0-only
 * SEC73, 2026-10-22: portable Samsung N976N y771_d event contract.
 * No transport, startup, power, IRQ, allocation or coordinate rotation here.
 */
#ifndef N976N_Y771_EVENT_H
#define N976N_Y771_EVENT_H
#ifdef _KERNEL_MODE
#include <ntdef.h>
typedef UCHAR N976N_U8;
typedef USHORT N976N_U16;
typedef SIZE_T N976N_SIZE;
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t N976N_U8;
typedef uint16_t N976N_U16;
typedef size_t N976N_SIZE;
#endif
#define N976N_Y771_EVENT_BYTES 16U
#define N976N_Y771_REMAINING_MASK 0x1FU
#define N976N_Y771_CONTACTS 10U
#define N976N_Y771_COORDINATE_MAX 4095U

typedef enum {
    N976nY771Invalid = -1,
    N976nY771ErrorStatus = -2,
    N976nY771UnexpectedBoot = -3,
    N976nY771Empty = 0,
    N976nY771Coordinate = 1,
    N976nY771Status = 2,
    N976nY771Gesture = 3,
    N976nY771OtherTool = 4
} N976N_Y771_RESULT;

typedef enum { N976nY771Press = 1, N976nY771Move = 2, N976nY771Release = 3 } N976N_Y771_ACTION;

typedef struct {
    N976N_U16 X, Y;
    N976N_U8 WireId, ContactIndex, Action, Type, Remaining;
    N976N_U8 Pressure, Major, Minor, StatusSubtype, StatusId, StatusData;
} N976N_Y771_EVENT;

/* Exact16 bytes. Output is zero on malformed input; no stale contact survives.
 * Startup boot-ready policy is intentionally outside this running-input API.
 * INFO/VENDOR BOOT_COMPLETE is an explicit control-plane event, never a finger.
 */
N976N_Y771_RESULT N976nY771DecodeEvent(const N976N_U8 *Bytes, N976N_SIZE Length,
                                    N976N_Y771_EVENT *Event);
#endif
