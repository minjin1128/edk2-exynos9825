/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 internal platform preparation model. No MMIO/PMIC backend or firmware
 * producer exists. These structures are NOT an ACPI/shared-memory wire ABI,
 * authentication mechanism, or permission to start hardware.
 */
#ifndef N976N_PLATFORM_H
#define N976N_PLATFORM_H
#include "N976nResources.h"

#define N976N_PLATFORM_VERSION 1U
#define N976N_PLATFORM_SPANS 5U
#define N976N_PLATFORM_FIELDS 6U
#define N976N_PLATFORM_GATES 9U
#define N976N_PLATFORM_OWNERS 0x3FU
#define N976N_GPIO_ALIVE_BASE 0x15850000ULL
#define N976N_GPIO_ALIVE_BYTES 0x1000U
#define N976N_GPIO_TOUCH_PIN 8U
#define N976N_PLATFORM_RESTORE_MAX 9U

enum {
    N976nOwnRails = 1, N976nOwnHsi = 2, N976nOwnClock = 4,
    N976nOwnUsi = 8, N976nOwnSclSda = 16, N976nOwnTouchGpio = 32
};
enum {
    N976nFieldUsiMode = 0, N976nFieldQch = 1,
    N976nFieldPinsCon = 2, N976nFieldPinsPull = 3,
    N976nFieldPinsDrive = 4, N976nFieldTouchMask = 5
};
typedef enum {
    N976nPlatformOk = 0, N976nPlatformInvalid = -1,
    N976nPlatformStale = -2, N976nPlatformOwnership = -3,
    N976nPlatformResource = -4, N976nPlatformPower = -5,
    N976nPlatformClock = -6, N976nPlatformBusy = -7,
    N976nPlatformChanged = -8, N976nPlatformQuarantined = -9
} N976N_PLATFORM_RESULT;

typedef struct { N976N_U64 Base, Bytes; } N976N_PLATFORM_SPAN;
typedef struct {
    N976N_U64 Address;
    N976N_U32 Mask, Original, Prepared;
} N976N_PLATFORM_FIELD;
typedef struct {
    N976N_U32 Register, Original, Enabled;
} N976N_PLATFORM_RAIL;

/* Internal, trusted provider records only. Generation identifies ONE provider
 * ownership lifetime; no clock-derived/persistent boot token is invented.
 * Sequence is monotonic within that lifetime. The absent firmware/Windows
 * producer must establish actual exclusivity, current observations, and the
 * clock rate from its owned clock path; copying a DT rate is insufficient.
 */
typedef struct {
    N976N_U32 Version, Size;
    N976N_U64 Generation, Sequence;
    N976N_U32 Owners, FirmwareOutstanding, FirmwareRetired, Quarantined;
    N976N_PLATFORM_SPAN Span[N976N_PLATFORM_SPANS];
    N976N_PLATFORM_FIELD Field[N976N_PLATFORM_FIELDS];
    N976N_PLATFORM_RAIL Rail[2];
    N976N_U32 PowerIoToAnalogUs, PowerSettleUs;
    N976N_U32 ClockGate[N976N_PLATFORM_GATES], ClockMux, ClockDiv;
    N976N_U32 InputClockHz, PrimaryGsiv, PrimaryIrqMaskedOwned;
} N976N_PLATFORM_HANDOFF;

typedef struct {
    N976N_U64 Generation, Sequence;
    N976N_U32 Owners, Rail[2], Field[N976N_PLATFORM_FIELDS];
    N976N_U32 ClockGate[N976N_PLATFORM_GATES], ClockMux, ClockDiv;
    N976N_U32 InputClockHz, PrimaryGsiv, PrimaryIrqMaskedOwned;
} N976N_PLATFORM_FRESH;

typedef struct {
    N976N_U32 Valid, Owners, InputClockHz, PrimaryIrqMaskedOwned;
    N976N_U64 Generation, Sequence;
    N976N_U32 ChangedFields, ChangedRails;
} N976N_PLATFORM_PLAN;

/* Retirement comes from the future serialized controller/provider lifecycle,
 * not from PnP ReleaseHardware alone. Revocation prevents new requests before
 * teardown. A failed/cancelled request must still be provably retired; unresolved
 * completion quarantines ownership and forbids outer pin/rail restoration.
 */
typedef struct {
    N976N_U64 Generation, Submitted, Retired;
    N976N_U32 Owners, Revoked, Outstanding, Quarantined;
    N976N_U32 HsiConfigurationRestored, PrimaryIrqRetired;
} N976N_PLATFORM_RETIREMENT;

enum { N976nOpField = 1, N976nOpPmicEnable = 2, N976nOpDelayUs = 3,
       N976nOpW1c = 4 };
typedef struct {
    N976N_U32 Kind, Mask, Value;
    N976N_U64 Address;
} N976N_PLATFORM_OP;
typedef struct {
    N976N_U32 Count;
    N976N_PLATFORM_OP Op[N976N_PLATFORM_RESTORE_MAX];
} N976N_PLATFORM_RESTORE_PLAN;

/* Caller owns disjoint, fully initialized input/output storage and serialization.
 * Outputs are zero on failure. These functions inspect typed metadata only.
 * Clock/controller timing preparation remains a separate HSI provider contract;
 * matching this platform record does not initialize or validate HSI registers.
 */
N976N_PLATFORM_RESULT N976nPlatformCheckIdReady(
    const N976N_PLATFORM_HANDOFF *Handoff, const N976N_PLATFORM_FRESH *Fresh,
    N976N_U64 ExpectedGeneration, N976N_PLATFORM_PLAN *Plan);
N976N_PLATFORM_RESULT N976nPlatformPlanRestore(
    const N976N_PLATFORM_HANDOFF *Handoff, const N976N_PLATFORM_FRESH *Fresh,
    const N976N_PLATFORM_RETIREMENT *Retirement,
    N976N_U64 ExpectedGeneration, N976N_PLATFORM_RESTORE_PLAN *Plan);

typedef struct {
    N976N_U32 Pin, ParentGsiv, Con, Data, Pull, Trigger, Filter, Mask, Pending;
    N976N_U32 Bit, FieldMask, FieldShift, FilterMask, FilterShift;
} N976N_GPIO_LAYOUT;
typedef struct {
    N976N_U32 Con, Pull, Trigger, Filter, Mask, Pending;
} N976N_GPIO_SNAPSHOT;
typedef struct {
    N976N_U32 Count;
    N976N_PLATFORM_OP Op[5];
} N976N_GPIO_PLAN;

N976N_PLATFORM_RESULT N976nGpioDescribePin(
    N976N_U64 Base, N976N_U64 Bytes, N976N_U32 Pin, N976N_GPIO_LAYOUT *Layout);
/* These touch-only plans keep EINT8 masked throughout; ID is polling-only.
 * Caller/provider must hold one interrupt-safe lock for each complete RMW;
 * GpioClx pseudo-bank locks alone do not protect shared physical words.
 * No WDF spinlock or interrupt callback is implemented here.
 */
N976N_PLATFORM_RESULT N976nGpioPlanTouchMasked(
    const N976N_GPIO_LAYOUT *Layout, const N976N_GPIO_SNAPSHOT *Original,
    N976N_GPIO_PLAN *Plan);
N976N_PLATFORM_RESULT N976nGpioPlanTouchRestore(
    const N976N_GPIO_LAYOUT *Layout, const N976N_GPIO_SNAPSHOT *Original,
    const N976N_GPIO_SNAPSHOT *Current, N976N_U32 Retired,
    N976N_GPIO_PLAN *Plan);
N976N_U32 N976nGpioActiveMask(
    N976N_U32 Pending, N976N_U32 HardwareMask, N976N_U32 EnabledMask,
    N976N_U32 OwnedMask);
/* Field RMW retains current unrelated bits; W1C writes only the owned bit. */
N976N_PLATFORM_RESULT N976nApplyPlatformOp(
    const N976N_PLATFORM_OP *Op, N976N_U32 Current, N976N_U32 *WriteValue);
#endif
