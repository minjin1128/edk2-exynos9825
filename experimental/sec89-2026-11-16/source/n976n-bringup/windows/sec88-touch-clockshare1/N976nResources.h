/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76: inert N976N resource and transfer contracts. No hardware access.
 */
#ifndef N976N_RESOURCES_H
#define N976N_RESOURCES_H
#include "Y771Event.h"
#ifdef _KERNEL_MODE
typedef ULONG N976N_U32;
typedef ULONGLONG N976N_U64;
#else
typedef uint32_t N976N_U32;
typedef uint64_t N976N_U64;
#endif

#define N976N_TOUCH_RESOURCE_COUNT 2U
#define N976N_CONTROLLER_RESOURCE_COUNT 5U
#define N976N_RESOURCE_LIMIT 5U
#define N976N_I2C_ADDRESS 0x48U
#define N976N_I2C_SPEED_HZ 400000U
#define N976N_HSI_IRQ_GSIV 420U

enum {
    N976nResourceUnknown = 0, N976nResourceMemory = 1,
    N976nResourceConnection = 2, N976nResourceInterrupt = 3
};
enum { N976nShareUnknown = 0, N976nShareExclusive = 1 };
enum { N976nInterruptLevel = 0, N976nInterruptEdge = 1 };
enum { N976nConnectionSerial = 1, N976nConnectionI2c = 1 };

typedef enum {
    N976nResourceOk = 0, N976nResourceInvalid = -1,
    N976nResourceCount = -2, N976nResourceKind = -3,
    N976nResourceShare = -4, N976nResourceFlags = -5,
    N976nResourceIdentity = -6, N976nResourceRange = -7,
    N976nResourceDuplicate = -8
} N976N_RESOURCE_RESULT;

/* Normalized CM descriptors, never pointers or owned/mapped resources.
 * Interrupt Flags contains edge/level only; Secondary records GPIO secondary
 * interrupt routing separately. ACPI polarity is not represented
 * in a CM partial interrupt descriptor and cannot be re-proven here.
 */
typedef struct {
    N976N_U32 Kind, Share, Flags, ConnectionClass, ConnectionType;
    N976N_U64 Start, Length, ConnectionId;
    N976N_U32 Vector, Level, Group, Secondary;
    N976N_U64 Affinity;
} N976N_RESOURCE;

typedef struct {
    N976N_U32 Valid, DescriptorCount;
    N976N_U64 ConnectionId;
    N976N_U32 RawInterruptVector, TranslatedInterruptVector;
    N976N_U32 RawInterruptSecondary, TranslatedInterruptSecondary;
    N976N_U32 TranslatedInterruptLevel, TranslatedInterruptGroup;
    N976N_U64 TranslatedInterruptAffinity;
} N976N_TOUCH_RESOURCE_PLAN;

typedef struct {
    N976N_U32 Valid, DescriptorCount;
    N976N_U64 Base[4], Bytes[4];
    N976N_U32 RawInterruptVector, TranslatedInterruptVector;
    N976N_U32 InterruptTrigger, TranslatedInterruptLevel, TranslatedInterruptGroup;
    N976N_U64 TranslatedInterruptAffinity;
} N976N_CONTROLLER_RESOURCE_PLAN;

typedef struct {
    N976N_U32 Valid, Address, SpeedHz, MessageCount;
    N976N_U8 Command;
    N976N_U32 WriteBytes, ReadBytes;
    N976N_U32 StopAfterWrite, StopAfterRead, RequiresSerializedBusOwnership;
} N976N_TRANSFER_PLAN;

/* Trusted caller precondition: Plan and both complete input arrays occupy
 * disjoint storage. Actual callers use framework descriptors, distinct local
 * arrays, and a separate context/output plan. This is not an untrusted-pointer
 * probing API. Given this precondition, output is zero on any failure.
 * Raw/translated pairs must retain their CM list order. No MMIO mapping,
 * ResourceHub opening, interrupt creation or execution permission results.
 */
N976N_RESOURCE_RESULT N976nValidateTouchResources(
    const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE Count, N976N_TOUCH_RESOURCE_PLAN *Plan);
N976N_RESOURCE_RESULT N976nValidateControllerResources(
    const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE Count, N976N_CONTROLLER_RESOURCE_PLAN *Plan);

/* ID/event reads only, not startup/configuration commands. Samsung HSI2C
 * emits STOP for each message. A future SPB controller must serialize the
 * whole pair while preserving those STOPs; ordinary sequence semantics alone
 * do not establish that behavior. This function only describes the pair.
 */
N976N_RESOURCE_RESULT N976nPlanTouchRead(
    N976N_U8 Command, N976N_U32 ReadBytes,
    N976N_U32 Address, N976N_U32 SpeedHz, N976N_TRANSFER_PLAN *Plan);
#endif
