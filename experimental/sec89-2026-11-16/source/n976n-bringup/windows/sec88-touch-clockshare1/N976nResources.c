/* SPDX-License-Identifier: GPL-2.0-only */
#include "N976nResources.h"

static void
N976nZero(void *Buffer, N976N_SIZE Bytes)
{
    N976N_U8 *p = (N976N_U8 *)Buffer;
    while (Bytes != 0U) { *p++ = 0; --Bytes; }
}

static N976N_RESOURCE_RESULT
N976nValidatePair(const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated)
{
    if (Raw->Kind != Translated->Kind || Raw->Kind == N976nResourceUnknown)
        return N976nResourceKind;
    if (Raw->Share != N976nShareExclusive || Translated->Share != N976nShareExclusive)
        return N976nResourceShare;
    if (Raw->Flags != Translated->Flags)
        return N976nResourceFlags;
    if (Raw->Kind == N976nResourceInterrupt) {
        if (Raw->Secondary > 1U || Translated->Secondary > 1U)
            return N976nResourceFlags;
        if (Raw->Flags != N976nInterruptLevel && Raw->Flags != N976nInterruptEdge)
            return N976nResourceFlags;
        if (Translated->Vector == 0U || Translated->Affinity == 0U)
            return N976nResourceIdentity;
        if (Raw->Start != 0U || Raw->Length != 0U || Raw->ConnectionId != 0U ||
            Raw->ConnectionClass != 0U || Raw->ConnectionType != 0U ||
            Translated->Start != 0U || Translated->Length != 0U ||
            Translated->ConnectionId != 0U || Translated->ConnectionClass != 0U ||
            Translated->ConnectionType != 0U)
            return N976nResourceInvalid;
    } else {
        if (Raw->Flags != 0U)
            return N976nResourceFlags;
        if (Raw->Vector != 0U || Raw->Level != 0U || Raw->Group != 0U || Raw->Secondary != 0U ||
            Raw->Affinity != 0U || Translated->Vector != 0U || Translated->Level != 0U ||
            Translated->Group != 0U || Translated->Secondary != 0U ||
            Translated->Affinity != 0U)
            return N976nResourceInvalid;
    }
    return N976nResourceOk;
}

N976N_RESOURCE_RESULT
N976nValidateTouchResources(const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE Count, N976N_TOUCH_RESOURCE_PLAN *Plan)
{
    N976N_TOUCH_RESOURCE_PLAN next;
    N976N_U32 seen = 0;
    N976N_SIZE i;
    if (Plan == 0) return N976nResourceInvalid;
    N976nZero(Plan, sizeof(*Plan));
    N976nZero(&next, sizeof(next));
    if (Raw == 0 || Translated == 0) return N976nResourceInvalid;
    if (Count != N976N_TOUCH_RESOURCE_COUNT) return N976nResourceCount;
    for (i = 0; i < Count; ++i) {
        N976N_RESOURCE_RESULT result = N976nValidatePair(&Raw[i], &Translated[i]);
        if (result != N976nResourceOk) return result;
        if (Raw[i].Kind == N976nResourceConnection) {
            if ((seen & 1U) != 0U) return N976nResourceDuplicate;
            if (Raw[i].ConnectionClass != N976nConnectionSerial ||
                Raw[i].ConnectionType != N976nConnectionI2c ||
                Translated[i].ConnectionClass != N976nConnectionSerial ||
                Translated[i].ConnectionType != N976nConnectionI2c ||
                Raw[i].ConnectionId == 0U || Raw[i].ConnectionId != Translated[i].ConnectionId)
                return N976nResourceIdentity;
            if (Raw[i].Start != 0U || Raw[i].Length != 0U ||
                Translated[i].Start != 0U || Translated[i].Length != 0U)
                return N976nResourceInvalid;
            next.ConnectionId = Translated[i].ConnectionId;
            seen |= 1U;
        } else if (Raw[i].Kind == N976nResourceInterrupt) {
            if ((seen & 2U) != 0U) return N976nResourceDuplicate;
            if (Raw[i].Flags != N976nInterruptLevel) return N976nResourceFlags;
            /* GPIO interrupt identity belongs to the provider/ACPI graph.
             * Neither raw nor translated Vector is assumed to be GSIV45. */
            next.RawInterruptVector = Raw[i].Vector;
            next.TranslatedInterruptVector = Translated[i].Vector;
            next.RawInterruptSecondary = Raw[i].Secondary;
            next.TranslatedInterruptSecondary = Translated[i].Secondary;
            next.TranslatedInterruptLevel = Translated[i].Level;
            next.TranslatedInterruptGroup = Translated[i].Group;
            next.TranslatedInterruptAffinity = Translated[i].Affinity;
            seen |= 2U;
        } else {
            return N976nResourceKind;
        }
    }
    if (seen != 3U) return N976nResourceCount;
    next.Valid = 1U;
    next.DescriptorCount = (N976N_U32)Count;
    *Plan = next;
    return N976nResourceOk;
}

N976N_RESOURCE_RESULT
N976nValidateControllerResources(const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE Count, N976N_CONTROLLER_RESOURCE_PLAN *Plan)
{
    static const N976N_U64 bases[4] = { 0x104B0000ULL, 0x10400000ULL, 0x10421000ULL, 0x10430000ULL };
    static const N976N_U64 bytes[4] = { 0x1000ULL, 0x8000ULL, 0x1000ULL, 0x1000ULL };
    N976N_CONTROLLER_RESOURCE_PLAN next;
    N976N_U32 seen = 0;
    N976N_SIZE i;
    if (Plan == 0) return N976nResourceInvalid;
    N976nZero(Plan, sizeof(*Plan));
    N976nZero(&next, sizeof(next));
    if (Raw == 0 || Translated == 0) return N976nResourceInvalid;
    if (Count != N976N_CONTROLLER_RESOURCE_COUNT) return N976nResourceCount;
    for (i = 0; i < Count; ++i) {
        N976N_RESOURCE_RESULT result = N976nValidatePair(&Raw[i], &Translated[i]);
        if (result != N976nResourceOk) return result;
        if (Raw[i].Kind == N976nResourceMemory) {
            N976N_U32 slot;
            if (Raw[i].ConnectionClass != 0U || Raw[i].ConnectionType != 0U || Raw[i].ConnectionId != 0U ||
                Translated[i].ConnectionClass != 0U || Translated[i].ConnectionType != 0U ||
                Translated[i].ConnectionId != 0U)
                return N976nResourceInvalid;
            if (Raw[i].Length == 0U || Raw[i].Start > (~(N976N_U64)0) - Raw[i].Length ||
                Translated[i].Length == 0U ||
                Translated[i].Start > (~(N976N_U64)0) - Translated[i].Length)
                return N976nResourceRange;
            for (slot = 0; slot < 4U; ++slot)
                if (Raw[i].Start == bases[slot] && Raw[i].Length == bytes[slot]) break;
            if (slot == 4U || Translated[i].Start != bases[slot] || Translated[i].Length != bytes[slot])
                return N976nResourceRange;
            if ((seen & (1U << slot)) != 0U) return N976nResourceDuplicate;
            next.Base[slot] = bases[slot];
            next.Bytes[slot] = bytes[slot];
            seen |= 1U << slot;
        } else if (Raw[i].Kind == N976nResourceInterrupt) {
            if ((seen & 16U) != 0U) return N976nResourceDuplicate;
            if (Raw[i].Secondary != 0U || Translated[i].Secondary != 0U)
                return N976nResourceFlags;
            if (Raw[i].Vector != N976N_HSI_IRQ_GSIV) return N976nResourceIdentity;
            next.RawInterruptVector = Raw[i].Vector;
            next.TranslatedInterruptVector = Translated[i].Vector;
            next.TranslatedInterruptLevel = Translated[i].Level;
            next.TranslatedInterruptGroup = Translated[i].Group;
            next.TranslatedInterruptAffinity = Translated[i].Affinity;
            /* DT specifies no trigger. Preserve a draft edge/level choice
             * for review; admission is NOT physical trigger validation. */
            next.InterruptTrigger = Translated[i].Flags;
            seen |= 16U;
        } else {
            return N976nResourceKind;
        }
    }
    if (seen != 31U) return N976nResourceCount;
    next.Valid = 1U;
    next.DescriptorCount = (N976N_U32)Count;
    *Plan = next;
    return N976nResourceOk;
}

N976N_RESOURCE_RESULT
N976nPlanTouchRead(N976N_U8 Command, N976N_U32 ReadBytes,
    N976N_U32 Address, N976N_U32 SpeedHz, N976N_TRANSFER_PLAN *Plan)
{
    N976N_TRANSFER_PLAN next;
    if (Plan == 0) return N976nResourceInvalid;
    N976nZero(Plan, sizeof(*Plan));
    N976nZero(&next, sizeof(next));
    if (Address != N976N_I2C_ADDRESS || SpeedHz != N976N_I2C_SPEED_HZ)
        return N976nResourceIdentity;
    if (!((Command == 0x52U && ReadBytes == 3U) ||
          (Command == 0x60U && ReadBytes == N976N_Y771_EVENT_BYTES) ||
          (Command == 0x61U && ReadBytes != 0U && ReadBytes <= 31U * N976N_Y771_EVENT_BYTES &&
           ReadBytes % N976N_Y771_EVENT_BYTES == 0U)))
        return N976nResourceRange;
    next.Valid = 1U;
    next.Address = Address;
    next.SpeedHz = SpeedHz;
    next.MessageCount = 2U;
    next.Command = Command;
    next.WriteBytes = 1U;
    next.ReadBytes = ReadBytes;
    next.StopAfterWrite = 1U;
    next.StopAfterRead = 1U;
    next.RequiresSerializedBusOwnership = 1U;
    *Plan = next;
    return N976nResourceOk;
}
