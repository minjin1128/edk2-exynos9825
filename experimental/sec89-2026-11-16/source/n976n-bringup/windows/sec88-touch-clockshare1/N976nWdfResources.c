/* SPDX-License-Identifier: GPL-2.0-only */
#include "N976nWdfResources.h"

N976N_RESOURCE_RESULT
N976nNormalizeCmResource(const CM_PARTIAL_RESOURCE_DESCRIPTOR *Descriptor,
    N976N_RESOURCE *Resource)
{
    N976N_RESOURCE next;
    if (Resource == NULL) return N976nResourceInvalid;
    RtlZeroMemory(Resource, sizeof(*Resource));
    RtlZeroMemory(&next, sizeof(next));
    if (Descriptor == NULL) return N976nResourceInvalid;
    if (Descriptor->ShareDisposition != CmResourceShareDeviceExclusive)
        return N976nResourceShare;
    next.Share = N976nShareExclusive;
    switch (Descriptor->Type) {
    case CmResourceTypeConnection:
        if (Descriptor->Flags != 0U) return N976nResourceFlags;
        if (Descriptor->u.Connection.Class != CM_RESOURCE_CONNECTION_CLASS_SERIAL ||
            Descriptor->u.Connection.Type != CM_RESOURCE_CONNECTION_TYPE_SERIAL_I2C)
            return N976nResourceIdentity;
        next.Kind = N976nResourceConnection;
        next.ConnectionClass = N976nConnectionSerial;
        next.ConnectionType = N976nConnectionI2c;
        next.ConnectionId = ((N976N_U64)Descriptor->u.Connection.IdHighPart << 32) |
            Descriptor->u.Connection.IdLowPart;
        break;
    case CmResourceTypeInterrupt:
        /* CM carries trigger, not ACPI polarity. Reject MSI and extra modes;
         * no GPIO-controller physical GSIV is inferred from a Windows vector. */
        if ((Descriptor->Flags & ~(CM_RESOURCE_INTERRUPT_LATCHED |
                                   CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT)) != 0U)
            return N976nResourceFlags;
        next.Kind = N976nResourceInterrupt;
        next.Flags = ((Descriptor->Flags & CM_RESOURCE_INTERRUPT_LATCHED) != 0U) ?
            N976nInterruptEdge : N976nInterruptLevel;
        next.Secondary = ((Descriptor->Flags & CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT) != 0U) ? 1U : 0U;
        next.Vector = Descriptor->u.Interrupt.Vector;
        next.Level = Descriptor->u.Interrupt.Level;
#if defined(NT_PROCESSOR_GROUPS)
        next.Group = Descriptor->u.Interrupt.Group;
#else
        /* Match the selected WDK descriptor ABI; do not change its layout.
         * Without NT_PROCESSOR_GROUPS, Interrupt has ULONG Level and no Group.
         * Group zero is this ABI's representation, not an observed field. */
        next.Group = 0U;
#endif
        next.Affinity = (N976N_U64)Descriptor->u.Interrupt.Affinity;
        break;
    case CmResourceTypeMemory:
        if (Descriptor->Flags != CM_RESOURCE_MEMORY_READ_WRITE)
            return N976nResourceFlags;
        if (Descriptor->u.Memory.Start.QuadPart < 0 || Descriptor->u.Memory.Length == 0U)
            return N976nResourceRange;
        next.Kind = N976nResourceMemory;
        next.Start = (N976N_U64)Descriptor->u.Memory.Start.QuadPart;
        next.Length = Descriptor->u.Memory.Length;
        break;
    default:
        return N976nResourceKind;
    }
    *Resource = next;
    return N976nResourceOk;
}

static N976N_RESOURCE_RESULT
N976nCollectCmResources(WDFCMRESLIST Raw, WDFCMRESLIST Translated,
    ULONG ExpectedCount, N976N_RESOURCE *RawItems, N976N_RESOURCE *TranslatedItems)
{
    ULONG i;
    if (Raw == NULL || Translated == NULL || RawItems == NULL || TranslatedItems == NULL)
        return N976nResourceInvalid;
    if (ExpectedCount > N976N_RESOURCE_LIMIT ||
        WdfCmResourceListGetCount(Raw) != ExpectedCount ||
        WdfCmResourceListGetCount(Translated) != ExpectedCount)
        return N976nResourceCount;
    for (i = 0; i < ExpectedCount; ++i) {
        N976N_RESOURCE_RESULT result;
        result = N976nNormalizeCmResource(WdfCmResourceListGetDescriptor(Raw, i), &RawItems[i]);
        if (result != N976nResourceOk) return result;
        result = N976nNormalizeCmResource(WdfCmResourceListGetDescriptor(Translated, i), &TranslatedItems[i]);
        if (result != N976nResourceOk) return result;
    }
    return N976nResourceOk;
}

N976N_RESOURCE_RESULT
N976nCaptureTouchResources(WDFCMRESLIST Raw, WDFCMRESLIST Translated,
    N976N_TOUCH_RESOURCE_PLAN *Plan)
{
    N976N_RESOURCE rawItems[N976N_TOUCH_RESOURCE_COUNT];
    N976N_RESOURCE translatedItems[N976N_TOUCH_RESOURCE_COUNT];
    N976N_RESOURCE_RESULT result;
    if (Plan == NULL) return N976nResourceInvalid;
    RtlZeroMemory(Plan, sizeof(*Plan));
    result = N976nCollectCmResources(Raw, Translated, N976N_TOUCH_RESOURCE_COUNT, rawItems, translatedItems);
    if (result != N976nResourceOk) return result;
    return N976nValidateTouchResources(rawItems, translatedItems, N976N_TOUCH_RESOURCE_COUNT, Plan);
}

N976N_RESOURCE_RESULT
N976nCaptureControllerResources(WDFCMRESLIST Raw, WDFCMRESLIST Translated,
    N976N_CONTROLLER_RESOURCE_PLAN *Plan)
{
    N976N_RESOURCE rawItems[N976N_CONTROLLER_RESOURCE_COUNT];
    N976N_RESOURCE translatedItems[N976N_CONTROLLER_RESOURCE_COUNT];
    N976N_RESOURCE_RESULT result;
    if (Plan == NULL) return N976nResourceInvalid;
    RtlZeroMemory(Plan, sizeof(*Plan));
    result = N976nCollectCmResources(Raw, Translated, N976N_CONTROLLER_RESOURCE_COUNT, rawItems, translatedItems);
    if (result != N976nResourceOk) return result;
    return N976nValidateControllerResources(rawItems, translatedItems, N976N_CONTROLLER_RESOURCE_COUNT, Plan);
}
