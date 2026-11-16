/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76: WDF descriptor capture only. No mapping or object activation.
 */
#ifndef N976N_WDF_RESOURCES_H
#define N976N_WDF_RESOURCES_H
#include <ntddk.h>
#include <wdf.h>
#include "N976nResources.h"

/* Trusted WDF caller only; Descriptor/Resource and input lists/output Plan
 * must not alias. Helpers never take ownership of descriptor memory. */
N976N_RESOURCE_RESULT N976nNormalizeCmResource(
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Descriptor, N976N_RESOURCE *Resource);
N976N_RESOURCE_RESULT N976nCaptureTouchResources(
    WDFCMRESLIST Raw, WDFCMRESLIST Translated, N976N_TOUCH_RESOURCE_PLAN *Plan);
N976N_RESOURCE_RESULT N976nCaptureControllerResources(
    WDFCMRESLIST Raw, WDFCMRESLIST Translated, N976N_CONTROLLER_RESOURCE_PLAN *Plan);
#endif
