/* SPDX-License-Identifier: MIT */
#ifndef N976N_THERMAL_BRIDGE_H
#define N976N_THERMAL_BRIDGE_H
#include "Charge.h"
#include "Thermal.h"
/* Producer-owned invocation only; caller serializes context and supplies a
 * fresh ADC identity. F's Windows times are 100ns; portable NCC times are ms.
 * No ADC acquisition, default temperature, source authority or control write.
 * Missing/error clears thermal facts; independent source/protection flags are
 * never promoted. Valid temperatures can still be outside the bench limits. */
int N976nThermalObserve(NCT_CONTEXT *,const NCT_IDENTITY *,N976N_POWER_FACTS *);
#endif
