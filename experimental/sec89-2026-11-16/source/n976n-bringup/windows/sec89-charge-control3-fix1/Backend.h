/* SPDX-License-Identifier: MIT */
#ifndef N976N_BAT_BACKEND_H
#define N976N_BAT_BACKEND_H
#include "Bus.h"
typedef struct {
  N976N_BAT_BUS_CONTEXT Bus;
  N976N_BAT_U64 Sequence;
  N976N_BAT_U32 Factor;
  unsigned Initialized;
} N976N_BAT_BACKEND;
typedef struct {
  N976N_BATTERY_RAW Raw;
  N976N_BATTERY_VALUES Values;
  N976N_BAT_U64 StartedCounter, CompletedCounter, Status;
  unsigned Publishable;
  /* Frozen at this gauge read's retirement, before later charger reads can
   * overwrite Bus.Report. Does not authorize publication or control. */
  unsigned CleanReadFailure;
} N976N_BAT_BACKEND_SAMPLE;
/* Called only for newly mapped/claimed state; no MMIO in Init. Factor is DT
 * admitted 2/5, or0 (unknown), never inferred from model name or old OEMB. */
int N976nBatBackendInit(N976N_BAT_BACKEND *Backend,
  const N976N_BAT_BUS_OPS *Ops,void *Opaque,
  const N976N_BAT_BUS_BINDING *Binding,N976N_BAT_U32 Factor,
  const N976N_BAT_U32 SelectedConfig[16]);
/* One serialized PASSIVE worker. Caller brackets this with generation/time
 * state and rejects results after stop. No callback, notification, allocation,
 * arbitrary writes, retry or stale-value fallback is performed here. */
N976N_BAT_U64 N976nBatBackendSample(N976N_BAT_BACKEND *Backend,
  N976N_BAT_BACKEND_SAMPLE *Sample);
N976N_BAT_U64 N976nBatBackendReadActive(N976N_BAT_BACKEND *Backend,
  N976N_BAT_BACKEND_SAMPLE *Sample);
#endif
