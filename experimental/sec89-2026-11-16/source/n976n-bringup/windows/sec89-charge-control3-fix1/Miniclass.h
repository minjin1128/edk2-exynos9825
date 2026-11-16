/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_MINICLASS_H
#define N976N_BATTERY_MINICLASS_H

#if defined(N976N_BATTERY_HOST_TEST)
#include "tests/WdkBatteryStub.h"
#else
#include <ntddk.h>
#include <batclass.h>
#endif
#include "BatteryCache.h"

/* All callbacks run at PASSIVE_LEVEL. Device supplies a nonrecursive state
 * lock shared with the publishing worker and D0 stop. Lock/Unlock must not
 * fail. Now returns the same monotonic 100ns clock used by the live worker.
 * Context, bindings and Cache remain alive until Battc is fully unloaded.
 */
typedef struct {
  N976N_BATTERY_CACHE *Cache;
  PVOID Owner;
  void (*Lock)(PVOID Owner);
  void (*Unlock)(PVOID Owner);
  N976N_BAT_U64 (*Now100ns)(PVOID Owner);
} N976N_BATTERY_MINICLASS_CONTEXT;

BCLASS_QUERY_TAG_CALLBACK N976nBatteryQueryTag;
BCLASS_QUERY_INFORMATION_CALLBACK N976nBatteryQueryInformation;
BCLASS_SET_INFORMATION_CALLBACK N976nBatterySetInformation;
BCLASS_QUERY_STATUS_CALLBACK N976nBatteryQueryStatus;
BCLASS_SET_STATUS_NOTIFY_CALLBACK N976nBatterySetStatusNotify;
BCLASS_DISABLE_STATUS_NOTIFY_CALLBACK N976nBatteryDisableStatusNotify;

/* Only callback pointers and Context are filled. Device owns version, PDO/FDO,
 * class registration, request forwarding, remove-lock/rundown and all lifetime
 * ordering. For V1_1 the caller supplies the usual PBATTERY_MINIPORT_INFO cast.
 * Returns 0 for incomplete context without modifying Info.
 */
int N976nBatteryMiniBind(PBATTERY_MINIPORT_INFO Info,
                       N976N_BATTERY_MINICLASS_CONTEXT *Context);

#endif
