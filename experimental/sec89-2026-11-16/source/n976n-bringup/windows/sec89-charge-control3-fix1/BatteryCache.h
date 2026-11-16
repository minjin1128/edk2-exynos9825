/* SPDX-License-Identifier: MIT
 * Live-sample cache, independent of WDK and transport. Frozen OEMB has no entry
 * path here. The device serializes every call below with one state lock.
 */
#ifndef N976N_BATTERY_CACHE_H
#define N976N_BATTERY_CACHE_H

#include "N976nBattery.h"

typedef struct {
  N976N_BATTERY_VALUES Values;
  N976N_BAT_U64 Generation;
  N976N_BAT_U64 SampleStart100ns;
  N976N_BAT_U64 SampleCompleted100ns;
  N976N_BAT_U32 Tag;
  N976N_BAT_U64 PowerSample100ns;
  N976N_BAT_U32 OnlineKnown,Online,ChargingObserved;
} N976N_BATTERY_CACHE_VIEW;

typedef struct {
  N976N_BATTERY_CACHE_VIEW View;
  N976N_BAT_U64 Ttl100ns;
  N976N_BAT_U64 Generation;
  N976N_BAT_U64 LastObserved100ns;
  N976N_BAT_U64 LastAcceptedSampleId;
  N976N_BAT_U64 LastAcceptedStart100ns;
  N976N_BAT_U64 NotificationSequence;
  N976N_BAT_U32 TagCounter;
  N976N_BAT_U32 Running;
  N976N_BAT_U32 HaveClock;
  N976N_BAT_U32 HaveSample;
} N976N_BATTERY_CACHE;

enum N976N_BATTERY_CACHE_RESULT {
  N976N_BAT_CACHE_OK,
  N976N_BAT_CACHE_BAD_ARGUMENT,
  N976N_BAT_CACHE_STOPPED,
  N976N_BAT_CACHE_OLD_GENERATION,
  N976N_BAT_CACHE_BAD_CLOCK,
  N976N_BAT_CACHE_STALE,
  N976N_BAT_CACHE_BAD_SAMPLE,
  N976N_BAT_CACHE_REPLAY
};

/* Init is once per device lifetime. TTL is nonzero and measured in 100ns.
 * BeginD0 returns a nonzero generation token, or zero for invalid config.
 * Stop makes every old tag unavailable before the caller drains workers.
 * A worker captures the token before reading and must publish using that token.
 */
int N976nBatteryCacheInit(N976N_BATTERY_CACHE *Cache, N976N_BAT_U64 Ttl100ns);
N976N_BAT_U64 N976nBatteryCacheBeginD0(N976N_BATTERY_CACHE *Cache);
void N976nBatteryCacheStop(N976N_BATTERY_CACHE *Cache);

/* Caller supplies only an actual live transaction result, never a boot snapshot.
 * SampleId increases within each D0 generation. Start is before the first read;
 * Completed is after ACK/retirement/restoration, not after just RX. Now uses the
 * same monotonic clock. TTL starts at Start because the fields are sequential.
 * This cache supports partial samples, but the current Backend requires all
 * gauge fields before publication. No failed field is recycled.
 */
enum N976N_BATTERY_CACHE_RESULT N976nBatteryCachePublish(
  N976N_BATTERY_CACHE *Cache, const N976N_BATTERY_RAW *Raw,
  N976N_BAT_U32 AdmittedResistor, N976N_BAT_U64 Generation,
  N976N_BAT_U64 Start100ns, N976N_BAT_U64 Completed100ns,
  N976N_BAT_U64 Now100ns);

/* A current-generation unsafe failure immediately invalidates data. The
 * adapter may retain an old sample after a proven clean read failure only by
 * calling CacheRead at the current time; it never renews the sample's TTL.
 * An obsolete worker may not invalidate a newer D0 generation's cache.
 */
void N976nBatteryCacheFail(N976N_BATTERY_CACHE *Cache,
                         N976N_BAT_U64 Generation);
/* Same worker and StateLock as Publish. Independent source freshness, never
 * supplied by a class request and never a grant to change charging settings. */
int N976nBatteryCachePower(N976N_BATTERY_CACHE *Cache,N976N_BAT_U64 Generation,
  N976N_BAT_U64 At100ns,N976N_BAT_U64 Now100ns,unsigned Known,unsigned Online,unsigned Charging);

/* Read copies a known-present fresh view, otherwise clears Out and returns 0.
 * Read also expires the old tag; it performs no wait, MMIO or allocation.
 */
int N976nBatteryCacheRead(N976N_BATTERY_CACHE *Cache,
                         N976N_BAT_U64 Now100ns,
                         N976N_BATTERY_CACHE_VIEW *Out);

/* NotificationSequence changes on publication/invalidation. Device compares it
 * under its state lock, releases that lock, and only then may call
 * BatteryClassStatusNotify while pinning the class handle's lifetime. Battc can
 * synchronously reenter QueryStatus. None of this module's methods notify.
 */
#endif
