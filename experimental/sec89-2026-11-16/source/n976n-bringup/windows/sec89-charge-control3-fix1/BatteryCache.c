/* SPDX-License-Identifier: MIT */
#include "BatteryCache.h"

/* Shared with firmware/host builds; no user CRT include in a kernel TU. */
static void Clear(void *Memory, N976N_BAT_U32 Bytes)
{
  N976N_BAT_U8 *P = (N976N_BAT_U8 *)Memory;
  while (Bytes--) *P++ = 0;
}

static N976N_BAT_U64 Next64(N976N_BAT_U64 Value)
{
  ++Value;
  return Value ? Value : 1;
}

static void Invalidate(N976N_BATTERY_CACHE *Cache)
{
  if (Cache->HaveSample || Cache->View.Tag) {
    Cache->NotificationSequence = Next64(Cache->NotificationSequence);
  }
  Clear(&Cache->View, (N976N_BAT_U32)sizeof(Cache->View));
  Cache->HaveSample = 0;
}

/* A backwards monotonic clock is an unavailable observation, not an enormous
 * unsigned age and not permission to reuse the last good battery reading. */
static int ObserveTime(N976N_BATTERY_CACHE *Cache, N976N_BAT_U64 Now)
{
  if (Cache->HaveClock && Now < Cache->LastObserved100ns) {
    Invalidate(Cache);
    return 0;
  }
  Cache->LastObserved100ns = Now;
  Cache->HaveClock = 1;
  if (Cache->HaveSample &&
      (Now < Cache->View.SampleStart100ns ||
       Now - Cache->View.SampleStart100ns >= Cache->Ttl100ns)) {
    Invalidate(Cache);
  }
  return 1;
}

int N976nBatteryCacheInit(N976N_BATTERY_CACHE *Cache, N976N_BAT_U64 Ttl)
{
  if (!Cache) return 0;
  Clear(Cache, (N976N_BAT_U32)sizeof(*Cache));
  Cache->Ttl100ns = Ttl;
  return Ttl != 0;
}

N976N_BAT_U64 N976nBatteryCacheBeginD0(N976N_BATTERY_CACHE *Cache)
{
  if (!Cache || !Cache->Ttl100ns) return 0;
  Invalidate(Cache);
  Cache->Generation = Next64(Cache->Generation);
  Cache->Running = 1;
  Cache->LastAcceptedSampleId = 0;
  Cache->LastAcceptedStart100ns = 0;
  /* The clock is global across D0 transitions. Keep its high-water mark. */
  return Cache->Generation;
}

void N976nBatteryCacheStop(N976N_BATTERY_CACHE *Cache)
{
  if (!Cache) return;
  Cache->Running = 0;
  Invalidate(Cache);
}

void N976nBatteryCacheFail(N976N_BATTERY_CACHE *Cache,
                         N976N_BAT_U64 Generation)
{
  if (Cache && Cache->Running && Generation &&
      Generation == Cache->Generation) Invalidate(Cache);
}

enum N976N_BATTERY_CACHE_RESULT N976nBatteryCachePublish(
  N976N_BATTERY_CACHE *Cache, const N976N_BATTERY_RAW *Raw,
  N976N_BAT_U32 Factor, N976N_BAT_U64 Generation,
  N976N_BAT_U64 Start, N976N_BAT_U64 Completed, N976N_BAT_U64 Now)
{
  N976N_BATTERY_VALUES Values;
  N976N_BAT_U32 Tag;
  if (!Cache) return N976N_BAT_CACHE_BAD_ARGUMENT;
  if (!Cache->Running) return N976N_BAT_CACHE_STOPPED;
  if (!Generation || Generation != Cache->Generation)
    return N976N_BAT_CACHE_OLD_GENERATION;
  if (!ObserveTime(Cache, Now)) return N976N_BAT_CACHE_BAD_CLOCK;
  if (Start > Completed || Completed > Now) {
    Invalidate(Cache);
    return N976N_BAT_CACHE_BAD_CLOCK;
  }
  if (Now - Start >= Cache->Ttl100ns) {
    Invalidate(Cache);
    return N976N_BAT_CACHE_STALE;
  }
  if (!Raw || !N976nBatteryDecode(Raw, Factor, &Values)) {
    Invalidate(Cache);
    return N976N_BAT_CACHE_BAD_SAMPLE;
  }
  if (Raw->SampleId <= Cache->LastAcceptedSampleId ||
      (Cache->LastAcceptedSampleId && Start < Cache->LastAcceptedStart100ns))
    return N976N_BAT_CACHE_REPLAY;

  Tag = Cache->View.Tag;
  Cache->LastAcceptedSampleId = Raw->SampleId;
  Cache->LastAcceptedStart100ns = Start;
  Cache->View.Values = Values;
  Cache->View.OnlineKnown=Cache->View.Online=Cache->View.ChargingObserved=0;
  Cache->View.PowerSample100ns=0;
  Cache->View.Generation = Generation;
  Cache->View.SampleStart100ns = Start;
  Cache->View.SampleCompleted100ns = Completed;
  Cache->HaveSample = 1;
  if (!(Values.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_STATUS)) ||
      !Values.Present) {
    Tag = 0;
  } else if (!Tag) {
    ++Cache->TagCounter;
    if (!Cache->TagCounter) Cache->TagCounter = 1;
    Tag = Cache->TagCounter;
  }
  Cache->View.Tag = Tag;
  Cache->NotificationSequence = Next64(Cache->NotificationSequence);
  return N976N_BAT_CACHE_OK;
}

int N976nBatteryCacheRead(N976N_BATTERY_CACHE *Cache,
                         N976N_BAT_U64 Now,
                         N976N_BATTERY_CACHE_VIEW *Out)
{
  if (!Out) return 0;
  Clear(Out, (N976N_BAT_U32)sizeof(*Out));
  if (!Cache || !Cache->Running || !Cache->Ttl100ns) return 0;
  if (!ObserveTime(Cache, Now) || !Cache->HaveSample || !Cache->View.Tag)
    return 0;
  *Out = Cache->View;
  if(!Out->PowerSample100ns||Now<Out->PowerSample100ns||
     Now-Out->PowerSample100ns>=2000ULL*10000){Out->OnlineKnown=Out->Online=Out->ChargingObserved=0;}
  return 1;
}

int N976nBatteryCachePower(N976N_BATTERY_CACHE *c,N976N_BAT_U64 generation,
 N976N_BAT_U64 at,N976N_BAT_U64 now,unsigned known,unsigned online,unsigned charging)
{
 if(!c||!c->Running||generation!=c->Generation||!c->HaveSample)return 0;
 c->View.OnlineKnown=c->View.Online=c->View.ChargingObserved=0;c->View.PowerSample100ns=0;
 if(!ObserveTime(c,now)||!c->HaveSample||!at||at>now||now-at>=2000ULL*10000||
    known>1||online>1||charging>1||(!known&&online)||(charging&&!online))return 0;
 c->View.OnlineKnown=known;c->View.Online=online;c->View.ChargingObserved=charging;c->View.PowerSample100ns=at;
 c->NotificationSequence=Next64(c->NotificationSequence);return 1;
}
