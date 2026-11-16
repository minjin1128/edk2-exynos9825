/* Actual cache/adapter behavioral tests; no simulated callback implementation. */
#include "../Miniclass.h"
#include <assert.h>
#include <stdio.h>
#include <string.h>

static unsigned Cases;
#define CHECK(x) do { ++Cases; if (!(x)) { \
  fprintf(stderr,"FAIL line %u: %s\n",__LINE__,#x); return 0; } } while (0)

typedef struct {
  N976N_BATTERY_CACHE Cache;
  N976N_BATTERY_MINICLASS_CONTEXT Mini;
  N976N_BAT_U64 Now;
  unsigned Held, Locks, Unlocks, ClockReads;
} FIXTURE;

static void Lock(PVOID Owner)
{
  FIXTURE *F = Owner;
  assert(!F->Held);
  F->Held = 1; ++F->Locks;
}
static void Unlock(PVOID Owner)
{
  FIXTURE *F = Owner;
  assert(F->Held);
  F->Held = 0; ++F->Unlocks;
}
static N976N_BAT_U64 Now(PVOID Owner)
{
  FIXTURE *F = Owner;
  assert(F->Held); /* Time is sampled after locking, not before contention. */
  ++F->ClockReads;
  return F->Now;
}
static void Init(FIXTURE *F)
{
  memset(F, 0, sizeof(*F));
  assert(N976nBatteryCacheInit(&F->Cache, 1000));
  F->Mini.Cache = &F->Cache;
  F->Mini.Owner = F;
  F->Mini.Lock = Lock; F->Mini.Unlock = Unlock; F->Mini.Now100ns = Now;
}
static void Field(N976N_BATTERY_RAW *Raw, unsigned F, unsigned Value)
{
  N976N_BATTERY_READ Spec;
  N976N_BAT_U8 Data[2] = {(N976N_BAT_U8)Value, (N976N_BAT_U8)(Value >> 8)};
  assert(N976nBatteryReadSpec(F, &Spec));
  assert(N976nBatteryRecord(Raw, F, 1, Data, Spec.Bytes) == N976N_BAT_OK);
}
static N976N_BATTERY_RAW Sample(N976N_BAT_U64 Id)
{
  N976N_BATTERY_RAW Raw;
  assert(N976nBatteryBegin(&Raw, Id));
  Field(&Raw, N976N_BAT_STATUS, 0);
  Field(&Raw, N976N_BAT_SOCREP, 0x3E80); /* 62.5%. */
  Field(&Raw, N976N_BAT_VCELL, 0xC000); /* 3840mV. */
  Field(&Raw, N976N_BAT_CURRENT, 0xFC00);
  Field(&Raw, N976N_BAT_AVG_CURRENT, 0xFC00);
  Field(&Raw, N976N_BAT_REMAINING, 2000);
  Field(&Raw, N976N_BAT_FULL, 4000);
  Field(&Raw, N976N_BAT_INPUT, 0x60); /* Never proof of sink/AC-online. */
  Field(&Raw, N976N_BAT_CHARGE_DETAIL, 8);
  return Raw;
}
static int Publish(FIXTURE *F, N976N_BATTERY_RAW *Raw, unsigned Factor,
                   N976N_BAT_U64 Start, N976N_BAT_U64 End, N976N_BAT_U64 Time)
{
  F->Now = Time;
  return N976nBatteryCachePublish(&F->Cache, Raw, Factor, F->Cache.Generation,
                                   Start, End, Time);
}

static int CacheLifecycle(void)
{
  FIXTURE F;
  N976N_BATTERY_RAW R;
  N976N_BATTERY_CACHE_VIEW V;
  N976N_BAT_U64 Gen, Seq;
  unsigned Tag;
  Init(&F); R = Sample(1);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 0, &V));
  CHECK(Publish(&F, &R, 2, 0, 0, 0) == N976N_BAT_CACHE_STOPPED);
  Gen = N976nBatteryCacheBeginD0(&F.Cache);
  CHECK(Gen != 0);
  CHECK(Publish(&F, &R, 2, 100, 120, 130) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 150, &V));
  CHECK(V.Tag && V.Values.SocPermille == 625 && V.Values.VoltageMv == 3840);
  Tag = V.Tag; Seq = F.Cache.NotificationSequence;
  R = Sample(2);
  CHECK(Publish(&F, &R, 2, 160, 170, 180) == N976N_BAT_CACHE_OK);
  CHECK(F.Cache.NotificationSequence != Seq);
  CHECK(N976nBatteryCacheRead(&F.Cache, 200, &V) && V.Tag == Tag);
  CHECK(Publish(&F, &R, 2, 180, 190, 200) == N976N_BAT_CACHE_REPLAY);
  CHECK(N976nBatteryCacheRead(&F.Cache, 210, &V) && V.Tag == Tag);
  R = Sample(3);
  CHECK(Publish(&F, &R, 2, 159, 220, 220) == N976N_BAT_CACHE_REPLAY);
  CHECK(N976nBatteryCacheRead(&F.Cache, 1159, &V));
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1160, &V)); /* Exact TTL expires. */
  CHECK(!V.Tag && !V.Values.ValueValidMask);
  CHECK(Publish(&F, &R, 2, 1150, 1160, 1170) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 1180, &V) && V.Tag != Tag);
  Tag = V.Tag;
  N976nBatteryCacheStop(&F.Cache);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1190, &V));
  CHECK(N976nBatteryCachePublish(&F.Cache, &R, 2, Gen, 1190, 1190, 1190) ==
         N976N_BAT_CACHE_STOPPED);
  CHECK(N976nBatteryCacheBeginD0(&F.Cache) != Gen);
  R = Sample(1);
  CHECK(Publish(&F, &R, 2, 1200, 1210, 1220) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 1230, &V) && V.Tag != Tag);
  Tag = V.Tag;
  CHECK(N976nBatteryCachePublish(&F.Cache, &R, 2, Gen, 0, 0, 0) ==
        N976N_BAT_CACHE_OLD_GENERATION);
  N976nBatteryCacheFail(&F.Cache, Gen);
  CHECK(N976nBatteryCacheRead(&F.Cache, 1240, &V) && V.Tag == Tag);
  N976nBatteryCacheFail(&F.Cache, F.Cache.Generation);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1250, &V));
  CHECK(Publish(&F, &R, 2, 1250, 1260, 1270) == N976N_BAT_CACHE_REPLAY);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1280, &V));
  R = Sample(2);
  CHECK(Publish(&F, &R, 2, 1280, 1290, 1300) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 1310, &V) && V.Tag != Tag);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1309, &V)); /* Clock rollback. */
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1320, &V)); /* No revival. */
  return 1;
}

static int PresencePartialAndTiming(void)
{
  FIXTURE F;
  N976N_BATTERY_RAW R;
  N976N_BATTERY_CACHE_VIEW V;
  unsigned Tag;
  Init(&F); N976nBatteryCacheBeginD0(&F.Cache);
  assert(N976nBatteryBegin(&R, 1));
  Field(&R, N976N_BAT_SOCREP, 0x4000);
  CHECK(Publish(&F, &R, 0, 10, 20, 30) == N976N_BAT_CACHE_OK);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 31, &V)); /* No known presence. */
  R = Sample(2); Field(&R, N976N_BAT_STATUS, 8);
  CHECK(Publish(&F, &R, 2, 40, 50, 60) == N976N_BAT_CACHE_OK);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 61, &V)); /* Known absent. */
  assert(N976nBatteryBegin(&R, 3)); Field(&R, N976N_BAT_STATUS, 0);
  CHECK(Publish(&F, &R, 0, 70, 80, 90) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 91, &V));
  CHECK(V.Values.ValueValidMask == N976N_BAT_FIELD_BIT(N976N_BAT_STATUS));
  Tag = V.Tag;
  R = Sample(4); Field(&R, N976N_BAT_STATUS, 0xFFFF);
  CHECK(Publish(&F, &R, 2, 100, 110, 120) == N976N_BAT_CACHE_OK);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 121, &V));
  R = Sample(5);
  CHECK(Publish(&F, &R, 0, 130, 140, 150) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 151, &V) && V.Tag != Tag);
  CHECK(!(V.Values.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT)));
  CHECK(Publish(&F, &R, 2, 130, 120, 160) == N976N_BAT_CACHE_BAD_CLOCK);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 170, &V));
  R = Sample(6);
  CHECK(Publish(&F, &R, 2, 171, 200, 180) == N976N_BAT_CACHE_BAD_CLOCK);
  CHECK(Publish(&F, &R, 2, 0, 1100, 1100) == N976N_BAT_CACHE_STALE);
  CHECK(Publish(&F, &R, 2, 1100, 1110, 1120) == N976N_BAT_CACHE_OK);
  R = Sample(7); R.ValidMask |= 1U << 31;
  CHECK(Publish(&F, &R, 2, 1130, 1140, 1150) == N976N_BAT_CACHE_BAD_SAMPLE);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 1160, &V));
  R = Sample(8);
  CHECK(Publish(&F, &R, 2, 1170, 1180, 1190) == N976N_BAT_CACHE_OK);
  Tag = F.Cache.View.Tag;
  R = Sample(9);
  CHECK(Publish(&F, &R, 2, 2200, 2210, 2220) == N976N_BAT_CACHE_OK);
  CHECK(F.Cache.View.Tag != Tag); /* Expiry without an intervening reader. */
  R = Sample(10);
  CHECK(Publish(&F, &R, 2, 2220, 2220, 2219) == N976N_BAT_CACHE_BAD_CLOCK);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 2230, &V));
  return 1;
}

static int WrapAndArguments(void)
{
  FIXTURE F;
  N976N_BATTERY_RAW R = Sample(1);
  N976N_BATTERY_CACHE_VIEW V;
  CHECK(!N976nBatteryCacheInit(NULL, 10));
  Init(&F); CHECK(!N976nBatteryCacheInit(&F.Cache, 0));
  CHECK(!N976nBatteryCacheBeginD0(&F.Cache));
  CHECK(!N976nBatteryCacheBeginD0(NULL));
  CHECK(!N976nBatteryCacheRead(NULL, 0, &V));
  CHECK(!N976nBatteryCacheRead(&F.Cache, 0, NULL));
  CHECK(N976nBatteryCachePublish(NULL, &R, 2, 1, 0, 0, 0) ==
        N976N_BAT_CACHE_BAD_ARGUMENT);
  Init(&F); F.Cache.Generation = UINT64_MAX; F.Cache.TagCounter = UINT32_MAX;
  CHECK(N976nBatteryCacheBeginD0(&F.Cache) == 1);
  CHECK(Publish(&F, &R, 2, 0, 0, 0) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryCacheRead(&F.Cache, 0, &V) && V.Tag == 1);
  CHECK(Publish(&F, NULL, 2, 1, 1, 1) == N976N_BAT_CACHE_BAD_SAMPLE);
  CHECK(!N976nBatteryCacheRead(&F.Cache, 2, &V));
  N976nBatteryCacheStop(NULL); N976nBatteryCacheFail(NULL, 0);
  return 1;
}

static int AdapterContract(void)
{
  FIXTURE F;
  N976N_BATTERY_RAW R;
  BATTERY_MINIPORT_INFO Info, Before;
  BATTERY_INFORMATION B;
  BATTERY_STATUS Status;
  BATTERY_NOTIFY Notify = {0};
  ULONG Tag, OldTag, Length, Time;
  unsigned char Buffer[128], Saved[128];
  unsigned Level;
  Init(&F); memset(&Info, 0xA5, sizeof(Info)); Before = Info;
  CHECK(N976nBatteryMiniBind(&Info, &F.Mini));
  CHECK(Info.MajorVersion == Before.MajorVersion && Info.Pdo == Before.Pdo);
  CHECK(Info.Context == &F.Mini && Info.QueryTag == N976nBatteryQueryTag &&
        Info.QueryStatus == N976nBatteryQueryStatus);
  Before = Info;
  CHECK(!N976nBatteryMiniBind(&Info, NULL) && !memcmp(&Info, &Before, sizeof(Info)));
  CHECK(Info.QueryTag(&F.Mini, &Tag) == STATUS_NO_SUCH_DEVICE && Tag == 0);
  CHECK(Info.QueryTag(NULL, &Tag) == STATUS_INVALID_PARAMETER);
  CHECK(Info.QueryTag(&F.Mini, NULL) == STATUS_INVALID_PARAMETER);
  N976nBatteryCacheBeginD0(&F.Cache); R = Sample(1);
  CHECK(Publish(&F, &R, 2, 100, 110, 120) == N976N_BAT_CACHE_OK);
  CHECK(Info.QueryTag(&F.Mini, &Tag) == STATUS_SUCCESS && Tag != 0);
  CHECK(Info.QueryStatus(&F.Mini, Tag, &Status) == STATUS_SUCCESS);
  CHECK(Status.Capacity == 625 && Status.Voltage == 3840);
  CHECK(Status.Rate == BATTERY_UNKNOWN_RATE && Status.PowerState == BATTERY_DISCHARGING);
  CHECK(!(Status.PowerState & (BATTERY_CRITICAL | BATTERY_POWER_ON_LINE)));
  CHECK(Info.QueryStatus(&F.Mini, Tag + 1, &Status) == STATUS_NO_SUCH_DEVICE);
  CHECK(Status.Capacity == BATTERY_UNKNOWN_CAPACITY && Status.Rate == BATTERY_UNKNOWN_RATE);
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryInformation, 0, &B,
                            sizeof(B), &Length) == STATUS_SUCCESS);
  CHECK(Length == sizeof(B) && B.Capabilities ==
        (BATTERY_SYSTEM_BATTERY | BATTERY_CAPACITY_RELATIVE));
  CHECK(B.DesignedCapacity == BATTERY_UNKNOWN_CAPACITY && B.FullChargedCapacity == 1000);
  CHECK(B.DefaultAlert1 == 0 && B.DefaultAlert2 == 0 && B.CriticalBias == 0 && B.CycleCount == 0);
  memset(Buffer, 0xA5, sizeof(Buffer)); memcpy(Saved, Buffer, sizeof(Saved));
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryInformation, 0, Buffer,
                            sizeof(B) - 1, &Length) == STATUS_BUFFER_TOO_SMALL);
  CHECK(Length == sizeof(B) && !memcmp(Buffer, Saved, sizeof(Buffer)));
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryInformation, 0, NULL,
                            sizeof(B), &Length) == STATUS_INVALID_PARAMETER);
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryInformation, 0, &B,
                            sizeof(B), NULL) == STATUS_INVALID_PARAMETER);
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryEstimatedTime, -100, &Time,
                            sizeof(Time), &Length) == STATUS_SUCCESS);
  CHECK(Time == BATTERY_UNKNOWN_TIME && Length == 4);
  CHECK(Info.QueryInformation(&F.Mini, Tag, BatteryDeviceName, 0, Buffer,
                            sizeof(Buffer), &Length) == STATUS_SUCCESS);
  CHECK(Length == 42 && Buffer[Length-2] == 0 && Buffer[Length-1] == 0);
  for (Level = 0; Level <= BatterySerialNumber; ++Level) {
    if (Level == BatteryInformation || Level == BatteryEstimatedTime ||
        Level == BatteryDeviceName) continue;
    CHECK(Info.QueryInformation(&F.Mini, Tag, (BATTERY_QUERY_INFORMATION_LEVEL)Level,
                                0, Buffer, sizeof(Buffer), &Length) == STATUS_INVALID_DEVICE_REQUEST);
    CHECK(Length == 0);
  }
  CHECK(Info.QueryInformation(&F.Mini, Tag, (BATTERY_QUERY_INFORMATION_LEVEL)99,
                              0, Buffer, sizeof(Buffer), &Length) == STATUS_INVALID_PARAMETER);
  CHECK(Info.SetInformation(&F.Mini, Tag, BatteryCharge, NULL) == STATUS_NOT_SUPPORTED);
  CHECK(Info.SetInformation(&F.Mini, Tag+1, BatteryCharge, NULL) == STATUS_NO_SUCH_DEVICE);
  CHECK(Info.SetStatusNotify(&F.Mini, Tag, &Notify) == STATUS_NOT_SUPPORTED);
  CHECK(Info.SetStatusNotify(&F.Mini, Tag+1, &Notify) == STATUS_NO_SUCH_DEVICE);
  CHECK(Info.DisableStatusNotify(&F.Mini) == STATUS_NOT_SUPPORTED);
  CHECK(Info.DisableStatusNotify(NULL) == STATUS_INVALID_PARAMETER);
  CHECK(Info.SetStatusNotify(&F.Mini, Tag, NULL) == STATUS_INVALID_PARAMETER);
  OldTag = Tag; F.Now = 1100;
  CHECK(Info.QueryStatus(&F.Mini, Tag, &Status) == STATUS_NO_SUCH_DEVICE);
  CHECK(Info.QueryTag(&F.Mini, &Tag) == STATUS_NO_SUCH_DEVICE && Tag == 0);
  R = Sample(2);
  CHECK(Publish(&F, &R, 2, 1101, 1110, 1120) == N976N_BAT_CACHE_OK);
  CHECK(Info.QueryTag(&F.Mini, &Tag) == STATUS_SUCCESS && Tag != OldTag);
  CHECK(Info.QueryInformation(&F.Mini, OldTag, BatteryInformation, 0, &B,
                            sizeof(B), &Length) == STATUS_NO_SUCH_DEVICE && Length == 0);
  CHECK(!F.Held && F.Locks == F.Unlocks && F.ClockReads == F.Locks);
  return 1;
}

static int AdapterPartialStates(void)
{
  FIXTURE F;
  N976N_BATTERY_RAW R;
  BATTERY_STATUS B;
  N976N_BAT_U8 FailedPayload[2] = {0};
  ULONG Tag;
  Init(&F); N976nBatteryCacheBeginD0(&F.Cache);
  assert(N976nBatteryBegin(&R, 1)); Field(&R, N976N_BAT_STATUS, 0);
  CHECK(Publish(&F, &R, 2, 0, 1, 2) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryTag(&F.Mini, &Tag) == STATUS_SUCCESS);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS);
  CHECK(B.Capacity == BATTERY_UNKNOWN_CAPACITY && B.Voltage == BATTERY_UNKNOWN_VOLTAGE &&
        B.Rate == BATTERY_UNKNOWN_RATE && B.PowerState == 0);
  R = Sample(2); Field(&R, N976N_BAT_CURRENT, 0x0400);
  Field(&R, N976N_BAT_CHARGE_DETAIL, 1);
  CHECK(Publish(&F, &R, 2, 3, 4, 5) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS &&
        B.PowerState == 0 && B.Rate == BATTERY_UNKNOWN_RATE);
  R = Sample(3); Field(&R, N976N_BAT_CHARGE_DETAIL, 1);
  CHECK(Publish(&F, &R, 2, 6, 7, 8) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS && B.PowerState == 0);
  R = Sample(4); Field(&R, N976N_BAT_SOCREP, 0xFFFF);
  CHECK(Publish(&F, &R, 0, 9, 10, 11) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS &&
        B.Capacity == 1000 && B.Rate == BATTERY_UNKNOWN_RATE && B.PowerState == 0);
  R = Sample(5); Field(&R, N976N_BAT_SOCREP, 0);
  CHECK(Publish(&F, &R, 2, 12, 13, 14) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS &&
        B.Capacity == 0 && !(B.PowerState & BATTERY_CRITICAL));
  R = Sample(6);
  CHECK(N976nBatteryRecord(&R, N976N_BAT_SOCREP, 0, FailedPayload, 0) == N976N_BAT_TRANSPORT_FAILED);
  CHECK(Publish(&F, &R, 2, 15, 16, 17) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryStatus(&F.Mini, Tag, &B) == STATUS_SUCCESS &&
        B.Capacity == BATTERY_UNKNOWN_CAPACITY);
  R = Sample(7); Field(&R, N976N_BAT_STATUS, 8);
  CHECK(Publish(&F, &R, 2, 18, 19, 20) == N976N_BAT_CACHE_OK);
  CHECK(N976nBatteryQueryTag(&F.Mini, &Tag) == STATUS_NO_SUCH_DEVICE && !Tag);
  CHECK(!F.Held && F.Locks == F.Unlocks);
  return 1;
}

static int PowerStates(void){
 FIXTURE F;N976N_BATTERY_RAW R;BATTERY_STATUS B;ULONG tag;
 Init(&F);F.Cache.Ttl100ns=50000000;N976nBatteryCacheBeginD0(&F.Cache);
 R=Sample(1);Field(&R,N976N_BAT_CURRENT,0x0400);Field(&R,N976N_BAT_CHARGE_DETAIL,1);
 CHECK(Publish(&F,&R,2,100,110,120)==N976N_BAT_CACHE_OK);
 CHECK(N976nBatteryQueryTag(&F.Mini,&tag)==0);
 CHECK(N976nBatteryCachePower(&F.Cache,F.Cache.Generation,100,120,1,1,1));
 CHECK(N976nBatteryQueryStatus(&F.Mini,tag,&B)==0&&B.PowerState==(BATTERY_POWER_ON_LINE|BATTERY_CHARGING));
 CHECK(N976nBatteryCachePower(&F.Cache,F.Cache.Generation,100,120,1,1,0));
 CHECK(N976nBatteryQueryStatus(&F.Mini,tag,&B)==0&&B.PowerState==BATTERY_POWER_ON_LINE);
 CHECK(N976nBatteryCachePower(&F.Cache,F.Cache.Generation,100,120,1,0,0));
 CHECK(N976nBatteryQueryStatus(&F.Mini,tag,&B)==0&&B.PowerState==0);
 CHECK(!N976nBatteryCachePower(&F.Cache,F.Cache.Generation,100,120,1,0,1));
 CHECK(N976nBatteryCachePower(&F.Cache,F.Cache.Generation,100,120,1,1,1));
 F.Now=20000100;CHECK(N976nBatteryQueryStatus(&F.Mini,tag,&B)==0&&B.PowerState==0);
 CHECK(!N976nBatteryCachePower(&F.Cache,F.Cache.Generation+1,20000100,20000120,1,1,1));
 CHECK(!N976nBatteryCachePower(&F.Cache,F.Cache.Generation,20000200,20000120,1,1,1));
 R=Sample(2);CHECK(Publish(&F,&R,2,20000200,20000210,20000220)==N976N_BAT_CACHE_OK);
 CHECK(N976nBatteryCachePower(&F.Cache,F.Cache.Generation,20000200,20000220,1,1,0));
 CHECK(N976nBatteryQueryStatus(&F.Mini,tag,&B)==0&&B.PowerState==(BATTERY_POWER_ON_LINE|BATTERY_DISCHARGING));
 return 1;
}
int main(void)
{
  if (!CacheLifecycle() || !PresencePartialAndTiming() || !WrapAndArguments() ||
      !AdapterContract() || !AdapterPartialStates() || !PowerStates()) return 1;
  printf("PASS %u cases: actual cache + Battc callback adapter\n", Cases);
  return 0;
}
