/* SPDX-License-Identifier: MIT
 * Physical attachment lifetime, independent of the observation SourceEpoch.
 * No hardware effects. Only the single PASSIVE producer may update it.
 */
#ifndef N976N_CHARGE_CONNECTION_H
#define N976N_CHARGE_CONNECTION_H
#include <stdint.h>
enum { NCL_UNKNOWN, NCL_ONLINE, NCL_OFFLINE };
typedef struct {
 uint64_t Id,Detaches,LastNow,LastSample,OfflineAt;
 unsigned Signal,Attached,OfflineSamples,Detached,Fault;
} NCL_CONNECTION;
/* Two independent bracketed offline samples over >=1s confirm removal.
 * UNKNOWN, duplicate/stale sample or online cancels partial detach proof.
 * Observation-epoch changes (including our C0 writes) never create an attach.
 * Fault cannot be cleared by cable changes. Return1 means a fresh attachment.
 */
static int NclObserve(NCL_CONNECTION *c,uint64_t now,uint64_t start,uint64_t end,
                     unsigned valid,unsigned known,unsigned online)
{
 c->Signal=NCL_UNKNOWN;
 if(c->Fault)return 0;
 if(!now||(c->LastNow&&now<c->LastNow)){c->Fault=1;return 0;}
 c->LastNow=now;
 if(!valid||!known||!start||start>end||end>now||now-start>=1000||
    start<=c->LastSample){c->OfflineAt=0;c->OfflineSamples=0;return 0;}
 c->LastSample=start;
 if(online){
  c->Signal=NCL_ONLINE;c->OfflineAt=0;c->OfflineSamples=0;
  if(c->Attached)return 0;
  if(c->Id==UINT64_MAX){c->Fault=1;return 0;}
  ++c->Id;c->Attached=1;c->Detached=0;return 1;
 }
 c->Signal=NCL_OFFLINE;
 if(!c->OfflineSamples){c->OfflineSamples=1;c->OfflineAt=start;return 0;}
 if(start<c->OfflineAt){c->Fault=1;return 0;}
 if(start-c->OfflineAt<1000)return 0;
 c->OfflineSamples=2;
 if(c->Attached){
  if(c->Detaches==UINT64_MAX){c->Fault=1;return 0;}
  ++c->Detaches;c->Attached=0;
 }
 c->Detached=1;return 0;
}
#endif
