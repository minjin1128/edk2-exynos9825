/* SPDX-License-Identifier: MIT */
#ifndef N976N_SOURCE_STATE_H
#define N976N_SOURCE_STATE_H
#include "Charge.h"
/* A bracketed observation epoch, NOT a negotiated USB/PD power contract.
 * Its lifetime is one producer generation. It can establish UI online status
 * and bind temperature sampling; it never grants charger-write capability. */
typedef struct {
 N976N_BAT_U64 Generation,Epoch,LastNow,StartedAt,CompletedAt;
 N976N_POWER_RAW Last;
 unsigned Valid,OnlineKnown,Online,Changed,Exhausted,Open;
} N976N_SOURCE_STATE;
void N976nSourceInit(N976N_SOURCE_STATE *,N976N_BAT_U64 Generation);
int N976nSourceBegin(N976N_SOURCE_STATE *,const N976N_POWER_RAW *,N976N_BAT_U64 Now);
int N976nSourceFinish(N976N_SOURCE_STATE *,const N976N_POWER_RAW *,N976N_BAT_U64 Now);
void N976nSourceInvalidate(N976N_SOURCE_STATE *);
int N976nSourceMatches(const N976N_SOURCE_STATE *,const N976N_POWER_RAW *);
#endif
