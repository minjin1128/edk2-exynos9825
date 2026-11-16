/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef N976N_DEMO_CONTRACT_H
#define N976N_DEMO_CONTRACT_H
#include "N976nHsi2c.h"
#include "N976nTouchHandoff.h"
#include "N976nDemoDiagnostic.h"
#define N976N_DEMO_MAP_COUNT 7U
/* Mapping indices are fixed, never hardware-provided addresses. */
enum { N976nMapHsi=0, N976nMapCmu=1, N976nMapUsi=2,
       N976nMapPins=3, N976nMapTop=4, N976nMapHandoff=5, N976nMapAlive=6 };
typedef int (*N976N_DEMO_READ)(void *, N976N_U32, N976N_U32, N976N_U32 *);
N976N_U32 N976nDemoCrc(const N976N_TOUCH_HANDOFF *H);
int N976nDemoValidateHandoff(const N976N_TOUCH_HANDOFF *H);
int N976nDemoReject(N976N_DEMO_DIAGNOSTIC *D,unsigned Bucket,unsigned Condition,
    unsigned Index,unsigned Offset,N976N_U64 Expected,N976N_U64 Actual,N976N_U64 Mask,int ReadOk);
int N976nDemoValidateHandoffEx(const N976N_TOUCH_HANDOFF *H,N976N_DEMO_DIAGNOSTIC *D);
int N976nDemoFresh(const N976N_TOUCH_HANDOFF *H, void *Context, N976N_DEMO_READ Read,
    N976N_HSI_LEASE *Lease);
int N976nDemoFreshEx(const N976N_TOUCH_HANDOFF *H, void *Context, N976N_DEMO_READ Read,
    N976N_HSI_LEASE *Lease,N976N_DEMO_DIAGNOSTIC *D);
#endif
