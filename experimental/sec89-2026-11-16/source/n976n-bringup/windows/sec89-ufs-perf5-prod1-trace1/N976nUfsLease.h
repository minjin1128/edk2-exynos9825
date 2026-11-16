/* SPDX-License-Identifier: MIT */
#ifndef N976N_UFS_LEASE_H
#define N976N_UFS_LEASE_H
#include "N976nUfsCore.h"
#include "N976nUfsHandoff.h"
int NufRange(U64 Base,U64 Bytes);
int NufResourceAllowed(U32 Index,U64 Base,U32 Bytes,U32 Memory);
int NufOverlap(U64 A,U64 An,U64 B,U64 Bn);
U32 NufLeaseCrc(const N976N_UFS_HANDOFF *);
U32 NufValidateLease(const N976N_UFS_HANDOFF *,U64 LeaseBase,U64 DmaBase);
U32 NufValidateLeasePage(const U8 *);
#endif
