/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_GPT_VIEW_H
#define N976N_UFS_GPT_VIEW_H
#include "N976nUfsCore.h"
enum { NufViewOk=0,NufViewArgument,NufViewSignature,NufViewRevision,NufViewSize,
 NufViewCrc,NufViewReserved,NufViewLocation,NufViewUsable,NufViewEntries,
 NufViewExtent,NufViewRetirement };
/* Only the fully retired CPU output of physical LBA1/LastLba is eligible.
 * Other LBAs are untouched. A refused header is never modified. */
int NufGptView(U8 *,U32,U64,U64,NUF_GPT_VIEW_SNAPSHOT *);
#endif
