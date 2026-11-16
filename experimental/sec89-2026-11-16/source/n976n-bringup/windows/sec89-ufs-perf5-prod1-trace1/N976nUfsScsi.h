/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_SCSI_H
#define N976N_UFS_SCSI_H
#include "N976nUfsCore.h"
enum { NufScsiDone=0,NufScsiRead=1,NufScsiCheck=2,NufScsiWrite=3,NufScsiFlush=4 };
#define NUF_SCSI_FUA 1U
enum { NufDirectionNone=0,NufDirectionIn=1,NufDirectionOut=2 };
typedef struct {
 U32 Disposition,Bytes,Blocks,WriteDenied,Flags;
 U64 Lba;
 U8 Key,Asc,Ascq,Reserved;
} NUF_SCSI_RESULT;
/* Exact host CDB -> bounded software reply or admitted operation plan. Planning
 * a WRITE is not permission to issue it: the runtime must additionally hold its
 * immutable admitted NTFS range and ownership gates. Ordinary WRITE success
 * permits volatile device caching (WCE=1). An incoming FUA requires one real
 * device flush after all blocks and before OS success. Explicit flush plans
 * always require hardware completion. Unknown CDBs
 * never reach hardware. Refusals leave the caller payload untouched. */
NUF_SCSI_RESULT NufScsiPlan(const U8 *Cdb,U32 CdbBytes,U32 Direction,U8 *Data,U32 DataBytes,U64 LastLba);
#endif
