/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_USERDATA_VOLUME_H_
#define N976N_USERDATA_VOLUME_H_
#include <Uefi.h>
#define N976N_USERDATA_START 0x222200ULL
#define N976N_USERDATA_PARTITION_BLOCKS 0x3972800ULL
#define N976N_USERDATA_VOLUME_BLOCKS 0x1000000ULL
/* Development boot I/O allowance: at most two64GiB volume passes. This is
 * finite accounting, not a complete volume integrity or coverage claim. */
#define N976N_USERDATA_MAX_DATA_BLOCKS (2ULL * N976N_USERDATA_VOLUME_BLOCKS)
typedef struct {
 UINT64 Magic, Version, Size, Status, Reason, PartitionIndex, Start, PartitionBlocks;
 UINT64 VolumeBlocks, LastLba, ReadBlocks, ReadCalls, MetadataBlocks, Rejected, Frozen, Closed;
 EFI_GUID DiskGuid, PartitionGuid;
} N976N_USERDATA_VOLUME_REPORT;
extern volatile N976N_USERDATA_VOLUME_REPORT mN976nUserdataVolumeReport;
BOOLEAN N976nUserdataVolumeLbaAllowed (UINT64 Lba);
BOOLEAN N976nUserdataVolumeReadAllowed (UINT64 Lba, CONST VOID *Buffer);
UINT64 N976nUserdataVolumeReadCount (VOID);
#endif
