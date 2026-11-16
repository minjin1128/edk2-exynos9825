/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC79 portable adapter of the preserved firmware GPT reader. Read-only.
 */
#ifndef N976N_UFS_GPT_H
#define N976N_UFS_GPT_H
#include <stddef.h>
#if defined(NUF_KERNEL_BUILD)
/* WDK kernel CRT has no compatible user-mode MSVC stdint/vcruntime mix.
 * Match Core's fixed unsigned widths without importing user CRT headers. */
typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned int uint32_t;
typedef unsigned long long uint64_t;
#ifndef UINT32_MAX
#define UINT32_MAX 0xFFFFFFFFU
#endif
#ifndef UINT64_C
#define UINT64_C(value) value##ULL
#endif
#else
#include <stdint.h>
#endif
typedef char NufGptFixedWidths[(sizeof(uint8_t)==1&&sizeof(uint16_t)==2&&sizeof(uint32_t)==4&&sizeof(uint64_t)==8)?1:-1];
#define NUF_GPT_ERROR (UINT64_C(1)<<63)
#define NUF_GPT_BLOCK 4096U
#define NUF_GPT_MAX 128U
#pragma pack(push,1)
typedef struct { uint32_t Data1;uint16_t Data2,Data3;uint8_t Data4[8]; } NUF_GPT_GUID;
typedef struct { uint64_t Signature;uint32_t Revision,HeaderSize,CRC32,Reserved; } NUF_GPT_TABLE;
typedef struct { NUF_GPT_TABLE Header;uint64_t MyLBA,AlternateLBA,FirstUsableLBA,LastUsableLBA;
 NUF_GPT_GUID DiskGUID;uint64_t PartitionEntryLBA;uint32_t NumberOfPartitionEntries,SizeOfPartitionEntry,PartitionEntryArrayCRC32;
} NUF_GPT_HEADER;
typedef struct { NUF_GPT_GUID PartitionTypeGUID,UniquePartitionGUID;uint64_t StartingLBA,EndingLBA,Attributes;uint16_t PartitionName[36]; } NUF_GPT_ENTRY;
#pragma pack(pop)
typedef struct { uint64_t Magic,Version,Size,Phase,Status,Checks,Reason,EntryCount;
 uint64_t UsedCount,EspCount,TableCrc32,LargestStart,LargestBlocks,PrimaryHeaderCrc32,BackupHeaderCrc32,ReadCount;
} NUF_GPT_REPORT;
typedef uint64_t (*NUF_GPT_READ)(void *,uint64_t,uint8_t *);
extern volatile NUF_GPT_REPORT mNufGptReport;
void NufResetGpt(void);
uint64_t NufObserveGpt(uint64_t last,uint32_t blockBytes,NUF_GPT_READ read,void *context);
const NUF_GPT_ENTRY *NufGptEntries(void);
uint32_t NufGptCrc32(const void *,size_t);
#endif
