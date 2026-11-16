/* SEC86: exact existing SYSTEM identity and FAT32 geometry, not a media seal.
 * Derived from canonical UART return primary/backup BPB and physical GPT.
 * Mutable boot code, reserved boot-status byte, labels, FSInfo counters and file bytes are not pinned. */
#ifndef N976N_UFS_SYSTEM_H
#define N976N_UFS_SYSTEM_H
#define NUF_SYSTEM_PARTITION_START 0x17A00ULL
#define NUF_SYSTEM_PARTITION_BLOCKS 0x182400ULL
#define NUF_SYSTEM_VOLUME_BLOCKS 0x40000ULL
#define NUF_SYSTEM_VOLUME_BYTES 0x40000000ULL
#define NUF_SYSTEM_SECTOR_BYTES 4096U
#define NUF_SYSTEM_CLUSTER_SECTORS 1U
#define NUF_SYSTEM_RESERVED_SECTORS 32U
#define NUF_SYSTEM_FAT_COPIES 2U
#define NUF_SYSTEM_FAT_SECTORS 256U
#define NUF_SYSTEM_ROOT_CLUSTER 2U
#define NUF_SYSTEM_FSINFO_SECTOR 1U
#define NUF_SYSTEM_BACKUP_SECTOR 6U
#define NUF_SYSTEM_VOLUME_ID 0x1234ABCDU
#endif
