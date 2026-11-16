/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC80 sealed 1GiB FAT32 on 4Kn UFS. The host image validator binds these
 * exact values to the BPB; this is not permission for arbitrary FAT layouts.
 * Measured with dosfstools4.2:4096/1/32/2/256,root2,info1,backup6.
 */
#ifndef N976N_SYSTEM_GEOMETRY_H
#define N976N_SYSTEM_GEOMETRY_H
#define N976N_SYSTEM_SECTOR_BYTES 4096U
#define N976N_SYSTEM_FAT_OFFSET 0x20000ULL
#define N976N_SYSTEM_FAT_BYTES 0x100000ULL
#define N976N_SYSTEM_DATA_OFFSET 0x220000ULL
#define N976N_SYSTEM_DATA_CLUSTERS 261600U
#define N976N_SYSTEM_INFO_OFFSET 4096ULL
#endif
