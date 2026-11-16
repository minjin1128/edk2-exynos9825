/* SPDX-License-Identifier: MIT
 * SEC78 firmware/Windows ABI. Fixed-width integer spelling is shared verbatim.
 * Offsets, rather than virtual pointers, describe the two reserved NVS pages.
 * All 64 bytes of Reserved and both page tails must remain zero except guard.
 * CRC covers [0, ImmutableBytes) with Crc32 zero; ClaimState and Guard excluded.
 * Baseline is exactly the already validated LBA0 4096-byte GPT read.
 */
#ifndef N976N_UFS_HANDOFF_H
#define N976N_UFS_HANDOFF_H
#define N976N_UFS_HANDOFF_MAGIC 0x38374653554E4EULL
#define N976N_UFS_HANDOFF_VERSION 2U
#define N976N_UFS_HANDOFF_GUARD 0x38474653554E4E47ULL
#define N976N_UFS_HANDOFF_BYTES 336U
#define N976N_UFS_HANDOFF_IMMUTABLE_BYTES 320U
#define N976N_UFS_HANDOFF_LEASE_BYTES 8192U
#define N976N_UFS_HANDOFF_DMA_BYTES 90112U
#define N976N_UFS_FIRMWARE_DMA_BYTES 28672U
#define N976N_UFS_HANDOFF_BASELINE_OFFSET 4096U
#define N976N_UFS_HANDOFF_BASELINE_BYTES 4096U
#define N976N_UFS_HANDOFF_PREPARED 1U
#define N976N_UFS_HANDOFF_STOPPED 2U
#define N976N_UFS_HANDOFF_RELEASED 3U
#define N976N_UFS_CLAIM_READY 0ULL
#define N976N_UFS_CLAIM_WINDOWS 1ULL
#define N976N_UFS_CLAIM_RETIRED 2ULL
#define N976N_UFS_CLAIM_QUARANTINED 3ULL
#define N976N_UFS_HANDOFF_PREPARED_CHECKS 0x1FU
#define N976N_UFS_HANDOFF_STOPPED_CHECKS 0x3FU
#define N976N_UFS_HANDOFF_RELEASED_CHECKS 0x7FU
/* The only supplied Windows workspace is UC, NX, below4GiB, reserved NVS.
 * Firmware lease/baseline and prior firmware DMA remain WB, NX, reserved NVS.
 */
#define N976N_UFS_HANDOFF_FLAGS 7U

typedef struct {
  unsigned long long Magic;
  unsigned int Version, Bytes, ImmutableBytes, Crc32;
  unsigned int Profile, ProducerStage;
  unsigned long long BootCounter, CounterHz, LeaseBase, LeaseBytes;
  unsigned long long DmaBase, DmaBytes, FirmwareDmaBase, FirmwareDmaBytes;
  unsigned long long HciBase;
  unsigned int HciBytes, VendorOffset;
  unsigned long long CoherencyBase;
  unsigned int CoherencyOffset, CoherencyBytes;
  unsigned int BaselineOffset, BaselineBytes, BaselineCrc32, Lun;
  unsigned long long LastLba;
  unsigned int BlockBytes, Flags;
  unsigned int HciCap, HciVersion, Hce, Hcs;
  unsigned int Ie, Ahit, Is, Iacr;
  unsigned int TrlBase, TrlBaseHi, TmBase, TmBaseHi;
  unsigned int TrlRun, TmRun, TrlDoorbell, TmDoorbell;
  unsigned int TxPrdt, RxPrdt, Reorder, Nexus;
  unsigned int Axi, Coherency, ProducerChecks, PowerRaw;
  unsigned char Reserved[64];
  volatile unsigned long long ClaimState;
  unsigned long long Guard;
} N976N_UFS_HANDOFF;
#endif
