/* SPDX-License-Identifier: MIT
 * SEC76 private polling demo handoff. This is a current-boot producer record,
 * not an authorization flag: the consumer must also validate exact resources,
 * fresh live clock/pin/idle state, exclusive claim and the physical chip ID.
 * Immutable bytes end immediately before ClaimState. CRC32 uses the standard
 * reflected polynomial 0xEDB88320 with Crc32 zeroed. Claim uses 64-bit atomics.
 * NVS is normal write-back memory, never a device/uncached alias. Firmware
 * stops touching it after EBS release. No pointers, callbacks or arbitrary
 * MMIO addresses are accepted from the record.
 */
#ifndef N976N_TOUCH_HANDOFF_SHARED_H
#define N976N_TOUCH_HANDOFF_SHARED_H
#define N976N_TOUCH_HANDOFF_MAGIC 0x3637444E41484354ULL
#define N976N_TOUCH_HANDOFF_VERSION 2U
#define N976N_TOUCH_HANDOFF_PAGE_BYTES 4096U
#define N976N_TOUCH_HANDOFF_PREPARED 1U
#define N976N_TOUCH_HANDOFF_RELEASED 2U
#define N976N_TOUCH_CLAIM_READY 0ULL
#define N976N_TOUCH_CLAIM_OWNED 1ULL
#define N976N_TOUCH_CLAIM_RETIRED 2ULL
#define N976N_TOUCH_CLAIM_QUARANTINED 3ULL
#define N976N_TOUCH_HANDOFF_GUARD 0x36444843554F544EULL
#define N976N_TOUCH_CLOCK_MAX 12U
#define N976N_TOUCH_CMU_COUNT 13U
#define N976N_TOUCH_HANDOFF_LOW 0x92001000ULL
#define N976N_TOUCH_HANDOFF_END 0x95FDE000ULL
#pragma pack(push, 8)
typedef struct {
  unsigned long long Magic;
  unsigned int Version, Bytes, ImmutableBytes, Crc32;
  unsigned int Profile, ProducerStage;
  unsigned long long BootCounter, CounterHz, InputHz;
  unsigned int ChipId, BusHz, LdoBefore, LdoEnabled;
  unsigned int TimingFs[3];
  unsigned int Cmu[N976N_TOUCH_CMU_COUNT];
  unsigned int UsiMode, UsiControl, UsiOption;
  unsigned int GppCon, GppPull, GppDrive;
  unsigned int HsiConf, HsiTimeout, HsiTrailing, HsiCtl, HsiFifo, HsiAuto, HsiAddr;
  unsigned int ClockCount;
  unsigned int ClockOffsets[N976N_TOUCH_CLOCK_MAX];
  unsigned int ClockValues[N976N_TOUCH_CLOCK_MAX];
  unsigned int Gic420Disabled, Gic45Disabled, Eint8Masked;
  unsigned int PowerRequests, PowerResponses, PowerRetired;
  unsigned long long ProducerChecks;
  /* Version2 consumes two formerly reserved slots; ClaimState remains0x180.
   * Raw GPA1 words are captured, but only owned pin0 CON/PUD and EINT8 mask
   * are admission dependencies. DAT is live and is not an immutable value. */
  unsigned int Gpa1Con, Gpa1Pull, Gpa1EintMask, Gpa1Reserved;
  unsigned long long Reserved[6];
  volatile unsigned long long ClaimState;
  unsigned long long Guard;
} N976N_TOUCH_HANDOFF;
#pragma pack(pop)
#endif
