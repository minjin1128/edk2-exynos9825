/* SPDX-License-Identifier: MIT */
#ifndef N976N_BAT_LIVE_LEASE_H
#define N976N_BAT_LIVE_LEASE_H
#include "Bus.h"
#include "AdcLease.h"
#define N976N_BAT_LEASE_VERSION 4U
#define N976N_BAT_PRODUCER_GAUGE_USB 2U
#define N976N_BAT_LEASE_MAGIC 0x314556494C544142ULL
#define N976N_BAT_LEASE_GUARD 0x385442414C454153ULL
#define N976N_BAT_LEASE_LOW 0x92001000ULL
#define N976N_BAT_LEASE_END 0x95FDE000ULL
#define N976N_BAT_LEASE_PAGE 4096U
#define N976N_BAT_LEASE_IMMUTABLE_BYTES 1384U
#define N976N_BAT_LEASE_CRC_OFFSET 36U
#define N976N_BAT_LEASE_PREPARED 1U
#define N976N_BAT_LEASE_RELEASED 2U
#define N976N_BAT_CLAIM_READY 0U
#define N976N_BAT_CLAIM_OWNED 1U
#define N976N_BAT_CLAIM_CONSUMED 2U
#define N976N_BAT_CLAIM_QUARANTINED 3U
/* ADCWIN1 admits one D0 per firmware generation. Clean rundown after D0 is
 * CONSUMED, not READY: a fresh WDF context must not rearm the same generation.
 * Runtime suspend/resume requires its own validated re-admission policy. */
/* Native little-endian fixed-width ARM64/host ABI. All bytes/padding zeroed by
 * producer. No pointer, firmware call or inherited sample is an OS capability.
 * Claim is outside CRC, atomically owned while mappings/worker can exist.
 */
typedef struct {
  N976N_BAT_U64 Magic, BootCounter, CounterHz;
  N976N_BAT_U32 Version, Bytes, ImmutableBytes, Crc32;
  N976N_BAT_U32 Profile, ProducerStage, Factor, FactorStatus;
  N976N_BAT_U32 Gic114Masked, ProducerRetired, ProducerRestored, ProducerKind;
  N976N_BAT_BUS_BINDING Binding;
  N976N_BAT_U32 SelectedConfig[16]; /* final named producer selected-domain restore image */
  NCA_LEASE_BINDING Adc;
  N976N_BAT_U64 Guard;
  volatile N976N_BAT_U32 ClaimState;
  N976N_BAT_U32 ClaimReserved;
} N976N_BAT_LEASE;
typedef char N976nBatLeaseAbi[(sizeof(N976N_BAT_LEASE)==1392)?1:-1];
N976N_BAT_U32 N976nBatLeaseCrc(const N976N_BAT_LEASE *Lease);
int N976nBatLeaseValid(const N976N_BAT_LEASE *Lease,N976N_BAT_U32 Stage);
/* Read-only check after claim and before each sample/D0 use. Expected is the
 * immutable PrepareHardware copy. PageGuard is a fresh volatile read at4088.
 * This does not acquire ownership: caller has already performed claim CAS and
 * serializes its producer/rundown. A failed check requires quarantine. */
int N976nBatLeaseOwned(const N976N_BAT_LEASE *Expected,
  const volatile N976N_BAT_LEASE *Current,N976N_BAT_U64 PageGuard);
/* DIRQL variant: Expected was fully validated once in PrepareHardware and is
 * thereafter private/immutable. No repeated CRC or table validation in ISR. */
int N976nBatLeaseMatches(const N976N_BAT_LEASE *Expected,
  const volatile N976N_BAT_LEASE *Current,N976N_BAT_U64 PageGuard);
#endif
