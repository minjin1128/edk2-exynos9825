/* SPDX-License-Identifier: MIT
 * Three-channel fresh ADC producer. Caller serializes this private context.
 * No hardware access, default temperature, source contract or charge authority.
 */
#ifndef N976N_CHARGE_THERMAL_H
#define N976N_CHARGE_THERMAL_H
#include "ChargeControl.h"
#define NCT_CHANNELS 3U
#define NCT_SAMPLES 5U
#define NCT_TOTAL 15U
#define NCT_POINTS 23U
#define NCT_MS 10000ULL /* input clock unit: 100 ns; NCC_FACTS uses ms */
#define NCT_BATCH_MAX_MS 500U
#define NCT_CONVERSION_MS 100U
enum NCT_REASON {NCT_OK,NCT_ARGUMENT,NCT_BINDING,NCT_OWNER,NCT_CANCELLED,
 NCT_CLOCK,NCT_DEADLINE,NCT_SEQUENCE,NCT_COMPLETION,NCT_SAMPLE,NCT_MISSING,
 NCT_SOURCE,NCT_STALE,NCT_REENTRANT,NCT_UNCERTAIN};
enum NCT_STATE {NCT_IDLE,NCT_COLLECTING,NCT_READY,NCT_INVALID};
typedef struct {
 /* Supplied only from validated DT/firmware admission, never a user IOCTL.
  * A nonzero digest is a binding token, NOT independent validation of a DT.
  * Tables are copied so later caller mutation cannot alter an active batch. */
 uint8_t DtHash[32],Channel[NCT_CHANNELS];
 uint64_t AdcAddress;
 uint32_t AdcBytes,Irq;
 uint16_t Adc[NCT_CHANNELS][NCT_POINTS],MaxMiddleSpread[NCT_CHANNELS];
 int32_t DeciC[NCT_CHANNELS][NCT_POINTS];
} NCT_PROFILE;
typedef struct {
 uint64_t Now100ns,AdcGeneration,SourceEpoch;
 uint8_t Ready,Retired,Cancelled,Quarantined;
} NCT_IDENTITY;
typedef struct {
 uint64_t Batch,Sequence,AdcGeneration,SourceEpoch,NotBefore100ns,Deadline100ns;
 uint32_t Channel;
} NCT_TICKET;
typedef struct {
 NCT_TICKET Ticket;
 uint64_t Started100ns,Completed100ns;
 uint32_t Raw;
 /* IRQ and ACK are actual observations. Retired includes adapter-specific
  * interrupt rundown; GIC EOI is platform-owned in Windows, not a fake flag. */
 uint8_t Issued,Irq,Ack,Retired,Cancelled,Quarantined;
} NCT_COMPLETION_RECORD;
typedef struct {
 uint64_t Batch,AdcGeneration,SourceEpoch,Oldest100ns,Newest100ns,Finished100ns;
 int32_t DeciC[NCT_CHANNELS];
 uint32_t Count,Valid;
} NCT_RESULT;
typedef struct {
 NCT_PROFILE Profile;
 NCT_TICKET Pending;
 NCT_COMPLETION_RECORD Samples[NCT_TOTAL];
 NCT_RESULT Result;
 uint64_t AdcGeneration,SourceEpoch,Batch,Sequence,LastNow100ns,Deadline100ns;
 uint32_t Initialized,State,Reason,Count,Outstanding,Quarantined,CancelLatched;
} NCT_CONTEXT;
/* Init is for a new zeroed, independently admitted owner only. It cannot reset
 * cancellation/quarantine or an existing context after a failed conversion. */
int NctInit(NCT_CONTEXT *,const NCT_PROFILE *,uint64_t AdcGeneration);
void NctInvalidate(NCT_CONTEXT *,enum NCT_REASON,int Uncertain);
int NctBegin(NCT_CONTEXT *,const NCT_IDENTITY *,uint32_t BudgetMs);
int NctNext(NCT_CONTEXT *,const NCT_IDENTITY *,NCT_TICKET *);
int NctAccept(NCT_CONTEXT *,const NCT_IDENTITY *,const NCT_COMPLETION_RECORD *);
int NctFinish(NCT_CONTEXT *,const NCT_IDENTITY *);
/* Check again at consumption, retaining the oldest sample of all inputs.
 * HSI and ADC generations are distinct; I validates ADC, F validates HSI.
 * Clears only thermal evidence/temperatures on every failure. Other source,
 * watchdog and input-owner evidence must come from their actual providers. */
int NctApply(NCT_CONTEXT *,const NCT_IDENTITY *,NCC_FACTS *);
typedef struct {
 int (*Identity)(void *,NCT_IDENTITY *);
 /* Must check ticket under ADC owner lock at issue, use finite wall deadline
  * plus frozen-clock escape, retire before returning, and never retry timeout.
  * Return 0 must still describe retirement/uncertainty in the zeroed record.
  * Adapter cannot synthesize completion from a previously cached raw sample. */
 int (*Convert)(void *,const NCT_TICKET *,NCT_COMPLETION_RECORD *);
} NCT_OPS;
int NctCollect(NCT_CONTEXT *,const NCT_OPS *,void *,uint32_t BudgetMs);
#endif
