/* SPDX-License-Identifier: MIT
 * Exynos9825 ADC v3 transaction engine. All entry points are serialized by the
 * OS interrupt object's lock. Only Irq() is called from the ADC ISR. No GIC,
 * clock, charger or DMA access. The platform owns IRQ connection and rundown.
 */
#ifndef N976N_WINDOWS_ADC_H
#define N976N_WINDOWS_ADC_H
#include "Thermal.h"
#define NCA_BASE 0x15C40000ULL
#define NCA_CLOCKS 9U
#define NCA_FROZEN_LIMIT 20000U
enum NCA_STATE {NCA_OFF,NCA_IDLE,NCA_PENDING,NCA_DONE,NCA_QUARANTINED};
enum NCA_REASON {NCA_OK,NCA_ARGUMENT,NCA_OWNER,NCA_CONFIGURATION,NCA_CLOCK_DRIFT,
 NCA_CANCEL,NCA_DEADLINE,NCA_CLOCK_BACKWARD,NCA_CLOCK_FROZEN,NCA_IRQ_UNEXPECTED,
 NCA_IRQ_LATE,NCA_DATA,NCA_RESTORE,NCA_MASK,NCA_REPLAY,NCA_WAIT_TIMEOUT,NCA_WAIT_FAILED};
typedef struct {
 uint32_t (*Read)(void *,uint64_t);
 void (*Write)(void *,uint64_t,uint32_t);
 void (*Fence)(void *);
 uint64_t (*Now)(void *); /* monotonic, 100 ns; callable at interrupt DIRQL */
 int (*Owned)(void *); /* nonblocking; live immutable lease/claim, no WDF wait */
} NCA_OPS;
typedef struct {
 uint32_t Original[3],Clocks[NCA_CLOCKS];
 uint64_t Generation;
 /* Validated by firmware handoff consumer before calling Init. These bits
  * summarize a physical resource contract, not evidence obtained by this core. */
 uint32_t FirmwareRetired,FirmwareRestored,FirmwareIrqDetached;
} NCA_BINDING;
typedef struct {
 NCA_OPS Ops;void *Owner;NCA_BINDING Binding;
 NCT_COMPLETION_RECORD Record;
 uint64_t LastNow,LastSequence,Irqs,Unexpected,Polls;
 uint32_t Initialized,State,Reason,FirstReason,Cancelled,Quarantined;
 uint32_t Changed,MaskVerified,Restored,Frozen,MaxFrozen,ClockDrift;
} NCA_CONTEXT;
extern const uint64_t NcaClockAddresses[NCA_CLOCKS];
int NcaInit(NCA_CONTEXT *,const NCA_OPS *,void *,const NCA_BINDING *);
int NcaBegin(NCA_CONTEXT *,const NCT_TICKET *);
/* Return true only for this driver's exclusive, connected ADC interrupt.
 * Platform wrapper must not call it after MMIO rundown. No KeSetEvent here. */
void NcaIrq(NCA_CONTEXT *);
/* -1 failure; 0 still pending; 1 completed. Cancel never fabricates retirement
 * and does not abort an issued conversion: IRQ/finite deadline still decide. */
int NcaPoll(NCA_CONTEXT *,int Cancel);
/* OS wait expiry/failure cannot prove hardware retirement. Called under the
 * same IRQ lock after checking the persistent completion record once more. */
void NcaWaitFailed(NCA_CONTEXT *,int TimedOut);
int NcaRetire(NCA_CONTEXT *,NCT_COMPLETION_RECORD *);
void NcaCancel(NCA_CONTEXT *);
/* Peripheral IRQ mask only. The platform subsequently disables/disconnects
 * the interrupt and drains ISR/DPC/worker before unmapping its memory. */
int NcaDisable(NCA_CONTEXT *);
/* IRQ lock held; final live register/clock check, not a cached restore flag. */
int NcaRestoredBinding(NCA_CONTEXT *);
#endif
