/* SPDX-License-Identifier: MIT
 * ADC adapter component. Device.c may connect this only after the matching
 * v3 lease + ACPI resource admission exists. Device.c now instantiates this
 * draft adapter; a matched firmware producer and validation remain required.
 * No caller-supplied IOCTL or synthetic source epoch.
 */
#ifndef N976N_ADC_WDF_H
#define N976N_ADC_WDF_H
#include <ntddk.h>
#include <wdf.h>
#include "Adc.h"
typedef struct {
 WDFINTERRUPT Interrupt;KEVENT Completion;
 NCA_CONTEXT Engine;NCA_OPS Ops;NCA_BINDING Binding;void *Owner;
 volatile LONG Prepared,Enabled,StopRequested,Active,ReleaseReady;
 ULONG SpuriousWakes;NTSTATUS LastWait;
 /* Written only by the single PASSIVE producer before collecting a batch.
  * Observation generation, not a negotiated-current or write authorization. */
 uint64_t ObservedSourceEpoch;
} NCA_WDF;
/* Add once; framework owns the interrupt and its nonpaged context. */
NTSTATUS NcaWdfCreate(WDFDEVICE,NCA_WDF **);
/* Prepare, before IRQ enable. Caller has validated/maps exact ADC/clock/NVS
 * resources and owns their lifetime through IRQ-disable + worker join.
 * These callbacks must be resident and legal at DIRQL. No hardware here. */
NTSTATUS NcaWdfPrepare(NCA_WDF *,const NCA_OPS *,void *,const NCA_BINDING *,
 PCM_PARTIAL_RESOURCE_DESCRIPTOR,PCM_PARTIAL_RESOURCE_DESCRIPTOR);
/* Single producer only, between PostInterruptsEnabled and PreInterruptsDisabled.
 * Identity carries the bracketed source observation epoch from the producer. */
int NcaWdfIdentity(void *,NCT_IDENTITY *);
int NcaWdfConvert(void *,const NCT_TICKET *,NCT_COMPLETION_RECORD *);
/* Set stop, JOIN the producer while IRQ is enabled, then let WDF disable IRQ.
 * Returning a timeout from the join must never permit Release/unmap. */
void NcaWdfRequestStop(NCA_WDF *);
/* Release only AFTER WDF disabled IRQ and caller joined its worker. Does not
 * delete the interrupt. DPC touches only its owned event, never maps/Owner.
 * STATUS_DEVICE_HARDWARE_ERROR retains diagnostic quarantine; caller must not
 * return the firmware claim to READY. Neither success nor Active==0 proves
 * the caller's worker has actually exited. */
NTSTATUS NcaWdfRelease(NCA_WDF *);
#endif
