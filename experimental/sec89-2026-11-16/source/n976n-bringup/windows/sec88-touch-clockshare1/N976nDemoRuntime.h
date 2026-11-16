/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef N976N_DEMO_RUNTIME_H
#define N976N_DEMO_RUNTIME_H
#include <ntddk.h>
#include <wdf.h>
#include "N976nDemoContract.h"
#include "N976nDemoLifecycle.h"
typedef struct {
    WDFDEVICE Device;
    PUCHAR Map[N976N_DEMO_MAP_COUNT];
    ULONG Bytes[N976N_DEMO_MAP_COUNT];
    N976N_TOUCH_HANDOFF Handoff;
    N976N_HSI_LEASE Lease;
    N976N_HSI_IO Io;
    N976N_HSI_RESULT Last;
    N976N_DEMO_DIAGNOSTIC Diagnostic;
    volatile LONG StopRequested;
    ULONG Claimed, Mapped, Quarantined, SenseAttempted, FunctionSaved, FunctionChanged;
    ULONG FunctionBefore, FunctionEnabled, Id, Polls, Events, LastX, LastY, LastAction;
    ULONG Stage, Status, CleanupStatus, DiagnosticRecorded,CurrentCommand,HsiCurrent,LifeCanPublish;
    N976N_STARTUP_EVIDENCE Startup;
    N976N_LIFECYCLE_STATE EventFirst;
    UCHAR EventBatch[31][16]; /* Single passive producer owns all496 bytes. */
    N976N_FIRST_RECOVERY FirstRead;
    N976N_DEMO_LIFECYCLE Lifecycle;
} N976N_DEMO_RUNTIME;
/* Runtime must start in the zero-initialized WDF device context. */
NTSTATUS N976nDemoPrepare(N976N_DEMO_RUNTIME *R,WDFDEVICE Device,WDFCMRESLIST Raw,WDFCMRESLIST Translated);
NTSTATUS N976nDemoStart(N976N_DEMO_RUNTIME *R);
NTSTATUS N976nDemoEventReady(N976N_DEMO_RUNTIME *R,BOOLEAN *Ready);
NTSTATUS N976nDemoReadEvent(N976N_DEMO_RUNTIME *R,UCHAR Event[16]);
NTSTATUS N976nDemoReadTail(N976N_DEMO_RUNTIME *R,ULONG Remaining);
VOID N976nDemoValidatedBatch(N976N_DEMO_RUNTIME *R);
NTSTATUS N976nDemoClearEvents(N976N_DEMO_RUNTIME *R);
NTSTATUS N976nDemoStop(N976N_DEMO_RUNTIME *R);
VOID N976nDemoRelease(N976N_DEMO_RUNTIME *R);
VOID N976nDemoRecord(N976N_DEMO_RUNTIME *R);
VOID N976nDemoCallback(N976N_DEMO_RUNTIME *R,ULONG Callback);
ULONG N976nDemoLifecycleCrc(const N976N_DEMO_LIFECYCLE *L);
#endif
