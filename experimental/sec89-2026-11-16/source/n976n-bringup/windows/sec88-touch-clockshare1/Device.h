/*++

Copyright (C) Microsoft Corporation, All Rights Reserved

Module Name:

    vhidmini.h

Abstract:

    This module contains the type definitions for the driver

Environment:

    Windows Driver Framework (WDF)

--*/

#ifdef _KERNEL_MODE
#include <ntddk.h>
#else
#include <windows.h>
#endif

#include <ntddk.h>
#include <wdm.h>
#include <ntstrsafe.h>

#include <wdf.h>

#include <hidport.h>  // located in $(DDK_INC_PATH)/wdm
#include <spb.h>

#include "common.h"
#include "N976nResources.h"
#include "N976nDemoRuntime.h"

#define RESHUB_USE_HELPER_ROUTINES
#include "reshub.h"

/* SEC73 modification, 2026-10-22: inherited direct GPIO mapping removed.
 * N976N power, interrupt ownership and SPB transport are not ported. */
#define S6SY761_MAX_CONTACTS               10
#define S6SY761_INPUT_REPORT_QUEUE_DEPTH   64

typedef UCHAR HID_REPORT_DESCRIPTOR, * PHID_REPORT_DESCRIPTOR;

typedef struct __declspec(align(2)) _S6SY761_INPUT_POINT
{
    BYTE  FingerState;
    BYTE  ContactIdentifier;
    BYTE  XLow;
    BYTE  XHigh;
    BYTE  YLow;
    BYTE  YHigh;
} inputpoint;

typedef struct __declspec(align(2)) _S6SY761_INPUT_REPORT
{
    BYTE  reportId;
    BYTE  points[S6SY761_MAX_CONTACTS * sizeof(inputpoint)];
    BYTE  DIG_TouchScreenScanTimeLow;
    BYTE  DIG_TouchScreenScanTimeHigh;
    BYTE  DIG_TouchScreenContactCount;
} inputReport54_t;

C_ASSERT(sizeof(inputpoint) == 6);
C_ASSERT(sizeof(inputReport54_t) == 64);

typedef struct _S6SY761_CONTACT_STATE
{
    BOOLEAN Active;
    BOOLEAN ReleasePending;
    USHORT  X;
    USHORT  Y;
} S6SY761_CONTACT_STATE;

/* SEC73 FIX1: state committed for successful HID request completion.
 * This is distinct from the newest received sensor sample. */
typedef struct _S6SY761_COMMITTED_CONTACT_STATE
{
    BOOLEAN Active;
    USHORT  X;
    USHORT  Y;
} S6SY761_COMMITTED_CONTACT_STATE;

DRIVER_INITIALIZE                   DriverEntry;
EVT_WDF_DRIVER_DEVICE_ADD           EvtDeviceAdd;
EVT_WDF_TIMER                       EvtTimerFunc;
EVT_WDF_TIMER                       TouchHoldTimerFunc;
EVT_WDF_TIMER                       N976nPollTimer;

#define S6SY761_HOLD_REPEAT_MS              20
EVT_WDF_OBJECT_CONTEXT_CLEANUP      EvtDriverCleanup;

EVT_WDF_DEVICE_PREPARE_HARDWARE      OnPrepareHardware;
EVT_WDF_DEVICE_RELEASE_HARDWARE      OnReleaseHardware;
EVT_WDF_DEVICE_D0_ENTRY              OnD0Entry;
EVT_WDF_DEVICE_D0_EXIT               OnD0Exit;

typedef struct _DEVICE_CONTEXT
{
    WDFDEVICE               Device;
    N976N_DEMO_RUNTIME      Runtime;
    WDFTIMER               PollTimer;
    ULONGLONG              LastDiagnosticTick;
    WDFQUEUE                DefaultQueue;
    WDFQUEUE                ManualQueue;
    HID_DEVICE_ATTRIBUTES   HidDeviceAttributes;
    BYTE                    DeviceData;
    HID_DESCRIPTOR          HidDescriptor;
    PHID_REPORT_DESCRIPTOR  ReportDescriptor;
    BOOLEAN                 ReadReportDescFromRegistry;

    LARGE_INTEGER           PeripheralId;
    /* SEC76: diagnostic metadata only. Never copied into PeripheralId/IRQ. */
    N976N_TOUCH_RESOURCE_PLAN ResourceDiagnostic;
    N976N_RESOURCE_RESULT   ResourceDiagnosticResult;
    WDFINTERRUPT            Interrupt;
    WDFIOTARGET             SpbController;
    WDFWAITLOCK             InputLock;
    S6SY761_CONTACT_STATE   Contacts[S6SY761_MAX_CONTACTS];
    S6SY761_COMMITTED_CONTACT_STATE CommittedContacts[S6SY761_MAX_CONTACTS];
    inputReport54_t         RecoveryReport;
    BOOLEAN                 RecoveryPending;
    inputReport54_t         InputReports[S6SY761_INPUT_REPORT_QUEUE_DEPTH];
    BOOLEAN                 InputReportIsMove[S6SY761_INPUT_REPORT_QUEUE_DEPTH];
    ULONG                   InputReportHead;
    ULONG                   InputReportTail;
    ULONG                   InputReportCount;
    volatile LONG           InputDrainActive;
    BOOLEAN                 InputStopping;
    BOOLEAN                 InputResetPending;
    volatile LONG           InputInterruptCount;
    volatile LONG           InputI2cErrorCount;
    volatile LONG           InputOverflowCount;
    volatile LONG           InputQueueFlushCount;
    volatile LONG           InputReportCoalesceCount;
    volatile LONG           InputReportCompleteCount;

    // m12 right-click (notes/m12-touch.md, s10etouchlog run m16-3): the S6SY761 only raises events when a
    // finger moves; Windows lifts a pointer ~200 ms after the last report, so a held finger became a burst
    // of taps and press-and-hold never fired. While any contact is down this one-shot passive timer
    // repeats the current report every S6SY761_HOLD_REPEAT_MS and re-arms itself.
    WDFTIMER                HoldTimer;
    volatile LONG           HoldTimerArmed;
    volatile LONG           HoldRepeatCount;

    PVOID PoFxPowerSettingCallbackHandle1;
    PVOID PoFxPowerSettingCallbackHandle2;

} DEVICE_CONTEXT, * PDEVICE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(DEVICE_CONTEXT, GetDeviceContext);

typedef struct _QUEUE_CONTEXT
{
    WDFQUEUE                Queue;
    PDEVICE_CONTEXT         DeviceContext;
    UCHAR                   OutputReport;

} QUEUE_CONTEXT, * PQUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(QUEUE_CONTEXT, GetQueueContext);

NTSTATUS
QueueCreate(
    _In_  WDFDEVICE         Device,
    _Out_ WDFQUEUE* Queue
);

typedef struct _MANUAL_QUEUE_CONTEXT
{
    WDFQUEUE                Queue;
    PDEVICE_CONTEXT         DeviceContext;
    WDFTIMER                Timer;

} MANUAL_QUEUE_CONTEXT, * PMANUAL_QUEUE_CONTEXT;

WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(MANUAL_QUEUE_CONTEXT, GetManualQueueContext);

NTSTATUS
ManualQueueCreate(
    _In_  WDFDEVICE         Device,
    _Out_ WDFQUEUE* Queue
);

NTSTATUS
ReadReport(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request,
    _Always_(_Out_)
    BOOLEAN* CompleteRequest
);

NTSTATUS
WriteReport(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request
);

NTSTATUS
GetFeature(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request
);

NTSTATUS
SetFeature(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request
);

NTSTATUS
GetInputReport(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request
);

NTSTATUS
SetOutputReport(
    _In_  PQUEUE_CONTEXT    QueueContext,
    _In_  WDFREQUEST        Request
);

NTSTATUS
GetString(
    _In_  WDFREQUEST        Request
);

NTSTATUS
GetIndexedString(
    _In_  WDFREQUEST        Request
);

NTSTATUS
GetStringId(
    _In_  WDFREQUEST        Request,
    _Out_ ULONG* StringId,
    _Out_ ULONG* LanguageId
);

NTSTATUS
RequestCopyFromBuffer(
    _In_  WDFREQUEST        Request,
    _In_  PVOID             SourceBuffer,
    _When_(NumBytesToCopyFrom == 0, __drv_reportError(NumBytesToCopyFrom cannot be zero))
    _In_  size_t            NumBytesToCopyFrom
);

NTSTATUS
RequestGetHidXferPacket_ToReadFromDevice(
    _In_  WDFREQUEST        Request,
    _Out_ HID_XFER_PACKET* Packet
);

NTSTATUS
RequestGetHidXferPacket_ToWriteToDevice(
    _In_  WDFREQUEST        Request,
    _Out_ HID_XFER_PACKET* Packet
);

BOOLEAN
OnInterruptIsr(
    _In_  WDFINTERRUPT FxInterrupt,
    _In_  ULONG        MessageID
);

NTSTATUS
SpbDeviceOpen(
    _In_  PDEVICE_CONTEXT  pDevice
);
VOID
SpbDeviceClose(
    _In_  PDEVICE_CONTEXT  pDevice
);
NTSTATUS
SpbDeviceWrite(
    _In_ PDEVICE_CONTEXT pDevice,
    _In_ PVOID pInputBuffer,
    _In_ size_t inputBufferLength
);
NTSTATUS
SpbDeviceWriteRead(
    _In_ PDEVICE_CONTEXT pDevice,
    _In_ PVOID pInputBuffer,
    _In_ PVOID pOutputBuffer,
    _In_ size_t inputBufferLength,
    _In_ size_t outputBufferLength
);

NTSTATUS
ReadDescriptorFromRegistry(
    WDFDEVICE Device
);
NTSTATUS
CheckRegistryForDescriptor(
    WDFDEVICE Device
);

//
// Misc definitions
//
#define CONTROL_FEATURE_REPORT_ID   0x54

//
// These are the device attributes returned by the mini driver in response
// to IOCTL_HID_GET_DEVICE_ATTRIBUTES.
//
#define HIDMINI_PID             0xFEED
#define HIDMINI_VID             0xDEED
#define HIDMINI_VERSION         0x0101
