/* Test-only KMDF/Battc boundary. Actual Device.c is compiled, not reimplemented. */
#ifndef BAT_DEVICE_MOCKS_H
#define BAT_DEVICE_MOCKS_H
#include "../WdkBatteryStub.h"
#include <assert.h>
#include <stdlib.h>
#include <stddef.h>
#include <wchar.h>
typedef void VOID; typedef unsigned char BOOLEAN,*PUCHAR; typedef uint16_t USHORT;
typedef int64_t LONGLONG; typedef uintptr_t ULONG_PTR; typedef uint64_t ULONGLONG; typedef size_t SIZE_T; typedef void *HANDLE;
typedef struct {int64_t QuadPart;} LARGE_INTEGER,PHYSICAL_ADDRESS;
typedef struct {USHORT Length,MaximumLength;void *Buffer;} UNICODE_STRING,*PUNICODE_STRING;
typedef struct {int Signaled;} KEVENT;
typedef struct {unsigned Flags;} OBJECT_ATTRIBUTES;
typedef struct {unsigned Dummy;} DRIVER_OBJECT,*PDRIVER_OBJECT;
typedef struct {void *Wdf;} DEVICE_OBJECT,*PDEVICE_OBJECT;
typedef struct {struct {struct {ULONG IoControlCode,InputBufferLength,OutputBufferLength;} DeviceIoControl;} Parameters;} IO_STACK_LOCATION,*PIO_STACK_LOCATION;
typedef struct {struct {NTSTATUS Status;SIZE_T Information;} IoStatus;unsigned Completed,Skipped,Forwarded;IO_STACK_LOCATION Stack;struct{void *SystemBuffer;}AssociatedIrp;} IRP,*PIRP;
static inline PIO_STACK_LOCATION IoGetCurrentIrpStackLocation(PIRP irp){return &irp->Stack;}
#define TRUE 1
#define FALSE 0
#define MAXULONG UINT32_MAX
#define PASSIVE_LEVEL 0
#define PAGE_READWRITE 4
#define PAGE_READONLY 2
#define PAGE_NOCACHE 0x200
#define IO_NO_INCREMENT 0
#define Executive 0
#define KernelMode 0
#define NotificationEvent 0
#define OBJ_KERNEL_HANDLE 0x200
#define SYNCHRONIZE 0x100000
#define IRP_MJ_DEVICE_CONTROL 14
#define IRP_MJ_SYSTEM_CONTROL 23
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3)
#define STATUS_DEVICE_HARDWARE_ERROR ((NTSTATUS)0xC0000185)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184)
#define STATUS_WMI_GUID_NOT_FOUND ((NTSTATUS)0xC0000295)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define FIELD_OFFSET(t,f) offsetof(t,f)
#define KeMemoryBarrier() ((void)0)
#define InitializeObjectAttributes(o,n,f,r,s) do{(void)(n);(void)(r);(void)(s);(o)->Flags=(f);}while(0)
static inline SIZE_T RtlCompareMemory(const void*a,const void*b,SIZE_T n){SIZE_T i;for(i=0;i<n&&((const UCHAR*)a)[i]==((const UCHAR*)b)[i];i++){}return i;}
static inline LONG InterlockedCompareExchange(volatile LONG*p,LONG n,LONG old){LONG v=*p;if(v==old)*p=n;return v;}
static inline LONG InterlockedExchange(volatile LONG*p,LONG n){LONG v=*p;*p=n;return v;}
static inline void RtlInitUnicodeString(PUNICODE_STRING s,const wchar_t*t){s->Buffer=(void*)t;s->Length=(USHORT)(wcslen(t)*2);s->MaximumLength=s->Length+2;}
static inline void KeInitializeEvent(KEVENT*e,int t,int s){(void)t;e->Signaled=s;}
static inline void KeClearEvent(KEVENT*e){e->Signaled=0;}
static inline int KeSetEvent(KEVENT*e,int p,int w){(void)p;(void)w;e->Signaled=1;return 0;}
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG*);
LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*);
void KeStallExecutionProcessor(ULONG);
NTSTATUS KeWaitForSingleObject(void*,int,int,int,LARGE_INTEGER*);
NTSTATUS PsCreateSystemThread(HANDLE*,ULONG,OBJECT_ATTRIBUTES*,void*,void*,void(*)(void*),void*);
NTSTATUS ZwWaitForSingleObject(HANDLE,int,LARGE_INTEGER*);
_Noreturn void KeBugCheckEx(ULONG,ULONG_PTR,ULONG_PTR,ULONG_PTR,ULONG_PTR);
NTSTATUS ZwClose(HANDLE);
void PsTerminateSystemThread(NTSTATUS);
void *MmMapIoSpaceEx(PHYSICAL_ADDRESS,SIZE_T,ULONG);
void MmUnmapIoSpace(void*,SIZE_T);
ULONG READ_REGISTER_ULONG(volatile ULONG*);
void WRITE_REGISTER_ULONG(volatile ULONG*,ULONG);
unsigned KeGetCurrentIrql(void);
void IoCompleteRequest(PIRP,int);
static inline void IoSkipCurrentIrpStackLocation(PIRP i){i->Skipped++;}

enum {CmResourceTypePort=1,CmResourceTypeInterrupt=2,CmResourceTypeMemory=3,CmResourceTypeMemoryLarge=7};
enum {CmResourceShareDeviceExclusive=1,CmResourceShareShared=3};
#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0
#define CM_RESOURCE_MEMORY_READ_WRITE 0
#define CM_RESOURCE_MEMORY_READ_ONLY 1
#define CM_RESOURCE_MEMORY_WRITE_ONLY 2
typedef struct {UCHAR Type,ShareDisposition;USHORT Flags;union{struct{PHYSICAL_ADDRESS Start;ULONG Length;}Memory;struct{ULONG Level,Vector;uintptr_t Affinity;}Interrupt;}u;} CM_PARTIAL_RESOURCE_DESCRIPTOR,*PCM_PARTIAL_RESOURCE_DESCRIPTOR;
typedef struct {ULONG Count;CM_PARTIAL_RESOURCE_DESCRIPTOR Items[32];} MOCK_CM,*WDFCMRESLIST;
typedef struct {unsigned Held;} MOCK_LOCK,*WDFWAITLOCK;
typedef struct {void*Context;DEVICE_OBJECT Object;} MOCK_DEVICE,*WDFDEVICE;
typedef MOCK_DEVICE *WDFINTERRUPT; typedef void *WDFCONTEXT,*WDFOBJECT;
typedef void*WDFDRIVER;typedef void*WDFQUEUE;
typedef struct {unsigned Completed;NTSTATUS Status;} MOCK_REQUEST,*WDFREQUEST;
typedef unsigned WDF_POWER_DEVICE_STATE;
typedef struct MOCK_INIT*PWDFDEVICE_INIT;
typedef NTSTATUS DRIVER_INITIALIZE(PDRIVER_OBJECT,PUNICODE_STRING);
typedef NTSTATUS EVT_WDF_DRIVER_DEVICE_ADD(WDFDRIVER,PWDFDEVICE_INIT);
typedef NTSTATUS EVT_WDF_DEVICE_PREPARE_HARDWARE(WDFDEVICE,WDFCMRESLIST,WDFCMRESLIST);
typedef NTSTATUS EVT_WDF_DEVICE_RELEASE_HARDWARE(WDFDEVICE,WDFCMRESLIST);
typedef NTSTATUS EVT_WDF_DEVICE_D0_ENTRY(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef NTSTATUS EVT_WDF_DEVICE_D0_EXIT(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef NTSTATUS EVT_WDF_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef NTSTATUS EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED(WDFDEVICE,WDF_POWER_DEVICE_STATE);
typedef NTSTATUS EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT(WDFDEVICE);
typedef VOID EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP(WDFDEVICE);
typedef NTSTATUS EVT_WDFDEVICE_WDM_IRP_PREPROCESS(WDFDEVICE,PIRP);
typedef VOID EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL(WDFQUEUE,WDFREQUEST,size_t,size_t,ULONG);
typedef struct {void*ParentObject;SIZE_T ContextSize;unsigned ExecutionLevel,SynchronizationScope;} WDF_OBJECT_ATTRIBUTES;
#define WDF_DECLARE_CONTEXT_TYPE_WITH_NAME(t,n) static inline t*n(WDFDEVICE d){return (t*)d->Context;}
#define WDF_OBJECT_ATTRIBUTES_INIT(a) memset((a),0,sizeof(*(a)))
#define WDF_OBJECT_ATTRIBUTES_INIT_CONTEXT_TYPE(a,t) do{WDF_OBJECT_ATTRIBUTES_INIT(a);(a)->ContextSize=sizeof(t);}while(0)
#define WdfExecutionLevelPassive 1
#define WdfSynchronizationScopeNone 0
#define WDF_NO_OBJECT_ATTRIBUTES NULL
#define WDF_NO_HANDLE NULL
#define WdfIoQueueDispatchParallel 1
#define WdfFalse 0
#define WdfTrue 1
#define WdfUseDefault 2
typedef struct {EVT_WDF_DEVICE_PREPARE_HARDWARE*EvtDevicePrepareHardware;EVT_WDF_DEVICE_RELEASE_HARDWARE*EvtDeviceReleaseHardware;EVT_WDF_DEVICE_D0_ENTRY*EvtDeviceD0Entry;EVT_WDF_DEVICE_D0_EXIT*EvtDeviceD0Exit;EVT_WDF_DEVICE_D0_ENTRY_POST_INTERRUPTS_ENABLED*EvtDeviceD0EntryPostInterruptsEnabled;EVT_WDF_DEVICE_D0_EXIT_PRE_INTERRUPTS_DISABLED*EvtDeviceD0ExitPreInterruptsDisabled;EVT_WDF_DEVICE_SELF_MANAGED_IO_INIT*EvtDeviceSelfManagedIoInit;EVT_WDF_DEVICE_SELF_MANAGED_IO_CLEANUP*EvtDeviceSelfManagedIoCleanup;} WDF_PNPPOWER_EVENT_CALLBACKS;
#define WDF_PNPPOWER_EVENT_CALLBACKS_INIT(a) memset((a),0,sizeof(*(a)))
typedef struct {EVT_WDF_IO_QUEUE_IO_DEVICE_CONTROL*EvtIoDeviceControl;unsigned PowerManaged;} WDF_IO_QUEUE_CONFIG;
#define WDF_IO_QUEUE_CONFIG_INIT_DEFAULT_QUEUE(a,k) do{(void)(k);memset((a),0,sizeof(*(a)));(a)->PowerManaged=WdfUseDefault;}while(0)
typedef struct {EVT_WDF_DRIVER_DEVICE_ADD*EvtDeviceAdd;} WDF_DRIVER_CONFIG;
#define WDF_DRIVER_CONFIG_INIT(a,f) ((a)->EvtDeviceAdd=(f))
static inline ULONG WdfCmResourceListGetCount(WDFCMRESLIST r){return r->Count;}
static inline PCM_PARTIAL_RESOURCE_DESCRIPTOR WdfCmResourceListGetDescriptor(WDFCMRESLIST r,ULONG n){return n<r->Count?&r->Items[n]:NULL;}
NTSTATUS WdfWaitLockAcquire(WDFWAITLOCK,LONGLONG*);void WdfWaitLockRelease(WDFWAITLOCK);
NTSTATUS WdfWaitLockCreate(WDF_OBJECT_ATTRIBUTES*,WDFWAITLOCK*);
NTSTATUS WdfDeviceCreate(PWDFDEVICE_INIT*,WDF_OBJECT_ATTRIBUTES*,WDFDEVICE*);
NTSTATUS WdfDeviceWdmDispatchPreprocessedIrp(WDFDEVICE,PIRP);
NTSTATUS WdfDeviceInitAssignWdmIrpPreprocessCallback(PWDFDEVICE_INIT,EVT_WDFDEVICE_WDM_IRP_PREPROCESS*,UCHAR,void*,ULONG);
void WdfDeviceInitSetPnpPowerEventCallbacks(PWDFDEVICE_INIT,WDF_PNPPOWER_EVENT_CALLBACKS*);
static inline PDEVICE_OBJECT WdfDeviceWdmGetDeviceObject(WDFDEVICE d){return &d->Object;}
static inline PDEVICE_OBJECT WdfDeviceWdmGetPhysicalDevice(WDFDEVICE d){return &d->Object;}
static inline WDFDEVICE WdfWdmDeviceGetWdfDeviceHandle(PDEVICE_OBJECT o){return o->Wdf;}
static inline const wchar_t*WdfDriverGetRegistryPath(WDFDRIVER d){(void)d;return L"\\Registry\\Machine\\MockBattery";}
NTSTATUS WdfIoQueueCreate(WDFDEVICE,WDF_IO_QUEUE_CONFIG*,WDF_OBJECT_ATTRIBUTES*,void*);
static inline void WdfRequestComplete(WDFREQUEST r,NTSTATUS s){r->Completed++;r->Status=s;}
static inline NTSTATUS WdfDriverCreate(PDRIVER_OBJECT o,PUNICODE_STRING p,WDF_OBJECT_ATTRIBUTES*a,WDF_DRIVER_CONFIG*c,void*h){(void)o;(void)p;(void)a;(void)c;(void)h;return 0;}

typedef struct{UCHAR Option,Type,ShareDisposition,Spare1;USHORT Flags,Spare2;union{struct{ULONG Length,Alignment;PHYSICAL_ADDRESS MinimumAddress,MaximumAddress;}Memory;}u;}IO_RESOURCE_DESCRIPTOR,*PIO_RESOURCE_DESCRIPTOR;
typedef struct{ULONG Count;IO_RESOURCE_DESCRIPTOR Items[32];}MOCK_REQ_LIST,*WDFIORESLIST;
typedef struct{ULONG Count;MOCK_REQ_LIST Lists[2];}MOCK_REQ,*WDFIORESREQLIST;
typedef NTSTATUS EVT_WDF_DEVICE_FILTER_RESOURCE_REQUIREMENTS(WDFDEVICE,WDFIORESREQLIST);
typedef struct{EVT_WDF_DEVICE_FILTER_RESOURCE_REQUIREMENTS*EvtDeviceFilterRemoveResourceRequirements;}WDF_FDO_EVENT_CALLBACKS;
struct MOCK_INIT{WDF_FDO_EVENT_CALLBACKS Fdo;WDF_PNPPOWER_EVENT_CALLBACKS Pnp;EVT_WDFDEVICE_WDM_IRP_PREPROCESS*Preprocess[24];};
#define WDF_FDO_EVENT_CALLBACKS_INIT(a) memset((a),0,sizeof(*(a)))
static inline void WdfFdoInitSetEventCallbacks(PWDFDEVICE_INIT i,WDF_FDO_EVENT_CALLBACKS*c){i->Fdo=*c;}
static inline ULONG WdfIoResourceRequirementsListGetCount(WDFIORESREQLIST r){return r->Count;}
static inline WDFIORESLIST WdfIoResourceRequirementsListGetIoResList(WDFIORESREQLIST r,ULONG i){return i<r->Count?&r->Lists[i]:NULL;}
static inline ULONG WdfIoResourceListGetCount(WDFIORESLIST r){return r->Count;}
static inline PIO_RESOURCE_DESCRIPTOR WdfIoResourceListGetDescriptor(WDFIORESLIST r,ULONG i){return i<r->Count?&r->Items[i]:NULL;}
static inline void WdfIoResourceListUpdateDescriptor(WDFIORESLIST r,PIO_RESOURCE_DESCRIPTOR d,ULONG i){r->Items[i]=*d;}
static inline ULONGLONG RtlIoDecodeMemIoResource(PIO_RESOURCE_DESCRIPTOR d,ULONGLONG*a,ULONGLONG*lo,ULONGLONG*hi){if(a)*a=d->u.Memory.Alignment;if(lo)*lo=d->u.Memory.MinimumAddress.QuadPart;if(hi)*hi=d->u.Memory.MaximumAddress.QuadPart;return d->u.Memory.Length;}

#define BATTERY_CLASS_MAJOR_VERSION 1
#define BATTERY_CLASS_MINOR_VERSION_1 1
typedef struct {ULONG MajorVersion,MinorVersion;PVOID Context;BCLASS_QUERY_TAG_CALLBACK*QueryTag;BCLASS_QUERY_INFORMATION_CALLBACK*QueryInformation;BCLASS_SET_INFORMATION_CALLBACK*SetInformation;BCLASS_QUERY_STATUS_CALLBACK*QueryStatus;BCLASS_SET_STATUS_NOTIFY_CALLBACK*SetStatusNotify;BCLASS_DISABLE_STATUS_NOTIFY_CALLBACK*DisableStatusNotify;PVOID Pdo,DeviceName;PVOID Fdo;}BATTERY_MINIPORT_INFO_V1_1;
typedef enum {IrpProcessed,IrpNotCompleted,IrpForward,IrpNotWmi}SYSCTL_IRP_DISPOSITION;
typedef struct {NTSTATUS(*QueryWmiRegInfo)(PDEVICE_OBJECT,PULONG,PUNICODE_STRING,PUNICODE_STRING*,PUNICODE_STRING,PDEVICE_OBJECT*);NTSTATUS(*QueryWmiDataBlock)(PDEVICE_OBJECT,PIRP,ULONG,ULONG,ULONG,PULONG,ULONG,PUCHAR);}WMILIB_CONTEXT;
#define WMIREG_FLAG_INSTANCE_PDO 0x20
#define WMIREG_ACTION_REGISTER 1
#define WMIREG_ACTION_DEREGISTER 2
NTSTATUS BatteryClassInitializeDevice(PBATTERY_MINIPORT_INFO,PVOID*);
void BatteryClassStatusNotify(PVOID);void BatteryClassUnload(PVOID);
NTSTATUS BatteryClassIoctl(PVOID,PIRP);
NTSTATUS BatteryClassSystemControl(PVOID,WMILIB_CONTEXT*,PDEVICE_OBJECT,PIRP,SYSCTL_IRP_DISPOSITION*);
NTSTATUS BatteryClassQueryWmiDataBlock(PVOID,PDEVICE_OBJECT,PIRP,ULONG,PULONG,ULONG,PUCHAR);
NTSTATUS WmiCompleteRequest(PDEVICE_OBJECT,PIRP,NTSTATUS,ULONG,int);
NTSTATUS IoWMIRegistrationControl(PDEVICE_OBJECT,ULONG);
typedef BOOLEAN EVT_WDF_INTERRUPT_ISR(WDFINTERRUPT,ULONG);
typedef VOID EVT_WDF_INTERRUPT_DPC(WDFINTERRUPT,WDFOBJECT);
typedef NTSTATUS EVT_WDF_INTERRUPT_ENABLE(WDFINTERRUPT,WDFDEVICE);
typedef NTSTATUS EVT_WDF_INTERRUPT_DISABLE(WDFINTERRUPT,WDFDEVICE);
typedef BOOLEAN EVT_WDF_INTERRUPT_SYNCHRONIZE(WDFINTERRUPT,WDFCONTEXT);
typedef struct {EVT_WDF_INTERRUPT_ISR *Isr;EVT_WDF_INTERRUPT_DPC *Dpc;EVT_WDF_INTERRUPT_ENABLE *EvtInterruptEnable;EVT_WDF_INTERRUPT_DISABLE *EvtInterruptDisable;int PassiveHandling,AutomaticSerialization,ShareVector;} WDF_INTERRUPT_CONFIG;
#define WDF_INTERRUPT_CONFIG_INIT(C,I,D) do{memset(C,0,sizeof(*(C)));(C)->Isr=I;(C)->Dpc=D;}while(0)
NTSTATUS WdfInterruptCreate(WDFDEVICE,WDF_INTERRUPT_CONFIG *,WDF_OBJECT_ATTRIBUTES *,WDFINTERRUPT *);
BOOLEAN WdfInterruptQueueDpcForIsr(WDFINTERRUPT);
BOOLEAN WdfInterruptSynchronize(WDFINTERRUPT,EVT_WDF_INTERRUPT_SYNCHRONIZE *,WDFCONTEXT);
#endif
