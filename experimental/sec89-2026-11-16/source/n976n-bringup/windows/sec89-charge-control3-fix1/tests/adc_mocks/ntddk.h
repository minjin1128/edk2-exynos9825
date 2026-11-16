#ifndef NCA_TEST_NTDDK_H
#define NCA_TEST_NTDDK_H
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
typedef void VOID,*PVOID,*WDFCONTEXT,*WDFOBJECT,*WDFDEVICE,*WDFINTERRUPT;
typedef int32_t LONG,NTSTATUS;typedef uint32_t ULONG;typedef unsigned char BOOLEAN;
typedef int64_t LONGLONG;typedef struct {LONGLONG QuadPart;} LARGE_INTEGER;
typedef struct {int Set;} KEVENT;
typedef struct {unsigned char Type,ShareDisposition;unsigned short Flags;union {struct{ULONG Level,Vector;uintptr_t Affinity;} Interrupt;} u;} CM_PARTIAL_RESOURCE_DESCRIPTOR,*PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#define TRUE 1
#define FALSE 0
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_TIMEOUT ((NTSTATUS)0x102)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182)
#define STATUS_DEVICE_HARDWARE_ERROR ((NTSTATUS)0xC0000185)
#define NT_SUCCESS(S) ((S)>=0)
#define PASSIVE_LEVEL 0
#define NotificationEvent 0
#define IO_NO_INCREMENT 0
#define Executive 0
#define KernelMode 0
#define CmResourceTypeInterrupt 2
#define CmResourceShareDeviceExclusive 1
#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0
#define UNREFERENCED_PARAMETER(X) ((void)(X))
#define RtlZeroMemory(P,N) memset(P,0,N)
LONG InterlockedCompareExchange(volatile LONG *,LONG,LONG);
LONG InterlockedExchange(volatile LONG *,LONG);
unsigned KeGetCurrentIrql(void);
void KeInitializeEvent(KEVENT *,int,int);
void KeClearEvent(KEVENT *);
LONG KeSetEvent(KEVENT *,int,int);
NTSTATUS KeWaitForSingleObject(KEVENT *,int,int,int,LARGE_INTEGER *);
#endif
