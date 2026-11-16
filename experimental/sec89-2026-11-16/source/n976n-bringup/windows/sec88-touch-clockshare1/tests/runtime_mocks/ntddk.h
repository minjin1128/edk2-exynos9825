/* Minimal field-level CM fixture, not the native WDK layout/ABI. */
#ifndef SEC76_MOCK_NTDDK_H
#define SEC76_MOCK_NTDDK_H
#include <stdint.h>
#include <stddef.h>
#include <string.h>
typedef uint32_t ULONG;
typedef struct { int64_t QuadPart; } LARGE_INTEGER;
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define CmResourceTypeMemory 3
#define CmResourceTypeInterrupt 2
#define CmResourceTypeConnection 132
#define CmResourceTypeMemoryLarge 7
#define CmResourceShareDeviceExclusive 1
#define CmResourceShareShared 3
#define CM_RESOURCE_CONNECTION_CLASS_SERIAL 1
#define CM_RESOURCE_CONNECTION_TYPE_SERIAL_I2C 1
#define CM_RESOURCE_INTERRUPT_LEVEL_SENSITIVE 0
#define CM_RESOURCE_INTERRUPT_LATCHED 1
#define CM_RESOURCE_INTERRUPT_MESSAGE 2
#define CM_RESOURCE_INTERRUPT_SECONDARY_INTERRUPT 0x10
#define CM_RESOURCE_INTERRUPT_WAKE_HINT 0x20
#define CM_RESOURCE_MEMORY_READ_WRITE 0
#define CM_RESOURCE_MEMORY_READ_ONLY 1
#define CM_RESOURCE_MEMORY_PREFETCHABLE 4
typedef struct {
    uint8_t Type,ShareDisposition;
    uint16_t Flags;
    union {
        struct {uint8_t Class,Type; uint16_t Reserved; uint32_t IdLowPart,IdHighPart;} Connection;
        struct {
#if defined(NT_PROCESSOR_GROUPS)
            uint16_t Level,Group;
#else
            uint32_t Level;
#endif
            uint32_t Vector;
            uint64_t Affinity;
        } Interrupt;
        struct {LARGE_INTEGER Start; uint32_t Length;} Memory;
    } u;
} CM_PARTIAL_RESOURCE_DESCRIPTOR;
#endif
#ifndef DEMO_RUNTIME_NT_MOCK_EXTRA
#define DEMO_RUNTIME_NT_MOCK_EXTRA
#include <wchar.h>
#include <stdlib.h>
typedef void VOID,*PVOID;
typedef uint8_t UCHAR,*PUCHAR,BOOLEAN;
typedef uint32_t *PULONG;
typedef int32_t LONG,NTSTATUS;
typedef int64_t LONG64,LONGLONG;
typedef uint64_t ULONGLONG;
typedef wchar_t WCHAR;
typedef LARGE_INTEGER PHYSICAL_ADDRESS;
typedef struct{const wchar_t *Buffer;}UNICODE_STRING;
typedef CM_PARTIAL_RESOURCE_DESCRIPTOR *PCM_PARTIAL_RESOURCE_DESCRIPTOR;
#define TRUE 1
#define FALSE 0
#define PAGE_READONLY 2
#define PAGE_READWRITE 4
#define PAGE_NOCACHE 0x200
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_DEVICE_NOT_READY ((NTSTATUS)0xC00000A3)
#define STATUS_DEVICE_HARDWARE_ERROR ((NTSTATUS)0xC0000483)
#define STATUS_IO_TIMEOUT ((NTSTATUS)0xC00000B5)
#define STATUS_DEVICE_DATA_ERROR ((NTSTATUS)0xC000009C)
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120)
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define KernelMode 0
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlCopyMemory(d,s,n) memcpy(d,s,n)
static inline size_t RtlCompareMemory(const void*a,const void*b,size_t n){return memcmp(a,b,n)?0:n;}
#define RTL_NUMBER_OF(a) (sizeof(a)/sizeof((a)[0]))
#define KeMemoryBarrier() MockMemoryBarrier()
void MockMemoryBarrier(void);
static inline void RtlInitUnicodeString(UNICODE_STRING*n,const wchar_t*s){n->Buffer=s;}
static inline PVOID InterlockedCompareExchangePointer(PVOID volatile*d,PVOID e,PVOID c){PVOID o=*d;if(o==c)*d=e;return o;}
static inline LONG64 InterlockedCompareExchange64(volatile LONG64*d,LONG64 e,LONG64 c){LONG64 o=*d;if(o==c)*d=e;return o;}
static inline LONG InterlockedExchange(volatile LONG*d,LONG v){LONG o=*d;*d=v;return o;}
ULONG MockReadRegister(PULONG);void MockWriteRegister(PULONG,ULONG);
#define READ_REGISTER_ULONG(p) MockReadRegister(p)
#define WRITE_REGISTER_ULONG(p,v) MockWriteRegister(p,v)
ULONGLONG KeQueryInterruptTime(void);
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG *Qpc);
NTSTATUS KeDelayExecutionThread(int,int,LARGE_INTEGER*);
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS,size_t,ULONG);
VOID MmUnmapIoSpace(PVOID,size_t);
#endif
