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
