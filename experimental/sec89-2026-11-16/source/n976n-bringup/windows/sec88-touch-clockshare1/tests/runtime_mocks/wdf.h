#ifndef DEMO_WDF_RUNTIME_MOCK_H
#define DEMO_WDF_RUNTIME_MOCK_H
#include <ntddk.h>
typedef void *WDFDEVICE,*WDFKEY;
typedef struct{ULONG Count;CM_PARTIAL_RESOURCE_DESCRIPTOR Item[7];}MOCK_LIST,*WDFCMRESLIST;
static inline ULONG WdfCmResourceListGetCount(WDFCMRESLIST L){return L->Count;}
static inline PCM_PARTIAL_RESOURCE_DESCRIPTOR WdfCmResourceListGetDescriptor(WDFCMRESLIST L,ULONG I){return I<L->Count?&L->Item[I]:NULL;}
#define PLUGPLAY_REGKEY_DEVICE 1
#define KEY_SET_VALUE 2
#define KEY_QUERY_VALUE 1
#define WDF_NO_OBJECT_ATTRIBUTES NULL
static inline NTSTATUS WdfDeviceOpenRegistryKey(WDFDEVICE D,ULONG P,ULONG A,void*O,WDFKEY*K){(void)D;(void)P;(void)A;(void)O;*K=(void*)1;return 0;}
static inline NTSTATUS WdfRegistryAssignULong(WDFKEY K,UNICODE_STRING*N,ULONG V){(void)K;(void)N;(void)V;return 0;}
#define REG_BINARY 3
NTSTATUS MockRegistryAssignValue(WDFKEY,UNICODE_STRING*,ULONG,ULONG,const void*);
#define WdfRegistryAssignValue MockRegistryAssignValue
NTSTATUS MockRegistryQueryValue(WDFKEY,UNICODE_STRING*,ULONG,void*,ULONG*,ULONG*);
#define WdfRegistryQueryValue MockRegistryQueryValue
static inline void WdfRegistryClose(WDFKEY K){(void)K;}
#include "clockshare_mocks.inc"
#endif
