/* Bounded list-access fixture; no WDF object creation or scheduling. */
#ifndef SEC76_MOCK_WDF_H
#define SEC76_MOCK_WDF_H
#include "ntddk.h"
typedef struct {
    ULONG Count,GetCalls;
    const CM_PARTIAL_RESOURCE_DESCRIPTOR *Descriptors[8];
} MOCK_CM_LIST,*WDFCMRESLIST;
static inline ULONG WdfCmResourceListGetCount(WDFCMRESLIST List) { return List->Count; }
static inline const CM_PARTIAL_RESOURCE_DESCRIPTOR *WdfCmResourceListGetDescriptor(WDFCMRESLIST List,ULONG Index) {
    List->GetCalls++;
    if(Index>=List->Count||Index>=8)return NULL;
    return List->Descriptors[Index];
}
#endif
