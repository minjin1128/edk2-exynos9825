/* Test-only WDF resource list operations, not the native WDK object ABI. */
#ifndef N976N_CLOCKSHARE_MOCKS
#define N976N_CLOCKSHARE_MOCKS
#include <assert.h>
typedef uint16_t USHORT;
#ifndef _Use_decl_annotations_
#define _Use_decl_annotations_
#endif
typedef struct {
  UCHAR Option, Type, ShareDisposition, Spare1;
  USHORT Flags, Spare2;
  union {struct {ULONG Length, Alignment;PHYSICAL_ADDRESS MinimumAddress,MaximumAddress;} Memory;
         ULONGLONG Reserved[4];} u;
} IO_RESOURCE_DESCRIPTOR,*PIO_RESOURCE_DESCRIPTOR;
typedef struct {
  ULONG Count, UpdatedMask, Updates;
  IO_RESOURCE_DESCRIPTOR Items[16];
} MOCK_REQ_LIST,*WDFIORESLIST;
typedef struct {ULONG Count;MOCK_REQ_LIST Lists[4];} MOCK_REQUIREMENTS,*WDFIORESREQLIST;
typedef NTSTATUS EVT_WDF_DEVICE_FILTER_RESOURCE_REQUIREMENTS(WDFDEVICE,WDFIORESREQLIST);
typedef struct {
  ULONG Size;
  EVT_WDF_DEVICE_FILTER_RESOURCE_REQUIREMENTS *EvtDeviceFilterRemoveResourceRequirements;
} WDF_FDO_EVENT_CALLBACKS;
typedef struct {WDF_FDO_EVENT_CALLBACKS Callbacks;ULONG Registered;} MOCK_DEVICE_INIT,*PWDFDEVICE_INIT;
static inline void WDF_FDO_EVENT_CALLBACKS_INIT(WDF_FDO_EVENT_CALLBACKS *C)
{memset(C,0,sizeof(*C));C->Size=sizeof(*C);}
static inline void WdfFdoInitSetEventCallbacks(PWDFDEVICE_INIT D,WDF_FDO_EVENT_CALLBACKS *C)
{assert(D&&C&&C->Size==sizeof(*C));D->Callbacks=*C;++D->Registered;}
static inline ULONG WdfIoResourceRequirementsListGetCount(WDFIORESREQLIST R)
{return R->Count;}
static inline WDFIORESLIST WdfIoResourceRequirementsListGetIoResList(WDFIORESREQLIST R,ULONG I)
{return I<R->Count&&I<4?&R->Lists[I]:NULL;}
static inline ULONG WdfIoResourceListGetCount(WDFIORESLIST L){return L->Count;}
static inline PIO_RESOURCE_DESCRIPTOR WdfIoResourceListGetDescriptor(WDFIORESLIST L,ULONG I)
{return I<L->Count&&I<16?&L->Items[I]:NULL;}
static inline VOID WdfIoResourceListUpdateDescriptor(WDFIORESLIST L,PIO_RESOURCE_DESCRIPTOR D,ULONG I)
{assert(L&&D&&I<L->Count&&I<16);L->Items[I]=*D;++L->Updates;L->UpdatedMask|=1U<<I;}
static inline ULONGLONG RtlIoDecodeMemIoResource(PIO_RESOURCE_DESCRIPTOR D,
  ULONGLONG *Alignment,ULONGLONG *Minimum,ULONGLONG *Maximum)
{assert(D&&D->Type==CmResourceTypeMemory);if(Alignment)*Alignment=D->u.Memory.Alignment;
 if(Minimum)*Minimum=(ULONGLONG)D->u.Memory.MinimumAddress.QuadPart;
 if(Maximum)*Maximum=(ULONGLONG)D->u.Memory.MaximumAddress.QuadPart;return D->u.Memory.Length;}
#endif
