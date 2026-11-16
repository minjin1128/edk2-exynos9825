/* Test-only DDI model. Production N976nUfs.c is compiled unchanged against it. */
#ifndef SEC78_FAKE_NTDDK_H
#define SEC78_FAKE_NTDDK_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef void VOID;
typedef void *PVOID,*PDRIVER_OBJECT,*PUNICODE_STRING;
typedef char *PCHAR;
typedef unsigned char BOOLEAN,*PBOOLEAN,UCHAR;
typedef unsigned int ULONG,*PULONG;
typedef uintptr_t ULONG_PTR;
typedef int LONG,NTSTATUS;
typedef long long LONG64,LONGLONG;
typedef unsigned long long ULONGLONG;
typedef struct { LONGLONG QuadPart; } PHYSICAL_ADDRESS;
typedef PHYSICAL_ADDRESS LARGE_INTEGER;
#define KernelMode 0
NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alertable,LARGE_INTEGER *interval);
#define TRUE 1
#define FALSE 0
#define PAGE_READWRITE 4
#define PAGE_READONLY 2
#define PAGE_NOCACHE 0x200
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_PENDING ((NTSTATUS)0x103)
#define STATUS_DEVICE_CONFIGURATION_ERROR ((NTSTATUS)0xC0000182)
#define STATUS_DEVICE_BUSY ((NTSTATUS)0x80000011)
#define STATUS_IO_DEVICE_ERROR ((NTSTATUS)0xC0000185)
#define STATUS_INSUFFICIENT_RESOURCES ((NTSTATUS)0xC000009A)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120)
#define STATUS_INVALID_DEVICE_STATE ((NTSTATUS)0xC0000184)
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlCopyMemory(d,s,n) memcpy((d),(s),(n))
static inline size_t RtlCompareMemory(const void *a,const void *b,size_t n){return memcmp(a,b,n)?0:n;}
static inline LONG InterlockedExchange(volatile LONG *p,LONG n){return __atomic_exchange_n(p,n,__ATOMIC_SEQ_CST);}
static inline LONG InterlockedCompareExchange(volatile LONG *p,LONG n,LONG expected){
 __atomic_compare_exchange_n(p,&expected,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return expected;}
static inline LONG64 InterlockedCompareExchange64(volatile LONG64 *p,LONG64 n,LONG64 expected){
 __atomic_compare_exchange_n(p,&expected,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return expected;}
static inline LONG64 InterlockedIncrement64(volatile LONG64 *p){return __atomic_add_fetch(p,1,__ATOMIC_SEQ_CST);}
static inline PVOID InterlockedCompareExchangePointer(PVOID volatile *p,PVOID n,PVOID expected){
 __atomic_compare_exchange_n(p,&expected,n,0,__ATOMIC_SEQ_CST,__ATOMIC_SEQ_CST);return expected;}
void KeQuerySystemTimePrecise(LARGE_INTEGER *value);
ULONG FakeReadRegister(PULONG p);
void FakeWriteRegister(PULONG p,ULONG v);
void FakeBarrier(void);
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG *qpc);
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS p,ULONG n,ULONG flags);
void MmUnmapIoSpace(PVOID p,size_t n);
#define READ_REGISTER_ULONG(p) FakeReadRegister(p)
#define WRITE_REGISTER_ULONG(p,v) FakeWriteRegister(p,v)
#define KeMemoryBarrier() FakeBarrier()
#define YieldProcessor() ((void)0)
#endif
