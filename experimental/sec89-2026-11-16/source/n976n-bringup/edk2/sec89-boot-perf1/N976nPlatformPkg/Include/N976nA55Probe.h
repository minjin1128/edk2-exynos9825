/* SPDX-License-Identifier: MIT */
#ifndef N976N_A55_PROBE_H_
#define N976N_A55_PROBE_H_
#include <Uefi.h>
#include <N976nA55Entry.h>
#include <N976nA55Clock.h>
#define N976N_A55_PROBE_MAGIC 0x3142503535414E4EULL
#define N976N_A55_PROBE_ARENA_BYTES 0x8000U
#define N976N_A55_PROBE_WAIT_US 500000U
typedef struct {
  UINT64 Arena, Code, Witness, SmcReturn, WaitUs;
  N976N_A55_ENTRY_WITNESS Entry;
} N976N_A55_AP_REPORT;
typedef struct {
  UINT64 Magic, Phase, Status, Reason, AttemptedMask, ParkedMask;
  UINT64 GuardMask, MapMask, BspMpidr, BspMidr, BspEl, Frequency;
  N976N_A55_CLOCK_SAMPLE ClockRaw;
  N976N_A55_CLOCK_RESULT Clock;
  N976N_A55_AP_REPORT Ap[3];
  UINT64 BspInterface;
} N976N_A55_PROBE_REPORT;
extern volatile N976N_A55_PROBE_REPORT mN976nA55ProbeReport;
/* One attempt per A55. Dedicated reserved RX code, private witness and RW/XN
 * Device mailbox remain allocated permanently. No frequency/voltage writes. */
EFI_STATUS N976nA55Probe (UINT64 Profile, VOID (*Progress)(VOID));
EFI_STATUS N976nA55PublishAcpi(UINT64 Profile, VOID *Madt);
BOOLEAN N976nA55OsMap(CONST EFI_MEMORY_DESCRIPTOR *Map,UINTN Bytes,UINTN Stride);
#endif
