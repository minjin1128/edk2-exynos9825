/* SPDX-License-Identifier: MIT */
#ifndef N976N_PLATFORM_H_
#define N976N_PLATFORM_H_

#include <Uefi.h>

#define N976N_PLATFORM_HANDOFF_MAGIC  0x32344345534E394EULL
#define N976N_PLATFORM_ABI_VERSION    2U
#define N976N_PLATFORM_PROFILE_PHONE  0U
#define N976N_PLATFORM_PROFILE_QEMU   1U
#define N976N_BDS_REPORT_MAGIC        0x325344424E394EULL
#define N976N_BDS_COMPLETE            0x454E4F4432534442ULL
#define N976N_BDS_CHECKS_ALL          0xFFULL

/* Produced only after SEC has admitted the firmware and constructed the
 * memory/stack HOBs. Heap excludes the separately reserved inherited stack.
 * The bounded, image-owned screen callback is independently checked by BDS. */
typedef struct {
  UINT64 Magic;
  UINT32 Version;
  UINT32 Size;
  UINT32 Profile;
  UINT32 Reserved;
  UINT64 FirmwareBase;
  UINT64 FirmwareSize;
  UINT64 HeapBase;
  UINT64 HeapSize;
  UINT64 StackBase;
  UINT64 StackSize;
  UINT64 ImageBase;
  UINT64 ImageSize;
  UINT64 Screen;
  UINT64 ReportAddress;
} N976N_PLATFORM_HANDOFF;

/* Exported by BdsDxe's platform library for the read-only execution observer.
 * Success describes this BDS self-check only; no OS or ResetSystem is run. */
typedef struct {
  UINT64 Magic;
  UINT32 Version;
  UINT32 Size;
  UINT64 Profile;
  UINT64 Stage;
  UINT64 Status;
  UINT64 Checks;
  UINT64 ArchMask;
  UINT64 VariableStatus;
  UINT64 TimerStatus;
  UINT64 MemoryStatus;
  UINT64 Frequency;
  UINT64 CounterStart;
  UINT64 CounterEnd;
  UINT64 TimerPolls;
  UINT64 ImageBase;
  UINT64 ImageSize;
  UINT64 CodeAttributes;
  UINT64 DataAttributes;
  UINT64 StackAttributes;
  UINT64 AllocationAttributes;
  UINT64 AllocationAddress;
  UINT64 Sctlr;
  UINT64 Mair;
  UINT64 Daif;
  UINT64 Complete;
  UINT64 CodeAllocationAddress;
  UINT64 CodeAllocationAttributes;
  UINT64 CodeAllocationStatus;
  UINT64 GopStatus;
  UINT64 ConsoleStatus;
  UINT64 ConsoleChecks;
} N976N_BDS_REPORT;

STATIC_ASSERT (sizeof (N976N_PLATFORM_HANDOFF) == 104, "SEC49 handoff ABI");
STATIC_ASSERT (sizeof (N976N_BDS_REPORT) == 248, "SEC49 BDS report ABI");

extern EFI_GUID gN976nPlatformHandoffGuid;
extern volatile N976N_BDS_REPORT mN976nBdsReport;

VOID EFIAPI N976nBdsStop (EFI_STATUS Status);

#endif
