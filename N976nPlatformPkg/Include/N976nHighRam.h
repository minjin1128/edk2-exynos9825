/* SPDX-License-Identifier: MIT */
#ifndef N976N_HIGH_RAM_H
#define N976N_HIGH_RAM_H
#include <N976nPlatform.h>

#define N976N_HIGH_RAM_MAGIC 0x38354d415248394eULL
#define N976N_HIGH_RAM_BASE  0x900000000ULL
#define N976N_HIGH_RAM_BYTES 0x80000000ULL
#define N976N_HIGH_RAM_ADMISSION_ALL 0xFFULL

/* SEC's software ownership gate only. No RAM allocation/resource grant and
   no assertion that secure hardware or every byte in this bank was tested. */
typedef struct {
  UINT64 Magic;
  UINT64 Version;
  UINT64 Size;
  UINT64 Base;
  UINT64 Bytes;
  UINT64 Checks;
  UINT64 Reason;
  UINT64 Admitted;
  UINT64 Dtb;
  UINT64 DtbBytes;
  UINT64 ImageBase;
  UINT64 ImageBytes;
  UINT64 InitrdBase;
  UINT64 InitrdBytes;
  UINT64 DynamicMask;
  UINT64 Reserved;
} N976N_HIGH_RAM_ADMISSION;
STATIC_ASSERT (sizeof (N976N_HIGH_RAM_ADMISSION) == 128, "SEC58 admission ABI");

extern EFI_GUID gN976nHighRamAdmissionGuid;
/* The 24 exact screen fields are owned and documented by HighRamProbe.c. */
extern volatile UINT64 mN976nHighRamReport[24];
EFI_STATUS N976nRunHighRamProbe (CONST N976N_PLATFORM_HANDOFF *Handoff);
VOID N976nHighRamScreen (VOID);
BOOLEAN N976nHighRamPublished (VOID);
BOOLEAN N976nHighRamOwnedCpuRange (CONST VOID *Buffer, UINTN Bytes, UINT32 TypeMask);
BOOLEAN N976nHighRamFreedCpuRange (CONST VOID *Buffer, UINTN Bytes);
/* SEC66 private CPU-only file staging. Slots 0/1 are SDI/WIM. These APIs
   never grant DMA or filesystem-control ownership. Both allocations coexist
   until retirement; failed ownership/protection checks quarantine them. */
extern volatile UINT64 mN976nHighRamStageReport[16];
EFI_STATUS N976nHighRamStageAllocate (UINTN Slot, UINTN Bytes, VOID **Buffer);
BOOLEAN N976nHighRamStageRange (UINTN Slot, UINTN Offset, UINTN Bytes);
BOOLEAN N976nHighRamStageGuards (UINTN Slot);
EFI_STATUS N976nHighRamStageVerify (UINTN Slot, CONST UINT8 ExpectedSha[32]);
EFI_STATUS N976nHighRamStageFree (UINTN Slot);
#endif
