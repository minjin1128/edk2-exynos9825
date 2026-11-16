/* SPDX-License-Identifier: MIT
 * SEC66: exact CPU-owned SDI/WIM allocations over the published high bank.
 * Upstream AllocatePages/FreePages remain the allocator; no high DMA, new
 * memory map, memory-type exception or executable permission is introduced.
 */
#include <PiDxe.h>
#include <N976nHighRam.h>
#include <N976nSystemVolume.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/UefiLib.h>

#define HS_PAGE 4096ULL
#define HS_SLICE 0x400000U
#define HS_LIMIT 0x40000000ULL
#define HS_GUARD 0x3644475541524448ULL
typedef struct {
  EFI_PHYSICAL_ADDRESS Base;
  UINTN Bytes, Pages;
  BOOLEAN Active, Used, Initialized;
} HS_SLOT;
STATIC HS_SLOT mHsSlot[2];
/* phase,status,checks,reason,SDI base,WIM base,SDI bytes,WIM bytes,
 * allocations,frees,SHA mask,guard mask,pages allocated,slice checks,active,0.
 * Checks: allocate both1, verify both2, retire both4. */
volatile UINT64 mN976nHighRamStageReport[16];

STATIC EFI_STATUS HsFail (UINT64 Reason, EFI_STATUS Status) {
  if (!mN976nHighRamStageReport[3]) {
    mN976nHighRamStageReport[3] = Reason;
    mN976nHighRamStageReport[1] = Status;
  }
  mN976nHighRamStageReport[0] = 0xE;
  return Status;
}
STATIC BOOLEAN HsValid (UINTN Slot) {
  if (Slot >= ARRAY_SIZE (mHsSlot) || !N976nHighRamPublished () ||
      EfiGetCurrentTpl () != TPL_APPLICATION) return FALSE;
  CONST HS_SLOT *S = &mHsSlot[Slot];
  return S->Active && S->Used && S->Bytes && S->Bytes <= HS_LIMIT - 3 * HS_PAGE &&
    S->Pages == EFI_SIZE_TO_PAGES (S->Bytes) + 2 && !(S->Base & (HS_PAGE - 1)) &&
    S->Base >= N976N_HIGH_RAM_BASE &&
    S->Base - N976N_HIGH_RAM_BASE < N976N_HIGH_RAM_BYTES &&
    S->Pages * HS_PAGE <= N976N_HIGH_RAM_BYTES - (S->Base - N976N_HIGH_RAM_BASE);
}
STATIC BOOLEAN HsOwned (UINT64 Address, UINTN Bytes) {
  return N976nHighRamOwnedCpuRange ((CONST VOID *)(UINTN)Address, Bytes,
                                  1U << EfiBootServicesData);
}
STATIC BOOLEAN HsAudit (UINTN Slot) {
  if (!HsValid (Slot)) return FALSE;
  CONST HS_SLOT *S = &mHsSlot[Slot];
  UINTN Total = S->Pages * HS_PAGE;
  for (UINTN At = 0; At < Total; ) {
    UINTN N = MIN ((UINTN)HS_SLICE, Total - At);
    if (!HsOwned (S->Base + At, N)) return FALSE;
    At += N;
  }
  return TRUE;
}
STATIC BOOLEAN HsGuards (UINTN Slot, BOOLEAN Initialize) {
  if (!HsValid (Slot)) return FALSE;
  HS_SLOT *S = &mHsSlot[Slot];
  UINT64 Tail = S->Base + (S->Pages - 1) * HS_PAGE;
  UINT64 Last = (S->Base + HS_PAGE + S->Bytes - 1) & ~(HS_PAGE - 1);
  if ((!Initialize && !S->Initialized) || !HsOwned (S->Base, HS_PAGE) ||
      !HsOwned (Tail, HS_PAGE) || !HsOwned (Last, HS_PAGE)) return FALSE;
  for (UINTN End = 0; End < 2; ++End) {
    UINT64 A = End ? Tail : S->Base;
    volatile UINT64 *P = (volatile UINT64 *)(UINTN)A;
    for (UINTN W = 0; W < HS_PAGE / sizeof (UINT64); ++W) {
      UINT64 Value = HS_GUARD ^ A ^ W;
      if (Initialize) P[W] = Value;
      else if (P[W] != Value) return FALSE;
    }
    if (Initialize) WriteBackInvalidateDataCacheRange ((VOID *)(UINTN)A, HS_PAGE);
  }
  volatile UINT8 *Padding = (volatile UINT8 *)(UINTN)(S->Base + HS_PAGE + S->Bytes);
  UINTN PadBytes = Tail - (UINTN)Padding;
  for (UINTN I = 0; I < PadBytes; ++I) {
    if (Initialize) Padding[I] = 0xA5;
    else if (Padding[I] != 0xA5) return FALSE;
  }
  if (Initialize) {
    if (PadBytes) WriteBackInvalidateDataCacheRange ((VOID *)(UINTN)Last, HS_PAGE);
    S->Initialized = TRUE;
  }
  MemoryFence ();
  return TRUE;
}
EFI_STATUS N976nHighRamStageAllocate (UINTN Slot, UINTN Bytes, VOID **Buffer) {
  if (Buffer) *Buffer = NULL;
  if (!Buffer || Slot >= ARRAY_SIZE (mHsSlot) || mHsSlot[Slot].Used ||
      !Bytes || Bytes > HS_LIMIT - 3 * HS_PAGE || !N976nHighRamPublished () ||
      EfiGetCurrentTpl () != TPL_APPLICATION)
    return HsFail (1, EFI_ACCESS_DENIED);
  UINTN Pages = EFI_SIZE_TO_PAGES (Bytes) + 2;
  UINT64 Total = Pages * HS_PAGE;
  for (UINTN I = 0; I < ARRAY_SIZE (mHsSlot); ++I) if (mHsSlot[I].Active) {
    if (mHsSlot[I].Pages * HS_PAGE > HS_LIMIT - Total)
      return HsFail (2, EFI_OUT_OF_RESOURCES);
    Total += mHsSlot[I].Pages * HS_PAGE;
  }
  EFI_PHYSICAL_ADDRESS Address = N976N_HIGH_RAM_BASE + N976N_HIGH_RAM_BYTES - 1;
  EFI_STATUS Status = gBS->AllocatePages (AllocateMaxAddress, EfiBootServicesData, Pages, &Address);
  if (EFI_ERROR (Status)) return HsFail (3, Status);
  HS_SLOT *S = &mHsSlot[Slot];
  S->Base = Address; S->Bytes = Bytes; S->Pages = Pages; S->Active = S->Used = TRUE;
  ++mN976nHighRamStageReport[8]; ++mN976nHighRamStageReport[14];
  mN976nHighRamStageReport[12] += Pages;
  if (!HsValid (Slot)) return HsFail (4, EFI_SECURITY_VIOLATION);
  for (UINTN I = 0; I < ARRAY_SIZE (mHsSlot); ++I) if (I != Slot && mHsSlot[I].Active &&
      Address < mHsSlot[I].Base + mHsSlot[I].Pages * HS_PAGE &&
      mHsSlot[I].Base < Address + Pages * HS_PAGE)
    return HsFail (4, EFI_SECURITY_VIOLATION);
  if (!HsAudit (Slot) || !HsGuards (Slot, TRUE) || !HsGuards (Slot, FALSE))
    return HsFail (5, EFI_SECURITY_VIOLATION);
  *Buffer = (VOID *)(UINTN)(Address + HS_PAGE);
  mN976nHighRamStageReport[4 + Slot] = (UINTN)*Buffer;
  mN976nHighRamStageReport[6 + Slot] = Bytes;
  mN976nHighRamStageReport[11] |= 1ULL << Slot;
  if (mN976nHighRamStageReport[8] == 2) mN976nHighRamStageReport[2] |= 1;
  if (!mN976nHighRamStageReport[3]) mN976nHighRamStageReport[0] = 1;
  return EFI_SUCCESS;
}
BOOLEAN N976nHighRamStageGuards (UINTN Slot) {
  if (!HsGuards (Slot, FALSE)) { HsFail (6, EFI_SECURITY_VIOLATION); return FALSE; }
  return TRUE;
}
BOOLEAN N976nHighRamStageRange (UINTN Slot, UINTN Offset, UINTN Bytes) {
  if (!HsValid (Slot) || !Bytes || Bytes > HS_SLICE || Offset >= mHsSlot[Slot].Bytes ||
      Bytes > mHsSlot[Slot].Bytes - Offset || !HsGuards (Slot, FALSE) ||
      !HsOwned (mHsSlot[Slot].Base + HS_PAGE + Offset, Bytes)) {
    HsFail (7, EFI_SECURITY_VIOLATION); return FALSE;
  }
  ++mN976nHighRamStageReport[13];
  return TRUE;
}
EFI_STATUS N976nHighRamStageVerify (UINTN Slot, CONST UINT8 ExpectedSha[32]) {
  UINT8 Digest[32];
  if (!ExpectedSha || !HsAudit (Slot) || !HsGuards (Slot, FALSE))
    return HsFail (8, EFI_SECURITY_VIOLATION);
  HS_SLOT *S = &mHsSlot[Slot];
  /* Exact owned pages only. This writes CPU cache lines back, never issues a
     UFS/DMA transfer. The independent full-file hash reads the RAM copy after
     cache retirement; the SHA primitive makes no UEFI allocation/callback. */
  WriteBackInvalidateDataCacheRange ((VOID *)(UINTN)(S->Base + HS_PAGE), (S->Pages - 2) * HS_PAGE);
  MemoryFence ();
  if (!HsAudit (Slot) || !HsGuards (Slot, FALSE) ||
      !N976nSystemSha256 ((CONST VOID *)(UINTN)(S->Base + HS_PAGE), S->Bytes, Digest) ||
      CompareMem (Digest, ExpectedSha, sizeof (Digest)) != 0)
    return HsFail (9, EFI_COMPROMISED_DATA);
  if (!HsAudit (Slot) || !HsGuards (Slot, FALSE))
    return HsFail (10, EFI_SECURITY_VIOLATION);
  mN976nHighRamStageReport[10] |= 1ULL << Slot;
  if (mN976nHighRamStageReport[10] == 3) mN976nHighRamStageReport[2] |= 2;
  if (!mN976nHighRamStageReport[3]) mN976nHighRamStageReport[0] = 2;
  return EFI_SUCCESS;
}
EFI_STATUS N976nHighRamStageFree (UINTN Slot) {
  if (!HsAudit (Slot) || !HsGuards (Slot, FALSE))
    return HsFail (11, EFI_SECURITY_VIOLATION);
  HS_SLOT *S = &mHsSlot[Slot];
  /* Verified RW-XN ownership is mandatory: upstream FreePages can otherwise
     return SUCCESS for an RO/RP range while retaining the allocation. */
  EFI_STATUS Status = gBS->FreePages (S->Base, S->Pages);
  if (EFI_ERROR (Status)) return HsFail (12, Status);
  /* Success must revoke exact ownership. Check every bounded piece so a
     partial/free-false-success cannot be reported as complete retirement. */
  UINTN Total = S->Pages * HS_PAGE;
  for (UINTN At = 0; At < Total; ) {
    UINTN N = MIN ((UINTN)HS_SLICE, Total - At);
    if (!N976nHighRamFreedCpuRange ((CONST VOID *)(UINTN)(S->Base + At), N))
      return HsFail (13, EFI_SECURITY_VIOLATION);
    At += N;
  }
  S->Active = FALSE;
  ++mN976nHighRamStageReport[9]; --mN976nHighRamStageReport[14];
  if (mN976nHighRamStageReport[9] == 2 && !mN976nHighRamStageReport[14]) {
    mN976nHighRamStageReport[2] |= 4;
    if (!mN976nHighRamStageReport[3]) mN976nHighRamStageReport[0] = 8;
  }
  return EFI_SUCCESS;
}
