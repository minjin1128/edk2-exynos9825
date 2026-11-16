/* SPDX-License-Identifier: MIT
 * SEC58: software admission of one DT-described high bank for a bounded
 * pre-Linux CPU probe. No address in that bank is dereferenced here.
 * Known size-only Linux allocations are not preexisting physical extents;
 * the exact captured dynamic contract remains mandatory and fails closed.
 */
#include <N976nHighRamAdmission.h>
#include <Library/BaseMemoryLib.h>

STATIC BOOLEAN HighExtent (UINT64 Base, UINT64 Bytes)
{ return Bytes != 0 && Base <= MAX_UINT64 - Bytes; }

STATIC BOOLEAN HighOverlap (UINT64 Base, UINT64 Bytes)
{
  return HighExtent (Base, Bytes) &&
    Base < N976N_HIGH_RAM_BASE + N976N_HIGH_RAM_BYTES &&
    N976N_HIGH_RAM_BASE < Base + Bytes;
}

BOOLEAN EFIAPI N976nAdmitHighRam (
  CONST SEC_PROBE_HANDOFF *H, CONST MEMORY_PLAN *P,
  N976N_HIGH_RAM_ADMISSION *A
  )
{
  UINT64 Banks = 0, Covered = 0;
  if (A == NULL) return FALSE;
  ZeroMem (A, sizeof (*A));
  A->Magic = N976N_HIGH_RAM_MAGIC; A->Version = 1; A->Size = sizeof (*A);
  A->Base = N976N_HIGH_RAM_BASE; A->Bytes = N976N_HIGH_RAM_BYTES;
  A->Reason = 1;
  if (H == NULL || P == NULL ||
      !HighExtent (A->Base, A->Bytes) || ((A->Base | A->Bytes) & 4095) != 0 ||
      P->Info.RamCount == 0 || P->Info.RamCount > MAX_RAM_RANGES ||
      P->Info.FixedCount > MAX_FIXED_RANGES || P->Info.ReserveMapCount > MAX_MAP_RANGES ||
      P->Info.SegmentCount == 0 || P->Info.SegmentCount > MAX_SEGMENTS ||
      P->ExclusionCount > MAX_EXCLUSIONS) return FALSE;
  A->Checks = 1;
  A->Reason = 2;
  if (P->Info.DynamicCount != 3 || P->DynamicWhitelistMask != 7) return FALSE;
  A->Checks |= 2;
  A->Reason = 3;
  if (!ValidateMemoryPlan (H, P)) return FALSE;
  A->Checks |= 4;
  A->Dtb = H->Dtb; A->DtbBytes = P->Info.DtbSize;
  A->ImageBase = H->ImageBase; A->ImageBytes = H->ImageEnd - H->ImageBase;
  A->InitrdBase = P->InitrdStart; A->InitrdBytes = P->InitrdEnd - P->InitrdStart;
  A->DynamicMask = P->DynamicWhitelistMask;
  A->Reason = 4;
  for (UINTN I = 0; I < P->Info.RamCount; ++I) {
    CONST MEMORY_RANGE *R = &P->Ram[I];
    if (HighOverlap (R->Base, R->Size)) {
      if (R->Base != A->Base || R->Size != A->Bytes) return FALSE;
      ++Banks;
    }
  }
  if (Banks != 1) return FALSE;
  A->Checks |= 8;
  A->Reason = 5;
  for (UINTN I = 0; I < P->Info.FixedCount; ++I)
    if (!HighExtent (P->Fixed[I].Base, P->Fixed[I].Size) ||
        HighOverlap (P->Fixed[I].Base, P->Fixed[I].Size)) return FALSE;
  A->Checks |= 0x10;
  A->Reason = 6;
  for (UINTN I = 0; I < P->Info.ReserveMapCount; ++I)
    if (!HighExtent (P->ReserveMap[I].Base, P->ReserveMap[I].Size) ||
        HighOverlap (P->ReserveMap[I].Base, P->ReserveMap[I].Size)) return FALSE;
  A->Checks |= 0x20;
  A->Reason = 7;
  if (HighOverlap (A->ImageBase, A->ImageBytes) ||
      HighOverlap (A->Dtb, A->DtbBytes) ||
      HighOverlap (A->InitrdBase, A->InitrdBytes) ||
      HighOverlap (FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE)) return FALSE;
  for (UINTN I = 0; I < P->ExclusionCount; ++I)
    if (!HighExtent (P->Exclusions[I].Base, P->Exclusions[I].Size) ||
        HighOverlap (P->Exclusions[I].Base, P->Exclusions[I].Size)) return FALSE;
  A->Checks |= 0x40;
  A->Reason = 8;
  for (UINTN I = 0; I < P->Info.SegmentCount; ++I) {
    CONST MEMORY_SEGMENT *S = &P->Segments[I];
    if (HighOverlap (S->Base, S->Size)) {
      /* Validated segments already form an exact nonoverlapping partition;
         still bound every addition before claiming whole-bank DT coverage. */
      if (S->Reasons != 0 || S->Base < A->Base || S->Size > A->Bytes ||
          S->Base - A->Base > A->Bytes - S->Size ||
          Covered > A->Bytes - S->Size) return FALSE;
      Covered += S->Size;
    }
  }
  if (Covered != A->Bytes) return FALSE;
  A->Checks |= 0x80;
  A->Reason = 0; A->Admitted = 1;
  return TRUE;
}
