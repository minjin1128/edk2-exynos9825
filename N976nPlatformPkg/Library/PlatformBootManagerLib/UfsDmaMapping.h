/* SPDX-License-Identifier: MIT
 * SEC49 FIX1: bounded actual mapping check for the seven owned DMA pages.
 * Reuses BootstrapImagePolicy.c's PublishedPermissions walk: EL1, 4K,
 * non-LPA2 identity mappings and page tables inside the admitted heap.
 * MemoryAttributeProtocol proves permissions only; it does not return WB.
 */
#ifndef N976N_UFS_DMA_MAPPING_H_
#define N976N_UFS_DMA_MAPPING_H_

#include <AArch64/AArch64Mmu.h>
#ifndef N976N_UFS_HOST_TEST
#include <Library/ArmLib.h>
#endif

typedef struct {
  UINT64 El, Sctlr, Tcr, Root, Mair;
  UINTN CacheLine, WritebackGranule;
} UFS_DMA_CPU_STATE;

#ifdef N976N_UFS_HOST_TEST
/* The component test supplies architectural registers and actual synthetic
   table pages. It still executes the production mapping check below. */
STATIC VOID UfsDmaReadCpuState (UFS_DMA_CPU_STATE *Cpu);
#else
STATIC VOID UfsDmaReadCpuState (UFS_DMA_CPU_STATE *Cpu) {
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (Cpu->El));
  Cpu->Sctlr = Cpu->Tcr = Cpu->Root = Cpu->Mair = 0;
  Cpu->CacheLine = Cpu->WritebackGranule = 0;
  if (Cpu->El != 4) { return; }
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Cpu->Sctlr));
  __asm__ volatile ("mrs %0, tcr_el1" : "=r" (Cpu->Tcr));
  __asm__ volatile ("mrs %0, ttbr0_el1" : "=r" (Cpu->Root));
  __asm__ volatile ("mrs %0, mair_el1" : "=r" (Cpu->Mair));
  Cpu->CacheLine = ArmDataCacheLineLength ();
  /* Upstream uses a conservative 2048-byte default when CTR.CWG is zero. */
  Cpu->WritebackGranule = ArmCacheWritebackGranule ();
}
#endif

STATIC BOOLEAN UfsDmaGranuleValid (UINTN Granule) {
  return Granule != 0 && Granule <= 4096 && (Granule & (Granule - 1)) == 0;
}

STATIC BOOLEAN UfsDmaMappingSnapshotValid (
  CONST N976N_PLATFORM_HANDOFF *Handoff, UINT64 Address, UINT64 Bytes,
  CONST UFS_DMA_CPU_STATE *Cpu
  ) {
  UINTN T0;
  UINT64 End, HeapEnd;
  if (Handoff == NULL || Cpu == NULL || Bytes != 7U * 4096U ||
      (Address & 4095) != 0 || Address > MAX_UINT32 - Bytes ||
      Handoff->HeapSize == 0 || ((Handoff->HeapBase | Handoff->HeapSize) & 4095) != 0 ||
      Handoff->HeapSize > MAX_UINT64 - Handoff->HeapBase) { return FALSE; }
  End = Address + Bytes; HeapEnd = Handoff->HeapBase + Handoff->HeapSize;
  if (Address < Handoff->HeapBase || End > HeapEnd ||
      !UfsDmaGranuleValid (Cpu->CacheLine) || !UfsDmaGranuleValid (Cpu->WritebackGranule) ||
      ((Address | Bytes) & (Cpu->CacheLine - 1)) != 0 ||
      ((Address | Bytes) & (Cpu->WritebackGranule - 1)) != 0) { return FALSE; }
  T0 = Cpu->Tcr & 63;
  /* MMU and D-cache enabled; little-endian EL1; no disabled TTBR0 walk,
     alternate granule, TBI0, hardware AF/dirty update, or LPA2 profile. */
  if (Cpu->El != 4 || (Cpu->Sctlr & (BIT0 | BIT2)) != (BIT0 | BIT2) ||
      (Cpu->Sctlr & BIT25) != 0 || T0 < 16 || T0 > 39 ||
      (Cpu->Tcr & (BIT7 | BIT14 | BIT15 | BIT37 | BIT39 | BIT40 | BIT59)) != 0 ||
      ((Cpu->Tcr >> 32) & 7) > 5 || (Cpu->Root & 0xFFE) != 0 ||
      End > (1ULL << (64 - T0))) { return FALSE; }
  for (UINT64 Page = Address; Page < End; Page += 4096) {
    UINT64 Table = Cpu->Root & TT_ADDRESS_MASK_DESCRIPTION_TABLE, Entry = 0;
    for (UINTN Level = (T0 - 16) / 9; Level <= 3; ++Level) {
      UINTN Shift = 12 + (3 - Level) * 9;
      UINT64 BlockMask = (1ULL << Shift) - 1;
      /* Never follow an unowned page-table pointer or treat the DMA allocation
         itself as a page table, even if a corrupted entry would look valid. */
      if (Table < Handoff->HeapBase || Table >= HeapEnd || 4096 > HeapEnd - Table ||
          (Table < End && Address < Table + 4096)) { return FALSE; }
      Entry = ((volatile UINT64 *)(UINTN)Table)[(Page >> Shift) & 511];
      if ((Entry & 1) == 0) { return FALSE; }
      if (Level < 3 && (Entry & 3) == 3) {
        if (Entry & (BIT59 | BIT60 | BIT61 | BIT62 | BIT63)) { return FALSE; }
        Table = Entry & TT_ADDRESS_MASK_DESCRIPTION_TABLE;
        continue;
      }
      if (Level == 0 || (Entry & 3) != (Level == 3 ? 3U : 1U) ||
          (Entry & TT_ADDRESS_MASK_BLOCK_ENTRY & BlockMask) != 0 ||
          (Entry & TT_ADDRESS_MASK_BLOCK_ENTRY) != (Page & ~BlockMask)) { return FALSE; }
      break;
    }
    if ((Entry & TT_AF) == 0 || (Entry & TT_AP_MASK) != TT_AP_NO_RW ||
        (Entry & (TT_PXN_MASK | TT_UXN_MASK)) != (TT_PXN_MASK | TT_UXN_MASK) ||
        (Entry & TT_SH_MASK) != TT_SH_INNER_SHAREABLE ||
        ((Cpu->Mair >> (((Entry >> 2) & 7) * 8)) & 255) != 255) { return FALSE; }
  }
  return TRUE;
}

STATIC BOOLEAN UfsDmaMappingValid (
  CONST N976N_PLATFORM_HANDOFF *Handoff, UINT64 Address, UINT64 Bytes
  ) {
  UFS_DMA_CPU_STATE Cpu;
  UfsDmaReadCpuState (&Cpu);
  return UfsDmaMappingSnapshotValid (Handoff, Address, Bytes, &Cpu);
}

#endif
