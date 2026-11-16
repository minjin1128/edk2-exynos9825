/* SPDX-License-Identifier: MIT
 * Owned wrapper report[48..63], inside its existing validated 512-byte span.
 * BSP only, pre-EBS; diagnostics never grant admission or survive as OS state.
 */
#ifndef N976N_BOOT_TIMING_H
#define N976N_BOOT_TIMING_H
#ifndef NBP_U64
#define NBP_U64 UINT64
#endif
#define NBP_MAGIC 0x3146524550544F42ULL
#ifndef NBP_READ_TICK
static inline NBP_U64 NbpTick(void) {
  NBP_U64 V;
  __asm__ volatile("isb\n\tmrs %0, cntpct_el0" : "=r"(V) :: "memory");
  return V;
}
#define NBP_READ_TICK() NbpTick()
#endif
static inline void NbpMark(volatile NBP_U64 *R, unsigned Slot) {
  if (!R || Slot<51 || Slot>63 || R[48]!=NBP_MAGIC || !R[49]) return;
  R[Slot]=NBP_READ_TICK();
  R[50]|=1ULL<<(Slot-51);
}
static inline int NbpMilliseconds(const volatile NBP_U64 *R,
                                 unsigned First,unsigned Last,NBP_U64 *Ms) {
  NBP_U64 Mask,Delta,Frequency;
  if (!R || !Ms || First<51 || Last>63 || Last<=First || R[48]!=NBP_MAGIC) return 0;
  Mask=(1ULL<<(First-51))|(1ULL<<(Last-51));
  Frequency=R[49];
  if (!Frequency || Frequency>0xffffffffULL || (R[50]&Mask)!=Mask || R[Last]<R[First]) return 0;
  Delta=R[Last]-R[First];
  if (Delta>0xffffffffffffffffULL/1000) return 0;
  *Ms=Delta*1000/Frequency;
  return 1;
}
#endif
