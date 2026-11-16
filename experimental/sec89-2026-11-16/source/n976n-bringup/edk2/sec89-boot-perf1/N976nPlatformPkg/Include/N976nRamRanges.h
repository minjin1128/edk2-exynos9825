/* SPDX-License-Identifier: MIT */
#ifndef N976N_RAM_RANGES_H
#define N976N_RAM_RANGES_H
#include <N976nHighRam.h>
/* Pure range arithmetic, shared by SEC admission and its DXE consumer. */
STATIC inline BOOLEAN N976nRamRangesValid(CONST N976N_HIGH_RAM_ADMISSION *A) {
  UINT64 Total=0,End=0;
  if(!A || !A->RangeCount || A->RangeCount>N976N_RAM_MAX_RANGES ||
     !A->RawBytes || !A->Bytes || A->Bytes>A->RawBytes) return FALSE;
  for(UINTN I=0;I<A->RangeCount;++I){
    CONST N976N_RAM_RANGE *R=&A->Ranges[I];
    if(!R->Bytes || ((R->Base|R->Bytes)&4095) || R->Bytes>MAX_UINT64-R->Base ||
       (I && R->Base<=End) || R->Bytes>A->RawBytes-Total) return FALSE;
    Total+=R->Bytes; End=R->Base+R->Bytes;
  }
  for(UINTN I=A->RangeCount;I<N976N_RAM_MAX_RANGES;++I)
    if(A->Ranges[I].Base || A->Ranges[I].Bytes) return FALSE;
  return A->Base==A->Ranges[0].Base && A->Bytes==Total;
}
STATIC inline BOOLEAN N976nRamRangesContain(CONST N976N_HIGH_RAM_ADMISSION *A,UINT64 B,UINT64 N) {
  if(!N || N>MAX_UINT64-B || !A || A->RangeCount>N976N_RAM_MAX_RANGES) return FALSE;
  for(UINTN I=0;I<A->RangeCount;++I){
    CONST N976N_RAM_RANGE *R=&A->Ranges[I];
    if(B>=R->Base && B-R->Base<R->Bytes && N<=R->Bytes-(B-R->Base)) return TRUE;
  }
  return FALSE;
}
STATIC inline UINT64 N976nRamRangesIntersect(CONST N976N_HIGH_RAM_ADMISSION *A,UINT64 B,UINT64 N) {
  UINT64 Total=0;
  if(!N || N>MAX_UINT64-B || !A || A->RangeCount>N976N_RAM_MAX_RANGES) return 0;
  for(UINTN I=0;I<A->RangeCount;++I){
    CONST N976N_RAM_RANGE *R=&A->Ranges[I];
    UINT64 Lo=B>R->Base?B:R->Base,Hi=B+N<R->Base+R->Bytes?B+N:R->Base+R->Bytes;
    if(Hi>Lo) Total+=Hi-Lo;
  }
  return Total;
}
#endif
