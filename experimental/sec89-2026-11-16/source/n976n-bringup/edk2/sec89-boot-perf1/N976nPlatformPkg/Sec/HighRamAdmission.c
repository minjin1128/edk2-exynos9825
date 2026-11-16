/* SPDX-License-Identifier: MIT
 * SEC87: derive all free RAM from the validated live Samsung DT plan.
 * No candidate memory is dereferenced here. Fixed reservations, memreserve,
 * framebuffer, image, DTB, initrd and the whole bootstrap window are excluded.
 */
#include <N976nHighRamAdmission.h>
#include <N976nRamRanges.h>
#include <Library/BaseMemoryLib.h>

STATIC BOOLEAN HighExtent(UINT64 B,UINT64 N) { return N && N<=MAX_UINT64-B; }
STATIC BOOLEAN Append(N976N_HIGH_RAM_ADMISSION *A,UINT64 B,UINT64 E) {
  if(B==E) return TRUE;
  if(E<B || ((B|E)&4095) || E-B>A->RawBytes-A->Bytes) return FALSE;
  if(A->RangeCount){
    N976N_RAM_RANGE *R=&A->Ranges[A->RangeCount-1];
    UINT64 End=R->Base+R->Bytes;
    if(B<End) return FALSE;
    if(B==End){R->Bytes+=E-B;A->Bytes+=E-B;return TRUE;}
  }
  if(A->RangeCount>=N976N_RAM_MAX_RANGES) return FALSE;
  A->Ranges[A->RangeCount++]=(N976N_RAM_RANGE){B,E-B};
  A->Bytes+=E-B;return TRUE;
}
BOOLEAN EFIAPI N976nAdmitHighRam(CONST SEC_PROBE_HANDOFF *H,CONST MEMORY_PLAN *P,
                                N976N_HIGH_RAM_ADMISSION *A) {
  UINT64 Policy=0,Candidate=0,Excluded=0;
  if(!A)return FALSE;
  ZeroMem(A,sizeof(*A));
  A->Magic=N976N_HIGH_RAM_MAGIC;A->Version=N976N_RAM_ADMISSION_VERSION;A->Size=sizeof(*A);A->Reason=1;
  if(!H || !P || !P->Info.RamCount || P->Info.RamCount>MAX_RAM_RANGES ||
     P->Info.FixedCount>MAX_FIXED_RANGES || P->Info.ReserveMapCount>MAX_MAP_RANGES ||
     !P->Info.SegmentCount || P->Info.SegmentCount>MAX_SEGMENTS ||
     P->ExclusionCount>MAX_EXCLUSIONS) return FALSE;
  A->Checks=1;A->Reason=2;
  if(P->Info.DynamicCount!=3 || P->DynamicWhitelistMask!=7)return FALSE;
  A->Checks|=2;A->Reason=3;
  if(!ValidateMemoryPlan(H,P))return FALSE;
  A->Checks|=4;
  A->Dtb=H->Dtb;A->DtbBytes=P->Info.DtbSize;A->ImageBase=H->ImageBase;
  A->ImageBytes=H->ImageEnd-H->ImageBase;A->InitrdBase=P->InitrdStart;
  A->InitrdBytes=P->InitrdEnd-P->InitrdStart;A->DynamicMask=P->DynamicWhitelistMask;
  A->RawBytes=P->Info.RamBytes;A->ExternalBase=H->BootInfo.ExternalBase;
  A->ExternalBytes=H->BootInfo.ExternalSize;A->Reason=4;
  if(!HighExtent(A->ExternalBase,A->ExternalBytes) ||
     ((A->ExternalBase|A->ExternalBytes)&4095) ||
     !ValidateExternalMemoryPolicy(H,P,&Policy) || Policy!=0xFF)return FALSE;
  A->Checks|=8;A->Reason=5;
  for(UINTN I=0;I<P->Info.SegmentCount;++I){
    CONST MEMORY_SEGMENT *S=&P->Segments[I];
    if(S->Reasons)continue;
    UINT64 B=S->Base,E=B+S->Size,X=A->ExternalBase,Y=X+A->ExternalBytes;
    if(S->Size>A->RawBytes-Candidate)return FALSE;
    Candidate+=S->Size;
    if(B<Y && X<E){
      UINT64 Lo=B>X?B:X,Hi=E<Y?E:Y;
      Excluded+=Hi-Lo;
      if(!Append(A,B,Lo) || !Append(A,Hi,E))return FALSE;
    }else if(!Append(A,B,E))return FALSE;
  }
  A->Base=A->RangeCount?A->Ranges[0].Base:0;
  if(Candidate!=P->Info.CandidateBytes || Excluded!=A->ExternalBytes ||
     A->Bytes!=Candidate-Excluded || !N976nRamRangesValid(A))return FALSE;
  A->Checks|=0x10;A->Reason=6;
  /* Recheck exclusions against the derived set, rather than trusting a union
   * whose upper/lower envelope would include protected holes. */
  for(UINTN I=0;I<P->ExclusionCount;++I)
    if(N976nRamRangesIntersect(A,P->Exclusions[I].Base,P->Exclusions[I].Size))return FALSE;
  if(N976nRamRangesIntersect(A,A->ExternalBase,A->ExternalBytes))return FALSE;
  A->Checks|=0x20;A->Reason=7;
  /* Preserve the verified allocator/protection test anchor. This is a small
   * owned allocation requirement, not the size or identity of a RAM bank. */
  if(!N976nRamRangesContain(A,N976N_HIGH_RAM_BASE+0x200000,5*4096))return FALSE;
  A->Checks|=0x40;A->Reason=8;
  if(A->Bytes<=N976N_HIGH_RAM_BYTES)return FALSE;
  A->Checks|=0x80;A->Reason=0;A->Admitted=1;return TRUE;
}
