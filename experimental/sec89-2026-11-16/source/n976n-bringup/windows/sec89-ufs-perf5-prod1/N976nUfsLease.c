/* SPDX-License-Identifier: MIT */
#include "N976nUfsLease.h"
#include <string.h>
/* WDK's kernel C invocation does not consistently forward LanguageStandard_C;
 * negative-array assertions retain the same compile-time contract in MSVC C. */
typedef char NufLeaseSizeCheck[(sizeof(N976N_UFS_HANDOFF)==N976N_UFS_HANDOFF_BYTES)?1:-1];
typedef char NufLeaseClaimCheck[(offsetof(N976N_UFS_HANDOFF,ClaimState)==320)?1:-1];
int NufRange(U64 b,U64 n){return n&&b>=0x92001000ULL&&b<0x95FDE000ULL&&
 n<=0x95FDE000ULL-b&&((b|n)&4095ULL)==0;}
int NufResourceAllowed(U32 i,U64 b,U32 n,U32 memory){if(memory!=1)return 0;
 switch(i){case 0:return b==0x13D60000ULL&&n==8192;case 1:return b==0x13C10000ULL&&n==4096;
 case 2:return NufRange(b,n)&&n==8192;case 3:return NufRange(b,n)&&n==NUF_DMA_BYTES;default:return 0;}}
int NufOverlap(U64 a,U64 an,U64 b,U64 bn){return a<b+bn&&b<a+an;}
U32 NufLeaseCrc(const N976N_UFS_HANDOFF *h){U8 copy[320];memcpy(copy,h,sizeof(copy));
 memset(copy+offsetof(N976N_UFS_HANDOFF,Crc32),0,4);return NufCrc32(copy,sizeof(copy));}
U32 NufValidateLease(const N976N_UFS_HANDOFF *h,U64 lease,U64 dma){
 if(!h||h->Magic!=N976N_UFS_HANDOFF_MAGIC||h->Version!=N976N_UFS_HANDOFF_VERSION||h->Bytes!=336||
 h->ImmutableBytes!=320||h->Profile!=0||h->ProducerStage!=3||h->ProducerChecks!=0x7F||
 h->Guard!=N976N_UFS_HANDOFF_GUARD||h->Flags!=7||h->PowerRaw!=0x11||h->BootCounter==0||
 h->CounterHz==0||h->CounterHz>1000000000ULL||h->Crc32!=NufLeaseCrc(h))return 1;
 for(U32 i=0;i<sizeof(h->Reserved);i++)if(h->Reserved[i])return 2;
 if(h->LeaseBase!=lease||h->LeaseBytes!=8192||h->DmaBase!=dma||h->DmaBytes!=NUF_DMA_BYTES||
  h->FirmwareDmaBytes!=NUF_FIRMWARE_DMA_BYTES||!NufRange(lease,8192)||!NufRange(dma,NUF_DMA_BYTES)||
  !NufRange(h->FirmwareDmaBase,NUF_FIRMWARE_DMA_BYTES)||NufOverlap(lease,8192,dma,NUF_DMA_BYTES)||
  NufOverlap(lease,8192,h->FirmwareDmaBase,NUF_FIRMWARE_DMA_BYTES)||
  NufOverlap(dma,NUF_DMA_BYTES,h->FirmwareDmaBase,NUF_FIRMWARE_DMA_BYTES))return 3;
 if(h->HciBase!=0x13D60000ULL||h->HciBytes!=8192||h->VendorOffset!=0x1100||
  h->CoherencyBase!=0x13C10000ULL||h->CoherencyOffset!=0x700||h->CoherencyBytes!=4096||
  h->BaselineOffset!=4096||h->BaselineBytes!=4096)return 4;
 if(h->Lun!=0||h->BlockBytes!=4096||h->LastLba==0||h->LastLba>=0xFFFFFFFFULL||
  h->Hce!=1||h->Ie||h->Ahit||h->Iacr||h->TrlRun||h->TmRun||h->TrlDoorbell||h->TmDoorbell||
  (h->Is&(NUF_FATAL_IS|1U))||(h->Hcs&0xBU)!=0xBU||h->TrlBaseHi||
  h->TrlBase!=h->FirmwareDmaBase+4096||h->TxPrdt!=12||h->RxPrdt!=12||h->Reorder!=10||
  (h->Coherency!=0&&h->Coherency!=0x11))return 5;
 return 0;}
U32 NufValidateLeasePage(const U8 *p){const N976N_UFS_HANDOFF *h=(const N976N_UFS_HANDOFF*)p;U64 tail=0;
 if(!p)return 1;for(U32 i=336;i<4088;i++)if(p[i])return 2;memcpy(&tail,p+4088,8);
 if(tail!=N976N_UFS_HANDOFF_GUARD)return 3;
 if(NufCrc32(p+4096,4096)!=h->BaselineCrc32)return 4;return 0;}
