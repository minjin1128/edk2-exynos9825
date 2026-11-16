/* SPDX-License-Identifier: MIT */
#include "Lease.h"
N976N_BAT_U32 N976nBatLeaseCrc(const N976N_BAT_LEASE *L)
{
  N976N_BAT_U32 c=0xFFFFFFFFU; unsigned i,b;
  const N976N_BAT_U8 *p=(const N976N_BAT_U8 *)L;
  if(!L)return 0;
  for(i=0;i<N976N_BAT_LEASE_IMMUTABLE_BYTES;++i) {
    c^=(i>=N976N_BAT_LEASE_CRC_OFFSET&&i<N976N_BAT_LEASE_CRC_OFFSET+4)?0:p[i];
    for(b=0;b<8;b++)c=(c>>1)^((c&1)?0xEDB88320U:0);
  }
  return ~c;
}
int N976nBatLeaseValid(const N976N_BAT_LEASE *L,N976N_BAT_U32 Stage)
{
  if(!L||L->Magic!=N976N_BAT_LEASE_MAGIC||L->Version!=N976N_BAT_LEASE_VERSION||L->Bytes!=sizeof(*L)||
    L->ImmutableBytes!=N976N_BAT_LEASE_IMMUTABLE_BYTES||L->Profile||
    (Stage!=1&&Stage!=2)||L->ProducerStage!=Stage||!L->BootCounter||L->CounterHz!=26000000||
    L->Binding.CounterHz!=L->CounterHz||!N976nBatBusBindingValid(&L->Binding)||
    !N976nBatBusSelectedValid(L->SelectedConfig)||!NcaLeaseValid(&L->Adc)||L->Adc.Generation!=L->BootCounter||
    L->Gic114Masked!=1||L->ProducerRetired!=1||L->ProducerRestored!=1||L->ProducerKind!=N976N_BAT_PRODUCER_GAUGE_USB||L->ClaimReserved||
    L->Guard!=N976N_BAT_LEASE_GUARD||L->Crc32!=N976nBatLeaseCrc(L)||
    !((L->FactorStatus==1&&(L->Factor==2||L->Factor==5))||
      (L->FactorStatus>=2&&L->FactorStatus<=6&&L->Factor==0)))return 0;
  return 1;
}
int N976nBatLeaseOwned(const N976N_BAT_LEASE *Expected,
  const volatile N976N_BAT_LEASE *Current,N976N_BAT_U64 PageGuard)
{
 return N976nBatLeaseValid(Expected,N976N_BAT_LEASE_RELEASED)&&
  N976nBatLeaseMatches(Expected,Current,PageGuard);
}
int N976nBatLeaseMatches(const N976N_BAT_LEASE *Expected,
  const volatile N976N_BAT_LEASE *Current,N976N_BAT_U64 PageGuard)
{
  const N976N_BAT_U8 *a=(const N976N_BAT_U8 *)Expected;
  const volatile N976N_BAT_U8 *b=(const volatile N976N_BAT_U8 *)Current;
  unsigned i;
  if(!Expected||!Current||PageGuard!=N976N_BAT_LEASE_GUARD||
     Current->ClaimState!=N976N_BAT_CLAIM_OWNED||Current->ClaimReserved)return 0;
  for(i=0;i<N976N_BAT_LEASE_IMMUTABLE_BYTES;i++)if(a[i]!=b[i])return 0;
  return Current->ClaimState==N976N_BAT_CLAIM_OWNED&&!Current->ClaimReserved;
}
