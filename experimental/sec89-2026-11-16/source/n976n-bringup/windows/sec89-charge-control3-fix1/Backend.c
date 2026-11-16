/* SPDX-License-Identifier: MIT */
#include "Backend.h"
static void BackendZero(void *Destination, N976N_BAT_U64 Bytes)
{
  N976N_BAT_U8 *D=(N976N_BAT_U8 *)Destination;
  while(Bytes--)*D++=0;
}
int N976nBatBackendInit(N976N_BAT_BACKEND *B,const N976N_BAT_BUS_OPS *Ops,
  void *Opaque,const N976N_BAT_BUS_BINDING *Binding,N976N_BAT_U32 Factor,
  const N976N_BAT_U32 SelectedConfig[16])
{
  if(!B||(Factor!=0&&Factor!=2&&Factor!=5))return 0;
  BackendZero(B,sizeof(*B));
  if(!N976nBatBusInit(&B->Bus,Ops,Opaque,Binding)||
     !N976nBatBusBindSelected(&B->Bus,SelectedConfig))return 0;
  B->Factor=Factor;B->Initialized=1;return 1;
}
static N976N_BAT_U64 SampleCore(N976N_BAT_BACKEND *B,N976N_BAT_BACKEND_SAMPLE *S,unsigned Active)
{
  if(!B||!B->Initialized||!S)return N976N_BAT_BUS_INVALID_PARAMETER;
  BackendZero(S,sizeof(*S));
  if(B->Sequence==0xFFFFFFFFFFFFFFFFULL){S->Status=N976N_BAT_BUS_NOT_READY;return S->Status;}
  S->StartedCounter=B->Bus.Ops.Counter(B->Bus.Opaque);
  ++B->Sequence;
  S->Status=Active?N976nBatBusReadActive(&B->Bus,B->Sequence,&S->Raw):
    N976nBatBusSample(&B->Bus,B->Sequence,&S->Raw);
  S->CompletedCounter=B->Bus.Ops.Counter(B->Bus.Opaque);
  if(Active && S->Status && S->Status!=N976N_BAT_BUS_ABORTED &&
     B->Bus.D0Active && B->Bus.Report.Retired==1 && !B->Bus.Quarantined &&
     !B->Bus.Running && !B->Bus.S.InTransaction && !B->Bus.S.Held &&
     !B->Bus.S.RestoreBlocked && !B->Bus.Ops.Cancelled(B->Bus.Opaque) &&
     S->CompletedCounter>=S->StartedCounter &&
     (B->Bus.Report.Reason==0xB112 ||
      (B->Bus.Report.Reason==0xB116 && B->Bus.Report.FirstWaitExit==1)))
    S->CleanReadFailure=1;
  if(S->Status==0 && (Active?B->Bus.D0Active==1:B->Bus.Report.Restored==1) && B->Bus.Report.Retired==1 &&
     !B->Bus.Quarantined && !B->Bus.Running && S->CompletedCounter>=S->StartedCounter &&
     S->Raw.ValidMask==N976N_BAT_ALL_FIELDS &&
     N976nBatteryDecode(&S->Raw,B->Factor,&S->Values))S->Publishable=1;
  else {
    BackendZero(&S->Values,sizeof(S->Values));
    if(S->Status==0)S->Status=N976N_BAT_BUS_DEVICE_ERROR;
  }
  return S->Status;
}

N976N_BAT_U64 N976nBatBackendSample(N976N_BAT_BACKEND *B,N976N_BAT_BACKEND_SAMPLE *S)
{return SampleCore(B,S,0);}
N976N_BAT_U64 N976nBatBackendReadActive(N976N_BAT_BACKEND *B,N976N_BAT_BACKEND_SAMPLE *S)
{return SampleCore(B,S,1);}
