#include "ClockShare.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
static unsigned Cases;
#define CHECK(X)do{++Cases;if(!(X)){fprintf(stderr,"line %u: %s\n",__LINE__,#X);exit(1);}}while(0)
static IO_RESOURCE_DESCRIPTOR Top(unsigned Flags)
{
  IO_RESOURCE_DESCRIPTOR D;
  memset(&D,0xA5,sizeof(D));
  D.Type=CmResourceTypeMemory;D.ShareDisposition=CmResourceShareDeviceExclusive;
  D.Flags=(USHORT)Flags;D.Option=0;D.u.Memory.Length=N976N_CLOCK_SHARE_BYTES;
  D.u.Memory.Alignment=1;D.u.Memory.MinimumAddress.QuadPart=N976N_CLOCK_SHARE_BASE;
  D.u.Memory.MaximumAddress.QuadPart=N976N_CLOCK_SHARE_END;
  return D;
}
static MOCK_REQUIREMENTS Fixture(void)
{
  MOCK_REQUIREMENTS R={0};R.Count=2;
  for(unsigned I=0;I<2;++I){
    MOCK_REQ_LIST *L=&R.Lists[I];L->Count=4;
    L->Items[0]=Top(0);L->Items[0].u.Memory.MinimumAddress.QuadPart=0x104B0000;
    L->Items[1]=Top(I);L->Items[1].Option=(UCHAR)I;
    L->Items[2]=Top(1);L->Items[2].Option=8; /* Exact alternative too. */
    L->Items[3]=Top(0);L->Items[3].Type=CmResourceTypeInterrupt;
  }
  return R;
}
static CM_PARTIAL_RESOURCE_DESCRIPTOR Assigned(unsigned Flags)
{
  CM_PARTIAL_RESOURCE_DESCRIPTOR D={0};D.Type=CmResourceTypeMemory;
  D.ShareDisposition=CmResourceShareShared;D.Flags=(USHORT)Flags;
  D.u.Memory.Start.QuadPart=N976N_CLOCK_SHARE_BASE;D.u.Memory.Length=N976N_CLOCK_SHARE_BYTES;
  return D;
}
int main(void)
{
  MOCK_REQUIREMENTS R=Fixture(),Before=R;
  MOCK_DEVICE_INIT Init={0};
  N976nClockShareRegister(&Init);
  CHECK(Init.Registered==1&&Init.Callbacks.EvtDeviceFilterRemoveResourceRequirements==N976nClockShareFilter);
  CHECK(N976nClockShareFilter(NULL,&R)==STATUS_SUCCESS);
  for(unsigned A=0;A<R.Count;++A){
    CHECK(R.Lists[A].UpdatedMask==6&&R.Lists[A].Updates==2);
    for(unsigned I=0;I<R.Lists[A].Count;++I){
      IO_RESOURCE_DESCRIPTOR Expected=Before.Lists[A].Items[I];
      if(I==1||I==2)Expected.ShareDisposition=CmResourceShareShared;
      CHECK(!memcmp(&Expected,&R.Lists[A].Items[I],sizeof(Expected)));
    }
  }
  Before=R;
  CHECK(N976nClockShareFilter(NULL,&R)==STATUS_SUCCESS&&!memcmp(&R,&Before,sizeof(R)));
  CHECK(N976nClockShareFilter(NULL,NULL)==STATUS_INVALID_PARAMETER);
  R=Fixture();R.Count=0;Before=R;
  CHECK(N976nClockShareFilter(NULL,&R)==STATUS_DEVICE_CONFIGURATION_ERROR&&!memcmp(&R,&Before,sizeof(R)));
  /* Malformed later logical alternative must not partially change the first. */
  for(unsigned Kind=0;Kind<10;++Kind){
    R=Fixture();R.Lists[1].Count=1;R.Lists[1].Items[0]=Top(1);
    IO_RESOURCE_DESCRIPTOR *D=&R.Lists[1].Items[0];
    switch(Kind){
    case 0:D->u.Memory.MinimumAddress.QuadPart++;break;
    case 1:D->u.Memory.MaximumAddress.QuadPart--;break;
    case 2:D->u.Memory.MaximumAddress.QuadPart++;break;
    case 3:D->u.Memory.Length--;break;
    case 4:D->u.Memory.Length++;break;
    case 5:D->Flags=CM_RESOURCE_MEMORY_PREFETCHABLE|CM_RESOURCE_MEMORY_READ_ONLY;break;
    case 6:D->ShareDisposition=0;break;
    case 7:D->Type=CmResourceTypeMemoryLarge;break;
    case 8:D->u.Memory.MinimumAddress.QuadPart=-1;break;
    case 9:R.Lists[1].Count=0;break;
    }
    Before=R;CHECK(N976nClockShareFilter(NULL,&R)==STATUS_DEVICE_CONFIGURATION_ERROR);
    CHECK(!memcmp(&R,&Before,sizeof(R)));
  }
  for(unsigned Flags=0;Flags<2;++Flags){
    CM_PARTIAL_RESOURCE_DESCRIPTOR A=Assigned(Flags),B=A;
    CHECK(N976nClockSharePreparePair(&A,&B));
    for(unsigned Kind=0;Kind<11;++Kind){
      B=A;switch(Kind){
      case 0:B.ShareDisposition=CmResourceShareDeviceExclusive;break;
      case 1:B.Flags^=1;break;
      case 2:B.Flags|=CM_RESOURCE_MEMORY_PREFETCHABLE;break;
      case 3:B.Type=CmResourceTypeMemoryLarge;break;
      case 4:B.u.Memory.Start.QuadPart++;break;
      case 5:B.u.Memory.Start.QuadPart--;break;
      case 6:B.u.Memory.Length--;break;
      case 7:B.u.Memory.Length++;break;
      case 8:B.u.Memory.Start.QuadPart=-1;break;
      case 9:B.u.Memory.Start.QuadPart=0x104B0000;break;
      case 10:B.ShareDisposition=2;break;
      }
      CHECK(!N976nClockSharePreparePair(&A,&B));
      CHECK(!N976nClockSharePreparePair(&B,&A));
    }
    CHECK(!N976nClockSharePreparePair(NULL,&A));
    CHECK(!N976nClockSharePreparePair(&A,NULL));
  }
  printf("PASS %u cases: exact TOP shared resource filter + assignment\n",Cases);
  return 0;
}
