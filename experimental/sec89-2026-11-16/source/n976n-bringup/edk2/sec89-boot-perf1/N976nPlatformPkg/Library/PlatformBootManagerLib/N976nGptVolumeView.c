/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#include "N976nGptVolumeView.h"
static void cp(void *d,const void *s,NV_U32 n){NV_U8 *a=d;const NV_U8 *b=s;while(n--)*a++=*b++;}
static int eq(const void *x,const void *y,NV_U32 n){const NV_U8 *a=x,*b=y;while(n--)if(*a++!=*b++)return 0;return 1;}
static int nz(const void *x,NV_U32 n){const NV_U8 *a=x;while(n--)if(*a++)return 1;return 0;}
static NV_U32 rd32(const NV_U8 *p){return p[0]|((NV_U32)p[1]<<8)|((NV_U32)p[2]<<16)|((NV_U32)p[3]<<24);}
static NV_U64 rd64(const NV_U8 *p){return rd32(p)|((NV_U64)rd32(p+4)<<32);}
static void wr32(NV_U8 *p,NV_U32 v){for(NV_U32 n=0;n<4;n++)p[n]=(NV_U8)(v>>(8*n));}
static void wr64(NV_U8 *p,NV_U64 v){for(NV_U32 n=0;n<8;n++)p[n]=(NV_U8)(v>>(8*n));}
static NV_U32 bytecrc(NV_U32 c,NV_U8 b){c^=b;for(unsigned n=0;n<8;n++)c=(c>>1)^((0U-(c&1))&0xEDB88320U);return c;}
static NV_U32 crc(const NV_U8 *p,NV_U32 n){NV_U32 c=~0U;while(n--)c=bytecrc(c,*p++);return ~c;}
static NV_U32 hcrc(const NV_U8 *p,NV_U32 n){NV_U32 c=~0U;for(NV_U32 i=0;i<n;i++)c=bytecrc(c,i>=16&&i<20?0:p[i]);return ~c;}
static int overlaps(const void *a,NV_U32 an,const void *b,NV_U32 bn){
 NV_U64 x=(NV_U64)a,y=(NV_U64)b;if(x>~(NV_U64)0-an||y>~(NV_U64)0-bn)return 1;
 return x<y+bn&&y<x+an;
}
/* Only private immutable state may be supplied. Cheap dependent bounds are
 * rechecked on each read; no array address relies on unchecked saved scalars. */
static int sealed(const NUV_VIEW *v){
 if(!v||v->Ready!=1||v->Reason||v->LastLba<11||!v->EntryCount||v->EntryCount>128||
    v->ArrayBlocks!=(v->EntryCount*128+4095)/4096||v->TargetIndex>=v->EntryCount)return 0;
 for(unsigned side=0;side<2;side++){
  NV_U64 base=side?v->LastLba-4:2;const NV_U8 *h=v->Header[side];
  if(v->EntryLba[side]<base||v->EntryLba[side]>=base+4||v->ArrayBlocks>base+4-v->EntryLba[side]||
     rd64(h+72)!=v->EntryLba[side]||rd32(h+80)!=v->EntryCount||rd32(h+84)!=128||
     rd64(h+24)!=(side?v->LastLba:1)||rd64(h+32)!=(side?1:v->LastLba))return 0;
 }
 if(!v->Policy.RawBlocks||!v->Policy.ViewBlocks||v->Policy.ViewBlocks>v->Policy.RawBlocks||
    v->Policy.Start>v->LastLba||v->Policy.RawBlocks-1>v->LastLba-v->Policy.Start)return 0;
 const NV_U8 *e=v->Array[0]+(NV_U32)(v->EntryLba[0]-2)*4096+v->TargetIndex*128;
 return eq(v->Policy.DiskGuid,v->Header[0]+56,16)&&eq(v->Policy.PartitionGuid,e+16,16)&&
   rd64(e+32)==v->Policy.Start&&rd64(e+40)-rd64(e+32)+1==v->Policy.RawBlocks;
}
static int fail(NUV_VIEW *v,NV_U32 r){v->Ready=0;v->Reason=r;return 0;}
void NuvViewReset(NUV_VIEW *v){if(v){NV_U8 *p=(NV_U8*)v;for(NV_U32 n=0;n<sizeof(*v);n++)p[n]=0;}}
static int slot(NV_U64 last,NV_U64 lba,NV_U32 *side,NV_U32 *block,NV_U32 *bit){
 if(last<11||lba>last)return 0;
 if(lba==1||lba==last){*side=lba==1?0:1;*block=4;*bit=*side;return 1;}
 if(lba>=2&&lba<=5){*side=0;*block=(NV_U32)(lba-2);*bit=2+*block;return 1;}
 if(lba>=last-4&&lba<last){*side=1;*block=(NV_U32)(lba-(last-4));*bit=6+*block;return 1;}return 0;
}
int NuvViewCapture(NUV_VIEW *v,NV_U64 last,NV_U64 lba,const void *p,NV_U32 bytes){
 NV_U32 side,block,bit;if(!v||!p||bytes!=4096||overlaps(v,sizeof(*v),p,bytes))return 0;
 if(v->Ready||v->Reason)return 0;
 if(!slot(last,lba,&side,&block,&bit)||(v->Mask&&v->LastLba!=last))return fail(v,NuvCapture);
 NV_U8 *out=block==4?v->Header[side]:v->Array[side]+block*4096;
 if(v->Mask&(1U<<bit)){if(!eq(out,p,4096))return fail(v,NuvDrift);return 1;}
 cp(out,p,4096);v->LastLba=last;v->Mask|=1U<<bit;return 1;
}
static int header(NUV_VIEW *v,unsigned side){
 const NV_U8 *p=v->Header[side];NV_U32 size=rd32(p+12),count=rd32(p+80),blocks=(count*128+4095)/4096;
 NV_U64 start=rd64(p+72),first=rd64(p+40),last=rd64(p+48),base=side?v->LastLba-4:2;
 if(!eq(p,"EFI PART",8)||rd32(p+8)!=0x10000||size<92||size>4096||rd32(p+20)||
    rd32(p+16)!=hcrc(p,size)||nz(p+92,4096-92)||rd64(p+24)!=(side?v->LastLba:1)||
    rd64(p+32)!=(side?1:v->LastLba)||first<6||last<first||last>v->LastLba-5||
    !nz(p+56,16)||!count||count>128||rd32(p+84)!=128||start<base||start>=base+4||blocks>base+4-start)return 0;
 NV_U32 offset=(NV_U32)(start-base),mask=((1U<<blocks)-1)<<(2+side*4+offset);
 if((v->Mask&mask)!=mask)return 0;
 const NV_U8 *a=v->Array[side]+offset*4096;
 if(crc(a,count*128)!=rd32(p+88))return 0;
 v->EntryLba[side]=start;v->EntryCount=count;v->ArrayBlocks=blocks;return 1;
}
int NuvViewSeal(NUV_VIEW *v,const NUV_POLICY *policy){
 static const NV_U8 basic[16]={0xA2,0xA0,0xD0,0xEB,0xE5,0xB9,0x33,0x44,0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7};
 if(!v||!policy||overlaps(v,sizeof(*v),policy,sizeof(*policy)))return 0;if(v->Ready||v->Reason)return 0;
 if((v->Mask&3)!=3||!header(v,0)||!header(v,1))return fail(v,NuvHeader);
 const NV_U8 *h=v->Header[0],*b=v->Header[1];
 if(!eq(h+40,b+40,32)||!eq(h+80,b+80,12))return fail(v,NuvHeader);
 NV_U8 *a=v->Array[0]+(NV_U32)(v->EntryLba[0]-2)*4096;
 const NV_U8 *ab=v->Array[1]+(NV_U32)(v->EntryLba[1]-(v->LastLba-4))*4096;
 if(!eq(a,ab,v->EntryCount*128))return fail(v,NuvArray);
 if(!nz(policy->DiskGuid,16)||!nz(policy->PartitionGuid,16)||!eq(policy->DiskGuid,h+56,16))return fail(v,NuvIdentity);
 if(!policy->RawBlocks||!policy->ViewBlocks||policy->ViewBlocks>policy->RawBlocks||
    policy->Start>v->LastLba||policy->RawBlocks-1>v->LastLba-policy->Start)return fail(v,NuvExtent);
 NV_U32 matches=0;NV_U64 first=rd64(h+40),last=rd64(h+48);
 for(NV_U32 n=0;n<v->EntryCount;n++){
  const NV_U8 *e=a+n*128;if(!nz(e,16))continue;
  NV_U64 s=rd64(e+32),end=rd64(e+40);
  if(!nz(e+16,16)||s<first||end<s||end>last)return fail(v,NuvExtent);
  for(NV_U32 j=0;j<n;j++){const NV_U8 *q=a+j*128;if(!nz(q,16))continue;
   if(eq(e+16,q+16,16)||(s<=rd64(q+40)&&rd64(q+32)<=end))return fail(v,NuvExtent);}
  if(!eq(e+16,policy->PartitionGuid,16))continue;
  matches++;v->TargetIndex=n;
  if(!eq(e,basic,16)||rd64(e+48)||s!=policy->Start||end-s+1!=policy->RawBlocks)return fail(v,NuvIdentity);
  for(NV_U32 j=0;j<36;j++)if(e[56+j*2]!=(j<8?(NV_U8)"userdata"[j]:0)||e[57+j*2])return fail(v,NuvIdentity);
 }
 if(matches!=1)return fail(v,NuvIdentity);
 cp(&v->Policy,policy,sizeof(*policy));NV_U8 endbytes[8];wr64(endbytes,policy->Start+policy->ViewBlocks-1);
 NV_U32 c=~0U,at=v->TargetIndex*128+40;
 for(NV_U32 n=0;n<v->EntryCount*128;n++)c=bytecrc(c,n>=at&&n<at+8?endbytes[n-at]:a[n]);v->ViewArrayCrc=~c;
 for(unsigned side=0;side<2;side++){NV_U8 out[92];cp(out,v->Header[side],92);wr32(out+12,92);wr32(out+88,v->ViewArrayCrc);v->HeaderCrc[side]=hcrc(out,92);}
 v->Ready=1;return 1;
}
int NuvViewContains(const NUV_VIEW *v,NV_U64 lba){
 if(!sealed(v))return 0;
 if(lba==1||lba==v->LastLba)return 1;
 for(unsigned side=0;side<2;side++)if(lba>=v->EntryLba[side]&&lba-v->EntryLba[side]<v->ArrayBlocks)return 1;return 0;
}
int NuvViewApply(const NUV_VIEW *v,NV_U64 lba,void *buffer,NV_U32 bytes,NV_U32 *changed){
 if(!sealed(v)||!buffer||bytes!=4096||lba>v->LastLba||overlaps(v,sizeof(*v),buffer,bytes)||
    (changed&&(overlaps(v,sizeof(*v),changed,sizeof(*changed))||overlaps(buffer,bytes,changed,sizeof(*changed)))))return 0;
 if(changed)*changed=0;
 NV_U8 *out=buffer;if(!NuvViewContains(v,lba))return 1;
 if(lba==1||lba==v->LastLba){unsigned side=lba==1?0:1;if(!eq(out,v->Header[side],4096))return 0;
  if(changed)*changed=rd32(out+12)!=92||rd32(out+16)!=v->HeaderCrc[side]||rd32(out+88)!=v->ViewArrayCrc;
  wr32(out+12,92);wr32(out+16,v->HeaderCrc[side]);wr32(out+88,v->ViewArrayCrc);return 1;}
 unsigned side=lba<v->EntryLba[1]?0:1;NV_U64 base=side?v->LastLba-4:2;
 if(!eq(out,v->Array[side]+(NV_U32)(lba-base)*4096,4096))return 0;
 NV_U32 at=v->TargetIndex*128+40,block=(NV_U32)(lba-v->EntryLba[side]);
 if(at/4096==block){NV_U64 end=v->Policy.Start+v->Policy.ViewBlocks-1;if(changed)*changed=rd64(out+at%4096)!=end;wr64(out+at%4096,end);}return 1;
}
