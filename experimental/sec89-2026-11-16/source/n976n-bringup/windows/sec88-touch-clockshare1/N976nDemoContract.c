/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 FIX2: unchanged admission, with immutable first-refusal operands.
 * Pure fields come from the existing copied NVS snapshot. Fresh diagnostics
 * retain the result of each original read; no failure path performs a reread.
 */
#include "N976nDemoContract.h"
#include <stddef.h>
static const N976N_U32 CmuOffsets[13]={0x2008,0x2024,0x200C,0x2010,0x2018,0x2058,0x2054,0x2094,0x2098,0x3038,0x100,0x280,0x182C};
int N976nDemoReject(N976N_DEMO_DIAGNOSTIC *D,unsigned B,unsigned W,unsigned I,
    unsigned O,N976N_U64 E,N976N_U64 A,N976N_U64 M,int ReadOk)
{
    if(D&&!D->Valid){
        D->Version=N976N_DIAGNOSTIC_VERSION;D->Bytes=sizeof(*D);
        D->Bucket=B;D->Condition=W;D->Index=I;D->Offset=O;
        D->Expected=E;D->Actual=A;D->Mask=M;D->ReadOk=ReadOk?1U:0U;
        /* Only the serialized Prepare path owns this object. Publication via
         * WdfRegistryAssignValue occurs after it returns, never concurrently. */
        D->Valid=N976N_DIAGNOSTIC_VALID;
    }
    return 0;
}
#define REJECT(B,W,I,O,E,A,M) N976nDemoReject(D,B,W,I,O,(N976N_U64)(E),(N976N_U64)(A),(N976N_U64)(M),1)
#define CHECK(C,B,W,I,O,E,A,M) do{if(!(C))return REJECT(B,W,I,O,E,A,M);}while(0)
#define OFF(F) ((unsigned)offsetof(N976N_TOUCH_HANDOFF,F))
#define FIELD(F,E) CHECK(H->F==(E),N976nDiagShape,N976nWhyField,0,OFF(F),E,H->F,~0ULL)
#define MASKED(F,M,E) CHECK((H->F&(M))==(E),N976nDiagShape,N976nWhyField,0,OFF(F),E,H->F,M)
static int Gate(N976N_U32 V){return V!=0xFFFFFFFFU&&((V&0x100000U)?(V&0x200000U)!=0:(V&0x10000000U)==0);}
N976N_U32 N976nDemoCrc(const N976N_TOUCH_HANDOFF *H)
{
    const N976N_U8 *P=(const N976N_U8*)H;N976N_U32 C=0xFFFFFFFFU,I,B;
    if(!H)return 0;
    for(I=0;I<offsetof(N976N_TOUCH_HANDOFF,ClaimState);++I){
        N976N_U8 V=I>=offsetof(N976N_TOUCH_HANDOFF,Crc32)&&I<offsetof(N976N_TOUCH_HANDOFF,Crc32)+4?0:P[I];
        C^=V;for(B=0;B<8;++B)C=(C>>1)^((C&1)?0xEDB88320U:0);
    }return ~C;
}
static int ClockWord(const N976N_TOUCH_HANDOFF *H,N976N_U32 O,N976N_U32 *V,
    N976N_U32 *Used,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U32 I;
    for(I=0;I<H->ClockCount;++I)if(H->ClockOffsets[I]==O){
        CHECK(!(*Used&(1U<<I)),N976nDiagClock,N976nWhyClockReuse,I,O,0,*Used,1U<<I);
        CHECK(H->ClockValues[I]!=0xFFFFFFFFU,N976nDiagClock,N976nWhyClockWord,I,O,0,H->ClockValues[I],0xFFFFFFFFU);
        *Used|=1U<<I;*V=H->ClockValues[I];return 1;
    }
    return REJECT(N976nDiagClock,N976nWhyClockMissing,0,O,1,0,0);
}
static int Pll(N976N_U32 V,N976N_U64 *Hz,N976N_U32 O,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U64 M=(V>>16)&0x3FFU,P=(V>>8)&0x3FU,S=V&7U;
    CHECK(V!=0xFFFFFFFFU,N976nDiagClock,N976nWhyPll,0,O,0,V,0xFFFFFFFFU);
    CHECK(!(V&0x80U),N976nDiagClock,N976nWhyPll,0,O,0,V,0x80U);
    if(!(V&0x10U)){*Hz=26000000;return 1;}
    CHECK((V&0xA0000000U)==0xA0000000U,N976nDiagClock,N976nWhyPll,0,O,0xA0000000U,V,0xA0000000U);
    CHECK(M,N976nDiagClock,N976nWhyPll,1,O,1,M,0x3FFU);
    CHECK(P,N976nDiagClock,N976nWhyPll,2,O,1,P,0x3FU);
    CHECK(S<=6,N976nDiagClock,N976nWhyPll,3,O,6,S,7);
    *Hz=(26000000ULL*M)/(P<<S);
    CHECK(*Hz>=26000000&&*Hz<=4000000000ULL,N976nDiagClock,N976nWhyClockRate,0,O,26000000,*Hz,4000000000ULL);
    return 1;
}
static int ClockValid(const N976N_TOUCH_HANDOFF *H,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U32 M=H->Cmu[11],Div=H->Cmu[12],Used=0,Tm,Td,S,D0,D1,V,I;
    N976N_U64 Hz=26000000;
    CHECK(!(M&~0x10U),N976nDiagClock,N976nWhyField,11,OFF(Cmu)+44,0,M,~0x10U);
    CHECK(!(Div&~15U),N976nDiagClock,N976nWhyField,12,OFF(Cmu)+48,0,Div,~15U);
    CHECK(H->ClockCount<=N976N_TOUCH_CLOCK_MAX,N976nDiagClock,N976nWhyCount,0,OFF(ClockCount),N976N_TOUCH_CLOCK_MAX,H->ClockCount,0);
    if(M&0x10U){
        if(!ClockWord(H,0x20C0,&V,&Used,D))return 0;
        CHECK(Gate(V),N976nDiagClock,N976nWhyGate,0,0x20C0,0,V,0);
        if(!ClockWord(H,0x10BC,&Tm,&Used,D)||!ClockWord(H,0x18A8,&Td,&Used,D))return 0;
        CHECK(!(Tm&~0x10000001U),N976nDiagClock,N976nWhyField,0,0x10BC,0,Tm,~0x10000001U);
        CHECK(!(Td&~0x1000000FU),N976nDiagClock,N976nWhyField,0,0x18A8,0,Td,~0x1000000FU);
        if((Tm&1)==0){
            if(!ClockWord(H,0x10DC,&S,&Used,D)||!ClockWord(H,0x18CC,&D0,&Used,D)||!ClockWord(H,0x18D4,&D1,&Used,D))return 0;
            CHECK(!(S&~0x10000001U),N976nDiagClock,N976nWhyField,0,0x10DC,0,S,~0x10000001U);
            CHECK(!(D0&~0x10000001U),N976nDiagClock,N976nWhyField,0,0x18CC,0,D0,~0x10000001U);
            CHECK(!(D1&~0x10000001U),N976nDiagClock,N976nWhyField,0,0x18D4,0,D1,~0x10000001U);
            if(!ClockWord(H,(S&1)?0x100:0x160,&V,&Used,D)||!Pll(V,&Hz,(S&1)?0x100:0x160,D))return 0;
            Hz/=((D0&1)+1)*((D1&1)+1);
        }else{
            if(!ClockWord(H,0x18E4,&D0,&Used,D))return 0;
            CHECK(!(D0&~0x10000001U),N976nDiagClock,N976nWhyField,0,0x18E4,0,D0,~0x10000001U);
            if(!ClockWord(H,0x1A0,&V,&Used,D)||!Pll(V,&Hz,0x1A0,D))return 0;
            Hz/=(D0&1)+1;
        }Hz/=(Td&15)+1;
    }Hz/=(Div&15)+1;
    CHECK(Used==((1U<<H->ClockCount)-1),N976nDiagClock,N976nWhyClockReuse,0,OFF(ClockCount),(1U<<H->ClockCount)-1,Used,0);
    CHECK(Hz==H->InputHz,N976nDiagClock,N976nWhyClockRate,0,OFF(InputHz),H->InputHz,Hz,0);
    CHECK(Hz>=1600000&&Hz<=400000000,N976nDiagClock,N976nWhyClockRate,0,OFF(InputHz),1600000,Hz,400000000);
    for(I=H->ClockCount;I<N976N_TOUCH_CLOCK_MAX;++I){
        CHECK(!H->ClockOffsets[I],N976nDiagClock,N976nWhyField,I,OFF(ClockOffsets)+4*I,0,H->ClockOffsets[I],0xFFFFFFFFU);
        CHECK(!H->ClockValues[I],N976nDiagClock,N976nWhyField,I,OFF(ClockValues)+4*I,0,H->ClockValues[I],0xFFFFFFFFU);
    }return 1;
}
int N976nDemoValidateHandoffEx(const N976N_TOUCH_HANDOFF *H,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U32 I,Crc;N976N_U64 Div,Shift;
    CHECK(H!=NULL,N976nDiagNvs,N976nWhyDescriptor,0,0,1,0,0);
    FIELD(Magic,N976N_TOUCH_HANDOFF_MAGIC);FIELD(Version,N976N_TOUCH_HANDOFF_VERSION);
    FIELD(Bytes,sizeof(*H));FIELD(ImmutableBytes,offsetof(N976N_TOUCH_HANDOFF,ClaimState));
    Crc=N976nDemoCrc(H);
    CHECK(H->Crc32==Crc,N976nDiagNvs,N976nWhyCrc,0,OFF(Crc32),Crc,H->Crc32,0xFFFFFFFFU);
    FIELD(ProducerStage,N976N_TOUCH_HANDOFF_RELEASED);FIELD(Profile,0);
    CHECK(H->BootCounter,N976nDiagShape,N976nWhyField,0,OFF(BootCounter),1,H->BootCounter,~0ULL);
    CHECK(H->CounterHz,N976nDiagShape,N976nWhyField,0,OFF(CounterHz),1,H->CounterHz,~0ULL);
    FIELD(ChipId,0xAC3771);FIELD(BusHz,100000);FIELD(UsiMode,4);FIELD(UsiControl,0);
    CHECK(H->UsiOption<=7,N976nDiagShape,N976nWhyField,0,OFF(UsiOption),7,H->UsiOption,0);
    MASKED(GppCon,0x00FF0000U,0x00220000U);MASKED(GppPull,0x00FF0000U,0);FIELD(HsiCtl,8);
    CHECK(H->HsiConf!=0xFFFFFFFFU,N976nDiagShape,N976nWhyField,0,OFF(HsiConf),0,H->HsiConf,0xFFFFFFFFU);
    MASKED(HsiConf,0xE0000000U,0x80000000U);MASKED(HsiTimeout,0x80000000U,0);FIELD(HsiTrailing,0xFFFFFFU);
    MASKED(HsiAuto,0x80000000U,0);FIELD(Gic420Disabled,1);FIELD(Gic45Disabled,1);FIELD(Eint8Masked,1);
    CHECK(H->PowerRequests,N976nDiagShape,N976nWhyField,0,OFF(PowerRequests),1,H->PowerRequests,0);
    FIELD(PowerRequests,H->PowerResponses);FIELD(PowerRetired,0xF);FIELD(ProducerChecks,0xF);FIELD(Guard,N976N_TOUCH_HANDOFF_GUARD);
    CHECK(((H->Gpa1Con&15)==0||(H->Gpa1Con&15)==15),N976nDiagShape,N976nWhyField,6,OFF(Gpa1Con),15,H->Gpa1Con,15);
    CHECK(H->Gpa1Pull!=0xFFFFFFFFU&&((H->Gpa1Pull&15)==0||(H->Gpa1Pull&15)==1||(H->Gpa1Pull&15)==3),N976nDiagShape,N976nWhyField,6,OFF(Gpa1Pull),3,H->Gpa1Pull,15);
    CHECK(H->Gpa1EintMask!=0xFFFFFFFFU&&(H->Gpa1EintMask&1),N976nDiagShape,N976nWhyField,6,OFF(Gpa1EintMask),1,H->Gpa1EintMask,1);
    FIELD(Gpa1Reserved,0);
    if(!ClockValid(H,D))return 0;
    for(I=0;I<6;++I)CHECK(!H->Reserved[I],N976nDiagShape,N976nWhyField,I,OFF(Reserved)+8*I,0,H->Reserved[I],~0ULL);
    for(I=0;I<9;++I)CHECK(Gate(H->Cmu[I]),N976nDiagShape,N976nWhyGate,I,OFF(Cmu)+4*I,0,H->Cmu[I],0);
    CHECK(!(H->Cmu[9]&~0x003F0003U),N976nDiagShape,N976nWhyField,9,OFF(Cmu)+36,0,H->Cmu[9],~0x003F0003U);
    MASKED(LdoBefore,0xFFFF0000U,0);MASKED(LdoBefore,0xC0C0U,0);
    MASKED(LdoEnabled,0xFFFF0000U,0);MASKED(LdoEnabled,0xC0C0U,0xC0C0U);
    MASKED(LdoEnabled,~0xC0C0U,H->LdoBefore&~0xC0C0U);
    Div=H->InputHz/1600000U;
    CHECK(Div&&Div<=255,N976nDiagShape,N976nWhyTiming,0,OFF(InputHz),1,Div,255);
    Shift=(25*(H->InputHz/1000000U))/((Div+1)*10);
    CHECK(Shift&&Shift<8,N976nDiagShape,N976nWhyTiming,1,OFF(InputHz),1,Shift,7);
    CHECK((H->TimingFs[0]&0xFF0000U)==(((0xFFU<<(Shift-1))&255)<<16),N976nDiagShape,N976nWhyTiming,0,OFF(TimingFs),((0xFFU<<(Shift-1))&255)<<16,H->TimingFs[0],0xFF0000U);
    CHECK((H->TimingFs[1]&255)==((0xFFU<<Shift)&255),N976nDiagShape,N976nWhyTiming,1,OFF(TimingFs)+4,(0xFFU<<Shift)&255,H->TimingFs[1],255);
    CHECK((H->TimingFs[2]&0xFF0000U)==(Div<<16),N976nDiagShape,N976nWhyTiming,2,OFF(TimingFs)+8,Div<<16,H->TimingFs[2],0xFF0000U);
    return 1;
}
int N976nDemoValidateHandoff(const N976N_TOUCH_HANDOFF *H){return N976nDemoValidateHandoffEx(H,NULL);}
static int ReadOnce(void *C,N976N_DEMO_READ R,N976N_U32 M,N976N_U32 O,N976N_U32 *V,N976N_DEMO_DIAGNOSTIC *D)
{
    *V=0;
    if(!R(C,M,O,V))return N976nDemoReject(D,N976nDiagFresh,N976nWhyRead,M,O,1,0,0,0);
    return 1;
}
static int Eq(void *C,N976N_DEMO_READ R,N976N_U32 M,N976N_U32 O,N976N_U32 E,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U32 V;if(!ReadOnce(C,R,M,O,&V,D))return 0;
    CHECK(V==E,N976nDiagFresh,N976nWhyEqual,M,O,E,V,0xFFFFFFFFU);return 1;
}
int N976nDemoFreshEx(const N976N_TOUCH_HANDOFF *H,void *C,N976N_DEMO_READ Read,N976N_HSI_LEASE *L,N976N_DEMO_DIAGNOSTIC *D)
{
    N976N_U32 I,V;
    if(!L)return N976nDemoReject(D,N976nDiagFresh,N976nWhyDescriptor,0,0,1,0,0,0);
    {N976N_U8 *P=(N976N_U8*)L;for(I=0;I<sizeof(*L);++I)P[I]=0;}
    if(!Read)return N976nDemoReject(D,N976nDiagFresh,N976nWhyDescriptor,0,1,1,0,0,0);
    if(!N976nDemoValidateHandoffEx(H,D))return 0;
    for(I=0;I<13;++I)if(!Eq(C,Read,N976nMapCmu,CmuOffsets[I],H->Cmu[I],D))return 0;
    for(I=0;I<H->ClockCount;++I)if(!Eq(C,Read,N976nMapTop,H->ClockOffsets[I],H->ClockValues[I],D))return 0;
#define EQ(M,O,E) do{if(!Eq(C,Read,M,O,E,D))return 0;}while(0)
    EQ(N976nMapUsi,0x1C,H->UsiMode);EQ(N976nMapHsi,0xC4,H->UsiControl);EQ(N976nMapHsi,0xC8,H->UsiOption);
    EQ(N976nMapPins,0x20,H->GppCon);EQ(N976nMapPins,0x28,H->GppPull);EQ(N976nMapPins,0x2C,H->GppDrive);
    EQ(N976nMapHsi,0x60,H->TimingFs[0]);EQ(N976nMapHsi,0x64,H->TimingFs[1]);EQ(N976nMapHsi,0x68,H->TimingFs[2]);
    EQ(N976nMapHsi,0x40,H->HsiConf);EQ(N976nMapHsi,0x48,H->HsiTimeout);EQ(N976nMapHsi,8,H->HsiTrailing);
    EQ(N976nMapHsi,0x20,0);EQ(N976nMapHsi,0x24,0);
    if(!ReadOnce(C,Read,N976nMapHsi,0x50,&V,D))return 0;
    CHECK(V!=0xFFFFFFFFU,N976nDiagFresh,N976nWhyIdle,N976nMapHsi,0x50,0,V,0xFFFFFFFFU);
    CHECK(!(V&0x30000U),N976nDiagFresh,N976nWhyIdle,N976nMapHsi,0x50,0,V,0x30000U);
    CHECK((V&15)<=1,N976nDiagFresh,N976nWhyIdle,N976nMapHsi,0x50,1,V,15);
    if(!ReadOnce(C,Read,N976nMapHsi,0x30,&V,D))return 0;
    CHECK((V&0x01FF01FFU)==0x01000100U,N976nDiagFresh,N976nWhyMasked,N976nMapHsi,0x30,0x01000100U,V,0x01FF01FFU);
    if(!ReadOnce(C,Read,N976nMapHsi,0x44,&V,D))return 0;
    CHECK(V!=0xFFFFFFFFU,N976nDiagFresh,N976nWhyIdle,N976nMapHsi,0x44,0,V,0xFFFFFFFFU);
    CHECK(!(V&0x80000000U),N976nDiagFresh,N976nWhyIdle,N976nMapHsi,0x44,0,V,0x80000000U);
    /* GPA1 is shared: bind only the owned pin0 fields, never unrelated pins. */
    if(!ReadOnce(C,Read,N976nMapAlive,0x20,&V,D))return 0;
    CHECK((V&15)==(H->Gpa1Con&15),N976nDiagFresh,N976nWhyMasked,6,0x20,H->Gpa1Con,V,15);
    if(!ReadOnce(C,Read,N976nMapAlive,0x28,&V,D))return 0;
    CHECK(V!=0xFFFFFFFFU&&(V&15)==(H->Gpa1Pull&15),N976nDiagFresh,N976nWhyMasked,6,0x28,H->Gpa1Pull,V,15);
    if(!ReadOnce(C,Read,N976nMapAlive,0x904,&V,D))return 0;
    CHECK(V!=0xFFFFFFFFU&&(V&1)==1,N976nDiagFresh,N976nWhyMasked,6,0x904,1,V,1);
    L->Generation=H->BootCounter;L->Base=0x104B0000;L->Bytes=0x1000;L->InputHz=H->InputHz;
    L->Flags=N976nHsiLeaseRequired;L->Address=0x48;L->SpeedHz=100000;
    L->TimingFs1=H->TimingFs[0];L->TimingFs2=H->TimingFs[1];L->TimingFs3=H->TimingFs[2];L->Timeout=H->HsiTimeout;L->Trailing=H->HsiTrailing;
    return 1;
}
int N976nDemoFresh(const N976N_TOUCH_HANDOFF *H,void *C,N976N_DEMO_READ Read,N976N_HSI_LEASE *L)
{return N976nDemoFreshEx(H,C,Read,L,NULL);}
