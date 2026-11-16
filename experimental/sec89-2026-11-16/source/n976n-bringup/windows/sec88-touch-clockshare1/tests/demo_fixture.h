#ifndef N976N_DEMO_FIXTURE_H
#define N976N_DEMO_FIXTURE_H
#include <stddef.h>
#include <string.h>
#include "N976nDemoContract.h"
static const uint32_t fixture_cmu_offsets[13]={0x2008,0x2024,0x200C,0x2010,0x2018,0x2058,0x2054,0x2094,0x2098,0x3038,0x100,0x280,0x182C};
static void demo_fixture(N976N_TOUCH_HANDOFF *H)
{
    memset(H,0,sizeof(*H));H->Magic=N976N_TOUCH_HANDOFF_MAGIC;H->Version=N976N_TOUCH_HANDOFF_VERSION;
    H->Bytes=sizeof(*H);H->ImmutableBytes=offsetof(N976N_TOUCH_HANDOFF,ClaimState);
    H->ProducerStage=2;H->BootCounter=17;H->CounterHz=26000000;H->InputHz=26000000;
    H->ChipId=0xAC3771;H->BusHz=100000;H->LdoBefore=0x302C;H->LdoEnabled=0xF0EC;
    H->TimingFs[0]=0xFC0000;H->TimingFs[1]=0xF8;H->TimingFs[2]=0x100000;
    H->Cmu[9]=2;H->UsiMode=4;H->GppCon=0x220000;
    H->HsiConf=0x80000000;H->HsiTrailing=0xFFFFFF;H->HsiCtl=8;
    H->HsiFifo=0x30033;H->HsiAuto=0x30003;H->HsiAddr=0x07012000;
    H->Gic420Disabled=1;H->Gic45Disabled=1;H->Eint8Masked=1;
    H->Gpa1Con=0xF;H->Gpa1Pull=0;H->Gpa1EintMask=1;
    H->PowerRequests=8;H->PowerResponses=8;H->PowerRetired=15;H->ProducerChecks=15;
    H->Guard=N976N_TOUCH_HANDOFF_GUARD;H->Crc32=N976nDemoCrc(H);
}
static void demo_bind_regs(const N976N_TOUCH_HANDOFF *H,uint32_t *Maps[7])
{
    for(unsigned i=0;i<13;++i)Maps[1][fixture_cmu_offsets[i]/4]=H->Cmu[i];
    for(unsigned i=0;i<H->ClockCount;++i)Maps[4][H->ClockOffsets[i]/4]=H->ClockValues[i];
    Maps[2][0x1C/4]=H->UsiMode;Maps[0][0xC4/4]=H->UsiControl;Maps[0][0xC8/4]=H->UsiOption;
    Maps[3][0x20/4]=H->GppCon;Maps[3][0x28/4]=H->GppPull;Maps[3][0x2C/4]=H->GppDrive;
    Maps[0][0]=H->HsiCtl;Maps[0][4/4]=H->HsiFifo;Maps[0][0x44/4]=H->HsiAuto;
    Maps[0][0x60/4]=H->TimingFs[0];Maps[0][0x64/4]=H->TimingFs[1];Maps[0][0x68/4]=H->TimingFs[2];
    Maps[0][0x40/4]=H->HsiConf;Maps[0][0x48/4]=H->HsiTimeout;Maps[0][8/4]=H->HsiTrailing;
    Maps[6][0x20/4]=H->Gpa1Con;Maps[6][0x28/4]=H->Gpa1Pull;Maps[6][0x904/4]=H->Gpa1EintMask;
    Maps[0][0x50/4]=1;Maps[0][0x30/4]=0x01000100;
}
#endif
