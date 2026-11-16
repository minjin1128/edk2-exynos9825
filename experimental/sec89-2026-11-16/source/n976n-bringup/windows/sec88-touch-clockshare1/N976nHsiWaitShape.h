/* SPDX-License-Identifier: GPL-2.0-only
 * Pure diagnostic shape check shared by lifecycle restore and viewer.
 * Never used for MMIO permission, completion, timeout, or cleanup decisions. */
#ifndef N976N_HSI_WAIT_SHAPE_H
#define N976N_HSI_WAIT_SHAPE_H
#include "N976nHsi2c.h"
static __inline int N976nHsiWaitShape(const N976N_HSI_WAIT *W)
{
    const N976N_U8 *B=(const N976N_U8*)W;
    if(!W->Valid){for(N976N_SIZE I=0;I<sizeof(*W);++I)if(B[I])return 0;return 1;}
    if(W->Valid!=1||W->Receive>1||W->MessageIndex!=(W->Receive?2U:1U)||
       (W->Receive?(W->Requested!=1&&W->Requested!=2&&W->Requested!=3&&(W->Requested<16||W->Requested>480||(W->Requested&15U))):(W->Requested!=1&&W->Requested!=3))||W->RunIssued>1||
       W->ClockStarted>1||W->SameClock>W->MaxSameClock||W->MaxSameClock>N976N_HSI_MAX_POLLS||W->MaxSameClock>W->ClockChecks||W->Iterations>N976N_HSI_WAIT_MAX_ITERATIONS||W->ClockChecks>W->Iterations||
       W->Exit<N976nWaitComplete||W->Exit>N976nWaitOther||(W->Seen&~31U)||
       W->Status>N976nHsiClock||W->Phase<(W->Receive?4U:2U)||W->Phase>(W->Receive?5U:3U)||
       (W->First.Valid!=0&&W->First.Valid!=15)||(W->Last.Valid!=0&&W->Last.Valid!=15)||
       W->First.Valid!=W->Last.Valid)return 0;
    if(!W->First.Valid){
        const N976N_U8 *F=(const N976N_U8*)&W->First;
        for(N976N_SIZE I=0;I<sizeof(W->First)+sizeof(W->Last);++I)if(F[I])return 0;
        if(W->Seen||W->ClockChecks)return 0;
    }else if(!W->Iterations||!W->ClockStarted)return 0;
    if(W->First.Valid){
        const N976N_HSI_SAMPLE *S[2]={&W->First,&W->Last};
        for(N976N_SIZE I=0;I<2;++I){
            N976N_U32 F=((S[I]->Auto&0x80000000U)?1U:0U)|((S[I]->Transfer&0x30000U)?2U:0U)|
                (!(S[I]->Fifo&0x01000000U)?4U:0U)|((S[I]->Interrupt&0x80U)?8U:0U)|
                ((S[I]->Interrupt&(~0xFFFU|0xF3CU))?16U:0U);
            if((W->Seen&F)!=F)return 0;
        }
    }
    if(!W->ClockStarted&&(W->StartUs||W->PreviousUs||W->LastNowUs||W->ElapsedUs||W->ClockChecks||W->Iterations))return 0;
    if(W->ClockStarted&&(!W->RunIssued||W->Phase!=(W->Receive?5U:3U)))return 0;
    if(!W->ClockStarted&&W->Phase!=(W->Receive?4U:2U))return 0;
    if(!W->ClockChecks&&(W->PreviousUs||W->LastNowUs||W->ElapsedUs||W->SameClock||W->MaxSameClock))return 0;
    if(W->ClockChecks){
        if(W->Exit==N976nWaitClock){if(W->LastNowUs>=W->PreviousUs||W->ElapsedUs)return 0;}
        else if(W->LastNowUs<W->PreviousUs||W->PreviousUs<W->StartUs||W->ElapsedUs!=W->LastNowUs-W->StartUs)return 0;
    }
    if(W->Exit==N976nWaitComplete){
        if(!W->ClockStarted||!W->Iterations||W->ClockChecks!=W->Iterations-1||
           W->Last.Valid!=15||!(W->Last.Interrupt&0x80U)||!(W->Seen&N976nSeenDone)||
           (W->ClockChecks&&W->ElapsedUs>=N976N_HSI_TIMEOUT_US))return 0;
    }else if(W->Exit==N976nWaitDeadline||W->Exit==N976nWaitClockStall||W->Exit==N976nWaitClock){
        if(!W->ClockStarted||!W->Iterations||W->ClockChecks!=W->Iterations||W->Last.Valid!=15)return 0;
        if(W->Exit==N976nWaitDeadline&&(W->Status!=N976nHsiTimeout||W->ElapsedUs<N976N_HSI_TIMEOUT_US))return 0;
        if(W->Exit==N976nWaitClockStall&&(W->Status!=N976nHsiTimeout||W->SameClock!=N976N_HSI_MAX_POLLS||W->ElapsedUs>=N976N_HSI_TIMEOUT_US))return 0;
        if(W->Exit==N976nWaitClock&&W->Status!=N976nHsiClock)return 0;
    }else if(W->Status==N976nHsiOk)return 0;
    if(W->ClockChecks&&W->PreviousUs<W->StartUs)return 0;
    if(W->Exit!=N976nWaitClock&&W->ClockChecks&&
       ((W->LastNowUs==W->PreviousUs)!=(W->SameClock!=0)))return 0;
    if(W->Exit!=N976nWaitClockStall&&W->MaxSameClock>=N976N_HSI_MAX_POLLS)return 0;
    {
        const N976N_HSI_TRANSITION *T[2]={&W->RunClear,&W->BusyClear};
        for(N976N_SIZE I=0;I<2;++I){
            if(!T[I]->Iteration){const N976N_U8 *Z=(const N976N_U8*)T[I];for(N976N_SIZE J=0;J<sizeof(*T[I]);++J)if(Z[J])return 0;continue;}
            if(T[I]->Reserved||T[I]->Iteration<2||T[I]->Iteration>W->Iterations||T[I]->Sample.Valid!=15||
               !(W->Seen&(I?N976nSeenBusy:N976nSeenRun))||(I?(T[I]->Sample.Transfer&0x30000U):(T[I]->Sample.Auto&0x80000000U)))return 0;
        }
    }
    return 1;
}
/* Shape only: a read-valid operand is not a hardware-success assertion. */
static __inline int N976nHsiEvidenceShape(const N976N_HSI_RESULT *R)
{
    if(!N976nHsiWaitShape(&R->Wait))return 0;
    if (R->DiscardedBytes &&
        (R->FirstPhase != 5 || R->Status != N976nHsiTimeout ||
         !R->Wait.Valid || !R->Wait.Receive || R->Wait.Exit != N976nWaitDeadline ||
         R->Wait.Requested < 16 || R->Wait.Requested > 480 || (R->Wait.Requested & 15U) ||
         !R->RxBytes || R->RxBytes >= R->Wait.Requested ||
         R->DiscardedBytes > R->Wait.Requested - R->RxBytes ||
         (R->Retired && R->DiscardedBytes != R->Wait.Requested - R->RxBytes)))
        return 0;
    for(N976N_SIZE I=0;I<3;++I){
        const N976N_HSI_BOUNDARY *B=&R->Boundary[I];N976N_U32 V=B->Valid;
        if(V&~1023U)return 0;
        if((!(V&1U)&&B->PreStatus)||(!(V&2U)&&B->PreEnable)||
           (!(V&4U)&&B->ArmWanted)||(!(V&8U)&&B->ArmRead)||
           (!(V&16U)&&B->IdleStatus)||(!(V&64U)&&B->MaskRead)||
           (!(V&128U)&&B->Pending)||(!(V&512U)&&B->After))return 0;
        if(I==2&&(V&15U))return 0;
        if((V&2U)&&!(V&1U))return 0;
        if((V&4U)&&((V&3U)!=3U||B->PreStatus||B->PreEnable||B->ArmWanted!=N976N_HSI_COMPLETION_MASK))return 0;
        if((V&8U)&&!(V&4U))return 0;
        if((V&32U)&&!(V&16U))return 0;
        if((V&64U)&&!(V&32U))return 0;
        if((V&128U)&&(!(V&64U)||B->MaskRead))return 0;
        if((V&256U)&&(!(V&128U)||!B->Pending||(B->Pending&~0xFFFU)))return 0;
        if((V&512U)&&(!(V&128U)||(B->Pending&~0xFFFU)||(B->Pending&&!(V&256U))))return 0;
    }
    if(R->Wait.Valid&&R->Wait.RunIssued){
        const N976N_HSI_BOUNDARY *B=&R->Boundary[R->Wait.Receive?1:0];
        if((B->Valid&15U)!=15U||B->ArmRead!=N976N_HSI_COMPLETION_MASK)return 0;
    }
    if(R->Wait.Valid&&R->Wait.MessageIndex==2){
        const N976N_HSI_BOUNDARY *B=&R->Boundary[0];
        if((B->Valid&767U)!=767U||B->ArmRead!=N976N_HSI_COMPLETION_MASK||B->After||
           (B->Pending&(~0xFFFU|0xF3CU)))return 0;
    }
    return 1;
}
#endif
