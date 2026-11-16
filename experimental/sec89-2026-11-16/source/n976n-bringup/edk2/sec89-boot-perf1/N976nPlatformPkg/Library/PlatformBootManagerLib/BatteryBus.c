/* SPDX-License-Identifier: MIT
 * SEC88 BAT1 independent snapshot transport, derived from this project's
 * SEC88 SMP2 UartMux.c clock/pin/transaction/restore core. Baseline untouched.
 * Source references and reuse delta: references/sec88-battery1/reference-analysis.md.
 * Only allowlisted MAX77705 gauge/charger register reads are issued. A register
 * pointer byte is the only target TX payload; no charger/PD/MUIC opcodes,
 * voltage/current policy, GPIO DAT, PLL, storage or GIC writes exist here.
 */
#include <BatteryBus.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>

#define CMGP 0x15C00000U
#define APM  0x15800000U
#define TOP  0x1A240000U
#define GPIO 0x15C30000U
#define MODE 0x15C22030U
#define HSI  0x15D60000U
#define QCH  (CMGP + 0x304C)
#define CTL 0x00
#define FIFO_CTL 0x04
#define TRAILING 0x08
#define INT_EN 0x20
#define INT_ST 0x24
#define FIFO_ST 0x30
#define TX 0x34
#define RX 0x38
#define CONF 0x40
#define AUTO 0x44
#define TIMEOUT 0x48
#define TRANS 0x50
#define FS1 0x60
#define FS2 0x64
#define FS3 0x68
#define ADDR 0x70
#define USI_CON 0xC4
#define USI_OPTION 0xC8
#define INT_DONE BIT7
#define INT_ERRORS (0xF00U | 0x3CU)
#define INT_KNOWN 0xFFFU
#define AUTO_RUN BIT31
#define AUTO_STOP BIT17
#define AUTO_READ BIT16
#define HSI_BUSY (BIT17 | BIT16)
#define STALL_LIMIT 20000U

volatile N976N_BATTERY_BUS_REPORT mN976nBatteryBusReport;
STATIC BOOLEAN mTried, mHeld, mHsiSaved, mHsiChanged;
STATIC BOOLEAN mOuterChanged, mPinsChanged;
STATIC BOOLEAN mRestoreBlocked;
STATIC UINT64 mHz;
STATIC UINT32 mSavedQch, mSavedMode, mGpio[6], mSaved[16];
STATIC CONST UINT32 mConfigOffsets[16] = {
  CTL, FIFO_CTL, TRAILING, INT_EN, CONF, AUTO, TIMEOUT,
  0x54, 0x58, 0x5C, FS1, FS2, FS3, ADDR, USI_CON, USI_OPTION
};
STATIC CONST UINT32 mGpioOffsets[6] = {0x180,0x188,0x18C,0x1A0,0x1A8,0x1AC};
STATIC UINTN mClockAddress[32], mClockCount;
STATIC UINT32 mClockValue[32];
STATIC BOOLEAN mCompareValid, mCompareLocked, mSampleValid, mWaitValid;
STATIC UINT64 mCompareAddress, mCompareExpected, mCompareActual, mCompareMask, mCompareKind;

typedef struct { UINT64 Start, Previous; UINT32 Same; } DEADLINE;
STATIC UINT32 Rd (UINTN A) { return MmioRead32 (A); }
STATIC VOID Wr (UINTN A, UINT32 V)
{
  mN976nBatteryBusReport.NoMutation=0;
  MmioWrite32 (A,V); MemoryFence ();
}
/* Staging a failed predicate is not a failure decision: idle polling may later
 * succeed. Fail() alone freezes the first fatal observation before cleanup.
 * Every Actual argument is from a read already performed by the original core.
 */
STATIC BOOLEAN Different (UINTN A, UINT64 E, UINT64 V, UINT64 M, UINT64 Kind)
{
  if (mCompareLocked) return FALSE;
  mCompareValid=TRUE; mCompareAddress=A; mCompareExpected=E;
  mCompareActual=V; mCompareMask=M; mCompareKind=Kind; return FALSE;
}
STATIC BOOLEAN Accessible (UINTN A, UINT32 V)
{
  return V!=MAX_UINT32 || Different(A,MAX_UINT32,V,MAX_UINT32,2);
}
STATIC BOOLEAN Equal (UINTN A, UINT32 V, UINT32 E, UINT32 M)
{
  return ((V^E)&M)==0 || Different(A,E,V,M,1);
}
STATIC VOID Fail (UINT64 Why, EFI_STATUS Status)
{
  if (!mN976nBatteryBusReport.Reason) {
    mN976nBatteryBusReport.Reason=Why;
    mN976nBatteryBusReport.Status=Status;
    mN976nBatteryBusReport.FailurePhase=mN976nBatteryBusReport.Phase;
    mN976nBatteryBusReport.PinFailurePhase=mN976nBatteryBusReport.PinPhase;
    mN976nBatteryBusReport.CaptureValid|=BIT0;
    if (mCompareValid) {
      mN976nBatteryBusReport.CaptureValid|=BIT1;
      mN976nBatteryBusReport.FirstAddress=mCompareAddress;
      mN976nBatteryBusReport.FirstExpected=mCompareExpected;
      mN976nBatteryBusReport.FirstActual=mCompareActual;
      mN976nBatteryBusReport.FirstMask=mCompareMask;
      mN976nBatteryBusReport.FirstCompare=mCompareKind;
    }
    if (mSampleValid) mN976nBatteryBusReport.CaptureValid|=BIT2;
    if (mWaitValid) mN976nBatteryBusReport.CaptureValid|=BIT3;
    mN976nBatteryBusReport.FirstInterrupt=mN976nBatteryBusReport.Interrupt;
    mN976nBatteryBusReport.FirstTransfer=mN976nBatteryBusReport.Transfer;
    mN976nBatteryBusReport.FirstFifo=mN976nBatteryBusReport.Fifo;
    mN976nBatteryBusReport.FirstAuto=mN976nBatteryBusReport.Auto;
    mN976nBatteryBusReport.FirstWaitUs=mN976nBatteryBusReport.WaitUs;
    mN976nBatteryBusReport.FirstWaitExit=mN976nBatteryBusReport.WaitExit;
    mN976nBatteryBusReport.FirstTransfers=mN976nBatteryBusReport.Transfers;
    mN976nBatteryBusReport.FirstTxBytes=mN976nBatteryBusReport.TxBytes;
    mN976nBatteryBusReport.FirstRxBytes=mN976nBatteryBusReport.RxBytes;
  }
}
STATIC DEADLINE Begin (VOID)
{
  DEADLINE D; D.Start=D.Previous=GetPerformanceCounter (); D.Same=0; return D;
}
STATIC BOOLEAN Expired (DEADLINE *D, UINT32 Us)
{
  UINT64 Now=GetPerformanceCounter (), Elapsed=Now-D->Start;
  mWaitValid=TRUE;
  if (Now < D->Previous) { mN976nBatteryBusReport.WaitExit=3; return TRUE; }
  D->Same=Now==D->Previous ? D->Same+1 : 0; D->Previous=Now;
  mN976nBatteryBusReport.WaitUs=Elapsed*1000000/mHz;
  if (Elapsed >= (mHz*Us+999999)/1000000) {
    mN976nBatteryBusReport.WaitExit=1; return TRUE;
  }
  if (D->Same >= STALL_LIMIT) { mN976nBatteryBusReport.WaitExit=2; return TRUE; }
  return FALSE;
}
STATIC BOOLEAN Set (UINTN A, UINT32 V, UINT32 Mask)
{
  UINT32 Actual; Wr(A,V); Actual=Rd(A);
  if (Actual!=MAX_UINT32 && ((Actual^V)&Mask)==0) return TRUE;
  mN976nBatteryBusReport.SetupOffset=A;
  mN976nBatteryBusReport.SetupExpected=V;
  mN976nBatteryBusReport.SetupActual=Actual;
  mN976nBatteryBusReport.SetupDiff++;
  if (!Accessible(A,Actual)) return FALSE;
  return Different(A,V,Actual,Mask,1);
}
STATIC BOOLEAN Gate (UINT32 V)
{
  UINTN A=(UINTN)mN976nBatteryBusReport.ClockAddress;
  mN976nBatteryBusReport.GateAddress=A; mN976nBatteryBusReport.GateValue=V;
  mN976nBatteryBusReport.CaptureValid|=BIT4;
  return Accessible(A,V) && ((V&BIT20) ? Equal(A,V,BIT21,BIT21) : Equal(A,V,0,BIT28));
}
STATIC UINT32 Clock (UINTN A)
{
  UINT32 V=Rd(A);
  mN976nBatteryBusReport.ClockAddress=A; mN976nBatteryBusReport.ClockValue=V;
  if (mClockCount>=ARRAY_SIZE(mClockAddress)) return MAX_UINT32;
  mClockAddress[mClockCount]=A; mClockValue[mClockCount++]=V; return V;
}
STATIC BOOLEAN ClockStable (VOID)
{
  for (UINTN I=0; I<mClockCount; I++)
    if (!Equal(mClockAddress[I],Rd(mClockAddress[I]),mClockValue[I],MAX_UINT32)) return FALSE;
  return TRUE;
}
STATIC BOOLEAN Field (UINT32 V, UINT32 Mask, UINT32 Busy)
{
  /* Only SELECT/DIVRATIO and BUSY define this rate. Unrelated register policy
   * fields must not become a guessed all-bits-zero prerequisite. */
  (VOID)Mask;
  return V!=MAX_UINT32 && !(V&Busy);
}
STATIC BOOLEAN Pll (UINT32 V, UINT64 *Hz)
{
  UINT32 M=(V>>16)&0x3FF, P=(V>>8)&63, S=V&7;
  if (V==MAX_UINT32 || (V&BIT7)) return FALSE;
  if (!(V&BIT4)) { *Hz=26000000; return TRUE; }
  if ((V&(BIT31|BIT29))!=(BIT31|BIT29) || !M || !P || S>6) return FALSE;
  *Hz=26000000ULL*M/(P<<S); return *Hz>=26000000 && *Hz<=4000000000ULL;
}
/* Resolve inherited CMGP3 source, including APM and the two source PLL paths.
 * No shared clock is retuned. Fixed RCO/DLL rates come from cmucal-node.c.
 */
STATIC BOOLEAN InputClock (VOID)
{
  UINT32 M=Clock(CMGP+0x1020), D=Clock(CMGP+0x1824), U, A, AD, S, TD, PD;
  UINT64 Hz=49152000;
  if (!Field(M,1,BIT16) || !Field(D,15,BIT16)) return FALSE;
  if (M&1) {
    U=Clock(CMGP+0x100);
    if (!Field(U,BIT4,BIT7)) return FALSE;
    if (U&BIT4) {
      if (!Gate(Clock(APM+0x200C))) return FALSE;
      A=Clock(APM+0x1004); AD=Clock(APM+0x1804);
      if (!Field(A,3,BIT16) || !Field(AD,7,BIT16)) return FALSE;
      switch (A&3) {
        case 0: case 3:
          U=Clock(APM+0x120); if (!Field(U,BIT4,BIT7)) return FALSE; break;
        case 2:
          U=Clock(APM+0x140); if (!Field(U,BIT4,BIT7)) return FALSE;
          if (U&BIT4) Hz=360000000; break;
        case 1:
          U=Clock(APM+0x100); if (!Field(U,BIT4,BIT7)) return FALSE;
          if (U&BIT4) {
            if (!Gate(Clock(TOP+0x2018))) return FALSE;
            S=Clock(TOP+0x1004); TD=Clock(TOP+0x1800);
            if (!Field(S,1,BIT16) || !Field(TD,3,BIT16)) return FALSE;
            if (!(S&1)) {
              S=Clock(TOP+0x10DC); PD=Clock(TOP+0x18D0);
              if (!Field(S,1,BIT16) || !Field(PD,3,BIT16) ||
                  !Pll(Clock(TOP+((S&1)?0x100:0x160)),&Hz)) return FALSE;
              Hz/=(PD&3)+1;
            } else {
              PD=Clock(TOP+0x18E4);
              if (!Field(PD,1,BIT16) || !Pll(Clock(TOP+0x1A0),&Hz)) return FALSE;
              Hz/=(PD&1)+1;
            }
            Hz/=(TD&3)+1;
          }
          break;
      }
      Hz/=(AD&7)+1;
    }
  }
  Hz/=(D&15)+1;
  if (Hz<6000000 || Hz>400000000 || !ClockStable()) return FALSE;
  mN976nBatteryBusReport.InputHz=Hz; return TRUE;
}
STATIC BOOLEAN Empty (UINT32 F)
{
  return Accessible(HSI+FIFO_ST,F) && Equal(HSI+FIFO_ST,F,BIT24|BIT8,BIT24|BIT8) &&
    Equal(HSI+FIFO_ST,F,0,BIT23|BIT7|0x7F007FU);
}
STATIC VOID Sample (VOID)
{
  mN976nBatteryBusReport.Interrupt=Rd(HSI+INT_ST);
  mN976nBatteryBusReport.Transfer=Rd(HSI+TRANS);
  mN976nBatteryBusReport.Fifo=Rd(HSI+FIFO_ST);
  mN976nBatteryBusReport.Auto=Rd(HSI+AUTO);
  mSampleValid=TRUE;
}
STATIC BOOLEAN Idle (VOID)
{
  UINT32 T; Sample(); T=(UINT32)mN976nBatteryBusReport.Transfer;
  if (!Accessible(HSI+TRANS,T) || !Equal(HSI+TRANS,T,0,HSI_BUSY)) return FALSE;
  if ((T&15)>1) return Different(HSI+TRANS,1,T,15,3);
  return Equal(HSI+AUTO,(UINT32)mN976nBatteryBusReport.Auto,0,AUTO_RUN) &&
    Empty((UINT32)mN976nBatteryBusReport.Fifo);
}
STATIC BOOLEAN WaitIdle (VOID)
{
  DEADLINE D=Begin();
  do { if (Idle()) { mCompareValid=FALSE; return TRUE; } } while (!Expired(&D,100000));
  return FALSE;
}
STATIC BOOLEAN SelectedQuiescent(VOID)
{
  UINT32 T,F;
  if(mSaved[14]!=1)return Idle()&&mN976nBatteryBusReport.Interrupt==0;
  Sample();T=(UINT32)mN976nBatteryBusReport.Transfer;F=(UINT32)mN976nBatteryBusReport.Fifo;
  if(!Accessible(HSI+TRANS,T)||!Equal(HSI+TRANS,T,0,HSI_BUSY))return 0;
  if((T&15)>1)return Different(HSI+TRANS,1,T,15,3);
  return Equal(HSI+AUTO,(UINT32)mN976nBatteryBusReport.Auto,0,AUTO_RUN)&&
    Accessible(HSI+FIFO_ST,F)&&Equal(HSI+FIFO_ST,F,0,BIT23|BIT7|0x7F007FU)&&
    Equal(HSI+INT_ST,(UINT32)mN976nBatteryBusReport.Interrupt,0,MAX_UINT32)&&
    Equal(HSI+INT_EN,mSaved[3],0,MAX_UINT32);
}

STATIC BOOLEAN LinesHigh (VOID)
{
  UINT32 A=Rd(GPIO+0x184),B=Rd(GPIO+0x1A4);
  mN976nBatteryBusReport.Input=((UINT64)A<<32)|B;
  return Accessible(GPIO+0x184,A) && Accessible(GPIO+0x1A4,B) &&
    Equal(GPIO+0x184,A,1,1) && Equal(GPIO+0x1A4,B,1,1);
}
STATIC BOOLEAN PinData (volatile UINT64 *Values, UINTN ValidShift)
{
  UINT32 A=Rd(GPIO+0x184),B=Rd(GPIO+0x1A4);
  Values[0]=A; Values[1]=B;
  mN976nBatteryBusReport.PinDataValid|=3ULL<<ValidShift;
  return Accessible(GPIO+0x184,A) && Accessible(GPIO+0x1A4,B);
}
STATIC BOOLEAN PinField (UINTN Index, UINT32 Value)
{
  UINTN A=GPIO+mGpioOffsets[Index]; UINT32 Current=Rd(A);
  if (!Accessible(A,Current)) return FALSE;
  /* Samsung bank type gives each of these one-pin CON/PUD/DRV fields four
   * bits. Match pinctrl's RMW and preserve every unowned bit at its current
   * value, including during restoration. Never write the intervening DAT.
   */
  mN976nBatteryBusReport.PinChangedMask|=1ULL<<(Index/3);
  return Set(A,(Current&~15U)|(Value&15U),15);
}
STATIC BOOLEAN ReleaseOutputPins (VOID)
{
  DEADLINE D;
  if (!mN976nBatteryBusReport.PinOutputMask) return TRUE;
  /* Local safety transition, not a copied Linux sequence: first release the
   * inherited GPIO drivers. Controller ownership/idle was admitted before
   * this function. No GPIO clock pulses and no guessed DATA-latch writes.
   */
  if (!PinField(0,0) || !PinField(3,0)) {
    Fail(0xB141,EFI_DEVICE_ERROR); return FALSE;
  }
  D=Begin();
  do {
    if (!ClockStable() || !PinData(mN976nBatteryBusReport.PinDataReleased,2)) {
      Fail(0xB142,EFI_NOT_READY); return FALSE;
    }
    UINT32 A=(UINT32)mN976nBatteryBusReport.PinDataReleased[0];
    UINT32 B=(UINT32)mN976nBatteryBusReport.PinDataReleased[1];
    if (Equal(GPIO+0x184,A,1,1) && Equal(GPIO+0x1A4,B,1,1)) {
      mCompareValid=FALSE; mN976nBatteryBusReport.PinPhase=3; return TRUE;
    }
  } while (!Expired(&D,100000));
  Fail(0xB142,EFI_NOT_READY); return FALSE;
}
STATIC BOOLEAN Ack (BOOLEAN Completion)
{
  UINT32 P=Rd(HSI+INT_ST);
  mN976nBatteryBusReport.Interrupt=P;
  if (!Accessible(HSI+INT_ST,P) || !Equal(HSI+INT_ST,P,0,~INT_KNOWN)) return FALSE;
  /* The read inside ACK is the final acceptance observation. An error that
   * arrives after the RX-loop sample (or during WaitIdle) must not be cleared
   * and then promoted to success. Cleanup may retire errors, never validate data. */
  if (Completion && !Equal(HSI+INT_ST,P,INT_DONE,INT_DONE|INT_ERRORS)) return FALSE;
  if (P) Wr(HSI+INT_ST,P);
  return Equal(HSI+INT_ST,Rd(HSI+INT_ST),0,~BIT0); /* TX-empty may remain level asserted. */
}
STATIC BOOLEAN mObserving;
STATIC CONST N976N_BATTERY_READ mObservationPlan[N976N_CHARGE_OBS_FIELDS]={
 {0x69,0xB2,1},{0x69,0xB3,1},{0x69,0xB4,1},{0x69,0xB7,1},
 {0x69,0xB8,1},{0x69,0xB9,1},{0x69,0xBA,1},{0x69,0xBB,1},
 {0x69,0xBD,1},{0x69,0xC0,1},{0x69,0xC3,1},
 {0x25,0x06,1},{0x25,0x08,1},{0x25,0x0A,1},{0x25,0x0B,1},
 {0x25,0x0C,1},{0x25,0x0D,1},{0x57,0x05,1},{0x57,0x22,1}};
STATIC BOOLEAN ObservationAllowed(CONST N976N_BATTERY_READ *Spec)
{
 if(!mObserving||!Spec)return FALSE;
 for(UINTN I=0;I<ARRAY_SIZE(mObservationPlan);I++)
  if(Spec->Address==mObservationPlan[I].Address &&
     Spec->Register==mObservationPlan[I].Register && Spec->Bytes==1)return TRUE;
 return FALSE;
}
/* Private exact pointer/repeated-START/read contract. There is no arbitrary
 * register write or address API. Each successful STOP read is ACKed/retired
 * before the codec is allowed to mark the field valid. */
STATIC BOOLEAN Transfer (CONST N976N_BATTERY_READ *Spec, BOOLEAN Read, BOOLEAN Stop, UINT8 *Data, UINTN Length)
{
  UINT32 Auto, Ctl, Done=0; DEADLINE D;
  mCompareValid=FALSE;
  if (!Spec || !Data ||
      (!N976nBatteryReadAllowed(Spec->Address,Spec->Register,Spec->Bytes) && !ObservationAllowed(Spec)) ||
      (Read ? (!Stop || !mHeld || Length!=Spec->Bytes) :
              (Stop || mHeld || Length!=1 || Data[0]!=Spec->Register)) ||
      !ClockStable() ||
      (!mHeld && (!Idle() || !LinesHigh())) || !Ack(FALSE)) {
    if (!mCompareValid) Different(0,1,0,1,4); /* private argument contract */
    Fail(0xB110,EFI_NOT_READY); return FALSE;
  }
  if (mHeld) {
    Sample();
    if (!Equal(HSI+AUTO,(UINT32)mN976nBatteryBusReport.Auto,0,AUTO_RUN) ||
        !Empty((UINT32)mN976nBatteryBusReport.Fifo)) {
      Fail(0xB111,EFI_NOT_READY); return FALSE;
    }
  }
  Ctl=BIT3|(Read?BIT6:BIT7);
  Auto=(Stop?AUTO_STOP:0)|(Read?AUTO_READ:0)|(UINT32)Length;
  Wr(HSI+FIFO_CTL,BIT0|BIT1|((UINT32)Length<<4)|((UINT32)Length<<16));
  /* Direction selectors can read back asynchronously. Completion, exact
   * bytes and terminal bus state are the functional acceptance criteria. */
  Wr(HSI+CTL,Ctl); Wr(HSI+ADDR,(7U<<24)|((UINT32)Spec->Address<<10));
  Wr(HSI+INT_EN,INT_DONE|INT_ERRORS); Wr(HSI+AUTO,Auto);
  Wr(HSI+AUTO,Auto|AUTO_RUN); mHeld=TRUE; mN976nBatteryBusReport.Transfers++;
  mN976nBatteryBusReport.Retired=0; D=Begin();
  for (;;) {
    BOOLEAN Dequeued=FALSE; Sample();
    UINT32 I=(UINT32)mN976nBatteryBusReport.Interrupt,F=(UINT32)mN976nBatteryBusReport.Fifo;
    if (!Equal(HSI+INT_ST,I,0,~INT_KNOWN|INT_ERRORS) || !Accessible(HSI+FIFO_ST,F) ||
        !Accessible(HSI+TRANS,(UINT32)mN976nBatteryBusReport.Transfer) ||
        !Accessible(HSI+AUTO,(UINT32)mN976nBatteryBusReport.Auto)) {
      Fail(0xB112,EFI_DEVICE_ERROR); return FALSE;
    }
    if (!Read && Done<Length && !(F&BIT7) && (F&0x7F)<64) {
      Wr(HSI+TX,Data[Done++]); mN976nBatteryBusReport.TxBytes++;
    }
    if (Read && !(F&BIT24)) {
      if (Done>=Length || (F&BIT23)) {
        if (Done>=Length) Different(0,Length-1,Done,MAX_UINT32,3);
        else Different(HSI+FIFO_ST,0,F,BIT23,1);
        Fail(0xB113,EFI_DEVICE_ERROR); return FALSE;
      }
      Data[Done++]=(UINT8)Rd(HSI+RX); mN976nBatteryBusReport.RxBytes++; Dequeued=TRUE;
    }
    if (!Dequeued && Done==Length && (I&INT_DONE) && Empty(F) &&
        !(mN976nBatteryBusReport.Auto&AUTO_RUN)) {
      if (Stop && !WaitIdle()) { Fail(0xB114,EFI_TIMEOUT); return FALSE; }
      if (!Ack(TRUE) || !ClockStable()) { Fail(0xB115,EFI_DEVICE_ERROR); return FALSE; }
      Wr(HSI+INT_EN,0);
      if (!Equal(HSI+INT_EN,Rd(HSI+INT_EN),0,MAX_UINT32)) {
        Fail(0xB115,EFI_DEVICE_ERROR); return FALSE;
      }
      mHeld=!Stop; mN976nBatteryBusReport.Retired=Stop; mCompareValid=FALSE; return TRUE;
    }
    if (Expired(&D,100000)) { mCompareValid=FALSE; Fail(0xB116,EFI_TIMEOUT); return FALSE; }
  }
}
STATIC BOOLEAN ReadField (UINT32 Field, N976N_BATTERY_RAW *Raw)
{
  N976N_BATTERY_READ Spec; UINT8 Pointer, Data[2]={0,0}; UINT64 RxBefore;
  mN976nBatteryBusReport.Field=Field;
  if (!N976nBatteryReadSpec(Field,&Spec)) {
    Fail(0xB117,EFI_INVALID_PARAMETER); return FALSE;
  }
  mN976nBatteryBusReport.Address=Spec.Address;
  mN976nBatteryBusReport.Register=Spec.Register;
  mN976nBatteryBusReport.Requested=Spec.Bytes;
  Pointer=Spec.Register;
  RxBefore=mN976nBatteryBusReport.RxBytes;
  BOOLEAN Ok=Transfer(&Spec,FALSE,FALSE,&Pointer,1) &&
             Transfer(&Spec,TRUE,TRUE,Data,Spec.Bytes);
  UINT32 Received=(UINT32)(mN976nBatteryBusReport.RxBytes-RxBefore);
  mN976nBatteryBusReport.Received=Received;
  if (N976nBatteryRecord(Raw,Field,Ok && mN976nBatteryBusReport.Retired,
                        Data,Received)!=N976N_BAT_OK) {
    if (Ok) Fail(0xB118,EFI_DEVICE_ERROR);
    return FALSE;
  }
  return TRUE;
}
STATIC BOOLEAN Configure (VOID)
{
  UINT32 Div,Shift,V; UINT64 Hz=mN976nBatteryBusReport.InputHz;
  mCompareValid=FALSE;
  /* HSI45 uses Samsung's default FAST400kHz mode, unlike touch's100kHz. */
  Div=(UINT32)(Hz/(400000U*15U)); Shift=(UINT32)((9*Hz/1000000)/((Div+1)*10));
  if (!Div || Div>255 || !Shift || Shift>=8) { Fail(0xB106,EFI_UNSUPPORTED); return FALSE; }
  mHsiChanged=TRUE;
  if (!Set(HSI+USI_CON,0,BIT0)) return FALSE;
  Wr(HSI+CTL,mSaved[0]|BIT31); V=Rd(HSI+CTL); Wr(HSI+CTL,V&~BIT31);
  Wr(HSI+INT_EN,0);
  V=Rd(HSI+FS3); Wr(HSI+FS3,(V&~0x00FF0000U)|(Div<<16));
  V=Rd(HSI+FS2); Wr(HSI+FS2,(V&~0xFFU)|((0xFFU<<Shift)&0xFFU));
  V=Rd(HSI+FS1); Wr(HSI+FS1,(V&~0x00FF0000U)|(((0xFFU<<(Shift-1))&0xFFU)<<16));
  Wr(HSI+CTL,BIT3); Wr(HSI+TRAILING,0xFFFFFF);
  Wr(HSI+TIMEOUT,mSaved[6]&~BIT31);
  V=Rd(HSI+CONF); Wr(HSI+CONF,(V&~(BIT29|BIT30))|BIT31);
  return ClockStable() && WaitIdle() && LinesHigh() && Ack(FALSE);
}
/* Same live domain predicates as SEC89 portable D0 core. This candidate is
 * synchronous and terminal; no owner is exported or reused after the sample. */
STATIC BOOLEAN OwnerDomain(VOID)
{
 UINT32 Q=mSavedQch|((mSavedQch&BIT0)?0:BIT1);
 if(!ClockStable()||!Equal(MODE,Rd(MODE),4,MAX_UINT32)||
    !Equal(QCH,Rd(QCH),Q,MAX_UINT32)||
    !Equal(HSI+USI_CON,Rd(HSI+USI_CON),0,MAX_UINT32)||
    !Equal(HSI+USI_OPTION,Rd(HSI+USI_OPTION),mSaved[15],MAX_UINT32)||
    !Equal(HSI+CTL,Rd(HSI+CTL),BIT3,BIT31|BIT3|BIT0)||
    !Equal(HSI+CONF,Rd(HSI+CONF),BIT31,BIT31|BIT30|BIT29))return FALSE;
 for(UINTN I=0;I<6;I++)
  if(!Equal(GPIO+mGpioOffsets[I],Rd(GPIO+mGpioOffsets[I]),I%3==0?2:0,15))return FALSE;
 return TRUE;
}
STATIC BOOLEAN OwnerReady(VOID)
{
 if(!OwnerDomain()||!Equal(HSI+INT_EN,Rd(HSI+INT_EN),0,MAX_UINT32)){
  mRestoreBlocked=TRUE;return FALSE;
 }
 return Idle()&&LinesHigh()&&Equal(HSI+INT_ST,(UINT32)mN976nBatteryBusReport.Interrupt,0,~BIT0);
}
STATIC BOOLEAN ReadObservation(N976N_CHARGE_OBSERVATION *O)
{
 for(UINTN Round=0;Round<3;Round++){
  O->Count=Round+1;O->Begin[Round]=GetPerformanceCounter();
  if(!OwnerReady()){Fail(0xB153,EFI_NOT_READY);O->End[Round]=GetPerformanceCounter();return FALSE;}
  for(UINTN I=0;I<ARRAY_SIZE(mObservationPlan);I++){
   CONST N976N_BATTERY_READ *S=&mObservationPlan[I];UINT8 P=S->Register,D=0;
   UINT64 Before=mN976nBatteryBusReport.RxBytes;
   mN976nBatteryBusReport.Field=0x100+I;mN976nBatteryBusReport.Address=S->Address;
   mN976nBatteryBusReport.Register=S->Register;mN976nBatteryBusReport.Requested=1;
   if(!Transfer(S,FALSE,FALSE,&P,1)||!Transfer(S,TRUE,TRUE,&D,1)){
    O->End[Round]=GetPerformanceCounter();return FALSE;
   }
   if(mN976nBatteryBusReport.RxBytes-Before!=1||!mN976nBatteryBusReport.Retired){
    Fail(0xB118,EFI_DEVICE_ERROR);O->End[Round]=GetPerformanceCounter();return FALSE;
   }
   O->Raw[Round][I]=D;O->Valid[Round]|=1ULL<<I;
  }
  O->End[Round]=GetPerformanceCounter();
  if(!OwnerReady()){Fail(0xB153,EFI_NOT_READY);return FALSE;}
  O->Complete++;
  if(Round<2){
   DEADLINE D=Begin();while(!Expired(&D,100000)){}
   if(mN976nBatteryBusReport.WaitExit!=1){Fail(0xB116,EFI_TIMEOUT);return FALSE;}
  }
 }
 return TRUE;
}
STATIC BOOLEAN RestoreSet (UINTN A, UINT32 V, UINT32 Mask)
{
  BOOLEAN Ok=Set(A,V,Mask);
  /* Restoration continues as before, but its first failed write/readback
   * predicate must not be replaced by a subsequent restoration mismatch. */
  if (!Ok) mCompareLocked=TRUE;
  return Ok;
}
STATIC BOOLEAN SelectedOuterOwned(VOID)
{
  UINT32 Q=mSavedQch|((mSavedQch&BIT0)?0:BIT1);
  if(!ClockStable()||!Equal(MODE,Rd(MODE),4,MAX_UINT32)||
     !Equal(QCH,Rd(QCH),Q,MAX_UINT32))return 0;
  for(unsigned I=0;I<6;I++)
    if(!Equal(GPIO+mGpioOffsets[I],Rd(GPIO+mGpioOffsets[I]),mGpio[I],15))return 0;
  return 1;
}
STATIC BOOLEAN Restore(VOID)
{
  BOOLEAN Ok=1;
  mCompareValid=mCompareLocked=0;
  if (mRestoreBlocked) { mN976nBatteryBusReport.Quarantine=1; return 0; }
  if (mHsiSaved) {
    if (!ClockStable()) { mN976nBatteryBusReport.Quarantine=1; return 0; }
    if (!mHsiChanged) {
      /* Pad release/selection can fail before Configure writes HSI. No command
       * was issued and the inherited register image must still match exactly.
       * Do not demand active FIFO flags, mask IRQs or ACK someone else's state.
       * Once Configure attempts any HSI write, the strict retirement path below
       * applies even if initialization fails partway through.
       */
      if(!mPinsChanged&&!SelectedOuterOwned()){mN976nBatteryBusReport.Quarantine=1;return 0;}
      for (UINTN I=0; I<ARRAY_SIZE(mConfigOffsets); I++)
        if (!Equal(HSI+mConfigOffsets[I],Rd(HSI+mConfigOffsets[I]),mSaved[I],MAX_UINT32)) {
          mN976nBatteryBusReport.Quarantine=1; return 0;
        }
      if (mHeld || mN976nBatteryBusReport.Transfers ||
          !SelectedQuiescent() || mN976nBatteryBusReport.Interrupt) {
        mN976nBatteryBusReport.Quarantine=1; return 0;
      }
      mN976nBatteryBusReport.Retired=1;
    } else {
      if (!WaitIdle()) { mN976nBatteryBusReport.Quarantine=1; return 0; }
      mHeld=0; Wr(HSI+INT_EN,0);
      if (!Ack(0)) { mN976nBatteryBusReport.Quarantine=1; return 0; }
      mN976nBatteryBusReport.Retired=1;
      /* Restore the idle configuration, with interrupt enable and USI reset
       * last. No saved AUTO_RUN is admitted, so no saved value submits I/O. */
      for (UINTN I=0; I<ARRAY_SIZE(mConfigOffsets); I++) {
        if (I==3 || I==14) continue;
        if (!RestoreSet(HSI+mConfigOffsets[I],mSaved[I],MAX_UINT32)) Ok=0;
      }
      if (!RestoreSet(HSI+INT_EN,mSaved[3],MAX_UINT32)) Ok=0;
      if (!RestoreSet(HSI+USI_CON,mSaved[14],MAX_UINT32)) Ok=0;
    }
  }
  if (!Ok) { mN976nBatteryBusReport.Quarantine=1; return 0; }
  if (mPinsChanged) {
    BOOLEAN PinsOk=1;
    /* Retired HSI first, saved pull/drive next, and original CON last. This
     * prevents re-enabling an inherited GPIO output with temporary pad policy.
     * Its DATA latch was never changed, so no speculative latch reconstruction.
     */
    for (UINTN I=0; I<6; I+=3) {
      BOOLEAN PadOk=1;
      if (!PinField(I+1,mGpio[I+1])) { mCompareLocked=1; PadOk=0; }
      if (!PinField(I+2,mGpio[I+2])) { mCompareLocked=1; PadOk=0; }
      if (PadOk && PinField(I,mGpio[I])) mN976nBatteryBusReport.PinRestoredMask|=1ULL<<(I/3);
      else { mCompareLocked=1; PinsOk=0; }
    }
    if (!PinData(mN976nBatteryBusReport.PinDataRestored,6)) PinsOk=0;
    if (!PinsOk) { mN976nBatteryBusReport.Quarantine=1; return 0; }
    mN976nBatteryBusReport.PinPhase=8;
  }
  if (mOuterChanged) {
    if (!RestoreSet(MODE,mSavedMode,MAX_UINT32)) Ok=0;
    if (!RestoreSet(QCH,mSavedQch,MAX_UINT32)) Ok=0;
  }

  mN976nBatteryBusReport.Restored=Ok;
  if (!Ok) mN976nBatteryBusReport.Quarantine=1;
  return Ok;
}

STATIC EFI_STATUS SampleBus (UINT64 SampleId, N976N_BATTERY_RAW *Raw, N976N_CHARGE_OBSERVATION *O)
{
  UINT64 Start,End; BOOLEAN Ok=FALSE;
  STATIC CONST UINT32 Gates[]={0x2010,0x206C,0x205C,0x2088,0x208C};
  if (!Raw || !SampleId) return EFI_INVALID_PARAMETER;
  if (mTried) return EFI_ALREADY_STARTED;
  if (!N976nBatteryBegin(Raw,SampleId)) return EFI_INVALID_PARAMETER;
  mTried=TRUE; mObserving=(O!=NULL); ZeroMem((VOID *)&mN976nBatteryBusReport,sizeof(mN976nBatteryBusReport));
  mN976nBatteryBusReport.NoMutation=1;
  mCompareValid=mCompareLocked=mSampleValid=mWaitValid=FALSE;
  mN976nBatteryBusReport.SampleId=SampleId;
  mN976nBatteryBusReport.Status=EFI_NOT_READY; mN976nBatteryBusReport.Phase=1;
  mHz=GetPerformanceCounterProperties(&Start,&End);
  if (!mHz || mHz>1000000000 || End<=Start || !InputClock()) { Fail(0xB101,EFI_UNSUPPORTED); goto Done; }
  for (UINTN I=0; I<ARRAY_SIZE(Gates); I++)
    if (!Gate(Clock(CMGP+Gates[I]))) { Fail(0xB102,EFI_NOT_READY); goto Done; }
  mSavedQch=Rd(QCH); mSavedMode=Rd(MODE);
  mN976nBatteryBusReport.InheritedQch=mSavedQch; mN976nBatteryBusReport.InheritedMode=mSavedMode;
  mN976nBatteryBusReport.CaptureValid|=BIT5|BIT6;
  if (!Accessible(QCH,mSavedQch) || !Equal(MODE,mSavedMode,0,~4U)) { Fail(0xB103,EFI_NOT_READY); goto Done; }
  for (UINTN I=0; I<ARRAY_SIZE(mGpioOffsets); I++) {
    mGpio[I]=Rd(GPIO+mGpioOffsets[I]);
    mN976nBatteryBusReport.InheritedPin[I]=mGpio[I]; mN976nBatteryBusReport.CaptureValid|=1ULL<<(7+I);
  }
  if (!PinData(mN976nBatteryBusReport.PinDataBefore,0)) { Fail(0xB140,EFI_NOT_READY); goto Done; }
  mN976nBatteryBusReport.PinPhase=1;
  for (UINTN I=0; I<ARRAY_SIZE(mGpioOffsets); I++) {
    if (!Accessible(GPIO+mGpioOffsets[I],mGpio[I])) {
      Fail(0xB104,EFI_NOT_READY); goto Done;
    }
    if (I%3==0) {
      UINT32 Function=mGpio[I]&15;
      if (Function>2) {
        Different(GPIO+mGpioOffsets[I],2,mGpio[I],15,3);
        Fail(0xB104,EFI_NOT_READY); goto Done;
      }
      if (Function==1) mN976nBatteryBusReport.PinOutputMask|=1ULL<<(I/3);
    }
  }
  mN976nBatteryBusReport.Phase=2; mOuterChanged=TRUE;
  /* Samsung ra_req_enable_qch preserves ENABLE and only asserts REQUEST when
   * ENABLE=0. Expire/ignore-policy fields remain untouched. */
  if (!(mSavedQch&BIT0) && !Set(QCH,mSavedQch|BIT1,BIT0|BIT1)) goto Cleanup;
  if (!Set(MODE,4,MAX_UINT32)) goto Cleanup;
  for (UINTN I=0; I<ARRAY_SIZE(mConfigOffsets); I++) {
    mSaved[I]=Rd(HSI+mConfigOffsets[I]);
    switch (I) {
      case 0: mN976nBatteryBusReport.InheritedControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BIT13; break;
      case 1: mN976nBatteryBusReport.InheritedFifoControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BIT14; break;
      case 3: mN976nBatteryBusReport.InheritedInterruptEnable=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BIT15; break;
      case 14: mN976nBatteryBusReport.InheritedUsiControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BIT16; break;
      case 15: mN976nBatteryBusReport.InheritedUsiOption=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BIT17; break;
      default: break;
    }
    if (!Accessible(HSI+mConfigOffsets[I],mSaved[I])) {
      mRestoreBlocked=TRUE; Fail(0xB105,EFI_NOT_READY); goto Cleanup;
    }
  }
  /* No inherited in-flight request, slave ownership or unknown FIFO payload. */
  if (!SelectedQuiescent() || mN976nBatteryBusReport.Interrupt || mSaved[3] ||
      !Equal(HSI+CTL,mSaved[0],0,BIT31) ||
      !Equal(HSI+USI_CON,mSaved[14],0,~1U) || !Equal(HSI+USI_OPTION,mSaved[15],0,~7U) ||
      !Equal(HSI+INT_ST,(UINT32)mN976nBatteryBusReport.Interrupt,0,~INT_KNOWN)) {
    mRestoreBlocked=TRUE; Fail(0xB105,EFI_NOT_READY); goto Cleanup;
  }
  mHsiSaved=TRUE; mPinsChanged=TRUE;
  mN976nBatteryBusReport.PinPhase=2;
  if (!ReleaseOutputPins()) goto Cleanup;
  for (UINTN I=0; I<6; I+=3) {
    if (!PinField(I,2) || !PinField(I+1,0) || !PinField(I+2,0)) goto Cleanup;
  }
  mN976nBatteryBusReport.PinPhase=4;
  mN976nBatteryBusReport.Phase=3;
  if (!Configure()) { Fail(0xB107,EFI_NOT_READY); goto Cleanup; }
  mN976nBatteryBusReport.PinDataReady[0]=mN976nBatteryBusReport.Input>>32;
  mN976nBatteryBusReport.PinDataReady[1]=(UINT32)mN976nBatteryBusReport.Input;
  mN976nBatteryBusReport.PinDataValid|=0x30; mN976nBatteryBusReport.PinPhase=5;
  mN976nBatteryBusReport.Phase=4;
  if(!OwnerReady()){Fail(0xB153,EFI_NOT_READY);goto Cleanup;}
  for (UINT32 Field=0; Field<N976N_BAT_FIELD_COUNT; Field++) {
    if (!ReadField(Field,Raw)) goto Cleanup;
  }
  if(O && !ReadObservation(O)) goto Cleanup;
  if(!OwnerReady()){Fail(0xB153,EFI_NOT_READY);goto Cleanup;}
  Ok=TRUE;
Cleanup:
  if (!Ok && !mN976nBatteryBusReport.Reason) Fail(0xB108,EFI_DEVICE_ERROR);
  mN976nBatteryBusReport.Phase=6;
  if(mN976nBatteryBusReport.PinPhase==5 && !OwnerDomain())mRestoreBlocked=TRUE;
  if (!Restore()) { Fail(0xB130,EFI_DEVICE_ERROR); Ok=FALSE; }
  if (Ok && !mN976nBatteryBusReport.Quarantine) {
    mN976nBatteryBusReport.Status=EFI_SUCCESS; mN976nBatteryBusReport.Phase=8;
  }
Done:
  mObserving=FALSE;
  mN976nBatteryBusReport.SampledMask=Raw->ValidMask;
  return mN976nBatteryBusReport.Status;
}

EFI_STATUS N976nBatteryBusSample(UINT64 Id,N976N_BATTERY_RAW *R)
{ return SampleBus(Id,R,NULL); }
EFI_STATUS N976nBatteryBusObserve(UINT64 Id,N976N_BATTERY_RAW *R,N976N_CHARGE_OBSERVATION *O)
{ if(!O)return EFI_INVALID_PARAMETER;return SampleBus(Id,R,O); }

/* No MMIO here. Export only the successful final producer's retired snapshot.
 * The live caller separately validates the outer domain and clock binding. */
BOOLEAN N976nBatteryBusGetRestoredSelectedConfig(UINT32 Config[16])
{
 if(!Config)return FALSE;
 ZeroMem(Config,16*sizeof(*Config));
 if(!mTried||mHeld||mObserving||!mHsiSaved||!mHsiChanged||mRestoreBlocked||
    mN976nBatteryBusReport.Phase!=8||mN976nBatteryBusReport.Status||
    mN976nBatteryBusReport.Reason||mN976nBatteryBusReport.Retired!=1||
    mN976nBatteryBusReport.Restored!=1||mN976nBatteryBusReport.Quarantine)return FALSE;
 CopyMem(Config,mSaved,sizeof(mSaved));return TRUE;
}
