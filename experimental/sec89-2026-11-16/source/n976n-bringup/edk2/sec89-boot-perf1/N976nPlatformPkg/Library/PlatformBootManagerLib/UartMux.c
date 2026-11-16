/* SPDX-License-Identifier: MIT
 * Independently implemented from N976N Samsung i2c-exynos5, max77705_usbc,
 * max77705-muic and cal-if register/protocol facts. See the pinned sources in
 * references/sec85-uart-kd/samsung-source. No Linux driver code is copied.
 * Only CTRL1 read(05)/write(06) on MAX77705's USBC address25 are submitted.
 * No charger, rail, firmware, PD, storage or GIC programming is performed.
 */
#include <N976nUartMux.h>
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
#define UART_ROUTE 0x9BU
#define STALL_LIMIT 20000U

volatile N976N_UART_MUX_REPORT mN976nUartMuxReport;
STATIC BOOLEAN mTried, mReady, mHeld, mHsiSaved, mHsiChanged;
STATIC BOOLEAN mOuterChanged, mPinsChanged, mOpcodeOutstanding;
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
STATIC VOID Wr (UINTN A, UINT32 V) { MmioWrite32 (A,V); MemoryFence (); }
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
  if (!mN976nUartMuxReport.Reason) {
    mN976nUartMuxReport.Reason=Why;
    mN976nUartMuxReport.Status=Status;
    mN976nUartMuxReport.FailurePhase=mN976nUartMuxReport.Phase;
    mN976nUartMuxReport.PinFailurePhase=mN976nUartMuxReport.PinPhase;
    mN976nUartMuxReport.CaptureValid|=BIT0;
    if (mCompareValid) {
      mN976nUartMuxReport.CaptureValid|=BIT1;
      mN976nUartMuxReport.FirstAddress=mCompareAddress;
      mN976nUartMuxReport.FirstExpected=mCompareExpected;
      mN976nUartMuxReport.FirstActual=mCompareActual;
      mN976nUartMuxReport.FirstMask=mCompareMask;
      mN976nUartMuxReport.FirstCompare=mCompareKind;
    }
    if (mSampleValid) mN976nUartMuxReport.CaptureValid|=BIT2;
    if (mWaitValid) mN976nUartMuxReport.CaptureValid|=BIT3;
    mN976nUartMuxReport.FirstInterrupt=mN976nUartMuxReport.Interrupt;
    mN976nUartMuxReport.FirstTransfer=mN976nUartMuxReport.Transfer;
    mN976nUartMuxReport.FirstFifo=mN976nUartMuxReport.Fifo;
    mN976nUartMuxReport.FirstAuto=mN976nUartMuxReport.Auto;
    mN976nUartMuxReport.FirstWaitUs=mN976nUartMuxReport.WaitUs;
    mN976nUartMuxReport.FirstWaitExit=mN976nUartMuxReport.WaitExit;
    mN976nUartMuxReport.FirstTransfers=mN976nUartMuxReport.Transfers;
    mN976nUartMuxReport.FirstTxBytes=mN976nUartMuxReport.TxBytes;
    mN976nUartMuxReport.FirstRxBytes=mN976nUartMuxReport.RxBytes;
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
  if (Now < D->Previous) { mN976nUartMuxReport.WaitExit=3; return TRUE; }
  D->Same=Now==D->Previous ? D->Same+1 : 0; D->Previous=Now;
  mN976nUartMuxReport.WaitUs=Elapsed*1000000/mHz;
  if (Elapsed >= (mHz*Us+999999)/1000000) {
    mN976nUartMuxReport.WaitExit=1; return TRUE;
  }
  if (D->Same >= STALL_LIMIT) { mN976nUartMuxReport.WaitExit=2; return TRUE; }
  return FALSE;
}
STATIC BOOLEAN Set (UINTN A, UINT32 V, UINT32 Mask)
{
  UINT32 Actual; Wr(A,V); Actual=Rd(A);
  if (Actual!=MAX_UINT32 && ((Actual^V)&Mask)==0) return TRUE;
  mN976nUartMuxReport.SetupOffset=A;
  mN976nUartMuxReport.SetupExpected=V;
  mN976nUartMuxReport.SetupActual=Actual;
  mN976nUartMuxReport.SetupDiff++;
  if (!Accessible(A,Actual)) return FALSE;
  return Different(A,V,Actual,Mask,1);
}
STATIC BOOLEAN Gate (UINT32 V)
{
  UINTN A=(UINTN)mN976nUartMuxReport.ClockAddress;
  mN976nUartMuxReport.GateAddress=A; mN976nUartMuxReport.GateValue=V;
  mN976nUartMuxReport.CaptureValid|=BIT4;
  return Accessible(A,V) && ((V&BIT20) ? Equal(A,V,BIT21,BIT21) : Equal(A,V,0,BIT28));
}
STATIC UINT32 Clock (UINTN A)
{
  UINT32 V=Rd(A);
  mN976nUartMuxReport.ClockAddress=A; mN976nUartMuxReport.ClockValue=V;
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
  mN976nUartMuxReport.InputHz=Hz; return TRUE;
}
STATIC BOOLEAN Empty (UINT32 F)
{
  return Accessible(HSI+FIFO_ST,F) && Equal(HSI+FIFO_ST,F,BIT24|BIT8,BIT24|BIT8) &&
    Equal(HSI+FIFO_ST,F,0,BIT23|BIT7|0x7F007FU);
}
STATIC VOID Sample (VOID)
{
  mN976nUartMuxReport.Interrupt=Rd(HSI+INT_ST);
  mN976nUartMuxReport.Transfer=Rd(HSI+TRANS);
  mN976nUartMuxReport.Fifo=Rd(HSI+FIFO_ST);
  mN976nUartMuxReport.Auto=Rd(HSI+AUTO);
  mSampleValid=TRUE;
}
STATIC BOOLEAN Idle (VOID)
{
  UINT32 T; Sample(); T=(UINT32)mN976nUartMuxReport.Transfer;
  if (!Accessible(HSI+TRANS,T) || !Equal(HSI+TRANS,T,0,HSI_BUSY)) return FALSE;
  if ((T&15)>1) return Different(HSI+TRANS,1,T,15,3);
  return Equal(HSI+AUTO,(UINT32)mN976nUartMuxReport.Auto,0,AUTO_RUN) &&
    Empty((UINT32)mN976nUartMuxReport.Fifo);
}
STATIC BOOLEAN WaitIdle (VOID)
{
  DEADLINE D=Begin();
  do { if (Idle()) { mCompareValid=FALSE; return TRUE; } } while (!Expired(&D,100000));
  return FALSE;
}
STATIC BOOLEAN LinesHigh (VOID)
{
  UINT32 A=Rd(GPIO+0x184),B=Rd(GPIO+0x1A4);
  mN976nUartMuxReport.Input=((UINT64)A<<32)|B;
  return Accessible(GPIO+0x184,A) && Accessible(GPIO+0x1A4,B) &&
    Equal(GPIO+0x184,A,1,1) && Equal(GPIO+0x1A4,B,1,1);
}
STATIC BOOLEAN PinData (volatile UINT64 *Values, UINTN ValidShift)
{
  UINT32 A=Rd(GPIO+0x184),B=Rd(GPIO+0x1A4);
  Values[0]=A; Values[1]=B;
  mN976nUartMuxReport.PinDataValid|=3ULL<<ValidShift;
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
  mN976nUartMuxReport.PinChangedMask|=1ULL<<(Index/3);
  return Set(A,(Current&~15U)|(Value&15U),15);
}
STATIC BOOLEAN ReleaseOutputPins (VOID)
{
  DEADLINE D;
  if (!mN976nUartMuxReport.PinOutputMask) return TRUE;
  /* Local safety transition, not a copied Linux sequence: first release the
   * inherited GPIO drivers. Controller ownership/idle was admitted before
   * this function. No GPIO clock pulses and no guessed DATA-latch writes.
   */
  if (!PinField(0,0) || !PinField(3,0)) {
    Fail(0x8641,EFI_DEVICE_ERROR); return FALSE;
  }
  D=Begin();
  do {
    if (!ClockStable() || !PinData(mN976nUartMuxReport.PinDataReleased,2)) {
      Fail(0x8642,EFI_NOT_READY); return FALSE;
    }
    UINT32 A=(UINT32)mN976nUartMuxReport.PinDataReleased[0];
    UINT32 B=(UINT32)mN976nUartMuxReport.PinDataReleased[1];
    if (Equal(GPIO+0x184,A,1,1) && Equal(GPIO+0x1A4,B,1,1)) {
      mCompareValid=FALSE; mN976nUartMuxReport.PinPhase=3; return TRUE;
    }
  } while (!Expired(&D,100000));
  Fail(0x8642,EFI_NOT_READY); return FALSE;
}
STATIC BOOLEAN Ack (VOID)
{
  UINT32 P=Rd(HSI+INT_ST);
  if (!Accessible(HSI+INT_ST,P) || !Equal(HSI+INT_ST,P,0,~INT_KNOWN)) return FALSE;
  if (P) Wr(HSI+INT_ST,P);
  return Equal(HSI+INT_ST,Rd(HSI+INT_ST),0,~BIT0); /* TX-empty may remain level asserted. */
}
/* No reusable public I2C API: length <=3, address fixed25, one repeated-START
 * register pointer/read pair. RX payload is the low byte, never a FIFO level.
 */
STATIC BOOLEAN Transfer (BOOLEAN Read, BOOLEAN Stop, UINT8 *Data, UINTN Length)
{
  UINT32 Auto, Ctl, Done=0; DEADLINE D;
  mCompareValid=FALSE;
  if (!Data || !Length || Length>3 || !ClockStable() ||
      (!mHeld && (!Idle() || !LinesHigh())) || !Ack()) {
    if (!mCompareValid) Different(0,1,0,1,4); /* private argument contract */
    Fail(0x8610,EFI_NOT_READY); return FALSE;
  }
  if (mHeld) {
    Sample();
    if (!Equal(HSI+AUTO,(UINT32)mN976nUartMuxReport.Auto,0,AUTO_RUN) ||
        !Empty((UINT32)mN976nUartMuxReport.Fifo)) {
      Fail(0x8611,EFI_NOT_READY); return FALSE;
    }
  }
  Ctl=BIT3|(Read?BIT6:BIT7);
  Auto=(Stop?AUTO_STOP:0)|(Read?AUTO_READ:0)|(UINT32)Length;
  Wr(HSI+FIFO_CTL,BIT0|BIT1|((UINT32)Length<<4)|((UINT32)Length<<16));
  /* Direction selectors can read back asynchronously. Completion, exact
   * bytes and terminal bus state are the functional acceptance criteria. */
  Wr(HSI+CTL,Ctl); Wr(HSI+ADDR,(7U<<24)|(0x25U<<10));
  Wr(HSI+INT_EN,INT_DONE|INT_ERRORS); Wr(HSI+AUTO,Auto);
  Wr(HSI+AUTO,Auto|AUTO_RUN); mHeld=TRUE; mN976nUartMuxReport.Transfers++;
  mN976nUartMuxReport.Retired=0; D=Begin();
  for (;;) {
    BOOLEAN Dequeued=FALSE; Sample();
    UINT32 I=(UINT32)mN976nUartMuxReport.Interrupt,F=(UINT32)mN976nUartMuxReport.Fifo;
    if (!Equal(HSI+INT_ST,I,0,~INT_KNOWN|INT_ERRORS) || !Accessible(HSI+FIFO_ST,F) ||
        !Accessible(HSI+TRANS,(UINT32)mN976nUartMuxReport.Transfer) ||
        !Accessible(HSI+AUTO,(UINT32)mN976nUartMuxReport.Auto)) {
      Fail(0x8612,EFI_DEVICE_ERROR); return FALSE;
    }
    if (!Read && Done<Length && !(F&BIT7) && (F&0x7F)<64) {
      Wr(HSI+TX,Data[Done++]); mN976nUartMuxReport.TxBytes++;
    }
    if (Read && !(F&BIT24)) {
      if (Done>=Length || (F&BIT23)) {
        if (Done>=Length) Different(0,Length-1,Done,MAX_UINT32,3);
        else Different(HSI+FIFO_ST,0,F,BIT23,1);
        Fail(0x8613,EFI_DEVICE_ERROR); return FALSE;
      }
      Data[Done++]=(UINT8)Rd(HSI+RX); mN976nUartMuxReport.RxBytes++; Dequeued=TRUE;
    }
    if (!Dequeued && Done==Length && (I&INT_DONE) && Empty(F) &&
        !(mN976nUartMuxReport.Auto&AUTO_RUN)) {
      if (Stop && !WaitIdle()) { Fail(0x8614,EFI_TIMEOUT); return FALSE; }
      if (!Ack() || !ClockStable()) { Fail(0x8615,EFI_DEVICE_ERROR); return FALSE; }
      mHeld=!Stop; mN976nUartMuxReport.Retired=Stop; mCompareValid=FALSE; return TRUE;
    }
    if (Expired(&D,100000)) { mCompareValid=FALSE; Fail(0x8616,EFI_TIMEOUT); return FALSE; }
  }
}
STATIC BOOLEAN ReadByte (UINT8 Register, UINT8 *Value)
{
  return Transfer(FALSE,FALSE,&Register,1) && Transfer(TRUE,TRUE,Value,1);
}
STATIC BOOLEAN ReadReply (UINT8 *Data, UINTN Length)
{
  UINT8 R=0x51; return Transfer(FALSE,FALSE,&R,1) && Transfer(TRUE,TRUE,Data,Length);
}
STATIC BOOLEAN SafetyStatus (VOID)
{
  UINT8 V,B,C;
  if (!ReadByte(0x06,&V) || !ReadByte(0x08,&B) || !ReadByte(0x0B,&C)) return FALSE;
  mN976nUartMuxReport.VbusAdc=V; mN976nUartMuxReport.BcStatus=B; mN976nUartMuxReport.CcStatus=C;
  /* VBADC0 is below3.8V, not a voltmeter zero reading. Require independent
   * VBUS detector low and Samsung's ConnStat water bit clear as well. */
  if (!Equal(0x06,V,0,0xF0) || !Equal(0x08,B,0,BIT7) || !Equal(0x0B,C,0,BIT1)) {
    Fail(0x8620,EFI_ACCESS_DENIED); return FALSE;
  }
  return TRUE;
}
STATIC BOOLEAN Opcode (UINT8 Op, UINT8 Value, UINT8 *Reply)
{
  UINT8 P=0, Buf[3]={0x21,Op,Value}, End[2]={0x41,0}, Response[2]={0,0};
  DEADLINE D;
  mCompareValid=FALSE;
  if ((Op!=5 && Op!=6) || mOpcodeOutstanding || !ReadByte(0x02,&P)) return FALSE;
  mN976nUartMuxReport.UicSeen|=P;
  /* UIC reads acknowledge this controller's UIC latch. Other UIC event bits
   * are recorded; no CC/PD/VDM interrupt registers are read or cleared. An
   * existing AP response is foreign: do not overwrite or consume its payload.
   */
  if (P&BIT7) { Different(0x02,0,P,BIT7,1); Fail(0x8621,EFI_NOT_READY); return FALSE; }
  mN976nUartMuxReport.Opcode=Op;
  if (!Transfer(FALSE,TRUE,Buf,Op==5?2:3)) return FALSE;
  mOpcodeOutstanding=TRUE; /* even a failed END write must not be retried */
  if (!Transfer(FALSE,TRUE,End,2)) return FALSE;
  mN976nUartMuxReport.Opcodes++; D=Begin();
  do {
    if (!ReadByte(0x02,&P)) return FALSE;
    mN976nUartMuxReport.UicSeen|=P;
    if (P&BIT7) {
      if (!ReadReply(Response,Op==5?2:1)) return FALSE;
      mN976nUartMuxReport.Reply=((UINT64)Response[0]<<8)|Response[1];
      if (!Equal(0x51,Response[0],Op,0xFF)) { Fail(0x8622,EFI_DEVICE_ERROR); return FALSE; }
      mOpcodeOutstanding=FALSE; if (Reply) *Reply=Response[1]; mCompareValid=FALSE; return TRUE;
    }
  } while (!Expired(&D,1000000));
  mCompareValid=FALSE; Fail(0x8623,EFI_TIMEOUT); return FALSE;
}
STATIC BOOLEAN Configure (VOID)
{
  UINT32 Div,Shift,V; UINT64 Hz=mN976nUartMuxReport.InputHz;
  mCompareValid=FALSE;
  /* HSI45 uses Samsung's default FAST400kHz mode, unlike touch's100kHz. */
  Div=(UINT32)(Hz/(400000U*15U)); Shift=(UINT32)((9*Hz/1000000)/((Div+1)*10));
  if (!Div || Div>255 || !Shift || Shift>=8) { Fail(0x8606,EFI_UNSUPPORTED); return FALSE; }
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
  return ClockStable() && WaitIdle() && LinesHigh() && Ack();
}
STATIC BOOLEAN RestoreSet (UINTN A, UINT32 V, UINT32 Mask)
{
  BOOLEAN Ok=Set(A,V,Mask);
  /* Restoration continues as before, but its first failed write/readback
   * predicate must not be replaced by a subsequent restoration mismatch. */
  if (!Ok) mCompareLocked=TRUE;
  return Ok;
}
STATIC BOOLEAN Restore (VOID)
{
  BOOLEAN Ok=TRUE;
  mCompareValid=mCompareLocked=FALSE;
  if (mRestoreBlocked) { mN976nUartMuxReport.Quarantine=1; return FALSE; }
  if (mHsiSaved) {
    if (!ClockStable() || !WaitIdle()) {
      mN976nUartMuxReport.Quarantine=1; return FALSE;
    }
    mHeld=FALSE; Wr(HSI+INT_EN,0);
    if (!Ack()) { mN976nUartMuxReport.Quarantine=1; return FALSE; }
    mN976nUartMuxReport.Retired=1;
    if (mHsiChanged) {
      /* Restore the idle configuration, with interrupt enable and USI reset
       * last. No saved AUTO_RUN is admitted, so no saved value submits I/O. */
      for (UINTN I=0; I<ARRAY_SIZE(mConfigOffsets); I++) {
        if (I==3 || I==14) continue;
        if (!RestoreSet(HSI+mConfigOffsets[I],mSaved[I],MAX_UINT32)) Ok=FALSE;
      }
      if (!RestoreSet(HSI+INT_EN,mSaved[3],MAX_UINT32)) Ok=FALSE;
      if (!RestoreSet(HSI+USI_CON,mSaved[14],MAX_UINT32)) Ok=FALSE;
    }
  }
  if (!Ok) { mN976nUartMuxReport.Quarantine=1; return FALSE; }
  if (mPinsChanged) {
    BOOLEAN PinsOk=TRUE;
    /* Retired HSI first, saved pull/drive next, and original CON last. This
     * prevents re-enabling an inherited GPIO output with temporary pad policy.
     * Its DATA latch was never changed, so no speculative latch reconstruction.
     */
    for (UINTN I=0; I<6; I+=3) {
      BOOLEAN PadOk=TRUE;
      if (!PinField(I+1,mGpio[I+1])) { mCompareLocked=TRUE; PadOk=FALSE; }
      if (!PinField(I+2,mGpio[I+2])) { mCompareLocked=TRUE; PadOk=FALSE; }
      if (PadOk && PinField(I,mGpio[I])) mN976nUartMuxReport.PinRestoredMask|=1ULL<<(I/3);
      else { mCompareLocked=TRUE; PinsOk=FALSE; }
    }
    if (!PinData(mN976nUartMuxReport.PinDataRestored,6)) PinsOk=FALSE;
    if (!PinsOk) { mN976nUartMuxReport.Quarantine=1; return FALSE; }
    mN976nUartMuxReport.PinPhase=8;
  }
  if (mOuterChanged) {
    if (!RestoreSet(MODE,mSavedMode,MAX_UINT32)) Ok=FALSE;
    if (!RestoreSet(QCH,mSavedQch,MAX_UINT32)) Ok=FALSE;
  }
  mN976nUartMuxReport.Restored=Ok;
  if (!Ok) mN976nUartMuxReport.Quarantine=1;
  return Ok;
}

EFI_STATUS N976nUartMuxPrepare (VOID)
{
  UINT64 Start,End; UINT8 Route=0,Pending=0; BOOLEAN RouteKnown=FALSE,Changed=FALSE,Ok=FALSE;
  STATIC CONST UINT32 Gates[]={0x2010,0x206C,0x205C,0x2088,0x208C};
  if (mTried) return mN976nUartMuxReport.Status;
  mTried=TRUE; ZeroMem((VOID *)&mN976nUartMuxReport,sizeof(mN976nUartMuxReport));
  mCompareValid=mCompareLocked=mSampleValid=mWaitValid=FALSE;
  mN976nUartMuxReport.Status=EFI_NOT_READY; mN976nUartMuxReport.Phase=1;
  mHz=GetPerformanceCounterProperties(&Start,&End);
  if (!mHz || mHz>1000000000 || End<=Start || !InputClock()) { Fail(0x8601,EFI_UNSUPPORTED); goto Done; }
  for (UINTN I=0; I<ARRAY_SIZE(Gates); I++)
    if (!Gate(Clock(CMGP+Gates[I]))) { Fail(0x8602,EFI_NOT_READY); goto Done; }
  mSavedQch=Rd(QCH); mSavedMode=Rd(MODE);
  mN976nUartMuxReport.InheritedQch=mSavedQch; mN976nUartMuxReport.InheritedMode=mSavedMode;
  mN976nUartMuxReport.CaptureValid|=BIT5|BIT6;
  if (!Accessible(QCH,mSavedQch) || !Equal(MODE,mSavedMode,0,~4U)) { Fail(0x8603,EFI_NOT_READY); goto Done; }
  for (UINTN I=0; I<ARRAY_SIZE(mGpioOffsets); I++) {
    mGpio[I]=Rd(GPIO+mGpioOffsets[I]);
    mN976nUartMuxReport.InheritedPin[I]=mGpio[I]; mN976nUartMuxReport.CaptureValid|=1ULL<<(7+I);
  }
  if (!PinData(mN976nUartMuxReport.PinDataBefore,0)) { Fail(0x8640,EFI_NOT_READY); goto Done; }
  mN976nUartMuxReport.PinPhase=1;
  for (UINTN I=0; I<ARRAY_SIZE(mGpioOffsets); I++) {
    if (!Accessible(GPIO+mGpioOffsets[I],mGpio[I])) {
      Fail(0x8604,EFI_NOT_READY); goto Done;
    }
    if (I%3==0) {
      UINT32 Function=mGpio[I]&15;
      if (Function>2) {
        Different(GPIO+mGpioOffsets[I],2,mGpio[I],15,3);
        Fail(0x8604,EFI_NOT_READY); goto Done;
      }
      if (Function==1) mN976nUartMuxReport.PinOutputMask|=1ULL<<(I/3);
    }
  }
  mN976nUartMuxReport.Phase=2; mOuterChanged=TRUE;
  /* Samsung ra_req_enable_qch preserves ENABLE and only asserts REQUEST when
   * ENABLE=0. Expire/ignore-policy fields remain untouched. */
  if (!(mSavedQch&BIT0) && !Set(QCH,mSavedQch|BIT1,BIT0|BIT1)) goto Cleanup;
  if (!Set(MODE,4,MAX_UINT32)) goto Cleanup;
  for (UINTN I=0; I<ARRAY_SIZE(mConfigOffsets); I++) {
    mSaved[I]=Rd(HSI+mConfigOffsets[I]);
    switch (I) {
      case 0: mN976nUartMuxReport.InheritedControl=mSaved[I]; mN976nUartMuxReport.CaptureValid|=BIT13; break;
      case 1: mN976nUartMuxReport.InheritedFifoControl=mSaved[I]; mN976nUartMuxReport.CaptureValid|=BIT14; break;
      case 3: mN976nUartMuxReport.InheritedInterruptEnable=mSaved[I]; mN976nUartMuxReport.CaptureValid|=BIT15; break;
      case 14: mN976nUartMuxReport.InheritedUsiControl=mSaved[I]; mN976nUartMuxReport.CaptureValid|=BIT16; break;
      case 15: mN976nUartMuxReport.InheritedUsiOption=mSaved[I]; mN976nUartMuxReport.CaptureValid|=BIT17; break;
      default: break;
    }
    if (!Accessible(HSI+mConfigOffsets[I],mSaved[I])) {
      mRestoreBlocked=TRUE; Fail(0x8605,EFI_NOT_READY); goto Cleanup;
    }
  }
  /* No inherited in-flight request, slave ownership or unknown FIFO payload. */
  if (!Idle() || !Equal(HSI+CTL,mSaved[0],0,BIT31) ||
      !Equal(HSI+USI_CON,mSaved[14],0,~1U) || !Equal(HSI+USI_OPTION,mSaved[15],0,~7U) ||
      !Equal(HSI+INT_ST,(UINT32)mN976nUartMuxReport.Interrupt,0,~INT_KNOWN)) {
    mRestoreBlocked=TRUE; Fail(0x8605,EFI_NOT_READY); goto Cleanup;
  }
  mHsiSaved=TRUE; mPinsChanged=TRUE;
  mN976nUartMuxReport.PinPhase=2;
  if (!ReleaseOutputPins()) goto Cleanup;
  for (UINTN I=0; I<6; I+=3) {
    if (!PinField(I,2) || !PinField(I+1,0) || !PinField(I+2,0)) goto Cleanup;
  }
  mN976nUartMuxReport.PinPhase=4;
  mN976nUartMuxReport.Phase=3;
  if (!Configure()) { Fail(0x8607,EFI_NOT_READY); goto Cleanup; }
  mN976nUartMuxReport.PinDataReady[0]=mN976nUartMuxReport.Input>>32;
  mN976nUartMuxReport.PinDataReady[1]=(UINT32)mN976nUartMuxReport.Input;
  mN976nUartMuxReport.PinDataValid|=0x30; mN976nUartMuxReport.PinPhase=5;
  mN976nUartMuxReport.Phase=4;
  if (!SafetyStatus() || !ReadByte(0x02,&Pending)) goto Cleanup;
  mN976nUartMuxReport.UicBefore=Pending; mN976nUartMuxReport.UicSeen|=Pending;
  if (Pending&BIT7) { Different(0x02,0,Pending,BIT7,1); Fail(0x8621,EFI_NOT_READY); goto Cleanup; }
  if (!Opcode(5,0,&Route)) goto Cleanup;
  RouteKnown=TRUE; mN976nUartMuxReport.Before=Route;
  mN976nUartMuxReport.Phase=5;
  if (Route!=UART_ROUTE) {
    Changed=TRUE; if (!Opcode(6,UART_ROUTE,NULL)) goto Cleanup;
  }
  if (!Opcode(5,0,&Route)) goto Cleanup;
  mN976nUartMuxReport.After=Route;
  if (!Equal(0x52,Route,UART_ROUTE,0xFF)) { Fail(0x8624,EFI_DEVICE_ERROR); goto Cleanup; }
  if (!SafetyStatus()) goto Cleanup;
  Ok=TRUE;
Cleanup:
  if (!Ok && !mN976nUartMuxReport.Reason) Fail(0x8608,EFI_DEVICE_ERROR);
  /* Do not send a speculative undo while an opcode or HSI message may still
   * be active. A completed route change may be undone only on an idle owned
   * transport. A timeout leaves uncertainty visible instead of overwriting it.
   */
  if (!Ok && Changed && RouteKnown && !mOpcodeOutstanding && Idle() && ClockStable()) {
    UINT8 Restored=0;
    if (!Opcode(6,(UINT8)mN976nUartMuxReport.Before,NULL) ||
        !Opcode(5,0,&Restored) || Restored!=mN976nUartMuxReport.Before)
      mN976nUartMuxReport.Quarantine=1;
  }
  if (mOpcodeOutstanding) mN976nUartMuxReport.Quarantine=1;
  mN976nUartMuxReport.Phase=6;
  if (!Restore()) { Fail(0x8630,EFI_DEVICE_ERROR); Ok=FALSE; }
  if (Ok && !mN976nUartMuxReport.Quarantine) {
    mReady=TRUE; mN976nUartMuxReport.Status=EFI_SUCCESS; mN976nUartMuxReport.Phase=8;
  }
Done:
  return mN976nUartMuxReport.Status;
}
BOOLEAN N976nUartMuxReady (VOID) { return mReady; }

BOOLEAN N976nUartMuxGetRestoredSelectedConfig(UINT32 Config[16])
{
 if(Config==NULL)return FALSE;
 for(UINTN I=0;I<16;I++)Config[I]=0;
 if(!mReady||!mHsiSaved||!mHsiChanged||mHeld||mOpcodeOutstanding||mRestoreBlocked||
    mN976nUartMuxReport.Retired!=1||mN976nUartMuxReport.Restored!=1||
    mN976nUartMuxReport.Quarantine)return FALSE;
 for(UINTN I=0;I<16;I++)Config[I]=mSaved[I];
 return TRUE;
}
