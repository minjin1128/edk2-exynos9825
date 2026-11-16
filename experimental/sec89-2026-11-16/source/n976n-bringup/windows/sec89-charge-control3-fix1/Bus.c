/* SPDX-License-Identifier: MIT
 * Adapted from N976N BAT2 BatteryBus.c. Actual repeated-START, exact RX, DONE,
 * W1C ACK, quiescence and restore logic retained; state is per controller and
 * platform operations are callbacks. 9820 S10eBattery supplies architecture
 * comparison only: no watchdog/config/MUIC writes are imported.
 */
#include "Bus.h"
static void BusZero(void *Destination, N976N_BAT_U64 Bytes)
{
  N976N_BAT_U8 *D=(N976N_BAT_U8 *)Destination;
  while(Bytes--)*D++=0;
}
typedef N976N_BAT_U8 BAT_U8; typedef N976N_BAT_U16 BAT_U16; typedef N976N_BAT_U32 BAT_U32;
typedef N976N_BAT_U64 BAT_U64; typedef N976N_BAT_U64 BAT_SIZE; typedef int BAT_BOOL;
typedef N976N_BAT_U64 BAT_STATUS;
#define BAT_MAX_U32 0xFFFFFFFFU
#define BAT_MAX_U64 0xFFFFFFFFFFFFFFFFULL
#define BAT_ARRAY_SIZE(A) (sizeof(A)/sizeof((A)[0]))
#define BAT_BIT0 (1U<<0)
#define BAT_BIT1 (1U<<1)
#define BAT_BIT2 (1U<<2)
#define BAT_BIT3 (1U<<3)
#define BAT_BIT4 (1U<<4)
#define BAT_BIT5 (1U<<5)
#define BAT_BIT6 (1U<<6)
#define BAT_BIT7 (1U<<7)
#define BAT_BIT8 (1U<<8)
#define BAT_BIT9 (1U<<9)
#define BAT_BIT10 (1U<<10)
#define BAT_BIT11 (1U<<11)
#define BAT_BIT12 (1U<<12)
#define BAT_BIT13 (1U<<13)
#define BAT_BIT14 (1U<<14)
#define BAT_BIT15 (1U<<15)
#define BAT_BIT16 (1U<<16)
#define BAT_BIT17 (1U<<17)
#define BAT_BIT18 (1U<<18)
#define BAT_BIT19 (1U<<19)
#define BAT_BIT20 (1U<<20)
#define BAT_BIT21 (1U<<21)
#define BAT_BIT22 (1U<<22)
#define BAT_BIT23 (1U<<23)
#define BAT_BIT24 (1U<<24)
#define BAT_BIT25 (1U<<25)
#define BAT_BIT26 (1U<<26)
#define BAT_BIT27 (1U<<27)
#define BAT_BIT28 (1U<<28)
#define BAT_BIT29 (1U<<29)
#define BAT_BIT30 (1U<<30)
#define BAT_BIT31 (1U<<31)
#define mN976nBatteryBusReport C->Report
#define mHeld C->S.Held
#define mHsiSaved C->S.HsiSaved
#define mHsiChanged C->S.HsiChanged
#define mOuterChanged C->S.OuterChanged
#define mPinsChanged C->S.PinsChanged
#define mRestoreBlocked C->S.RestoreBlocked
#define mHz C->S.Hz
#define mSavedQch C->S.SavedQch
#define mSavedMode C->S.SavedMode
#define mGpio C->S.Gpio
#define mSaved C->S.Saved
#define mClockAddress C->S.ClockAddress
#define mClockCount C->S.ClockCount
#define mClockValue C->S.ClockValue
#define mCompareValid C->S.CompareValid
#define mCompareLocked C->S.CompareLocked
#define mSampleValid C->S.SampleValid
#define mWaitValid C->S.WaitValid
#define mCompareAddress C->S.CompareAddress
#define mCompareExpected C->S.CompareExpected
#define mCompareActual C->S.CompareActual
#define mCompareMask C->S.CompareMask
#define mCompareKind C->S.CompareKind
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
#define INT_DONE BAT_BIT7
#define INT_ERRORS (0xF00U | 0x3CU)
#define INT_KNOWN 0xFFFU
#define AUTO_RUN BAT_BIT31
#define AUTO_STOP BAT_BIT17
#define AUTO_READ BAT_BIT16
#define HSI_BUSY (BAT_BIT17 | BAT_BIT16)
#define STALL_LIMIT 20000U

static const BAT_U32 mConfigOffsets[16] = {
  CTL, FIFO_CTL, TRAILING, INT_EN, CONF, AUTO, TIMEOUT,
  0x54, 0x58, 0x5C, FS1, FS2, FS3, ADDR, USI_CON, USI_OPTION
};
static const BAT_U32 mGpioOffsets[6] = {0x180,0x188,0x18C,0x1A0,0x1A8,0x1AC};
typedef struct { BAT_U64 Start, Previous; BAT_U32 Same; } DEADLINE;
static BAT_U32 Rd(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A) { return C->Ops.Read32(C->Opaque,A); }
static void Wr(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U32 V)
{
  mN976nBatteryBusReport.NoMutation=0;
  C->Ops.Write32(C->Opaque,A,V); C->Ops.Barrier(C->Opaque);
}
/* Staging a failed predicate is not a failure decision: idle polling may later
 * succeed. Fail(C) alone freezes the first fatal observation before cleanup.
 * Every Actual argument is from a read already performed by the original core.
 */
static BAT_BOOL Different(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U64 E, BAT_U64 V, BAT_U64 M, BAT_U64 Kind)
{
  if (mCompareLocked) return 0;
  mCompareValid=1; mCompareAddress=A; mCompareExpected=E;
  mCompareActual=V; mCompareMask=M; mCompareKind=Kind; return 0;
}
static BAT_BOOL Accessible(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U32 V)
{
  return V!=BAT_MAX_U32 || Different(C, A,BAT_MAX_U32,V,BAT_MAX_U32,2);
}
static BAT_BOOL Equal(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U32 V, BAT_U32 E, BAT_U32 M)
{
  return ((V^E)&M)==0 || Different(C, A,E,V,M,1);
}
static void Fail(N976N_BAT_BUS_CONTEXT *C, BAT_U64 Why, BAT_STATUS Status)
{
  if (!mN976nBatteryBusReport.Reason) {
    mN976nBatteryBusReport.Reason=Why;
    mN976nBatteryBusReport.Status=Status;
    mN976nBatteryBusReport.FailurePhase=mN976nBatteryBusReport.Phase;
    mN976nBatteryBusReport.PinFailurePhase=mN976nBatteryBusReport.PinPhase;
    mN976nBatteryBusReport.CaptureValid|=BAT_BIT0;
    if (mCompareValid) {
      mN976nBatteryBusReport.CaptureValid|=BAT_BIT1;
      mN976nBatteryBusReport.FirstAddress=mCompareAddress;
      mN976nBatteryBusReport.FirstExpected=mCompareExpected;
      mN976nBatteryBusReport.FirstActual=mCompareActual;
      mN976nBatteryBusReport.FirstMask=mCompareMask;
      mN976nBatteryBusReport.FirstCompare=mCompareKind;
    }
    if (mSampleValid) mN976nBatteryBusReport.CaptureValid|=BAT_BIT2;
    if (mWaitValid) mN976nBatteryBusReport.CaptureValid|=BAT_BIT3;
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
static DEADLINE Begin(N976N_BAT_BUS_CONTEXT *C)
{
  DEADLINE D; D.Start=D.Previous=C->Ops.Counter(C->Opaque); D.Same=0; return D;
}
static BAT_BOOL Expired(N976N_BAT_BUS_CONTEXT *C, DEADLINE *D, BAT_U32 Us)
{
  BAT_U64 Now=C->Ops.Counter(C->Opaque), Elapsed=Now-D->Start;
  mWaitValid=1;
  if (!C->S.Cleanup && !C->S.InTransaction && C->Ops.Cancelled(C->Opaque)) {
    mN976nBatteryBusReport.WaitExit=4; return 1;
  }
  if (Now < D->Previous) { mN976nBatteryBusReport.WaitExit=3; return 1; }
  D->Same=Now==D->Previous ? D->Same+1 : 0; D->Previous=Now;
  mN976nBatteryBusReport.WaitUs=(Elapsed/mHz)*1000000+(Elapsed%mHz)*1000000/mHz;
  if (Elapsed >= (mHz*Us+999999)/1000000) {
    mN976nBatteryBusReport.WaitExit=1; return 1;
  }
  if (D->Same >= STALL_LIMIT) { mN976nBatteryBusReport.WaitExit=2; return 1; }
  C->Ops.StallUs(C->Opaque,1);
  return 0;
}
static BAT_BOOL Set(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U32 V, BAT_U32 Mask)
{
  BAT_U32 Actual; Wr(C, A,V); Actual=Rd(C, A);
  if (Actual!=BAT_MAX_U32 && ((Actual^V)&Mask)==0) return 1;
  mN976nBatteryBusReport.SetupOffset=A;
  mN976nBatteryBusReport.SetupExpected=V;
  mN976nBatteryBusReport.SetupActual=Actual;
  mN976nBatteryBusReport.SetupDiff++;
  if (!Accessible(C, A,Actual)) return 0;
  return Different(C, A,V,Actual,Mask,1);
}
static BAT_BOOL Gate(N976N_BAT_BUS_CONTEXT *C, BAT_U32 V)
{
  BAT_SIZE A=(BAT_SIZE)mN976nBatteryBusReport.ClockAddress;
  mN976nBatteryBusReport.GateAddress=A; mN976nBatteryBusReport.GateValue=V;
  mN976nBatteryBusReport.CaptureValid|=BAT_BIT4;
  return Accessible(C, A,V) && ((V&BAT_BIT20) ? Equal(C, A,V,BAT_BIT21,BAT_BIT21) : Equal(C, A,V,0,BAT_BIT28));
}
static BAT_U32 Clock(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A)
{
  BAT_U32 V; BAT_SIZE Index;
  if(!N976nBatBusClockAddressAllowed(A))return BAT_MAX_U32;
  for (Index=0;Index<C->Binding.ClockCount;Index++)
    if (C->Binding.ClockAddress[Index]==A) break;
  if (!C->S.Capturing && Index==C->Binding.ClockCount) {
    Different(C,A,1,0,BAT_MAX_U32,4); return BAT_MAX_U32;
  }
  V=Rd(C,A);
  if (!C->S.Capturing && !Equal(C,A,V,C->Binding.ClockValue[Index],BAT_MAX_U32)) return BAT_MAX_U32;
  mN976nBatteryBusReport.ClockAddress=A; mN976nBatteryBusReport.ClockValue=V;
  if (mClockCount>=BAT_ARRAY_SIZE(mClockAddress)) return BAT_MAX_U32;
  mClockAddress[mClockCount]=A; mClockValue[mClockCount++]=V; return V;
}
static BAT_BOOL ClockStable(N976N_BAT_BUS_CONTEXT *C)
{
  for (BAT_SIZE I=0; I<mClockCount; I++)
    if (!Equal(C, mClockAddress[I],Rd(C, mClockAddress[I]),mClockValue[I],BAT_MAX_U32)) return 0;
  return 1;
}
static BAT_BOOL Field(N976N_BAT_BUS_CONTEXT *C, BAT_U32 V, BAT_U32 Mask, BAT_U32 Busy)
{
  /* Only SELECT/DIVRATIO and BUSY define this rate. Unrelated register policy
   * fields must not become a guessed all-bits-zero prerequisite. */
  (void)C; (void)Mask;
  return V!=BAT_MAX_U32 && !(V&Busy);
}
static BAT_BOOL Pll(N976N_BAT_BUS_CONTEXT *C, BAT_U32 V, BAT_U64 *Hz)
{
  BAT_U32 M=(V>>16)&0x3FF, P=(V>>8)&63, S=V&7;
  (void)C;
  if (V==BAT_MAX_U32 || (V&BAT_BIT7)) return 0;
  if (!(V&BAT_BIT4)) { *Hz=26000000; return 1; }
  if ((V&(BAT_BIT31|BAT_BIT29))!=(BAT_BIT31|BAT_BIT29) || !M || !P || S>6) return 0;
  *Hz=26000000ULL*M/(P<<S); return *Hz>=26000000 && *Hz<=4000000000ULL;
}
/* Resolve inherited CMGP3 source, including APM and the two source PLL paths.
 * No shared clock is retuned. Fixed RCO/DLL rates come from cmucal-node.c.
 */
static BAT_BOOL InputClock(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 M=Clock(C, CMGP+0x1020), D=Clock(C, CMGP+0x1824), U, A, AD, S, TD, PD;
  BAT_U64 Hz=49152000;
  if (!Field(C, M,1,BAT_BIT16) || !Field(C, D,15,BAT_BIT16)) return 0;
  if (M&1) {
    U=Clock(C, CMGP+0x100);
    if (!Field(C, U,BAT_BIT4,BAT_BIT7)) return 0;
    if (U&BAT_BIT4) {
      if (!Gate(C, Clock(C, APM+0x200C))) return 0;
      A=Clock(C, APM+0x1004); AD=Clock(C, APM+0x1804);
      if (!Field(C, A,3,BAT_BIT16) || !Field(C, AD,7,BAT_BIT16)) return 0;
      switch (A&3) {
        case 0: case 3:
          U=Clock(C, APM+0x120); if (!Field(C, U,BAT_BIT4,BAT_BIT7)) return 0; break;
        case 2:
          U=Clock(C, APM+0x140); if (!Field(C, U,BAT_BIT4,BAT_BIT7)) return 0;
          if (U&BAT_BIT4) Hz=360000000; break;
        case 1:
          U=Clock(C, APM+0x100); if (!Field(C, U,BAT_BIT4,BAT_BIT7)) return 0;
          if (U&BAT_BIT4) {
            if (!Gate(C, Clock(C, TOP+0x2018))) return 0;
            S=Clock(C, TOP+0x1004); TD=Clock(C, TOP+0x1800);
            if (!Field(C, S,1,BAT_BIT16) || !Field(C, TD,3,BAT_BIT16)) return 0;
            if (!(S&1)) {
              S=Clock(C, TOP+0x10DC); PD=Clock(C, TOP+0x18D0);
              if (!Field(C, S,1,BAT_BIT16) || !Field(C, PD,3,BAT_BIT16) ||
                  !Pll(C, Clock(C, TOP+((S&1)?0x100:0x160)),&Hz)) return 0;
              Hz/=(PD&3)+1;
            } else {
              PD=Clock(C, TOP+0x18E4);
              if (!Field(C, PD,1,BAT_BIT16) || !Pll(C, Clock(C, TOP+0x1A0),&Hz)) return 0;
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
  if (Hz<6000000 || Hz>400000000 || !ClockStable(C)) return 0;
  mN976nBatteryBusReport.InputHz=Hz; return 1;
}
static BAT_BOOL Empty(N976N_BAT_BUS_CONTEXT *C, BAT_U32 F)
{
  return Accessible(C, HSI+FIFO_ST,F) && Equal(C, HSI+FIFO_ST,F,BAT_BIT24|BAT_BIT8,BAT_BIT24|BAT_BIT8) &&
    Equal(C, HSI+FIFO_ST,F,0,BAT_BIT23|BAT_BIT7|0x7F007FU);
}
static void Sample(N976N_BAT_BUS_CONTEXT *C)
{
  mN976nBatteryBusReport.Interrupt=Rd(C, HSI+INT_ST);
  mN976nBatteryBusReport.Transfer=Rd(C, HSI+TRANS);
  mN976nBatteryBusReport.Fifo=Rd(C, HSI+FIFO_ST);
  mN976nBatteryBusReport.Auto=Rd(C, HSI+AUTO);
  mSampleValid=1;
}
static BAT_BOOL Idle(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 T; Sample(C); T=(BAT_U32)mN976nBatteryBusReport.Transfer;
  if (!Accessible(C, HSI+TRANS,T) || !Equal(C, HSI+TRANS,T,0,HSI_BUSY)) return 0;
  if ((T&15)>1) return Different(C, HSI+TRANS,1,T,15,3);
  return Equal(C, HSI+AUTO,(BAT_U32)mN976nBatteryBusReport.Auto,0,AUTO_RUN) &&
    Empty(C, (BAT_U32)mN976nBatteryBusReport.Fifo);
}
/* Samsung clears USI reset and initializes MASTER/AUTO before using FIFO
 * readiness. A restored reset controller is not an initialized idle one:
 * DIAG1 observed MODE0/CTL0/USI_CON1 with FIFO_STATUS0. Classify that state
 * explicitly instead of interpreting missing EMPTY flags as queued data.
 * Neither class permits an in-flight request; mixed/reset-transition states
 * remain unowned. The binding ABI is unchanged and both endpoints use this.
 */
#define INHERITED_RESET 1U
#define INHERITED_READY 2U
static BAT_U32 InheritedClass(BAT_U32 Mode, const BAT_U32 *Config)
{
  if (Mode==0 && Config[0]==0 && Config[3]==0 && Config[4]==0 &&
      Config[5]==0 && Config[14]==1) return INHERITED_RESET;
  if (Mode==4 && Config[14]==0 &&
      (Config[0]&(BAT_BIT31|BAT_BIT3|BAT_BIT0))==BAT_BIT3 &&
      (Config[4]&BAT_BIT31)) return INHERITED_READY;
  return 0;
}
static BAT_BOOL InheritedIdle(N976N_BAT_BUS_CONTEXT *C, BAT_U32 Mode, const BAT_U32 *Config)
{
  BAT_U32 Class=InheritedClass(Mode,Config),T,F;
  if (!Class) return Different(C, 0,1,0,1,4);
  if (Class==INHERITED_READY)
    return Idle(C) && Equal(C, HSI+INT_ST,(BAT_U32)C->Report.Interrupt,0,BAT_MAX_U32);
  Sample(C); T=(BAT_U32)C->Report.Transfer; F=(BAT_U32)C->Report.Fifo;
  /* This is admission while reset is held, not transaction retirement. Keep
   * accessible-register, no RUN/BUSY, empty level/full and zero pending IRQ
   * predicates. EMPTY flags become mandatory after Configure, unchanged.
   */
  if (!Accessible(C, HSI+TRANS,T) || !Equal(C, HSI+TRANS,T,0,HSI_BUSY)) return 0;
  if ((T&15)>1) return Different(C, HSI+TRANS,1,T,15,3);
  return Equal(C, HSI+AUTO,(BAT_U32)C->Report.Auto,0,BAT_MAX_U32) &&
    Accessible(C, HSI+FIFO_ST,F) && Equal(C, HSI+FIFO_ST,F,0,BAT_BIT23|BAT_BIT7|0x7F007FU) &&
    Equal(C, HSI+INT_ST,(BAT_U32)C->Report.Interrupt,0,BAT_MAX_U32);
}
static BAT_BOOL WaitIdle(N976N_BAT_BUS_CONTEXT *C)
{
  DEADLINE D=Begin(C);
  do { if (Idle(C)) { mCompareValid=0; return 1; } } while (!Expired(C, &D,100000));
  return 0;
}
/* Selected MODE4 can expose a saved configuration while USI reset remains
 * asserted. Missing EMPTY flags are not FIFO payload. This is admission of an
 * exact captured image, never transaction retirement: BUSY/RUN, FIFO level/full,
 * pending IRQ and interrupt enable must all be absent. Configure still demands
 * strict Idle before any request. PRE-view InheritedClass is kept separate. */
static BAT_BOOL SelectedQuiescent(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 T,F;
  if(mSaved[14]!=1)return Idle(C)&&C->Report.Interrupt==0;
  Sample(C);T=(BAT_U32)C->Report.Transfer;F=(BAT_U32)C->Report.Fifo;
  if(!Accessible(C,HSI+TRANS,T)||!Equal(C,HSI+TRANS,T,0,HSI_BUSY))return 0;
  if((T&15)>1)return Different(C,HSI+TRANS,1,T,15,3);
  return Equal(C,HSI+AUTO,(BAT_U32)C->Report.Auto,0,AUTO_RUN)&&
    Accessible(C,HSI+FIFO_ST,F)&&Equal(C,HSI+FIFO_ST,F,0,BAT_BIT23|BAT_BIT7|0x7F007FU)&&
    Equal(C,HSI+INT_ST,(BAT_U32)C->Report.Interrupt,0,BAT_MAX_U32)&&
    Equal(C,HSI+INT_EN,mSaved[3],0,BAT_MAX_U32);
}
static BAT_BOOL LinesHigh(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 A=Rd(C, GPIO+0x184),B=Rd(C, GPIO+0x1A4);
  mN976nBatteryBusReport.Input=((BAT_U64)A<<32)|B;
  return Accessible(C, GPIO+0x184,A) && Accessible(C, GPIO+0x1A4,B) &&
    Equal(C, GPIO+0x184,A,1,1) && Equal(C, GPIO+0x1A4,B,1,1);
}
static BAT_BOOL PinData(N976N_BAT_BUS_CONTEXT *C, volatile BAT_U64 *Values, BAT_SIZE ValidShift)
{
  BAT_U32 A=Rd(C, GPIO+0x184),B=Rd(C, GPIO+0x1A4);
  Values[0]=A; Values[1]=B;
  mN976nBatteryBusReport.PinDataValid|=3ULL<<ValidShift;
  return Accessible(C, GPIO+0x184,A) && Accessible(C, GPIO+0x1A4,B);
}
static BAT_BOOL PinField(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE Index, BAT_U32 Value)
{
  BAT_SIZE A=GPIO+mGpioOffsets[Index]; BAT_U32 Current=Rd(C, A);
  if (!Accessible(C, A,Current)) return 0;
  /* Samsung bank type gives each of these one-pin CON/PUD/DRV fields four
   * bits. Match pinctrl's RMW and preserve every unowned bit at its current
   * value, including during restoration. Never write the intervening DAT.
   */
  mN976nBatteryBusReport.PinChangedMask|=1ULL<<(Index/3);
  return Set(C, A,(Current&~15U)|(Value&15U),15);
}
static BAT_BOOL ReleaseOutputPins(N976N_BAT_BUS_CONTEXT *C)
{
  DEADLINE D;
  if (!mN976nBatteryBusReport.PinOutputMask) return 1;
  /* Local safety transition, not a copied Linux sequence: first release the
   * inherited GPIO drivers. Controller ownership/idle was admitted before
   * this function. No GPIO clock pulses and no guessed DATA-latch writes.
   */
  if (!PinField(C, 0,0) || !PinField(C, 3,0)) {
    Fail(C, 0xB141,N976N_BAT_BUS_DEVICE_ERROR); return 0;
  }
  D=Begin(C);
  do {
    if (!ClockStable(C) || !PinData(C, mN976nBatteryBusReport.PinDataReleased,2)) {
      Fail(C, 0xB142,N976N_BAT_BUS_NOT_READY); return 0;
    }
    BAT_U32 A=(BAT_U32)mN976nBatteryBusReport.PinDataReleased[0];
    BAT_U32 B=(BAT_U32)mN976nBatteryBusReport.PinDataReleased[1];
    if (Equal(C, GPIO+0x184,A,1,1) && Equal(C, GPIO+0x1A4,B,1,1)) {
      mCompareValid=0; mN976nBatteryBusReport.PinPhase=3; return 1;
    }
  } while (!Expired(C, &D,100000));
  Fail(C, 0xB142,N976N_BAT_BUS_NOT_READY); return 0;
}
static BAT_BOOL Ack(N976N_BAT_BUS_CONTEXT *C, BAT_BOOL Completion)
{
  BAT_U32 P=Rd(C, HSI+INT_ST);
  mN976nBatteryBusReport.Interrupt=P;
  if (!Accessible(C, HSI+INT_ST,P) || !Equal(C, HSI+INT_ST,P,0,~INT_KNOWN)) return 0;
  /* The read inside ACK is the final acceptance observation. An error that
   * arrives after the RX-loop sample (or during WaitIdle) must not be cleared
   * and then promoted to success. Cleanup may retire errors, never validate data. */
  if (Completion && !Equal(C, HSI+INT_ST,P,INT_DONE,INT_DONE|INT_ERRORS)) return 0;
  if (P) Wr(C, HSI+INT_ST,P);
  return Equal(C, HSI+INT_ST,Rd(C, HSI+INT_ST),0,~BAT_BIT0); /* TX-empty may remain level asserted. */
}
/* Private exact pointer/repeated-START/read contract. There is no arbitrary
 * register write or address API. Each successful STOP read is ACKed/retired
 * before the codec is allowed to mark the field valid. */
static BAT_BOOL Transfer(N976N_BAT_BUS_CONTEXT *C, const N976N_BATTERY_READ *Spec, BAT_BOOL Read, BAT_BOOL Stop, BAT_U8 *Data, BAT_SIZE Length)
{
  BAT_U32 Auto, Ctl, Done=0; DEADLINE D;
  mCompareValid=0;
  if (!C->S.Cleanup && C->Ops.Cancelled(C->Opaque) && !mHeld) { Fail(C,0xB151,N976N_BAT_BUS_ABORTED); return 0; }
  if (!Spec || !Data ||
      (!N976nBatteryReadAllowed(Spec->Address,Spec->Register,Spec->Bytes) &&
       !N976nPowerReadAllowed(Spec->Address,Spec->Register,Spec->Bytes)) ||
      (Read ? (!Stop || !mHeld || Length!=Spec->Bytes) :
              (C->ControlPayload ? (!Stop||mHeld||Length!=2||Spec->Address!=0x69||
                (Spec->Register!=0xB7&&Spec->Register!=0xB9&&Spec->Register!=0xBD&&Spec->Register!=0xC0)||Data[0]!=Spec->Register) :
                (Stop || mHeld || Length!=1 || Data[0]!=Spec->Register))) ||
      !ClockStable(C) ||
      (!mHeld && (!Idle(C) || !LinesHigh(C))) || !Ack(C, 0)) {
    if (!mCompareValid) Different(C, 0,1,0,1,4); /* private argument contract */
    Fail(C, 0xB110,N976N_BAT_BUS_NOT_READY); return 0;
  }
  if (mHeld) {
    Sample(C);
    if (!Equal(C, HSI+AUTO,(BAT_U32)mN976nBatteryBusReport.Auto,0,AUTO_RUN) ||
        !Empty(C, (BAT_U32)mN976nBatteryBusReport.Fifo)) {
      Fail(C, 0xB111,N976N_BAT_BUS_NOT_READY); return 0;
    }
  }
  Ctl=BAT_BIT3|(Read?BAT_BIT6:BAT_BIT7);
  Auto=(Stop?AUTO_STOP:0)|(Read?AUTO_READ:0)|(BAT_U32)Length;
  Wr(C, HSI+FIFO_CTL,BAT_BIT0|BAT_BIT1|((BAT_U32)Length<<4)|((BAT_U32)Length<<16));
  /* Direction selectors can read back asynchronously. Completion, exact
   * bytes and terminal bus state are the functional acceptance criteria. */
  Wr(C, HSI+CTL,Ctl); Wr(C, HSI+ADDR,(7U<<24)|((BAT_U32)Spec->Address<<10));
  Wr(C, HSI+INT_EN,INT_DONE|INT_ERRORS); Wr(C, HSI+AUTO,Auto);
  if(C->ControlTicket&&!mHeld&&(!C->ControlGuard||!C->ControlGuard(C->ControlOpaque,C->ControlTicket))){
    Fail(C,0xB154,N976N_BAT_BUS_ABORTED);return 0;
  }
  C->S.InTransaction=1;
  Wr(C, HSI+AUTO,Auto|AUTO_RUN); mHeld=1; mN976nBatteryBusReport.Transfers++;
  mN976nBatteryBusReport.Retired=0; D=Begin(C);
  for (;;) {
    BAT_BOOL Dequeued=0; Sample(C);
    BAT_U32 I=(BAT_U32)mN976nBatteryBusReport.Interrupt,F=(BAT_U32)mN976nBatteryBusReport.Fifo;
    if (!Equal(C, HSI+INT_ST,I,0,~INT_KNOWN|INT_ERRORS) || !Accessible(C, HSI+FIFO_ST,F) ||
        !Accessible(C, HSI+TRANS,(BAT_U32)mN976nBatteryBusReport.Transfer) ||
        !Accessible(C, HSI+AUTO,(BAT_U32)mN976nBatteryBusReport.Auto)) {
      Fail(C, 0xB112,N976N_BAT_BUS_DEVICE_ERROR); return 0;
    }
    if (!Read && Done<Length && !(F&BAT_BIT7) && (F&0x7F)<64) {
      if(C->ControlPayload&&(!C->ControlGuard||!C->ControlGuard(C->ControlOpaque,C->ControlTicket))){
        Fail(C,0xB154,N976N_BAT_BUS_ABORTED);return 0;
      }
      Wr(C, HSI+TX,Data[Done++]); mN976nBatteryBusReport.TxBytes++;
    }
    if (Read && !(F&BAT_BIT24)) {
      if (Done>=Length || (F&BAT_BIT23)) {
        if (Done>=Length) Different(C, 0,Length-1,Done,BAT_MAX_U32,3);
        else Different(C, HSI+FIFO_ST,0,F,BAT_BIT23,1);
        Fail(C, 0xB113,N976N_BAT_BUS_DEVICE_ERROR); return 0;
      }
      Data[Done++]=(BAT_U8)Rd(C, HSI+RX); mN976nBatteryBusReport.RxBytes++; Dequeued=1;
    }
    if (!Dequeued && Done==Length && (I&INT_DONE) && Empty(C, F) &&
        !(mN976nBatteryBusReport.Auto&AUTO_RUN)) {
      if (Stop && !WaitIdle(C)) { Fail(C, 0xB114,C->Report.WaitExit==4?N976N_BAT_BUS_ABORTED:N976N_BAT_BUS_TIMEOUT); return 0; }
      if (!Ack(C, 1) || !ClockStable(C)) { Fail(C, 0xB115,N976N_BAT_BUS_DEVICE_ERROR); return 0; }
      Wr(C,HSI+INT_EN,0);
      if(!Equal(C,HSI+INT_EN,Rd(C,HSI+INT_EN),0,BAT_MAX_U32)) {
        Fail(C,0xB115,N976N_BAT_BUS_DEVICE_ERROR);return 0;
      }
      C->S.InTransaction=0; mHeld=!Stop; mN976nBatteryBusReport.Retired=Stop; mCompareValid=0; return 1;
    }
    if (Expired(C, &D,100000)) {
      /* A preempted reader may resume with the complete response in RX.
       * Only an actual RX dequeue permits one more fresh observation; each
       * such step consumes one of at most Spec->Bytes (<=2) bytes. Never
       * renew D, extend TX, ignore clock faults, retry, or synthesize DONE.
       * The next sample must still pass exact length/empty/DONE/AUTO and
       * the normal idle, final ACK, clock and INT_EN readback checks. */
      if (Read && Dequeued && C->Report.WaitExit==1) continue;
      mCompareValid=0; Fail(C, 0xB116,C->Report.WaitExit==4?N976N_BAT_BUS_ABORTED:N976N_BAT_BUS_TIMEOUT); return 0;
    }
  }
}
static BAT_BOOL ReadField(N976N_BAT_BUS_CONTEXT *C, BAT_U32 Field, N976N_BATTERY_RAW *Raw)
{
  N976N_BATTERY_READ Spec; BAT_U8 Pointer, Data[2]={0,0}; BAT_U64 RxBefore;
  mN976nBatteryBusReport.Field=Field;
  if (!N976nBatteryReadSpec(Field,&Spec)) {
    Fail(C, 0xB117,N976N_BAT_BUS_INVALID_PARAMETER); return 0;
  }
  mN976nBatteryBusReport.Address=Spec.Address;
  mN976nBatteryBusReport.Register=Spec.Register;
  mN976nBatteryBusReport.Requested=Spec.Bytes;
  Pointer=Spec.Register;
  RxBefore=mN976nBatteryBusReport.RxBytes;
  BAT_BOOL Ok=Transfer(C, &Spec,0,0,&Pointer,1) &&
             Transfer(C, &Spec,1,1,Data,Spec.Bytes);
  if(Ok && C->Ops.Cancelled(C->Opaque)){Fail(C,0xB151,N976N_BAT_BUS_ABORTED);Ok=0;}
  BAT_U32 Received=(BAT_U32)(mN976nBatteryBusReport.RxBytes-RxBefore);
  mN976nBatteryBusReport.Received=Received;
  if (N976nBatteryRecord(Raw,Field,Ok && mN976nBatteryBusReport.Retired,
                        Data,Received)!=N976N_BAT_OK) {
    if (Ok) Fail(C, 0xB118,N976N_BAT_BUS_DEVICE_ERROR);
    return 0;
  }
  return 1;
}
static BAT_BOOL Configure(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 Div,Shift,V; BAT_U64 Hz=mN976nBatteryBusReport.InputHz;
  mCompareValid=0;
  /* HSI45 uses Samsung's default FAST400kHz mode, unlike touch's100kHz. */
  Div=(BAT_U32)(Hz/(400000U*15U)); Shift=(BAT_U32)((9*Hz/1000000)/((Div+1)*10));
  if (!Div || Div>255 || !Shift || Shift>=8) { Fail(C, 0xB106,N976N_BAT_BUS_UNSUPPORTED); return 0; }
  mHsiChanged=1;
  if (!Set(C, HSI+USI_CON,0,BAT_BIT0)) return 0;
  Wr(C, HSI+CTL,mSaved[0]|BAT_BIT31); V=Rd(C, HSI+CTL); Wr(C, HSI+CTL,V&~BAT_BIT31);
  Wr(C, HSI+INT_EN,0);
  V=Rd(C, HSI+FS3); Wr(C, HSI+FS3,(V&~0x00FF0000U)|(Div<<16));
  V=Rd(C, HSI+FS2); Wr(C, HSI+FS2,(V&~0xFFU)|((0xFFU<<Shift)&0xFFU));
  V=Rd(C, HSI+FS1); Wr(C, HSI+FS1,(V&~0x00FF0000U)|(((0xFFU<<(Shift-1))&0xFFU)<<16));
  Wr(C, HSI+CTL,BAT_BIT3); Wr(C, HSI+TRAILING,0xFFFFFF);
  Wr(C, HSI+TIMEOUT,mSaved[6]&~BAT_BIT31);
  V=Rd(C, HSI+CONF); Wr(C, HSI+CONF,(V&~(BAT_BIT29|BAT_BIT30))|BAT_BIT31);
  return ClockStable(C) && WaitIdle(C) && LinesHigh(C) && Ack(C, 0);
}
static BAT_BOOL RestoreSet(N976N_BAT_BUS_CONTEXT *C, BAT_SIZE A, BAT_U32 V, BAT_U32 Mask)
{
  BAT_BOOL Ok=Set(C, A,V,Mask);
  /* Restoration continues as before, but its first failed write/readback
   * predicate must not be replaced by a subsequent restoration mismatch. */
  if (!Ok) mCompareLocked=1;
  return Ok;
}
static int BindingLive(N976N_BAT_BUS_CONTEXT *C);
static BAT_BOOL SelectedOuterOwned(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 Q=mSavedQch|((mSavedQch&BAT_BIT0)?0:BAT_BIT1);
  if(!ClockStable(C)||!Equal(C,MODE,Rd(C,MODE),4,BAT_MAX_U32)||
     !Equal(C,QCH,Rd(C,QCH),Q,BAT_MAX_U32))return 0;
  for(unsigned I=0;I<6;I++)
    if(!Equal(C,GPIO+mGpioOffsets[I],Rd(C,GPIO+mGpioOffsets[I]),mGpio[I],15))return 0;
  return 1;
}
static BAT_BOOL Restore(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_BOOL Ok=1;
  mCompareValid=mCompareLocked=0;
  if (mRestoreBlocked) { mN976nBatteryBusReport.Quarantine=1; return 0; }
  if (mHsiSaved) {
    if (!ClockStable(C)) { mN976nBatteryBusReport.Quarantine=1; return 0; }
    if (!mHsiChanged) {
      /* Pad release/selection can fail before Configure writes HSI. No command
       * was issued and the inherited register image must still match exactly.
       * Do not demand active FIFO flags, mask IRQs or ACK someone else's state.
       * Once Configure attempts any HSI write, the strict retirement path below
       * applies even if initialization fails partway through.
       */
      if(!mPinsChanged&&!SelectedOuterOwned(C)){mN976nBatteryBusReport.Quarantine=1;return 0;}
      for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(mConfigOffsets); I++)
        if (!Equal(C, HSI+mConfigOffsets[I],Rd(C, HSI+mConfigOffsets[I]),mSaved[I],BAT_MAX_U32)) {
          mN976nBatteryBusReport.Quarantine=1; return 0;
        }
      if (mHeld || mN976nBatteryBusReport.Transfers ||
          !SelectedQuiescent(C) || C->Report.Interrupt) {
        mN976nBatteryBusReport.Quarantine=1; return 0;
      }
      mN976nBatteryBusReport.Retired=1;
    } else {
      if (!WaitIdle(C)) { mN976nBatteryBusReport.Quarantine=1; return 0; }
      mHeld=0; Wr(C, HSI+INT_EN,0);
      if (!Ack(C, 0)) { mN976nBatteryBusReport.Quarantine=1; return 0; }
      mN976nBatteryBusReport.Retired=1;
      /* Restore the idle configuration, with interrupt enable and USI reset
       * last. No saved AUTO_RUN is admitted, so no saved value submits I/O. */
      for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(mConfigOffsets); I++) {
        if (I==3 || I==14) continue;
        if (!RestoreSet(C, HSI+mConfigOffsets[I],mSaved[I],BAT_MAX_U32)) Ok=0;
      }
      if (!RestoreSet(C, HSI+INT_EN,mSaved[3],BAT_MAX_U32)) Ok=0;
      if (!RestoreSet(C, HSI+USI_CON,mSaved[14],BAT_MAX_U32)) Ok=0;
    }
  }
  if (!Ok) { mN976nBatteryBusReport.Quarantine=1; return 0; }
  if (mPinsChanged) {
    BAT_BOOL PinsOk=1;
    /* Retired HSI first, saved pull/drive next, and original CON last. This
     * prevents re-enabling an inherited GPIO output with temporary pad policy.
     * Its DATA latch was never changed, so no speculative latch reconstruction.
     */
    for (BAT_SIZE I=0; I<6; I+=3) {
      BAT_BOOL PadOk=1;
      if (!PinField(C, I+1,mGpio[I+1])) { mCompareLocked=1; PadOk=0; }
      if (!PinField(C, I+2,mGpio[I+2])) { mCompareLocked=1; PadOk=0; }
      if (PadOk && PinField(C, I,mGpio[I])) mN976nBatteryBusReport.PinRestoredMask|=1ULL<<(I/3);
      else { mCompareLocked=1; PinsOk=0; }
    }
    if (!PinData(C, mN976nBatteryBusReport.PinDataRestored,6)) PinsOk=0;
    if (!PinsOk) { mN976nBatteryBusReport.Quarantine=1; return 0; }
    mN976nBatteryBusReport.PinPhase=8;
  }
  if (mOuterChanged) {
    if (!RestoreSet(C, MODE,mSavedMode,BAT_MAX_U32)) Ok=0;
    if (!RestoreSet(C, QCH,mSavedQch,BAT_MAX_U32)) Ok=0;
  }
  if (Ok && mOuterChanged && !BindingLive(C)) Ok=0;
  mN976nBatteryBusReport.Restored=Ok;
  if (!Ok) mN976nBatteryBusReport.Quarantine=1;
  return Ok;
}


int N976nBatBusClockAddressAllowed(N976N_BAT_U64 A)
{
  static const N976N_BAT_U64 Allowed[] = {
    CMGP+0x1020,CMGP+0x1824,CMGP+0x100,
    CMGP+0x2010,CMGP+0x206C,CMGP+0x205C,CMGP+0x2088,CMGP+0x208C,
    APM+0x200C,APM+0x1004,APM+0x1804,APM+0x120,APM+0x140,APM+0x100,
    TOP+0x2018,TOP+0x1004,TOP+0x1800,TOP+0x10DC,TOP+0x18D0,
    TOP+0x100,TOP+0x160,TOP+0x18E4,TOP+0x1A0
  };
  for(N976N_BAT_U32 I=0;I<BAT_ARRAY_SIZE(Allowed);I++) if(A==Allowed[I])return 1;
  return 0;
}
int N976nBatBusBindingValid(const N976N_BAT_BUS_BINDING *B)
{
  if(!B||!B->CounterHz||B->CounterHz>1000000000ULL||B->InputHz<6000000||
     B->InputHz>400000000||!B->ClockCount||B->ClockCount>N976N_BAT_BUS_MAX_CLOCKS||B->ClockReserved||
     (B->Mode&~4U)||B->Config[3]||(B->Config[0]&BAT_BIT31)||
     (B->Config[5]&AUTO_RUN)||(B->Config[14]&~1U)||(B->Config[15]&~7U))return 0;
  for(N976N_BAT_U32 I=0;I<B->ClockCount;I++){
    if(!N976nBatBusClockAddressAllowed(B->ClockAddress[I])||B->ClockValue[I]==BAT_MAX_U32)return 0;
    for(N976N_BAT_U32 J=0;J<I;J++)if(B->ClockAddress[J]==B->ClockAddress[I])return 0;
  }
  for(N976N_BAT_U32 I=B->ClockCount;I<N976N_BAT_BUS_MAX_CLOCKS;I++)
    if(B->ClockAddress[I]||B->ClockValue[I])return 0;
  for(N976N_BAT_U32 I=0;I<6;I++)if(B->Gpio[I]==BAT_MAX_U32||(I%3==0&&(B->Gpio[I]&15)>2))return 0;
  for(N976N_BAT_U32 I=0;I<16;I++)if(B->Config[I]==BAT_MAX_U32)return 0;
  if(B->Qch==BAT_MAX_U32||!InheritedClass(B->Mode,B->Config))return 0;
  return 1;
}
int N976nBatBusInit(N976N_BAT_BUS_CONTEXT *C,const N976N_BAT_BUS_OPS *Ops,
  void *Opaque,const N976N_BAT_BUS_BINDING *B)
{
  if(!C||!Ops||!Ops->Read32||!Ops->Write32||!Ops->Barrier||
     !Ops->Counter||!Ops->Cancelled||!Ops->StallUs||!N976nBatBusBindingValid(B))return 0;
  BusZero(C,sizeof(*C));C->Ops=*Ops;C->Opaque=Opaque;C->Binding=*B;C->Initialized=1;
  return 1;
}
static int BindingLive(N976N_BAT_BUS_CONTEXT *C)
{
  if(!Equal(C,QCH,Rd(C,QCH),C->Binding.Qch,BAT_MAX_U32)||
     !Equal(C,MODE,Rd(C,MODE),C->Binding.Mode,BAT_MAX_U32))return 0;
  for(N976N_BAT_U32 I=0;I<6;I++)
    if(!Equal(C,GPIO+mGpioOffsets[I],Rd(C,GPIO+mGpioOffsets[I]),C->Binding.Gpio[I],15))return 0;
  for(N976N_BAT_U32 I=0;I<16;I++)
    if(!Equal(C,HSI+mConfigOffsets[I],Rd(C,HSI+mConfigOffsets[I]),C->Binding.Config[I],BAT_MAX_U32))return 0;
  return InheritedIdle(C,C->Binding.Mode,C->Binding.Config);
}

static int ClockAndGates(N976N_BAT_BUS_CONTEXT *C)
{
  static const N976N_BAT_U32 Gates[]={0x2010,0x206C,0x205C,0x2088,0x208C};
  if(!InputClock(C))return 0;
  for(N976N_BAT_U32 I=0;I<BAT_ARRAY_SIZE(Gates);I++)if(!Gate(C,Clock(C,CMGP+Gates[I])))return 0;
  return ClockStable(C);
}
int N976nBatBusValidateBinding(N976N_BAT_BUS_CONTEXT *C)
{
  if(!C||!C->Initialized||C->Running||C->D0Active||C->Quarantined)return 0;
  BusZero(&C->S,sizeof(C->S));C->S.Hz=C->Binding.CounterHz;
  return ClockAndGates(C)&&C->Report.InputHz==C->Binding.InputHz&&
    C->S.ClockCount==C->Binding.ClockCount&&BindingLive(C);
}
int N976nBatBusCaptureBinding(const N976N_BAT_BUS_OPS *Ops,void *Opaque,
  N976N_BAT_U64 CounterHz,N976N_BAT_BUS_BINDING *B,N976N_BAT_BUS_REPORT *R)
{
  N976N_BAT_BUS_CONTEXT Temporary,Verified,*C=&Temporary;
  if(!Ops||!Ops->Read32||!Ops->Write32||!Ops->Barrier||!Ops->Counter||
     !Ops->StallUs||!Ops->Cancelled||!B||!R||!CounterHz||CounterHz>1000000000ULL)return 0;
  BusZero(B,sizeof(*B));BusZero(R,sizeof(*R));BusZero(C,sizeof(*C));
  C->Ops=*Ops;C->Opaque=Opaque;C->S.Hz=CounterHz;C->S.Capturing=1;
  C->Report.NoMutation=1;
  if(!ClockAndGates(C))goto Failed;
  B->CounterHz=CounterHz;B->InputHz=C->Report.InputHz;B->ClockCount=C->S.ClockCount;
  for(N976N_BAT_U32 I=0;I<B->ClockCount;I++){
    B->ClockAddress[I]=C->S.ClockAddress[I];B->ClockValue[I]=C->S.ClockValue[I];
  }
  B->Qch=Rd(C,QCH);B->Mode=Rd(C,MODE);
  for(N976N_BAT_U32 I=0;I<6;I++)B->Gpio[I]=Rd(C,GPIO+mGpioOffsets[I]);
  for(N976N_BAT_U32 I=0;I<16;I++)B->Config[I]=Rd(C,HSI+mConfigOffsets[I]);
  C->Binding=*B;
  if(!N976nBatBusInit(&Verified,Ops,Opaque,B)||!BindingLive(C)||!ClockStable(C))goto Failed;
  C->Report.Phase=8;*R=C->Report;return 1;
Failed:
  C->Report.Status=N976N_BAT_BUS_NOT_READY;C->Report.Reason=0xB150;*R=C->Report;
  BusZero(B,sizeof(*B));return 0;
}

int N976nBatBusSelectedValid(const N976N_BAT_U32 Config[16])
{
  if(!Config || Config[3] || (Config[0]&BAT_BIT31) ||
     (Config[5]&AUTO_RUN) || (Config[14]&~1U) || (Config[15]&~7U))return 0;
  for(unsigned I=0;I<16;I++)if(Config[I]==BAT_MAX_U32)return 0;
  return 1;
}
int N976nBatBusBindSelected(N976N_BAT_BUS_CONTEXT *C,const N976N_BAT_U32 Config[16])
{
  if(!C||!C->Initialized||C->D0Active||C->Running||C->Quarantined||C->SelectedValid||
     !N976nBatBusSelectedValid(Config))return 0;
  for(unsigned I=0;I<16;I++)C->SelectedConfig[I]=Config[I];
  C->SelectedValid=1;return 1;
}
N976N_BAT_U64 N976nBatBusAcquireD0(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_BOOL Ok=0;
  static const BAT_U32 Gates[]={0x2010,0x206C,0x205C,0x2088,0x208C};
  if (!C || !C->Initialized || !C->SelectedValid) return N976N_BAT_BUS_INVALID_PARAMETER;
  if (C->Running || C->D0Active) return N976N_BAT_BUS_BUSY;
  if (C->Quarantined) return N976N_BAT_BUS_NOT_READY;
  C->Running=1;
  BusZero(&C->S,sizeof(C->S));
  BusZero(&C->Report,sizeof(C->Report));
  mN976nBatteryBusReport.NoMutation=1;
  mCompareValid=mCompareLocked=mSampleValid=mWaitValid=0;
  mN976nBatteryBusReport.Status=N976N_BAT_BUS_NOT_READY; mN976nBatteryBusReport.Phase=1;
  mHz=C->Binding.CounterHz;
  if (!mHz || mHz>1000000000 || !InputClock(C)) { Fail(C, 0xB101,N976N_BAT_BUS_UNSUPPORTED); goto Done; }
  for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(Gates); I++)
    if (!Gate(C, Clock(C, CMGP+Gates[I]))) { Fail(C, 0xB102,N976N_BAT_BUS_NOT_READY); goto Done; }
  if (mN976nBatteryBusReport.InputHz!=C->Binding.InputHz ||
      mClockCount!=C->Binding.ClockCount || !BindingLive(C)) {
    Fail(C,0xB150,N976N_BAT_BUS_NOT_READY); goto Done;
  }
  if (C->Ops.Cancelled(C->Opaque)) { Fail(C,0xB151,N976N_BAT_BUS_ABORTED); goto Done; }
  mSavedQch=Rd(C, QCH); mSavedMode=Rd(C, MODE);
  mN976nBatteryBusReport.InheritedQch=mSavedQch; mN976nBatteryBusReport.InheritedMode=mSavedMode;
  mN976nBatteryBusReport.CaptureValid|=BAT_BIT5|BAT_BIT6;
  if (!Accessible(C, QCH,mSavedQch) || !Equal(C, MODE,mSavedMode,0,~4U)) { Fail(C, 0xB103,N976N_BAT_BUS_NOT_READY); goto Done; }
  for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(mGpioOffsets); I++) {
    mGpio[I]=Rd(C, GPIO+mGpioOffsets[I]);
    mN976nBatteryBusReport.InheritedPin[I]=mGpio[I]; mN976nBatteryBusReport.CaptureValid|=1ULL<<(7+I);
  }
  if (!PinData(C, mN976nBatteryBusReport.PinDataBefore,0)) { Fail(C, 0xB140,N976N_BAT_BUS_NOT_READY); goto Done; }
  mN976nBatteryBusReport.PinPhase=1;
  for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(mGpioOffsets); I++) {
    if (!Accessible(C, GPIO+mGpioOffsets[I],mGpio[I])) {
      Fail(C, 0xB104,N976N_BAT_BUS_NOT_READY); goto Done;
    }
    if (I%3==0) {
      BAT_U32 Function=mGpio[I]&15;
      if (Function>2) {
        Different(C, GPIO+mGpioOffsets[I],2,mGpio[I],15,3);
        Fail(C, 0xB104,N976N_BAT_BUS_NOT_READY); goto Done;
      }
      if (Function==1) mN976nBatteryBusReport.PinOutputMask|=1ULL<<(I/3);
    }
  }
  mN976nBatteryBusReport.Phase=2; mOuterChanged=1;
  /* Samsung ra_req_enable_qch preserves ENABLE and only asserts REQUEST when
   * ENABLE=0. Expire/ignore-policy fields remain untouched. */
  if (!(mSavedQch&BAT_BIT0) && !Set(C, QCH,mSavedQch|BAT_BIT1,BAT_BIT0|BAT_BIT1)) goto Cleanup;
  if (!Set(C, MODE,4,BAT_MAX_U32)) goto Cleanup;
  for (BAT_SIZE I=0; I<BAT_ARRAY_SIZE(mConfigOffsets); I++) {
    mSaved[I]=Rd(C, HSI+mConfigOffsets[I]);
    switch (I) {
      case 0: mN976nBatteryBusReport.InheritedControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BAT_BIT13; break;
      case 1: mN976nBatteryBusReport.InheritedFifoControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BAT_BIT14; break;
      case 3: mN976nBatteryBusReport.InheritedInterruptEnable=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BAT_BIT15; break;
      case 14: mN976nBatteryBusReport.InheritedUsiControl=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BAT_BIT16; break;
      case 15: mN976nBatteryBusReport.InheritedUsiOption=mSaved[I]; mN976nBatteryBusReport.CaptureValid|=BAT_BIT17; break;
      default: break;
    }
    if (!Accessible(C, HSI+mConfigOffsets[I],mSaved[I])) {
      mRestoreBlocked=1; Fail(C, 0xB105,N976N_BAT_BUS_NOT_READY); goto Cleanup;
    }
  }
  /* MODE is now selected, but USI reset/init has not been changed. Admit only
   * the classified inherited state; Configure establishes strict FIFO readiness
   * before the first pointer/read transaction. No FIFO payload is discarded. */
  if (!SelectedQuiescent(C) || C->Report.Interrupt || !Equal(C, HSI+CTL,mSaved[0],0,BAT_BIT31) ||
      !Equal(C, HSI+USI_CON,mSaved[14],0,~1U) || !Equal(C, HSI+USI_OPTION,mSaved[15],0,~7U) ||
      !Equal(C, HSI+INT_ST,(BAT_U32)mN976nBatteryBusReport.Interrupt,0,~INT_KNOWN)) {
    mRestoreBlocked=1; Fail(C, 0xB105,N976N_BAT_BUS_NOT_READY); goto Cleanup;
  }
  for (BAT_SIZE I=0;I<16;I++) {
    if (!Equal(C,HSI+mConfigOffsets[I],mSaved[I],C->SelectedConfig[I],BAT_MAX_U32)) {
      /* No HSI/pad write or command occurred. Preserve the observed selected
       * image, refuse reuse, and let the no-HSI-write cleanup prove it is still
       * idle/unchanged and ours before restoring only MODE/QCH. */
      mHsiSaved=1;mN976nBatteryBusReport.Quarantine=1;
      Fail(C,0xB152,N976N_BAT_BUS_NOT_READY); goto Cleanup;
    }
  }
  mHsiSaved=1; mPinsChanged=1;
  mN976nBatteryBusReport.PinPhase=2;
  if (!ReleaseOutputPins(C)) goto Cleanup;
  for (BAT_SIZE I=0; I<6; I+=3) {
    if (!PinField(C, I,2) || !PinField(C, I+1,0) || !PinField(C, I+2,0)) goto Cleanup;
  }
  mN976nBatteryBusReport.PinPhase=4;
  mN976nBatteryBusReport.Phase=3;
  if (!Configure(C)) { Fail(C, 0xB107,N976N_BAT_BUS_NOT_READY); goto Cleanup; }
  mN976nBatteryBusReport.PinDataReady[0]=mN976nBatteryBusReport.Input>>32;
  mN976nBatteryBusReport.PinDataReady[1]=(BAT_U32)mN976nBatteryBusReport.Input;
  mN976nBatteryBusReport.PinDataValid|=0x30; mN976nBatteryBusReport.PinPhase=5;
  /* Configuration is established once per D0. No request was submitted. */
  C->D0Active=1; C->Report.Retired=1; C->Report.Status=0; C->Report.Phase=3;
  C->AcquireReport=C->Report; C->Running=0; return 0;
Cleanup:
  if (!Ok && !mN976nBatteryBusReport.Reason) Fail(C, 0xB108,N976N_BAT_BUS_DEVICE_ERROR);
  mN976nBatteryBusReport.Phase=6; C->S.Cleanup=1;
  if (!Restore(C)) { Fail(C, 0xB130,N976N_BAT_BUS_DEVICE_ERROR); Ok=0; }
  if (Ok && !mN976nBatteryBusReport.Quarantine) {
    mN976nBatteryBusReport.Status=N976N_BAT_BUS_SUCCESS; mN976nBatteryBusReport.Phase=8;
  }
Done:
  C->Quarantined |= (unsigned)C->Report.Quarantine;
  C->Running=0; C->AcquireReport=C->Report;
  if(C->Report.Reason && !C->FirstFailure.Reason) C->FirstFailure=C->Report;
  return mN976nBatteryBusReport.Status;
}

/* Live-owner checks are not MODE0 BindingLive. Mutable FIFO/address/length
 * registers are proven by transaction retirement, not frozen across requests. */
static BAT_BOOL OwnerDomain(N976N_BAT_BUS_CONTEXT *C)
{
  BAT_U32 ExpectedQch=mSavedQch|((mSavedQch&BAT_BIT0)?0:BAT_BIT1);
  if(!C->D0Active || !ClockStable(C) ||
     !Equal(C,MODE,Rd(C,MODE),4,BAT_MAX_U32)||
     !Equal(C,QCH,Rd(C,QCH),ExpectedQch,BAT_MAX_U32)||
     !Equal(C,HSI+USI_CON,Rd(C,HSI+USI_CON),0,BAT_MAX_U32)||
     !Equal(C,HSI+USI_OPTION,Rd(C,HSI+USI_OPTION),C->SelectedConfig[15],BAT_MAX_U32)||
     !Equal(C,HSI+CTL,Rd(C,HSI+CTL),BAT_BIT3,BAT_BIT31|BAT_BIT3|BAT_BIT0)||
     !Equal(C,HSI+CONF,Rd(C,HSI+CONF),BAT_BIT31,BAT_BIT31|BAT_BIT30|BAT_BIT29))return 0;
  for(unsigned I=0;I<6;I++)
    if(!Equal(C,GPIO+mGpioOffsets[I],Rd(C,GPIO+mGpioOffsets[I]),I%3==0?2:0,15))return 0;
  return 1;
}
static BAT_BOOL OwnerReady(N976N_BAT_BUS_CONTEXT *C)
{
  if(!OwnerDomain(C)||!Equal(C,HSI+INT_EN,Rd(C,HSI+INT_EN),0,BAT_MAX_U32)) {
    mRestoreBlocked=1;return 0;
  }
  /* Readiness is not ownership. An owned, non-idle controller may still be
   * retired by bounded cleanup; unknown IRQ bits remain a refusal to ACK. */
  return Idle(C)&&LinesHigh(C)&&Equal(C,HSI+INT_ST,(BAT_U32)C->Report.Interrupt,0,~BAT_BIT0);
}
/* Retire owned failures without restoring pins/USI before MODE4 cleanup.
 * No reset, forced STOP, retry or FIFO fabrication. Unknown completion is Q. */
static BAT_BOOL RetireKeep(N976N_BAT_BUS_CONTEXT *C)
{
 C->S.Cleanup=1;
 if(mRestoreBlocked||!OwnerDomain(C)||!WaitIdle(C))goto Unknown;
 Wr(C,HSI+INT_EN,0);
 if(!Equal(C,HSI+INT_EN,Rd(C,HSI+INT_EN),0,BAT_MAX_U32)||!Ack(C,0)||!OwnerReady(C))goto Unknown;
 C->S.InTransaction=0;mHeld=0;C->Report.Retired=1;C->S.Cleanup=0;return 1;
Unknown:
 C->Quarantined=1;C->Report.Quarantine=1;C->S.Cleanup=0;return 0;
}
N976N_BAT_U64 N976nBatBusReadActive(N976N_BAT_BUS_CONTEXT *C,
  N976N_BAT_U64 SampleId,N976N_BATTERY_RAW *Raw)
{
  if(!C||!C->Initialized||!Raw||!SampleId)return N976N_BAT_BUS_INVALID_PARAMETER;
  if(C->Running)return N976N_BAT_BUS_BUSY;
  if(!C->D0Active||C->Quarantined)return N976N_BAT_BUS_NOT_READY;
  if(!N976nBatteryBegin(Raw,SampleId))return N976N_BAT_BUS_INVALID_PARAMETER;
  C->Running=1; C->Report=C->AcquireReport;
  C->Report.InputHz=C->Binding.InputHz; C->Report.NoMutation=1;
  C->Report.SampleId=SampleId; C->Report.Phase=4;
  mCompareValid=mCompareLocked=mSampleValid=mWaitValid=0; C->S.Cleanup=0;
  if(C->Ops.Cancelled(C->Opaque)){Fail(C,0xB151,N976N_BAT_BUS_ABORTED);goto Done;}
  if(!OwnerReady(C)) {Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);goto Done;}
  for(unsigned Field=0;Field<N976N_BAT_FIELD_COUNT;Field++)
    if(!ReadField(C,Field,Raw))goto Done;
  if(C->Ops.Cancelled(C->Opaque)){Fail(C,0xB151,N976N_BAT_BUS_ABORTED);goto Done;}
  if(!OwnerReady(C)){Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);goto Done;}
  C->Report.Phase=8;C->Report.Status=0;
Done:
  C->Report.SampledMask=Raw->ValidMask;C->Samples++;C->Running=0;
  if(C->Report.Reason&&!C->FirstFailure.Reason)C->FirstFailure=C->Report;
  /* Failed sample is never published. Retire/release before any later use. */
  if(C->Report.Reason){if(C->KeepControlOwner)RetireKeep(C);else N976nBatBusReleaseD0(C);}
  return C->Report.Status;
}
/* Additional safe byte observations. Still only pointer + repeated START + RX;
 * no configuration payload or watchdog kick is exposed. Same D0 owner. */
N976N_BAT_U64 N976nBatBusReadChargeActive(N976N_BAT_BUS_CONTEXT *C,
  N976N_BAT_U64 SampleId,N976N_POWER_RAW *Raw)
{
  if(!Raw)return N976N_BAT_BUS_INVALID_PARAMETER;
  BusZero(Raw,sizeof(*Raw));
  if(!C||!C->Initialized||!SampleId)return N976N_BAT_BUS_INVALID_PARAMETER;
  if(C->Running)return N976N_BAT_BUS_BUSY;
  if(!C->D0Active||C->Quarantined)return N976N_BAT_BUS_NOT_READY;
  C->Running=1;C->Report=C->AcquireReport;C->Report.SampleId=SampleId;C->Report.Phase=4;
  C->Report.NoMutation=1;mCompareValid=mCompareLocked=mSampleValid=mWaitValid=0;
  C->S.Cleanup=0;Raw->Sequence=SampleId;
  if(!OwnerReady(C)){Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);goto Done;}
  for(unsigned I=0;I<N976N_PWR_COUNT;I++) {
    N976N_BATTERY_READ Spec;BAT_U8 Pointer,Data=0;BAT_U64 Before;
    if(!N976nPowerReadSpec(I,&Spec)){Fail(C,0xB117,N976N_BAT_BUS_INVALID_PARAMETER);goto Done;}
    Pointer=Spec.Register;
    C->Report.Field=0x100+I;C->Report.Address=Spec.Address;C->Report.Register=Spec.Register;
    C->Report.Requested=1;Before=C->Report.RxBytes;
    if(!Transfer(C,&Spec,0,0,&Pointer,1)||!Transfer(C,&Spec,1,1,&Data,1))goto Done;
    if(C->Ops.Cancelled(C->Opaque)){Fail(C,0xB151,N976N_BAT_BUS_ABORTED);goto Done;}
    if(C->Report.RxBytes-Before!=1||!C->Report.Retired){Fail(C,0xB118,N976N_BAT_BUS_DEVICE_ERROR);goto Done;}
    Raw->Byte[I]=Data;Raw->ValidMask|=1U<<I;
  }
  if(!OwnerReady(C)){Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);goto Done;}
  C->Report.Phase=8;C->Report.Status=0;
Done:
  C->Running=0;
  if(C->Report.Reason) {
    Raw->ValidMask=0;
    if(!C->FirstFailure.Reason)C->FirstFailure=C->Report;
    if(C->KeepControlOwner)RetireKeep(C);else N976nBatBusReleaseD0(C);
  }
  return C->Report.Status;
}
static BAT_BOOL ControlByte(N976N_BAT_BUS_CONTEXT *C,unsigned Reg,BAT_U8 *Value)
{
 N976N_BATTERY_READ spec={0x69,(BAT_U8)Reg,1};BAT_U8 pointer=(BAT_U8)Reg;
 return Transfer(C,&spec,0,0,&pointer,1)&&Transfer(C,&spec,1,1,Value,1);
}
enum NCC_IO_RESULT N976nBatBusControl(N976N_BAT_BUS_CONTEXT *C,int Write,
 unsigned Reg,unsigned char *Value,const NCC_TICKET *T,
 int (*Guard)(void *,const NCC_TICKET *),void *Opaque)
{
 BAT_U8 before,payload[2];N976N_BATTERY_READ spec;
 enum NCC_IO_RESULT result=NCC_IO_NOT_ISSUED;
 if(!C||!Value||!T||!Guard||C->Running||!C->KeepControlOwner||!C->D0Active||
    C->Quarantined||!C->Report.Retired||C->S.InTransaction||C->S.Held)return result;
 if(Reg!=0xB7&&Reg!=0xB9&&Reg!=0xBD&&Reg!=0xC0)return result;
 if(T->InputSetup&&(T->Cleanup||(Reg!=0xB7&&Reg!=0xC0)||(Write&&Reg!=0xC0)))return result;
 if(Reg==0xC0&&!T->InputSetup&&!T->Cleanup)return result;
 if(T->Cleanup&&((Reg!=0xB7&&Reg!=0xC0)||
    (Write&&Reg==0xB7&&(*Value&15)!=4)||(Write&&Reg==0xC0&&(*Value&127)!=3)))return result;
 if(Write&&!T->CompareBefore)return result;
 if(Write){
  unsigned mask=Reg==0xB7?15:Reg==0xB9?63:Reg==0xC0?127:3,bits=*Value&mask;
  if(((*Value^T->Before)&~mask)||
    (Reg==0xB7&&(bits!=4&&bits!=5))||(Reg==0xB9&&(bits<2||bits>12))||
    (Reg==0xBD&&(bits!=1||(T->Before&12)!=12))||
    (Reg==0xC0&&bits!=(T->Cleanup?3U:0x23U)))return result;
 }
 if(!Guard(Opaque,T))return result;
 C->Running=1;C->Report=C->AcquireReport;C->Report.Phase=5;C->S.Cleanup=T->Cleanup;
 C->Report.Address=0x69;C->Report.Register=Reg;
 C->ControlTicket=T;C->ControlGuard=Guard;C->ControlOpaque=Opaque;
 if(!OwnerReady(C)){Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);goto Done;}
 /* Fixed ICL setup cannot issue while the charger is in MODE5. This fresh
  * controller-local read is inside the same serialized transaction owner. */
 if(Reg==0xC0&&Write){
  BAT_U8 mode;
  if(!ControlByte(C,0xB7,&mode)||(mode&15)!=4||!Guard(Opaque,T))goto Done;
 }
 if(!ControlByte(C,Reg,&before))goto Done;
 if(!Write){if(Guard(Opaque,T)){*Value=before;result=NCC_IO_OK;}goto Done;}
 if(before!=T->Before||!Guard(Opaque,T))goto Done;
 spec.Address=0x69;spec.Register=(BAT_U8)Reg;spec.Bytes=1;
 payload[0]=(BAT_U8)Reg;payload[1]=*Value;C->ControlPayload=1;
 if(Transfer(C,&spec,0,1,payload,2))result=NCC_IO_OK;
 else result=NCC_IO_RETIRED_ERROR; /* payload may have reached the PMIC */
Done:
 C->ControlPayload=0;C->ControlTicket=0;C->ControlGuard=0;C->ControlOpaque=0;
 if(C->Report.Reason&&!C->FirstFailure.Reason)C->FirstFailure=C->Report;
 if(C->Report.Reason&&!RetireKeep(C))result=NCC_IO_UNKNOWN;
 C->S.Cleanup=0;C->Running=0;return result;
}
N976N_BAT_U64 N976nBatBusReleaseD0(N976N_BAT_BUS_CONTEXT *C)
{
  if(!C||!C->Initialized)return N976N_BAT_BUS_INVALID_PARAMETER;
  if(C->Running)return N976N_BAT_BUS_BUSY;
  if(C->Quarantined)return N976N_BAT_BUS_NOT_READY;
  if(!C->D0Active)return 0;
  C->Running=1;C->S.Cleanup=1;C->Report.Phase=6;
  /* A stop can arrive between samples. Do not overwrite a changed owner domain.
   * IRQ/FIFO are retired below; they need not be idle before bounded cleanup. */
  if(!OwnerDomain(C)){mRestoreBlocked=1;Fail(C,0xB153,N976N_BAT_BUS_NOT_READY);}
  if(!Restore(C)){Fail(C,0xB130,N976N_BAT_BUS_DEVICE_ERROR);C->Quarantined=1;}
  else {C->D0Active=0;if(!C->Report.Reason){C->Report.Status=0;C->Report.Phase=8;}}
  C->Quarantined|=(unsigned)C->Report.Quarantine;C->Running=0;
  if(C->Report.Reason&&!C->FirstFailure.Reason)C->FirstFailure=C->Report;
  return C->Report.Status;
}
N976N_BAT_U64 N976nBatBusSample(N976N_BAT_BUS_CONTEXT *C,N976N_BAT_U64 SampleId,N976N_BATTERY_RAW *Raw)
{
  N976N_BAT_U64 S;
  if(!Raw||!SampleId)return N976N_BAT_BUS_INVALID_PARAMETER;
  if(!N976nBatteryBegin(Raw,SampleId))return N976N_BAT_BUS_INVALID_PARAMETER;
  S=N976nBatBusAcquireD0(C);if(S)return S;
  S=N976nBatBusReadActive(C,SampleId,Raw);
  if(C->D0Active){N976N_BAT_U64 End=N976nBatBusReleaseD0(C);if(!S)S=End;}
  return S;
}
