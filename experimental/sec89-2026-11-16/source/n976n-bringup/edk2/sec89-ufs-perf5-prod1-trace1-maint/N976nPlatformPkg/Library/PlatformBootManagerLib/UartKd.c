/* SPDX-License-Identifier: MIT
 * SEC85: one owned, pre-Windows UART preparation. The inbox SAM5250 kdcom
 * programs CPU/FIFO modes but does not program baud divisors. Decode the
 * inherited Samsung CMU tree, then leave this UART exclusively to Windows.
 * Sources: N976N Kernel.tar.gz samsung.c / serial_s3c.h and cmucal-sfr.c;
 * existing source-checked TouchProbe clock arithmetic. No PLL/clock retuning.
 */
#include <PiDxe.h>
#include <N976nUartKd.h>
#include <N976nUartAdmission.h>
#include <N976nUartMux.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/TimerLib.h>
#include <Library/UefiLib.h>

#define UART_BASE  0x10440000U
#define CMU_BASE   0x10400000U
#define TOP_BASE   0x1A240000U
#define PIN_BASE   0x10430060U
#define UART_MUX   (CMU_BASE + 0x120)
#define UART_DIV   (CMU_BASE + 0x1800)
#define UART_QCH   (CMU_BASE + 0x301C)
#define PIN_MASK   0xFF00U
#define PIN_UART   0x3300U
#define BAUD       115200U
#define STALL_MAX  20000U

typedef N976N_UART_KD_REPORT UART_REPORT;
STATIC volatile UART_REPORT mUart;
STATIC BOOLEAN mAttempted, mReady, mChanged;
STATIC BOOLEAN mInCleanup;
STATIC UINT64 mHz;
STATIC UINTN mClockAddress[12], mClockCount;
STATIC UINT32 mClockValue[12], mMux, mDiv, mPinCon, mPinPull;
STATIC UINT32 mBaudDiv, mFraction;
STATIC CONST UINT32 mGates[] = {0x2018, 0x2028, 0x205C, 0x2060};

STATIC UINT32 Rd (UINTN A) { return MmioRead32 (A); }
STATIC VOID Wr (UINTN A, UINT32 V) { MmioWrite32 (A, V); MemoryFence (); }

/* Only failed predicates populate this tuple. Normal observations and cleanup
 * cannot replace the first failure. Every value comes from an existing read.
 */
STATIC VOID Detail (UINTN A, UINT64 E, UINT64 V, UINT64 Mask, UINT64 Check)
{
  if (mInCleanup || (mUart.Captured&N976N_UART_KD_CAP_DETAIL)) return;
  mUart.Address=A;mUart.Expected=E;mUart.Actual=V;mUart.Mask=Mask;
  mUart.Check=Check;mUart.FailurePhase=mUart.Phase;
  mUart.Captured|=N976N_UART_KD_CAP_DETAIL;
}

STATIC BOOLEAN Match (UINTN A, UINT32 E, UINT32 Mask)
{
  UINT32 V=Rd(A);
  if ((V&Mask)==(E&Mask)) return TRUE;
  Detail(A,E,V,Mask,N976N_UART_KD_CHECK_EQUAL);return FALSE;
}

STATIC BOOLEAN Set (UINTN A, UINT32 V, UINT32 Mask)
{
  Wr (A,V);
  UINT32 Actual=Rd(A);
  if (Actual!=MAX_UINT32 && ((Actual^V)&Mask)==0) return TRUE;
  Detail(A,Actual==MAX_UINT32?MAX_UINT32:V,Actual,Actual==MAX_UINT32?MAX_UINT32:Mask,
    Actual==MAX_UINT32?N976N_UART_KD_CHECK_NOT_EQUAL:N976N_UART_KD_CHECK_EQUAL);
  return FALSE;
}

/* Consumer validation is deliberately independent of the admission producer. */
STATIC BOOLEAN Admission (UINT64 Profile)
{
  if (Profile!=N976N_PLATFORM_PROFILE_PHONE) return FALSE;
  VOID *Hob=GetFirstGuidHob(&gN976nUartAdmissionGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_UART_ADMISSION) ||
      GetNextGuidHob(&gN976nUartAdmissionGuid,GET_NEXT_HOB(Hob))) return FALSE;
  CONST N976N_UART_ADMISSION *A=GET_GUID_HOB_DATA(Hob);
  return A->Magic==N976N_UART_ADMISSION_MAGIC && A->Version==1 &&
    A->Size==sizeof(*A) && A->Profile==Profile && A->Admitted==1 &&
    A->Reason==0 && A->Checks==N976N_UART_ADMISSION_CHECKS &&
    A->Uart==N976N_UART_BASE && A->UartBytes==N976N_UART_BYTES &&
    A->GpioPeric0==N976N_UART_GPIO_PERIC0 && A->GpioPeric0Bytes==0x1000 &&
    A->Hsi2c==N976N_UART_HSI2C && A->Hsi2cBytes==0x1000 &&
    A->GpioCmgp==N976N_UART_GPIO_CMGP && A->GpioCmgpBytes==0x1000 &&
    A->SysregCmgp==N976N_UART_SYSREG_CMGP && A->SysregCmgpBytes==4 &&
    A->CmuPeric0==N976N_UART_CMU_PERIC0 && A->CmuPeric0Bytes==N976N_UART_CMU_BYTES &&
    A->CmuCmgp==N976N_UART_CMU_CMGP && A->CmuCmgpBytes==N976N_UART_CMU_BYTES &&
    A->CmuAlive==N976N_UART_CMU_ALIVE && A->CmuAliveBytes==N976N_UART_CMU_BYTES &&
    A->CmuTop==N976N_UART_CMU_TOP && A->CmuTopBytes==N976N_UART_CMU_BYTES &&
    A->UartClockIds[0]==0x1E5 && A->UartClockIds[1]==0x201 &&
    A->HsiClockIds[0]==0x82 && A->HsiClockIds[1]==0x7D;
}

STATIC BOOLEAN GatePass (UINT32 V)
{
  if (V==MAX_UINT32) return FALSE;
  return (V&BIT20) ? (V&BIT21)!=0 : (V&BIT28)==0;
}

STATIC VOID GateDetail (UINTN A, UINT32 V)
{
  if (V==MAX_UINT32) Detail(A,MAX_UINT32,V,MAX_UINT32,N976N_UART_KD_CHECK_NOT_EQUAL);
  else if (V&BIT20) Detail(A,BIT20|BIT21,V,BIT20|BIT21,N976N_UART_KD_CHECK_EQUAL);
  else Detail(A,0,V,BIT20|BIT28,N976N_UART_KD_CHECK_EQUAL);
}

STATIC BOOLEAN Gates (VOID)
{
  for (UINTN I=0; I<ARRAY_SIZE(mGates); I++) {
    UINT32 V=Rd(CMU_BASE+mGates[I]);
    if (!(mUart.GateSeen&(1ULL<<I))) mUart.GateValue[I]=V;
    mUart.GateLast[I]=V;mUart.GateSeen|=1ULL<<I;
    mUart.Captured|=N976N_UART_KD_CAP_GATES;
    if (!GatePass(V)) {GateDetail(CMU_BASE+mGates[I],V);return FALSE;}
  }
  return TRUE;
}

STATIC UINT32 ClockReg (UINT32 Offset)
{
  UINTN I=mClockCount++;
  ASSERT (I<ARRAY_SIZE(mClockAddress));
  mClockAddress[I]=TOP_BASE+Offset;
  mClockValue[I]=Rd(mClockAddress[I]);
  mUart.ClockAddress[I]=mClockAddress[I];mUart.ClockValue[I]=mClockValue[I];
  mUart.ClockCount=mClockCount;mUart.Captured|=N976N_UART_KD_CAP_CLOCK_TOP;
  return mClockValue[I];
}

STATIC BOOLEAN ClockUnchanged (VOID)
{
  UINT32 V=Rd(UART_MUX);
  mUart.ClockMuxObserved=V;mUart.ClockLocalObservedMask|=1;
  mUart.Captured|=N976N_UART_KD_CAP_CLOCK_COMPARE;
  if (V!=mMux) {Detail(UART_MUX,mMux,V,MAX_UINT32,N976N_UART_KD_CHECK_EQUAL);return FALSE;}
  V=Rd(UART_DIV);mUart.ClockDivObserved=V;mUart.ClockLocalObservedMask|=2;
  if (V!=mDiv) {Detail(UART_DIV,mDiv,V,MAX_UINT32,N976N_UART_KD_CHECK_EQUAL);return FALSE;}
  for (UINTN I=0;I<mClockCount;I++) {
    V=Rd(mClockAddress[I]);mUart.ClockObserved[I]=V;mUart.ClockObservedMask|=1ULL<<I;
    if (V!=mClockValue[I]) {Detail(mClockAddress[I],mClockValue[I],V,MAX_UINT32,N976N_UART_KD_CHECK_EQUAL);return FALSE;}
  }
  return TRUE;
}

STATIC BOOLEAN PllRate (UINT32 Con, UINT64 *Hz)
{
  UINT64 M=(Con>>16)&0x3FF, P=(Con>>8)&0x3F, S=Con&7;
  UINTN A=mClockCount?mClockAddress[mClockCount-1]:0;
  if (Con==MAX_UINT32 || (Con&BIT7)) {
    Detail(A,Con==MAX_UINT32?MAX_UINT32:0,Con,Con==MAX_UINT32?MAX_UINT32:BIT7,
      Con==MAX_UINT32?N976N_UART_KD_CHECK_NOT_EQUAL:N976N_UART_KD_CHECK_EQUAL);return FALSE;
  }
  if (!(Con&BIT4)) {*Hz=26000000;return TRUE;}
  if ((Con&(BIT31|BIT29))!=(BIT31|BIT29) || !M || !P || S>6) {
    Detail(A,BIT31|BIT29,Con,MAX_UINT32,N976N_UART_KD_CHECK_PLL);return FALSE;
  }
  *Hz=(26000000ULL*M)/(P<<S);
  BOOLEAN Valid=*Hz>=26000000 && *Hz<=4000000000ULL;
  if (!Valid) Detail(A,26000000,*Hz,4000000000ULL,N976N_UART_KD_CHECK_RANGE);
  return Valid;
}

/* CMU_TOP PERIC0 IP parent is shared with the proved HSI2C clock tree; the
 * UART has its own mux +120 and divider +1800. These reads never select a PLL.
 */
STATIC BOOLEAN InputClock (VOID)
{
  UINT32 TopMux,TopDiv,Select,D0,D1,Con;
  UINT64 Rate=26000000;
  mClockCount=0; mMux=Rd(UART_MUX);mDiv=Rd(UART_DIV);
  mUart.ClockMux=mMux;mUart.ClockDiv=mDiv;mUart.Captured|=N976N_UART_KD_CAP_CLOCK_LOCAL;
  if ((mMux&~BIT4) || (mDiv&~15U)) {
    if (mMux&~BIT4) Detail(UART_MUX,0,mMux,(UINT32)~BIT4,N976N_UART_KD_CHECK_EQUAL);
    else Detail(UART_DIV,0,mDiv,~15U,N976N_UART_KD_CHECK_EQUAL);
    return FALSE;
  }
  if (mMux&BIT4) {
    UINT32 Gate=ClockReg(0x20C0);
    if (!GatePass(Gate)) {GateDetail(TOP_BASE+0x20C0,Gate);return FALSE;}
    TopMux=ClockReg(0x10BC); TopDiv=ClockReg(0x18A8);
    if ((TopMux&~(1U|BIT28)) || (TopDiv&~(15U|BIT28))) {
      if (TopMux&~(1U|BIT28)) Detail(TOP_BASE+0x10BC,0,TopMux,~(1U|BIT28),N976N_UART_KD_CHECK_EQUAL);
      else Detail(TOP_BASE+0x18A8,0,TopDiv,~(15U|BIT28),N976N_UART_KD_CHECK_EQUAL);
      return FALSE;
    }
    TopMux&=1;TopDiv&=15;
    if (!TopMux) {
      Select=ClockReg(0x10DC);D0=ClockReg(0x18CC);D1=ClockReg(0x18D4);
      if ((Select&~(1U|BIT28)) || (D0&~(1U|BIT28)) || (D1&~(1U|BIT28))) {
        UINT32 O=(Select&~(1U|BIT28))?0x10DC:(D0&~(1U|BIT28))?0x18CC:0x18D4;
        UINT32 V=O==0x10DC?Select:O==0x18CC?D0:D1;
        Detail(TOP_BASE+O,0,V,~(1U|BIT28),N976N_UART_KD_CHECK_EQUAL);return FALSE;
      }
      Con=ClockReg((Select&1)?0x100:0x160);
      if (!PllRate(Con,&Rate)) return FALSE;
      Rate/=((D0&1)+1)*((D1&1)+1);
    } else {
      D0=ClockReg(0x18E4);Con=ClockReg(0x1A0);
      if (D0&~(1U|BIT28)) {Detail(TOP_BASE+0x18E4,0,D0,~(1U|BIT28),N976N_UART_KD_CHECK_EQUAL);return FALSE;}
      if (!PllRate(Con,&Rate)) return FALSE;
      Rate/=(D0&1)+1;
    }
    Rate/=TopDiv+1;
  }
  Rate/=(mDiv&15)+1;
  mUart.ComputedHz=Rate;mUart.Captured|=N976N_UART_KD_CAP_COMPUTED_HZ;
  if (Rate<1600000 || Rate>400000000) {
    Detail(0,1600000,Rate,400000000,N976N_UART_KD_CHECK_RANGE);return FALSE;
  }
  if (!ClockUnchanged()) return FALSE;
  mUart.InputHz=Rate;
  /* Samsung has_fracval: quotient floor and nearest fractional value, without
   * carrying frac15 across a fixed quotient. UBRDIV is quotient minus one.
   */
  UINT64 Div=Rate/BAUD;
  if (Div<16 || Div/16>65536) return FALSE;
  mBaudDiv=(UINT32)(Div/16-1);
  if ((Div&15)!=15) {
    UINT64 Down=Rate/Div,Up=Rate/(Div+1);
    UINT64 D=Down>BAUD?Down-BAUD:BAUD-Down;
    UINT64 U=Up>BAUD?Up-BAUD:BAUD-Up;
    if (U<D) Div++;
  }
  mFraction=(UINT32)(Div&15);
  UINT64 Actual=Rate/(16ULL*(mBaudDiv+1)+mFraction);
  UINT64 Error=Actual>BAUD?Actual-BAUD:BAUD-Actual;
  if (Error*100>BAUD*2) return FALSE; /* reject >2 percent baud error */
  mUart.ActualBaud=Actual;mUart.Divider=mBaudDiv;mUart.Fraction=mFraction;
  mUart.Captured|=N976N_UART_KD_CAP_BAUD;
  return TRUE;
}

/* 100 ms wall budget with a same-counter watchdog; no unbounded early printk.
 * UTRSTAT bit2 is shifter AND FIFO empty (Samsung tx_empty); bit1 alone only
 * says FIFO empty. TXFULL bit24 is the Exynos FIFO producer condition.
 */
STATIC BOOLEAN WaitTx (BOOLEAN Empty)
{
  UINT64 Start=GetPerformanceCounter(),Previous=Start;
  UINT32 Same=0;
  for (;;) {
    UINT32 U=Rd(UART_BASE+0x10),F=Rd(UART_BASE+0x18);
    if (mInCleanup) {
      mUart.CleanupUtrstat=U;mUart.CleanupUfstat=F;mUart.CleanupCaptured|=1;
    } else {mUart.Utrstat=U;mUart.Ufstat=F;mUart.Captured|=N976N_UART_KD_CAP_WAIT;}
    volatile UINT64 *Exit=mInCleanup?&mUart.CleanupWaitExit:&mUart.WaitExit;
    if (U==MAX_UINT32 || F==MAX_UINT32) {
      *Exit=4;Detail(U==MAX_UINT32?UART_BASE+0x10:UART_BASE+0x18,
        MAX_UINT32,MAX_UINT32,MAX_UINT32,N976N_UART_KD_CHECK_NOT_EQUAL);return FALSE;
    }
    if (Empty ? ((U&BIT2)!=0) : ((F&BIT24)==0)) {*Exit=0;return TRUE;}
    UINT64 Now=GetPerformanceCounter();
    if (Now<Previous) {
      *Exit=3;Detail(Empty?UART_BASE+0x10:UART_BASE+0x18,Empty?BIT2:0,
        Empty?U:F,Empty?BIT2:BIT24,N976N_UART_KD_CHECK_WAIT);return FALSE;
    }
    Same=Now==Previous?Same+1:0;Previous=Now;
    if (Now-Start>=mHz/10) {
      *Exit=1;Detail(Empty?UART_BASE+0x10:UART_BASE+0x18,Empty?BIT2:0,
        Empty?U:F,Empty?BIT2:BIT24,N976N_UART_KD_CHECK_WAIT);return FALSE;
    }
    if (Same>=STALL_MAX) {
      *Exit=2;Detail(Empty?UART_BASE+0x10:UART_BASE+0x18,Empty?BIT2:0,
        Empty?U:F,Empty?BIT2:BIT24,N976N_UART_KD_CHECK_WAIT);return FALSE;
    }
  }
}

STATIC BOOLEAN UsiDelay (VOID)
{
  UINT64 Start=GetPerformanceCounter(),Previous=Start;
  UINT32 Same=0;
  for (;;) {
    UINT64 Now=GetPerformanceCounter();
    if (Now<Previous) {mUart.WaitExit=3;return FALSE;}
    if (Now-Start>=(mHz+999999)/1000000) return TRUE;
    Same=Now==Previous?Same+1:0;Previous=Now;
    if (Same>=STALL_MAX) {mUart.WaitExit=2;return FALSE;}
  }
}

/* Samsung exynos_usi_init: active-high reset, 1us, release, 1us, then
 * CLKREQ_ON=1 / CLKSTOP_ON=0 and 1us. This wrapper is outside kdcom setup.
 * The source writes these whole registers: inherited reserved bits are logged,
 * not incorrectly required to equal their eventual initialized values.
 */
STATIC BOOLEAN PrepareUsi (VOID)
{
  return Set(UART_BASE+0xC4,1,MAX_UINT32) && UsiDelay() &&
    Set(UART_BASE+0xC4,0,MAX_UINT32) && UsiDelay() &&
    Set(UART_BASE+0xC8,2,MAX_UINT32) && UsiDelay();
}

STATIC BOOLEAN Configured (VOID)
{
  return ClockUnchanged() && Gates() &&
    Match(PIN_BASE,mPinCon,MAX_UINT32) && Match(PIN_BASE+8,mPinPull,MAX_UINT32) &&
    Match(UART_BASE,3,MAX_UINT32) && Match(UART_BASE+4,5,MAX_UINT32) &&
    Match(UART_BASE+8,1,7) && Match(UART_BASE+0xC,0,BIT4) &&
    Match(UART_BASE+0x28,mBaudDiv,MAX_UINT32) && Match(UART_BASE+0x2C,mFraction,MAX_UINT32) &&
    Match(UART_BASE+0x38,15,15) &&
    Match(UART_BASE+0xC4,0,MAX_UINT32) && Match(UART_BASE+0xC8,2,MAX_UINT32);
}

STATIC EFI_STATUS Stop (UINT64 Reason, EFI_STATUS Status)
{
  mUart.Reason=Reason;mUart.Status=Status;mReady=FALSE;
  if (!(mUart.Captured&N976N_UART_KD_CAP_DETAIL)) mUart.FailurePhase=mUart.Phase;
  mUart.Captured|=N976N_UART_KD_CAP_FAILURE;
  /* Never advertise a failed preparation to kdcom. This is a diagnostic stop,
   * not a claim of restoring consumed FIFO bytes or a successful handoff.
   */
  if (mChanged) {
    mUart.CleanupAttempted=1;mUart.Captured|=N976N_UART_KD_CAP_CLEANUP;mInCleanup=TRUE;
    BOOLEAN Drained=WaitTx(TRUE);mUart.CleanupDrained=Drained;
    if (Drained) {
      Wr(UART_BASE+0x38,15);Wr(UART_BASE+4,0);
      UINT32 V=Rd(UART_BASE+4);mUart.CleanupUcon=V;mUart.CleanupCaptured|=2;
      mUart.DisabledOnFailure=V==0;
    }
    mInCleanup=FALSE;
  }
  Print(L"UART KD stopped: phase %Lu reason %Lx status %r\n",mUart.Phase,Reason,Status);
  Print(L"clock %Lu baud %Lu div/frac %Lx/%Lx at %Lx expected %Lx actual %Lx\n",
    mUart.InputHz,mUart.ActualBaud,mUart.Divider,mUart.Fraction,
    mUart.Address,mUart.Expected,mUart.Actual);
  Print(L"TX UTR/FIFO %Lx/%Lx wait %Lu; mux phase/reason %Lu/%Lx\n",
    mUart.Utrstat,mUart.Ufstat,mUart.WaitExit,
    mN976nUartMuxReport.Phase,mN976nUartMuxReport.Reason);
  Print(L"Inherited UART USI control/options %Lx/%Lx\n",mUart.UsiBefore,mUart.UsiOptionBefore);
  return Status;
}

BOOLEAN N976nUartKdReady (VOID)
{
  /* Readiness is queried only before Windows owns UART; no periodic consumer. */
  return mReady && N976nUartMuxReady() && Configured();
}

CONST volatile N976N_UART_KD_REPORT *N976nUartKdReport (VOID)
{
  return &mUart;
}

EFI_STATUS N976nUartKdPrepare (UINT64 Profile)
{
  if (mAttempted) return EFI_ALREADY_STARTED;
  mAttempted=TRUE;mUart.Phase=1;
  if (Profile==N976N_PLATFORM_PROFILE_QEMU) return EFI_SUCCESS;
  if (!Admission(Profile)) return Stop(0x851,EFI_SECURITY_VIOLATION);
  UINT64 Start,End;
  mHz=GetPerformanceCounterProperties(&Start,&End);
  mUart.TimerHz=mHz;mUart.TimerStart=Start;mUart.TimerEnd=End;
  mUart.Captured|=N976N_UART_KD_CAP_TIMER;
  if (mHz!=26000000 || Start || End!=MAX_UINT64) return Stop(0x852,EFI_UNSUPPORTED);
  mUart.Phase=2;
  if (!InputClock()) return Stop(0x853,EFI_UNSUPPORTED);
  UINT32 Q=Rd(UART_QCH);mUart.QchBefore=Q;
  mUart.Captured|=N976N_UART_KD_CAP_QCH;
  if (Q==MAX_UINT32 || (Q&~0x03FF0007U)) {
    Detail(UART_QCH,Q==MAX_UINT32?MAX_UINT32:0,Q,Q==MAX_UINT32?MAX_UINT32:~0x03FF0007U,
      Q==MAX_UINT32?N976N_UART_KD_CHECK_NOT_EQUAL:N976N_UART_KD_CHECK_EQUAL);
    return Stop(0x854,EFI_UNSUPPORTED);
  }
  /* Samsung ra_req_enable_qch changes REQUEST only in manual mode. */
  if (!(Q&BIT0) && !Set(UART_QCH,Q|BIT1,MAX_UINT32)) return Stop(0x854,EFI_DEVICE_ERROR);
  if (!Gates()) return Stop(0x855,EFI_NOT_READY);
  mUart.Phase=3;
  UINT32 Ucon=Rd(UART_BASE+4),Fifo=Rd(UART_BASE+8);
  UINT32 Usi=Rd(UART_BASE+0xC4),Option=Rd(UART_BASE+0xC8);
  mUart.UconBefore=Ucon;mUart.FifoBefore=Fifo;
  mUart.UsiBefore=Usi;mUart.UsiOptionBefore=Option;
  mUart.Captured|=N976N_UART_KD_CAP_UART;
  if (Usi==MAX_UINT32 || Option==MAX_UINT32) {
    Detail(Usi==MAX_UINT32?UART_BASE+0xC4:UART_BASE+0xC8,MAX_UINT32,MAX_UINT32,MAX_UINT32,N976N_UART_KD_CHECK_NOT_EQUAL);
    return Stop(0x85E,EFI_DEVICE_ERROR);
  }
  /* Reserved/DMA modes are not an owned polled console. */
  if (Ucon==MAX_UINT32 || Fifo==MAX_UINT32 || (Ucon&3)>1 || ((Ucon>>2)&3)>1) {
    if (Ucon==MAX_UINT32 || Fifo==MAX_UINT32)
      Detail(Ucon==MAX_UINT32?UART_BASE+4:UART_BASE+8,MAX_UINT32,MAX_UINT32,MAX_UINT32,N976N_UART_KD_CHECK_NOT_EQUAL);
    else Detail(UART_BASE+4,5,Ucon,15,N976N_UART_KD_CHECK_DMA_MODE);
    return Stop(0x856,EFI_ACCESS_DENIED);
  }
  /* An inherited held reset cannot drain a shifter. The known active-high
   * wrapper reset permits initialization, but never overrides DMA refusal.
   * An active wrapper must retire its existing TX before it can be reset.
   */
  if (!(Usi&BIT0) && !WaitTx(TRUE)) return Stop(0x857,EFI_TIMEOUT);
  UINT32 Con=Rd(PIN_BASE),Pull=Rd(PIN_BASE+8),Flow=Rd(UART_BASE+0xC);
  mUart.PinBefore=Con;mUart.PullBefore=Pull;
  mUart.FlowBefore=Flow;mUart.Captured|=N976N_UART_KD_CAP_PINS;
  if (Con==MAX_UINT32 || Pull==MAX_UINT32 || Flow==MAX_UINT32) {
    Detail(Con==MAX_UINT32?PIN_BASE:Pull==MAX_UINT32?PIN_BASE+8:UART_BASE+0xC,
      MAX_UINT32,MAX_UINT32,MAX_UINT32,N976N_UART_KD_CHECK_NOT_EQUAL);return Stop(0x858,EFI_DEVICE_ERROR);
  }
  mPinCon=(Con&~PIN_MASK)|PIN_UART;mPinPull=Pull&~PIN_MASK;
  mUart.Phase=4;mChanged=TRUE;
  if (!PrepareUsi()) return Stop(0x85F,EFI_DEVICE_ERROR);
  if (!Set(UART_BASE+0x38,15,15) || !Set(UART_BASE+4,0,MAX_UINT32) ||
      !Set(PIN_BASE+8,mPinPull,MAX_UINT32) || !Set(PIN_BASE,mPinCon,MAX_UINT32) ||
      !Set(UART_BASE,3,MAX_UINT32) || !Set(UART_BASE+0xC,Flow&~BIT4,MAX_UINT32) ||
      !Set(UART_BASE+0x28,mBaudDiv,MAX_UINT32) || !Set(UART_BASE+0x2C,mFraction,MAX_UINT32))
    return Stop(0x859,EFI_DEVICE_ERROR);
  /* Reset old FIFO content before the one marker; never reset after kdcom starts. */
  Wr(UART_BASE+8,7);Wr(UART_BASE+8,1);
  Wr(UART_BASE+0x30,15);Wr(UART_BASE+0x34,15);
  if (!Set(UART_BASE+4,5,MAX_UINT32) || !Configured()) return Stop(0x85A,EFI_DEVICE_ERROR);
  mUart.Phase=5;
  EFI_STATUS Status=N976nUartMuxPrepare();
  if (EFI_ERROR(Status) || !N976nUartMuxReady()) return Stop(0x85B,EFI_ERROR(Status)?Status:EFI_NOT_READY);
  mUart.Phase=6;
  STATIC CONST CHAR8 Marker[]="N976N SEC85 UART KD READY 115200\r\n";
  for (UINTN I=0;I<sizeof(Marker)-1;I++) {
    if (!WaitTx(FALSE)) return Stop(0x85C,EFI_TIMEOUT);
    MmioWrite8(UART_BASE+0x20,(UINT8)Marker[I]);MemoryFence();mUart.MarkerBytes++;
  }
  if (!WaitTx(TRUE) || !Configured()) return Stop(0x85D,EFI_NOT_READY);
  mUart.Phase=8;mUart.Status=EFI_SUCCESS;mReady=TRUE;
  Print(L"UART KD prepared: 115200 8N1, clock %Lu Hz; marker %Lu bytes.\n",
    mUart.InputHz,mUart.MarkerBytes);
  Print(L"Waiting for Windows KD handshake; preparation is not attachment proof.\n");
  return EFI_SUCCESS;
}
