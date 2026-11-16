/* SPDX-License-Identifier: MIT
 * SEC72 bounded Samsung HSI2C identification attempt. Register facts and timing
 * equations are independently implemented from the N976N Samsung kernel and
 * pinned NTDEV transport structure; no Linux/NTDEV driver source is copied.
 * Command52 ID plus a bounded cold-owned Y771 event session. No rails, touch reset,
 * firmware, storage, GIC or ALIVE interrupt writes are permitted.
 */
#include <N976nTouchProbe.h>
#include <N976nTouchHandoff.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>

STATIC CONST UINT32 mCmuOffsets[TouchCmuCount] = {
  0x2008, 0x2024, 0x200C, 0x2010, 0x2018, 0x2058, 0x2054,
  0x2094, 0x2098, 0x3038, 0x0100, 0x0280, 0x182C
};
STATIC CONST UINT32 mAliveOffsets[TouchAliveCount] = {
  0x020, 0x024, 0x028, 0x02C, 0x704, 0x808, 0x904, 0xA04
};
STATIC CONST UINT32 mGppOffsets[TouchGppCount] = { 0x20, 0x24, 0x28, 0x2C };
STATIC CONST UINT32 mHsiOffsets[TouchHsiCount] = {
  0x00, 0x04, 0x08, 0x20, 0x24, 0x30, 0x40, 0x44,
  0x50, 0x54, 0x58, 0x5C, 0x60, 0x64, 0x68, 0x70
};

STATIC BOOLEAN AdmissionValid (CONST N976N_TOUCH_ADMISSION *A)
{
  return A && A->Magic == N976N_TOUCH_ADMISSION_MAGIC &&
    A->Version == 1 && A->Size == sizeof (*A) && A->Profile <= 1 &&
    A->Admitted == 1 && A->Reason == 0 &&
    A->Checks == N976N_TOUCH_ADMISSION_CHECKS &&
    A->Hsi2c == N976N_TOUCH_HSI2C && A->Hsi2cBytes == 0x1000 &&
    A->GpioAlive == N976N_TOUCH_GPIO_ALIVE && A->GpioAliveBytes == 0x1000 &&
    A->GpioPeric0 == N976N_TOUCH_GPIO_PERIC0 && A->GpioPeric0Bytes == 0x1000 &&
    A->SysregUsi == N976N_TOUCH_SYSREG_USI && A->SysregUsiBytes == 4 &&
    A->CmuPeric0 == N976N_TOUCH_CMU_PERIC0 && A->CmuPeric0Bytes == 0x8000 &&
    A->I2cAddress == 0x48 && A->I2cGsiv == 420 && A->ClockHz == 200000000 &&
    A->ClockIds[0] == 0x1FD && A->ClockIds[1] == 0x1ED &&
    A->IrqPin == 0 && A->IrqGsiv == 45 && A->IrqFlags == 0x2008 &&
    A->SclPin == 4 && A->SdaPin == 5 && A->PinFunction == 2 &&
    A->MaxX == 4096 && A->MaxY == 4096 && A->EventBytes == 16 &&
    A->BootOn == 1;
}

STATIC UINT64 TouchCounter (VOID);

STATIC UINT32 ReadReg (N976N_TOUCH_SNAPSHOT *R, UINTN Address)
{
  R->ReadCount++;
  return MmioRead32 (Address);
}

STATIC VOID WriteReg (N976N_TOUCH_SNAPSHOT *R, UINTN Address, UINT32 Value)
{
  MemoryFence ();
  MmioWrite32 (Address, Value);
  R->WriteCount++;
  MemoryFence ();
}

STATIC BOOLEAN SetReg (
  N976N_TOUCH_SNAPSHOT *R, UINTN Address, UINT32 Value)
{
  WriteReg (R, Address, Value);
  return ReadReg (R, Address) == Value;
}

STATIC VOID ReadClass (
  UINT64 Base, CONST UINT32 *Offsets, UINTN Count, UINT32 *Values,
  N976N_TOUCH_SNAPSHOT *R)
{
  MemoryFence ();
  for (UINTN I = 0; I < Count; I++)
    Values[I] = ReadReg (R, (UINTN)Base + Offsets[I]);
  MemoryFence ();
}

/* Samsung cal-if/ra.c manual/pass/automatic gate interpretation. */
STATIC BOOLEAN GatePass (UINT32 Value)
{
  if (Value == MAX_UINT32) return FALSE;
  return (Value & BIT20) ? (Value & BIT21) != 0 : (Value & BIT28) == 0;
}

STATIC VOID Fail (N976N_TOUCH_SNAPSHOT *R, UINT64 Reason, EFI_STATUS Status)
{
  if (R->Reason == 0) {
    R->Reason = Reason;
    R->FailureStage = R->Phase;
    R->Status = Status;
  }
}

#define HSI_CTL        0x00
#define HSI_FIFO_CTL   0x04
#define HSI_TRAILING   0x08
#define HSI_INT_EN     0x20
#define HSI_INT_ST     0x24
#define HSI_FIFO_ST    0x30
#define HSI_TX         0x34
#define HSI_RX         0x38
#define HSI_CONF       0x40
#define HSI_AUTO       0x44
#define HSI_TIMEOUT    0x48
#define HSI_TRANS      0x50
#define HSI_FS1        0x60
#define HSI_FS2        0x64
#define HSI_FS3        0x68
#define HSI_ADDR       0x70
#define HSI_USI_CON    0xC4
#define HSI_USI_OPTION 0xC8
#define HSI_BUSY       (BIT17 | BIT16)
#define FIFO_EMPTY     (BIT24 | BIT8)
#define FIFO_LEVELS    (0x7F0000U | 0x7FU)
#define FIFO_FULL      (BIT23 | BIT7)
#define INT_DONE       BIT7
#define INT_ERRORS     (0xF00U | 0x3CU)
#define INT_KNOWN      0xFFFU
#define AUTO_STOP      BIT17
#define AUTO_READ      BIT16
#define AUTO_RUN       BIT31

STATIC BOOLEAN FifoEmpty (UINT32 F)
{
  return F != MAX_UINT32 && (F & FIFO_EMPTY) == FIFO_EMPTY &&
    (F & (FIFO_LEVELS | FIFO_FULL)) == 0;
}

STATIC BOOLEAN Inactive (UINT32 T)
{
  /* Kernel uses INIT=1 in this controller generation, while other supported
   * revisions use IDLE=0. Neither can be accepted with MASTER/SLAVE_BUSY set.
   */
  return T != MAX_UINT32 && (T & HSI_BUSY) == 0 && (T & 15) <= 1;
}

STATIC VOID ObserveTransfer (UINTN B, N976N_TOUCH_SNAPSHOT *R)
{
  R->InterruptStatus = ReadReg (R, B + HSI_INT_ST);
  R->TransferStatus = ReadReg (R, B + HSI_TRANS);
  R->FifoStatus = ReadReg (R, B + HSI_FIFO_ST);
}

STATIC BOOLEAN IdleNow (UINTN B, N976N_TOUCH_SNAPSHOT *R)
{
  ObserveTransfer (B, R);
  return Inactive ((UINT32)R->TransferStatus) &&
    FifoEmpty ((UINT32)R->FifoStatus) &&
    (ReadReg (R, B + HSI_AUTO) & AUTO_RUN) == 0;
}

/* Fixed local budget plus architectural counter deadline. A stalled counter
 * cannot turn an MMIO polling loop into an unbounded firmware hang. */
STATIC BOOLEAN WaitIdle (UINTN B, N976N_TOUCH_SNAPSHOT *R)
{
  UINT64 Start = TouchCounter (), Now = Start;
  UINT32 Seen = 0;
  for (UINTN I = 0; I < TOUCH_POLL_LIMIT; I++) {
    BOOLEAN Idle = IdleNow (B, R);
    Seen |= (UINT32)R->InterruptStatus;
    R->InterruptStatus |= Seen;
    if (Idle) {
      R->WaitTicks += TouchCounter () - Start;
      return TRUE;
    }
    Now = TouchCounter ();
    if (Now - Start >= R->CounterHz / 10) break;
  }
  R->WaitTicks += Now - Start;
  return FALSE;
}

STATIC BOOLEAN AckOwned (UINTN B, N976N_TOUCH_SNAPSHOT *R, BOOLEAN AllowErrors)
{
  UINT32 Pending = ReadReg (R, B + HSI_INT_ST);
  R->InterruptStatus |= Pending;
  if (AllowErrors && (R->InterruptStatus & (~INT_KNOWN | INT_ERRORS)))
    Fail (R, 0x70C, EFI_DEVICE_ERROR);
  if ((Pending & ~INT_KNOWN) || (!AllowErrors && (Pending & INT_ERRORS))) return FALSE;
  if (Pending) WriteReg (R, B + HSI_INT_ST, Pending);
  /* TX-empty may be a level source. Terminal cleanup separately disables
   * interrupts; this helper does not claim to change INT_ENABLE. */
  return (ReadReg (R, B + HSI_INT_ST) & ~BIT0) == 0;
}

/* EXP1 only: retain each existing full-width readback as evidence, without
 * making immediate equality a gate for these five transfer configuration
 * registers. Samsung/NTDEV submit the configured transaction without this
 * local equality gate. This is an experiment, not proof that a mismatching
 * write took effect. Admission, initialization, completion, byte bounds and
 * restoration still enforce their original checks. No retry is introduced. */
STATIC VOID SetSetupReg (
  N976N_TOUCH_SNAPSHOT *R, UINTN B, BOOLEAN Read, UINT32 Step, UINT32 Offset, UINT32 Value)
{
  /* Step is one of the five literal callers below; direction is the local
   * Transfer argument, not a report value or hardware-supplied index. */
  UINTN Slot = (Read ? 5U : 0U) + Step - 1;
  WriteReg (R, B + Offset, Value);
  UINT32 Observed = ReadReg (R, B + Offset);
  R->SetupObserved[Slot] = Observed;
  R->SetupObservedMask |= 1ULL << Slot;
  if (Observed == Value) return;
  R->SetupMismatchMask |= 1ULL << Slot;
  if (R->SetupFailureStep == 0) {
    R->SetupFailureStep = Step;
    R->SetupFailureOffset = Offset;
    R->SetupFailureExpected = Value;
    R->SetupFailureObserved = Observed;
    R->SetupFailureMask = MAX_UINT32;
    R->SetupFailurePhase = R->Phase;
    R->SetupFailureTransactionCount = R->TransactionCount;
  }
}

/* Preserve the first anomaly separately from the first functional failure.
 * INT/TRANS/FIFO are the already sampled transfer values; AUTO is sampled once
 * only when a new record is needed. These are not an atomic hardware snapshot.
 * Raw payload is passed from the sole MMIO dequeue, never read for telemetry.
 */
STATIC VOID ObserveRx (
  UINTN B, N976N_TOUCH_SNAPSHOT *R, UINT64 Kind, BOOLEAN Fatal,
  BOOLEAN DataValid, UINT32 Data, BOOLEAN Event)
{
  N976N_TOUCH_RX_OBSERVATION *First = Event ? &R->Event.RxFirst : &R->RxFirst;
  N976N_TOUCH_RX_OBSERVATION *Failure = Event ? &R->Event.RxFailure : &R->RxFailure;
  if (First->Kind && (!Fatal || Failure->Kind)) return;
  N976N_TOUCH_RX_OBSERVATION O;
  ZeroMem (&O, sizeof (O));
  O.Kind = Kind; O.Phase = Event ? R->Event.Phase : R->Phase;
  O.TransactionCount = Event ? R->Event.Transactions : R->TransactionCount;
  O.Before = Event ? R->Event.Done : R->RxBytes;
  O.Remaining = (Event ? R->Event.Length : 3) - O.Before;
  O.Fifo = R->FifoStatus; O.Interrupt = R->InterruptStatus;
  O.Transfer = R->TransferStatus; O.Auto = ReadReg (R, B + HSI_AUTO);
  if (DataValid) { O.DataValid = 1; O.Data32 = Data; O.Payload = (UINT8)Data; }
  if (!First->Kind) *First = O;
  if (Fatal && !Failure->Kind) *Failure = O;
}

STATIC BOOLEAN TransferBytes (UINTN B, BOOLEAN Read, UINT8 *DataBuffer,
  UINT32 Len, BOOLEAN Event, N976N_TOUCH_SNAPSHOT *R)
{
  if (!DataBuffer || Len == 0 || Len > 16 ||
      (Event && R->Event.Transactions >= TOUCH_EVENT_MAX_TRANSACTIONS)) {
    Fail (R, 0x740, EFI_INVALID_PARAMETER); return FALSE;
  }
  UINT32 Done = 0;
  if (Event) {
    R->Event.Length = Len; R->Event.Done = 0; R->Event.Direction = Read ? 1 : 0;
  }
  UINT32 Fifo = BIT0 | BIT1 | (Len << 4) | (Len << 16);
  UINT32 Ctl = BIT3 | (Read ? BIT6 : BIT7);
  UINT32 Auto = AUTO_STOP | (Read ? AUTO_READ : 0) | Len;
  UINT64 Start, Now;
  CONST UINT32 Offsets[5] = { HSI_FIFO_CTL, HSI_CTL, HSI_ADDR, HSI_INT_EN, HSI_AUTO };
  CONST UINT32 Values[5] = { Fifo, Ctl, (7U << 24) | (0x48U << 10), INT_DONE, Auto };
  for (UINTN J = 0; J < 5; J++) {
    if (!Event) SetSetupReg (R, B, Read, (UINT32)J + 1, Offsets[J], Values[J]);
    else {
      WriteReg (R, B + Offsets[J], Values[J]);
      UINT32 Actual = ReadReg (R, B + Offsets[J]);
      R->Event.SetupSeen++;
      if (Actual != Values[J]) {
        R->Event.SetupMismatch++;
        if (R->Event.SetupMismatch == 1) {
          R->Event.SetupOffset = Offsets[J]; R->Event.SetupExpected = Values[J];
          R->Event.SetupActual = Actual;
        }
      }
    }
  }
  /* Samsung polling submits before filling the bounded TX FIFO. */
  WriteReg (R, B + HSI_AUTO, Auto | AUTO_RUN);
  if (Event) R->Event.Transactions++; else R->TransactionCount++;
  Start = Now = TouchCounter ();
  for (UINTN I = 0; I < TOUCH_POLL_LIMIT; I++) {
    BOOLEAN Dequeued = FALSE;
    ObserveTransfer (B, R);
    if ((R->InterruptStatus & (~INT_KNOWN | INT_ERRORS)) ||
        R->TransferStatus == MAX_UINT32 || R->FifoStatus == MAX_UINT32) {
      if (Read) ObserveRx (B, R, TOUCH_RX_CONTROLLER, TRUE, FALSE, 0, Event);
      Fail (R, 0x70C, EFI_DEVICE_ERROR);
      break;
    }
    if (!Read && Done < Len && (R->FifoStatus & (BIT7 | 0x7F)) == 0) {
      WriteReg (R, B + HSI_TX, DataBuffer[Done++]);
      if (Event) { R->Event.TxBytes++; R->Event.Done = Done; }
      else R->TxBytes = Done;
    }
    if (Read && (R->FifoStatus & BIT24) == 0) {
      UINT32 Level = ((UINT32)R->FifoStatus >> 16) & 0x7F;
      /* RX_FULL cannot fit this bounded owned request. Never dequeue a
       * byte beyond the requested length, even if a stale/contradictory level says zero. */
      if (Done == Len || (R->FifoStatus & BIT23)) {
        ObserveRx (B, R, TOUCH_RX_EXCESS, TRUE, FALSE, 0, Event);
        Fail (R, 0x70D, EFI_DEVICE_ERROR);
        break;
      }
      if (Level == 0 || Level > Len - Done)
        ObserveRx (B, R, Level ? TOUCH_RX_LEVEL_EXCESS : TOUCH_RX_LEVEL_ZERO,
          FALSE, FALSE, 0, Event);
      /* Samsung polling and pinned9820 use RX_EMPTY for each dequeue and an
       * unsigned8 payload from readl/ReadRegister32. Level is telemetry, not
       * authority to batch-consume bytes. Recheck all status on the next poll.
       * Owned remaining length is checked above before this one MMIO read. */
      UINT32 Data = ReadReg (R, B + HSI_RX);
      if (Data > 255) ObserveRx (B, R, TOUCH_RX_DATA_HIGH, FALSE, TRUE, Data, Event);
      DataBuffer[Done++] = (UINT8)Data;
      if (Event) { R->Event.RxBytes++; R->Event.Done = Done; }
      else { R->Id = (R->Id << 8) | (UINT8)Data; R->RxBytes = Done; }
      Dequeued = TRUE;
    }
    /* After the last dequeue, observe fresh FIFO/IRQ state on the next poll
     * before declaring completion. This detects excess without draining it. */
    if (!Dequeued && (R->InterruptStatus & INT_DONE) &&
        Done == Len) {
      R->WaitTicks += TouchCounter () - Start;
      if (!WaitIdle (B, R)) {
        if (Read) ObserveRx (B, R, TOUCH_RX_IDLE, TRUE, FALSE, 0, Event);
        Fail (R, 0x70E, EFI_DEVICE_ERROR); return FALSE;
      }
      if ((R->InterruptStatus & (~INT_KNOWN | INT_ERRORS)) || !AckOwned (B, R, FALSE)) {
        if (Read) ObserveRx (B, R, TOUCH_RX_ACK, TRUE, FALSE, 0, Event);
        Fail (R, 0x70C, EFI_DEVICE_ERROR); return FALSE;
      }
      return TRUE;
    }
    Now = TouchCounter ();
    if (Now - Start >= R->CounterHz / 10) break;
  }
  R->WaitTicks += Now - Start;
  if (Read && (!R->Reason || Event)) ObserveRx (B, R, TOUCH_RX_TIMEOUT, TRUE, FALSE, 0, Event);
  Fail (R, 0x70B, EFI_TIMEOUT);
  return FALSE;
}

STATIC BOOLEAN Transfer (UINTN B, BOOLEAN Read, N976N_TOUCH_SNAPSHOT *R)
{
  UINT8 Bytes[3] = { 0x52, 0, 0 };
  return TransferBytes (B, Read, Bytes, Read ? 3 : 1, FALSE, R);
}

/* Exact CMU_TOP addresses are admitted by TouchAdmission's clock-controller
 * resource/phandle contract. Read-only parent traversal; no shared PLL/mux/div
 * is retuned. The requested DT default200MHz is not a clock observation. */
typedef struct {
  UINTN Address[12];
  UINT32 Value[12];
  UINTN Count;
} TOUCH_CLOCK_PROOF;

STATIC UINT32 ClockReg (TOUCH_CLOCK_PROOF *P, N976N_TOUCH_SNAPSHOT *R, UINT32 Offset)
{
  UINT32 V = ReadReg (R, 0x1A240000U + Offset);
  P->Address[P->Count] = 0x1A240000U + Offset;
  P->Value[P->Count++] = V;
  return V;
}

STATIC BOOLEAN ClockUnchanged (CONST TOUCH_CLOCK_PROOF *P, N976N_TOUCH_SNAPSHOT *R)
{
  for (UINTN I = 0; I < P->Count; I++)
    if (ReadReg (R, P->Address[I]) != P->Value[I]) return FALSE;
  return ReadReg (R, N976N_TOUCH_CMU_PERIC0 + 0x280) == R->Cmu[TouchCmuI2cMux] &&
    ReadReg (R, N976N_TOUCH_CMU_PERIC0 + 0x182C) == R->Cmu[TouchCmuI2cDiv];
}

STATIC BOOLEAN PllRate (UINT32 Con, UINT64 *Hz)
{
  UINT64 M = (Con >> 16) & 0x3FF, P = (Con >> 8) & 0x3F, S = Con & 7;
  if (Con == MAX_UINT32 || (Con & BIT7)) return FALSE;
  if (!(Con & BIT4)) { *Hz = 26000000; return TRUE; }
  if ((Con & (BIT31 | BIT29)) != (BIT31 | BIT29) || M == 0 || P == 0 || S > 6)
    return FALSE;
  *Hz = (26000000ULL * M) / (P << S);
  return *Hz >= 26000000 && *Hz <= 4000000000ULL;
}

STATIC BOOLEAN InputClock (TOUCH_CLOCK_PROOF *P, N976N_TOUCH_SNAPSHOT *R)
{
  UINT32 Mux = R->Cmu[TouchCmuI2cMux], Div = R->Cmu[TouchCmuI2cDiv];
  UINT32 TopMux, TopDiv, Select, D0, D1, Con;
  UINT64 Rate = 26000000;
  P->Count = 0;
  if ((Mux & ~BIT4) != 0 || (Div & ~15U) != 0) return FALSE;
  if (Mux & BIT4) {
    if (!GatePass (ClockReg (P, R, 0x20C0))) return FALSE;
    TopMux = ClockReg (P, R, 0x10BC);
    TopDiv = ClockReg (P, R, 0x18A8);
    if ((TopMux & ~(1U | BIT28)) || (TopDiv & ~(15U | BIT28))) return FALSE;
    TopMux &= 1; TopDiv &= 15;
    if (TopMux == 0) {
      Select = ClockReg (P, R, 0x10DC);
      D0 = ClockReg (P, R, 0x18CC);
      D1 = ClockReg (P, R, 0x18D4);
      if ((Select & ~(1U | BIT28)) || (D0 & ~(1U | BIT28)) ||
          (D1 & ~(1U | BIT28))) return FALSE;
      Select &= 1; D0 &= 1; D1 &= 1;
      Con = ClockReg (P, R, Select ? 0x100 : 0x160);
      if (!PllRate (Con, &Rate)) return FALSE;
      Rate /= (D0 + 1) * (D1 + 1);
    } else {
      D0 = ClockReg (P, R, 0x18E4);
      Con = ClockReg (P, R, 0x1A0);
      if ((D0 & ~(1U | BIT28)) || !PllRate (Con, &Rate)) return FALSE;
      Rate /= (D0 & 1) + 1;
    }
    Rate /= TopDiv + 1;
  }
  Rate /= (Div & 15) + 1;
  if (Rate < 1600000 || Rate > 400000000 || !ClockUnchanged (P, R)) return FALSE;
  R->InputHz = Rate;
  return TRUE;
}

STATIC VOID ObserveStage (
  UINTN B, UINTN Gpio, UINT64 Bit, UINT64 *Value, N976N_TOUCH_SNAPSHOT *R)
{
  UINT32 T = ReadReg (R, B + HSI_TRANS);
  UINT32 D = ReadReg (R, Gpio + 0x24);
  *Value = ((UINT64)T << 32) | D;
  R->StageMask |= Bit;
}

/* Samsung writes the asserted reset, then clears it from the actual readback.
 * The caller must own an admitted, not-submitted controller and release USI
 * first. This does not issue an I2C command or reset the touchscreen itself. */
STATIC BOOLEAN ResetController (UINTN B, UINT32 Ctl, N976N_TOUCH_SNAPSHOT *R)
{
  if (Ctl == MAX_UINT32 || (Ctl & BIT31)) return FALSE;
  WriteReg (R, B + HSI_CTL, Ctl | BIT31);
  UINT32 Now = ReadReg (R, B + HSI_CTL);
  return (Now & BIT31) && Now != MAX_UINT32 &&
    SetReg (R, B + HSI_CTL, Now & ~BIT31);
}

STATIC BOOLEAN ConfigureAfterReset (
  UINTN B, UINT32 Timeout, CONST TOUCH_CLOCK_PROOF *Clock,
  N976N_TOUCH_SNAPSHOT *R);

/* Samsung's pre-transfer predicate resets controller state6 before any
 * transaction. Limit that source-backed recovery to this probe's own setup:
 * it is never a retry, a post-submission abort, or a foreign-state takeover. */
STATIC BOOLEAN RecoverBeforeStart (
  UINTN B, UINTN Gpio, UINT32 Timeout, CONST TOUCH_CLOCK_PROOF *Clock,
  BOOLEAN HsiChanged, BOOLEAN UsiChanged, N976N_TOUCH_SNAPSHOT *R)
{
  if (!HsiChanged || !UsiChanged || !(R->PrepChecks & TOUCH_PREP_IDLE) ||
      R->TransactionCount || R->TxBytes || R->RxBytes ||
      (R->StageMask & TOUCH_STAGE_RECOVERY)) return FALSE;
  ObserveTransfer (B, R);
  if (R->TransferStatus == MAX_UINT32 || (R->TransferStatus & BIT16) ||
      (R->TransferStatus & 15) != 6 ||
      !FifoEmpty ((UINT32)R->FifoStatus) || R->InterruptStatus ||
      ReadReg (R, B + HSI_INT_EN) || (ReadReg (R, B + HSI_AUTO) & AUTO_RUN) ||
      ReadReg (R, B + HSI_USI_CON) != 0 || !ClockUnchanged (Clock, R)) return FALSE;
  UINT32 Ctl = ReadReg (R, B + HSI_CTL);
  if (Ctl == MAX_UINT32 || (Ctl & BIT31)) return FALSE;
  R->StageMask |= TOUCH_STAGE_RECOVERY;
  BOOLEAN Reset = ResetController (B, Ctl, R);
  /* Samsung's pre-transfer reset invokes its entire timing/master init,
   * not a bare reset followed by an idle wait. This remains cleanup only. */
  BOOLEAN Configured = Reset && ConfigureAfterReset (B, Timeout, Clock, R);
  BOOLEAN Idle = Configured && WaitIdle (B, R);
  ObserveStage (B, Gpio, TOUCH_STAGE_CLEANUP, &R->CleanupState, R);
  if (!Idle || !Inactive ((UINT32)(R->CleanupState >> 32)) ||
      (R->CleanupState & 0x30) != 0x30 || R->InterruptStatus ||
      ReadReg (R, B + HSI_INT_EN) || ReadReg (R, B + HSI_USI_CON) != 0 ||
      !ClockUnchanged (Clock, R)) return FALSE;
  R->StageMask |= TOUCH_STAGE_RECOVERED;
  return TRUE;
}

/* Observe the bus before connecting its alternate function. PUD fields are
 * the only pin mutation here; CON remains input, DRV unchanged and USI held
 * in reset. This is neither a rail test nor a GPIO pulse/recovery sequence. */
STATIC BOOLEAN InputPreflight (
  UINTN B, UINTN Gpio, CONST TOUCH_CLOCK_PROOF *Clock,
  BOOLEAN *PullChanged, N976N_TOUCH_SNAPSHOT *R)
{
  UINT32 Con = R->Gpp[TouchGppCon], Pull = R->Gpp[TouchGppPull];
  UINT32 Drive = R->Gpp[TouchGppDrive], Pins = Con & 0x00FF0000U;
  if (Pins == 0x00220000U) {
    R->InputCheck = TOUCH_INPUT_AF_SKIP;
    return TRUE;
  }
  if (Pins || R->UsiControlBefore != 1) {
    Fail (R, 0x714, EFI_NOT_READY); return FALSE;
  }
  if (!IdleNow (B, R) || R->InterruptStatus ||
      ReadReg (R, B + HSI_INT_EN) || ReadReg (R, B + HSI_USI_CON) != 1 ||
      ReadReg (R, Gpio + 0x20) != Con ||
      ReadReg (R, Gpio + 0x28) != Pull ||
      ReadReg (R, Gpio + 0x2C) != Drive) {
    Fail (R, 0x714, EFI_NOT_READY); return FALSE;
  }
  if (!ClockUnchanged (Clock, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED); return FALSE;
  }
  UINT32 Neutral = Pull & ~0x00FF0000U;
  if (Neutral != Pull) {
    *PullChanged = TRUE;
    R->InputCheck |= TOUCH_INPUT_PULL_WRITE;
    if (!SetReg (R, Gpio + 0x28, Neutral)) {
      Fail (R, 0x714, EFI_DEVICE_ERROR); return FALSE;
    }
  }
  BOOLEAN Idle = IdleNow (B, R);
  UINT32 Data = ReadReg (R, Gpio + 0x24);
  R->InputState = (R->TransferStatus << 32) | Data;
  R->InputCheck |= TOUCH_INPUT_RAW;
  if (!Idle || R->InterruptStatus || Data == MAX_UINT32 ||
      ReadReg (R, B + HSI_INT_EN) || ReadReg (R, B + HSI_USI_CON) != 1 ||
      ReadReg (R, Gpio + 0x20) != Con ||
      ReadReg (R, Gpio + 0x28) != Neutral ||
      ReadReg (R, Gpio + 0x2C) != Drive ||
      !IdleNow (B, R) || R->InterruptStatus) {
    Fail (R, 0x714, EFI_NOT_READY); return FALSE;
  }
  if (!ClockUnchanged (Clock, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED); return FALSE;
  }
  R->InputCheck |= TOUCH_INPUT_OBSERVED;
  if ((Data & 0x30) != 0x30) {
    Fail (R, 0x713, EFI_NOT_READY); return FALSE;
  }
  R->InputCheck |= TOUCH_INPUT_HIGH;
  return TRUE;
}

STATIC BOOLEAN Timing (UINTN B, N976N_TOUCH_SNAPSHOT *R)
{
  UINT64 Div = R->InputHz / (100000U * 16U);
  UINT64 Shift;
  UINT32 F1 = ReadReg (R, B + HSI_FS1);
  UINT32 F2 = ReadReg (R, B + HSI_FS2);
  UINT32 F3 = ReadReg (R, B + HSI_FS3);
  if (F1 == MAX_UINT32 || F2 == MAX_UINT32 || F3 == MAX_UINT32) return FALSE;
  if (Div == 0 || Div > 255) return FALSE;
  /* Samsung standard-speed equation. Keep shifts defined even if a future
   * admitted clock falls outside this deliberately small timing contract. */
  Shift = (25 * (R->InputHz / 1000000U)) / ((Div + 1) * 10);
  if (Shift == 0 || Shift >= 8) return FALSE;
  R->TimingFs1 = (F1 & ~0x00FF0000U) |
    (((0xFFU << (Shift - 1)) & 0xFFU) << 16);
  R->TimingFs2 = (F2 & ~0xFFU) |
    ((0xFFU << Shift) & 0xFFU);
  R->TimingFs3 = (F3 & ~0x00FF0000U) | (Div << 16);
  return TRUE;
}

/* A reset-owned FSM6 is an initialization state which may be configured,
 * never an idle state authorizing AUTO_RUN. Samsung completes FS timing and
 * MASTER/AUTO initialization before requiring a ready controller. Retain
 * the separate initial ownership admission and final idle/line gate. */
STATIC BOOLEAN ConfigureAfterReset (
  UINTN B, UINT32 Timeout, CONST TOUCH_CLOCK_PROOF *Clock,
  N976N_TOUCH_SNAPSHOT *R)
{
  ObserveTransfer (B, R);
  UINT32 State = (UINT32)R->TransferStatus;
  if (!(R->PrepChecks & TOUCH_PREP_IDLE) ||
      R->TransactionCount || R->TxBytes || R->RxBytes ||
      State == MAX_UINT32 || (State & BIT16) ||
      (!Inactive (State) && (State & 15) != 6) ||
      !FifoEmpty ((UINT32)R->FifoStatus) || R->InterruptStatus ||
      ReadReg (R, B + HSI_INT_EN) ||
      (ReadReg (R, B + HSI_AUTO) & AUTO_RUN) ||
      ReadReg (R, B + HSI_USI_CON) != 0) {
    Fail (R, 0x709, EFI_NOT_READY); return FALSE;
  }
  if (!ClockUnchanged (Clock, R) || !Timing (B, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED); return FALSE;
  }
  /* N976N clock_setup writes FS3/FS2/FS1 before i2c_init selects MASTER/AUTO.
   * No address, FIFO payload or AUTO_RUN is written by this helper. */
  if (!SetReg (R, B + HSI_INT_EN, 0) ||
      !SetReg (R, B + HSI_FS3, (UINT32)R->TimingFs3) ||
      !SetReg (R, B + HSI_FS2, (UINT32)R->TimingFs2) ||
      !SetReg (R, B + HSI_FS1, (UINT32)R->TimingFs1) ||
      !SetReg (R, B + HSI_CTL, BIT3) ||
      !SetReg (R, B + HSI_TRAILING, 0xFFFFFF) ||
      !SetReg (R, B + HSI_TIMEOUT, Timeout & ~BIT31) ||
      !SetReg (R, B + HSI_CONF,
        (ReadReg (R, B + HSI_CONF) & ~(BIT29 | BIT30)) | BIT31)) {
    Fail (R, 0x70A, EFI_DEVICE_ERROR); return FALSE;
  }
  if (!ClockUnchanged (Clock, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED); return FALSE;
  }
  return TRUE;
}

/* Compile-time independent tests call this exact core with only CPU/counter
 * observations and MMIO primitives mocked. Ordinary firmware uses the wrapper.
 */
/* Event-session failures preserve the first cause; restoration has its own
 * reason. No device reset, FIFO-clear command, retry or firmware operation. */
STATIC VOID EventFail (N976N_TOUCH_SNAPSHOT *R, UINT64 Why, EFI_STATUS Status)
{
  if (!R->Event.Reason) { R->Event.Reason = Why; R->Event.Status = Status; }
  Fail (R, Why, Status);
}

STATIC BOOLEAN EventDelay (N976N_TOUCH_SNAPSHOT *R, UINT32 Ms)
{
  UINT64 Start = TouchCounter (), Budget = R->CounterHz * Ms / 1000;
  for (UINTN I = 0; I < TOUCH_EVENT_DELAY_LIMIT; I++)
    if (TouchCounter () - Start >= Budget) return TRUE;
  return FALSE;
}

STATIC BOOLEAN EventReady (UINTN B, TOUCH_CLOCK_PROOF *Clock,
  N976N_TOUCH_SNAPSHOT *R)
{
  if (!ClockUnchanged (Clock, R) || !WaitIdle (B, R) ||
      (R->InterruptStatus & ~BIT0) ||
      ReadReg (R, B + HSI_USI_CON) != 0) {
    EventFail (R, 0x740, EFI_NOT_READY); return FALSE;
  }
  return TRUE;
}

STATIC BOOLEAN EventIo (
  UINTN B, TOUCH_CLOCK_PROOF *Clock, N976N_TOUCH_SNAPSHOT *R,
  UINT8 Command, UINT8 *Bytes, UINT32 Length, BOOLEAN Read)
{
  /* Literal command/length grammar: only the Samsung read/event/sense and
   * reversible touch-function operations below can reach AUTO_RUN. */
  BOOLEAN Allowed = Read ?
    ((Command == 0x60 && Length == 16) ||
     (Command == 0x55 && Length == 1) || (Command == 0x30 && Length == 2)) :
    ((Command == 0x10 || Command == 0x11) ? Length == 0 :
     (Command == 0x30 && Length == 2));
  if (!Allowed || (Length && !Bytes) || !ClockUnchanged (Clock, R)) {
    EventFail (R, 0x740, EFI_INVALID_PARAMETER); return FALSE;
  }
  R->Event.Command = Command;
  UINT8 Tx[3] = { Command, 0, 0 };
  if (!Read && Length) { Tx[1] = Bytes[0]; Tx[2] = Bytes[1]; }
  if (!EventReady (B, Clock, R) ||
      !TransferBytes (B, FALSE, Tx, Read ? 1 : Length + 1, TRUE, R) ||
      (Read && (!EventReady (B, Clock, R) ||
       !TransferBytes (B, TRUE, Bytes, Length, TRUE, R)))) {
    EventFail (R, R->Reason ? R->Reason : 0x740,
      R->Reason ? R->Status : EFI_DEVICE_ERROR); return FALSE;
  }
  if (!ClockUnchanged (Clock, R)) {
    EventFail (R, 0x708, EFI_UNSUPPORTED); return FALSE;
  }
  return TRUE;
}

STATIC BOOLEAN EventPacket (N976N_TOUCH_SNAPSHOT *R, CONST UINT8 *P)
{
  N976N_TOUCH_EVENT_OBSERVATION *E = &R->Event;
  if (P[0] == 0) { E->EmptyCount++; return TRUE; }
  UINT32 Kind = P[0] & 3;
  if (Kind == 1) {
    UINT32 Subtype = (P[0] >> 2) & 15;
    if (Subtype == 1 || ((Subtype == 2 || Subtype == 7) && P[1] == 0)) {
      for (UINTN I = 0; I < 16; I++) E->RejectRaw[I] = P[I];
      EventFail (R, Subtype == 1 ? 0x749 : 0x74A, EFI_DEVICE_ERROR); return FALSE;
    }
    E->StatusCount++; return TRUE;
  }
  if (Kind == 2) { E->OtherCount++; return TRUE; }
  if (Kind == 3) {
    for (UINTN I = 0; I < 16; I++) E->RejectRaw[I] = P[I];
    EventFail (R, 0x744, EFI_COMPROMISED_DATA); return FALSE;
  }
  UINT32 Id = (P[0] >> 2) & 15, Action = P[0] >> 6;
  UINT32 X = ((UINT32)P[1] << 4) | (P[3] >> 4);
  UINT32 Y = ((UINT32)P[2] << 4) | (P[3] & 15);
  UINT32 Type = ((P[6] >> 6) << 2) | (P[7] >> 6);
  if (Id == 0 || Id > 11 || Action == 0 || X >= 4096 || Y >= 4096) {
    for (UINTN I = 0; I < 16; I++) E->RejectRaw[I] = P[I];
    EventFail (R, 0x744, EFI_COMPROMISED_DATA); return FALSE;
  }
  /* NORMAL, GLOVE, PALM and WET are finger-class events in N976N y771_d.
   * Other documented tool classes are observed but never called fingers. */
  if (Type != 0 && Type != 3 && Type != 5 && Type != 6) {
    E->OtherCount++; return TRUE;
  }
  if (Id > 10) {
    for (UINTN I = 0; I < 16; I++) E->RejectRaw[I] = P[I];
    EventFail (R, 0x744, EFI_COMPROMISED_DATA); return FALSE;
  }
  if (E->CoordinateCount == 0) {
    E->FirstX = X; E->FirstY = Y; E->FirstId = Id;
    for (UINTN I = 0; I < 16; I++) E->FirstRaw[I] = P[I];
  }
  E->CoordinateCount++;
  E->LastX = X; E->LastY = Y; E->LastId = Id;
  E->LastAction = Action; E->LastType = Type; E->Remaining = P[7] & 31;
  for (UINTN I = 0; I < 16; I++) E->LastRaw[I] = P[I];
  if (Action == 1) E->PressCount++;
  else if (Action == 2) E->MoveCount++;
  else E->ReleaseCount++;
  if (Action == 3) E->ActiveMask &= ~(1ULL << (Id - 1));
  else E->ActiveMask |= 1ULL << (Id - 1);
  return TRUE;
}

STATIC BOOLEAN ObserveEvents (
  UINTN B, TOUCH_CLOCK_PROOF *Clock, N976N_TOUCH_SNAPSHOT *R)
{
  N976N_TOUCH_EVENT_OBSERVATION *E = &R->Event;
  UINT8 Data[16] = { 0 };
  BOOLEAN FunctionAttempted = FALSE, SenseAttempted = FALSE, Retired = TRUE;
  E->Mode = 1; E->Phase = 1; E->Status = EFI_SUCCESS;
  E->WindowTicks = R->CounterHz * TOUCH_EVENT_WINDOW_SECONDS;
  /* Cold-owned power-on notification is consumed as an event, not guessed
   * from elapsed time. The kernel allows INFO or VENDOR_INFO boot-complete. */
  for (UINTN I = 0; I < TOUCH_EVENT_BOOT_LIMIT; I++) {
    if (!EventIo (B, Clock, R, 0x60, Data, 16, TRUE)) goto Cleanup;
    UINT32 Subtype = (Data[0] >> 2) & 15;
    if ((Data[0] & 3) == 1 && (Subtype == 2 || Subtype == 7) && Data[1] == 0) {
      E->BootReady = 1; E->Checks |= TOUCH_EVENT_BOOT_READY; break;
    }
    if (!EventDelay (R, 20)) { EventFail (R, 0x746, EFI_TIMEOUT); goto Cleanup; }
  }
  if (!E->BootReady) { EventFail (R, 0x741, EFI_TIMEOUT); goto Cleanup; }
  E->Phase = 2;
  if (!EventIo (B, Clock, R, 0x55, Data, 1, TRUE)) goto Cleanup;
  E->BootStatus = Data[0];
  if (Data[0] != 0x20) { EventFail (R, 0x742, EFI_NOT_READY); goto Cleanup; }
  E->Checks |= TOUCH_EVENT_APP;
  E->Phase = 3;
  if (!EventIo (B, Clock, R, 0x30, Data, 2, TRUE)) goto Cleanup;
  E->FunctionBefore = Data[0] | ((UINT32)Data[1] << 8);
  E->Checks |= TOUCH_EVENT_FUNCTION_READ;
  if (E->FunctionBefore == 0xFFFF) { EventFail (R, 0x743, EFI_DEVICE_ERROR); goto Cleanup; }
  E->FunctionEnabled = E->FunctionBefore | 0x61;
  if (E->FunctionEnabled != E->FunctionBefore) {
    Data[0] = (UINT8)E->FunctionEnabled; Data[1] = (UINT8)(E->FunctionEnabled >> 8);
    FunctionAttempted = TRUE;
    if (!EventIo (B, Clock, R, 0x30, Data, 2, FALSE)) goto Cleanup;
    if (!EventDelay (R, 30)) { EventFail (R, 0x746, EFI_TIMEOUT); goto Cleanup; }
  }
  if (!EventIo (B, Clock, R, 0x30, Data, 2, TRUE)) goto Cleanup;
  if ((Data[0] | ((UINT32)Data[1] << 8)) != E->FunctionEnabled) {
    EventFail (R, 0x743, EFI_DEVICE_ERROR); goto Cleanup;
  }
  E->Checks |= TOUCH_EVENT_FUNCTION_SET;
  E->Phase = 4; SenseAttempted = TRUE;
  if (!EventIo (B, Clock, R, 0x10, NULL, 0, FALSE)) goto Cleanup;
  E->SenseOn = 1; E->Checks |= TOUCH_EVENT_SENSE_ON;
  E->Phase = 5;
  UINT64 Start = TouchCounter (), LastProgress = Start;
  if (!N976nTouchEventProgress (R)) {
    EventFail (R, 0x74B, EFI_DEVICE_ERROR); goto Cleanup;
  }
  for (UINTN I = 0; I < TOUCH_EVENT_POLL_LIMIT; I++) {
    E->ElapsedTicks = TouchCounter () - Start;
    if (E->ElapsedTicks >= E->WindowTicks) { E->Stop = 1; break; }
    if (!EventIo (B, Clock, R, 0x60, Data, 16, TRUE)) goto Cleanup;
    E->Polls++;
    UINT64 PreviousCoordinates = E->CoordinateCount;
    if (!EventPacket (R, Data)) goto Cleanup;
    UINT64 Now = TouchCounter ();
    E->ElapsedTicks = Now - Start;
    if (E->CoordinateCount != PreviousCoordinates && !N976nTouchEventContact (R)) {
      EventFail (R, 0x74B, EFI_DEVICE_ERROR); goto Cleanup;
    }
    if (Now - LastProgress >= R->CounterHz) {
      LastProgress = Now;
      if (!N976nTouchEventProgress (R)) {
        EventFail (R, 0x74B, EFI_DEVICE_ERROR); goto Cleanup;
      }
    }
    /* Fresh remaining count is a scheduling hint, never permission to batch
     * dequeue. Each next event still needs its own owned command/read pair. */
    if ((Data[0] == 0 || (Data[7] & 31) == 0) && !EventDelay (R, 20)) {
      EventFail (R, 0x746, EFI_TIMEOUT); goto Cleanup;
    }
  }
  E->ElapsedTicks = TouchCounter () - Start;
  if (!E->Stop) E->Stop = E->ElapsedTicks >= E->WindowTicks ? 1 : 2;
  E->Checks |= TOUCH_EVENT_WINDOW;
  E->Outcome = E->CoordinateCount ? 2 : 1;
Cleanup:
  /* A failed/incomplete request is not retried or drained. Cleanup commands
   * require fresh idle/empty/AUTO-off and acknowledgement of our known IRQs.
   * Unknown activity retains all owned resources for quarantine. */
  if ((SenseAttempted || FunctionAttempted) &&
      (!WaitIdle (B, R) || !AckOwned (B, R, TRUE) || !ClockUnchanged (Clock, R))) {
    E->CleanupReason = 0x747; EventFail (R, 0x747, EFI_DEVICE_ERROR);
    Retired = FALSE; goto Done;
  }
  if (SenseAttempted) {
    E->Phase = 6;
    if (!EventIo (B, Clock, R, 0x11, NULL, 0, FALSE) || !EventDelay (R, 100)) {
      E->CleanupReason = 0x747; EventFail (R, 0x747, EFI_DEVICE_ERROR);
      Retired = FALSE; goto Done;
    }
    E->SenseOff = 1; E->Checks |= TOUCH_EVENT_SENSE_OFF;
  }
  E->Phase = 7;
  if (E->Checks & TOUCH_EVENT_FUNCTION_READ) {
    if (FunctionAttempted) {
      Data[0] = (UINT8)E->FunctionBefore; Data[1] = (UINT8)(E->FunctionBefore >> 8);
      if (!EventIo (B, Clock, R, 0x30, Data, 2, FALSE) || !EventDelay (R, 30)) {
        E->CleanupReason = 0x748; EventFail (R, 0x748, EFI_DEVICE_ERROR);
        Retired = FALSE; goto Done;
      }
    }
    if (!EventIo (B, Clock, R, 0x30, Data, 2, TRUE)) {
      E->CleanupReason = 0x748; Retired = FALSE; goto Done;
    }
    E->FunctionRestored = Data[0] | ((UINT32)Data[1] << 8);
    if (E->FunctionRestored != E->FunctionBefore) {
      E->CleanupReason = 0x748; EventFail (R, 0x748, EFI_DEVICE_ERROR);
      Retired = FALSE; goto Done;
    }
    E->Checks |= TOUCH_EVENT_FUNCTION_RESTORE;
  }
Done:
  if (E->Reason) E->Outcome = 0;
  E->Phase = 8;
  if (!N976nTouchEventProgress (R)) EventFail (R, 0x74B, EFI_DEVICE_ERROR);
  if (E->Reason) E->Outcome = 0;
  return Retired;
}

/* FIX3: a handoff boundary, never a transfer-start or reset sequence. Clock
 * stability is checked before accessing the already owned controller. */
STATIC BOOLEAN RetainedIdle (
  UINTN B, UINTN Gpio, CONST TOUCH_CLOCK_PROOF *Clock, N976N_TOUCH_SNAPSHOT *R)
{
  if (!ClockUnchanged (Clock, R) || ReadReg (R, B + HSI_USI_CON) != 0)
    return FALSE;
  UINT32 Pad = ReadReg (R, Gpio + 0x24);
  return Pad != MAX_UINT32 && (Pad & 0x30) == 0x30 &&
    ReadReg (R, B + HSI_INT_EN) == 0 &&
    ReadReg (R, B + HSI_INT_ST) == 0 && IdleNow (B, R) &&
    R->InterruptStatus == 0;
}

STATIC BOOLEAN SnapshotStateEx (
  CONST N976N_TOUCH_ADMISSION *A, UINT64 El, UINT64 Sctlr, UINT64 Daif,
  UINT64 CounterHz, N976N_TOUCH_SNAPSHOT *R, BOOLEAN Events,
  N976N_TOUCH_HANDOFF *Lease)
{
  UINTN Ap = (UINTN)A, Rp = (UINTN)R, B;
  UINT32 Timeout = 0, CmuAny = 0, ObserveOnly[3];
  CONST UINT32 ObserveOffsets[3] = { 0x0C, 0x10, 0x6C };
  TOUCH_CLOCK_PROOF Clock;
  BOOLEAN OuterChanged = FALSE, HaveHsi = FALSE, HsiChanged = FALSE;
  BOOLEAN UsiChanged = FALSE, PinsChanged = FALSE, PullChanged = FALSE;
  BOOLEAN Safe = TRUE, Ok;
  if (!R || (Rp & 7) || Rp > MAX_UINTN - sizeof (*R) ||
      (A && ((Ap & 7) || Ap > MAX_UINTN - sizeof (*A) ||
       (Ap < Rp + sizeof (*R) && Rp < Ap + sizeof (*A))))) return FALSE;
  ZeroMem (R, sizeof (*R));
  R->Magic = N976N_TOUCH_SNAPSHOT_MAGIC; R->Version = 8; R->Size = sizeof (*R);
  R->CpuEl = El; R->CpuSctlr = Sctlr; R->CpuDaif = Daif;
  R->Phase = 1; R->Status = EFI_INVALID_PARAMETER; R->Reason = 0x700;
  R->SkipMask = N976N_TOUCH_CLASS_ALL;
  if (!AdmissionValid (A)) return FALSE;
  R->Profile = A->Profile; R->Checks = 1; R->Reason = 0x701;
  R->Status = EFI_UNSUPPORTED;
  if (El != 4 || (Sctlr & (BIT0 | BIT2 | BIT12)) ||
      (Daif & 0x3C0) != 0x3C0 ||
      CounterHz != (A->Profile ? 62500000U : 26000000U)) return FALSE;
  R->Checks |= 2 | 0x80;
  if (A->Profile == 1) { R->Phase = 8; R->Reason = 0x697; return TRUE; }
  R->CounterHz = CounterHz; R->Reason = 0; R->Status = EFI_SUCCESS;
  R->Phase = 2; B = (UINTN)A->Hsi2c;
  ReadClass (A->GpioAlive, mAliveOffsets, TouchAliveCount, R->Alive, R);
  R->ValidMask |= N976N_TOUCH_CLASS_ALIVE; R->Checks |= 4;
  /* EXP9 never configures ALIVE. Samsung GPIO input reads accept input or
   * EINT mux; pin0 PUD uses the documented none/down/up codes0/1/3. */
  if (Lease != NULL &&
      (R->Alive[TouchAlivePull] == MAX_UINT32 ||
       R->Alive[TouchAliveEintMask] == MAX_UINT32 ||
       ((R->Alive[TouchAliveCon] & 15) != 0 &&
        (R->Alive[TouchAliveCon] & 15) != 15) ||
       ((R->Alive[TouchAlivePull] & 15) != 0 &&
        (R->Alive[TouchAlivePull] & 15) != 1 &&
        (R->Alive[TouchAlivePull] & 15) != 3))) {
    Fail (R, 0x762, EFI_DEVICE_ERROR); goto Done;
  }
  ReadClass (A->CmuPeric0, mCmuOffsets, TouchCmuCount, R->Cmu, R);
  R->ValidMask |= N976N_TOUCH_CLASS_CMU; R->Checks |= 8;
  for (UINTN I = 0; I < TouchCmuCount; I++) CmuAny |= R->Cmu[I];
  if (CmuAny == 0 || CmuAny == MAX_UINT32) { Fail (R, 0x702, EFI_NOT_READY); goto Done; }
  for (UINTN I = TouchCmuOsc; I <= TouchCmuI2cPclk; I++) {
    if (!GatePass (R->Cmu[I])) { Fail (R, 0x702, EFI_NOT_READY); goto Done; }
  }
  ReadClass (A->GpioPeric0, mGppOffsets, TouchGppCount, R->Gpp, R);
  R->GppConPdn = ReadReg (R, (UINTN)A->GpioPeric0 + 0x30);
  R->GppPullPdn = ReadReg (R, (UINTN)A->GpioPeric0 + 0x34);
  R->ValidMask |= N976N_TOUCH_CLASS_GPIO; R->Checks |= 0x10;
  R->UsiMode = ReadReg (R, (UINTN)A->SysregUsi);
  R->ValidMask |= N976N_TOUCH_CLASS_USI; R->Checks |= 0x20;
  /* Do not take over an SPI/UART mode or pins already assigned elsewhere. */
  if (R->UsiMode != 0 && R->UsiMode != 4) { Fail (R, 0x704, EFI_NOT_READY); goto Done; }
  for (UINTN I = 4; I <= 5; I++) {
    UINT32 Mode = (R->Gpp[TouchGppCon] >> (I * 4)) & 15;
    if (Mode != 0 && Mode != 2) { Fail (R, 0x705, EFI_NOT_READY); goto Done; }
  }
  if (R->Cmu[TouchCmuI2cQch] & ~0x003F0003U) { Fail (R, 0x703, EFI_NOT_READY); goto Done; }
  if (!InputClock (&Clock, R)) { Fail (R, 0x708, EFI_UNSUPPORTED); goto Done; }
  R->PrepChecks |= TOUCH_PREP_SOURCE | TOUCH_PREP_CLOCK;
  R->Phase = 3;
  /* Samsung ra_req_enable_qch only writes REQUEST(bit1) while automatic
   * Q-channel ENABLE(bit0) is clear. Never change that policy bit here. */
  OuterChanged = TRUE;
  if ((R->Cmu[TouchCmuI2cQch] & BIT0) == 0 &&
      !SetReg (R, (UINTN)A->CmuPeric0 + 0x3038, R->Cmu[TouchCmuI2cQch] | BIT1)) {
    Fail (R, 0x706, EFI_DEVICE_ERROR); goto Restore;
  }
  R->PrepChecks |= TOUCH_PREP_QCH;
  if (!SetReg (R, (UINTN)A->SysregUsi, 4)) { Fail (R, 0x706, EFI_DEVICE_ERROR); goto Restore; }
  R->PrepChecks |= TOUCH_PREP_USI;
  ReadClass (A->Hsi2c, mHsiOffsets, TouchHsiCount, R->Hsi, R);
  R->ValidMask |= N976N_TOUCH_CLASS_HSI; R->Checks |= 0x40; HaveHsi = TRUE;
  Timeout = ReadReg (R, B + HSI_TIMEOUT);
  for (UINTN I = 0; I < 3; I++) ObserveOnly[I] = ReadReg (R, B + ObserveOffsets[I]);
  R->UsiControlBefore = ReadReg (R, B + HSI_USI_CON);
  R->UsiOptionBefore = ReadReg (R, B + HSI_USI_OPTION);
  R->TransferStatus = R->Hsi[TouchHsiTransStatus];
  R->InterruptStatus = R->Hsi[TouchHsiIntStatus];
  R->FifoStatus = R->Hsi[TouchHsiFifoStatus];
  if (!Inactive ((UINT32)R->TransferStatus) ||
      !FifoEmpty ((UINT32)R->FifoStatus) ||
      (R->Hsi[TouchHsiAutoConf] & AUTO_RUN) ||
      R->Hsi[TouchHsiIntEnable] || R->Hsi[TouchHsiIntStatus] ||
      (R->Hsi[TouchHsiCtl] & BIT31) ||
      (R->UsiControlBefore & ~1ULL) || R->UsiOptionBefore > 7 ||
      Timeout == MAX_UINT32 || R->Hsi[TouchHsiConf] == MAX_UINT32) {
    Fail (R, 0x709, EFI_NOT_READY); goto Restore;
  }
  R->PrepChecks |= TOUCH_PREP_IDLE;
  if (!InputPreflight (B, (UINTN)A->GpioPeric0, &Clock, &PullChanged, R))
    goto Restore;
  PinsChanged = TRUE;
  if ((!(R->InputCheck & TOUCH_INPUT_OBSERVED) &&
       !SetReg (R, (UINTN)A->GpioPeric0 + 0x28,
        R->Gpp[TouchGppPull] & ~0x00FF0000U)) ||
      !SetReg (R, (UINTN)A->GpioPeric0 + 0x2C,
       R->Gpp[TouchGppDrive] & ~0x00FF0000U) ||
      !SetReg (R, (UINTN)A->GpioPeric0 + 0x20,
       (R->Gpp[TouchGppCon] & ~0x00FF0000U) | 0x00220000U)) {
    Fail (R, 0x706, EFI_DEVICE_ERROR); goto Restore;
  }
  R->PrepChecks |= TOUCH_PREP_PINS;
  ObserveStage (B, (UINTN)A->GpioPeric0, TOUCH_STAGE_PINS, &R->PinsState, R);
  R->Phase = 4;
  /* Actual N976N Samsung probe releases USI before its HSI software reset.
   * NTDEV's 9810 order differs here and is not authoritative for this device. */
  UsiChanged = TRUE;
  if (!SetReg (R, B + HSI_USI_CON, 0)) {
    Fail (R, 0x70A, EFI_DEVICE_ERROR); goto Restore;
  }
  ObserveStage (B, (UINTN)A->GpioPeric0, TOUCH_STAGE_RELEASED, &R->ReleasedState, R);
  HsiChanged = TRUE;
  /* Samsung and NTDEV use hardware reset defaults for the untouched timing
   * fields. No inherited arbitrary timing is silently promoted as validated.
   * Initial FIFO/IRQ/active-bus admission above must precede this reset.
   */
  if (!ResetController (B, R->Hsi[TouchHsiCtl], R)) {
    Fail (R, 0x70A, EFI_DEVICE_ERROR); goto Restore;
  }
  ObserveStage (B, (UINTN)A->GpioPeric0, TOUCH_STAGE_RESET, &R->ResetState, R);
  if (!ConfigureAfterReset (B, Timeout, &Clock, R)) goto Restore;
  /* Only the completed configuration is required to become ready. Snapshot
   * the terminal wait state, then reject a newer contradictory raw sample. */
  BOOLEAN Ready = WaitIdle (B, R);
  ObserveStage (B, (UINTN)A->GpioPeric0, TOUCH_STAGE_CONFIGURED,
    &R->ConfiguredState, R);
  Ready = Ready && Inactive ((UINT32)(R->ConfiguredState >> 32));
  if ((R->ConfiguredState & 0x30) != 0x30) {
    Fail (R, 0x712, EFI_NOT_READY); goto Restore;
  }
  if (!Ready || R->InterruptStatus || ReadReg (R, B + HSI_INT_EN) ||
      ReadReg (R, B + HSI_USI_CON) != 0) {
    Fail (R, 0x709, EFI_NOT_READY); goto Restore;
  }
  if (!ClockUnchanged (&Clock, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED); goto Restore;
  }
  R->PrepChecks |= TOUCH_PREP_CONFIG;
  R->Phase = 5;
  if (!Transfer (B, FALSE, R)) goto Restore;
  R->Phase = 6;
  if (!Transfer (B, TRUE, R)) goto Restore;
  if (!ClockUnchanged (&Clock, R)) {
    Fail (R, 0x708, EFI_UNSUPPORTED);
    if (Lease != NULL) { Safe = FALSE; goto Done; }
    goto Restore;
  }
  if (R->Id == 0 || R->Id == 0xFFFFFF) {
    ObserveRx (B, R, TOUCH_RX_ID, TRUE, FALSE, 0, FALSE);
    Fail (R, 0x70D, EFI_DEVICE_ERROR); goto Restore;
  }
  R->PrepChecks |= TOUCH_PREP_ID;
  if (Lease != NULL) {
    /* Retire the owned ID transaction before changing the channel selector.
     * Samsung HSI_CTL MASTER is BIT3 and RXCHON is BIT6. A completed RX leaves
     * 0x48; the Windows lease requires neutral MASTER (0x08). Neither this
     * write nor a failed attempt may start a transfer, reset, or retry. */
    if (Events || R->Id != 0xAC3771 || R->TransactionCount != 2 ||
        R->TxBytes != 1 || R->RxBytes != 3) {
      Fail (R, 0x760, EFI_DEVICE_ERROR); goto Restore;
    }
    if (!ClockUnchanged (&Clock, R) || !WaitIdle (B, R) ||
        !AckOwned (B, R, FALSE) || !SetReg (R, B + HSI_INT_EN, 0) ||
        !RetainedIdle (B, (UINTN)A->GpioPeric0, &Clock, R)) {
      Fail (R, 0x760, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    UINT32 Ctl = ReadReg (R, B + HSI_CTL);
    if (Ctl != BIT3 && Ctl != (BIT3 | BIT6)) {
      Fail (R, 0x761, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    if (Ctl == (BIT3 | BIT6)) {
      WriteReg (R, B + HSI_CTL, BIT3);
      Ctl = ReadReg (R, B + HSI_CTL);
      /* Preserve the first readback evidence. A later known value must not
       * erase an inaccessible/reset/foreign selector observation. */
      if (Ctl != BIT3 && Ctl != (BIT3 | BIT6)) {
        Fail (R, 0x761, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
      }
    }
    BOOLEAN Normalized = Ctl == BIT3;
    /* A newer active, inaccessible or clock-drifted state cannot authorize
     * restoration of outer pins/rails. Only known-idle selector mismatch may
     * enter the existing bounded cleanup path. */
    if (!RetainedIdle (B, (UINTN)A->GpioPeric0, &Clock, R)) {
      Fail (R, 0x761, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    Ctl = ReadReg (R, B + HSI_CTL);
    if (!Normalized || Ctl != BIT3) {
      Fail (R, 0x761, EFI_DEVICE_ERROR);
      if (Ctl != BIT3 && Ctl != (BIT3 | BIT6)) { Safe = FALSE; goto Done; }
      goto Restore;
    }
    ZeroMem (Lease, sizeof (*Lease));
    Lease->Magic = N976N_TOUCH_HANDOFF_MAGIC;
    Lease->Version = N976N_TOUCH_HANDOFF_VERSION;
    Lease->Bytes = sizeof (*Lease);
    Lease->ImmutableBytes = OFFSET_OF (N976N_TOUCH_HANDOFF, ClaimState);
    Lease->Profile = 0; Lease->ProducerStage = N976N_TOUCH_HANDOFF_PREPARED;
    Lease->BootCounter = TouchCounter (); Lease->CounterHz = R->CounterHz;
    Lease->InputHz = R->InputHz; Lease->ChipId = (UINT32)R->Id;
    Lease->BusHz = 100000;
    Lease->TimingFs[0] = (UINT32)R->TimingFs1;
    Lease->TimingFs[1] = (UINT32)R->TimingFs2;
    Lease->TimingFs[2] = (UINT32)R->TimingFs3;
    for (UINTN I=0; I<TouchCmuCount; I++)
      Lease->Cmu[I] = ReadReg (R, (UINTN)A->CmuPeric0 + mCmuOffsets[I]);
    Lease->UsiMode = ReadReg (R, (UINTN)A->SysregUsi);
    Lease->UsiControl = ReadReg (R, B + HSI_USI_CON);
    Lease->UsiOption = ReadReg (R, B + HSI_USI_OPTION);
    Lease->GppCon = ReadReg (R, (UINTN)A->GpioPeric0 + 0x20);
    Lease->GppPull = ReadReg (R, (UINTN)A->GpioPeric0 + 0x28);
    Lease->GppDrive = ReadReg (R, (UINTN)A->GpioPeric0 + 0x2C);
    Lease->Gpa1Con = ReadReg (R, (UINTN)A->GpioAlive + 0x20);
    Lease->Gpa1Pull = ReadReg (R, (UINTN)A->GpioAlive + 0x28);
    Lease->Gpa1EintMask = ReadReg (R, (UINTN)A->GpioAlive + 0x904);
    Lease->HsiConf = ReadReg (R, B + HSI_CONF);
    Lease->HsiTimeout = ReadReg (R, B + HSI_TIMEOUT);
    Lease->HsiTrailing = ReadReg (R, B + HSI_TRAILING);
    Lease->HsiCtl = ReadReg (R, B + HSI_CTL);
    Lease->HsiFifo = ReadReg (R, B + HSI_FIFO_CTL);
    Lease->HsiAuto = ReadReg (R, B + HSI_AUTO);
    Lease->HsiAddr = ReadReg (R, B + HSI_ADDR);
    Lease->ClockCount = (UINT32)Clock.Count;
    for (UINTN I=0; I<Clock.Count; I++) {
      Lease->ClockOffsets[I] = (UINT32)(Clock.Address[I] - 0x1A240000U);
      Lease->ClockValues[I] = Clock.Value[I];
    }
    /* Snapshot the actual readback, then reject late drift before publication.
     * Never manufacture the contract value in the immutable producer record. */
    if (Lease->HsiCtl != BIT3 || !RetainedIdle (B, (UINTN)A->GpioPeric0, &Clock, R) ||
        ReadReg (R, B + HSI_CTL) != Lease->HsiCtl) {
      ZeroMem (Lease, sizeof (*Lease));
      Fail (R, 0x761, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    UINT32 GpaCon = ReadReg (R, (UINTN)A->GpioAlive + 0x20);
    UINT32 GpaPull = ReadReg (R, (UINTN)A->GpioAlive + 0x28);
    UINT32 GpaMask = ReadReg (R, (UINTN)A->GpioAlive + 0x904);
    if (Lease->Gpa1Pull == MAX_UINT32 ||
        Lease->Gpa1EintMask == MAX_UINT32 ||
        GpaPull == MAX_UINT32 || GpaMask == MAX_UINT32 ||
        ((Lease->Gpa1Con ^ R->Alive[TouchAliveCon]) & 15) ||
        ((Lease->Gpa1Pull ^ R->Alive[TouchAlivePull]) & 15) ||
        ((GpaCon ^ Lease->Gpa1Con) & 15) ||
        ((GpaPull ^ Lease->Gpa1Pull) & 15) ||
        ((GpaMask ^ Lease->Gpa1EintMask) & BIT0)) {
      ZeroMem (Lease, sizeof (*Lease));
      Fail (R, 0x762, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    Lease->ProducerChecks = 1; Lease->Guard = N976N_TOUCH_HANDOFF_GUARD;
    R->Phase = 9; R->RestoreChecks = 0;
    R->SkipMask = N976N_TOUCH_CLASS_ALL ^ R->ValidMask;
    return TRUE;
  }
  if (Events && !ObserveEvents (B, &Clock, R)) { Safe = FALSE; goto Done; }
Restore:
  R->Phase = 7;
  /* Never switch outer resources over an active transfer. A single narrowly
   * admitted pre-start FSM6 reset is allowed; unresolved or submitted activity
   * stays quarantined. No GPIO pulses, PMIC changes or touch reset are used. */
  if (HaveHsi) {
    BOOLEAN Idle = WaitIdle (B, R);
    ObserveStage (B, (UINTN)A->GpioPeric0, TOUCH_STAGE_CLEANUP, &R->CleanupState, R);
    /* Do not ignore a newer contradictory controller observation introduced
     * by stage sampling after the successful idle wait. */
    Idle = Idle && Inactive ((UINT32)(R->CleanupState >> 32));
    if (!Idle && !RecoverBeforeStart (B, (UINTN)A->GpioPeric0, Timeout, &Clock,
          HsiChanged, UsiChanged, R)) {
      R->CleanupReason = 0x70E;
      Fail (R, 0x70E, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
    }
    if ((R->CleanupState & 0x30) != 0x30)
      Fail (R, 0x712, EFI_NOT_READY);
  }
  R->RestoreChecks |= TOUCH_RESTORE_IDLE;
  if (HsiChanged) {
    Ok = SetReg (R, B + HSI_INT_EN, 0);
    Ok = AckOwned (B, R, TRUE) && Ok;
    /* Only ordinary writable configuration is restored; FIFO/INT/FSM aren't
     * falsely described as a reversible byte-for-byte peripheral snapshot. */
    CONST UINTN Index[] = { TouchHsiAutoConf, TouchHsiCtl, TouchHsiFifoCtl,
      TouchHsiTrailing, TouchHsiConf, TouchHsiTimingHs1,
      TouchHsiTimingHs2, TouchHsiTimingHs3, TouchHsiTimingFs1,
      TouchHsiTimingFs2, TouchHsiTimingFs3, TouchHsiAddr };
    for (UINTN I = 0; I < sizeof(Index)/sizeof(Index[0]); I++)
      Ok = SetReg (R, B + mHsiOffsets[Index[I]], R->Hsi[Index[I]]) && Ok;
    Ok = SetReg (R, B + HSI_TIMEOUT, Timeout) && Ok;
    Ok = SetReg (R, B + HSI_INT_EN, R->Hsi[TouchHsiIntEnable]) && Ok;
    if (ReadReg (R, B + HSI_USI_OPTION) != R->UsiOptionBefore) Ok = FALSE;
    /* These offsets are defined but not written by the reference driver.
     * Do not guess their write/reset semantics: require them unchanged. */
    for (UINTN I = 0; I < 3; I++)
      if (ReadReg (R, B + ObserveOffsets[I]) != ObserveOnly[I]) Ok = FALSE;
    if (!Ok) { R->CleanupReason = 0x70F; Fail (R, 0x70F, EFI_DEVICE_ERROR); Safe = FALSE; goto Done; }
  }
  R->RestoreChecks |= TOUCH_RESTORE_HSI;
  if ((UsiChanged && !SetReg (R, B + HSI_USI_CON, (UINT32)R->UsiControlBefore)) ||
      (!UsiChanged && HaveHsi &&
       ReadReg (R, B + HSI_USI_CON) != R->UsiControlBefore)) {
    R->CleanupReason = 0x70F; Fail (R, 0x70F, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
  }
  R->RestoreChecks |= TOUCH_RESTORE_USI_CTL;
  Ok = TRUE;
  if (PinsChanged) {
    Ok = SetReg (R, (UINTN)A->GpioPeric0 + 0x20, R->Gpp[TouchGppCon]);
    Ok = SetReg (R, (UINTN)A->GpioPeric0 + 0x28, R->Gpp[TouchGppPull]) && Ok;
    Ok = SetReg (R, (UINTN)A->GpioPeric0 + 0x2C, R->Gpp[TouchGppDrive]) && Ok;
  } else if (PullChanged) {
    UINT32 Live = ReadReg (R, (UINTN)A->GpioPeric0 + 0x28);
    Ok = SetReg (R, (UINTN)A->GpioPeric0 + 0x28,
      (Live & ~0x00FF0000U) | (R->Gpp[TouchGppPull] & 0x00FF0000U));
  }
  /* An early refusal must not rewrite CON/DRV which this probe never changed.
   * Contradictory inherited configuration is retained and quarantined. */
  Ok = (ReadReg (R, (UINTN)A->GpioPeric0 + 0x20) == R->Gpp[TouchGppCon]) && Ok;
  Ok = (ReadReg (R, (UINTN)A->GpioPeric0 + 0x28) == R->Gpp[TouchGppPull]) && Ok;
  Ok = (ReadReg (R, (UINTN)A->GpioPeric0 + 0x2C) == R->Gpp[TouchGppDrive]) && Ok;
  if (!Ok) {
    R->CleanupReason = 0x70F; Fail (R, 0x70F, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
  }
  R->RestoreChecks |= TOUCH_RESTORE_PINS;
  if (!SetReg (R, (UINTN)A->SysregUsi, R->UsiMode)) {
    R->CleanupReason = 0x70F; Fail (R, 0x70F, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
  }
  R->RestoreChecks |= TOUCH_RESTORE_USI_MODE;
  if (!SetReg (R, (UINTN)A->CmuPeric0 + 0x3038, R->Cmu[TouchCmuI2cQch])) {
    R->CleanupReason = 0x70F; Fail (R, 0x70F, EFI_DEVICE_ERROR); Safe = FALSE; goto Done;
  }
  R->RestoreChecks |= TOUCH_RESTORE_QCH;
  if (!ClockUnchanged (&Clock, R)) Fail (R, 0x708, EFI_UNSUPPORTED);
Done:
  if (!Safe) { R->Quarantined = 1; R->Checks &= ~0x80ULL; }
  if (!R->Reason && (R->PrepChecks != TOUCH_PREP_ALL ||
      R->RestoreChecks != TOUCH_RESTORE_ALL || !OuterChanged))
    Fail (R, 0x711, EFI_DEVICE_ERROR);
  R->SkipMask = N976N_TOUCH_CLASS_ALL ^ R->ValidMask;
  R->Phase = 8;
  return TRUE;
}

/* Retained diagnostic entry remains available for bounded restoration checks. */
STATIC BOOLEAN SnapshotState (
  CONST N976N_TOUCH_ADMISSION *A, UINT64 El, UINT64 Sctlr, UINT64 Daif,
  UINT64 CounterHz, N976N_TOUCH_SNAPSHOT *R, BOOLEAN Events)
{ return SnapshotStateEx(A,El,Sctlr,Daif,CounterHz,R,Events,NULL); }

/* AArch64 entry wrapper: never called later by BDS/Windows. */
STATIC UINT64 TouchCounter (VOID)
{
  UINT64 Value;
  __asm__ volatile ("isb; mrs %0, cntpct_el0" : "=r" (Value));
  return Value;
}
BOOLEAN EFIAPI N976nSnapshotTouch (
  CONST N976N_TOUCH_ADMISSION *Admission, N976N_TOUCH_SNAPSHOT *Snapshot)
{
  UINT64 El, Sctlr, Daif, CounterHz;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, daif" : "=r" (Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (CounterHz));
  return SnapshotState (Admission, El, Sctlr, Daif, CounterHz, Snapshot, FALSE);
}

BOOLEAN EFIAPI N976nObserveTouchEvents (
  CONST N976N_TOUCH_ADMISSION *Admission, N976N_TOUCH_SNAPSHOT *Snapshot)
{
  UINT64 El, Sctlr, Daif, CounterHz;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, daif" : "=r" (Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (CounterHz));
  return SnapshotState (Admission, El, Sctlr, Daif, CounterHz, Snapshot, TRUE);
}

/* SEC76: only the SEC owner may retain a prepared controller for OS handoff. */
BOOLEAN EFIAPI N976nPrepareTouchWindows (
  CONST N976N_TOUCH_ADMISSION *Admission, N976N_TOUCH_SNAPSHOT *Snapshot,
  N976N_TOUCH_HANDOFF *Lease)
{
  UINT64 El, Sctlr, Daif, CounterHz;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, daif" : "=r" (Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0" : "=r" (CounterHz));
  if (!Lease || ((UINTN)Lease & 7) ||
      (UINTN)Lease > MAX_UINTN-sizeof(*Lease) ||
      ((UINTN)Lease < (UINTN)Snapshot+sizeof(*Snapshot) &&
       (UINTN)Snapshot < (UINTN)Lease+sizeof(*Lease)) ||
      ((UINTN)Lease < (UINTN)Admission+sizeof(*Admission) &&
       (UINTN)Admission < (UINTN)Lease+sizeof(*Lease))) return FALSE;
  return SnapshotStateEx (Admission, El, Sctlr, Daif, CounterHz, Snapshot, FALSE, Lease);
}
