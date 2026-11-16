/* SPDX-License-Identifier: MIT
 * Validate a frozen SEC attempt, not peripheral readiness. BDS never issues
 * MMIO or converts a failed/restored transaction into working Windows input.
 */
#include <N976nTouchReport.h>

STATIC BOOLEAN ExtensionZero (CONST N976N_TOUCH_SNAPSHOT *R)
{
  return (R->WriteCount | R->PrepChecks | R->RestoreChecks | R->Quarantined |
    R->InputHz | R->CounterHz | R->WaitTicks | R->TransactionCount |
    R->TxBytes | R->RxBytes | R->Id | R->TransferStatus | R->InterruptStatus |
    R->FifoStatus | R->UsiControlBefore | R->UsiOptionBefore |
    R->TimingFs1 | R->TimingFs2 | R->TimingFs3 | R->FailureStage |
    R->StageMask | R->PinsState | R->ReleasedState | R->ResetState |
    R->ConfiguredState | R->CleanupState | R->CleanupReason |
    R->InputCheck | R->InputState | R->GppConPdn | R->GppPullPdn |
    R->SetupFailureStep | R->SetupFailureOffset | R->SetupFailureExpected |
    R->SetupFailureObserved | R->SetupFailureMask | R->SetupFailurePhase |
    R->SetupFailureTransactionCount | R->SetupObservedMask |
    R->SetupMismatchMask) == 0;
}

/* EXP1 records all ten possible immediate readbacks. Equality is diagnostic
 * only for these five setup writes; the report still requires exact evidence,
 * progress and first-mismatch provenance. A successful transfer does not prove
 * why a programmed bit read back differently. No report value grants MMIO. */
STATIC BOOLEAN SetupObservationValid (CONST N976N_TOUCH_SNAPSHOT *R)
{
  CONST UINT32 Offsets[] = { 0x04, 0x00, 0x70, 0x20, 0x44 };
  CONST UINT32 Expected[10] = {
    0x10013, 0x88, 0x07012000, 0x80, 0x20001,
    0x30033, 0x48, 0x07012000, 0x80, 0x30003
  };
  UINT64 Mask = R->TransactionCount == 2 ? 0x3FF :
    R->TransactionCount == 1 ? 0x1F : 0;
  UINT64 Mismatches = 0;
  UINTN First = ARRAY_SIZE (Expected);
  if (R->SetupObservedMask != Mask ||
      (R->Reason == 0x70A && (R->FailureStage == 5 || R->FailureStage == 6)))
    return FALSE;
  for (UINTN I = 0; I < ARRAY_SIZE (Expected); I++) {
    if (!(Mask & (1ULL << I))) {
      if (R->SetupObserved[I]) return FALSE;
    } else if (R->SetupObserved[I] != Expected[I]) {
      Mismatches |= 1ULL << I;
      if (First == ARRAY_SIZE (Expected)) First = I;
    }
  }
  if (R->SetupMismatchMask != Mismatches) return FALSE;
  if (Mask && ((R->PrepChecks & 0x7F) != 0x7F ||
      !(R->StageMask & TOUCH_STAGE_CONFIGURED) ||
      R->ValidMask != N976N_TOUCH_CLASS_ALL || !R->WriteCount)) return FALSE;
  if (!Mismatches)
    return R->SetupFailureStep == 0 &&
      (R->SetupFailureOffset | R->SetupFailureExpected |
       R->SetupFailureObserved | R->SetupFailureMask | R->SetupFailurePhase |
       R->SetupFailureTransactionCount) == 0;
  return R->SetupFailureStep == First % 5 + 1 &&
    R->SetupFailureOffset == Offsets[First % 5] &&
    R->SetupFailureExpected == Expected[First] &&
    R->SetupFailureObserved == R->SetupObserved[First] &&
    R->SetupFailureMask == MAX_UINT32 &&
    R->SetupFailurePhase == 5 + First / 5 &&
    R->SetupFailureTransactionCount == First / 5;
}

/* Frozen sequential observations; only the FIFO/INT/TRANS operands used by
 * the RX poll are related here. AUTO was read separately, never atomically.
 * The diagnostic record grants no additional access or retirement permission. */
STATIC BOOLEAN RxRecordValid (CONST N976N_TOUCH_RX_OBSERVATION *O)
{
  UINT64 Level = (O->Fifo >> 16) & 0x7F;
  if (!O->Kind)
    return (O->Phase | O->TransactionCount | O->Before | O->Remaining |
      O->Fifo | O->Interrupt | O->Transfer | O->Auto | O->DataValid |
      O->Data32 | O->Payload) == 0;
  if (O->Kind > TOUCH_RX_ID || O->Phase != 6 || O->TransactionCount != 2 ||
      O->Before > 3 || O->Remaining != 3 - O->Before ||
      O->Fifo > MAX_UINT32 || O->Interrupt > MAX_UINT32 ||
      O->Transfer > MAX_UINT32 || O->Auto > MAX_UINT32) return FALSE;
  if (O->Kind == TOUCH_RX_DATA_HIGH) {
    if (O->DataValid != 1 || O->Data32 <= 255 || O->Data32 > MAX_UINT32 ||
        O->Payload != (O->Data32 & 255)) return FALSE;
  } else if (O->DataValid || O->Data32 || O->Payload) return FALSE;
  if (O->Kind <= TOUCH_RX_EXCESS) {
    if (O->Fifo == MAX_UINT32 || O->Transfer == MAX_UINT32 ||
        (O->Interrupt & (0xFFFFF000ULL | 0xF3CULL)) ||
        (O->Fifo & BIT24)) return FALSE;
    if (O->Kind == TOUCH_RX_EXCESS)
      return O->Before == 3 || (O->Fifo & BIT23) != 0;
    if (O->Before >= 3 || (O->Fifo & BIT23)) return FALSE;
    if (O->Kind == TOUCH_RX_LEVEL_ZERO) return Level == 0;
    if (O->Kind == TOUCH_RX_LEVEL_EXCESS) return Level > O->Remaining;
    /* An earlier level anomaly would already own RxFirst. */
    return Level > 0 && Level <= O->Remaining;
  }
  if (O->Kind == TOUCH_RX_CONTROLLER)
    return O->Fifo == MAX_UINT32 || O->Transfer == MAX_UINT32 ||
      (O->Interrupt & (0xFFFFF000ULL | 0xF3CULL)) != 0;
  if (O->Kind == TOUCH_RX_IDLE || O->Kind == TOUCH_RX_ACK || O->Kind == TOUCH_RX_ID)
    return O->Before == 3;
  return TRUE; /* A bounded timeout can retain zero through three bytes. */
}

STATIC BOOLEAN RxRecordsEqual (
  CONST N976N_TOUCH_RX_OBSERVATION *A, CONST N976N_TOUCH_RX_OBSERVATION *B)
{
  return A->Kind == B->Kind && A->Phase == B->Phase &&
    A->TransactionCount == B->TransactionCount && A->Before == B->Before &&
    A->Remaining == B->Remaining && A->Fifo == B->Fifo &&
    A->Interrupt == B->Interrupt && A->Transfer == B->Transfer && A->Auto == B->Auto &&
    A->DataValid == B->DataValid && A->Data32 == B->Data32 && A->Payload == B->Payload;
}

STATIC BOOLEAN RxObservationsValid (CONST N976N_TOUCH_SNAPSHOT *R)
{
  CONST N976N_TOUCH_RX_OBSERVATION *A = &R->RxFirst, *F = &R->RxFailure;
  if (!RxRecordValid (A) || !RxRecordValid (F)) return FALSE;
  if ((A->Kind || F->Kind) &&
      (R->TransactionCount != 2 || R->TxBytes != 1 ||
       (R->PrepChecks & 0x7F) != 0x7F ||
       !(R->StageMask & TOUCH_STAGE_CONFIGURED) ||
       R->ValidMask != N976N_TOUCH_CLASS_ALL || !R->WriteCount)) return FALSE;
  if (A->Kind && (A->Before > R->RxBytes ||
      (A->Kind <= TOUCH_RX_DATA_HIGH && A->Before >= R->RxBytes))) return FALSE;
  if (A->Kind >= TOUCH_RX_EXCESS && !RxRecordsEqual (A, F)) return FALSE;
  if (!F->Kind)
    return R->Event.Mode || !(R->FailureStage == 6 &&
      (R->Reason == 0x70B || R->Reason == 0x70C ||
       R->Reason == 0x70D || R->Reason == 0x70E));
  if (!A->Kind || F->Kind < TOUCH_RX_EXCESS ||
      F->Before != R->RxBytes || R->FailureStage != 6 ||
      R->PrepChecks != 0x7F || R->Status !=
        (F->Kind == TOUCH_RX_TIMEOUT ? EFI_TIMEOUT : EFI_DEVICE_ERROR)) return FALSE;
  UINT64 Reason = F->Kind == TOUCH_RX_EXCESS || F->Kind == TOUCH_RX_ID ? 0x70D :
    F->Kind == TOUCH_RX_CONTROLLER || F->Kind == TOUCH_RX_ACK ? 0x70C :
    F->Kind == TOUCH_RX_IDLE ? 0x70E : 0x70B;
  if (R->Reason != Reason) return FALSE;
  return F->Kind != TOUCH_RX_ID || R->Id == 0 || R->Id == 0xFFFFFF;
}

STATIC BOOLEAN BytesZero (CONST VOID *Data, UINTN Bytes)
{
  CONST UINT8 *P = Data;
  for (UINTN I=0; I<Bytes; I++) if (P[I]) return FALSE;
  return TRUE;
}

STATIC BOOLEAN EventCoordinateValid (CONST UINT8 *P, UINT64 X, UINT64 Y, UINT64 Id)
{
  UINT32 Type = ((P[6] >> 6) << 2) | (P[7] >> 6);
  return P[0] != 0 && (P[0] & 3) == 0 && (P[0] >> 6) != 0 &&
    Id >= 1 && Id <= 10 && Id == ((P[0] >> 2) & 15) &&
    X < 4096 && Y < 4096 && X == (((UINT32)P[1] << 4) | (P[3] >> 4)) &&
    Y == (((UINT32)P[2] << 4) | (P[3] & 15)) &&
    (Type == 0 || Type == 3 || Type == 5 || Type == 6);
}

/* Event RX records retain their own phase and transaction. The last command
   may already be cleanup, so it must not replace historic receive operands. */
STATIC BOOLEAN EventRxValid (CONST N976N_TOUCH_RX_OBSERVATION *O, UINT64 Total)
{
  if (!O->Kind) return BytesZero (O, sizeof (*O));
  UINT64 Len = O->Before + O->Remaining;
  UINT64 Level = (O->Fifo >> 16) & 0x7F;
  if (O->Kind > TOUCH_RX_TIMEOUT || O->Phase < 1 || O->Phase > 7 ||
      O->TransactionCount == 0 || O->TransactionCount > Total ||
      O->Before > 16 || O->Remaining > 16 ||
      (Len != 1 && Len != 2 && Len != 16) || O->Before > Len ||
      O->Fifo > MAX_UINT32 || O->Interrupt > MAX_UINT32 ||
      O->Transfer > MAX_UINT32 || O->Auto > MAX_UINT32) return FALSE;
  if (O->Kind == TOUCH_RX_DATA_HIGH) {
    if (O->DataValid != 1 || O->Data32 <= 255 || O->Data32 > MAX_UINT32 ||
        O->Payload != (O->Data32 & 255)) return FALSE;
  } else if (O->DataValid || O->Data32 || O->Payload) return FALSE;
  if (O->Kind <= TOUCH_RX_EXCESS) {
    if (O->Fifo == MAX_UINT32 || O->Transfer == MAX_UINT32 ||
        (O->Interrupt & (0xFFFFF000ULL | 0xF3CULL)) ||
        (O->Fifo & BIT24)) return FALSE;
    if (O->Kind == TOUCH_RX_EXCESS)
      return O->Before == Len || (O->Fifo & BIT23) != 0;
    if (O->Before >= Len || (O->Fifo & BIT23)) return FALSE;
    if (O->Kind == TOUCH_RX_LEVEL_ZERO) return Level == 0;
    if (O->Kind == TOUCH_RX_LEVEL_EXCESS) return Level > O->Remaining;
    return Level > 0 && Level <= O->Remaining;
  }
  if (O->Kind == TOUCH_RX_CONTROLLER)
    return O->Fifo == MAX_UINT32 || O->Transfer == MAX_UINT32 ||
      (O->Interrupt & (0xFFFFF000ULL | 0xF3CULL)) != 0;
  if (O->Kind == TOUCH_RX_IDLE || O->Kind == TOUCH_RX_ACK) return O->Before == Len;
  return TRUE;
}

STATIC BOOLEAN EventReportValid (CONST N976N_TOUCH_SNAPSHOT *R)
{
  CONST N976N_TOUCH_EVENT_OBSERVATION *E = &R->Event;
  if (!E->Mode) return BytesZero (E, sizeof (*E));
  if (E->Mode != 1 || R->Profile != N976N_PLATFORM_PROFILE_PHONE ||
      E->Phase != 8 || (E->Checks & ~TOUCH_EVENT_ALL) || E->Outcome > 2 ||
      R->PrepChecks != TOUCH_PREP_ALL || R->TransactionCount != 2 ||
      R->TxBytes != 1 || R->RxBytes != 3 || !R->Id || R->Id == 0xFFFFFF ||
      R->RxFailure.Kind || E->Transactions > TOUCH_EVENT_MAX_TRANSACTIONS ||
      E->TxBytes > 3 * E->Transactions || E->RxBytes > 16 * E->Transactions ||
      E->Direction > 1 || E->Length > 16 || E->Done > E->Length ||
      E->BootReady > 1 || E->BootStatus > 255 || E->SenseOn > 1 || E->SenseOff > 1 ||
      E->FunctionBefore > 0xFFFF || E->FunctionEnabled > 0xFFFF ||
      E->FunctionRestored > 0xFFFF || E->Polls > TOUCH_EVENT_POLL_LIMIT ||
      E->CoordinateCount > E->Polls || E->EmptyCount > E->Polls ||
      E->StatusCount > E->Polls || E->OtherCount > E->Polls ||
      E->PressCount > E->CoordinateCount || E->MoveCount > E->CoordinateCount ||
      E->ReleaseCount > E->CoordinateCount || E->ActiveMask > 0x3FF ||
      E->LastAction > 3 || E->LastType > 15 || E->Remaining > 31 ||
      E->WindowTicks != R->CounterHz * TOUCH_EVENT_WINDOW_SECONDS ||
      E->ElapsedTicks > R->CounterHz * (TOUCH_EVENT_WINDOW_SECONDS +
        TOUCH_EVENT_MAX_TRANSACTIONS + 2) ||
      E->SetupSeen != 5 * E->Transactions || E->SetupMismatch > E->SetupSeen ||
      E->SetupExpected > MAX_UINT32 || E->SetupActual > MAX_UINT32 ||
      !EventRxValid (&E->RxFirst, E->Transactions) ||
      !EventRxValid (&E->RxFailure, E->Transactions)) return FALSE;
  if ((E->Transactions && (E->Length == 0 ||
      (E->Command != 0x60 && E->Command != 0x55 && E->Command != 0x30 &&
       E->Command != 0x10 && E->Command != 0x11))) ||
      (!E->Transactions && (E->TxBytes || E->RxBytes || E->Length || E->Done || E->Direction)))
    return FALSE;
  if (E->SetupMismatch) {
    if (E->SetupExpected == E->SetupActual ||
        (E->SetupOffset != 0 && E->SetupOffset != 4 && E->SetupOffset != 0x70 &&
         E->SetupOffset != 0x20 && E->SetupOffset != 0x44)) return FALSE;
  } else if (E->SetupOffset || E->SetupExpected || E->SetupActual) return FALSE;
  if (E->RxFirst.Kind >= TOUCH_RX_EXCESS &&
      !RxRecordsEqual (&E->RxFirst, &E->RxFailure)) return FALSE;
  if (E->RxFailure.Kind && (!E->RxFirst.Kind || E->RxFailure.Kind < TOUCH_RX_EXCESS ||
      E->RxFirst.TransactionCount > E->RxFailure.TransactionCount ||
      !E->Reason || !EFI_ERROR (E->Status))) return FALSE;
  if ((!!E->BootReady != !!(E->Checks & TOUCH_EVENT_BOOT_READY)) ||
      (!!E->SenseOn != !!(E->Checks & TOUCH_EVENT_SENSE_ON)) ||
      (!!E->SenseOff != !!(E->Checks & TOUCH_EVENT_SENSE_OFF))) return FALSE;
  if ((E->Checks & TOUCH_EVENT_APP) &&
      (!(E->Checks & TOUCH_EVENT_BOOT_READY) || E->BootStatus != 0x20)) return FALSE;
  if (!(E->Checks & TOUCH_EVENT_BOOT_READY) && E->BootStatus) return FALSE;
  if ((E->Checks & TOUCH_EVENT_FUNCTION_READ) && !(E->Checks & TOUCH_EVENT_APP)) return FALSE;
  if (!(E->Checks & TOUCH_EVENT_FUNCTION_READ) &&
      (E->FunctionBefore || E->FunctionEnabled || E->FunctionRestored)) return FALSE;
  if (E->FunctionEnabled && E->FunctionEnabled != (E->FunctionBefore | 0x61)) return FALSE;
  if ((E->Checks & TOUCH_EVENT_FUNCTION_SET) &&
      (!(E->Checks & TOUCH_EVENT_FUNCTION_READ) || E->FunctionBefore == 0xFFFF ||
       E->FunctionEnabled != (E->FunctionBefore | 0x61))) return FALSE;
  if (E->SenseOn && !(E->Checks & TOUCH_EVENT_FUNCTION_SET)) return FALSE;
  if ((E->Checks & TOUCH_EVENT_FUNCTION_RESTORE) &&
      (!(E->Checks & TOUCH_EVENT_FUNCTION_READ) || E->FunctionRestored != E->FunctionBefore))
    return FALSE;
  UINT64 Classified = E->CoordinateCount + E->EmptyCount + E->StatusCount + E->OtherCount;
  if (Classified > E->Polls || E->Polls - Classified > 1 ||
      E->CoordinateCount != E->PressCount + E->MoveCount + E->ReleaseCount) return FALSE;
  if (!E->CoordinateCount) {
    if (E->FirstX || E->FirstY || E->FirstId || E->LastX || E->LastY || E->LastId ||
        E->LastAction || E->LastType || E->Remaining || E->ActiveMask ||
        !BytesZero (E->FirstRaw,16) || !BytesZero (E->LastRaw,16)) return FALSE;
  } else {
    if (!E->SenseOn || !EventCoordinateValid (E->FirstRaw,E->FirstX,E->FirstY,E->FirstId) ||
        !EventCoordinateValid (E->LastRaw,E->LastX,E->LastY,E->LastId) ||
        E->LastAction != (E->LastRaw[0] >> 6) ||
        E->LastType != (UINT64)(((E->LastRaw[6] >> 6) << 2) | (E->LastRaw[7] >> 6)) ||
        E->Remaining != (E->LastRaw[7] & 31)) return FALSE;
    UINT64 LastBit = 1ULL << (E->LastId - 1);
    if ((E->LastAction == 3) == ((E->ActiveMask & LastBit) != 0)) return FALSE;
    if (E->CoordinateCount == 1)
      for (UINTN I=0; I<16; I++) if (E->FirstRaw[I] != E->LastRaw[I]) return FALSE;
  }
  if ((E->Polls || E->ElapsedTicks) && !E->SenseOn) return FALSE;
  if (E->Checks & TOUCH_EVENT_WINDOW) {
    if (!E->SenseOn || !E->Polls ||
        (E->Stop != 1 && E->Stop != 2) ||
        (E->Stop == 1 && E->ElapsedTicks < E->WindowTicks) ||
        (E->Stop == 2 && E->Polls != TOUCH_EVENT_POLL_LIMIT)) return FALSE;
  } else if (E->Stop) return FALSE;
  BOOLEAN Rejected = !BytesZero (E->RejectRaw,16);
  if (Rejected != (E->Reason == 0x744 || E->Reason == 0x749 || E->Reason == 0x74A) ||
      (Rejected && (!E->RejectRaw[0] || E->Polls - Classified != 1))) return FALSE;
  if (E->CleanupReason && E->CleanupReason != 0x747 && E->CleanupReason != 0x748) return FALSE;
  if (E->CleanupReason && (!R->Quarantined || !E->Reason)) return FALSE;
  if (E->Reason) {
    if (!EFI_ERROR (E->Status) || E->Outcome || R->Reason != E->Reason ||
        R->Status != E->Status || R->FailureStage != 6) return FALSE;
    return E->Reason == 0x708 || (E->Reason >= 0x70B && E->Reason <= 0x70E) ||
      (E->Reason >= 0x740 && E->Reason <= 0x74B && E->Reason != 0x745);
  }
  return E->Status == EFI_SUCCESS && E->Checks == TOUCH_EVENT_ALL &&
    E->CleanupReason == 0 && E->Outcome == (E->CoordinateCount ? 2 : 1) &&
    E->SenseOn == 1 && E->SenseOff == 1 && E->FunctionRestored == E->FunctionBefore;
}

STATIC BOOLEAN RawStageValid (CONST N976N_TOUCH_SNAPSHOT *R)
{
  CONST UINT64 States[] = { R->PinsState, R->ReleasedState, R->ResetState,
    R->ConfiguredState, R->CleanupState };
  if (R->StageMask & ~0x7FULL) return FALSE;
  for (UINTN I = 0; I < 5; I++)
    if (!(R->StageMask & (1ULL << I)) && States[I] != 0) return FALSE;
  if (R->StageMask &&
      (!(R->ValidMask & N976N_TOUCH_CLASS_HSI) || !R->WriteCount)) return FALSE;
  if ((R->StageMask & TOUCH_STAGE_RELEASED) && !(R->StageMask & TOUCH_STAGE_PINS))
    return FALSE;
  if ((R->StageMask & TOUCH_STAGE_RESET) && !(R->StageMask & TOUCH_STAGE_RELEASED))
    return FALSE;
  if ((R->StageMask & TOUCH_STAGE_CONFIGURED) && !(R->StageMask & TOUCH_STAGE_RESET))
    return FALSE;
  if ((R->StageMask & TOUCH_STAGE_RECOVERY) &&
      (R->TransactionCount || R->TxBytes || R->RxBytes ||
       (R->PrepChecks & (TOUCH_PREP_IDLE | TOUCH_PREP_PINS)) !=
         (TOUCH_PREP_IDLE | TOUCH_PREP_PINS) ||
       !(R->StageMask & TOUCH_STAGE_RELEASED))) return FALSE;
  if ((R->StageMask & TOUCH_STAGE_RECOVERED) &&
      ((R->StageMask & (TOUCH_STAGE_RECOVERY | TOUCH_STAGE_CLEANUP)) !=
         (TOUCH_STAGE_RECOVERY | TOUCH_STAGE_CLEANUP) ||
       !(R->RestoreChecks & TOUCH_RESTORE_IDLE))) return FALSE;
  return R->CleanupReason == 0 || R->CleanupReason == 0x70E ||
    R->CleanupReason == 0x70F;
}

STATIC BOOLEAN ReadyState (UINT64 State)
{
  UINT32 Trans = (UINT32)(State >> 32);
  return Trans != MAX_UINT32 && !(Trans & (BIT17 | BIT16)) &&
    (Trans & 15) <= 1 && (State & 0x30) == 0x30;
}

STATIC BOOLEAN FailureReason (UINT64 Reason)
{
  return (Reason >= 0x702 && Reason <= 0x706) ||
    (Reason >= 0x708 && Reason <= 0x70F) ||
    (Reason >= 0x711 && Reason <= 0x714) ||
    (Reason >= 0x740 && Reason <= 0x74B && Reason != 0x745);
}

/* GPIO input observations precede pin mux/controller activation. A low
 * neutral input is a readiness refusal, not proof of an unpowered rail.
 * PDN fields are captured configuration, not proof of active retention. */
STATIC BOOLEAN InputObservationValid (CONST N976N_TOUCH_SNAPSHOT *R)
{
  UINT64 C = R->InputCheck;
  UINT32 Pins = R->Gpp[TouchGppCon] & 0x00FF0000U;
  UINT32 Trans = (UINT32)(R->InputState >> 32);
  if ((C & ~0x1FULL) || R->GppConPdn > MAX_UINT32 ||
      R->GppPullPdn > MAX_UINT32) return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_GPIO) &&
      (C || R->InputState || R->GppConPdn || R->GppPullPdn)) return FALSE;
  if (!(C & BIT4) && R->InputState) return FALSE;
  if (C && (R->ValidMask != N976N_TOUCH_CLASS_ALL ||
      !(R->PrepChecks & TOUCH_PREP_IDLE) || !R->WriteCount)) return FALSE;
  if (C & BIT3) {
    if (C != BIT3 || Pins != 0x00220000U) return FALSE;
  } else if (C) {
    if (Pins || R->UsiControlBefore != 1) return FALSE;
    if ((C & BIT2) && !(R->Gpp[TouchGppPull] & 0x00FF0000U))
      return FALSE;
    if ((C & BIT1) && !(C & BIT0)) return FALSE;
    if (C & BIT0) {
      if (!(C & BIT4) ||
          ((R->Gpp[TouchGppPull] & 0x00FF0000U) && !(C & BIT2)) ||
          Trans == MAX_UINT32 ||
          (Trans & (BIT17 | BIT16)) || (Trans & 15) > 1 ||
          (!!(C & BIT1) != ((R->InputState & 0x30) == 0x30)))
        return FALSE;
    }
  }
  if ((R->StageMask & TOUCH_STAGE_PINS) &&
      C != BIT3 && (C & (BIT0 | BIT1 | BIT4)) != (BIT0 | BIT1 | BIT4))
    return FALSE;
  if (R->Reason == 0x713 &&
      (R->Status != EFI_NOT_READY || R->FailureStage != 3 ||
       !(C & BIT0) || (C & BIT1) || R->TransactionCount ||
       R->TxBytes || R->RxBytes || R->Id ||
       (R->PrepChecks & (TOUCH_PREP_PINS | TOUCH_PREP_CONFIG | TOUCH_PREP_ID)) ||
       (R->StageMask & ~TOUCH_STAGE_CLEANUP)))
    return FALSE;
  return TRUE;
}

BOOLEAN N976nTouchReportValid (CONST N976N_TOUCH_SNAPSHOT *R, UINT64 Profile)
{
  UINT64 Count = 0;
  if (!R || Profile > 1 || R->Magic != N976N_TOUCH_SNAPSHOT_MAGIC ||
      R->Version != 8 || R->Size != sizeof (*R) || R->Profile != Profile ||
      ((R->ValidMask | R->SkipMask) != N976N_TOUCH_CLASS_ALL) ||
      (R->ValidMask & R->SkipMask) || (R->Checks & ~0xFFULL) ||
      (R->PrepChecks & ~TOUCH_PREP_ALL) ||
      (R->RestoreChecks & ~TOUCH_RESTORE_ALL) ||
      R->Quarantined > 1 ||
      R->ReadCount > 26ULL * TOUCH_POLL_LIMIT + 512ULL +
        R->Event.Transactions * (12ULL * TOUCH_POLL_LIMIT + 32ULL) ||
      R->WriteCount > 128ULL + 12ULL * R->Event.Transactions ||
      R->TransactionCount > 2 || R->TxBytes > 1 || R->RxBytes > 3 ||
      R->Id > 0xFFFFFF || R->TransferStatus > MAX_UINT32 ||
      R->InterruptStatus > MAX_UINT32 || R->FifoStatus > MAX_UINT32 ||
      R->UsiControlBefore > MAX_UINT32 || R->UsiOptionBefore > MAX_UINT32 ||
      R->TimingFs1 > MAX_UINT32 || R->TimingFs2 > MAX_UINT32 ||
      R->TimingFs3 > MAX_UINT32 || !RawStageValid (R) ||
      !InputObservationValid (R) || !SetupObservationValid (R) ||
      !RxObservationsValid (R) || !EventReportValid (R) ||
      (!!(R->CleanupReason || R->Event.CleanupReason) != !!R->Quarantined))
    return FALSE;
  if ((R->StageMask & TOUCH_STAGE_RECOVERED) && !ReadyState (R->CleanupState))
    return FALSE;
  if (R->ValidMask & N976N_TOUCH_CLASS_ALIVE) Count += TouchAliveCount;
  if (R->ValidMask & N976N_TOUCH_CLASS_CMU) Count += TouchCmuCount;
  if (R->ValidMask & N976N_TOUCH_CLASS_GPIO) Count += TouchGppCount + 2;
  if (R->ValidMask & N976N_TOUCH_CLASS_USI) Count++;
  if (R->ValidMask & N976N_TOUCH_CLASS_HSI) Count += TouchHsiCount;
  if (R->ReadCount < Count || (R->Checks & 0x7C) != (R->ValidMask << 2))
    return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_ALIVE))
    for (UINTN I = 0; I < TouchAliveCount; I++) if (R->Alive[I]) return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_CMU))
    for (UINTN I = 0; I < TouchCmuCount; I++) if (R->Cmu[I]) return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_GPIO))
    for (UINTN I = 0; I < TouchGppCount; I++) if (R->Gpp[I]) return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_USI) && R->UsiMode) return FALSE;
  if (!(R->ValidMask & N976N_TOUCH_CLASS_HSI))
    for (UINTN I = 0; I < TouchHsiCount; I++) if (R->Hsi[I]) return FALSE;
  if (R->Phase == 1)
    return R->ValidMask == 0 && R->ReadCount == 0 && ExtensionZero (R) &&
      ((R->Checks == 0 && R->Reason == 0x700 && R->Status == EFI_INVALID_PARAMETER) ||
       (R->Checks == 1 && R->Reason == 0x701 && R->Status == EFI_UNSUPPORTED));
  if (R->Phase != 8 || (R->Checks & 3) != 3 || R->CpuEl != 4 ||
      (R->CpuSctlr & (BIT0 | BIT2 | BIT12)) || (R->CpuDaif & 0x3C0) != 0x3C0)
    return FALSE;
  if (Profile == N976N_PLATFORM_PROFILE_QEMU)
    return R->ValidMask == 0 && R->ReadCount == 0 && R->Checks == 0x83 &&
      R->Status == EFI_UNSUPPORTED && R->Reason == 0x697 && ExtensionZero (R);
  if ((R->ValidMask & 3) != 3 || R->CounterHz != 26000000 ||
      (!!(R->Checks & 0x80) == !!R->Quarantined))
    return FALSE;
  if ((R->ValidMask & N976N_TOUCH_CLASS_HSI) &&
      (R->ValidMask & (N976N_TOUCH_CLASS_GPIO | N976N_TOUCH_CLASS_USI)) !=
        (N976N_TOUCH_CLASS_GPIO | N976N_TOUCH_CLASS_USI))
    return FALSE;
  if ((R->PrepChecks & TOUCH_PREP_CONFIG) &&
      (R->PrepChecks & 0x7F) != 0x7F) return FALSE;
  if ((R->PrepChecks & TOUCH_PREP_ID) && R->PrepChecks != TOUCH_PREP_ALL)
    return FALSE;
  if ((R->PrepChecks & TOUCH_PREP_CLOCK) &&
      (R->InputHz < 1000000 || R->InputHz > 1000000000)) return FALSE;
  if (R->TransactionCount &&
      (!(R->PrepChecks & TOUCH_PREP_CONFIG) ||
       R->ValidMask != N976N_TOUCH_CLASS_ALL || R->WriteCount == 0))
    return FALSE;
  if ((R->TxBytes && R->TransactionCount == 0) ||
      (R->RxBytes && (R->TransactionCount != 2 || R->TxBytes != 1)) ||
      (!R->RxBytes && R->Id)) return FALSE;
  if (R->WriteCount == 0 && (R->RestoreChecks || R->Quarantined))
    return FALSE;
  if (R->WriteCount && !R->Quarantined &&
      R->RestoreChecks != TOUCH_RESTORE_ALL) return FALSE;
  if (R->Status == EFI_SUCCESS)
    return R->Reason == 0 && R->FailureStage == 0 && R->Checks == 0xFF &&
      R->PrepChecks == TOUCH_PREP_ALL && R->RestoreChecks == TOUCH_RESTORE_ALL &&
      !R->Quarantined && R->TransactionCount == 2 &&
      R->TxBytes == 1 && R->RxBytes == 3 && R->Id != 0 && R->Id != 0xFFFFFF &&
      R->StageMask == 0x1F && ReadyState (R->ConfiguredState) &&
      ReadyState (R->CleanupState);
  return EFI_ERROR (R->Status) && FailureReason (R->Reason) &&
    R->FailureStage >= 2 && R->FailureStage <= 7;
}
