/* SPDX-License-Identifier: MIT
 * SEC85 FIX1: saved-state diagnostics only. No MMIO, IPC, or policy changes.
 * Bits follow the unchanged 4376 Need expression in PhoneSec.c. FIRST FAIL is
 * the first false predicate in that order, NOT the first chronological cause.
 */
STATIC UINT64 TouchLeaseFailureMask (VOID)
{
  UINT64 Mask = 0;
  if (mTouchLease.ProducerChecks != 1) Mask |= BIT0;
  if (mAcpmSnapshot.PowerMode != 2) Mask |= BIT1;
  if (mAcpmSnapshot.Status != 0) Mask |= BIT2;
  if (mAcpmSnapshot.PowerStatus != 0) Mask |= BIT3;
  if (mAcpmSnapshot.PowerChecks != 0xBF) Mask |= BIT4;
  if (mAcpmSnapshot.Quarantined) Mask |= BIT5;
  if (mAcpmSnapshot.RetireCheck != ACPM_RETIRE_ALL) Mask |= BIT6;
  if (mAcpmSnapshot.RequestCount != mAcpmSnapshot.ResponseCount) Mask |= BIT7;
  if (mAcpmSnapshot.PowerCallbackRetired != 1) Mask |= BIT8;
  if (mPowerAdmission.Admitted != 1) Mask |= BIT9;
  if (mAcpiAdmission.Admitted != 1) Mask |= BIT10;
  if (mAcpiAdmission.GicBase[0] != 0x10101000) Mask |= BIT11;
  return Mask;
}

STATIC VOID ReportTouchLeaseFailure (UINT64 Mask)
{
  UINT64 First = 0;
  if (!Mask) return;
  for (UINTN Bit = 0; Bit < 12; Bit++) {
    if (Mask & (1ULL << Bit)) { First = Bit + 1; break; }
  }
  /* IDs33..63 accumulate without paint; ID64 publishes one complete page.
   * Original status Event2 follows, leaving this failure page latched.
   * All fields retain their full width. Zero alone is not evidence of a read:
   * LDO VALID marks the original read, PWR VALID enabled/restored readbacks.
   * Callback and phase/check fields distinguish an unattempted touch probe.
   */
  Event (33, 0x76);
  Event (34, 0x4376);
  Event (35, Mask);
  Event (36, First);
  Event (37, mAcpmSnapshot.Status);
  Event (38, mAcpmSnapshot.Reason);
  Event (39, mAcpmSnapshot.Phase);
  Event (40, mAcpmSnapshot.PowerStatus);
  Event (41, mAcpmSnapshot.PowerReason);
  Event (42, mAcpmSnapshot.PowerPhase);
  Event (43, mAcpmSnapshot.PowerChecks);
  Event (44, mAcpmSnapshot.LdoValues);
  Event (45, mAcpmSnapshot.PowerEnabled);
  Event (46, mAcpmSnapshot.PowerValid);
  Event (47, mAcpmSnapshot.ValidValues);
  Event (48, mAcpmSnapshot.PowerChanged);
  Event (49, mAcpmSnapshot.RequestCount);
  Event (50, mAcpmSnapshot.ResponseCount);
  Event (51, mAcpmSnapshot.RetireCheck);
  Event (52, mAcpmSnapshot.Quarantined);
  Event (53, mAcpmSnapshot.PowerCallbackCount);
  Event (54, mAcpmSnapshot.PowerCallbackRetired);
  Event (55, mTouchBeforeSnapshot.Status);
  Event (56, mTouchBeforeSnapshot.Reason);
  Event (57, mTouchBeforeSnapshot.Checks);
  Event (58, mTouchBeforeSnapshot.RestoreChecks);
  Event (59, mTouchSnapshot.Status);
  Event (60, mTouchSnapshot.Reason);
  Event (61, mTouchSnapshot.Phase);
  Event (62, mTouchSnapshot.PrepChecks);
  Event (63, mTouchSnapshot.RestoreChecks);
  Event (64, mTouchLease.ProducerChecks);
}
