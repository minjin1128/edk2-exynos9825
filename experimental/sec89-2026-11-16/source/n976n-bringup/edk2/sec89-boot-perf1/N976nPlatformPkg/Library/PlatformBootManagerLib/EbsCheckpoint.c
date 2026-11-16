/* SPDX-License-Identifier: MIT
 * SEC78 FIX1: bounded observation only, including the accepted-EBS callback.
 * No Boot Services, GOP, allocation, register access or counter-property query.
 */
#include <Uefi.h>
#include <Library/BaseLib.h>
#include <Library/TimerLib.h>
#include <N976nEbsCheckpoint.h>
#include <N976nSec78DiagnosticMode.h>
#include <N976nWindowsBoot.h>

volatile N976N_EBS_CHECKPOINT_REPORT mN976nEbsCheckpointReport;
STATIC BOOLEAN mPrepared, mBusy, mClosed;

STATIC VOID Invalid (UINT64 Why) {
  if (mN976nEbsCheckpointReport.InvalidCalls != MAX_UINT64) {
    ++mN976nEbsCheckpointReport.InvalidCalls;
  }
  mN976nEbsCheckpointReport.LastInvalid = Why;
}

VOID N976nEbsCheckpointPrepare (UINT64 Frequency) {
  if (mClosed) { return; }
  if (mPrepared || mBusy) { Invalid (N976N_EBS_INVALID_PREPARE); return; }
  mPrepared = TRUE;
  mN976nEbsCheckpointReport.Frequency = Frequency;
  mN976nEbsCheckpointReport.Mode = N976nSec78DiagnosticMode;
  MemoryFence ();
}

STATIC VOID Paint (VOID) {
  MemoryFence ();
  N976nUfsWindowsObserved ();
}

VOID N976nEbsCheckpoint (UINT64 Mark, BOOLEAN Hold) {
  UINT64 Bit, Frequency, Start, Last, Now, Same, Loops, Exit;
  if (mClosed) { return; }
  if (mBusy) { Invalid (N976N_EBS_INVALID_REENTRY); return; }
  if ((Mark < 1 || Mark > 6) && Mark != 0xE0) {
    Invalid (N976N_EBS_INVALID_MARK); return;
  }
  mBusy = TRUE;
  /* A missing Prepare leaves frequency0 (no wait); a late Prepare cannot reset
   * the already observed state. The build identity is still visible. */
  mPrepared = TRUE;
  mN976nEbsCheckpointReport.Mode = N976nSec78DiagnosticMode;
  Bit = Mark == 0xE0 ? (1ULL << 63) : (1ULL << (Mark - 1));
  mN976nEbsCheckpointReport.Mark = Mark;
  if (mN976nEbsCheckpointReport.Count != MAX_UINT64) {
    ++mN976nEbsCheckpointReport.Count;
  }
  mN976nEbsCheckpointReport.Seen |= Bit;
  mN976nEbsCheckpointReport.PauseExit = N976N_EBS_PAUSE_NONE;
  mN976nEbsCheckpointReport.Start = 0;
  mN976nEbsCheckpointReport.Last = 0;
  mN976nEbsCheckpointReport.Elapsed = 0;
  mN976nEbsCheckpointReport.Loops = 0;
  mN976nEbsCheckpointReport.SameClock = 0;
  Frequency = mN976nEbsCheckpointReport.Frequency;
  if (!Hold) {
    /* Plain checkpoint: one paint, no timer read. */
  } else if (Mark != 3 && Mark != 6) {
    mN976nEbsCheckpointReport.PauseExit = N976N_EBS_PAUSE_NOT_ALLOWED;
  } else if (mN976nEbsCheckpointReport.HoldSeen & Bit) {
    mN976nEbsCheckpointReport.PauseExit = N976N_EBS_PAUSE_ALREADY_HELD;
  } else {
    mN976nEbsCheckpointReport.HoldSeen |= Bit;
    if (Frequency == 0 || Frequency > 1000000000ULL) {
      mN976nEbsCheckpointReport.PauseExit = N976N_EBS_PAUSE_INVALID_CLOCK;
    } else {
      Start = GetPerformanceCounter (); Last = Start; Same = 0; Loops = 0;
      mN976nEbsCheckpointReport.Start = Start;
      mN976nEbsCheckpointReport.Last = Start;
      mN976nEbsCheckpointReport.PauseExit = N976N_EBS_PAUSE_WAITING;
      Paint ();
      Exit = N976N_EBS_PAUSE_ITERATIONS;
      while (Loops < N976N_EBS_ITERATION_LIMIT) {
        Now = GetPerformanceCounter (); ++Loops;
        mN976nEbsCheckpointReport.Last = Now;
        if (Now < Last) { Exit = N976N_EBS_PAUSE_CLOCK_BACKWARD; break; }
        Same = Now == Last ? Same + 1 : 0;
        mN976nEbsCheckpointReport.Elapsed = Now - Start;
        if (Now - Start >= Frequency * 2) { Exit = N976N_EBS_PAUSE_DEADLINE; break; }
        if (Same >= N976N_EBS_STOPPED_LIMIT) { Exit = N976N_EBS_PAUSE_CLOCK_STOPPED; break; }
        Last = Now;
      }
      mN976nEbsCheckpointReport.Loops = Loops;
      mN976nEbsCheckpointReport.SameClock = Same;
      mN976nEbsCheckpointReport.PauseExit = Exit;
    }
  }
  /* Set the latch before final paint: a callback, or any subsequent caller,
   * cannot resurrect observation after the accepted-EBS final checkpoint. */
  if (Mark == 6) { mClosed = TRUE; mN976nEbsCheckpointReport.Closed = 1; }
  Paint ();
  mBusy = FALSE;
}
