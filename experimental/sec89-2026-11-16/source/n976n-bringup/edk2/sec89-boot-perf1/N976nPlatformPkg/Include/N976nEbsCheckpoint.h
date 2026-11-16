/* SPDX-License-Identifier: MIT */
#ifndef N976N_EBS_CHECKPOINT_H_
#define N976N_EBS_CHECKPOINT_H_
#include <Uefi.h>

#define N976N_EBS_PAUSE_NONE             0ULL
#define N976N_EBS_PAUSE_WAITING          1ULL
#define N976N_EBS_PAUSE_DEADLINE         2ULL
#define N976N_EBS_PAUSE_CLOCK_STOPPED    3ULL
#define N976N_EBS_PAUSE_CLOCK_BACKWARD   4ULL
#define N976N_EBS_PAUSE_ITERATIONS       5ULL
#define N976N_EBS_PAUSE_INVALID_CLOCK    6ULL
#define N976N_EBS_PAUSE_ALREADY_HELD     7ULL
#define N976N_EBS_PAUSE_NOT_ALLOWED      8ULL
#define N976N_EBS_INVALID_MARK           1ULL
#define N976N_EBS_INVALID_REENTRY        2ULL
#define N976N_EBS_INVALID_PREPARE        3ULL
#define N976N_EBS_STOPPED_LIMIT          65536ULL
#define N976N_EBS_ITERATION_LIMIT        50000000ULL

/* Seen/HoldSeen: marks1..6 use bit(Mark-1), failure0xE0 uses bit63.
 * Pause fields describe the most recent checkpoint call; they are observation,
 * never permission to continue a failed handoff. Closed becomes permanent at6.
 * Reading this cached report must not issue a device request. */
typedef struct {
  UINT64 Mark, Count, Seen, PauseExit, HoldSeen, Frequency;
  UINT64 Start, Last, Elapsed, Loops, SameClock, Closed;
  UINT64 InvalidCalls, LastInvalid, Mode;
} N976N_EBS_CHECKPOINT_REPORT;
extern volatile N976N_EBS_CHECKPOINT_REPORT mN976nEbsCheckpointReport;

/* Caller has already admitted an upcounter with range0..MAX_UINT64. A zero or
 * >1GHz frequency disables the pause, with INVALID_CLOCK evidence. No services
 * or counter-property queries are made here. Repeat preparation cannot reset
 * the hold or closed latches. */
VOID N976nEbsCheckpointPrepare (UINT64 Frequency);
/* Uses only cached RAM, MemoryFence, GetPerformanceCounter and the pre-admitted
 * direct framebuffer observation callback. The caller owns its lifetime. */
VOID N976nEbsCheckpoint (UINT64 Mark, BOOLEAN Hold);
#endif
