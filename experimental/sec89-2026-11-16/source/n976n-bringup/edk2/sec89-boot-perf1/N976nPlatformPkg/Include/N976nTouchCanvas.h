/* SPDX-License-Identifier: MIT */
#ifndef N976N_TOUCH_CANVAS_H_
#define N976N_TOUCH_CANVAS_H_
#include <N976nFramebuffer.h>
#include <N976nTouchProbe.h>

#define N976N_TOUCH_CANVAS_HEIGHT 2048U
#define N976N_TOUCH_RAW_MAX 4095ULL

/* An observation transform, not a discovered physical orientation. Raw
 * endpoint 4095 maps to the final FULL portrait framebuffer pixel. A point
 * below the canvas remains below it; never squeeze it into the visible area. */
STATIC inline BOOLEAN N976nTouchMapPoint (
  UINT64 RawX, UINT64 RawY, UINTN *PixelX, UINTN *PixelY)
{
  if (RawX > N976N_TOUCH_RAW_MAX || RawY > N976N_TOUCH_RAW_MAX ||
      PixelX == NULL || PixelY == NULL || PixelX == PixelY) return FALSE;
  *PixelX = (UINTN)(RawX * 1439ULL / N976N_TOUCH_RAW_MAX);
  *PixelY = (UINTN)(RawY * 3039ULL / N976N_TOUCH_RAW_MAX);
  return TRUE;
}

/* Fixed SEC-owned callers only, while EL1 M/C/I are off and DAIF masked.
 * Begin requires the already read-only-admitted display report's Info.
 * A bad CPU/metadata/session condition disarms stores and returns FALSE.
 * Throttled moves and points below the canvas are accepted observations and
 * return TRUE. Neither this renderer nor its return value admits touch I/O. */
BOOLEAN EFIAPI N976nTouchCanvasBegin (CONST N976N_PLATFORM_FB_INFO *Info);
BOOLEAN EFIAPI N976nTouchCanvasUpdate (CONST N976N_TOUCH_SNAPSHOT *Snapshot);
BOOLEAN EFIAPI N976nTouchCanvasFinish (CONST N976N_TOUCH_SNAPSHOT *Snapshot);
#endif
