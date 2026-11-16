/* SPDX-License-Identifier: MIT
 * A presentation viewport over the entire admitted inherited framebuffer.
 * This never changes scanout, the physical HOB, reservations or MMU coverage.
 */
#ifndef N976N_GOP_VIEWPORT_H_
#define N976N_GOP_VIEWPORT_H_
#include <N976nFramebuffer.h>

#ifndef N976N_GOP_Y_INSET
#error Build must select the exact GOP viewport
#endif
#if N976N_GOP_Y_INSET != 0 && N976N_GOP_Y_INSET != 160
#error Only the preserved full view or the bounded 160-row inset is admitted
#endif

#define N976N_GOP_VIEW_BASE (0xCA000000ULL + 5760ULL * N976N_GOP_Y_INSET)
#define N976N_GOP_VIEW_WIDTH 1440ULL
#define N976N_GOP_VIEW_HEIGHT (3040ULL - 2ULL * N976N_GOP_Y_INSET)
#define N976N_GOP_VIEW_BYTES (5760ULL * N976N_GOP_VIEW_HEIGHT)

STATIC_ASSERT ((N976N_GOP_VIEW_BASE & 4095) == 0, "GOP view page alignment");
STATIC_ASSERT ((N976N_GOP_VIEW_BYTES & 4095) == 0, "GOP view extent page alignment");
STATIC_ASSERT (N976N_GOP_VIEW_BASE >= 0xCA000000ULL &&
  N976N_GOP_VIEW_BASE + N976N_GOP_VIEW_BYTES <= 0xCB0B3000ULL,
  "GOP view must remain inside physical framebuffer");

STATIC inline BOOLEAN N976nGopViewInfoValid (CONST EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Info)
{
  return Info != NULL && Info->Version == 0 &&
    Info->HorizontalResolution == N976N_GOP_VIEW_WIDTH &&
    Info->VerticalResolution == N976N_GOP_VIEW_HEIGHT &&
    Info->PixelFormat == PixelBlueGreenRedReserved8BitPerColor &&
    Info->PixelsPerScanLine == 1440;
}

STATIC inline BOOLEAN N976nGopViewModeValid (CONST EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode)
{
  return Mode != NULL && Mode->MaxMode == 1 && Mode->Mode == 0 &&
    Mode->SizeOfInfo == sizeof (*Mode->Info) && N976nGopViewInfoValid (Mode->Info) &&
    Mode->FrameBufferBase == N976N_GOP_VIEW_BASE &&
    Mode->FrameBufferSize == N976N_GOP_VIEW_BYTES;
}
#endif
