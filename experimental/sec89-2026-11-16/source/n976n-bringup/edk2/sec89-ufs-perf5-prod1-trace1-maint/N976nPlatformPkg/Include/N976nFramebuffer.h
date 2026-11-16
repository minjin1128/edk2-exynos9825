/* SPDX-License-Identifier: MIT */
#ifndef N976N_FRAMEBUFFER_H_
#define N976N_FRAMEBUFFER_H_
#include <Uefi.h>
#include <Protocol/GraphicsOutput.h>

#define N976N_PLATFORM_FB_INFO_MAGIC 0x46423134494E464FULL
#define N976N_PLATFORM_FB_INFO_VERSION 1ULL
#define N976N_PLATFORM_FB_INFO_FLAGS 0xFFULL
#define N976N_GOP_PATH_GUID {0x8caa976e,0x032a,0x4e51,{0xb5,0xa2,0x4e,0x39,0x37,0x36,0x14,0x47}}

typedef struct {
  UINT64 Magic, Size, Version, Flags, Base, VisibleBytes, Width, Height;
  UINT64 PitchBytes, PixelFormat, RedMask, GreenMask, BlueMask, ReservedMask;
  UINT64 ReservedByteValue, Reserved;
} N976N_PLATFORM_FB_INFO;

typedef struct {
  UINT64 Raw[32];
  N976N_PLATFORM_FB_INFO Info;
  UINT64 Reserved[16];
} N976N_PLATFORM_FB_REPORT;

STATIC_ASSERT (sizeof (N976N_PLATFORM_FB_INFO) == 128, "inherited framebuffer ABI");
STATIC_ASSERT (sizeof (N976N_PLATFORM_FB_REPORT) == 512, "inherited framebuffer evidence ABI");

STATIC inline BOOLEAN N976nFbInfoValid (CONST N976N_PLATFORM_FB_INFO *F)
{
  return F != NULL && F->Magic == N976N_PLATFORM_FB_INFO_MAGIC && F->Size == sizeof (*F) &&
    F->Version == N976N_PLATFORM_FB_INFO_VERSION && F->Flags == N976N_PLATFORM_FB_INFO_FLAGS &&
    F->Base == 0xCA000000ULL && F->VisibleBytes == 0x10B3000ULL &&
    F->Width == 1440 && F->Height == 3040 && F->PitchBytes == 5760 &&
    F->PitchBytes * F->Height == F->VisibleBytes &&
    F->PixelFormat == PixelBlueGreenRedReserved8BitPerColor &&
    F->RedMask == 0x00FF0000 && F->GreenMask == 0x0000FF00 &&
    F->BlueMask == 0x000000FF && F->ReservedMask == 0xFF000000 &&
    (F->ReservedByteValue == 0 || F->ReservedByteValue == 0xFF) && F->Reserved == 0;
}

extern EFI_GUID gN976nFramebufferHobGuid;
EFI_STATUS N976nValidateDisplay (N976N_PLATFORM_FB_REPORT *Report);
#endif
