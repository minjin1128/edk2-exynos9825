/** @file
  One inherited, already scanned-out linear mode. The SEC supplies validated
  geometry through a HOB after the device-state and DT ownership gates.
  NTDEV supplies the inherited-framebuffer DXE/GOP architecture; the N976N
  provider retains its tested stricter bounds and overlap behavior.
  No modesetting, timer, interrupt, clock or new MMIO recipe is used here.
  SPDX-License-Identifier: MIT
**/
#include <PiDxe.h>
#include <N976nFramebuffer.h>
#include <N976nPlatform.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/DevicePath.h>
#include <Protocol/MemoryAttribute.h>

#pragma pack (1)
typedef struct {
  VENDOR_DEVICE_PATH Vendor;
  EFI_DEVICE_PATH_PROTOCOL End;
} N976N_GOP_DEVICE_PATH;
#pragma pack ()

STATIC CONST EFI_GUID mGopGuid = EFI_GRAPHICS_OUTPUT_PROTOCOL_GUID;
STATIC CONST EFI_GUID mPathGuid = EFI_DEVICE_PATH_PROTOCOL_GUID;
STATIC N976N_PLATFORM_FB_INFO mFb;
STATIC EFI_BOOT_SERVICES *mBs;
STATIC EFI_HANDLE mDisplayHandle;
STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL mGop;
STATIC EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE mMode;
STATIC EFI_GRAPHICS_OUTPUT_MODE_INFORMATION mModeInfo;
STATIC N976N_GOP_DEVICE_PATH mDevicePath = {
  {{HARDWARE_DEVICE_PATH, HW_VENDOR_DP, {sizeof (VENDOR_DEVICE_PATH), 0}}, N976N_GOP_PATH_GUID},
  {END_DEVICE_PATH_TYPE, END_ENTIRE_DEVICE_PATH_SUBTYPE, {sizeof (EFI_DEVICE_PATH_PROTOCOL), 0}}
};

STATIC BOOLEAN Rect (UINTN X, UINTN Y, UINTN Width, UINTN Height)
{
  return Width != 0 && Height != 0 && X < mFb.Width && Y < mFb.Height &&
    Width <= mFb.Width - X && Height <= mFb.Height - Y;
}

STATIC volatile UINT32 *Video (UINTN X, UINTN Y)
{
  return (volatile UINT32 *)(UINTN)(mFb.Base + Y * mFb.PitchBytes + X * 4);
}

/* GOP buffer rows are byte strides. They need not be 4-byte aligned. This
   validates arithmetic, not the caller's allocation capacity (GOP has no such
   argument). For a nonzero buffer origin the UEFI contract requires Delta. */
STATIC BOOLEAN BufferRange (CONST VOID *Buffer, UINTN X, UINTN Y,
                           UINTN Width, UINTN Height, UINTN *Delta)
{
  UINTN RowEnd, LastRow, End;
  if (Buffer == NULL || X > MAX_UINTN / 4 || Width > MAX_UINTN / 4 - X ||
      Height == 0 || Y > MAX_UINTN - (Height - 1)) { return FALSE; }
  RowEnd = (X + Width) * 4;
  if (*Delta == 0) {
    if (X != 0 || Y != 0) { return FALSE; }
    *Delta = Width * 4;
  }
  if (*Delta < RowEnd) { return FALSE; }
  LastRow = Y + Height - 1;
  if (LastRow > (MAX_UINTN - RowEnd) / *Delta) { return FALSE; }
  End = LastRow * *Delta + RowEnd;
  return (UINTN)Buffer <= MAX_UINTN - End;
}

STATIC UINT32 ReadBuffer (CONST UINT8 *P)
{
  return (UINT32)P[0] | ((UINT32)P[1] << 8) | ((UINT32)P[2] << 16);
}

STATIC VOID WriteBuffer (UINT8 *P, UINT32 Pixel)
{
  P[0] = (UINT8)Pixel; P[1] = (UINT8)(Pixel >> 8); P[2] = (UINT8)(Pixel >> 16); P[3] = 0;
}

/* The admitted effective framebuffer layout and standard BLT pixels both
   store B,G,R in the first three bytes. Ignore the caller's Reserved byte
   when writing, and return zero for that byte when reading. */
STATIC UINT32 EncodePixel (UINT32 Pixel)
{
  return (Pixel & 0xFFFFFF) | ((UINT32)mFb.ReservedByteValue << 24);
}

STATIC UINT32 DecodePixel (UINT32 Pixel)
{
  return Pixel & 0xFFFFFF;
}

EFI_STATUS EFIAPI N976nGopQueryMode (EFI_GRAPHICS_OUTPUT_PROTOCOL *This, UINT32 Number,
  UINTN *SizeOfInfo, EFI_GRAPHICS_OUTPUT_MODE_INFORMATION **Info)
{
  EFI_STATUS Status;
  EFI_GRAPHICS_OUTPUT_MODE_INFORMATION *Copy;
  if (This != &mGop || SizeOfInfo == NULL || Info == NULL || Number != 0) { return EFI_INVALID_PARAMETER; }
  *Info = NULL; *SizeOfInfo = 0;
  Status = mBs->AllocatePool (EfiBootServicesData, sizeof (*Copy), (VOID **)&Copy);
  if (EFI_ERROR (Status)) { return Status; }
  *Copy = mModeInfo; *Info = Copy; *SizeOfInfo = sizeof (*Copy);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI N976nGopBlt (EFI_GRAPHICS_OUTPUT_PROTOCOL *This,
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL *BltBuffer, EFI_GRAPHICS_OUTPUT_BLT_OPERATION Operation,
  UINTN SourceX, UINTN SourceY, UINTN DestinationX, UINTN DestinationY,
  UINTN Width, UINTN Height, UINTN Delta)
{
  UINTN Y, X;
  UINT32 Pixel;
  EFI_TPL OldTpl;
  if (This != &mGop || (UINTN)Operation >= EfiGraphicsOutputBltOperationMax || Width == 0 || Height == 0) {
    return EFI_INVALID_PARAMETER;
  }
  if (Operation == EfiBltVideoToBltBuffer || Operation == EfiBltVideoToVideo) {
    if (!Rect (SourceX, SourceY, Width, Height)) { return EFI_INVALID_PARAMETER; }
  }
  if (Operation != EfiBltVideoToBltBuffer && !Rect (DestinationX, DestinationY, Width, Height)) { return EFI_INVALID_PARAMETER; }
  if (Operation == EfiBltVideoFill && (BltBuffer == NULL || (UINTN)BltBuffer > MAX_UINTN - 4)) { return EFI_INVALID_PARAMETER; }
  if (Operation == EfiBltBufferToVideo && !BufferRange (BltBuffer, SourceX, SourceY, Width, Height, &Delta)) { return EFI_INVALID_PARAMETER; }
  if (Operation == EfiBltVideoToBltBuffer && !BufferRange (BltBuffer, DestinationX, DestinationY, Width, Height, &Delta)) { return EFI_INVALID_PARAMETER; }
  OldTpl = mBs->RaiseTPL (TPL_NOTIFY);
  if (Operation == EfiBltVideoFill) {
    Pixel = EncodePixel (ReadBuffer ((CONST UINT8 *)BltBuffer));
    for (Y = 0; Y < Height; Y++) {
      for (X = 0; X < Width; X++) { *Video (DestinationX + X, DestinationY + Y) = Pixel; }
    }
  } else if (Operation == EfiBltBufferToVideo) {
    for (Y = 0; Y < Height; Y++) {
      CONST UINT8 *P = (CONST UINT8 *)BltBuffer + (SourceY + Y) * Delta + SourceX * 4;
      for (X = 0; X < Width; X++) {
        *Video (DestinationX + X, DestinationY + Y) = EncodePixel (ReadBuffer (P + X * 4));
      }
    }
  } else if (Operation == EfiBltVideoToBltBuffer) {
    for (Y = 0; Y < Height; Y++) {
      UINT8 *P = (UINT8 *)BltBuffer + (DestinationY + Y) * Delta + DestinationX * 4;
      for (X = 0; X < Width; X++) { WriteBuffer (P + X * 4, DecodePixel (*Video (SourceX + X, SourceY + Y))); }
    }
  } else {
    /* Both axes independently choose memmove direction. No temporary heap is
       required and diagonal/horizontal/vertical overlaps preserve source data. */
    for (UINTN Row = 0; Row < Height; Row++) {
      Y = DestinationY > SourceY ? Height - 1 - Row : Row;
      for (UINTN Column = 0; Column < Width; Column++) {
        X = DestinationX > SourceX ? Width - 1 - Column : Column;
        *Video (DestinationX + X, DestinationY + Y) = *Video (SourceX + X, SourceY + Y);
      }
    }
  }
  __asm__ __volatile__ ("dsb sy" ::: "memory");
  mBs->RestoreTPL (OldTpl);
  return EFI_SUCCESS;
}

EFI_STATUS EFIAPI N976nGopSetMode (EFI_GRAPHICS_OUTPUT_PROTOCOL *This, UINT32 Number)
{
  EFI_GRAPHICS_OUTPUT_BLT_PIXEL Black = {0, 0, 0, 0};
  if (This != &mGop) { return EFI_INVALID_PARAMETER; }
  if (Number != 0) { return EFI_UNSUPPORTED; }
  /* Even reselecting this inherited mode must clear all visible pixels. */
  return N976nGopBlt (This, &Black, EfiBltVideoFill, 0, 0, 0, 0, mFb.Width, mFb.Height, 0);
}

/* Translation instructions observe the current mappings, including effective
 * cache type. Save PAR because this is an inspection, not a mapping change.
 * The entire inherited framebuffer must be identity-mapped Device-nGnRnE;
 * EFI_MEMORY_ATTRIBUTE_PROTOCOL independently checks read/write/XN. */
STATIC BOOLEAN DeviceIdentity (UINT64 Base, UINT64 Bytes)
{
  UINT64 SavedPar, Par;
  BOOLEAN Valid = TRUE;
  __asm__ __volatile__ ("mrs %0, par_el1" : "=r" (SavedPar));
  for (UINT64 Page = Base; Page < Base + Bytes; Page += 4096) {
    __asm__ __volatile__ ("at s1e1r, %1\n\tisb\n\tmrs %0, par_el1"
                         : "=r" (Par) : "r" (Page) : "memory");
    if ((Par & 1) != 0 || (Par >> 56) != 0 ||
        (Par & 0x0000FFFFFFFFF000ULL) != Page) {
      Valid = FALSE; break;
    }
  }
  __asm__ __volatile__ ("msr par_el1, %0" :: "r" (SavedPar) : "memory");
  return Valid;
}

STATIC BOOLEAN Overlap (UINT64 A, UINT64 An, UINT64 B, UINT64 Bn)
{
  return An != 0 && Bn != 0 && A <= MAX_UINT64 - An && B <= MAX_UINT64 - Bn &&
    A < B + Bn && B < A + An;
}

STATIC BOOLEAN Span (UINT64 Base, UINT64 Size)
{
  return Base != 0 && Size != 0 && ((Base | Size) & 4095) == 0 && Size <= MAX_UINT64 - Base;
}

EFI_STATUS EFIAPI N976nGopEntry (EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
  EFI_STATUS Status;
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *MemoryAttribute = NULL;
  UINT64 Attributes = 0;
  (VOID)ImageHandle; (VOID)SystemTable;
  if (mBs != NULL) { return EFI_ALREADY_STARTED; }
  VOID *Hob = GetFirstGuidHob (&gN976nFramebufferHobGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (N976N_PLATFORM_FB_REPORT)) {
    return EFI_COMPROMISED_DATA;
  }
  CONST N976N_PLATFORM_FB_REPORT *Report = GET_GUID_HOB_DATA (Hob);
  if (Report->Raw[0] != 0xFF || Report->Raw[1] != 0 || Report->Raw[2] != 0 ||
      Report->Raw[31] != 0 || !N976nFbInfoValid (&Report->Info)) {
    return EFI_COMPROMISED_DATA;
  }
  CopyMem (&mFb, &Report->Info, sizeof (mFb));
  Hob = GetFirstGuidHob (&gN976nPlatformHandoffGuid);
  if (Hob == NULL || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (N976N_PLATFORM_HANDOFF)) {
    return EFI_COMPROMISED_DATA;
  }
  CONST N976N_PLATFORM_HANDOFF *Handoff = GET_GUID_HOB_DATA (Hob);
  if (Handoff->Magic != N976N_PLATFORM_HANDOFF_MAGIC ||
      Handoff->Version != N976N_PLATFORM_ABI_VERSION || Handoff->Size != sizeof (*Handoff) ||
      Handoff->Reserved != 0 || Handoff->Profile > 1 ||
      !Span (Handoff->HeapBase, Handoff->HeapSize) || !Span (Handoff->StackBase, Handoff->StackSize) ||
      !Span (Handoff->FirmwareBase, Handoff->FirmwareSize) || !Span (Handoff->ImageBase, Handoff->ImageSize) ||
      Overlap (mFb.Base, mFb.VisibleBytes, Handoff->HeapBase, Handoff->HeapSize) ||
      Overlap (mFb.Base, mFb.VisibleBytes, Handoff->StackBase, Handoff->StackSize) ||
      Overlap (mFb.Base, mFb.VisibleBytes, Handoff->FirmwareBase, Handoff->FirmwareSize) ||
      Overlap (mFb.Base, mFb.VisibleBytes, Handoff->ImageBase, Handoff->ImageSize)) {
    return EFI_COMPROMISED_DATA;
  }
  EFI_PEI_HOB_POINTERS Resource;
  BOOLEAN Reserved = FALSE;
  for (Resource.Raw = GetHobList (); !END_OF_HOB_LIST (Resource); Resource.Raw = GET_NEXT_HOB (Resource)) {
    if (GET_HOB_TYPE (Resource) != EFI_HOB_TYPE_RESOURCE_DESCRIPTOR) { continue; }
    UINT64 Base = Resource.ResourceDescriptor->PhysicalStart;
    UINT64 Bytes = Resource.ResourceDescriptor->ResourceLength;
    if (Bytes > MAX_UINT64 - Base) { return EFI_COMPROMISED_DATA; }
    if (!Overlap (mFb.Base, mFb.VisibleBytes, Base, Bytes)) { continue; }
    if (Resource.ResourceDescriptor->ResourceType != EFI_RESOURCE_MEMORY_RESERVED ||
        Base > mFb.Base || mFb.Base - Base > Bytes ||
        mFb.VisibleBytes > Bytes - (mFb.Base - Base)) { return EFI_SECURITY_VIOLATION; }
    Reserved = TRUE;
  }
  if (!Reserved) { return EFI_SECURITY_VIOLATION; }
  Status = gBS->LocateProtocol (&gEfiMemoryAttributeProtocolGuid, NULL, (VOID **)&MemoryAttribute);
  if (EFI_ERROR (Status) || MemoryAttribute == NULL) { return EFI_UNSUPPORTED; }
  Status = MemoryAttribute->GetMemoryAttributes (MemoryAttribute, mFb.Base, mFb.VisibleBytes, &Attributes);
  if (EFI_ERROR (Status) || (Attributes & (EFI_MEMORY_RP | EFI_MEMORY_RO | EFI_MEMORY_XP)) != EFI_MEMORY_XP ||
      !DeviceIdentity (mFb.Base, mFb.VisibleBytes)) { return EFI_SECURITY_VIOLATION; }
  mBs = gBS;
  mModeInfo.Version = 0; mModeInfo.HorizontalResolution = (UINT32)mFb.Width;
  mModeInfo.VerticalResolution = (UINT32)mFb.Height;
  mModeInfo.PixelFormat = (EFI_GRAPHICS_PIXEL_FORMAT)mFb.PixelFormat;
  /* Native geometry must also describe direct framebuffer clients correctly. */
  mModeInfo.PixelsPerScanLine = (UINT32)(mFb.PitchBytes / 4);
  mMode.MaxMode = 1; mMode.Mode = 0; mMode.Info = &mModeInfo;
  mMode.SizeOfInfo = sizeof (mModeInfo); mMode.FrameBufferBase = mFb.Base;
  mMode.FrameBufferSize = (UINTN)mFb.VisibleBytes;
  mGop.QueryMode = N976nGopQueryMode; mGop.SetMode = N976nGopSetMode;
  mGop.Blt = N976nGopBlt; mGop.Mode = &mMode;
  Status = gBS->InstallMultipleProtocolInterfaces (&mDisplayHandle,
    (EFI_GUID *)&mGopGuid, &mGop, (EFI_GUID *)&mPathGuid, &mDevicePath, NULL);
  return Status;
}
