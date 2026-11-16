/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * QEMU-only RAM media fixture for the unchanged upstream FAT driver and the
 * actual SEC56 filesystem adapter. Physical UFS remains NOT_TESTED/F0.
 * No GDB intervention, hardware MMIO, device write or RAM-source fallback
 * exists in the phone path. This fixture has no claim to test UFS hardware.
 */
#include <N976nUfs.h>
#include <N976nUfsService.h>
#include <N976nUfsFileSystem.h>
#include <N976nBootMedia.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/PcdLib.h>

/* [checks, block reads, final status, active]. Explicit QEMU evidence ABI. */
volatile UINT64 mN976nFileFixture[4];
STATIC CONST N976N_PLATFORM_HANDOFF *mFixtureHandoff;
STATIC UINT8 mFixtureHeader[2048];
#define FIXTURE_START 6ULL
#define FIXTURE_BLOCKS 0x3700ULL
STATIC BOOLEAN EFIAPI FixtureCheck (VOID *Context, VOID *Buffer, UINTN Bytes) {
  return Context == &mFixtureHandoff && mN976nFileFixture[3] != 0 &&
    (N976nServiceBufferOwned (Buffer, Bytes) || N976nServiceStorageOwned (Buffer, Bytes)) &&
    N976nUfsCpuRangeAllowed (Buffer, Bytes);
}
STATIC UINTN EFIAPI FixtureBudget (VOID *Context) {
  if (Context != &mFixtureHandoff || mN976nFileFixture[3] == 0 ||
      mN976nFileFixture[1] >= N976nUfsBootDataLimit (N976N_BOOT_WINDOWS_BYTES)) { return 0; }
  return N976nUfsBootDataLimit (N976N_BOOT_WINDOWS_BYTES) - (UINTN)mN976nFileFixture[1];
}
STATIC EFI_STATUS EFIAPI FixtureRead (VOID *Context, UINT64 Lba, UINT8 *Block) {
  UINT64 Offset;
  if (mFixtureHandoff == NULL || mFixtureHandoff->Profile != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nPlatformProfile) != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nUfsQueryExperiment) != 9 ||
      FixtureBudget (Context) == 0 || !FixtureCheck (Context, Block, 4096) ||
      !N976nServiceBufferOwned (Block, 4096) || Lba < FIXTURE_START ||
      Lba - FIXTURE_START >= FIXTURE_BLOCKS) { return EFI_ACCESS_DENIED; }
  Offset = (Lba - FIXTURE_START) * 4096;
  for (UINTN I = 0; I < 4096; ++I) {
    UINT64 Position = Offset + I;
    if (Position < sizeof (mFixtureHeader)) { Block[I] = mFixtureHeader[Position]; }
    else if (Position - sizeof (mFixtureHeader) < mFixtureHandoff->ImageSize) {
      Block[I] = ((CONST UINT8 *)(UINTN)mFixtureHandoff->ImageBase)[Position - sizeof (mFixtureHeader)];
    } else { Block[I] = 0; }
  }
  ++mN976nFileFixture[1];
  return EFI_SUCCESS;
}
EFI_STATUS N976nRunUfsFileFixture (CONST N976N_PLATFORM_HANDOFF *Handoff) {
  EFI_STATUS Status, Close;
  if (Handoff == NULL || Handoff->Profile != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nPlatformProfile) != N976N_PLATFORM_PROFILE_QEMU ||
      PcdGet32 (PcdN976nUfsQueryExperiment) != 9 ||
      mN976nUfsReport.Phase != 0xF0 || mN976nUfsReport.Buffer != 0 ||
      mN976nUfsReport.CommandCount != 0 || mN976nFileFixture[0] != 0 ||
      Handoff->ImageSize > MAX_UINT32 ||
      !N976nUfsCpuRangeAllowed (mFixtureHeader, sizeof (mFixtureHeader))) { return EFI_ACCESS_DENIED; }
  mFixtureHandoff = Handoff;
  ZeroMem (mFixtureHeader, sizeof (mFixtureHeader));
  CopyMem (mFixtureHeader, "ANDROID!", 8);
  UINT32 KernelBytes = (UINT32)Handoff->ImageSize, PageBytes = sizeof (mFixtureHeader);
  CopyMem (mFixtureHeader + 8, &KernelBytes, sizeof (KernelBytes));
  CopyMem (mFixtureHeader + 36, &PageBytes, sizeof (PageBytes));
  mN976nFileFixture[0] = 1; mN976nFileFixture[3] = 1;
  Status = N976nStartUfsBootService (FIXTURE_START, FIXTURE_BLOCKS,
    FixtureRead, FixtureCheck, FixtureBudget, &mFixtureHandoff, N976N_BOOT_WINDOWS_BYTES);
  if (!EFI_ERROR (Status)) {
    mN976nFileFixture[0] |= 2;
    Status = N976nConsumeUfsFileSystem (Handoff, gImageHandle);
    if (!EFI_ERROR (Status)) { mN976nFileFixture[0] |= 4; }
  }
  if (N976nUfsFileSystemClosed ()) {
    Close = N976nStopUfsService ();
    if (!EFI_ERROR (Status)) { Status = Close; }
    if (N976nUfsServiceClosed ()) { mN976nFileFixture[3] = 0; }
    if (!EFI_ERROR (Close) && N976nUfsServiceClosed ()) { mN976nFileFixture[0] |= 8; }
  } else if (!EFI_ERROR (Status)) { Status = EFI_NOT_READY; }
  mN976nFileFixture[2] = Status;
  return Status;
}
