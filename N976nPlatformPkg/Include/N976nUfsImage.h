/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_IMAGE_H_
#define N976N_UFS_IMAGE_H_
#include <N976nPlatform.h>
#include <Protocol/DevicePath.h>
#define N976N_UFS_IMAGE_MAGIC SIGNATURE_64 ('N','9','7','6','I','M','0','1')
#define N976N_UFS_IMAGE_CHECKS 0xFFULL
#define N976N_UFS_IMAGE_CLOSE_CHECKS 0xFULL
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 SourceBytes, StagedBytes, ImageBase, ImageBytes;
  UINT64 LoadStatus, UnloadStatus, SourceAttributes, FreedAttributes, CloseChecks;
} N976N_UFS_IMAGE_REPORT;
STATIC_ASSERT (sizeof (N976N_UFS_IMAGE_REPORT) == 128, "SEC56 UFS image report ABI");
extern volatile N976N_UFS_IMAGE_REPORT mN976nUfsImageReport;
VOID EFIAPI N976nUfsImageLoadedCheckpoint (VOID);
VOID N976nResetUfsImage (VOID);
EFI_STATUS N976nBeginUfsImage (CONST N976N_PLATFORM_HANDOFF *Handoff,
  CONST UINT8 *Expected, UINTN Bytes);
EFI_STATUS N976nAppendUfsImage (UINTN Offset, CONST VOID *Verified, UINTN Bytes);
EFI_STATUS N976nLoadAndUnloadUfsImage (EFI_HANDLE Parent, EFI_HANDLE FsHandle,
  EFI_DEVICE_PATH_PROTOCOL *FullPath);
/* Native execution keeps the source, filesystem and service lease alive until
 * StartImage returns. A terminal observation deliberately never releases them. */
EFI_STATUS N976nRunUfsImage (EFI_HANDLE Parent, EFI_HANDLE FsHandle,
  EFI_DEVICE_PATH_PROTOCOL *FullPath);
EFI_STATUS N976nReleaseUfsImage (VOID);
/* Failed unload, permission restoration or FreePages retains the owned storage.
 * Closed is false for that quarantine; a failed instance can never be revived. */
BOOLEAN N976nUfsImageClosed (VOID);
BOOLEAN N976nUfsImageSourceOverlaps (CONST VOID *Buffer, UINTN Bytes);
#endif
