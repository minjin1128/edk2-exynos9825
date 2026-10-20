/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_UFS_FILE_SYSTEM_H_
#define N976N_UFS_FILE_SYSTEM_H_
#include <N976nPlatform.h>
/* Sealed FV reference lookup; source identity only, never storage fallback. */
EFI_STATUS N976nLocateUfsReferenceMedia (CONST N976N_PLATFORM_HANDOFF *Handoff, CONST UINT8 **Source);

#define N976N_FILE_SYSTEM_MAGIC SIGNATURE_64 ('N','9','7','6','F','S','0','2')
#define N976N_FILE_SYSTEM_CHECKS 0xFFULL
#define N976N_FILE_SYSTEM_OWNER_CHECKS 0xFULL
#define N976N_FILE_SYSTEM_CLOSE_CHECKS 0xFULL
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 FileBytes, VerifiedBytes, DiskCalls, ReadBytes, MissingWim;
  UINT64 VolumeOffset, VolumeBytes, OwnerChecks, CloseChecks;
} N976N_FILE_SYSTEM_REPORT;
STATIC_ASSERT (sizeof (N976N_FILE_SYSTEM_REPORT) == 128, "SEC56 filesystem report ABI");
extern volatile N976N_FILE_SYSTEM_REPORT mN976nFileSystemReport;
#define N976N_FILE_RUN_MAGIC SIGNATURE_64 ('N','9','7','6','F','R','0','1')
/* Runtime reads only, after native StartImage entry gate. BcdBytes/FontBytes
 * count byte-range intersections (including repeats), not file-open calls or
 * proof of complete-file consumption. Checks: path=1/read=2/BCD=4/font=8. */
typedef struct {
  UINT64 Magic, Version, Size, Phase, Status, Checks, Reason;
  UINT64 Calls, Bytes, BlockCalls, DiskCalls, BcdBytes, FontBytes;
  UINT64 Rejected, LastOffset, LastBytes;
} N976N_FILE_RUN_REPORT;
STATIC_ASSERT (sizeof (N976N_FILE_RUN_REPORT) == 128, "SEC56 runtime filesystem report ABI");
extern volatile N976N_FILE_RUN_REPORT mN976nFileRunReport;
/* SEC62: successful physical payload CHUNKS copied to allocated high RAM
 * while the native Windows EFI execution lease is live. Not File.Read calls
 * or proof the original caller was Windows rather than an intermediate
 * LoaderCode/Data CPU buffer. Generated MBR and all low copies are excluded.
 * [0] chunks, [1] bytes (including repeats), [2] last destination, [3] bytes,
 * [4] FAT-relative offset, [5] checks, [6] failed payload requests starting
 * in the candidate bank, [7] reserved zero. Checks: publication/CPU/map=1,
 * live synchronous lease=2, physical/reference match=4, copied readback=8,
 * guards=16. A successful chunk can precede a later request failure.
 * The checkpoint fires once on the first counted chunk before lease release. */
extern volatile UINT64 mN976nHighRamUseReport[8];
VOID EFIAPI N976nHighRamReadCheckpoint (VOID);
VOID N976nResetUfsFileSystem (VOID);
EFI_STATUS N976nConsumeUfsFileSystem (CONST N976N_PLATFORM_HANDOFF *Handoff, EFI_HANDLE Parent);
/* A failed protocol uninstall may leave a static inactive tombstone. Closed
 * describes the callback gate, not successful driver/interface retirement. */
BOOLEAN N976nUfsFileSystemClosed (VOID);
#endif
