/* SPDX-License-Identifier: MIT */
#ifndef N976N_BOOT_FILES_H_
#define N976N_BOOT_FILES_H_

#include <Uefi.h>

#define N976N_BOOT_FILES_MAGIC  0x5345433434424F4FULL
#define N976N_BOOT_RECEIPT_MAGIC  0x5345433434415050ULL
#define N976N_BOOT_FILES_CHECKS  0x7FFULL
#define N976N_BOOT_RECEIPT_CHECKS  0x1FULL
#define N976N_BOOT_INFO_CONTENT "N976N SEC66\nRead-only firmware boot files\nStandard EFI application\n"
#define N976N_BOOT_INFO_PATH L"\\BootInfo.txt"
#define N976N_BOOT_APP_PATH L"\\N976nBootTest.efi"

/* Fixed read-only observer ABI. Addresses are observations, not callbacks. */
typedef struct {
  UINT64 Magic, Version, Size, Stage, Status, Checks;
  UINT64 FsHandle, FileBytes, FileCrc;
  UINT64 MissingStatus, WriteOpenStatus, WriteStatus;
  UINT64 LoadStatus, StartStatus, AutoUnloadStatus, ExplicitUnloadStatus;
  UINT64 LoadedBase, LoadedBytes, HeaderAttributes, CodeAttributes, DataAttributes;
  UINT64 FreedAttributes, ExplicitFreedAttributes;
  UINT64 LoadCount, StartCount, AutoUnloadCount, ExplicitUnloadCount;
  UINT64 ReceiptChecks, ReceiptBytes, ReceiptCrc;
  UINT64 ExplicitLoadedBase, ExplicitLoadedBytes;
} N976N_BOOT_FILES_REPORT;

/* The parent owns this bounded RW/XN buffer for the whole synchronous call.
 * The child verifies its size, current permissions and image identity first. */
typedef struct {
  UINT64 Magic, Version, Size, Checks, Status, ImageBase, ImageBytes;
  UINT64 FileBytes, FileCrc, CodeAddress, CodeAttributes;
  UINT64 DataAddress, DataAttributes, StackAddress, StackAttributes, Reserved;
} N976N_BOOT_RECEIPT;

STATIC_ASSERT (sizeof (N976N_BOOT_FILES_REPORT) == 256, "SEC49 boot report ABI");
STATIC_ASSERT (sizeof (N976N_BOOT_RECEIPT) == 128, "SEC49 child receipt ABI");

extern volatile N976N_BOOT_FILES_REPORT mN976nBootFilesReport;
EFI_STATUS RunBootFiles (EFI_HANDLE Parent);
VOID EFIAPI N976nBootFilesCheckpoint (VOID);

#endif
