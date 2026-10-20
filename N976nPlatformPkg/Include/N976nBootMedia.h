/* SPDX-License-Identifier: MIT */
#ifndef N976N_BOOT_MEDIA_H_
#define N976N_BOOT_MEDIA_H_

#include <Uefi.h>

#define N976N_BOOT_MEDIA_MAGIC   0x53454334354D4544ULL
#define N976N_BOOT_MEDIA_BYTES   0x300000ULL
#define N976N_BOOT_WINDOWS_BYTES 2622896ULL
#define N976N_BOOT_MEDIA_CHECKS  0xFULL
#define N976N_BOOT_MEDIA_DEVICE_GUID \
  {0x6e5c45af,0xef14,0x4637,{0xa7,0x1b,0xe2,0x81,0x5d,0x9b,0x45,0x05}}

/* Published on the same handle as BlockIo and the device path. The immutable
 * backing is owned BootServicesData, within the existing DT-admitted heap.
 * Checks: source integrity, owned copy, actual RO/XN attributes, publication. */
typedef struct {
  UINT64 Magic;
  UINT32 Version;
  UINT32 Size;
  UINT64 Base;
  UINT64 Bytes;
  UINT64 Checks;
  UINT64 Crc32;
  UINT64 Attributes;
} N976N_BOOT_MEDIA_PROTOCOL;

STATIC_ASSERT (sizeof (N976N_BOOT_MEDIA_PROTOCOL) == 56, "SEC49 media protocol ABI");
extern EFI_GUID gN976nBootMediaProtocolGuid;
extern EFI_GUID gN976nBootMediaFileGuid;

#endif
