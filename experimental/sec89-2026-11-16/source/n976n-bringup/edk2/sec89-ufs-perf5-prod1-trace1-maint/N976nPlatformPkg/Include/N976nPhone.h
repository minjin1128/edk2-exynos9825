/* SPDX-License-Identifier: MIT */
#ifndef N976N_PHONE_H_
#define N976N_PHONE_H_
#define N976N_PHONE_INPUT_MAGIC 0x534543343350484eULL
#define N976N_PHONE_REPORT_MAGIC 0x5345433433535444ULL
#define N976N_PHONE_GUARD 0x5345433433475541ULL
#define N976N_PHONE_INPUT_BYTES 128
#define N976N_PHONE_REPORT_BYTES 512
#ifndef __ASSEMBLER__
#include <Uefi.h>
/* The Android wrapper verifies its immutable source CRCs and data-only SEC
 * relocation list, relocates the SEC, updates ImageBase, and synchronizes caches
 * before this call. No external-RAM address is trusted until the runtime DT gate.
 * All ranges are physical identity addresses. Stack remains inside the Image. */
typedef struct {
  UINT64 Magic, Size, ImageBase, ImageEnd;
  UINT64 WrapperCodeEnd, WritableBase, WritableEnd;
  UINT64 SecBase, SecSize, FvBase, FvSize, Dtb;
  UINT64 StackBase, StackSize, Screen, ReportAddress;
} N976N_PHONE_INPUT;
typedef VOID (EFIAPI *N976N_PHONE_SCREEN)(UINT64 Event, UINT64 Value);
STATIC_ASSERT (sizeof (N976N_PHONE_INPUT) == N976N_PHONE_INPUT_BYTES, "SEC49 phone input ABI");
#endif
#endif
