/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * One-shot adapter around unmodified MbedTLS SHA256 from the exact submodule
 * pinned by EDK2 870158586f14dbf9d57e312ea6ea87141a1b0699:
 * MbedTLS 0bebf8b8c7f07abe3571ded48a11aa907a1ffb20. */
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <Library/BaseLib.h>
#include <Library/DebugLib.h>
/* CLANGPDB uses the Windows COFF ABI, not Windows OS services. Keep the
 * freestanding scalar source from selecting Windows CRT/NEON headers.
 * EDK2 ABI headers above have already selected the target correctly. */
#undef _WIN32
#undef _WIN64
#undef __MINGW32__
#undef __MINGW64__
#undef _M_ARM64
#undef _M_ARM64EC
#define MBEDTLS_CONFIG_FILE "SystemShaConfig.h"
#define MBEDTLS_ALLOW_PRIVATE_ACCESS
#include <mbedtls/sha256.h>
/* Match the upstream C runtime contracts with existing EDK2 memory routines.
 * These macros only affect this translation unit; upstream bytes are intact. */
#include <string.h>
#undef memcpy
#undef memset
#undef memcmp
#define memcpy(Destination, Source, Bytes) CopyMem ((Destination), (Source), (Bytes))
#define memset(Buffer, Value, Bytes) SetMem ((Buffer), (Bytes), (UINT8)(Value))
#define memcmp(First, Second, Bytes) CompareMem ((First), (Second), (Bytes))
#include "UpstreamSha256/library/sha256.c"
void mbedtls_platform_zeroize (void *Buffer, size_t Bytes) {
  volatile UINT8 *P = (volatile UINT8 *)Buffer;
  while (Bytes--) { *P++ = 0; }
  MemoryFence ();
}
BOOLEAN N976nSystemSha256 (CONST VOID *Data, UINTN Bytes, UINT8 Digest[32]) {
  if ((Data == NULL && Bytes != 0) || Digest == NULL ||
      Bytes > MAX_UINTN - (UINTN)Data) { return FALSE; }
  return mbedtls_sha256 ((CONST unsigned char *)Data, Bytes, Digest, 0) == 0;
}
