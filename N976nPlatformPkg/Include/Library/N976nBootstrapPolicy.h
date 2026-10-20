/** @file Initial, sealed-FV image policy for the SEC49 platform bootstrap. */
// SPDX-License-Identifier: MIT
#pragma once
#include <Uefi.h>

#define N976N_BOOTSTRAP_FV_BYTES     0x00900000ULL
// A larger source container does not increase any admitted PE image's budget.
#define N976N_BOOTSTRAP_IMAGE_BYTES  0x00400000ULL
#define N976N_BOOTSTRAP_HEAP_BASE    0x92001000ULL
#define N976N_BOOTSTRAP_HEAP_END     0x95FDE000ULL
#define N976N_BOOTSTRAP_IMAGE_LIMIT  64U
#define N976N_BOOTSTRAP_POLICY_MAGIC 0x5345433432504549ULL
#define N976N_BOOTSTRAP_POLICY_HOB_GUID \
  {0xa09a5142,0x62a8,0x49bc,{0x91,0x55,0x4e,0x39,0x37,0x36,0x50,0x45}}

typedef struct {
  UINT64 SourceOffset, SourceBytes;
  UINT64 LoadedBase, LoadedBytes;
  UINT32 Subsystem, FileType;
} N976N_BOOTSTRAP_IMAGE;

typedef struct {
  UINT64 Magic, FvBase, FvBytes;
  // ActiveCount counts live images. PublishedCount counts lifetime admissions,
  // including applications that native StartImage has returned and unloaded.
  UINT32 SourceCount, ActiveCount, PublishedCount, Failure;
  N976N_BOOTSTRAP_IMAGE Images[N976N_BOOTSTRAP_IMAGE_LIMIT];
} N976N_BOOTSTRAP_POLICY;

// Call after HobConstructor/SetHobList and MMU setup, before loading DxeCore.
// Copies the catalog into a GUID HOB, then makes the original FV RO/XN.
// Each hook looks up the current HOB copy; no SEC-to-DXE state pointer survives.
EFI_STATUS EFIAPI N976nBootstrapPolicyInitialize (VOID);
EFI_STATUS EFIAPI N976nBootstrapPolicyValidateFv (VOID);

// Scope: uncompressed FV PE32+ AArch64 initial loads, including the initial
// load of runtime drivers and exact immutable-FV applications supplied through
// a standard file system. Only those applications may unload after revocation.
// This is not runtime virtual relocation or Secure Boot authentication, and it
// does not authorize arbitrary external images.
// Unknown formats/sources and failed checks halt before executable publication.
