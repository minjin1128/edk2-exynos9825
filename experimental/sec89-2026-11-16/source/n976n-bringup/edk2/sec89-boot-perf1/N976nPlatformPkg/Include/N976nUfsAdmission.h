/* SPDX-License-Identifier: MIT */
#ifndef N976N_UFS_ADMISSION_H_
#define N976N_UFS_ADMISSION_H_
#include <N976nUfs.h>

/* The caller owns and has already bounded Dtb through ParseRuntimeDtb.
 * No MMIO access occurs here. A rejection always leaves all addresses zero. */
BOOLEAN EFIAPI N976nAdmitUfs (
  CONST VOID *Dtb, UINT64 DtbBytes, N976N_UFS_ADMISSION *Admission);

#define N976N_UFS_DT_BAD_BUFFER  1ULL
#define N976N_UFS_DT_BAD_HEADER  2ULL
#define N976N_UFS_DT_BAD_TREE    3ULL
#define N976N_UFS_DT_DUPLICATE   4ULL
#define N976N_UFS_DT_BAD_VALUE   5ULL
#define N976N_UFS_DT_MISSING     6ULL
#endif
