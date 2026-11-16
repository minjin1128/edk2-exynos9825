/* SPDX-License-Identifier: MIT */
#ifndef N976N_UFS_WINDOWS_LEASE_H
#define N976N_UFS_WINDOWS_LEASE_H
#include <N976nUfs.h>
#include <N976nUfsHandoff.h>
EFI_STATUS N976nUfsWindowsPublish (UINT64 Profile);
EFI_STATUS N976nUfsWindowsLeasePrepare (CONST N976N_PLATFORM_HANDOFF *, CONST N976N_UFS_ADMISSION *, CONST N976N_UFS_REPORT *, CONST UINT8 *);
EFI_STATUS N976nUfsWindowsLeaseCheck (VOID);
EFI_STATUS N976nUfsWindowsLeaseStopped (VOID);
EFI_STATUS N976nUfsWindowsLeaseRelease (VOID);
BOOLEAN N976nUfsWindowsLeaseMap (CONST EFI_MEMORY_DESCRIPTOR *, UINTN, UINTN);
UINT64 N976nUfsWindowsLeaseAddress (VOID);
UINT64 N976nUfsWindowsDmaAddress (VOID);
#endif
