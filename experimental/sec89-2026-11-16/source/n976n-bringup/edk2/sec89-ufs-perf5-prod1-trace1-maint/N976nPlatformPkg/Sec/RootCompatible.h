/* SPDX-License-Identifier: MIT
 * Root platform identification only. The captured N976N DT names exynos9820;
 * Samsung's N976N Android 12 exynos9825.dts names exynos9825. Both identify the
 * supported family. Peripheral resources and live ownership remain separately
 * checked by each admission/probe; this match does not authorize MMIO itself.
 */
#ifndef N976N_ROOT_COMPATIBLE_H_
#define N976N_ROOT_COMPATIBLE_H_

#include <Base.h>
#include <Library/BaseMemoryLib.h>

STATIC BOOLEAN N976nRootCompatible (CONST UINT8 *Value, UINTN Bytes)
{
  STATIC CONST CHAR8 Arm[]="samsung,armv8";
  STATIC CONST CHAR8 Family9820[]="samsung,exynos9820";
  STATIC CONST CHAR8 Family9825[]="samsung,exynos9825";
  UINTN Offset=0;
  BOOLEAN HaveArm=FALSE, HaveFamily=FALSE;

  if (Value==NULL || Bytes==0) return FALSE;
  while (Offset<Bytes) {
    UINTN End=Offset, Length;
    while (End<Bytes && Value[End]!=0) End++;
    if (End==Bytes || End==Offset) return FALSE;
    Length=End-Offset;
    if (Length==sizeof(Arm)-1 && !CompareMem(Value+Offset,Arm,Length))
      HaveArm=TRUE;
    if ((Length==sizeof(Family9820)-1 && !CompareMem(Value+Offset,Family9820,Length)) ||
        (Length==sizeof(Family9825)-1 && !CompareMem(Value+Offset,Family9825,Length)))
      HaveFamily=TRUE;
    Offset=End+1;
  }
  return HaveArm && HaveFamily;
}

#endif
