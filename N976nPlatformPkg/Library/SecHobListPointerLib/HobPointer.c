/* SPDX-License-Identifier: MIT
 * Same image-owned HOB pointer arrangement as the verified N976N SEC path.
 */
#include <PiPei.h>
#include <Library/PrePiHobListPointerLib.h>
STATIC VOID *mHobList;
VOID *EFIAPI PrePeiGetHobList (VOID) { return mHobList; }
EFI_STATUS EFIAPI PrePeiSetHobList (VOID *HobList)
{ mHobList = HobList; return EFI_SUCCESS; }

