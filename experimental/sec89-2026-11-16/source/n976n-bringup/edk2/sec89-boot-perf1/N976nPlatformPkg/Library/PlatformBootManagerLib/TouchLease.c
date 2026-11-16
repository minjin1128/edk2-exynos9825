/* SPDX-License-Identifier: MIT
 * SEC76 current-boot handoff producer. The NVS record contains no executable
 * pointers. It is published only after physically owned SEC preparation, then
 * checked against live registers before standard ExitBootServices. Firmware
 * never accesses touch or this page after the release notification returns.
 */
#include <PiDxe.h>
#include <N976nTouchLease.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/HobLib.h>
#include <Library/IoLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>

STATIC N976N_TOUCH_HANDOFF *mLease;
STATIC UINT64 mProfile = MAX_UINT64;
STATIC BOOLEAN mReleased;
STATIC CONST UINT32 mCmuOffsets[13] = {
  0x2008,0x2024,0x200C,0x2010,0x2018,0x2058,0x2054,
  0x2094,0x2098,0x3038,0x100,0x280,0x182C
};
STATIC CONST UINT32 mTopAllowed[] = {
  0x20C0,0x10BC,0x18A8,0x10DC,0x18CC,0x18D4,0x100,0x160,0x18E4,0x1A0
};
STATIC_ASSERT (sizeof(N976N_TOUCH_HANDOFF) <= 512, "bounded NVS record");
STATIC_ASSERT ((OFFSET_OF(N976N_TOUCH_HANDOFF,ClaimState)&7)==0, "atomic claim alignment");
STATIC_ASSERT (sizeof(N976N_TOUCH_HANDOFF)==400, "version2 preserves record size");
STATIC_ASSERT (OFFSET_OF(N976N_TOUCH_HANDOFF,Gpa1Con)==0x140, "version2 reserved extension");
STATIC_ASSERT (OFFSET_OF(N976N_TOUCH_HANDOFF,ClaimState)==0x180, "version2 preserves claim offset");

UINT32 N976nTouchLeaseCrc (CONST N976N_TOUCH_HANDOFF *Lease)
{
  UINT32 Crc=MAX_UINT32;
  CONST UINT8 *P=(CONST UINT8 *)Lease;
  for (UINTN I=0;I<OFFSET_OF(N976N_TOUCH_HANDOFF,ClaimState);I++) {
    UINT8 Byte=(I>=OFFSET_OF(N976N_TOUCH_HANDOFF,Crc32) &&
      I<OFFSET_OF(N976N_TOUCH_HANDOFF,Crc32)+4)?0:P[I];
    Crc ^= Byte;
    for (UINTN Bit=0;Bit<8;Bit++) Crc=(Crc>>1)^((Crc&1)?0xEDB88320U:0);
  }
  return ~Crc;
}

STATIC BOOLEAN Shape (CONST N976N_TOUCH_HANDOFF *L)
{
  if (!L || L->Magic!=N976N_TOUCH_HANDOFF_MAGIC || L->Version!=N976N_TOUCH_HANDOFF_VERSION ||
      L->Bytes!=sizeof(*L) || L->ImmutableBytes!=OFFSET_OF(N976N_TOUCH_HANDOFF,ClaimState) ||
      L->Profile || L->ProducerStage!=N976N_TOUCH_HANDOFF_PREPARED ||
      !L->BootCounter || L->CounterHz!=26000000 || L->InputHz<1600000 ||
      L->InputHz>400000000 || L->ChipId!=0xAC3771 || L->BusHz!=100000 ||
      (L->LdoBefore&0xFFFFC0C0U) || L->LdoEnabled!=(L->LdoBefore|0xC0C0) ||
      L->Gic420Disabled!=1 || L->Gic45Disabled!=1 || L->Eint8Masked!=1 ||
      L->PowerRequests!=8 || L->PowerResponses!=8 || L->PowerRetired!=15 ||
      L->ProducerChecks!=7 || L->ClaimState!=N976N_TOUCH_CLAIM_READY ||
      L->Guard!=N976N_TOUCH_HANDOFF_GUARD || L->ClockCount>12 ||
      L->UsiMode!=4 || L->UsiControl || L->UsiOption>7 ||
      (L->GppCon&0xFF0000)!=0x220000 || (L->GppPull&0xFF0000) ||
       (L->GppDrive&0xFF0000) || L->HsiCtl!=BIT3 || (L->HsiAuto&0x80000000U) ||
       L->Gpa1Pull==MAX_UINT32 ||
       L->Gpa1EintMask==MAX_UINT32 || !(L->Gpa1EintMask&BIT0) || L->Gpa1Reserved ||
       ((L->Gpa1Con&15)!=0 && (L->Gpa1Con&15)!=15) ||
       ((L->Gpa1Pull&15)!=0 && (L->Gpa1Pull&15)!=1 && (L->Gpa1Pull&15)!=3)) return FALSE;
  for (UINTN I=0;I<ARRAY_SIZE(L->Reserved);I++) if (L->Reserved[I]) return FALSE;
  for (UINTN I=0;I<12;I++) {
    if (I>=L->ClockCount) {
      if (L->ClockOffsets[I] || L->ClockValues[I]) return FALSE;
      continue;
    }
    BOOLEAN Allowed=FALSE;
    for (UINTN J=0;J<ARRAY_SIZE(mTopAllowed);J++)
      if (L->ClockOffsets[I]==mTopAllowed[J]) Allowed=TRUE;
    if (!Allowed) return FALSE;
    for (UINTN J=0;J<I;J++) if (L->ClockOffsets[I]==L->ClockOffsets[J]) return FALSE;
  }
  return TRUE;
}

STATIC BOOLEAN Live (CONST N976N_TOUCH_HANDOFF *L)
{
  UINT32 GpaCon=MmioRead32(0x15850020), GpaPull=MmioRead32(0x15850028);
  UINT32 GpaMask=MmioRead32(0x15850904);
  if (GpaPull==MAX_UINT32 || GpaMask==MAX_UINT32 ||
      ((GpaCon^L->Gpa1Con)&15) || ((GpaPull^L->Gpa1Pull)&15) ||
      ((GpaMask^L->Gpa1EintMask)&BIT0)) return FALSE;
  for (UINTN I=0;I<13;I++)
    if (MmioRead32(0x10400000+mCmuOffsets[I])!=L->Cmu[I]) return FALSE;
  for (UINTN I=0;I<L->ClockCount;I++)
    if (MmioRead32(0x1A240000+L->ClockOffsets[I])!=L->ClockValues[I]) return FALSE;
  if (MmioRead32(0x1042101C)!=L->UsiMode || MmioRead32(0x104B00C4)!=L->UsiControl ||
      MmioRead32(0x104B00C8)!=L->UsiOption ||
      MmioRead32(0x10430020)!=L->GppCon || MmioRead32(0x10430028)!=L->GppPull ||
      MmioRead32(0x1043002C)!=L->GppDrive ||
      MmioRead32(0x104B0060)!=L->TimingFs[0] ||
      MmioRead32(0x104B0064)!=L->TimingFs[1] ||
      MmioRead32(0x104B0068)!=L->TimingFs[2] ||
      MmioRead32(0x104B0040)!=L->HsiConf ||
      MmioRead32(0x104B0048)!=L->HsiTimeout ||
      MmioRead32(0x104B0008)!=L->HsiTrailing ||
      MmioRead32(0x104B0000)!=L->HsiCtl ||
      MmioRead32(0x104B0004)!=L->HsiFifo ||
      MmioRead32(0x104B0044)!=L->HsiAuto ||
      MmioRead32(0x104B0070)!=L->HsiAddr ||
      MmioRead32(0x104B0020) || MmioRead32(0x104B0024)) return FALSE;
  UINT32 T=MmioRead32(0x104B0050), F=MmioRead32(0x104B0030);
  if ((T&0xF)>1 || (T&0x30000) ||
      (F&(BIT24|BIT8))!=(BIT24|BIT8) || (F&0xFF00FF) ||
      (MmioRead32(0x10430024)&0x30)!=0x30 ||
       !(GpaMask&BIT0) ||
      (MmioRead32(0x10101134)&(1U<<4)) ||
      (MmioRead32(0x10101104)&(1U<<13))) return FALSE;
  return TRUE;
}

UINT64 N976nTouchLeaseAddress (VOID) { return (UINTN)mLease; }

EFI_STATUS N976nTouchLeasePublish (UINT64 Profile)
{
  if (mProfile!=MAX_UINT64 || Profile>1) return EFI_ACCESS_DENIED;
  mProfile=Profile;
  if (Profile==1) return EFI_SUCCESS; /* no QEMU phone MMIO or fake lease */
  VOID *Hob=GetFirstGuidHob(&gN976nTouchLeaseGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE(Hob)!=sizeof(N976N_TOUCH_HANDOFF) ||
      GetNextGuidHob(&gN976nTouchLeaseGuid,GET_NEXT_HOB(Hob))) return EFI_COMPROMISED_DATA;
  CONST N976N_TOUCH_HANDOFF *L=GET_GUID_HOB_DATA(Hob);
  if (!Shape(L) || L->Crc32 || !Live(L)) return EFI_SECURITY_VIOLATION;
  EFI_PHYSICAL_ADDRESS Page=N976N_TOUCH_HANDOFF_END-4096;
  EFI_STATUS Status=gBS->AllocatePages(AllocateMaxAddress,EfiACPIMemoryNVS,1,&Page);
  if (EFI_ERROR(Status)) return Status;
  if (Page<N976N_TOUCH_HANDOFF_LOW || Page>=N976N_TOUCH_HANDOFF_END || (Page&4095)) {
    gBS->FreePages(Page,1); return EFI_SECURITY_VIOLATION;
  }
  EFI_MEMORY_ATTRIBUTE_PROTOCOL *Memory=NULL;
  Status=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&Memory);
  if (EFI_ERROR(Status) || !Memory || !Memory->SetMemoryAttributes || !Memory->GetMemoryAttributes) { gBS->FreePages(Page,1); return EFI_UNSUPPORTED; }
  Status=Memory->SetMemoryAttributes(Memory,Page,4096,EFI_MEMORY_XP);
  UINT64 Attributes=0;
  if (EFI_ERROR(Status) || EFI_ERROR(Memory->GetMemoryAttributes(Memory,Page,4096,&Attributes)) ||
      Attributes!=EFI_MEMORY_XP) { gBS->FreePages(Page,1); return EFI_SECURITY_VIOLATION; }
  mLease=(VOID *)(UINTN)Page;
  ZeroMem(mLease,4096); CopyMem(mLease,L,sizeof(*L));
  *(UINT64 *)((UINT8 *)mLease+4088)=N976N_TOUCH_HANDOFF_GUARD;
  mLease->Crc32=N976nTouchLeaseCrc(mLease); MemoryFence();
  return EFI_SUCCESS;
}

EFI_STATUS N976nTouchLeaseCheck (VOID)
{
  if (mProfile==1) return EFI_SUCCESS;
  if (mProfile!=0 || mReleased || !Shape(mLease) ||
      mLease->Crc32!=N976nTouchLeaseCrc(mLease) ||
      *(UINT64 *)((UINT8 *)mLease+4088)!=N976N_TOUCH_HANDOFF_GUARD || !Live(mLease))
    return EFI_SECURITY_VIOLATION;
  return EFI_SUCCESS;
}

EFI_STATUS N976nTouchLeaseRelease (VOID)
{
  EFI_STATUS Status=N976nTouchLeaseCheck();
  if (EFI_ERROR(Status) || mReleased) return EFI_SECURITY_VIOLATION;
  mReleased=TRUE;
  if (mProfile==1) return EFI_SUCCESS;
  mLease->ProducerChecks|=8;
  mLease->ProducerStage=N976N_TOUCH_HANDOFF_RELEASED;
  mLease->Crc32=N976nTouchLeaseCrc(mLease);
  MemoryFence();
  return EFI_SUCCESS;
}
