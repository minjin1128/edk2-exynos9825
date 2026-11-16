/* SPDX-License-Identifier: MIT
 * POWER1: a real BSP mailbox for the standard non-PSCI ACPI boot contract.
 * Microsoft MP-start spec 3.6 requires a mailbox even for the running BSP.
 * This platform advertises one CPU and no S3/S4; no AP is started or parked.
 * No executable mailbox code, resume, hotplug or SMP support is advertised.
 */
#include <PiDxe.h>
#include <N976nRuntimePower.h>
#include <N976nAcpiPlatform.h>
#include <AArch64/AArch64Mmu.h>
#include <Library/N976nBootstrapPolicy.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DxeServicesTableLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Protocol/MemoryAttribute.h>

#define MAIL_BYTES 0x10000ULL
#define MAIL_GUARD 0x3150574D44524147ULL
STATIC UINT64 mMailboxAllocation, mMailboxProfile=MAX_UINT64;
STATIC EFI_MEMORY_ATTRIBUTE_PROTOCOL *mMailboxAttributes;

typedef struct {UINT64 El,Sctlr,Tcr,Root,Mair;} POWER_MAP_CPU;
#ifdef N976N_POWER_HANDOFF_HOST_TEST
STATIC VOID PowerMapCpu(POWER_MAP_CPU *C);
#else
STATIC VOID PowerMapCpu(POWER_MAP_CPU *C) {
  ZeroMem(C,sizeof(*C));
  __asm__ volatile("mrs %0, CurrentEL":"=r"(C->El));
  if(C->El!=4)return;
  __asm__ volatile("mrs %0, sctlr_el1":"=r"(C->Sctlr));
  __asm__ volatile("mrs %0, tcr_el1":"=r"(C->Tcr));
  __asm__ volatile("mrs %0, ttbr0_el1":"=r"(C->Root));
  __asm__ volatile("mrs %0, mair_el1":"=r"(C->Mair));
}
#endif
/* Exact identity Device-nGnRnE/RW/XN leaves through low owned table pages.
 * Reuse the established SEC62 page-walk rules, including no block/table controls. */
STATIC BOOLEAN PowerDevicePage(UINT64 Address,CONST POWER_MAP_CPU *C) {
  UINTN T0=C->Tcr&63;
  if(C->El!=4 || (C->Sctlr&(BIT0|BIT2))!=(BIT0|BIT2) || (C->Sctlr&BIT25) ||
     T0<16 || T0>39 || (C->Tcr&(BIT7|BIT14|BIT15|BIT37|BIT39|BIT40|BIT59)) ||
     ((C->Tcr>>32)&7)>5 || (C->Root&0xFFE) || Address+4096>(1ULL<<(64-T0)))return FALSE;
  UINT64 Table=C->Root&TT_ADDRESS_MASK_DESCRIPTION_TABLE,Entry=0;
  for(UINTN L=(T0-16)/9;L<=3;++L) {
    if(Table<N976N_BOOTSTRAP_HEAP_BASE || Table>N976N_BOOTSTRAP_HEAP_END-4096)return FALSE;
    Entry=((volatile UINT64 *)(UINTN)Table)[(Address>>(12+(3-L)*9))&511];
    if((Entry&3)!=3)return FALSE;
    if(L<3) {
      if(Entry&(BIT59|BIT60|BIT61|BIT62|BIT63))return FALSE;
      Table=Entry&TT_ADDRESS_MASK_DESCRIPTION_TABLE;
    }
  }
  return (Entry&TT_ADDRESS_MASK_BLOCK_ENTRY)==Address && (Entry&TT_AF) &&
    (Entry&TT_AP_MASK)==TT_AP_NO_RW &&
    (Entry&(TT_PXN_MASK|TT_UXN_MASK))==(TT_PXN_MASK|TT_UXN_MASK) &&
    (Entry&TT_SH_MASK)==0 && ((C->Mair>>(((Entry>>2)&7)*8))&255)==0;
}

BOOLEAN N976nPowerHandoffMap(CONST EFI_MEMORY_DESCRIPTOR *Map,UINTN Bytes,UINTN Stride) {
  if(mMailboxProfile==N976N_PLATFORM_PROFILE_QEMU)return mMailboxAllocation==0;
  if(mMailboxProfile!=N976N_PLATFORM_PROFILE_PHONE || !mMailboxAllocation ||
     !Map || Stride<sizeof(*Map) || !Bytes || Bytes%Stride)return FALSE;
  UINT64 Covered=0;
  for(UINTN I=0;I<Bytes;I+=Stride) {
    CONST EFI_MEMORY_DESCRIPTOR *D=(CONST VOID *)((CONST UINT8 *)Map+I);
    if(!D->NumberOfPages || D->NumberOfPages>MAX_UINT64/4096 ||
       D->PhysicalStart>MAX_UINT64-D->NumberOfPages*4096)return FALSE;
    UINT64 End=D->PhysicalStart+D->NumberOfPages*4096;
    if(End<=mMailboxAllocation || D->PhysicalStart>=mMailboxAllocation+MAIL_BYTES)continue;
    /* EDK2 reports cache capabilities here, not the currently selected cache
     * type, and strips XP. Verify active GCD/CPU attributes separately below. */
    if(D->Type!=EfiReservedMemoryType || (D->Attribute&EFI_MEMORY_RUNTIME) ||
       !(D->Attribute&EFI_MEMORY_UC))return FALSE;
    Covered+=MIN(End,mMailboxAllocation+MAIL_BYTES)-MAX(D->PhysicalStart,mMailboxAllocation);
  }
  if(Covered!=MAIL_BYTES)return FALSE;
  POWER_MAP_CPU Cpu;PowerMapCpu(&Cpu);
  for(UINTN I=0;I<MAIL_BYTES/4096;++I)
    if(!PowerDevicePage(mMailboxAllocation+I*4096,&Cpu))return FALSE;
  for(UINTN I=0;I<N976N_RUNTIME_POWER_PAGES;++I)
    if(!PowerDevicePage(mN976nRuntimePowerPages[I],&Cpu))return FALSE;
  EFI_GCD_MEMORY_SPACE_DESCRIPTOR Gcd;
  if(EFI_ERROR(gDS->GetMemorySpaceDescriptor(mMailboxAllocation,&Gcd)) ||
     Gcd.GcdMemoryType!=EfiGcdMemoryTypeSystemMemory ||
     Gcd.BaseAddress>mMailboxAllocation || Gcd.Length<MAIL_BYTES ||
     mMailboxAllocation-Gcd.BaseAddress>Gcd.Length-MAIL_BYTES ||
     Gcd.Attributes!=(EFI_MEMORY_UC|EFI_MEMORY_XP))return FALSE;
  UINT64 Attributes=0;
  if(!mMailboxAttributes || EFI_ERROR(mMailboxAttributes->GetMemoryAttributes(
      mMailboxAttributes,mMailboxAllocation,MAIL_BYTES,&Attributes)) || Attributes!=EFI_MEMORY_XP)
    return FALSE;
  for(UINTN Side=0;Side<2;++Side) {
    CONST volatile UINT64 *G=(CONST VOID *)(UINTN)(mMailboxAllocation+(Side?MAIL_BYTES-4096:0));
    for(UINTN I=0;I<512;++I)if(G[I]!=(MAIL_GUARD^I^Side))return FALSE;
  }
  CONST volatile UINT8 *M=(CONST VOID *)(UINTN)(mMailboxAllocation+4096);
  /* Before OS ownership the complete mailbox must retain its initial content. */
  for(UINTN I=0;I<4096;++I)if(M[I]!=(I<4?0xFF:0))return FALSE;
  return TRUE;
}

EFI_STATUS N976nPreparePowerHandoff(UINT64 Profile,N976N_ACPI_MADT *Madt) {
  if(mMailboxProfile!=MAX_UINT64 || !Madt || Profile>1)return EFI_ALREADY_STARTED;
  mMailboxProfile=Profile;
  if(Profile==N976N_PLATFORM_PROFILE_QEMU)return EFI_SUCCESS;
  N976N_RUNTIME_POWER_READY *Ready=NULL;
  EFI_STATUS S=gBS->LocateProtocol(&gN976nRuntimePowerReadyGuid,NULL,(VOID **)&Ready);
  if(EFI_ERROR(S) || !N976nRuntimePowerReadyValid(Ready))return EFI_NOT_READY;
  S=gBS->LocateProtocol(&gEfiMemoryAttributeProtocolGuid,NULL,(VOID **)&mMailboxAttributes);
  if(EFI_ERROR(S))return S;
  EFI_PHYSICAL_ADDRESS Address=N976N_BOOTSTRAP_HEAP_END-1;
  S=gBS->AllocatePages(AllocateMaxAddress,EfiReservedMemoryType,MAIL_BYTES/4096,&Address);
  if(EFI_ERROR(S))return S;
  mMailboxAllocation=Address;
  VOID *P=(VOID *)(UINTN)Address;
  if(mMailboxAllocation<N976N_BOOTSTRAP_HEAP_BASE ||
     mMailboxAllocation>N976N_BOOTSTRAP_HEAP_END-MAIL_BYTES ||
     (mMailboxAllocation&(MAIL_BYTES-1)))return EFI_SECURITY_VIOLATION;
  ZeroMem(P,MAIL_BYTES);
  *(UINT32 *)((UINT8 *)P+4096)=MAX_UINT32;
  for(UINTN Side=0;Side<2;++Side) {
    UINT64 *G=(VOID *)((UINT8 *)P+(Side?MAIL_BYTES-4096:0));
    for(UINTN I=0;I<512;++I)G[I]=MAIL_GUARD^I^Side;
  }
  WriteBackInvalidateDataCacheRange(P,MAIL_BYTES);
  S=gDS->SetMemorySpaceAttributes(mMailboxAllocation,MAIL_BYTES,EFI_MEMORY_UC|EFI_MEMORY_XP);
  if(EFI_ERROR(S))return S; /* Never reuse or free a partly prepared mailbox. */
  Madt->Gicc.ParkingProtocolVersion=1;
  Madt->Gicc.ParkedAddress=mMailboxAllocation+4096;
  Madt->Header.Header.Checksum=0;
  Madt->Header.Header.Checksum=CalculateCheckSum8((UINT8 *)Madt,sizeof(*Madt));
  return EFI_SUCCESS;
}
