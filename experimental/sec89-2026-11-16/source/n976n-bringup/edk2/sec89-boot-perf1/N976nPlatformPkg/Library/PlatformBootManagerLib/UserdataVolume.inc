/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC85 physical GPT identity / read-only installed-Windows boot service.
 * Included by SystemVolume.c to share its single synchronous Loader buffer
 * lease, exact RW-XN memory admission and permanent before-EBS gate. NTFS is
 * interpreted by the Windows boot applications, not a new firmware parser.
 * USERDATA is mutable: these reads are not described as sealed/authenticated.
 * SEC86 shares its physical GPT-backed parent with the mutable SYSTEM ESP.
 * Existing USERDATA64GiB projection and exact NTFS BPB identity/geometry remain.
 * Boot code/checksum/tail are mutable and never executed by this consumer.
 */
#include "N976nGptVolumeView.h"
#define UD_MEDIA_ID 0x533835U
#pragma pack(1)
typedef struct { VENDOR_DEVICE_PATH Vendor; UFS_DEVICE_PATH Ufs; EFI_DEVICE_PATH_PROTOCOL End; } UD_PARENT_PATH;
typedef struct { VENDOR_DEVICE_PATH Vendor; UFS_DEVICE_PATH Ufs; HARDDRIVE_DEVICE_PATH Hd; EFI_DEVICE_PATH_PROTOCOL End; } UD_PATH;
#pragma pack()
STATIC struct {
 EFI_HANDLE Parent, Child;
 EFI_BLOCK_IO_MEDIA ParentMedia, ChildMedia;
 EFI_BLOCK_IO_PROTOCOL ParentBlock, ChildBlock;
 UD_PARENT_PATH ParentPath, ParentExpected;
 UD_PATH ChildPath, ChildExpected;
 EFI_PARTITION_ENTRY Entry;
 EFI_PARTITION_TABLE_HEADER Header;
 NUV_VIEW VolumeView;
 UINT8 Before[64], Page[4096], After[64];
 UINT64 ExpectedLba;
 BOOLEAN Prepared, Gate, Pending, Frozen, Failed;
} mUd;
volatile N976N_USERDATA_VOLUME_REPORT mN976nUserdataVolumeReport;
STATIC BOOLEAN SvBorrowAllowed (CONST VOID *, UINTN);
STATIC BOOLEAN SvGuards (VOID);
STATIC EFI_STATUS SvFail (EFI_STATUS, UINT64);
STATIC VOID SvProgressScreen (VOID);
STATIC EFI_STATUS UdFail (EFI_STATUS Status, UINT64 Reason) {
 mUd.Failed=TRUE; mUd.Gate=FALSE;
 mUd.ParentMedia.MediaPresent=FALSE; mUd.ChildMedia.MediaPresent=FALSE;
 if (!mN976nUserdataVolumeReport.Reason) {
  mN976nUserdataVolumeReport.Reason=Reason; mN976nUserdataVolumeReport.Status=Status;
 }
 return SvFail(Status,0x8500+Reason);
}
STATIC BOOLEAN UdGuards (VOID) {
 if (!mUd.Prepared || !N976nUfsCpuRangeAllowed(&mUd,sizeof(mUd))) return FALSE;
 for (UINTN I=0; I<64; ++I) if (mUd.Before[I]!=0xA5 || mUd.After[I]!=0xA5) return FALSE;
 return TRUE;
}
STATIC BOOLEAN UdPaths (VOID) {
 VOID *P=NULL;
 if (!mUd.Parent || !mUd.Child || !UdGuards() ||
  CompareMem(&mUd.ParentPath,&mUd.ParentExpected,sizeof(mUd.ParentPath)) ||
  CompareMem(&mUd.ChildPath,&mUd.ChildExpected,sizeof(mUd.ChildPath))) return FALSE;
 if (mUd.Parent!=mSvParentHandle || !SvParentPathValid()) return FALSE;
 P=NULL;
 return !EFI_ERROR(gBS->HandleProtocol(mUd.Child,&gEfiDevicePathProtocolGuid,&P)) && P==&mUd.ChildPath;
}
STATIC BOOLEAN UdExtent (UINT64 Lba, UINT64 Blocks) {
 return Blocks && Lba>=N976N_USERDATA_START && Lba-N976N_USERDATA_START<N976N_USERDATA_VOLUME_BLOCKS &&
  Blocks<=N976N_USERDATA_VOLUME_BLOCKS-(Lba-N976N_USERDATA_START);
}
BOOLEAN N976nUserdataVolumeLbaAllowed (UINT64 Lba) {
 return !mSvExitClosing && mSvScope && mSvBusy && mSvRead && mSvContext &&
  mUd.Gate && !mUd.Failed && mUd.Pending && Lba==mUd.ExpectedLba &&
  UdExtent(Lba,1) && mN976nUserdataVolumeReport.ReadBlocks<N976N_USERDATA_MAX_DATA_BLOCKS && UdGuards();
}
BOOLEAN N976nUserdataVolumeReadAllowed (UINT64 Lba, CONST VOID *Buffer) {
 return Buffer==mUd.Page && N976nUserdataVolumeLbaAllowed(Lba);
}
UINT64 N976nUserdataVolumeReadCount (VOID) { return mN976nUserdataVolumeReport.ReadBlocks; }
STATIC EFI_STATUS UdState (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (This!=&mUd.ParentBlock && This!=&mUd.ChildBlock) return EFI_INVALID_PARAMETER;
 if (!mUd.Gate || mUd.Failed || !mSvGate || !mSvScope) return EFI_NO_MEDIA;
 if (MediaId!=UD_MEDIA_ID) return EFI_MEDIA_CHANGED;
 EFI_BLOCK_IO_MEDIA *M=This==&mUd.ParentBlock?&mUd.ParentMedia:&mUd.ChildMedia;
 BOOLEAN Child=This==&mUd.ChildBlock;
 if (This->Media!=M || M->MediaId!=UD_MEDIA_ID || !M->MediaPresent || !M->ReadOnly ||
  M->LogicalPartition!=Child || M->RemovableMedia || M->WriteCaching || M->BlockSize!=4096 || M->IoAlign!=1 ||
  M->LastBlock!=(Child?N976N_USERDATA_VOLUME_BLOCKS-1:mUd.Header.AlternateLBA) || !SvGuards() || !UdPaths())
  return UdFail(EFI_SECURITY_VIOLATION,1);
 return EFI_SUCCESS;
}
STATIC EFI_STATUS EFIAPI UdRead (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (This!=&mUd.ParentBlock && This!=&mUd.ChildBlock) return EFI_INVALID_PARAMETER;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 EFI_TPL Old=gBS->RaiseTPL(TPL_CALLBACK); BOOLEAN Borrowed=FALSE;
 EFI_STATUS Status=UdState(This,MediaId); if (EFI_ERROR(Status)) goto Done;
 if (mSvBusy || mSvParentBusy || mSvLease.Active || mUd.Pending) { Status=EFI_NOT_READY; goto Done; }
 if (!Bytes) { Status=EFI_SUCCESS; goto Done; }
 if (Bytes%4096) { Status=EFI_BAD_BUFFER_SIZE; goto Done; }
 UINT64 Blocks=Bytes/4096, Absolute=Lba, DataBlocks=0;
 if (Lba>This->Media->LastBlock || Blocks>This->Media->LastBlock-Lba+1 ||
  Bytes>N976N_SYSTEM_SEAL_IMAGE_BYTES || !SvBorrowAllowed(Buffer,Bytes)) { Status=EFI_INVALID_PARAMETER; goto Done; }
 if (This==&mUd.ChildBlock) Absolute+=N976N_USERDATA_START;
 /* Validate the entire operation before consuming any transport budget or
  * modifying the caller buffer. No fallback reads outside this capability. */
 for (UINT64 I=0; I<Blocks; ++I) {
  UINT64 Here=Absolute+I;
  if (UdExtent(Here,1)) ++DataBlocks;
  else if (This!=&mUd.ParentBlock || !N976nGptSnapshotLba(Here)) { Status=EFI_ACCESS_DENIED; goto Done; }
 }
 if (mN976nUserdataVolumeReport.ReadBlocks>N976N_USERDATA_MAX_DATA_BLOCKS ||
  DataBlocks>N976N_USERDATA_MAX_DATA_BLOCKS-mN976nUserdataVolumeReport.ReadBlocks) { Status=EFI_OUT_OF_RESOURCES; goto Done; }
 mSvBusy=TRUE; mSvLease.Buffer=Buffer; mSvLease.Bytes=Bytes; mSvLease.Active=TRUE; Borrowed=TRUE;
 for (UINT64 I=0; I<Blocks; ++I) {
  UINT64 Here=Absolute+I; BOOLEAN Data=UdExtent(Here,1);
  if (!UdGuards() || !SvGuards()) { Status=UdFail(EFI_SECURITY_VIOLATION,2); goto Done; }
  if (Data) {
   mUd.ExpectedLba=Here; mUd.Pending=TRUE;
   if (!N976nUserdataVolumeReadAllowed(Here,mUd.Page)) { Status=UdFail(EFI_SECURITY_VIOLATION,3); goto Retire; }
   Status=mSvRead(mSvContext,Here,mUd.Page);
   if (!EFI_ERROR(Status) && !N976nUserdataVolumeReadAllowed(Here,mUd.Page)) Status=EFI_SECURITY_VIOLATION;
Retire:
   mUd.Pending=FALSE; mUd.ExpectedLba=0;
   if (EFI_ERROR(Status)) { UdFail(Status,4); goto Done; }
   ++mN976nUserdataVolumeReport.ReadBlocks;
  } else {
   Status=N976nGptCopySnapshot(Here,mUd.Page);
   if (EFI_ERROR(Status)) { UdFail(Status,5); goto Done; }
   /* Raw snapshot admission remains unchanged. Only the private CPU output
    * is projected into the same admitted64GiB geometry used after EBS. */
   if (!NuvViewApply(&mUd.VolumeView,Here,mUd.Page,4096,NULL)) {
    Status=UdFail(EFI_COMPROMISED_DATA,14); goto Done;
   }
  }
  UINT8 *Out=(UINT8*)Buffer+I*4096;
  if (!UdGuards() || !SvGuards() || !SvBorrowAllowed(Out,4096)) { Status=UdFail(EFI_SECURITY_VIOLATION,6); goto Done; }
  CopyMem(Out,mUd.Page,4096);
  if (!UdGuards() || !SvGuards() || !SvBorrowAllowed(Out,4096) || CompareMem(Out,mUd.Page,4096)) {
   Status=UdFail(EFI_SECURITY_VIOLATION,7); goto Done;
  }
  if (!Data) ++mN976nUserdataVolumeReport.MetadataBlocks;
  if (mSvProgress>MAX_UINT64-4096) { Status=UdFail(EFI_OUT_OF_RESOURCES,8); goto Done; }
  mSvProgress+=4096; SvProgressScreen();
 }
 ++mN976nUserdataVolumeReport.ReadCalls; Status=EFI_SUCCESS;
Done:
 if (Borrowed) { ZeroMem(&mSvLease,sizeof(mSvLease)); mSvBusy=FALSE; }
 if (EFI_ERROR(Status)) ++mN976nUserdataVolumeReport.Rejected;
 gBS->RestoreTPL(Old); return Status;
}
STATIC EFI_STATUS EFIAPI UdWrite (EFI_BLOCK_IO_PROTOCOL *This, UINT32 MediaId, EFI_LBA Lba, UINTN Bytes, VOID *Buffer) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 (VOID)Lba; (VOID)Bytes; (VOID)Buffer;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 EFI_STATUS Status=UdState(This,MediaId); return EFI_ERROR(Status)?Status:EFI_WRITE_PROTECTED;
}
STATIC EFI_STATUS EFIAPI UdReset (EFI_BLOCK_IO_PROTOCOL *This, BOOLEAN Extended) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 (VOID)Extended;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 EFI_STATUS Status=UdState(This,UD_MEDIA_ID); return EFI_ERROR(Status)?Status:EFI_UNSUPPORTED;
}
STATIC EFI_STATUS EFIAPI UdFlush (EFI_BLOCK_IO_PROTOCOL *This) {
 if (mSvExitClosing) return EFI_ACCESS_DENIED;
 if (EfiGetCurrentTpl()>TPL_CALLBACK) return EFI_NOT_READY;
 return UdState(This,UD_MEDIA_ID);
}
STATIC BOOLEAN UdName (CONST CHAR16 *P) {
 CONST CHAR8 Want[]="userdata";
 for (UINTN I=0; I<8; ++I) {
  UINT16 C=P[I]; if (C>='A' && C<='Z') C+='a'-'A';
  if (C!=(UINT8)Want[I]) return FALSE;
 }
 return P[8]==0;
}
STATIC EFI_STATUS UdAdmitNtfs (VOID) {
 if (mSvBusy || mSvLease.Active || mUd.Pending || !mSvRead || !mSvContext || !UdGuards()) return EFI_NOT_READY;
 mSvBusy=TRUE; mUd.Gate=TRUE;
 EFI_STATUS Status=EFI_SUCCESS;
 for (UINTN I=0; I<2; ++I) {
  UINT64 Lba=N976N_USERDATA_START+(I?N976N_USERDATA_VOLUME_BLOCKS-1:0);
  mUd.ExpectedLba=Lba; mUd.Pending=TRUE;
  if (!N976nUserdataVolumeReadAllowed(Lba,mUd.Page)) { Status=EFI_SECURITY_VIOLATION; goto Retire; }
  Status=mSvRead(mSvContext,Lba,mUd.Page);
  if (!EFI_ERROR(Status) && !N976nUserdataVolumeReadAllowed(Lba,mUd.Page)) Status=EFI_SECURITY_VIOLATION;
Retire:
  mUd.Pending=FALSE; mUd.ExpectedLba=0;
  if (EFI_ERROR(Status)) break;
  ++mN976nUserdataVolumeReport.ReadBlocks;
  if (!UdGuards() || !SvGuards() ||
   CompareMem(mUd.Page+3,"NTFS    ",8) || SvLe(mUd.Page+11,2)!=4096 || mUd.Page[13]!=1 ||
   SvLe(mUd.Page+28,4)!=N976N_USERDATA_START ||
   SvLe(mUd.Page+40,8)!=N976N_USERDATA_NTFS_TOTAL_SECTORS ||
   N976N_USERDATA_NTFS_TOTAL_SECTORS!=N976N_USERDATA_VOLUME_BLOCKS-1 ||
   SvLe(mUd.Page+72,8)!=N976N_USERDATA_NTFS_SERIAL || !N976N_USERDATA_NTFS_SERIAL ||
   mUd.Page[510]!=0x55 || mUd.Page[511]!=0xAA ||
   CompareMem(mUd.Page+3,mN976nUserdataBpb,77)) {
   Status=EFI_COMPROMISED_DATA; break;
  }
 }
 mUd.Gate=FALSE; mSvBusy=FALSE;
 return EFI_ERROR(Status)?UdFail(Status,12):EFI_SUCCESS;
}
/* Capture only already-admitted current-boot CPU metadata. No new UFS reads,
 * on-media edits or write capability are introduced by publication. */
STATIC EFI_STATUS UdPrepareView (VOID) {
 NUV_POLICY Policy; ZeroMem(&Policy,sizeof(Policy));
 CopyMem(Policy.DiskGuid,&mUd.Header.DiskGUID,16);
 CopyMem(Policy.PartitionGuid,&mUd.Entry.UniquePartitionGUID,16);
 Policy.Start=N976N_USERDATA_START; Policy.RawBlocks=N976N_USERDATA_PARTITION_BLOCKS;
 Policy.ViewBlocks=N976N_USERDATA_VOLUME_BLOCKS;
 NuvViewReset(&mUd.VolumeView);
 UINT64 Last=mUd.Header.AlternateLBA;
 if (Last<11) return UdFail(EFI_COMPROMISED_DATA,13);
 UINT64 Lbas[10]={1,Last,2,3,4,5,Last-4,Last-3,Last-2,Last-1};
 for (UINTN I=0; I<10; ++I) {
  UINT64 Lba=Lbas[I];
  if (!N976nGptSnapshotLba(Lba)) continue;
  if (!UdGuards() || !SvGuards()) return UdFail(EFI_SECURITY_VIOLATION,13);
  EFI_STATUS Status=N976nGptCopySnapshot(Lba,mUd.Page);
  if (EFI_ERROR(Status) || !UdGuards() ||
      !NuvViewCapture(&mUd.VolumeView,Last,Lba,mUd.Page,4096))
   return UdFail(EFI_COMPROMISED_DATA,13);
 }
 if (!UdGuards() || !SvGuards() || !NuvViewSeal(&mUd.VolumeView,&Policy))
  return UdFail(EFI_COMPROMISED_DATA,13);
 return EFI_SUCCESS;
}
STATIC EFI_STATUS UdClose (VOID);
STATIC EFI_STATUS UdPublish (VOID) {
 CONST EFI_GUID Basic={0xEBD0A0A2,0xB9E5,0x4433,{0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}};
 CONST EFI_GUID Vendor={0xA9F0B685,0x9760,0x4982,{0x85,0x00,0x55,0x46,0x53,0x47,0x50,0x54}};
 CONST EFI_GUID Zero={0};
 CONST EFI_PARTITION_TABLE_HEADER *H=N976nGptHeader();
 CONST EFI_PARTITION_ENTRY *Entries=N976nGptEntries(), *Entry=NULL; UINTN Index=0;
 if (mUd.Prepared || mUd.Parent || mUd.Child || mSvExitClosing) return EFI_ALREADY_STARTED;
 if (!H || !Entries || mN976nGptReport.Phase!=8 || mN976nGptReport.Checks!=0xFF ||
  mN976nGptReport.Status!=EFI_SUCCESS || mN976nGptReport.EntryCount==0 || mN976nGptReport.EntryCount>128 ||
  CompareGuid(&H->DiskGUID,&Zero) || mN976nUfsReport.Lun!=0 || mN976nUfsReport.BlockBytes!=4096 ||
  H->AlternateLBA!=mN976nUfsReport.LastLba || !N976nUfsCpuRangeAllowed(&mUd,sizeof(mUd))) return EFI_SECURITY_VIOLATION;
 for (UINTN I=0; I<mN976nGptReport.EntryCount; ++I) if (UdName(Entries[I].PartitionName)) {
  if (Entry) return EFI_VOLUME_CORRUPTED; Entry=&Entries[I]; Index=I;
 }
 if (!Entry || !CompareGuid(&Entry->PartitionTypeGUID,&Basic) || CompareGuid(&Entry->UniquePartitionGUID,&Zero) ||
  Entry->StartingLBA!=N976N_USERDATA_START || Entry->EndingLBA!=N976N_USERDATA_START+N976N_USERDATA_PARTITION_BLOCKS-1 ||
  Entry->EndingLBA>H->LastUsableLBA || Entry->Attributes&BIT1) return EFI_SECURITY_VIOLATION;
 ZeroMem(&mUd,sizeof(mUd)); ZeroMem((VOID*)&mN976nUserdataVolumeReport,sizeof(mN976nUserdataVolumeReport));
 CopyMem(&mUd.Entry,Entry,sizeof(*Entry)); CopyMem(&mUd.Header,H,sizeof(*H));
 SetMem(mUd.Before,64,0xA5); SetMem(mUd.After,64,0xA5); mUd.Prepared=TRUE;
 mN976nUserdataVolumeReport.Magic=SIGNATURE_64('N','9','7','6','U','D','8','5');
 mN976nUserdataVolumeReport.Version=1; mN976nUserdataVolumeReport.Size=sizeof(mN976nUserdataVolumeReport);
 mN976nUserdataVolumeReport.PartitionIndex=Index+1; mN976nUserdataVolumeReport.Start=Entry->StartingLBA;
 mN976nUserdataVolumeReport.PartitionBlocks=N976N_USERDATA_PARTITION_BLOCKS;
 mN976nUserdataVolumeReport.VolumeBlocks=N976N_USERDATA_VOLUME_BLOCKS; mN976nUserdataVolumeReport.LastLba=H->AlternateLBA;
 CopyMem((VOID*)&mN976nUserdataVolumeReport.DiskGuid,&H->DiskGUID,sizeof(EFI_GUID));
 CopyMem((VOID*)&mN976nUserdataVolumeReport.PartitionGuid,&Entry->UniquePartitionGUID,sizeof(EFI_GUID));
 EFI_STATUS Status=UdAdmitNtfs(); if (EFI_ERROR(Status)) return Status;
 Status=UdPrepareView(); if (EFI_ERROR(Status)) return Status;
 UD_PARENT_PATH *P=&mUd.ParentExpected;
 P->Vendor.Header.Type=HARDWARE_DEVICE_PATH; P->Vendor.Header.SubType=HW_VENDOR_DP;
 SetDevicePathNodeLength(&P->Vendor.Header,sizeof(P->Vendor)); CopyMem(&P->Vendor.Guid,&Vendor,sizeof(Vendor));
 P->Ufs.Header.Type=MESSAGING_DEVICE_PATH; P->Ufs.Header.SubType=MSG_UFS_DP;
 SetDevicePathNodeLength(&P->Ufs.Header,sizeof(P->Ufs)); P->Ufs.Lun=0;
 P->End.Type=END_DEVICE_PATH_TYPE; P->End.SubType=END_ENTIRE_DEVICE_PATH_SUBTYPE; SetDevicePathNodeLength(&P->End,4);
 CopyMem(&mUd.ParentPath,P,sizeof(*P));
 CopyMem(&mUd.ChildExpected,P,OFFSET_OF(UD_PARENT_PATH,End));
 CopyMem(&mUd.ChildExpected.End,&P->End,4);
 HARDDRIVE_DEVICE_PATH *D=&mUd.ChildExpected.Hd;
 D->Header.Type=MEDIA_DEVICE_PATH; D->Header.SubType=MEDIA_HARDDRIVE_DP; SetDevicePathNodeLength(&D->Header,sizeof(*D));
 D->PartitionNumber=(UINT32)Index+1; D->PartitionStart=Entry->StartingLBA; D->PartitionSize=N976N_USERDATA_VOLUME_BLOCKS;
 CopyMem(D->Signature,&Entry->UniquePartitionGUID,sizeof(EFI_GUID)); D->MBRType=2; D->SignatureType=2;
 CopyMem(&mUd.ChildPath,&mUd.ChildExpected,sizeof(mUd.ChildPath));
 mUd.ParentMedia.MediaId=UD_MEDIA_ID; mUd.ParentMedia.MediaPresent=TRUE; mUd.ParentMedia.ReadOnly=TRUE;
 mUd.ParentMedia.BlockSize=4096; mUd.ParentMedia.IoAlign=1; mUd.ParentMedia.LastBlock=H->AlternateLBA;
 mUd.ParentMedia.LogicalBlocksPerPhysicalBlock=1; mUd.ParentMedia.OptimalTransferLengthGranularity=1;
 mUd.ChildMedia=mUd.ParentMedia; mUd.ChildMedia.LogicalPartition=TRUE; mUd.ChildMedia.LastBlock=N976N_USERDATA_VOLUME_BLOCKS-1;
 mUd.ParentBlock.Revision=EFI_BLOCK_IO_PROTOCOL_REVISION3; mUd.ParentBlock.Media=&mUd.ParentMedia;
 mUd.ParentBlock.Reset=UdReset; mUd.ParentBlock.ReadBlocks=UdRead; mUd.ParentBlock.WriteBlocks=UdWrite; mUd.ParentBlock.FlushBlocks=UdFlush;
 mUd.ChildBlock=mUd.ParentBlock; mUd.ChildBlock.Media=&mUd.ChildMedia;
 /* SYSTEM already published the one GPT-backed parent. This internal block
  * interface dispatches its USERDATA/metadata reads; it is not another disk. */
 if (!SvParentPathValid() || CompareMem(&mUd.ParentExpected,&mSvParentExpectedPath,sizeof(mUd.ParentExpected))) {
  Status=UdFail(EFI_SECURITY_VIOLATION,9); goto Failed;
 }
 mUd.Parent=mSvParentHandle;
 Status=gBS->InstallMultipleProtocolInterfaces(&mUd.Child,&gEfiDevicePathProtocolGuid,&mUd.ChildPath,&gEfiBlockIoProtocolGuid,&mUd.ChildBlock,NULL);
 if (EFI_ERROR(Status)) { UdFail(Status,10); goto Failed; }
 if (!UdPaths()) { Status=UdFail(EFI_SECURITY_VIOLATION,11); goto Failed; }
 mUd.Gate=TRUE; mN976nUserdataVolumeReport.Status=EFI_SUCCESS; return EFI_SUCCESS;
Failed:
 /* Roll back partial publication synchronously. A refused uninstall retains
  * the revoked handle and outer cleanup ownership; never reopen its gate. */
 if (EFI_ERROR(UdClose())) return EFI_SECURITY_VIOLATION;
 return Status;
}
STATIC EFI_STATUS UdClose (VOID) {
 mUd.Gate=FALSE; mUd.ParentMedia.MediaPresent=FALSE; mUd.ChildMedia.MediaPresent=FALSE;
 if (mUd.Pending || mUd.ExpectedLba || mSvBusy || mSvLease.Active || mSvRunning) return EFI_NOT_READY;
 if (mUd.Child) {
  EFI_STATUS S=gBS->UninstallMultipleProtocolInterfaces(mUd.Child,&gEfiDevicePathProtocolGuid,&mUd.ChildPath,&gEfiBlockIoProtocolGuid,&mUd.ChildBlock,NULL);
  if (EFI_ERROR(S)) return S; mUd.Child=NULL;
 }
 /* Shared parent belongs to SystemVolume; its owner removes it only after
  * both partition children have retired. */
 mUd.Parent=NULL;
 mN976nUserdataVolumeReport.Closed=1; return EFI_SUCCESS;
}
