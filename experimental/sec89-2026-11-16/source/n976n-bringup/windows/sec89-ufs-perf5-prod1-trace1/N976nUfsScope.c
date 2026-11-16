/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC86: exactly admitted SYSTEM ESP FAT and USERDATA NTFS extents. Reads
 * require the unchanged raw-GPT/USERDATA CPU view. No caller can set policy.
 * All data commands use the existing private low DMA engine and retire before
 * another command. Ordinary writes may be cached; FUA and explicit barriers
 * require a real flush at the OS request boundary. No automatic readback.
 */
#include "N976nUfsScope.h"
#include "N976nUfsGpt.h"
#include "N976nUfsNtfsExpected.h"
#include <string.h>
typedef char NufScopeWireSize[(sizeof(NUF_SCOPE_REPORT)==352)?1:-1];
/* Check generated geometry independently of runtime GPT/boot validation.
 * This is a prefix of the real partition, never permission to write its tail. */
typedef char NufScopeImageFits[(NUF_NTFS_IMAGE_BLOCKS>0&&
 NUF_NTFS_IMAGE_BLOCKS<=NUF_NTFS_PARTITION_BLOCKS&&
 NUF_NTFS_IMAGE_BLOCKS<=0xFFFFFFFFULL-NUF_NTFS_PARTITION_START_LBA&&
 NUF_NTFS_BLOCK_BYTES==4096&&NUF_NTFS_CLUSTER_BYTES==4096&&
 NUF_NTFS_IMAGE_BYTES/4096==NUF_NTFS_IMAGE_BLOCKS&&
 NUF_NTFS_IMAGE_BYTES%4096==0&&
 NUF_NTFS_BACKUP_RELATIVE_LBA==NUF_NTFS_IMAGE_BLOCKS-1)?1:-1];
static const NUF_GPT_GUID BasicId={0xEBD0A0A2,0xB9E5,0x4433,{0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}};
static const NUF_GPT_GUID EspId={0xC12A7328,0xF81F,0x11D2,{0xBA,0x4B,0x00,0xA0,0xC9,0x3E,0xC9,0x3B}};
static const NUF_GPT_GUID SystemId={0x52444E41,0x494F,0x2044,{0x73,0x79,0x73,0x74,0x65,0x6D,0x00,0x00}};
typedef struct {NUF_ENGINE *Engine;NUF_SCOPE_REPORT *Report;NUF_SCOPE_WORK *Work;} ADMIT;
static U32 le16(const U8 *p){return p[0]|((U32)p[1]<<8);}
static U32 le32(const U8 *p){return p[0]|((U32)p[1]<<8)|((U32)p[2]<<16)|((U32)p[3]<<24);}
static U64 le64(const U8 *p){U64 v=0;for(U32 n=0;n<8;n++)v|=(U64)p[n]<<(8*n);return v;}
static int nonzero(const void *p,U32 bytes){const U8 *b=p;for(U32 n=0;n<bytes;n++)if(b[n])return 1;return 0;}
static int failure(NUF_SCOPE_REPORT *r,U32 reason){
 if(!r->FirstReason){r->FirstReason=reason;r->FirstStage=r->Stage;}
 r->Ready=0;r->Reason=r->LastReason=reason;r->Stage=NufScopeFailed;return 0;
}
static void io_report(NUF_SCOPE_REPORT *r,const NUF_ENGINE *e){
 const NUF_REPORT *i=e->Report;
 /* Scope retirement records a completed, reusable command. Report.Retired
  * remains the independent proof that the entire hardware session closed. */
 r->Issued=i->Issued;r->Acknowledged=i->Acknowledged;r->Retired=NufRequestRetired(e);
 r->Quarantined=i->Quarantined;r->Cleanup=i->CleanupReason;
}
static int operation(NUF_ENGINE *e,NUF_SCOPE_REPORT *r,U32 op,U64 lba,U32 tag,U8 *out,const U8 *in,U32 bytes){
 NUF_REPORT *i=e->Report;int ok;
 if(!i||(!e->SessionActive&&(e->Changed||e->Running))||!e->Ops.Owned||!e->Ops.Owned(e->Ops.Context)){
  e->Config.WriteEnabled=0;r->Quarantined=1;r->Retired=0;return failure(r,NufScopeOwnership);
 }
 memset(i,0,sizeof(*i));
 if(op==0x28)ok=NufReadBlock(e,lba,tag,out,bytes);
 else if(op==0x2A)ok=NufWriteBlock(e,lba,tag,in,bytes);
 else if(op==0x35)ok=NufFlushCache(e,tag);
 else return failure(r,NufScopeArgument);
 io_report(r,e);
 if(!ok||i->Reason||i->FirstReason||i->CleanupReason||i->Quarantined||!NufRequestRetired(e)||i->Issued!=1||i->Acknowledged!=1){
  e->Config.WriteEnabled=0;return failure(r,NufScopeTransport);
 }
 return 1;
}
static uint64_t read_gpt(void *context,uint64_t lba,uint8_t *out){
 ADMIT *a=context;U64 last=a->Engine->Config.LastLba;
 if(last<10||lba>last||(lba>5&&lba<last-4)||a->Work->NextTag>16)return NUF_GPT_ERROR|2;
 if(!operation(a->Engine,a->Report,0x28,lba,a->Work->NextTag++,out,NULL,4096))return NUF_GPT_ERROR|7;
 if(lba==1)memcpy(a->Report->DiskGuid,out+56,16);
 if(lba&&!NuvViewCapture(&a->Work->View,last,lba,out,4096)){failure(a->Report,NufScopeView);return NUF_GPT_ERROR|7;}
 return 0;
}
static int name(const uint16_t *p,const char *expected,U32 length){
 for(U32 n=0;n<36;n++)if(p[n]!=(n<length?(uint16_t)expected[n]:0))return 0;return 1;
}
/* Same FAT32 geometry rules used by upstream EnhancedFatDxe, narrowed to the
 * existing volume. Compare semantic BPB fields, never boot code or mutable
 * filesystem state. File/FAT/FSInfo writes cannot invalidate a media hash gate. */
typedef struct {
 U32 SectorBytes,ClusterSectors,ReservedSectors,FatCopies,TotalSectors,FatSectors;
 U32 FatFlags,RootCluster,FsInfoSector,BackupSector,VolumeId,HiddenSectors;
} SYSTEM_BPB;
typedef char NufSystemBpbNoPadding[(sizeof(SYSTEM_BPB)==12*sizeof(U32))?1:-1];
static int system_boot(const U8 *p,SYSTEM_BPB *b){
 b->SectorBytes=le16(p+11);b->ClusterSectors=p[13];b->ReservedSectors=le16(p+14);b->FatCopies=p[16];
 b->TotalSectors=le32(p+32);b->FatSectors=le32(p+36);b->FatFlags=le16(p+40);b->RootCluster=le32(p+44);
 b->FsInfoSector=le16(p+48);b->BackupSector=le16(p+50);b->VolumeId=le32(p+67);b->HiddenSectors=le32(p+28);
 if(b->SectorBytes!=NUF_SYSTEM_SECTOR_BYTES||b->ClusterSectors!=NUF_SYSTEM_CLUSTER_SECTORS||
    b->ReservedSectors!=NUF_SYSTEM_RESERVED_SECTORS||b->FatCopies!=NUF_SYSTEM_FAT_COPIES||
    b->TotalSectors!=NUF_SYSTEM_VOLUME_BLOCKS||b->FatSectors!=NUF_SYSTEM_FAT_SECTORS||b->FatFlags||
    b->RootCluster!=NUF_SYSTEM_ROOT_CLUSTER||b->FsInfoSector!=NUF_SYSTEM_FSINFO_SECTOR||
    b->BackupSector!=NUF_SYSTEM_BACKUP_SECTOR||b->VolumeId!=NUF_SYSTEM_VOLUME_ID||b->HiddenSectors||
    le16(p+17)||le16(p+19)||le16(p+22)||le16(p+42)||p[21]!=0xF8||p[66]!=0x29||
    p[510]!=0x55||p[511]!=0xAA)return 0;
 U64 data=(U64)b->ReservedSectors+(U64)b->FatCopies*b->FatSectors;
 if(data>=b->TotalSectors||b->FsInfoSector>=b->ReservedSectors||b->BackupSector>=b->ReservedSectors||b->FsInfoSector==b->BackupSector)return 0;
 U64 clusters=((U64)b->TotalSectors-data)/b->ClusterSectors;
 return clusters>=65525&&clusters<0x0FFFFFF5ULL&&b->RootCluster>=2&&b->RootCluster-2<clusters&&
  (U64)b->FatSectors*b->SectorBytes/4>=clusters+2&&(U64)b->TotalSectors*b->SectorBytes==NUF_SYSTEM_VOLUME_BYTES&&
  b->TotalSectors<=NUF_SYSTEM_PARTITION_BLOCKS;
}
static int boot(const U8 *p){
 return !memcmp(p+3,"NTFS    ",8)&&le16(p+11)==4096&&p[13]==1&&
  !le16(p+14)&&!p[16]&&!le16(p+17)&&!le16(p+19)&&!le16(p+22)&&
  p[510]==0x55&&p[511]==0xAA&&le64(p+40)==NUF_NTFS_BPB_SECTORS&&
  le64(p+48)==NUF_NTFS_MFT_LCN&&le64(p+56)==NUF_NTFS_MFTMIRR_LCN&&
  le64(p+48)<NUF_SCOPE_VOLUME_BLOCKS&&le64(p+56)<NUF_SCOPE_VOLUME_BLOCKS&&
  le64(p+72)==NUF_NTFS_VOLUME_SERIAL&&
  NUF_NTFS_IMAGE_BLOCKS==NUF_SCOPE_VOLUME_BLOCKS&&NUF_NTFS_IMAGE_BYTES==NUF_SCOPE_VOLUME_BLOCKS*4096&&
  NUF_NTFS_BACKUP_RELATIVE_LBA+1==NUF_SCOPE_VOLUME_BLOCKS&&
  /* OEM/BPB/extended BPB (identity, geometry and reserved fields) remain
   * pinned. Boot instructions, checksum and the unused tail are mutable.
   * These bytes are not executed by this driver or treated as authenticated. */
  !memcmp(p+3,NufNtfsExpectedBoot+3,77);
}
int NufScopeAdmit(NUF_ENGINE *e,NUF_SCOPE_REPORT *r,NUF_SCOPE_WORK *w){
 if(!e||!r||!w||!e->Report||!e->Ops.ClockUs)return 0;
 /* Admission runs only before publication. Never reset a live/failed policy. */
 if(r->Magic||r->Ready)return 0;
 memset(r,0,sizeof(*r));memset(w,0,sizeof(*w));
 r->Magic=NUF_SCOPE_MAGIC;r->Version=NUF_SCOPE_VERSION;r->Bytes=sizeof(*r);
 r->CompletionPolicy=NUF_SCOPE_COMPLETION_WRITEBACK;
 e->Config.WriteEnabled=0;e->Config.WriteFirst=e->Config.WriteBlocks=0;
 e->Config.SystemWriteFirst=e->Config.SystemWriteBlocks=0;
 w->NextTag=1;w->StartUs=e->Ops.ClockUs(e->Ops.Context);r->Stage=NufScopeGpt;
 ADMIT a={e,r,w};NufResetGpt();U64 status=NufObserveGpt(e->Config.LastLba,4096,read_gpt,&a);
 r->GptChecks=(U32)mNufGptReport.Checks;r->GptReason=(U32)mNufGptReport.Reason;
 if(status||r->GptChecks!=0xFF){if(!r->FirstReason)failure(r,NufScopeGptInvalid);goto done;}
 r->ReadChecks|=1;r->Stage=NufScopeTarget;
 const NUF_GPT_ENTRY *entries=NufGptEntries();
 if(!entries||mNufGptReport.EntryCount>128){failure(r,NufScopeGptInvalid);goto done;}
 for(U32 n=0;n<(U32)mNufGptReport.EntryCount;n++){
  const NUF_GPT_ENTRY *p=entries+n;
  if(name(p->PartitionName,"system",6)){
   r->SystemMatches++;
   if(memcmp(&p->PartitionTypeGUID,&EspId,16)||memcmp(&p->UniquePartitionGUID,&SystemId,16)||p->Attributes){failure(r,NufScopeSystemIdentity);goto done;}
   if(p->StartingLBA!=NUF_SYSTEM_PARTITION_START||p->EndingLBA-p->StartingLBA+1!=NUF_SYSTEM_PARTITION_BLOCKS){failure(r,NufScopeSystemGeometry);goto done;}
   r->SystemPartitionIndex=n+1;r->SystemPartitionStart=p->StartingLBA;r->SystemPartitionBlocks=p->EndingLBA-p->StartingLBA+1;
   memcpy(r->SystemGuid,&p->UniquePartitionGUID,16);memcpy(r->SystemType,&p->PartitionTypeGUID,16);
  }
  if(!name(p->PartitionName,"userdata",8))continue;r->TargetMatches++;
  if(memcmp(&p->PartitionTypeGUID,&BasicId,16)||!nonzero(&p->UniquePartitionGUID,16)||p->Attributes){failure(r,NufScopeIdentity);goto done;}
  if(p->StartingLBA!=NUF_SCOPE_USERDATA_START||p->EndingLBA-p->StartingLBA+1!=NUF_SCOPE_USERDATA_BLOCKS){failure(r,NufScopeGeometry);goto done;}
  r->PartitionIndex=n+1;r->PartitionStart=p->StartingLBA;r->PartitionBlocks=p->EndingLBA-p->StartingLBA+1;
  memcpy(r->PartitionGuid,&p->UniquePartitionGUID,16);memcpy(r->PartitionType,&p->PartitionTypeGUID,16);
 }
 if(r->TargetMatches!=1||!nonzero(r->DiskGuid,16)){failure(r,NufScopeIdentity);goto done;}
 if(r->SystemMatches!=1){failure(r,NufScopeSystemIdentity);goto done;}r->SystemChecks=1;
 SYSTEM_BPB primary,backup;r->Stage=NufScopeBoot;
 if(!operation(e,r,0x28,r->SystemPartitionStart,w->NextTag++,w->Block,NULL,4096))goto done;
 if(!system_boot(w->Block,&primary)){failure(r,NufScopeSystemBoot);goto done;}r->SystemChecks|=2;
 r->Stage=NufScopeBackup;
 if(!operation(e,r,0x28,r->SystemPartitionStart+NUF_SYSTEM_BACKUP_SECTOR,w->NextTag++,w->Block,NULL,4096))goto done;
 if(!system_boot(w->Block,&backup)||memcmp(&primary,&backup,sizeof(primary))){failure(r,NufScopeSystemBackup);goto done;}r->SystemChecks|=4;
 r->FatSerial=primary.VolumeId;
 r->Stage=NufScopeBoot;
 if(!operation(e,r,0x28,r->PartitionStart,w->NextTag++,w->Block,NULL,4096))goto done;
 if(!boot(w->Block)){failure(r,NufScopeBootMismatch);goto done;}r->ReadChecks|=2;
 r->Stage=NufScopeBackup;
 if(!operation(e,r,0x28,r->PartitionStart+NUF_NTFS_BACKUP_RELATIVE_LBA,w->NextTag++,w->Block,NULL,4096))goto done;
 if(!boot(w->Block)){failure(r,NufScopeBackupMismatch);goto done;}r->ReadChecks|=4;
 NUV_POLICY policy;memset(&policy,0,sizeof(policy));
 memcpy(policy.DiskGuid,r->DiskGuid,16);memcpy(policy.PartitionGuid,r->PartitionGuid,16);
 policy.Start=r->PartitionStart;policy.RawBlocks=r->PartitionBlocks;policy.ViewBlocks=NUF_SCOPE_VOLUME_BLOCKS;
 if(!NuvViewSeal(&w->View,&policy)){failure(r,NufScopeView);goto done;}
 r->WriteStart=r->PartitionStart;r->WriteBlocks=NUF_SCOPE_VOLUME_BLOCKS;r->NtfsSerial=NUF_NTFS_VOLUME_SERIAL;
 r->SystemWriteStart=r->SystemPartitionStart;r->SystemWriteBlocks=NUF_SYSTEM_VOLUME_BLOCKS;
 r->Ready=1;r->Stage=NufScopeReady;
 e->Config.WriteFirst=r->WriteStart;e->Config.WriteBlocks=r->WriteBlocks;
 e->Config.SystemWriteFirst=r->SystemWriteStart;e->Config.SystemWriteBlocks=r->SystemWriteBlocks;
 e->Config.WriteEnabled=1;
 done:{U64 end=e->Ops.ClockUs(e->Ops.Context);if(end>=w->StartUs)r->ElapsedUs=end-w->StartUs;else failure(r,NufScopeTransport);}
 if(!r->Ready){e->Config.WriteEnabled=0;e->Config.WriteFirst=e->Config.WriteBlocks=0;e->Config.SystemWriteFirst=e->Config.SystemWriteBlocks=0;}
 return r->Ready==1;
}
int NufScopeContains(const NUF_SCOPE_REPORT *r,U64 lba,U32 bytes){
 return r&&r->Magic==NUF_SCOPE_MAGIC&&r->Version==NUF_SCOPE_VERSION&&r->Bytes==sizeof(*r)&&r->Ready==1&&
  r->CompletionPolicy==NUF_SCOPE_COMPLETION_WRITEBACK&&
  r->Stage==NufScopeReady&&!r->Reason&&!r->FirstReason&&!r->Quarantined&&!r->Cleanup&&!r->WriteUncertain&&
  r->ReadChecks==7&&r->GptChecks==0xFF&&r->WriteStart==NUF_SCOPE_USERDATA_START&&
  r->SystemChecks==7&&r->SystemMatches==1&&r->SystemPartitionStart==NUF_SYSTEM_PARTITION_START&&
  r->SystemPartitionBlocks==NUF_SYSTEM_PARTITION_BLOCKS&&r->SystemWriteStart==NUF_SYSTEM_PARTITION_START&&
  r->SystemWriteBlocks==NUF_SYSTEM_VOLUME_BLOCKS&&r->FatSerial==NUF_SYSTEM_VOLUME_ID&&
  !memcmp(r->SystemGuid,&SystemId,16)&&!memcmp(r->SystemType,&EspId,16)&&
  r->WriteBlocks==NUF_SCOPE_VOLUME_BLOCKS&&bytes&&bytes<=NUF_MAX_TRANSFER&&!(bytes%NUF_BLOCK_BYTES)&&
  ((lba>=r->WriteStart&&lba-r->WriteStart<r->WriteBlocks&&
    bytes/NUF_BLOCK_BYTES<=r->WriteBlocks-(lba-r->WriteStart))||
   (lba>=r->SystemWriteStart&&lba-r->SystemWriteStart<r->SystemWriteBlocks&&
    bytes/NUF_BLOCK_BYTES<=r->SystemWriteBlocks-(lba-r->SystemWriteStart)));
}
int NufScopeWrite(NUF_ENGINE *e,NUF_SCOPE_REPORT *r,NUF_SCOPE_WORK *w,U64 lba,const U8 *in,U32 bytes){
 if(!e||!r||!w)return 0;
 /* The adapter admits the full OS span, then submits one bounded transfer. The
  * core still snapshots each payload and checks its immutable DMA bytes.
  * A retired WRITE response is not a persistence or media-readback claim. */
 if(!in||!NufScopeContains(r,lba,bytes)){r->Rejected++;r->LastReason=NufScopeBounds;return 0;}
 r->Requests++;r->Stage=NufScopeIo;r->LastLba=lba;r->LastOpcode=0x2A;
 U32 tag=(U32)(r->Requests%255)+1;
 r->WriteUncertain=1;r->CacheDirty=1;
 /* The core makes the single owned ExpectedData snapshot before submission. */
 if(!operation(e,r,0x2A,lba,tag,NULL,in,bytes))return 0;
 r->Writes+=bytes/4096;r->WriteBytes+=bytes;
 if(lba>=r->SystemWriteStart&&lba-r->SystemWriteStart<r->SystemWriteBlocks){r->SystemWrites+=bytes/4096;r->SystemWriteBytes+=bytes;}
 r->WriteUncertain=0;r->Stage=NufScopeReady;r->LastReason=0;return 1;
}
int NufScopeFlush(NUF_ENGINE *e,NUF_SCOPE_REPORT *r,U32 tag){
 if(!e||!r)return 0;
 if(!r->Ready||r->Stage!=NufScopeReady||r->Reason||r->FirstReason||
    r->Quarantined||r->Cleanup||r->WriteUncertain)return 0;
 r->Requests++;r->LastOpcode=0x35;r->LastLba=0;
 U32 stage=r->Stage;r->Stage=NufScopeIo;
 r->WriteUncertain=1;
 if(!operation(e,r,0x35,0,tag,NULL,NULL,0))return 0;
 r->Flushes++;r->CacheDirty=0;r->WriteUncertain=0;r->Stage=stage;return 1;
}
