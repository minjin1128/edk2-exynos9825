/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC86 retains NTDEV/9820's explicit WRITE10/16 and real no-data SYNCHRONIZE CACHE
 * classification. It translates validated CDBs; it never forwards arbitrary
 * commands. The independently admitted SYSTEM/FAT and USERDATA/NTFS scopes fence every WRITE. Normal
 * writes expose cacheable completion; FUA and explicit barriers require a real
 * flush before their OS request succeeds.
 */
#include "N976nUfsScsi.h"
#include <string.h>
/* WDK kernel CRT supplies size_t through the shared header. Pulling the user
 * CRT stdint.h into this translation unit mixes incompatible runtime headers. */
typedef char NufPointerSized[(sizeof(size_t)==sizeof(void*))?1:-1];
static U32 be16(const U8 *p){return ((U32)p[0]<<8)|p[1];}
static U32 be32(const U8 *p){return ((U32)p[0]<<24)|((U32)p[1]<<16)|((U32)p[2]<<8)|p[3];}
static U64 be64(const U8 *p){return ((U64)be32(p)<<32)|be32(p+4);}
static void put16(U8 *p,U32 v){p[0]=(U8)(v>>8);p[1]=(U8)v;}
static void put32(U8 *p,U32 v){p[0]=(U8)(v>>24);p[1]=(U8)(v>>16);p[2]=(U8)(v>>8);p[3]=(U8)v;}
static void put64(U8 *p,U64 v){put32(p,(U32)(v>>32));put32(p+4,(U32)v);}
static NUF_SCSI_RESULT check(U8 key,U8 asc,U32 write){NUF_SCSI_RESULT r={0};r.Disposition=NufScsiCheck;r.Key=key;r.Asc=asc;r.WriteDenied=write;return r;}
static int data_span(const U8 *p,U32 blocks,U32 bytes){
 return p&&blocks&&blocks<=NUF_MAX_TRANSFER/NUF_BLOCK_BYTES&&
  bytes==blocks*NUF_BLOCK_BYTES&&(size_t)p<=(size_t)-1-(bytes-1U);
}
static int write_op(U8 op){switch(op){
 case 0x04:case 0x0A:case 0x15:case 0x2A:case 0x2E:case 0x3B:case 0x41:case 0x42:
 case 0x48:case 0x55:case 0x89:case 0x8A:case 0x8B:case 0x8E:case 0x93:case 0xAA:case 0xAE:
 return 1;default:return 0;}}
static NUF_SCSI_RESULT reply(U8 *out,U32 bytes,U32 direction,const U8 *data,U32 size,U32 allocation){
 NUF_SCSI_RESULT r={0};U32 n=size;if(direction!=NufDirectionIn)return check(5,0x24,0);
 if(n>allocation)n=allocation;if(n>bytes)n=bytes;if(n&&!out)return check(5,0x24,0);
 if(n)memcpy(out,data,n);r.Bytes=n;return r;}
NUF_SCSI_RESULT NufScsiPlan(const U8 *c,U32 n,U32 direction,U8 *out,U32 bytes,U64 last){
 NUF_SCSI_RESULT r={0};U8 data[96]={0};U32 allocation=0,size=0,dbd,header,page,pc;
 if(!c||!n||n>16||last==0||last>=0xFFFFFFFFULL||direction>3)return check(5,0x24,0);
 /* Only two explicitly decoded data-out commands can reach the write plan.
  * No payload is inspected or changed here. Fresh range admission is checked later. */
 if(c[0]!=0x2A&&c[0]!=0x8A&&(write_op(c[0])||(direction&NufDirectionOut)))return check(7,0x27,1);
 if(c[0]==0x2A||c[0]==0x8A){
  if((c[0]==0x2A&&n!=10)||(c[0]==0x8A&&n!=16)||(c[1]&~8U))return check(5,0x24,1);
  if(c[0]==0x2A){if(c[6]||c[9])return check(5,0x24,1);r.Lba=be32(c+2);r.Blocks=be16(c+7);}
  else{if(c[14]||c[15])return check(5,0x24,1);r.Lba=be64(c+2);r.Blocks=be32(c+10);}
  if(r.Lba>last||(r.Blocks&&r.Blocks-1>last-r.Lba))return check(5,0x21,1);
  if(!r.Blocks){if(bytes||(direction!=NufDirectionNone&&direction!=NufDirectionOut))return check(5,0x24,1);return r;}
  if(direction!=NufDirectionOut||!data_span(out,r.Blocks,bytes))return check(5,0x24,1);
  /* Validate the whole OS request before any of its bounded 4KiB hardware
   * commands can run. Subtraction keeps the end-of-range check overflow-free. */
  if(!((r.Lba>=NUF_WRITE_REGION_FIRST&&r.Lba-NUF_WRITE_REGION_FIRST<NUF_WRITE_REGION_BLOCKS&&
        r.Blocks<=NUF_WRITE_REGION_BLOCKS-(r.Lba-NUF_WRITE_REGION_FIRST))||
       (r.Lba>=NUF_SYSTEM_PARTITION_START&&r.Lba-NUF_SYSTEM_PARTITION_START<NUF_SYSTEM_VOLUME_BLOCKS&&
        r.Blocks<=NUF_SYSTEM_VOLUME_BLOCKS-(r.Lba-NUF_SYSTEM_PARTITION_START))))return check(7,0x27,1);
  r.Flags=(c[1]&8)?NUF_SCSI_FUA:0;r.Bytes=bytes;r.Disposition=NufScsiWrite;return r;
 }
 if(c[0]==0x35||c[0]==0x91){
  if((c[0]==0x35&&n!=10)||(c[0]==0x91&&n!=16)||c[1]||direction!=NufDirectionNone||bytes)return check(5,0x24,0);
  if(c[0]==0x35){if(c[6]||c[9])return check(5,0x24,0);r.Lba=be32(c+2);r.Blocks=be16(c+7);}
  else{if(c[14]||c[15])return check(5,0x24,0);r.Lba=be64(c+2);r.Blocks=be32(c+10);}
  if(r.Lba>last||(r.Blocks&&r.Blocks-1>last-r.Lba))return check(5,0x21,0);
  /* Zero blocks means through the end, NOT a no-op. Even a clean-cache flush
   * must reach the device; the worker may synchronize a stronger whole-LUN
   * range, but must not acknowledge before that hardware request completes. */
  r.Disposition=NufScsiFlush;return r;
 }
 switch(c[0]){
 case 0x00: /* TEST UNIT READY */
  if(n!=6||c[1]||c[2]||c[3]||c[4]||c[5]||bytes)return check(5,0x24,0);return r;
 case 0x03: /* REQUEST SENSE: fixed sense, autosense already returned per error */
  if(n!=6||c[1]||c[2]||c[3]||c[5])return check(5,0x24,0);
  data[0]=0x70;data[7]=10;return reply(out,bytes,direction,data,18,c[4]);
 case 0x12: /* INQUIRY */
  if(n!=6||(c[1]&~1U)||c[3]||c[5])return check(5,0x24,0);
  allocation=c[4];
  if(!(c[1]&1)){if(c[2])return check(5,0x24,0);
   data[0]=0;data[2]=6;data[3]=2;data[4]=31;
   memcpy(data+8,"N976N   ",8);memcpy(data+16,"UFS SCOPED RW   ",16);memcpy(data+32,"0085",4);size=36;
  }else if(c[2]==0){data[1]=0;data[3]=3;data[4]=0;data[5]=0x80;data[6]=0x83;size=7;}
  else if(c[2]==0x80){static const char serial[]="N976N-UFS-LUN0";data[1]=0x80;data[3]=sizeof(serial)-1;memcpy(data+4,serial,sizeof(serial)-1);size=4+sizeof(serial)-1;}
  else if(c[2]==0x83){static const char id[]="N976N   N976N-UFS-LUN0";data[1]=0x83;data[3]=4+sizeof(id)-1;data[4]=2;data[5]=1;data[7]=sizeof(id)-1;memcpy(data+8,id,sizeof(id)-1);size=8+sizeof(id)-1;}
  else return check(5,0x24,0);
  return reply(out,bytes,direction,data,size,allocation);
 case 0x25: /* READ CAPACITY10; geometry physically checked at initialization */
  if(n!=10||c[1]||be32(c+2)||c[6]||c[7]||c[8]||c[9])return check(5,0x24,0);
  put32(data,(U32)last);put32(data+4,NUF_BLOCK_BYTES);return reply(out,bytes,direction,data,8,8);
 case 0x9E: /* SERVICE ACTION IN16: READ CAPACITY16 only */
  if(n!=16||c[1]!=0x10||be64(c+2)||c[14]||c[15])return check(5,0x24,0);
  put64(data,last);put32(data+8,NUF_BLOCK_BYTES);return reply(out,bytes,direction,data,32,be32(c+10));
 case 0x1A:case 0x5A: /* MODE SENSE: write-back completion; runtime scope stays fenced.
  * WCE=1 conservatively exposes that ordinary write success need not imply
  * stable media. Explicit barriers and write FUA are honored by real flushes.
  * Do not claim RCD or DPO/FUA capability for reads. MODE SELECT
  * remains refused: this policy cannot be changed by a caller. */
  if((c[0]==0x1A&&n!=6)||(c[0]==0x5A&&n!=10)||(c[1]&~8U)||c[3])return check(5,0x24,0);
  if(c[0]==0x1A){if(c[5])return check(5,0x24,0);allocation=c[4];header=4;}
  else{if(c[4]||c[5]||c[6]||c[9])return check(5,0x24,0);allocation=be16(c+7);header=8;}
  pc=c[2]>>6;page=c[2]&63;if((pc!=0&&pc!=2)||(page!=8&&page!=0x3F))return check(5,0x24,0);
  dbd=c[1]&8;size=header;
  if(!dbd){U32 blocks=last+1>0xFFFFFFULL?0xFFFFFFU:(U32)(last+1);data[size+1]=(U8)(blocks>>16);data[size+2]=(U8)(blocks>>8);data[size+3]=(U8)blocks;data[size+6]=0x10;size+=8;}
  data[size]=8;data[size+1]=18;data[size+2]=4;size+=20;
  if(header==4){data[0]=(U8)(size-1);data[2]=0;data[3]=dbd?0:8;}
  else{put16(data,size-2);data[3]=0;put16(data+6,dbd?0:8);}
  return reply(out,bytes,direction,data,size,allocation);
 case 0xA0: /* REPORT LUNS: this adapter exposes only real LUN0 */
  if(n!=12||c[1]||c[2]||c[3]||c[4]||c[5]||c[10]||c[11])return check(5,0x24,0);
  put32(data,8);return reply(out,bytes,direction,data,16,be32(c+6));
 case 0x08: /* READ6 */
  if(n!=6||(c[1]&0xE0)||c[5])return check(5,0x24,0);
  r.Lba=((U32)(c[1]&31)<<16)|((U32)c[2]<<8)|c[3];r.Blocks=c[4]?c[4]:256;break;
 case 0x28: /* READ10: do not silently discard physical cache-control semantics */
  if(n!=10||c[1]||c[6]||c[9])return check(5,0x24,0);
  r.Lba=be32(c+2);r.Blocks=be16(c+7);break;
 case 0xA8: /* READ12 */
  if(n!=12||c[1]||c[10]||c[11])return check(5,0x24,0);
  r.Lba=be32(c+2);r.Blocks=be32(c+6);break;
 case 0x88: /* READ16, translated only after full range validation */
  if(n!=16||c[1]||c[14]||c[15])return check(5,0x24,0);
  r.Lba=be64(c+2);r.Blocks=be32(c+10);break;
 default:return check(5,0x20,0);
 }
 if(!r.Blocks){if(bytes)return check(5,0x24,0);return r;}
 if(direction!=NufDirectionIn)return check(5,0x24,0);
 if(r.Lba>last||r.Blocks-1>last-r.Lba)return check(5,0x21,0);
 if(!data_span(out,r.Blocks,bytes))return check(5,0x24,0);
 r.Bytes=bytes;r.Disposition=NufScsiRead;return r;
}
