/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * Read-only compatibility view, never on-media repair. A valid GPT1.0 header
 * whose extension/reserved bytes are all zero is returned with the standard
 * 92-byte field set. Only HeaderSize and HeaderCRC32 change in the CPU output.
 */
#include "N976nUfsGptView.h"
#include <string.h>
static U32 Le32(const U8 *p){return (U32)p[0]|((U32)p[1]<<8)|((U32)p[2]<<16)|((U32)p[3]<<24);}
static U64 Le64(const U8 *p){return (U64)Le32(p)|((U64)Le32(p+4)<<32);}
static void Put32(U8 *p,U32 v){for(unsigned i=0;i<4;i++)p[i]=(U8)(v>>(i*8));}
static U32 HeaderCrc(const U8 *p,U32 size,U32 replacementSize){
 U32 crc=~0U;for(U32 i=0;i<size;i++){
  U8 b=(i>=16&&i<20)?0:p[i];
  if(replacementSize&&i>=12&&i<16)b=(U8)(replacementSize>>((i-12)*8));
  crc^=b;for(unsigned bit=0;bit<8;bit++)crc=(crc>>1)^(0xEDB88320U&((U32)0-(crc&1U)));
 }return ~crc;
}
static int Refuse(NUF_GPT_VIEW_SNAPSHOT *s,U32 why){if(s)s->Reason=why;return 0;}
int NufGptView(U8 *p,U32 bytes,U64 lba,U64 last,NUF_GPT_VIEW_SNAPSHOT *s){
 if(!s)return 0;memset(s,0,sizeof(*s));s->Lba=lba;
 if(!p||bytes!=NUF_BLOCK_BYTES||last<11||last>=0xFFFFFFFFULL||lba>last)return Refuse(s,NufViewArgument);
 if(lba!=1&&lba!=last)return 1; /* Never scan signatures at other addresses. */
 s->Seen=1;s->Checks=1;
 s->OriginalSize=Le32(p+12);s->OriginalCrc=Le32(p+16);
 s->MyLba=Le64(p+24);s->AlternateLba=Le64(p+32);s->FirstUsable=Le64(p+40);s->LastUsable=Le64(p+48);
 memcpy(s->DiskGuid,p+56,16);s->EntryLba=Le64(p+72);s->EntryCount=Le32(p+80);s->EntrySize=Le32(p+84);s->ArrayCrc=Le32(p+88);
 if(memcmp(p,"EFI PART",8))return Refuse(s,NufViewSignature);
 if(Le32(p+8)!=0x00010000U)return Refuse(s,NufViewRevision);s->Checks|=2;
 if(s->OriginalSize<92||s->OriginalSize>NUF_BLOCK_BYTES)return Refuse(s,NufViewSize);s->Checks|=4;
 s->ComputedCrc=HeaderCrc(p,s->OriginalSize,0);
 if(s->ComputedCrc!=s->OriginalCrc)return Refuse(s,NufViewCrc);s->Checks|=8;
 if(Le32(p+20))return Refuse(s,NufViewReserved);
 for(U32 i=92;i<NUF_BLOCK_BYTES;i++)if(p[i])return Refuse(s,NufViewReserved);s->Checks|=16;
 if(s->MyLba!=lba||s->AlternateLba!=(lba==1?last:1))return Refuse(s,NufViewLocation);
 U32 any=0;for(unsigned i=0;i<16;i++)any|=s->DiskGuid[i];if(!any)return Refuse(s,NufViewLocation);s->Checks|=32;
 if(s->FirstUsable<6||s->FirstUsable>s->LastUsable||s->LastUsable>last-5)return Refuse(s,NufViewUsable);s->Checks|=64;
 /* Existing admitted GPT reader has at most128 128-byte entries, four4KiB
  * array blocks per copy. Keep that contract; do not enlarge it for this view. */
 if(!s->EntryCount||s->EntryCount>128||s->EntrySize!=128)return Refuse(s,NufViewEntries);
 U64 blocks=((U64)s->EntryCount*128+NUF_BLOCK_BYTES-1)/NUF_BLOCK_BYTES;
 if(lba==1){if(s->EntryLba<2||s->EntryLba>5||blocks>6-s->EntryLba||s->EntryLba>=s->FirstUsable||blocks>s->FirstUsable-s->EntryLba)return Refuse(s,NufViewExtent);}
 else if(s->EntryLba<last-4||s->EntryLba>=last||blocks>last-s->EntryLba||s->EntryLba<=s->LastUsable)return Refuse(s,NufViewExtent);
 s->Checks|=128;s->ReturnedSize=92;s->ReturnedCrc=HeaderCrc(p,92,92);
 /* All validation is complete. No speculative writes, even temporary CRC
  * zeroing, have touched the source before this point. */
 if(s->OriginalSize!=92){Put32(p+12,92);Put32(p+16,s->ReturnedCrc);}
 return 1;
}
