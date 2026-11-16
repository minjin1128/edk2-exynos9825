/* SPDX-License-Identifier: BSD-2-Clause-Patent
 * SEC85 UFS FIX1: immutable CPU-only GPT read view; never writes media.
 * No CRT, allocation, platform headers or hardware access. Caller supplies
 * freshly authenticated raw GPT snapshots and NTFS-backed policy. */
#ifndef N976N_GPT_VOLUME_VIEW_H
#define N976N_GPT_VOLUME_VIEW_H
typedef unsigned char NV_U8;
typedef unsigned int NV_U32;
typedef unsigned long long NV_U64;
typedef char NvWidthCheck[(sizeof(NV_U8)==1&&sizeof(NV_U32)==4&&sizeof(NV_U64)==8)?1:-1];
typedef struct {NV_U8 DiskGuid[16],PartitionGuid[16];NV_U64 Start,RawBlocks,ViewBlocks;} NUV_POLICY;
enum {NuvOk=0,NuvArgument=1,NuvCapture=2,NuvHeader=3,NuvArray=4,NuvIdentity=5,NuvExtent=6,NuvDrift=7,NuvUnsealed=8};
typedef struct {
 NV_U32 Ready,Reason,Mask,EntryCount,ArrayBlocks,TargetIndex,ViewArrayCrc;
 NV_U64 LastLba,EntryLba[2];NV_U32 HeaderCrc[2];NUV_POLICY Policy;
 NV_U8 Header[2][4096],Array[2][16384];
} NUV_VIEW;
void NuvViewReset(NUV_VIEW *);
/* Capture headers1/last and reserved arrays2..5/last-4..last-1; other
 * LBAs are rejected. Repeat capture must match exactly. No post-seal mutation. */
int NuvViewCapture(NUV_VIEW *,NV_U64 last,NV_U64 lba,const void *,NV_U32 bytes);
int NuvViewSeal(NUV_VIEW *,const NUV_POLICY *);
/* Return1 for a sealed header/actual array block. Others remain raw. */
int NuvViewContains(const NUV_VIEW *,NV_U64 lba);
/* Input must be a fresh 4096-byte read of the specified LBA. Exact raw
 * snapshot comparison precedes mutation. Failure leaves input unchanged.
 * HeaderSize=92, USERDATA end and both CRCs form one consistent view.
 * Other partitions, identity, attributes, usable range and padding unchanged. */
int NuvViewApply(const NUV_VIEW *,NV_U64 lba,void *,NV_U32 bytes,NV_U32 *changed);
#endif
