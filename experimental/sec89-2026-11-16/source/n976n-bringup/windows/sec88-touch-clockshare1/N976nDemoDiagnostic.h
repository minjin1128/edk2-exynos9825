/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 FIX2 bounded first-refusal operands, shared with the native viewer.
 * This record grants no access. Valid is written last, then never modified.
 * Registry publication is one fixed-size REG_BINARY value, not a live MMIO dump.
 */
#ifndef N976N_DEMO_DIAGNOSTIC_H
#define N976N_DEMO_DIAGNOSTIC_H
#define N976N_DIAGNOSTIC_VALID 0x32444754U
#define N976N_DIAGNOSTIC_VERSION 1U
enum { N976nDiagResource=1, N976nDiagMap=2, N976nDiagNvs=3,
       N976nDiagShape=4, N976nDiagClock=5, N976nDiagFresh=6, N976nDiagClaim=7 };
enum { N976nWhyCount=1, N976nWhyOwner, N976nWhyDescriptor, N976nWhyType,
       N976nWhyShare, N976nWhyFlagsPair, N976nWhyFlagsMask,
       N976nWhyBasePair, N976nWhyLengthPair, N976nWhyPositiveBase,
       N976nWhyBase, N976nWhyLength, N976nWhyAlignment, N976nWhyRange,
       N976nWhyWritable, N976nWhyMap, N976nWhySnapshot, N976nWhyPageGuard,
       N976nWhyReady, N976nWhyField, N976nWhyCrc, N976nWhyClockWord,
       N976nWhyClockReuse, N976nWhyClockMissing, N976nWhyClockRate,
       N976nWhyGate, N976nWhyPll, N976nWhyTiming, N976nWhyRead,
       N976nWhyEqual, N976nWhyMasked, N976nWhyIdle, N976nWhyAtomic };
#pragma pack(push,8)
typedef struct {
    unsigned int Version,Bytes,Bucket,Condition,Index,Offset,MappedCount,ReadOk;
    unsigned long long Expected,Actual,Mask;
    unsigned int RawType,RawShare,RawFlags,RawLength;
    unsigned long long RawStart;
    unsigned int TransType,TransShare,TransFlags,TransLength;
    unsigned long long TransStart;
    unsigned int RawCount,TransCount,Valid,Reserved;
} N976N_DEMO_DIAGNOSTIC;
#pragma pack(pop)
#endif
