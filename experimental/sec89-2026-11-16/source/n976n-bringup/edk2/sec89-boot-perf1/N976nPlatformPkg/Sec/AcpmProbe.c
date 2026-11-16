/* SPDX-License-Identifier: MIT
 * Bounded SEC observation of the Samsung ACPM mailbox/shared SRAM ABI.
 * No guessed physical queue addresses: firmware offsets are admitted before
 * dereference. The queue transport is distinct from a PMIC-register write.
 */
#include <N976nAcpm.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/IoLib.h>

#define FW_WORDS 24U
#define CHANNEL_WORDS 18U
#define MAX_CHANNELS 32U
#define MAX_AP_CHANNELS 16U
#define MAX_QUEUE_LENGTH 64U
#define FW_BYTES 188U
#define INTGR0 0x08U
#define INTSR0 0x14U
#define INTCR1 0x20U
#define INTGR1 0x1CU
#define INTMR1 0x24U
#define INTSR1 0x28U
#define CHANNEL_BIT 4U
#define TX_PENDING (CHANNEL_BIT << 16)

typedef struct {
  UINT32 Framework[FW_WORDS];
  UINT32 Channel[MAX_CHANNELS][CHANNEL_WORDS];
  UINT32 Plugin[32][4];
  UINT32 Count, Selected;
  UINT32 TxRear, TxFront, TxBase, RxRear, RxFront, RxBase, Length;
  UINT32 SelectedMask;
  BOOLEAN MaskAcquired;
  UINT64 ExcludedSequences;
} ACPM_LAYOUT;

STATIC UINT64 AcpmCounter (VOID);

STATIC BOOLEAN Range (UINT64 Offset, UINT64 Bytes)
{
  return !(Offset & 3) && Offset < N976N_ACPM_SRAM_BYTES &&
    Bytes && !(Bytes & 3) && Bytes <= N976N_ACPM_SRAM_BYTES - Offset;
}

STATIC BOOLEAN Overlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return A < B + M && B < A + N; }

STATIC UINT32 Read (N976N_ACPM_SNAPSHOT *R, UINTN Address)
{
  R->ReadCount++;
  UINT32 V = MmioRead32 (Address);
  MemoryFence ();
  return V;
}

STATIC UINT32 SramRead (N976N_ACPM_SNAPSHOT *R, UINT32 Offset)
{ return Read (R, N976N_ACPM_SRAM + Offset); }

STATIC VOID Write (N976N_ACPM_SNAPSHOT *R, UINTN Address, UINT32 Value)
{
  R->WriteCount++;
  MmioWrite32(Address,Value);
  MemoryFence();
}

STATIC VOID Fail (N976N_ACPM_SNAPSHOT *R, UINT64 Reason, EFI_STATUS Status,
  UINT64 Offset)
{
  if (R->PowerMode && R->PowerPhase==7 && !R->PowerRestoreReason) {
    R->PowerRestoreReason=Reason;R->PowerRestoreStatus=Status;
  }
  if (!R->Reason) {
    R->Reason = Reason; R->Status = Status; R->FailureOffset = Offset;
  }
}

STATIC BOOLEAN Admission (CONST N976N_ACPM_ADMISSION *A)
{
  return A && A->Magic == N976N_ACPM_ADMISSION_MAGIC && A->Version == 1 &&
    A->Size == sizeof (*A) && A->Profile <= N976N_PLATFORM_PROFILE_QEMU &&
    A->Admitted == 1 && A->Checks == N976N_ACPM_ADMISSION_CHECKS && !A->Reason &&
    A->Mailbox == N976N_ACPM_MAILBOX && A->MailboxBytes == N976N_ACPM_MAILBOX_BYTES &&
    A->Sram == N976N_ACPM_SRAM && A->SramBytes == N976N_ACPM_SRAM_BYTES &&
    A->InitOffset == N976N_ACPM_INIT && A->Channel == 2 && A->PmicType == 1 &&
    !A->SpeedyChannel && A->ReadRegisters == 0x6058;
}

STATIC VOID PluginDiagnostic (N976N_ACPM_SNAPSHOT *R, UINTN Index,
  CONST UINT32 *P)
{
  R->PluginEntry=Index+1;
  R->PluginBaseSize=((UINT64)P[0]<<32)|P[1];
  R->PluginAttach=((UINT64)P[3]<<32)|P[2];
}

STATIC BOOLEAN Metadata (ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R)
{
  UINT32 *F = L->Framework;
  for (UINTN I = 0; I < FW_WORDS; I++)
    F[I] = SramRead (R, N976N_ACPM_INIT + 4 * I);
  R->FrameworkChannels = F[2];
  R->FrameworkCounts = ((UINT64)F[3] << 32) | F[6];
  R->PluginTableCount = ((UINT64)F[1]<<32)|F[0];
  if (!F[3] || F[3] > MAX_CHANNELS || !F[6] ||
      F[6] > MAX_AP_CHANNELS || F[6] > F[3] ||
      !Range (F[2], (UINT64)F[3] * CHANNEL_WORDS * 4) ||
      Overlap (F[2], (UINT64)F[3] * CHANNEL_WORDS * 4,
        N976N_ACPM_INIT, FW_BYTES)) {
    Fail (R, 0x723, EFI_UNSUPPORTED, F[2]); return FALSE;
  }
  L->Count = F[3]; L->Selected = MAX_UINT32;
  for (UINTN I = 0; I < L->Count; I++) {
    for (UINTN J = 0; J < CHANNEL_WORDS; J++)
      L->Channel[I][J] = SramRead (R, F[2] + I * CHANNEL_WORDS * 4 + J * 4);
    if (I < F[6]) {
      UINT32 Id = L->Channel[I][0];
      if (Id >= 16) {
        Fail (R, 0x724, EFI_UNSUPPORTED, F[2] + I * 72); return FALSE;
      }
      for (UINTN J = 0; J < I; J++)
        if (Id == L->Channel[J][0]) {
          Fail (R, 0x724, EFI_UNSUPPORTED, F[2] + I * 72); return FALSE;
        }
      if (Id == 2) L->Selected = I;
    }
  }
  if (L->Selected == MAX_UINT32) {
    Fail (R, 0x724, EFI_NOT_FOUND, F[2]); return FALSE;
  }
  if (F[1]>32 || (F[1] && !Range(F[0],(UINT64)F[1]*48))) {
    Fail(R,0x723,EFI_UNSUPPORTED,F[0]);return FALSE;
  }
  for (UINTN I=0;I<F[1];I++) {
    L->Plugin[I][0]=SramRead(R,F[0]+I*48+4);
    L->Plugin[I][1]=SramRead(R,F[0]+I*48+36);
    L->Plugin[I][2]=SramRead(R,F[0]+I*48+32);
    L->Plugin[I][3]=SramRead(R,F[0]+I*48+40);
    PluginDiagnostic(R,I,L->Plugin[I]);
    /* Plugin loader policy does not admit IPC storage. Size0 declares no
     * image extent, regardless of raw base/attachment bytes; do not follow
     * that base or invent a length. Protect every declared nonempty span. */
    UINT32 Base=L->Plugin[I][0]&~1U, Bytes=L->Plugin[I][1];
    if (Bytes && (Base>=N976N_ACPM_SRAM_BYTES ||
        Bytes>N976N_ACPM_SRAM_BYTES-Base)) {
      Fail(R,0x723,EFI_UNSUPPORTED,F[0]+I*48);return FALSE;
    }
  }
  UINT32 *C = L->Channel[L->Selected];
  R->ChannelOffset = F[2] + L->Selected * 72;
  R->ChannelInfo = ((UINT64)C[1] << 32) | ((UINT64)(C[17]!=0) << 16) |
    ((UINT64)C[3] << 8) | C[0];
  R->QueueInfo = ((UINT64)C[13] << 32) | C[14];
  R->QueueBases = ((UINT64)C[6] << 32) | C[12];
  R->IndexOffsets[0] = ((UINT64)C[4] << 32) | C[5];
  R->IndexOffsets[1] = ((UINT64)C[10] << 32) | C[11];
  if (C[3] != 1 || !C[17] || C[14] != 16 ||
      C[13] < 2 || C[13] > MAX_QUEUE_LENGTH) {
    Fail (R, 0x724, EFI_UNSUPPORTED, R->ChannelOffset); return FALSE;
  }
  L->TxRear=C[4]; L->TxFront=C[5]; L->TxBase=C[6];
  L->RxRear=C[10]; L->RxFront=C[11]; L->RxBase=C[12]; L->Length=C[13];
  R->Checks |= ACPM_CHECK_METADATA;
  return TRUE;
}

/* Capture only metadata already read through admitted descriptor ranges.
 * The rejected pointer is never followed to obtain diagnostic context. */
STATIC BOOLEAN LayoutFail (CONST ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R,
  UINT64 Check, UINT64 Source, UINTN Owner, UINTN Word, UINT64 Span,
  UINT64 Other, UINT64 OtherBytes, UINTN Selected)
{
  if (R->Reason) return FALSE;
  UINTN Channel=L->Selected;
  R->LayoutCheck=Check; R->LayoutSource=Source; R->LayoutOwner=Owner;
  R->LayoutSpan=Span; R->LayoutOther=Other; R->LayoutOtherBytes=OtherBytes;
  R->LayoutSelected=Selected+1;
  if (Source==ACPM_SOURCE_FRAMEWORK) {
    R->LayoutField=N976N_ACPM_INIT+Word*4;
    R->LayoutRaw=L->Framework[Word];
  } else if (Source==ACPM_SOURCE_CHANNEL) {
    Channel=Owner-1;
    R->LayoutField=L->Framework[2]+Channel*72+Word*4;
    R->LayoutRaw=L->Channel[Channel][Word];
  } else {
    /* Only a nonempty plugin image overlap reaches Layout; bounds were
     * checked in Metadata. Preserve its raw Thumb pointer separately. */
    PluginDiagnostic(R,Owner-1,L->Plugin[Owner-1]);
    R->LayoutField=L->Framework[0]+(Owner-1)*48+4;
    R->LayoutRaw=L->Plugin[Owner-1][0];
  }
  R->LayoutChannelEntry=Channel+1;
  for (UINTN I=0;I<FW_WORDS;I++) R->LayoutFramework[I]=L->Framework[I];
  for (UINTN I=0;I<CHANNEL_WORDS;I++) R->LayoutChannel[I]=L->Channel[Channel][I];
  Fail(R,0x724,EFI_UNSUPPORTED,Source==ACPM_SOURCE_PLUGIN?
    R->LayoutRaw&~1ULL:R->LayoutRaw);
  return FALSE;
}

/* SRAM storage bounds/exclusion. Register BUFFER spans are classified
 * separately and never passed to SramRead or interpreted as queue indices. */
STATIC BOOLEAN Exclude (CONST ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R,
  UINTN Selected, UINT64 Source, UINTN Owner, UINTN Word,
  UINT64 Base, UINT64 Bytes, UINT64 Target, UINT64 TargetBytes)
{
  if (!Range(Base,Bytes))
    return LayoutFail(L,R,ACPM_LAYOUT_RANGE,Source,Owner,Word,Bytes,0,0,Selected);
  if (Overlap(Target,TargetBytes,Base,Bytes))
    return LayoutFail(L,R,ACPM_LAYOUT_OVERLAP,Source,Owner,Word,Bytes,
      Target,TargetBytes,Selected);
  return TRUE;
}

/* No unvalidated firmware offset is followed. Selected rings and indices must
 * not alias one another, framework/descriptor metadata, or another channel.
 * A nonselected register BUFFER must be wholly in a known mailbox storage
 * envelope, disjoint from SRAM and our mailbox interrupt controls. The exact
 * AP resource and inferred observed-peer envelope have different bounds.
 * AP-prefix transfer selection does not remove non-AP storage from this scan.
 * This is an
 * exclusion decision only; no translated pointer is formed or followed. */
STATIC BOOLEAN Layout (CONST ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R)
{
  CONST UINTN Words[6]={4,5,6,10,11,12};
  CONST UINT32 Off[6]={L->TxRear,L->TxFront,L->TxBase,L->RxRear,L->RxFront,L->RxBase};
  CONST UINT32 Bytes[6]={4,4,L->Length*16,4,4,L->Length*16};
  CONST UINT32 *F=L->Framework;
  for (UINTN I=0;I<6;I++) {
    if (!Range(Off[I],Bytes[I]))
      return LayoutFail(L,R,ACPM_LAYOUT_RANGE,ACPM_SOURCE_CHANNEL,
        L->Selected+1,Words[I],Bytes[I],0,0,I);
    if (Overlap(Off[I],Bytes[I],N976N_ACPM_INIT,FW_BYTES))
      return LayoutFail(L,R,ACPM_LAYOUT_OVERLAP,ACPM_SOURCE_CHANNEL,
        L->Selected+1,Words[I],Bytes[I],N976N_ACPM_INIT,FW_BYTES,I);
    if (Overlap(Off[I],Bytes[I],F[2],L->Count*72))
      return LayoutFail(L,R,ACPM_LAYOUT_OVERLAP,ACPM_SOURCE_CHANNEL,
        L->Selected+1,Words[I],Bytes[I],F[2],L->Count*72,I);
    for (UINTN J=0;J<I;J++) if (Overlap(Off[I],Bytes[I],Off[J],Bytes[J]))
      return LayoutFail(L,R,ACPM_LAYOUT_OVERLAP,ACPM_SOURCE_CHANNEL,
        L->Selected+1,Words[I],Bytes[I],Off[J],Bytes[J],I);
    if (!Exclude(L,R,I,ACPM_SOURCE_FRAMEWORK,0,12,F[12],4,Off[I],Bytes[I]))
      return FALSE;
    if (F[1]) {
      /* Framework and descriptor-array geometry was admitted by Metadata. */
      if (!Exclude(L,R,I,ACPM_SOURCE_FRAMEWORK,0,0,F[0],(UINT64)F[1]*48,
          Off[I],Bytes[I])) return FALSE;
      for (UINTN J=0;J<F[1];J++)
        if (L->Plugin[J][1] &&
            Overlap(Off[I],Bytes[I],L->Plugin[J][0]&~1U,L->Plugin[J][1]))
          return LayoutFail(L,R,ACPM_LAYOUT_OVERLAP,ACPM_SOURCE_PLUGIN,
            J+1,1,L->Plugin[J][1],Off[I],Bytes[I],I);
    }
    if (F[13] || F[14] || F[15] || F[16] || F[17]) {
      if (!Exclude(L,R,I,ACPM_SOURCE_FRAMEWORK,0,13,F[13],4,Off[I],Bytes[I]) ||
          !Exclude(L,R,I,ACPM_SOURCE_FRAMEWORK,0,14,F[14],4,Off[I],Bytes[I]) ||
          !Exclude(L,R,I,ACPM_SOURCE_FRAMEWORK,0,15,F[15],(UINT64)F[16]*F[17],
            Off[I],Bytes[I])) return FALSE;
    }
    for (UINTN J=0;J<L->Count;J++) {
      CONST UINT32 *C=L->Channel[J];
      if (C[3]!=1 && C[3]!=2)
        return LayoutFail(L,R,ACPM_LAYOUT_TYPE,ACPM_SOURCE_CHANNEL,J+1,3,0,0,0,I);
      if (C[9] && !Exclude(L,R,I,ACPM_SOURCE_CHANNEL,J+1,7,C[7],C[9],
          Off[I],Bytes[I])) return FALSE;
      if (J==L->Selected) continue;
      if (C[3]==2) {
        UINTN BadWord, Domain=N976nAcpmBufferDomain(C,&BadWord);
        if (!Domain)
          return LayoutFail(L,R,ACPM_LAYOUT_DOMAIN,ACPM_SOURCE_CHANNEL,J+1,
            BadWord,BadWord==16?0:BadWord==12?C[14]:(UINT64)C[13]*C[14],0,0,I);
        /* BUFFER receive is one declared BYTE element, not an RX ring.
         * Domain already bounded each full SRAM span; round its exclusion
         * outward to whole words without granting a transfer. This reserves
         * at least the declared footprint even for a non-word-sized endpoint
         * that the generic AP copy helper cannot operate. Never infer size*4.
         * Mailbox payloads cannot alias SRAM; TX indices/indirection remain. */
        UINT64 RxExcluded=N976nAcpmBufferProtectedBytes(C[14]);
        UINT64 TxExcluded=N976nAcpmBufferProtectedBytes((UINT64)C[13]*C[14]);
        if (Domain==ACPM_BUFFER_SRAM &&
            !Exclude(L,R,I,ACPM_SOURCE_CHANNEL,J+1,12,C[12],RxExcluded,
              Off[I],Bytes[I])) return FALSE;
        if (C[13]) {
          CONST UINTN TxWords[3]={4,5,6};
          for (UINTN K=0;K<(Domain==ACPM_BUFFER_SRAM?3U:2U);K++)
            if (!Exclude(L,R,I,ACPM_SOURCE_CHANNEL,J+1,TxWords[K],C[TxWords[K]],
                K==2?TxExcluded:4,Off[I],Bytes[I])) return FALSE;
        }
        continue;
      }
      UINT64 RingBytes=(UINT64)C[13]*C[14];
      if (!C[13] || !C[14] || RingBytes>N976N_ACPM_SRAM_BYTES)
        return LayoutFail(L,R,ACPM_LAYOUT_GEOMETRY,ACPM_SOURCE_CHANNEL,
          J+1,!C[13]?13:!C[14]?14:13,RingBytes,0,0,I);
      for (UINTN K=0;K<6;K++)
        if (!Exclude(L,R,I,ACPM_SOURCE_CHANNEL,J+1,Words[K],C[Words[K]],
            (K==2 || K==5)?RingBytes:4,Off[I],Bytes[I])) return FALSE;
    }
  }
  R->Checks|=ACPM_CHECK_LAYOUT;
  return TRUE;
}

STATIC BOOLEAN Stable (CONST ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R)
{
  /* Compare only metadata used to admit accesses, not unrelated live framework
   * fields or firmware-managed channel credit. */
  CONST UINTN Fi[]={0,1,2,3,6,12,13,14,15,16,17};
  for (UINTN I=0; I<sizeof(Fi)/sizeof(Fi[0]); I++)
    if (SramRead(R,N976N_ACPM_INIT+Fi[I]*4)!=L->Framework[Fi[I]]) return FALSE;
  CONST UINTN Qi[]={3,9,12,13,14};
  for (UINTN I=0; I<L->Count; I++) {
    CONST UINT32 *C=L->Channel[I];
    UINT32 At=L->Framework[2]+I*72;
    for (UINTN J=0; J<sizeof(Qi)/sizeof(Qi[0]); J++)
      if (SramRead(R,At+Qi[J]*4)!=C[Qi[J]]) return FALSE;
    if (I<L->Framework[6] && SramRead(R,At)!=C[0]) return FALSE;
    /* Freeze the footprint actually admitted for this type. Geometry still
     * freezes absent resources: length/size0 becoming nonzero must refuse. */
    if (C[3]==1 || C[13])
      for (UINTN J=4;J<=6;J++)
        if (SramRead(R,At+J*4)!=C[J]) return FALSE;
    if (C[3]==1)
      for (UINTN J=10;J<=11;J++)
        if (SramRead(R,At+J*4)!=C[J]) return FALSE;
    if (C[9] && SramRead(R,At+28)!=C[7]) return FALSE;
    if (C[3]==2) {
      UINTN BadWord;
      if (N976nAcpmBufferDomain(C,&BadWord)==ACPM_BUFFER_MAILBOX &&
          SramRead(R,At+64)!=C[16]) return FALSE;
    }
    if (I==L->Selected && !SramRead(R,At+68)) return FALSE;
  }
  for (UINTN I=0;I<L->Framework[1];I++) {
    UINT32 P[4];
    P[0]=SramRead(R,L->Framework[0]+I*48+4);
    P[1]=SramRead(R,L->Framework[0]+I*48+36);
    P[2]=SramRead(R,L->Framework[0]+I*48+32);
    P[3]=SramRead(R,L->Framework[0]+I*48+40);
    PluginDiagnostic(R,I,P);
    /* Only size and a nonempty extent's base affect storage exclusion.
     * A size0 base or loader-policy change does not reassign an IPC range. */
    if (P[1]!=L->Plugin[I][1] ||
        (P[1] && ((P[0]^L->Plugin[I][0])&~1U)))
      return FALSE;
  }
  return TRUE;
}

STATIC UINT64 Pending (N976N_ACPM_SNAPSHOT *R)
{
  UINT32 A=Read(R,N976N_ACPM_MAILBOX+INTSR0);
  UINT32 B=Read(R,N976N_ACPM_MAILBOX+INTSR1);
  return ((UINT64)A<<32)|B;
}

STATIC BOOLEAN TransportFail (N976N_ACPM_SNAPSHOT *R, UINT64 Predicate)
{
  if (!R->TransportFailure) R->TransportFailure=Predicate;
  return FALSE;
}

STATIC BOOLEAN Indices (CONST ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R,
  UINT64 *Packed, UINT32 Raw[4])
{
  BOOLEAN Valid=TRUE;
  CONST UINT32 Off[]={L->TxRear,L->TxFront,L->RxRear,L->RxFront};
  *Packed=0;
  for (UINTN I=0;I<4;I++) {
    Raw[I]=SramRead(R,Off[I]);
    if (Raw[I]>=L->Length) Valid=FALSE;
  }
  if (!Valid) return FALSE;
  for (UINTN I=0;I<4;I++) *Packed|=(UINT64)Raw[I]<<(I*16);
  return TRUE;
}

/* The synchronous early SEC call keeps normal CPU exceptions masked. Follow
 * the actual9820 raw-poll client: either inherited mailbox mask is admissible,
 * but its selected bit must remain unchanged throughout this borrowed lease.
 * This does not claim exclusivity against a secure/remote firmware producer.
 * All unknown inherited work is still refused, never drained or acknowledged.
 */
STATIC BOOLEAN Observe (ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R,
  UINT64 Stage, UINT64 *Index, UINT64 *P)
{
  UINT32 Raw[4];
  BOOLEAN Valid=Indices(L,R,Index,Raw);
  *P=Pending(R);
  UINT32 Mask=Read(R,N976N_ACPM_MAILBOX+INTMR1);
  if (!R->TransportFailure) {
    if (!R->TransportSamples) {
      R->IndicesBefore=*Index;R->PendingBefore=*P;R->MaskBefore=Mask;
      CopyMem(R->RawIndicesBefore,Raw,sizeof(Raw));
    }
    R->TransportSamples++;R->TransportStage=Stage;
    R->IndicesAfter=*Index;R->PendingAfter=*P;R->MaskAfter=Mask;
    CopyMem(R->RawIndicesAfter,Raw,sizeof(Raw));
  }
  if (!Valid) {
    for (UINTN I=0;I<4;I++)
      if (Raw[I]>=L->Length) return TransportFail(R,I+1);
  }
  if (L->MaskAcquired && (Mask&CHANNEL_BIT)!=L->SelectedMask)
    return TransportFail(R,ACPM_FAIL_MASK_CHANGED);
  return TRUE;
}

STATIC BOOLEAN IdleValues (UINT64 I, UINT64 P, N976N_ACPM_SNAPSHOT *R)
{
  if ((UINT16)I!=(UINT16)(I>>16)) return TransportFail(R,ACPM_FAIL_TX_BUSY);
  if ((UINT16)(I>>32)!=(UINT16)(I>>48)) return TransportFail(R,ACPM_FAIL_RX_BUSY);
  if (P&((UINT64)TX_PENDING<<32)) return TransportFail(R,ACPM_FAIL_TX_PENDING);
  if (P&CHANNEL_BIT) return TransportFail(R,ACPM_FAIL_RX_PENDING);
  return TRUE;
}

STATIC BOOLEAN IdleStable (ACPM_LAYOUT *L, UINT64 Expected, UINT64 Stage,
  N976N_ACPM_SNAPSHOT *R)
{
  UINT64 P=0,I=0;
  if (!Observe(L,R,Stage,&I,&P)) return FALSE;
  if (I!=Expected) return TransportFail(R,ACPM_FAIL_INDEX_CHANGED);
  if (!IdleValues(I,P,R)) return FALSE;
  if (!Stable(L,R)) return TransportFail(R,ACPM_FAIL_METADATA);
  return TRUE;
}

STATIC BOOLEAN CompletionStable (ACPM_LAYOUT *L, UINT64 Expected, UINT64 Stage,
  N976N_ACPM_SNAPSHOT *R)
{
  UINT64 P=0,I=0;
  if (!Observe(L,R,Stage,&I,&P)) return FALSE;
  if (I!=Expected) return TransportFail(R,ACPM_FAIL_PROGRESS);
  if (P&((UINT64)TX_PENDING<<32)) return TransportFail(R,ACPM_FAIL_TX_PENDING);
  if (!(P&CHANNEL_BIT)) return TransportFail(R,ACPM_FAIL_COMPLETION);
  if (!Stable(L,R)) return TransportFail(R,ACPM_FAIL_METADATA);
  return TRUE;
}

STATIC BOOLEAN Sequence (ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R)
{
  UINT64 Used=L->ExcludedSequences|1;
  /* Retained slots also cover a request already dequeued by ACPM whose reply
   * has not arrived. Never restart blindly at sequence1 on an inherited ring. */
  for (UINTN I=0;I<L->Length;I++) {
    Used|=1ULL<<((SramRead(R,L->TxBase+I*16)>>16)&63);
    Used|=1ULL<<((SramRead(R,L->RxBase+I*16)>>16)&63);
  }
  L->ExcludedSequences=Used;
  for (UINTN I=1;I<64;I++) if (!(Used&(1ULL<<I))) {
    L->ExcludedSequences|=1ULL<<I;R->Sequence=I;return TRUE;
  }
  Fail(R,0x72C,EFI_NOT_READY,0);return FALSE;
}

STATIC VOID Quarantine (N976N_ACPM_SNAPSHOT *R, UINT64 Reason,
  EFI_STATUS Status, UINT64 Offset)
{
  R->Quarantined=1;R->Checks&=~ACPM_CHECK_RETIRED;R->RetireCheck=0;
  Fail(R,Reason,Status,Offset);
}

STATIC BOOLEAN Transfer (ACPM_LAYOUT *L, UINT32 Reg, UINT32 Operation,
  UINT32 Result[4], N976N_ACPM_SNAPSHOT *R)
{
  /* The only new PMIC command is UPDATE of enable[7:6] on these two admitted
   * registers. No full-register write, voltage value, other rail or DVFS API. */
  if ((Reg!=0x58 && Reg!=0x60) || R->RequestCount>=N976N_ACPM_MAX_REQUESTS ||
      (Operation && ((R->PowerMode!=1 && R->PowerMode!=2) || !(R->PowerChecks&ACPM_POWER_POLICY) ||
       (Operation&~0xC000U)!=0xC00002U ||
       (R->PowerPhase!=3 && R->PowerPhase!=4 && R->PowerPhase!=7)))) {
    Fail(R,0x737,EFI_INVALID_PARAMETER,Reg);return FALSE;
  }
  UINT64 StartIndex=R->IndicesAfter;
  if (!Sequence(L,R) || !IdleStable(L,StartIndex,ACPM_STAGE_QUERY,R)) {
    Fail(R,0x726,EFI_NOT_READY,0);return FALSE;
  }
  UINT32 Tx=(UINT16)(StartIndex>>16), Rx=(UINT16)(StartIndex>>32);
  UINT32 TxNext=(Tx+1)%L->Length, RxNext=(Rx+1)%L->Length;
  UINT32 Slot=L->TxBase+Tx*16, Saved[4];
  UINT32 Cmd[4]={ (UINT32)(R->Sequence<<16)|0x100U|Reg,Operation,0,0 };
  for (UINTN I=0;I<4;I++) Saved[I]=SramRead(R,Slot+I*4);
  if (!IdleStable(L,StartIndex,ACPM_STAGE_PAYLOAD,R)) {
    Fail(R,0x726,EFI_NOT_READY,0);return FALSE;
  }
  R->Phase=4;R->LastRegister=Reg;R->RetireCheck=0;
  for (UINTN I=0;I<4;I++) Write(R,N976N_ACPM_SRAM+Slot+I*4,Cmd[I]);
  BOOLEAN Same=TRUE;
  for (UINTN I=0;I<4;I++) if (SramRead(R,Slot+I*4)!=Cmd[I]) Same=FALSE;
  if (!Same || !IdleStable(L,StartIndex,ACPM_STAGE_PUBLISH,R)) {
    Fail(R,0x727,EFI_DEVICE_ERROR,Slot);
    /* Before producer publication, restore only this owned unused slot, and
     * only if the queues/metadata still prove no consumer can reach it. */
    if (!IdleStable(L,StartIndex,ACPM_STAGE_ROLLBACK,R)) {
      Quarantine(R,0x727,EFI_DEVICE_ERROR,Slot);return FALSE;
    }
    for (UINTN I=0;I<4;I++) Write(R,N976N_ACPM_SRAM+Slot+I*4,Saved[I]);
    Same=TRUE;
    for (UINTN I=0;I<4;I++) if (SramRead(R,Slot+I*4)!=Saved[I]) Same=FALSE;
    if (!Same || !IdleStable(L,StartIndex,ACPM_STAGE_ROLLBACK,R))
      Quarantine(R,0x727,EFI_DEVICE_ERROR,Slot);
    else R->RetireCheck=ACPM_RETIRE_ALL;
    return FALSE;
  }
  Write(R,N976N_ACPM_SRAM+L->TxFront,TxNext);
  /* Once publication was attempted, no index rollback or request retry. */
  R->RequestCount++;
  if (SramRead(R,L->TxFront)!=TxNext) {
    Quarantine(R,0x727,EFI_DEVICE_ERROR,L->TxFront);return FALSE;
  }
  UINT64 Published=0,PubPending=0;
  if (!Observe(L,R,ACPM_STAGE_PUBLISHED,&Published,&PubPending)) {
    Quarantine(R,0x727,EFI_DEVICE_ERROR,L->TxFront);return FALSE;
  }
  /* Front publication already makes the request visible to firmware. Accept
   * the same owned progress as the wait loop, even before the doorbell. */
  UINT32 Ptr=(UINT16)Published,Ptf=(UINT16)(Published>>16);
  UINT32 Prr=(UINT16)(Published>>32),Prf=(UINT16)(Published>>48);
  if (Ptf!=TxNext || Prr!=Rx || (Ptr!=Tx && Ptr!=TxNext) ||
      (Prf!=Rx && Prf!=RxNext)) {
    TransportFail(R,ACPM_FAIL_PROGRESS);
    Quarantine(R,0x727,EFI_DEVICE_ERROR,L->TxFront);return FALSE;
  }
  if (!Stable(L,R)) {
    TransportFail(R,ACPM_FAIL_METADATA);
    Quarantine(R,0x727,EFI_DEVICE_ERROR,L->TxFront);return FALSE;
  }
  Write(R,N976N_ACPM_MAILBOX+INTGR0,TX_PENDING);
  R->Phase=5;
  UINT64 Started=AcpmCounter(), Elapsed=0;
  BOOLEAN Complete=FALSE;
  for (UINTN Poll=0;Poll<N976N_ACPM_POLL_LIMIT;Poll++) {
    UINT64 Index=0,P=0;
    if (!Observe(L,R,ACPM_STAGE_WAIT,&Index,&P)) {
      Quarantine(R,0x729,EFI_DEVICE_ERROR,0);break;
    }
    UINT32 Tr=(UINT16)Index,Tf=(UINT16)(Index>>16);
    UINT32 Rr=(UINT16)(Index>>32),Rf=(UINT16)(Index>>48);
    if (Tf!=TxNext || Rr!=Rx || (Tr!=Tx && Tr!=TxNext) ||
        (Rf!=Rx && Rf!=RxNext)) {
      TransportFail(R,ACPM_FAIL_PROGRESS);
      Quarantine(R,0x729,EFI_DEVICE_ERROR,0);break;
    }
    if (Tr==TxNext && Rf==RxNext && (P&CHANNEL_BIT) &&
        !(P&((UINT64)TX_PENDING<<32))) { Complete=TRUE;break; }
    Elapsed=AcpmCounter()-Started;
    if (Elapsed>=R->CounterHz*N976N_ACPM_WAIT_US/1000000) break;
  }
  R->WaitTicks+=AcpmCounter()-Started;
  if (!Complete) {
    if (!R->TransportFailure) TransportFail(R,ACPM_FAIL_TIMEOUT);
    Quarantine(R,0x728,EFI_TIMEOUT,0);return FALSE;
  }
  UINT64 Completed=(UINT64)TxNext|((UINT64)TxNext<<16)|
    ((UINT64)Rx<<32)|((UINT64)RxNext<<48);
  if (!CompletionStable(L,Completed,ACPM_STAGE_RESPONSE,R)) {
    Quarantine(R,0x729,EFI_DEVICE_ERROR,0);return FALSE;
  }
  UINT32 Reply[4],Again[4];
  for (UINTN I=0;I<4;I++) Reply[I]=SramRead(R,L->RxBase+Rx*16+I*4);
  for (UINTN I=0;I<4;I++) Again[I]=SramRead(R,L->RxBase+Rx*16+I*4);
  for (UINTN I=0;I<4;I++) Result[I]=Reply[I];
  if (R->PowerMode) CopyMem(R->PowerLastResponse,Reply,sizeof(Reply));
  Same=TRUE;
  for (UINTN I=0;I<4;I++) if (Reply[I]!=Again[I]) Same=FALSE;
  /* Samsung's actual AP ABI matches only sequence6 and decodes status/data
   * from word1. No unsupported address echo or OWN/RSP flag claim is added.
   * Fresh ring progression and retained-tag exclusion establish ownership. */
  if (!Same || ((Reply[0]>>16)&63)!=R->Sequence) {
    TransportFail(R,ACPM_FAIL_RESPONSE);
    Quarantine(R,0x729,EFI_DEVICE_ERROR,L->RxBase+Rx*16);return FALSE;
  }
  if (!CompletionStable(L,Completed,ACPM_STAGE_CONSUME,R)) {
    Quarantine(R,0x729,EFI_DEVICE_ERROR,0);return FALSE;
  }
  R->Phase=6;
  Write(R,N976N_ACPM_SRAM+L->RxRear,RxNext);
  if (SramRead(R,L->RxRear)!=RxNext) {
    Quarantine(R,0x72B,EFI_DEVICE_ERROR,L->RxRear);return FALSE;
  }
  UINT64 Expected=(UINT64)TxNext|((UINT64)TxNext<<16)|
    ((UINT64)RxNext<<32)|((UINT64)RxNext<<48);
  if (!CompletionStable(L,Expected,ACPM_STAGE_ACK,R)) {
    Quarantine(R,0x72B,EFI_DEVICE_ERROR,0);return FALSE;
  }
  /* Clear only our channel after consuming exactly our sole response. Never
   * drain/reorder inherited data or acknowledge any other channel. */
  Write(R,N976N_ACPM_MAILBOX+INTCR1,CHANNEL_BIT);
  UINT32 NewFront=SramRead(R,L->RxFront);
  if (NewFront!=RxNext) {
    /* Actual Samsung ACK race recovery: restore the notification for newly
     * arrived data, never consume/reorder it or retry our request. */
    if (NewFront<L->Length) Write(R,N976N_ACPM_MAILBOX+INTGR1,CHANNEL_BIT);
    /* Repair the notification our ACK may have cleared before any broader
     * guard can return. Never consume the newly arrived entry. */
    UINT64 AfterClear=0,AfterPending=0;
    Observe(L,R,ACPM_STAGE_RETIRED,&AfterClear,&AfterPending);
    TransportFail(R,ACPM_FAIL_PROGRESS);
    Quarantine(R,0x72B,EFI_DEVICE_ERROR,L->RxFront);return FALSE;
  }
  if (!IdleStable(L,Expected,ACPM_STAGE_RETIRED,R)) {
    Quarantine(R,0x72B,EFI_DEVICE_ERROR,0);return FALSE;
  }
  R->RetireCheck=ACPM_RETIRE_ALL;R->ResponseCount++;
  if (Reply[1]>>24) { Fail(R,0x72A,EFI_DEVICE_ERROR,Reg);return FALSE; }
  return TRUE;
}

STATIC BOOLEAN Query (ACPM_LAYOUT *L, UINT32 Reg, UINTN Number,
  N976N_ACPM_SNAPSHOT *R)
{
  if (!Transfer(L,Reg,0,R->Response[Number],R)) return FALSE;
  R->LdoValues|=(UINT64)((R->Response[Number][1]>>8)&255)<<(Number*8);
  R->ValidValues|=1ULL<<Number;
  R->Checks|=Number?ACPM_CHECK_LDO27:ACPM_CHECK_LDO19;
  return TRUE;
}

STATIC BOOLEAN PowerFail (N976N_ACPM_SNAPSHOT *R, UINT64 Reason,
  EFI_STATUS Status)
{
  if (!R->PowerReason) {
    R->PowerReason=Reason;R->PowerStatus=Status;
    R->PowerFailureStage=R->PowerPhase;
  }
  Fail(R,Reason,Status,R->LastRegister);
  return FALSE;
}

STATIC BOOLEAN PowerTransportFailure (N976N_ACPM_SNAPSHOT *R)
{
  return PowerFail(R,R->Reason?R->Reason:0x737,
    EFI_ERROR(R->Status)?R->Status:EFI_DEVICE_ERROR);
}

STATIC BOOLEAN PowerDelay (N976N_ACPM_SNAPSHOT *R, UINT32 Microseconds)
{
  UINT64 Start=AcpmCounter(),Previous=Start,Now=Start;
  UINT64 Target=R->CounterHz*Microseconds/1000000;
  for (UINTN I=0;I<N976N_ACPM_DELAY_POLL_LIMIT;I++) {
    Now=AcpmCounter();
    if (Now<Previous) break;
    Previous=Now;
    if (Now-Start>=Target) {R->PowerWaitTicks+=Now-Start;return TRUE;}
  }
  if (Now>=Start) R->PowerWaitTicks+=Now-Start;
  return PowerFail(R,0x733,EFI_TIMEOUT);
}

STATIC BOOLEAN PowerRead (ACPM_LAYOUT *L, UINTN Rail, UINT32 *Value,
  N976N_ACPM_SNAPSHOT *R)
{
  UINT32 Reply[4]={0};
  if (!Transfer(L,Rail?0x60:0x58,0,Reply,R)) return PowerTransportFailure(R);
  *Value=(Reply[1]>>8)&255;return TRUE;
}

STATIC BOOLEAN PowerUpdate (ACPM_LAYOUT *L, UINTN Rail, UINT32 Enable,
  N976N_ACPM_SNAPSHOT *R)
{
  UINT64 Before=R->RequestCount;
  UINT32 Reply[4]={0};
  BOOLEAN Ok=Transfer(L,Rail?0x60:0x58,2U|((Enable&0xC0U)<<8)|(0xC0U<<16),Reply,R);
  if (R->RequestCount!=Before) R->PowerAttempted|=1ULL<<Rail;
  if (!Ok) return PowerTransportFailure(R);
  return TRUE;
}

STATIC BOOLEAN PowerSequenceBudget (ACPM_LAYOUT *L, N976N_ACPM_SNAPSHOT *R)
{
  UINT64 Used=L->ExcludedSequences|1;
  for (UINTN I=0;I<L->Length;I++) {
    Used|=1ULL<<((SramRead(R,L->TxBase+I*16)>>16)&63);
    Used|=1ULL<<((SramRead(R,L->RxBase+I*16)>>16)&63);
  }
  UINTN Free=0,Required=2; /* Two fresh final observations even if already on. */
  for (UINTN Rail=0;Rail<2;Rail++)
    if (!((R->LdoValues>>(Rail*8))&0xC0)) Required+=4;
  for (UINTN I=1;I<64;I++) if (!(Used&(1ULL<<I))) Free++;
  if (Free<Required) return PowerFail(R,0x731,EFI_NOT_READY);
  return TRUE;
}

STATIC BOOLEAN PowerOn (ACPM_LAYOUT *L, UINTN Rail, N976N_ACPM_SNAPSHOT *R)
{
  UINT32 Original=(UINT32)(R->LdoValues>>(Rail*8))&255,Value;
  if ((Original&0xC0)!=0xC0) {
    if (!PowerUpdate(L,Rail,0xC0,R)) return FALSE;
    R->PowerChanged|=1ULL<<Rail;
    if (!PowerRead(L,Rail,&Value,R)) return FALSE;
  } else Value=Original;
  R->PowerEnabled|=(UINT64)Value<<(Rail*8);
  R->PowerValid|=1ULL<<Rail;
  if (Value!=(Original|0xC0)) return PowerFail(R,0x732,EFI_DEVICE_ERROR);
  return TRUE;
}

STATIC BOOLEAN PowerRestoreOne (ACPM_LAYOUT *L, UINTN Rail,
  N976N_ACPM_SNAPSHOT *R)
{
  UINT32 Original=(UINT32)(R->LdoValues>>(Rail*8))&255,Value;
  /* A fresh complete byte must still be exactly the value we established.
   * A changed VSEL/enable means another actor or ambiguous hardware outcome;
   * never overwrite its policy with a stale saved full-register value. */
  if (!PowerRead(L,Rail,&Value,R)) return FALSE;
  if (Value!=(Original|0xC0)) return PowerFail(R,0x735,EFI_DEVICE_ERROR);
  if (R->PowerChanged&(1ULL<<Rail)) {
    if (!PowerUpdate(L,Rail,Original&0xC0,R) ||
        !PowerRead(L,Rail,&Value,R)) return FALSE;
  }
  R->PowerRestored|=(UINT64)Value<<(Rail*8);
  R->PowerValid|=1ULL<<(Rail+2);
  if (Value!=Original) return PowerFail(R,0x736,EFI_DEVICE_ERROR);
  R->PowerRestoreMask|=1ULL<<Rail;
  return TRUE;
}

STATIC VOID PowerRun (ACPM_LAYOUT *L, N976N_ACPM_TOUCH_PROBE Callback,
  VOID *Context, N976N_ACPM_SNAPSHOT *R, BOOLEAN Retain)
{
  R->PowerPhase=2;R->PowerChecks|=ACPM_POWER_ORIGINAL;
  if (Retain && (R->LdoValues & 0xC0C0)) {
    PowerFail(R,0x760,EFI_NOT_READY);return;
  }
  for (UINTN Rail=0;Rail<2;Rail++) {
    UINT32 Mode=(UINT32)(R->LdoValues>>(Rail*8))&0xC0;
    if (Mode && Mode!=0xC0) {
      PowerFail(R,0x730,EFI_UNSUPPORTED);return;
    }
  }
  /* Restoring IO-off while inherited analog remains on would violate the
   * source-backed shutdown dependency. Refuse that contradictory takeover. */
  if (!(R->LdoValues&0xC0) && (R->LdoValues&0xC000)) {
    PowerFail(R,0x730,EFI_UNSUPPORTED);return;
  }
  R->PowerChecks|=ACPM_POWER_POLICY;
  if (!PowerSequenceBudget(L,R)) return;
  R->PowerPhase=3;
  if (!PowerOn(L,0,R)) goto Cleanup;
  if (!PowerDelay(R,1000)) goto Cleanup;
  R->PowerPhase=4;
  if (!PowerOn(L,1,R)) goto Cleanup;
  R->PowerChecks|=ACPM_POWER_ENABLED;
  R->PowerPhase=5;
  if (!PowerDelay(R,70000)) goto Cleanup;
  R->PowerChecks|=ACPM_POWER_SETTLED;
  R->PowerPhase=6;R->PowerCallbackCount=1;R->PowerChecks|=ACPM_POWER_TOUCH;
  R->PowerCallbackRetired=Callback(Context)?1:0;
  if (!R->PowerCallbackRetired) {
    PowerFail(R,0x734,EFI_NOT_READY);goto Cleanup;
  }
  R->PowerChecks|=ACPM_POWER_TOUCH_RETIRED;
  if (Retain) {
    /* Retained power is a separate state, never ACPM_POWER_RESTORED. Both
     * control bytes must still equal the VSEL-preserving values we set. */
    for (UINTN Rail=0;Rail<2;Rail++) {
      UINT32 Value;
      if (!PowerRead(L,Rail,&Value,R) ||
          Value!=(((UINT32)(R->LdoValues>>(Rail*8))&255)|0xC0)) {
        PowerFail(R,0x761,EFI_DEVICE_ERROR);return;
      }
    }
    R->PowerRestoreStatus=EFI_NOT_READY;return;
  }
Cleanup:
  R->PowerPhase=7;R->PowerRestoreStatus=EFI_NOT_READY;
  /* A possibly applied update without its matched success is ambiguous.
   * No further request or speculative power rollback is permitted. */
  if (R->Quarantined || R->TransportFailure ||
      (R->PowerAttempted&~R->PowerChanged) ||
      (R->PowerCallbackCount && !R->PowerCallbackRetired)) {
    R->PowerRestoreReason=R->PowerReason?R->PowerReason:0x737;return;
  }
  /* If L27 was never enabled, only undo L19 after fresh proof L27 remains
   * original. Otherwise normal shutdown is analog,4ms,digital. */
  for (UINTN I=0;I<2;I++) {
    UINTN Rail=1-I;
    if (!(R->PowerChanged&(1ULL<<Rail)) &&
        !(R->PowerValid&(1ULL<<Rail))) {
      UINT32 Value=0,Original=(UINT32)(R->LdoValues>>(Rail*8))&255;
      if (!PowerRead(L,Rail,&Value,R)) goto RestoreFailed;
      if (Value!=Original) {
        PowerFail(R,0x735,EFI_DEVICE_ERROR);goto RestoreFailed;
      }
      R->PowerRestored|=(UINT64)Value<<(Rail*8);
      R->PowerValid|=1ULL<<(Rail+2);R->PowerRestoreMask|=1ULL<<Rail;
    } else if (!PowerRestoreOne(L,Rail,R)) goto RestoreFailed;
    if (Rail==1 && (R->PowerChanged&2) && !PowerDelay(R,4000)) goto RestoreFailed;
  }
  R->PowerChecks|=ACPM_POWER_RESTORED;
  R->PowerRestoreStatus=EFI_SUCCESS;return;
RestoreFailed:
  if (!R->PowerRestoreReason) {
    R->PowerRestoreStatus=EFI_ERROR(R->Status)?R->Status:EFI_DEVICE_ERROR;
    R->PowerRestoreReason=R->PowerReason?R->PowerReason:0x736;
  }
}

STATIC BOOLEAN ProbeStateRetain (CONST N976N_ACPM_ADMISSION *A, BOOLEAN TouchRetired,
  UINT64 El, UINT64 Sctlr, UINT64 Daif, UINT64 CounterHz,
  N976N_ACPM_TOUCH_PROBE Callback, VOID *Context, N976N_ACPM_SNAPSHOT *R, BOOLEAN Retain)
{
  if (!R || ((UINTN)R&7) || (UINTN)R>MAX_UINTN-sizeof(*R) ||
      (A && (((UINTN)A&7) || (UINTN)A>MAX_UINTN-sizeof(*A) ||
       Overlap((UINTN)A,sizeof(*A),(UINTN)R,sizeof(*R))))) return FALSE;
  ZeroMem(R,sizeof(*R));
  R->Magic=N976N_ACPM_SNAPSHOT_MAGIC;R->Version=N976N_ACPM_SNAPSHOT_VERSION;R->Size=sizeof(*R);
  R->Profile=A?A->Profile:0;R->Phase=1;R->Status=EFI_INVALID_PARAMETER;
  R->CpuEl=El;R->CpuSctlr=Sctlr;R->CpuDaif=Daif;
  if (!Admission(A)) { Fail(R,0x720,EFI_INVALID_PARAMETER,0); return FALSE; }
  R->Checks=ACPM_CHECK_ADMISSION;
  if (!TouchRetired || El!=4 || (Sctlr&(BIT0|BIT2|BIT12|BIT25)) ||
      (Daif&0x3C0)!=0x3C0 || (A->Profile==0 && CounterHz!=26000000) ||
      (A->Profile==1 && !CounterHz)) {
    Fail(R,0x721,EFI_UNSUPPORTED,0); return FALSE;
  }
  R->Checks|=ACPM_CHECK_CPU;
  if (A->Profile==N976N_PLATFORM_PROFILE_QEMU) {
    R->Checks|=ACPM_CHECK_RETIRED;R->Phase=8;
    Fail(R,0x722,EFI_UNSUPPORTED,0);return TRUE;
  }
  R->CounterHz=CounterHz;R->Status=EFI_NOT_READY;R->Phase=2;
  if (Callback) {
    R->PowerMode=Retain?2:1;R->PowerPhase=1;R->PowerStatus=EFI_NOT_READY;
    R->PowerRestoreStatus=EFI_NOT_READY;
  }
  ACPM_LAYOUT L;ZeroMem(&L,sizeof(L));
  if (!Metadata(&L,R) || !Layout(&L,R)) goto Done;
  R->Phase=3;
  UINT64 Initial=0,InitialPending=0;
  if (!Observe(&L,R,ACPM_STAGE_ACQUIRE,&Initial,&InitialPending) ||
      !IdleValues(Initial,InitialPending,R)) {
    Fail(R,0x725,EFI_NOT_READY,0);goto Done;
  }
  L.SelectedMask=(UINT32)R->MaskBefore&CHANNEL_BIT;L.MaskAcquired=TRUE;
  if (!Stable(&L,R)) {
    TransportFail(R,ACPM_FAIL_METADATA);
    Fail(R,0x726,EFI_NOT_READY,0);goto Done;
  }
  UINT64 Recheck=0,RecheckPending=0;
  if (!Observe(&L,R,ACPM_STAGE_ACQUIRE_CHECK,&Recheck,&RecheckPending) ||
      Recheck!=Initial) {
    if (!R->TransportFailure) TransportFail(R,ACPM_FAIL_INDEX_CHANGED);
    Fail(R,0x726,EFI_NOT_READY,0);goto Done;
  }
  if (!IdleValues(Recheck,RecheckPending,R)) {
    Fail(R,0x725,EFI_NOT_READY,0);goto Done;
  }
  R->Checks|=ACPM_CHECK_IDLE;
  if (!Query(&L,0x58,0,R) || !Query(&L,0x60,1,R)) goto Done;
  if (Callback) PowerRun(&L,Callback,Context,R,Retain);
  if (!R->Reason) R->Status=EFI_SUCCESS;
Done:
  if (!R->Quarantined && (!R->WriteCount || R->RetireCheck==ACPM_RETIRE_ALL))
    R->Checks|=ACPM_CHECK_RETIRED;
  if (Callback) {
    if (R->Reason && !R->PowerReason) PowerTransportFailure(R);
    if (R->Checks&ACPM_CHECK_RETIRED) R->PowerChecks|=ACPM_POWER_TRANSPORT_RETIRED;
    if (!R->PowerReason && R->PowerChecks==(Retain ? (ACPM_POWER_ALL & ~ACPM_POWER_RESTORED) : ACPM_POWER_ALL)) R->PowerStatus=EFI_SUCCESS;
    R->PowerPhase=8;
  }
  R->Phase=8;
  return TRUE;
}

STATIC BOOLEAN ProbeStateEx (CONST N976N_ACPM_ADMISSION *A, BOOLEAN TouchRetired,
  UINT64 El, UINT64 Sctlr, UINT64 Daif, UINT64 CounterHz,
  N976N_ACPM_TOUCH_PROBE Callback, VOID *Context, N976N_ACPM_SNAPSHOT *R)
{ return ProbeStateRetain(A,TouchRetired,El,Sctlr,Daif,CounterHz,Callback,Context,R,FALSE); }

STATIC BOOLEAN ProbeState (CONST N976N_ACPM_ADMISSION *A, BOOLEAN TouchRetired,
  UINT64 El, UINT64 Sctlr, UINT64 Daif, UINT64 CounterHz, N976N_ACPM_SNAPSHOT *R)
{ return ProbeStateEx(A,TouchRetired,El,Sctlr,Daif,CounterHz,NULL,NULL,R); }

/* AArch64 entry wrapper: this routine is used only before MMU/cache activation. */
STATIC UINT64 AcpmCounter (VOID)
{ UINT64 V; __asm__ volatile ("mrs %0, cntpct_el0":"=r"(V));return V; }
BOOLEAN EFIAPI N976nProbeAcpm (
  CONST N976N_ACPM_ADMISSION *Admission, BOOLEAN TouchRetired,
  N976N_ACPM_SNAPSHOT *Snapshot)
{
  UINT64 El,Sctlr,Daif,Hz;
  __asm__ volatile ("mrs %0, CurrentEL":"=r"(El));
  __asm__ volatile ("mrs %0, sctlr_el1":"=r"(Sctlr));
  __asm__ volatile ("mrs %0, daif":"=r"(Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0":"=r"(Hz));
  return ProbeState(Admission,TouchRetired,El,Sctlr,Daif,Hz,Snapshot);
}

BOOLEAN EFIAPI N976nProbePoweredTouchAcpm (
  CONST N976N_ACPM_ADMISSION *Admission, BOOLEAN TouchRetired,
  N976N_ACPM_TOUCH_PROBE Callback, VOID *Context,
  N976N_ACPM_SNAPSHOT *Snapshot)
{
  UINT64 El,Sctlr,Daif,Hz;
  __asm__ volatile ("mrs %0, CurrentEL":"=r"(El));
  __asm__ volatile ("mrs %0, sctlr_el1":"=r"(Sctlr));
  __asm__ volatile ("mrs %0, daif":"=r"(Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0":"=r"(Hz));
  if (!Callback) return FALSE;
  return ProbeStateEx(Admission,TouchRetired,El,Sctlr,Daif,Hz,Callback,Context,Snapshot);
}

BOOLEAN EFIAPI N976nRetainTouchPowerAcpm (
  CONST N976N_ACPM_ADMISSION *Admission, BOOLEAN TouchRetired,
  N976N_ACPM_TOUCH_PROBE Callback, VOID *Context,
  N976N_ACPM_SNAPSHOT *Snapshot)
{
  UINT64 El,Sctlr,Daif,Hz;
  __asm__ volatile ("mrs %0, CurrentEL":"=r"(El));
  __asm__ volatile ("mrs %0, sctlr_el1":"=r"(Sctlr));
  __asm__ volatile ("mrs %0, daif":"=r"(Daif));
  __asm__ volatile ("mrs %0, cntfrq_el0":"=r"(Hz));
  if (!Callback) return FALSE;
  return ProbeStateRetain(Admission,TouchRetired,El,Sctlr,Daif,Hz,Callback,Context,Snapshot,TRUE);
}
