/* SPDX-License-Identifier: MIT
 * Pure validation of the frozen SEC record. Never grants device access and
 * never promotes firmware enable policy to measured voltage/pull-up presence.
 */
#include <N976nAcpmReport.h>

STATIC BOOLEAN HardwareZero (CONST N976N_ACPM_SNAPSHOT *R)
{
  CONST UINT8 *P = (CONST UINT8 *)&R->ReadCount;
  for (UINTN I=0; I<OFFSET_OF(N976N_ACPM_SNAPSHOT,PowerPhase)-OFFSET_OF(N976N_ACPM_SNAPSHOT,ReadCount); I++)
    if (P[I]) return FALSE;
  return TRUE;
}

/* Frozen provenance is descriptive only. Even an invalid pointer is shown as
 * its original u32 value; this validator never follows it or grants access. */
STATIC BOOLEAN LayoutZero (CONST N976N_ACPM_SNAPSHOT *R)
{
  CONST UINT8 *P = (CONST UINT8 *)&R->LayoutCheck;
  for (UINTN I=0; I<OFFSET_OF(N976N_ACPM_SNAPSHOT,TransportStage)-
      OFFSET_OF(N976N_ACPM_SNAPSHOT,LayoutCheck); I++)
    if (P[I]) return FALSE;
  return TRUE;
}

STATIC BOOLEAN TransportZero (CONST N976N_ACPM_SNAPSHOT *R)
{
  CONST UINT8 *P=(CONST UINT8 *)&R->TransportStage;
  for (UINTN I=0; I<OFFSET_OF(N976N_ACPM_SNAPSHOT,PowerPhase)-OFFSET_OF(N976N_ACPM_SNAPSHOT,TransportStage); I++)
    if (P[I]) return FALSE;
  return TRUE;
}

STATIC BOOLEAN RawIndicesValid (CONST UINT32 *V, UINT64 Len)
{
  return V[0]<Len && V[1]<Len && V[2]<Len && V[3]<Len;
}

STATIC UINT64 RawIndicesPacked (CONST UINT32 *V, UINT64 Len)
{
  if (!RawIndicesValid(V,Len)) return 0;
  return (UINT64)V[0]|((UINT64)V[1]<<16)|((UINT64)V[2]<<32)|((UINT64)V[3]<<48);
}

/* This validates only the frozen diagnostic contract, never live ownership.
 * The first transport guard freezes all operands together. A legacy error
 * such as PMIC status or write readback may have no separate guard code. */
STATIC BOOLEAN TransportDetailValid (CONST N976N_ACPM_SNAPSHOT *R)
{
  if (!(R->Checks&ACPM_CHECK_LAYOUT)) return TransportZero(R);
  UINT64 Len=R->QueueInfo>>32;
  if (!R->TransportSamples || R->TransportSamples>N976N_ACPM_MAX_READS ||
      !R->TransportStage || R->TransportStage>ACPM_STAGE_PUBLISHED ||
      R->TransportFailure>ACPM_FAIL_TIMEOUT ||
      (R->MaskBefore>>32) || (R->MaskAfter>>32) ||
      R->IndicesBefore!=RawIndicesPacked(R->RawIndicesBefore,Len) ||
      R->IndicesAfter!=RawIndicesPacked(R->RawIndicesAfter,Len)) return FALSE;
  if (R->TransportFailure && (!EFI_ERROR(R->Status) || !R->Reason)) return FALSE;
  if (R->TransportSamples==1) {
    if (R->PendingBefore!=R->PendingAfter || R->MaskBefore!=R->MaskAfter)
      return FALSE;
    for (UINTN I=0; I<4; I++)
      if (R->RawIndicesBefore[I]!=R->RawIndicesAfter[I]) return FALSE;
  }
  if (!R->TransportFailure &&
      (((R->MaskBefore^R->MaskAfter)&BIT2) ||
       !RawIndicesValid(R->RawIndicesBefore,Len) ||
       !RawIndicesValid(R->RawIndicesAfter,Len))) return FALSE;
  if (R->Status==EFI_SUCCESS &&
      (R->TransportStage!=ACPM_STAGE_RETIRED || R->TransportFailure)) return FALSE;
  UINT64 F=R->TransportFailure;
  if (R->Reason==0x725 && (R->Status!=EFI_NOT_READY || R->Checks!=0x8F ||
      R->TransportStage>ACPM_STAGE_ACQUIRE_CHECK || !F || F>ACPM_FAIL_RX_PENDING))
    return FALSE;
  if (F>=1 && F<=4) {
    for (UINTN I=0; I<F-1; I++) if (R->RawIndicesAfter[I]>=Len) return FALSE;
    return R->RawIndicesAfter[F-1]>=Len;
  }
  if (F==5 || F==6)
    return RawIndicesValid(R->RawIndicesAfter,Len) &&
      (F==5 ? R->RawIndicesAfter[0]!=R->RawIndicesAfter[1] :
        R->RawIndicesAfter[2]!=R->RawIndicesAfter[3]);
  if (F==ACPM_FAIL_TX_PENDING) return (R->PendingAfter&(1ULL<<50))!=0;
  if (F==ACPM_FAIL_RX_PENDING) return (R->PendingAfter&BIT2)!=0;
  if (F==ACPM_FAIL_MASK_CHANGED) return R->TransportStage!=ACPM_STAGE_ACQUIRE &&
    ((R->MaskBefore^R->MaskAfter)&BIT2)!=0;
  if (F==ACPM_FAIL_COMPLETION) return !(R->PendingAfter&BIT2);
  /* Metadata, expected progression, sequence/payload stability, completion
   * timing and timeout require the core's execution evidence. The snapshot
   * alone cannot reconstruct them, so no invented equality is required. */
  return TRUE;
}

STATIC BOOLEAN LayoutRange (UINT64 Base, UINT64 Bytes)
{
  return !(Base&3) && Base<N976N_ACPM_SRAM_BYTES && Bytes && !(Bytes&3) &&
    Bytes<=N976N_ACPM_SRAM_BYTES-Base;
}

STATIC BOOLEAN LayoutDetailValid (CONST N976N_ACPM_SNAPSHOT *R)
{
  if (!R->LayoutCheck)
    return LayoutZero(R) && !(R->Reason==0x724 && (R->Checks&ACPM_CHECK_METADATA));
  if (R->Reason!=0x724 || R->Status!=EFI_UNSUPPORTED || R->Checks!=0x87 ||
      R->WriteCount || R->RequestCount || R->ResponseCount || R->Quarantined ||
      R->RetireCheck || R->LayoutCheck>5 ||
      R->LayoutSelected<1 || R->LayoutSelected>6) return FALSE;
  CONST UINT32 *F=R->LayoutFramework, *C=R->LayoutChannel;
  if (R->FrameworkChannels!=F[2] || R->FrameworkCounts!=(((UINT64)F[3]<<32)|F[6]) ||
      R->PluginTableCount!=(((UINT64)F[1]<<32)|F[0]) ||
      !R->LayoutChannelEntry || R->LayoutChannelEntry>F[3]) return FALSE;
  UINT64 Selected=(R->ChannelOffset-R->FrameworkChannels)/72+1;
  if (R->LayoutChannelEntry==Selected &&
      (R->ChannelInfo!=(((UINT64)C[1]<<32)|((UINT64)(C[17]!=0)<<16)|
         ((UINT64)C[3]<<8)|C[0]) ||
       R->QueueInfo!=(((UINT64)C[13]<<32)|C[14]) ||
       R->QueueBases!=(((UINT64)C[6]<<32)|C[12]) ||
       R->IndexOffsets[0]!=(((UINT64)C[4]<<32)|C[5]) ||
       R->IndexOffsets[1]!=(((UINT64)C[10]<<32)|C[11]))) return FALSE;
  UINT64 Word, Base=R->LayoutRaw, Span;
  if (R->LayoutSource==1) {
    if (R->LayoutOwner || R->LayoutChannelEntry!=Selected ||
        R->LayoutField<N976N_ACPM_INIT || (R->LayoutField-N976N_ACPM_INIT)%4 ||
        (R->LayoutField-N976N_ACPM_INIT)/4>=24) return FALSE;
    Word=(R->LayoutField-N976N_ACPM_INIT)/4;
    if (R->LayoutRaw!=F[Word]) return FALSE;
    switch (Word) {
      case 0: Span=(UINT64)F[1]*48; break;
      case 12: case 13: case 14: Span=4; break;
      case 15: Span=(UINT64)F[16]*F[17]; break;
      default: return FALSE;
    }
  } else if (R->LayoutSource==2) {
    if (!R->LayoutOwner || R->LayoutOwner>F[3] || R->LayoutChannelEntry!=R->LayoutOwner)
      return FALSE;
    UINT64 Entry=(UINT64)F[2]+(R->LayoutOwner-1)*72;
    if (R->LayoutField<Entry || (R->LayoutField-Entry)%4 ||
        (R->LayoutField-Entry)/4>=18) return FALSE;
    Word=(R->LayoutField-Entry)/4;
    if (R->LayoutRaw!=C[Word]) return FALSE;
    switch (Word) {
      case 3: Span=0; break;
      case 4: case 5: case 10: case 11: Span=4; break;
      case 6: Span=(UINT64)C[13]*C[14]; break;
      case 7: Span=C[9]; break;
      case 12: Span=C[3]==2?C[14]:(UINT64)C[13]*C[14]; break;
      case 13: case 14: Span=(UINT64)C[13]*C[14]; break;
      case 16: Span=0; break;
      default: return FALSE;
    }
  } else if (R->LayoutSource==3) {
    if (!R->LayoutOwner || R->LayoutOwner>F[1] || R->PluginEntry!=R->LayoutOwner ||
        R->LayoutChannelEntry!=Selected ||
        R->LayoutField!=(UINT64)F[0]+(R->LayoutOwner-1)*48+4 ||
        R->LayoutRaw!=(R->PluginBaseSize>>32)) return FALSE;
    Word=1; Base&=~1ULL; Span=(UINT32)R->PluginBaseSize;
  } else return FALSE;
  /* An overlap reports the conservative protected-word extent, while DOMAIN
   * refusal reports the original declared byte count. No foreign payload is
   * accessed to validate either form of frozen evidence. */
  if (R->LayoutSource==2 && R->LayoutCheck==ACPM_LAYOUT_OVERLAP &&
      C[3]==2 && R->LayoutOwner!=Selected && (Word==6 || Word==12)) {
    UINTN BadWord;
    if (N976nAcpmBufferDomain(C,&BadWord)!=ACPM_BUFFER_SRAM) return FALSE;
    Span=N976nAcpmBufferProtectedBytes(Span);
  }
  if (R->LayoutSpan!=Span || R->FailureOffset!=Base) return FALSE;
  if (R->LayoutSource==3 && R->LayoutCheck!=2) return FALSE;
  if (R->LayoutSource==2 && R->LayoutCheck<=2 &&
      (Word==3 || Word==13 || Word==14)) return FALSE;
  if (R->LayoutCheck!=2 && (R->LayoutOther || R->LayoutOtherBytes)) return FALSE;
  if (R->LayoutCheck==ACPM_LAYOUT_DOMAIN) {
    UINTN BadWord;
    return R->LayoutSource==2 && C[3]==2 && R->LayoutOwner!=Selected &&
      !N976nAcpmBufferDomain(C,&BadWord) && Word==BadWord;
  }
  if (R->LayoutSource==2 && Word==16) return FALSE;
  /* Foreign BUFFER payload bounds are rejected as DOMAIN before exclusion.
   * Admitted SRAM payloads have bounded word padding, so their only later
   * refusal is OVERLAP. Do not mislabel a valid short declaration as RANGE. */
  if (R->LayoutSource==2 && C[3]==2 && R->LayoutOwner!=Selected &&
      (Word==6 || Word==12) && R->LayoutCheck==ACPM_LAYOUT_RANGE) return FALSE;
  if (R->LayoutCheck==1)
    return !LayoutRange(Base,Span);
  if (R->LayoutCheck==2) {
    /* Plugin images may have byte geometry, unlike the word-based IPC rings. */
    return Span && Base<N976N_ACPM_SRAM_BYTES && Span<=N976N_ACPM_SRAM_BYTES-Base &&
      R->LayoutOtherBytes && R->LayoutOther<N976N_ACPM_SRAM_BYTES &&
      R->LayoutOtherBytes<=N976N_ACPM_SRAM_BYTES-R->LayoutOther &&
      Base<R->LayoutOther+R->LayoutOtherBytes && R->LayoutOther<Base+Span;
  }
  if (R->LayoutCheck==3)
    return R->LayoutSource==2 && Word==3 && C[3]!=1 && C[3]!=2;
  return R->LayoutSource==2 && C[3]==1 && R->LayoutOwner!=Selected &&
    ((Word==13 && (!C[13] || Span>N976N_ACPM_SRAM_BYTES)) ||
     (Word==14 && C[13] && !C[14]));
}

CONST CHAR16 *N976nAcpmLayoutFieldName (CONST N976N_ACPM_SNAPSHOT *R)
{
  if (!R || !R->LayoutCheck) return L"none";
  if (R->LayoutSource==1) {
    switch (R->LayoutField-N976N_ACPM_INIT) {
      case 0: return L"framework.plugins";
      case 8: return L"framework.ipc_channels";
      case 48: return L"framework.ktime_index";
      case 52: return L"framework.log_buf_rear";
      case 56: return L"framework.log_buf_front";
      case 60: return L"framework.log_data";
      default: return L"framework.unknown";
    }
  }
  if (R->LayoutSource==2 && R->LayoutOwner) {
    UINT64 Entry=R->FrameworkChannels+(R->LayoutOwner-1)*72;
    BOOLEAN Ap=R->LayoutOwner<=(UINT32)R->FrameworkCounts;
    switch (R->LayoutField-Entry) {
      case 12: return L"channel.type";
      case 16: return Ap?L"channel.rx_rear (AP TX)":L"channel.rx_rear (peer TX)";
      case 20: return Ap?L"channel.rx_front (AP TX)":L"channel.rx_front (peer TX)";
      case 24: return Ap?L"channel.rx_base (AP TX)":L"channel.rx_base (peer TX)";
      case 28: return L"channel.rx_indr_buf";
      case 40: return Ap?L"channel.tx_rear (AP RX)":L"channel.tx_rear (peer RX)";
      case 44: return Ap?L"channel.tx_front (AP RX)":L"channel.tx_front (peer RX)";
      case 48: return Ap?L"channel.tx_base (AP RX)":L"channel.tx_base (peer RX)";
      case 52: return L"channel.ch.q_len";
      case 56: return L"channel.ch.q_elem_size";
      case 64: return L"channel.ch.mbox_addr";
      default: return L"channel.unknown";
    }
  }
  return R->LayoutSource==3?L"plugin.base_addr (Thumb bit retained)":L"unknown";
}

/* Power proof is separate from transport retirement and from touch success.
 * Saved bytes, observed bytes and verified restoration have distinct fields;
 * failed readback observations must remain displayable. */
STATIC BOOLEAN PowerDetailValid (CONST N976N_ACPM_SNAPSHOT *R)
{
  if (!R->PowerMode) {
    CONST UINT8 *P=(CONST UINT8 *)&R->PowerPhase;
    for (UINTN I=0; I<sizeof(*R)-OFFSET_OF(N976N_ACPM_SNAPSHOT,PowerPhase); I++)
      if (P[I]) return FALSE;
    return R->RequestCount<=2 && R->WriteCount<=32 &&
      R->ReadCount<=16ULL*N976N_ACPM_POLL_LIMIT+16384ULL;
  }
  if (R->PowerMode!=1 || R->Profile!=0 || R->Phase!=8 || R->PowerPhase!=8 ||
      R->PowerChecks&~ACPM_POWER_ALL || R->PowerEnabled>0xFFFF ||
      R->PowerRestored>0xFFFF || R->PowerValid>15 || R->PowerAttempted>3 ||
      R->PowerChanged>3 || (R->PowerChanged&~R->PowerAttempted) ||
      R->PowerRestoreMask>3 || R->PowerCallbackCount>1 || R->PowerCallbackRetired>1 ||
      R->PowerTouchBeforeInputCheck>31 || R->PowerTouchBeforeReason>0xFFFF ||
      ((R->PowerTouchBeforeInputCheck&2) && !(R->PowerTouchBeforeInputCheck&1)) ||
      R->PowerReason!=R->Reason || R->PowerStatus!=R->Status) return FALSE;
  if (R->PowerReason) {
    if (!EFI_ERROR(R->PowerStatus) || !R->PowerFailureStage || R->PowerFailureStage>7)
      return FALSE;
  } else if (R->PowerStatus!=EFI_SUCCESS || R->PowerFailureStage) return FALSE;
  if ((R->PowerChecks&ACPM_POWER_ORIGINAL) && R->ValidValues!=3) return FALSE;
  if (R->PowerChecks&ACPM_POWER_POLICY) {
    UINT64 Modes=R->LdoValues&0xC0C0;
    if (!(R->PowerChecks&ACPM_POWER_ORIGINAL) ||
        (Modes!=0 && Modes!=0xC0 && Modes!=0xC0C0)) return FALSE;
  }
  if ((R->PowerAttempted || R->PowerValid || R->PowerCallbackCount) &&
      !(R->PowerChecks&ACPM_POWER_POLICY)) return FALSE;
  for (UINTN I=0; I<2; I++) {
    UINT64 Bit=1ULL<<I, Original=(R->LdoValues>>(I*8))&255;
    UINT64 Enabled=(R->PowerEnabled>>(I*8))&255;
    UINT64 Restored=(R->PowerRestored>>(I*8))&255;
    if (!(R->PowerValid&Bit) && Enabled) return FALSE;
    if (!(R->PowerValid&(Bit<<2)) && Restored) return FALSE;
    if ((R->PowerChanged&Bit) && (Original&0xC0)) return FALSE;
    if ((R->PowerRestoreMask&Bit) &&
        (!(R->PowerValid&(Bit<<2)) || Restored!=Original)) return FALSE;
  }
  if (R->PowerChecks&ACPM_POWER_ENABLED) {
    if ((R->PowerValid&3)!=3 || !(R->PowerChecks&ACPM_POWER_POLICY) ||
        R->PowerEnabled!=(R->LdoValues|0xC0C0)) return FALSE;
  }
  if ((R->PowerChecks&ACPM_POWER_SETTLED) &&
      (!(R->PowerChecks&ACPM_POWER_ENABLED) || R->PowerWaitTicks<71ULL*R->CounterHz/1000))
    return FALSE;
  if (((R->PowerChecks&ACPM_POWER_TOUCH)!=0)!=(R->PowerCallbackCount!=0) ||
      ((R->PowerChecks&ACPM_POWER_TOUCH_RETIRED)!=0)!=(R->PowerCallbackRetired!=0) ||
      (R->PowerCallbackCount && !(R->PowerChecks&ACPM_POWER_SETTLED)) ||
      (R->PowerCallbackRetired && !R->PowerCallbackCount)) return FALSE;
  if (R->PowerChecks&ACPM_POWER_RESTORED) {
    if (R->PowerRestoreMask!=3 || R->PowerRestored!=R->LdoValues ||
        (R->PowerValid&12)!=12 || R->PowerRestoreStatus!=EFI_SUCCESS ||
        R->PowerRestoreReason || (R->PowerCallbackCount && !R->PowerCallbackRetired))
      return FALSE;
  } else if (!EFI_ERROR(R->PowerRestoreStatus)) return FALSE;
  if (R->PowerRestoreReason && !EFI_ERROR(R->PowerRestoreStatus)) return FALSE;
  if (((R->PowerChecks&ACPM_POWER_TRANSPORT_RETIRED)!=0)!=
      ((R->Checks&ACPM_CHECK_RETIRED)!=0)) return FALSE;
  if (R->Quarantined && (R->PowerChecks&ACPM_POWER_RESTORED)) return FALSE;
  if (!R->PowerReason) {
    if (R->PowerChecks!=ACPM_POWER_ALL || R->PowerValid!=15 ||
        R->PowerCallbackCount!=1 || !R->PowerCallbackRetired ||
        R->PowerRestoreMask!=3 || R->PowerRestoreStatus || R->PowerRestoreReason ||
        R->RequestCount!=R->ResponseCount || R->RequestCount<4 ||
        R->LastRegister!=0x58 || (R->PowerLastResponse[1]>>24) ||
        ((R->PowerLastResponse[1]>>8)&255)!=(R->LdoValues&255) ||
        ((R->PowerLastResponse[0]>>16)&63)!=R->Sequence) return FALSE;
  }
  return TRUE;
}

BOOLEAN N976nAcpmReportValid (CONST N976N_ACPM_SNAPSHOT *R, UINT64 Profile)
{
  if (!R || Profile>1 || R->Magic!=N976N_ACPM_SNAPSHOT_MAGIC ||
      R->Version!=N976N_ACPM_SNAPSHOT_VERSION || R->Size!=sizeof(*R) || R->Profile!=Profile ||
      (R->Checks&~ACPM_CHECK_ALL) || (R->RetireCheck&~ACPM_RETIRE_ALL) ||
      R->Quarantined>1 || R->ReadCount>N976N_ACPM_MAX_READS ||
      R->WriteCount>N976N_ACPM_MAX_WRITES || R->RequestCount>N976N_ACPM_MAX_REQUESTS ||
      R->ResponseCount>R->RequestCount || R->Sequence>63 ||
      R->LdoValues>0xFFFF || (R->ValidValues!=0 && R->ValidValues!=1 && R->ValidValues!=3))
    return FALSE;
  if (!PowerDetailValid(R)) return FALSE;
  if (R->Phase==1) {
    return HardwareZero(R) &&
      ((R->Reason==0x720 && R->Status==EFI_INVALID_PARAMETER && R->Checks==0) ||
       (R->Reason==0x721 && R->Status==EFI_UNSUPPORTED && R->Checks==1));
  }
  if (R->Phase!=8 || (R->Checks&3)!=3 || R->CpuEl!=4 ||
      (R->CpuSctlr&(BIT0|BIT2|BIT12|BIT25)) || (R->CpuDaif&0x3C0)!=0x3C0)
    return FALSE;
  if (Profile==1)
    return R->Status==EFI_UNSUPPORTED && R->Reason==0x722 &&
      R->Checks==0x83 && HardwareZero(R);
  if (R->Reason==0x722 || R->CounterHz!=26000000) return FALSE;
  /* Failed raw plugin values must remain displayable. Only validate their
   * capture relationship here; metadata admission belongs to the SEC probe. */
  UINT64 Plugins=R->PluginTableCount>>32;
  UINT64 Table=(UINT32)R->PluginTableCount;
  if (R->PluginEntry>32 || R->PluginEntry>Plugins ||
      (!R->PluginEntry && (R->PluginBaseSize || R->PluginAttach))) return FALSE;
  if ((R->Checks&ACPM_CHECK_LAYOUT) && !(R->Checks&ACPM_CHECK_METADATA)) return FALSE;
  if ((R->Checks&ACPM_CHECK_IDLE) && (R->Checks&0x0F)!=0x0F) return FALSE;
  if (R->Checks&ACPM_CHECK_METADATA) {
    UINT64 Count=R->FrameworkCounts>>32, Ap=(UINT32)R->FrameworkCounts;
    UINT64 Len=R->QueueInfo>>32;
    if (Plugins>32 || (Plugins && !R->PluginEntry) ||
        (R->Status==EFI_SUCCESS && R->PluginEntry!=Plugins) ||
        (Plugins && ((Table&3) || Table>=N976N_ACPM_SRAM_BYTES ||
          Plugins*48>N976N_ACPM_SRAM_BYTES-Table)) ||
        !Count || Count>32 || !Ap || Ap>16 || Ap>Count ||
        R->FrameworkChannels>=N976N_ACPM_SRAM_BYTES ||
        (R->FrameworkChannels&3) ||
        Count*72>N976N_ACPM_SRAM_BYTES-R->FrameworkChannels ||
        R->ChannelOffset<R->FrameworkChannels ||
        (R->ChannelOffset-R->FrameworkChannels)%72 ||
        (R->ChannelOffset-R->FrameworkChannels)/72>=Ap ||
        Len<2 || Len>64 ||
        (UINT32)R->QueueInfo!=16 || (R->ChannelInfo&0xFFFFFFFF)!=0x10102)
      return FALSE;
  }
  /* Plugin loader policy is not the IPC channel's access authority. A zero
   * size declares no image span, regardless of raw base or attachment words.
   * Only a declared nonempty span has a bounds contract here. This checks the
   * frozen record, never dereferences the base or re-admits an IPC resource. */
  if (R->Status==EFI_SUCCESS && R->PluginEntry) {
    UINT64 RawBase=R->PluginBaseSize>>32, Bytes=(UINT32)R->PluginBaseSize;
    UINT64 Base=RawBase&~1ULL;
    if (Bytes &&
        (Base>=N976N_ACPM_SRAM_BYTES ||
         Bytes>N976N_ACPM_SRAM_BYTES-Base)) return FALSE;
  }
  if (!LayoutDetailValid(R) || !TransportDetailValid(R)) return FALSE;
  if (R->WriteCount && (!(R->Checks&ACPM_CHECK_IDLE) ||
      !R->Sequence || (R->LastRegister!=0x58 && R->LastRegister!=0x60))) return FALSE;
  /* RequestCount includes a producer-publication attempt before doorbell.
     Preserve a failed first publication (four payload writes + front write). */
  if (R->RequestCount && R->WriteCount<5) return FALSE;
  if (R->RequestCount && R->WriteCount==5 &&
      (!R->Quarantined || R->Reason!=0x727)) return FALSE;
  if (R->ResponseCount && R->WriteCount<8) return FALSE;
  if (!R->WriteCount && (R->RequestCount || R->ResponseCount || R->Quarantined ||
      R->LastRegister || R->RetireCheck || R->ValidValues || R->LdoValues)) return FALSE;
  if (!R->PowerMode && R->RequestCount==2 && R->LastRegister!=0x60) return FALSE;
  if (R->Quarantined) {
    if (!R->WriteCount || (R->Checks&ACPM_CHECK_RETIRED) || R->RetireCheck) return FALSE;
  } else if (!(R->Checks&ACPM_CHECK_RETIRED) ||
      (R->WriteCount && R->RetireCheck!=ACPM_RETIRE_ALL)) return FALSE;
  if (((R->Checks>>5)&3)!=R->ValidValues) return FALSE;
  UINT64 Good=(R->ValidValues&1)+((R->ValidValues>>1)&1);
  if (R->ResponseCount<Good) return FALSE;
  for (UINTN I=0; I<2; I++) {
    if (R->ValidValues&(1ULL<<I)) {
      if ((R->Response[I][1]>>24) ||
          ((R->Response[I][1]>>8)&255)!=((R->LdoValues>>(I*8))&255)) return FALSE;
    } else if ((R->LdoValues>>(I*8))&255) return FALSE;
  }
  if (R->Status==EFI_SUCCESS)
    return R->Checks==ACPM_CHECK_ALL && !R->Reason && !R->Quarantined &&
      (R->PowerMode || (R->RequestCount==2 && R->ResponseCount==2)) && R->ValidValues==3 &&
      R->RetireCheck==ACPM_RETIRE_ALL && !R->FailureOffset;
  return EFI_ERROR(R->Status) && R->Reason>=0x723 && (R->Reason<=0x72C ||
    (R->PowerMode && R->Reason>=0x730 && R->Reason<=0x737));
}
