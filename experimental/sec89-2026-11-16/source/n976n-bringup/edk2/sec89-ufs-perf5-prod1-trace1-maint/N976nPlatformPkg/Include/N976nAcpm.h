/* SPDX-License-Identifier: MIT */
#ifndef N976N_ACPM_H_
#define N976N_ACPM_H_
#include <Uefi.h>
#include <N976nPlatform.h>

#define N976N_ACPM_ADMISSION_MAGIC 0x344144504D43414EULL
#define N976N_ACPM_SNAPSHOT_MAGIC  0x345350504D43414EULL
#define N976N_ACPM_ADMISSION_CHECKS 0xFFULL
#define N976N_ACPM_VERSION 1ULL
#define N976N_ACPM_SNAPSHOT_VERSION 5ULL
#define N976N_ACPM_MAILBOX 0x15900000ULL
#define N976N_ACPM_MAILBOX_BYTES 0x1000ULL
#define N976N_ACPM_SRAM 0x02039000ULL
#define N976N_ACPM_SRAM_BYTES 0x30000ULL
#define N976N_ACPM_INIT 0x7000ULL
#define N976N_ACPM_POLL_LIMIT 65536U
#define N976N_ACPM_WAIT_US 15000U
/* At most12 transactions: original reads2, enable/readback4, and reverse
 * restore pre-read/update/readback6. Per-request ownership checks stay intact. */
#define N976N_ACPM_MAX_REQUESTS 12ULL
#define N976N_ACPM_MAX_READS (N976N_ACPM_MAX_REQUESTS * (7ULL * N976N_ACPM_POLL_LIMIT + 8192ULL) + 16384ULL)
#define N976N_ACPM_MAX_WRITES (N976N_ACPM_MAX_REQUESTS * 9ULL)
/* Separate from the short IPC iteration bound: allow a real70ms counter wait,
 * while retaining a finite instruction bound if the physical counter stalls. */
#define N976N_ACPM_DELAY_POLL_LIMIT (32U * 1024U * 1024U)
#define ACPM_POWER_ORIGINAL BIT0
#define ACPM_POWER_POLICY BIT1
#define ACPM_POWER_ENABLED BIT2
#define ACPM_POWER_SETTLED BIT3
#define ACPM_POWER_TOUCH BIT4
#define ACPM_POWER_TOUCH_RETIRED BIT5
#define ACPM_POWER_RESTORED BIT6
#define ACPM_POWER_TRANSPORT_RETIRED BIT7
#define ACPM_POWER_ALL 0xFFULL

/* Source-backed DT admission only; no live firmware/queue claim. */
typedef struct {
  UINT64 Magic, Version, Size, Profile, Admitted, Checks, Reason;
  UINT64 Mailbox, MailboxBytes, Sram, SramBytes, InitOffset;
  UINT64 Channel, PmicType, SpeedyChannel, ReadRegisters;
} N976N_ACPM_ADMISSION;
STATIC_ASSERT (sizeof (N976N_ACPM_ADMISSION) == 128, "FIX4 ACPM admission");

#define ACPM_CHECK_ADMISSION BIT0
#define ACPM_CHECK_CPU       BIT1
#define ACPM_CHECK_METADATA  BIT2
#define ACPM_CHECK_LAYOUT    BIT3
#define ACPM_CHECK_IDLE      BIT4
#define ACPM_CHECK_LDO19     BIT5
#define ACPM_CHECK_LDO27     BIT6
#define ACPM_CHECK_RETIRED   BIT7
#define ACPM_CHECK_ALL       0xFFULL
#define ACPM_RETIRE_TX       BIT0
#define ACPM_RETIRE_RX       BIT1
#define ACPM_RETIRE_PENDING  BIT2
#define ACPM_RETIRE_METADATA BIT3
#define ACPM_RETIRE_ALL      0xFULL

/* FIX12: where the first failed transport predicate was sampled. */
#define ACPM_STAGE_ACQUIRE       1U
#define ACPM_STAGE_ACQUIRE_CHECK 2U
#define ACPM_STAGE_QUERY         3U
#define ACPM_STAGE_PAYLOAD       4U
#define ACPM_STAGE_PUBLISH       5U
#define ACPM_STAGE_ROLLBACK      6U
#define ACPM_STAGE_WAIT          7U
#define ACPM_STAGE_RESPONSE      8U
#define ACPM_STAGE_CONSUME       9U
#define ACPM_STAGE_ACK          10U
#define ACPM_STAGE_RETIRED      11U
#define ACPM_STAGE_PUBLISHED    12U
#define ACPM_FAIL_TX_REAR        1U
#define ACPM_FAIL_TX_FRONT       2U
#define ACPM_FAIL_RX_REAR        3U
#define ACPM_FAIL_RX_FRONT       4U
#define ACPM_FAIL_TX_BUSY        5U
#define ACPM_FAIL_RX_BUSY        6U
#define ACPM_FAIL_TX_PENDING     7U
#define ACPM_FAIL_RX_PENDING     8U
#define ACPM_FAIL_INDEX_CHANGED  9U
#define ACPM_FAIL_MASK_CHANGED  10U
#define ACPM_FAIL_METADATA      11U
#define ACPM_FAIL_PROGRESS      12U
#define ACPM_FAIL_RESPONSE      13U
#define ACPM_FAIL_COMPLETION    14U
#define ACPM_FAIL_TIMEOUT       15U

/* FIX8: provenance is a frozen diagnostic, never an address authority.
 * Word offsets below refer to the source-backed u32 SRAM ABI. */
#define ACPM_LAYOUT_RANGE    1ULL
#define ACPM_LAYOUT_OVERLAP  2ULL
#define ACPM_LAYOUT_TYPE     3ULL
#define ACPM_LAYOUT_GEOMETRY 4ULL
#define ACPM_LAYOUT_DOMAIN   5ULL
#define ACPM_SOURCE_FRAMEWORK 1ULL
#define ACPM_SOURCE_CHANNEL   2ULL
#define ACPM_SOURCE_PLUGIN    3ULL
#define ACPM_FRAMEWORK_WORDS 24U
#define ACPM_CHANNEL_WORDS   18U

/* Exclusion-only address classification, not an MMIO access grant.
 * Samsung fvmap.c uses the 0x90000000 ACPM address bias for clock addresses;
 * FIX8 physically records this mailbox anchor and payload at anchor+SR2.
 * Together they support this exact mailbox-view hypothesis, not a generic
 * conversion of firmware pointers. SRAM queues never use this interpretation.
 * The AP envelope is the DT-admitted resource. FIX10 physically reported a
 * separate anchor A5910000 with payloads at +80/+88. Its exact physical
 * resource is not in the supplied DT. Admit only that anchor with the Samsung
 * mailbox-family 64-word storage envelope [80,180), as a platform inference
 * for exclusion, NOT a peer identity, implemented-register or mapping claim.
 * Never extend this by bank arithmetic. No BUFFER payload is dereferenced.
 * AP-prefix membership selects our transfer channel; all descriptors still
 * contribute foreign storage exclusions irrespective of AP membership.
 */
#define N976N_ACPM_FW_MAILBOX (N976N_ACPM_MAILBOX + 0x90000000ULL)
#define N976N_ACPM_FW_PEER_MAILBOX 0xA5910000ULL
#define N976N_ACPM_PEER_STORAGE_END 0x180ULL
#define N976N_ACPM_SR0 0x80ULL
#define ACPM_BUFFER_SRAM 1U
#define ACPM_BUFFER_MAILBOX 2U
STATIC_ASSERT (N976N_ACPM_SRAM + N976N_ACPM_SRAM_BYTES <= N976N_ACPM_MAILBOX,
  "ACPM mailbox resource must be disjoint from SRAM");
STATIC_ASSERT ((N976N_ACPM_SRAM_BYTES & 3) == 0,
  "Bounded aligned SRAM spans must remain bounded after word padding");
STATIC_ASSERT ((N976N_ACPM_PEER_STORAGE_END & 3) == 0 &&
  N976N_ACPM_SR0 < N976N_ACPM_PEER_STORAGE_END,
  "Peer storage envelope contains complete shared words");

/* All nonselected BUFFER declarations describe byte storage. Bound both the
 * raw span and the enclosing words; this does not admit a byte-sized transfer.
 * Checked subtraction bounds Bytes before +3, including u32-product inputs. */
STATIC inline BOOLEAN N976nAcpmDomainSpan (UINT64 Base, UINT64 Bytes,
  UINT64 Anchor, UINT64 Minimum, UINT64 Extent)
{
  return !(Base&3) && Bytes && Base>=Anchor &&
    Base-Anchor>=Minimum && Base-Anchor<Extent &&
    Bytes<=Extent-(Base-Anchor) &&
    ((Bytes+3ULL)&~3ULL)<=Extent-(Base-Anchor);
}

/* FIX10: a foreign SRAM BUFFER declares byte storage, not permission to use
 * the AP's memcpy_align_4 consumer. Keep aligned bases and complete bounds;
 * reserve every intersecting word below, without reading this storage.
 * Selected queues and indices retain their actual word transfer conditions.
 * The published descriptor remains our ownership model;
 * this is not proof of an unknown firmware-side consumer's implementation.
 */
STATIC inline BOOLEAN N976nAcpmSramBufferSpan (UINT64 Base, UINT64 Bytes)
{
  return !(Base&3) && Bytes && Base<N976N_ACPM_SRAM_BYTES &&
    Bytes<=N976N_ACPM_SRAM_BYTES-Base;
}

/* Call only for an admitted SRAM byte span, or a u32-by-u32 descriptor
 * product (which leaves room for +3 in u64). Never use rounding to admit
 * an out-of-bounds extent or to change the descriptor's declared unit. */
STATIC inline UINT64 N976nAcpmBufferProtectedBytes (UINT64 Bytes)
{
  return (Bytes+3ULL)&~3ULL;
}

STATIC inline UINTN N976nAcpmBufferDomain (CONST UINT32 *C, UINTN *BadWord)
{
  UINT64 TxBytes=(UINT64)C[13]*C[14];
  *BadWord=0;
  if (N976nAcpmSramBufferSpan(C[12],C[14]) &&
      (!C[13] || N976nAcpmSramBufferSpan(C[6],TxBytes)))
    return ACPM_BUFFER_SRAM;
  *BadWord=16;
  UINT64 Extent;
  if (C[16]==N976N_ACPM_FW_MAILBOX) Extent=N976N_ACPM_MAILBOX_BYTES;
  else if (C[16]==N976N_ACPM_FW_PEER_MAILBOX) Extent=N976N_ACPM_PEER_STORAGE_END;
  else return 0;
  *BadWord=12;
  if (!N976nAcpmDomainSpan(C[12],C[14],C[16],N976N_ACPM_SR0,
      Extent)) return 0;
  *BadWord=6;
  if (C[13] && !N976nAcpmDomainSpan(C[6],TxBytes,C[16],N976N_ACPM_SR0,
      Extent)) return 0;
  *BadWord=0;
  return ACPM_BUFFER_MAILBOX;
}

/* Reason 720 admission, 721 CPU/counter/touch retirement, 722 QEMU skip;
 * 723 framework metadata, 724 channel/layout, 725 inherited busy/pending;
 * 726 metadata/index change, 727 writeback/publication, 728 timeout;
 * 729 foreign/malformed response, 72A PMIC status, 72B retirement;
 * 72C no unused retained-slot sequence.
 * Invalid admission/CPU state returns FALSE at Phase1 (Checks0/1).
 * All bounded attempts finish Phase8. QEMU=UNSUPPORTED/722/Checks83,
 * zero hardware/counter fields. CPU observation fields remain populated.
 * No writes => retired check bit7, RetireCheck0 (nothing to undo).
 * Unresolved published/modified transport => Quarantined1, check bit7 clear.
 * Only Status0/ChecksFF/ValidValues3 proves two fresh read responses.
 * Retired means owned queue progress completed, not rollback of ring indices.
 * Quarantine forbids any further transport mutation after unresolved ownership.
 */
typedef struct {
  UINT64 Magic, Version, Size, Profile;
  UINT64 Phase, Status, Checks, Reason;
  UINT64 CpuEl, CpuSctlr, CpuDaif;
  UINT64 ReadCount, WriteCount, CounterHz, WaitTicks;
  UINT64 FrameworkChannels, FrameworkCounts, ChannelOffset;
  UINT64 ChannelInfo, QueueInfo, QueueBases;
  UINT64 IndexOffsets[2];
  UINT64 IndicesBefore, IndicesAfter, PendingBefore, PendingAfter;
  UINT64 RequestCount, ResponseCount, LastRegister, Sequence;
  UINT64 LdoValues, ValidValues, RetireCheck, Quarantined, FailureOffset;
  UINT32 Response[2][4];
  UINT64 PluginTableCount, PluginEntry, PluginBaseSize, PluginAttach;
  UINT64 LayoutCheck, LayoutSource, LayoutOwner, LayoutField, LayoutRaw;
  UINT64 LayoutSpan, LayoutOther, LayoutOtherBytes, LayoutSelected;
  UINT64 LayoutChannelEntry;
  UINT32 LayoutFramework[ACPM_FRAMEWORK_WORDS];
  UINT32 LayoutChannel[ACPM_CHANNEL_WORDS];
  UINT64 TransportStage, TransportFailure, TransportSamples;
  UINT64 MaskBefore, MaskAfter;
  UINT32 RawIndicesBefore[4], RawIndicesAfter[4];
  /* FIX13: the first672byte offsets and initial Response[] are retained.
   * ReadCount/WriteCount/RequestCount/ResponseCount cover the whole power
   * lifecycle (up to12 requests), not just the original two reads.
   * LdoValues/ValidValues
   * preserve the two original reads. No later read overwrites those bytes.
   * PowerValid bits0/1=enabled19/27, bits2/3=restored19/27.
   * Attempted records producer publication, not proof a PMIC write succeeded;
   * Changed records a matched update response; RestoreMask requires readback.
   * PowerReason/FailureStage preserve the first power or transport failure;
   * cleanup has independent Status/Reason. An unresolved published update is
   * never retried or followed by blind rollback. Callback false forbids rail
   * removal while touch ownership/activity is unknown.
   * Mode0 keeps this whole tail zero (legacy read-only entry); Mode1 is the
   * explicitly authorized temporary L19/L27 enable-and-restore experiment. */
  UINT64 PowerPhase, PowerStatus, PowerChecks, PowerReason;
  UINT64 PowerEnabled, PowerRestored, PowerValid;
  UINT64 PowerAttempted, PowerChanged, PowerRestoreMask;
  UINT64 PowerRestoreStatus, PowerRestoreReason, PowerWaitTicks;
  UINT64 PowerCallbackCount, PowerCallbackRetired, PowerFailureStage, PowerMode;
  UINT32 PowerLastResponse[4];
  /* PhoneSec-only diagnostic copy, not an MMIO or access authority. */
  UINT64 PowerTouchBeforeReason, PowerTouchBeforeInputCheck, PowerTouchBeforeInputState;
} N976N_ACPM_SNAPSHOT;
STATIC_ASSERT (sizeof (N976N_ACPM_SNAPSHOT) == 848, "FIX13 ACPM snapshot");

/* Packed diagnostics: FrameworkCounts=numChannels:APmax; QueueInfo=len:bytes;
 * QueueBases=AP-TX:AP-RX SRAM offsets; IndexOffsets=rear:front for each ring;
 * Indices=TXrear[15:0],TXfront[31:16],RXrear[47:32],RXfront[63:48];
 * Pending=INTSR0:INTSR1; ChannelInfo=field[63:32],poll[23:16],type[15:8],id[7:0].
 * LdoValues=LDO19 byte0,LDO27 byte1; ValidValues bits0/1 require fresh status0.
 * PluginTableCount=count:SRAM offset (raw); PluginEntry=last examined index+1,
 * zero means no entry read. PluginBaseSize=raw base:size, including Thumb bit.
 * PluginAttach=raw stay_attached word:raw is_attached word; only low8 of each
 * word has semantic meaning, other bytes are padding. These diagnostic values
 * may be invalid; they never grant MMIO access or assert successful admission.
 * Layout*: populated only by Layout's first rejection after metadata admission.
 * Source=framework/channel/plugin; Owner=0 for framework, otherwise ordinal+1.
 * Field is the source word's storage offset; Raw is that word, not a value read
 * through it. Span is the tested target extent; overlap alone sets Other/Bytes.
 * Selected=selected resource index+1 (TX rear/front/base, RX rear/front/base).
 * ChannelEntry=offending channel ordinal+1, or selected channel for framework
 * and plugin failures. Full framework24/channel18 words come from the existing
 * bounded metadata snapshot. They are not a coherent live-firmware dump.
 * For plugin overlap the raw base retains its Thumb bit; FailureOffset is the
 * normalized base. No arbitrary SRAM/physical pointer conversion is performed.
 * FIX12 tail: all fields zero before Layout succeeds. Each complete transport
 * sample reads four u32 indices, raw INTSR0/1 and INTMR1. Before fields hold
 * acquisition, After fields hold the latest sample (not an atomic snapshot).
 * On first TransportFailure, latest diagnostics freeze while safety reads may
 * continue for bounded cleanup. Packed indices are zero for an invalid sample;
 * raw indices retain every full u32. Mask fields retain all32bits but only the
 * selected bit is an ownership dependency; firmware never writes INTMR1.
 * TransportFailure describes a predicate, not every possible EFI error. PMIC
 * status and MMIO writeback failures may leave this field zero. No MMIO address
 * authority is granted by any diagnostic value.
 */
extern EFI_GUID gN976nAcpmSnapshotGuid;
BOOLEAN EFIAPI N976nAdmitAcpm (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_ACPM_ADMISSION *Admission);
BOOLEAN EFIAPI N976nProbeAcpm (
  CONST N976N_ACPM_ADMISSION *Admission, BOOLEAN TouchRetired,
  N976N_ACPM_SNAPSHOT *Snapshot);
typedef BOOLEAN (EFIAPI *N976N_ACPM_TOUCH_PROBE)(VOID *Context);
/* Callback is statically trusted SEC code, invoked once only after confirmed
 * rail readback and settling. TRUE means its controller state safely retired;
 * it need not mean touch identification succeeded. No callback survives SEC. */
BOOLEAN EFIAPI N976nProbePoweredTouchAcpm (
  CONST N976N_ACPM_ADMISSION *Admission, BOOLEAN TouchRetired,
  N976N_ACPM_TOUCH_PROBE Callback, VOID *Context,
  N976N_ACPM_SNAPSHOT *Snapshot);
#endif
