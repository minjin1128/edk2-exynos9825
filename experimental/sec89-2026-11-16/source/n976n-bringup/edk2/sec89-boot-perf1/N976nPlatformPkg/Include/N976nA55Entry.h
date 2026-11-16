/* SPDX-License-Identifier: MIT
 * SEC88 SMP2: exact entry witness plus GICv2 Windows parking protocol v1.
 * Keep constants usable by both preprocessed assembly and C.
 */
#ifndef N976N_A55_ENTRY_H_
#define N976N_A55_ENTRY_H_

#define N976N_A55_ENTRY_CONFIG_MAGIC 0x334746433535414E
#define N976N_A55_ENTRY_MAGIC        0x31544E453535414E
#define N976N_A55_ENTRY_PARKED       0x314B52413535414E
#define N976N_A55_ENTRY_VERSION      3
#define N976N_A55_ENTRY_CONFIG_BYTES 56
#define N976N_A55_ENTRY_WITNESS_BYTES 176
#define N976N_A55_ENTRY_MAX_BYTES    4096
#define N976N_A55_ENTRY_STATUS_OK    0
#define N976N_A55_ENTRY_STATUS_MPIDR 1
/* N976N-specific, exact pairs. CPU_ON consumes DT reg, not MPIDR_EL1.
 * Target 1 / affinity 0x100 was observed in IMG_0403. Targets 2/3 are
 * observed as 0x200/0x300 in IMG_0404; mismatch still fails closed.
 * Never feed these affinity values back into Samsung CPU_ON Arg1.
 */
#define N976N_A55_TARGET1 1
#define N976N_A55_TARGET2 2
#define N976N_A55_TARGET3 3
#define N976N_A55_AFFINITY1 0x100
#define N976N_A55_AFFINITY2 0x200
#define N976N_A55_AFFINITY3 0x300
/* EL1 CNTVCT access depends on an EL2 control which EL1 cannot inspect.
 * The stub deliberately does not try that read and uses this sentinel.
 */
#define N976N_A55_ENTRY_COUNTER_UNREAD 0xFFFFFFFFFFFFFFFF

#define N976N_A55_CONFIG_MAGIC_OFF   0
#define N976N_A55_CONFIG_WITNESS_OFF 8
#define N976N_A55_CONFIG_AFFINITY_OFF 16
#define N976N_A55_CONFIG_TARGET_OFF  24

#define N976N_A55_W_MAGIC_OFF        0
#define N976N_A55_W_VERSION_OFF      8
#define N976N_A55_W_BYTES_OFF        16
#define N976N_A55_W_EXPECTED_OFF     24
#define N976N_A55_W_MPIDR_OFF        32
#define N976N_A55_W_MIDR_OFF         40
#define N976N_A55_W_EL_OFF           48
#define N976N_A55_W_SCTLR_OFF        56
#define N976N_A55_W_DAIF_OFF         64
#define N976N_A55_W_CONTEXT_OFF      72
#define N976N_A55_W_CNTFRQ_OFF       80
#define N976N_A55_W_CNTVCT_OFF       88
#define N976N_A55_W_STATUS_OFF       96
#define N976N_A55_W_TARGET_OFF       104
#define N976N_A55_CONFIG_MAILBOX_OFF 32
#define N976N_A55_CONFIG_GICD_OFF    40
#define N976N_A55_CONFIG_GICC_OFF    48
#define N976N_A55_W_INTERFACE_OFF   112
#define N976N_A55_W_GICTARGET_OFF   120
#define N976N_A55_W_GICCTLR_OFF     128
#define N976N_A55_W_GICPMR_OFF      136
#define N976N_A55_W_TIMER_OFF       144
#define N976N_A55_W_READYDAIF_OFF   152
#define N976N_A55_W_RESERVED1_OFF   160
#define N976N_A55_W_PARKED_OFF      168

#ifndef __ASSEMBLER__
#include <Base.h>

typedef struct {
  UINT64 Magic;
  UINT64 WitnessAddress;
  UINT64 ExpectedAffinity;
  UINT64 CpuOnTarget;
  UINT64 MailboxAddress, GicDistributor, GicCpuInterface;
} N976N_A55_ENTRY_CONFIG;

typedef struct {
  UINT64 Magic;
  UINT64 Version;
  UINT64 Bytes;
  UINT64 ExpectedAffinity;
  UINT64 Mpidr;
  UINT64 Midr;
  UINT64 CurrentEl;
  UINT64 Sctlr;
  UINT64 Daif;
  UINT64 ContextX0;
  UINT64 Cntfrq;
  UINT64 Cntvct;
  UINT64 Status;
  UINT64 CpuOnTarget;
  UINT64 GicInterface, GicTarget, GicCtlr, GicPmr, TimerControl, ReadyDaif;
  UINT64 Reserved1;
  UINT64 Parked;
} N976N_A55_ENTRY_WITNESS;

STATIC_ASSERT(sizeof(N976N_A55_ENTRY_CONFIG)==N976N_A55_ENTRY_CONFIG_BYTES,
              "A55 entry config size");
STATIC_ASSERT(sizeof(N976N_A55_ENTRY_WITNESS)==N976N_A55_ENTRY_WITNESS_BYTES,
              "A55 entry witness size");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_CONFIG,WitnessAddress)==N976N_A55_CONFIG_WITNESS_OFF,
              "A55 config physical witness offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_CONFIG,ExpectedAffinity)==N976N_A55_CONFIG_AFFINITY_OFF,
              "A55 config expected affinity offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_CONFIG,CpuOnTarget)==N976N_A55_CONFIG_TARGET_OFF,
              "A55 config CPU_ON target offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_WITNESS,CpuOnTarget)==N976N_A55_W_TARGET_OFF,
              "A55 witness CPU_ON target offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_WITNESS,Parked)==N976N_A55_W_PARKED_OFF,
              "A55 final commit offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_WITNESS,ContextX0)==N976N_A55_W_CONTEXT_OFF,
              "A55 incoming context offset");
STATIC_ASSERT(OFFSET_OF(N976N_A55_ENTRY_WITNESS,Status)==N976N_A55_W_STATUS_OFF,
              "A55 witness status offset");

/* Copy [Start,End) to an owned physical code page, patch the embedded config
 * before making it RO/X, and clean code/data before CPU_ON. Config-Start is the
 * patch offset: require 8-byte alignment, Config >= Start, and
 * Config + sizeof(CONFIG) <= End <= Start + MAX_BYTES. Each AP gets its own
 * immutable copied code/config and a disjoint, zero-initialized witness plus a separate standard mailbox page.
 * These are data symbols, not C-callable functions.
 */
extern CONST UINT8 N976nA55EntryStart[];
extern CONST UINT8 N976nA55EntryEnd[];
extern CONST UINT8 N976nA55EntryConfig[];

/* The SMP2 stub writes only after observing the physically measured EL1 and the current EL's M/C/I=0.
 * A rejected entry, a firmware hang, or an AP which never starts all leave no
 * committed witness. A BSP timeout cannot distinguish them or abort an SMC.
 * Parked is written LAST after a DSB; accept it only together with every fixed
 * field, exact expected identity, and the external ownership/guard checks.
 * The stub never returns, uses no stack, and branches only on the standard matching ID/nonzero aligned jump with ACK.
 * Its code/data must never be freed or reused after any CPU_ON attempt.
 */
#endif
#endif
