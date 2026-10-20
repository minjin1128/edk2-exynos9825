/* SPDX-License-Identifier: MIT
 * Private bootshim-to-SEC ABI, not EFI_SEC_PEI_HAND_OFF or an EFI system table.
 * Both sides use 64-bit fields; callback takes (event, value) in x0/x1.
 */
#ifndef N976N_DXE_SEC_PROBE_H
#define N976N_DXE_SEC_PROBE_H
#define SEC_HANDOFF_MAGIC 0x4E39373653454344
#define SEC_ENTER_MAGIC   0x53454344454E5452
#define SEC_DONE_MAGIC    0x53454344444F4E45
#define SEC_DATA_MAGIC    0x13579BDF2468ACE0
#define SEC_CHECKS_ALL    0x7F
#define SEC_HANDOFF_SIZE  816
#define SEC_OFF_ENTERED   80
#define SEC_OFF_CHECKS    88
#define SEC_OFF_STATUS    96
#define SEC_OFF_POINTER   104
#define SEC_OFF_LIB_VALUE 112
#define SEC_OFF_BSS       120
#define SEC_OFF_COMPLETE  128
#define HOB_OFF_BASE       144
#define HOB_OFF_END        152
#define HOB_OFF_COUNT      160
#define HOB_OFF_USED       168
#define HOB_OFF_CHECKS     176
#define HOB_OFF_STATUS     184
#define HOB_OFF_CAPACITY   192
#define HOB_CHECKS_ALL     0xFF
#define HOB_ARENA_SIZE     16384
#define MEMORY_OFF_DTB_SIZE 208
#define MEMORY_OFF_RAM_COUNT 216
#define MEMORY_OFF_FIXED_COUNT 224
#define MEMORY_OFF_DYNAMIC_COUNT 232
#define MEMORY_OFF_RESERVE_MAP_COUNT 240
#define MEMORY_OFF_SEGMENT_COUNT 248
#define MEMORY_OFF_CHECKS 256
#define MEMORY_OFF_STATUS 264
#define MEMORY_OFF_POLICY_FLAGS 272
#define MEMORY_OFF_RAM_BYTES 280
#define MEMORY_OFF_PROTECTED_BYTES 288
#define MEMORY_OFF_CANDIDATE_BYTES 296
#define MEMORY_OFF_FIRST_CANDIDATE_BASE 304
#define MEMORY_OFF_FIRST_CANDIDATE_SIZE 312
#define MEMORY_OFF_INITRD_START 320
#define MEMORY_OFF_INITRD_END 328
#define MEMORY_OFF_PARSE_STATUS 336
#define MEMORY_OFF_RESERVED 344
#define MEMORY_CHECKS_ALL 0xFF
#define TRANSLATION_OFF_CPU_MMFR0 352
#define TRANSLATION_OFF_CPU_SCTLR 360
#define TRANSLATION_OFF_POOL_BASE 368
#define TRANSLATION_OFF_POOL_SIZE 376
#define TRANSLATION_OFF_WRAPPER_CODE_BASE 384
#define TRANSLATION_OFF_WRAPPER_CODE_END 392
#define TRANSLATION_OFF_MODULE_CODE_BASE 400
#define TRANSLATION_OFF_MODULE_CODE_END 408
#define TRANSLATION_OFF_BASE 416
#define TRANSLATION_OFF_PAGES 424
#define TRANSLATION_OFF_MAPPED_PAGES 432
#define TRANSLATION_OFF_CHECKS 440
#define TRANSLATION_OFF_STATUS 448
#define TRANSLATION_OFF_PA_BITS 456
#define TRANSLATION_OFF_GRANULE_4K 464
#define TRANSLATION_OFF_TCR 472
#define TRANSLATION_OFF_MAIR 480
#define TRANSLATION_OFF_ERROR 488
#define TRANSLATION_OFF_WALK_CHECKS 496
#define TRANSLATION_OFF_MMU_ON 504
#define TRANSLATION_OFF_GUARD_CHECKS 512
#define TRANSLATION_OFF_RESERVED 520
#define TRANSLATION_CHECKS_ALL 0xFF
#define TRANSLATION_POOL_PAGES 64
#define TRANSLATION_POOL_SIZE 262144
#define TRANSLATION_GUARD_MAGIC 0x5441424C45313047
#define DXE_OFF_BOOT_INFO 528
#define DXE_OFF_PREPARE_CHECKS 744
#define DXE_OFF_PREPARE_STATUS 752
#define DXE_OFF_PREPARE_ERROR 760
#define DXE_OFF_HOB_ADDRESS 768
#define DXE_OFF_HOB_USED 776
#define DXE_OFF_HOB_COUNT 784
#define DXE_OFF_FREE_BOTTOM 792
#define DXE_OFF_FREE_TOP 800
#define DXE_OFF_HEAP_TESTED 808
#define DXE_PREPARE_CHECKS_ALL 0xFF
#define DXE_HEAP_GUARD_MAGIC 0x4845415031324752
#define SEC_IMAGE_MAX_SIZE 0xC00000
/* The final Image section is the complete read-only/XN FAT volume. The pinned
 * BYDJ PE is an ordinary file inside it, with no second raw source copy.
 * Independent linker symbols and generated CRCs bind both nested ranges.
 * Neither source range is published as general allocatable memory. */
#define SEC_BOOT_VOLUME_SIZE 0x300000
#define SEC_BOOT_VOLUME_BASE(H) ((H)->ImageEnd - SEC_BOOT_VOLUME_SIZE)
#define SEC_BOOT_PAYLOAD_OFFSET 0x7F000
#define SEC_BOOT_PAYLOAD_FILE_SIZE 2622896
#define SEC_BOOT_PAYLOAD_SPAN 0x281000
#define SEC_BOOT_PAYLOAD_BASE(H) ((H)->ImageEnd - SEC_BOOT_PAYLOAD_SPAN)
#ifndef __ASSEMBLER__
#include "DxeProbe.h"
#ifdef N976N_EDK2_MODULE
#include <Base.h>
typedef UINT64 sec_u64;
#else
#include <stdint.h>
typedef uint64_t sec_u64;
#endif
typedef void (*SEC_SCREEN_CALLBACK)(sec_u64 Event, sec_u64 Value);
typedef struct {
  sec_u64 Magic;
  sec_u64 Size;
  sec_u64 ImageBase;
  sec_u64 ImageEnd;
  sec_u64 ModuleBase;
  sec_u64 ModuleSize;
  sec_u64 Dtb;
  sec_u64 StackBottom;
  sec_u64 StackTop;
  SEC_SCREEN_CALLBACK Screen;
  sec_u64 Entered;
  sec_u64 Checks;
  sec_u64 Status;
  sec_u64 Pointer;
  sec_u64 LibValue;
  sec_u64 BssBefore;
  sec_u64 Complete;
  sec_u64 Reserved;
  sec_u64 HobBase;
  sec_u64 HobEnd;
  sec_u64 HobCount;
  sec_u64 HobUsed;
  sec_u64 HobChecks;
  sec_u64 HobStatus;
  sec_u64 HobCapacity;
  sec_u64 HobReserved;
  sec_u64 DtbSize;
  sec_u64 RamCount;
  sec_u64 FixedCount;
  sec_u64 DynamicCount;
  sec_u64 ReserveMapCount;
  sec_u64 SegmentCount;
  sec_u64 MemoryChecks;
  sec_u64 MemoryStatus;
  sec_u64 PolicyFlags;
  sec_u64 RamBytes;
  sec_u64 ProtectedBytes;
  sec_u64 CandidateBytes;
  sec_u64 FirstCandidateBase;
  sec_u64 FirstCandidateSize;
  sec_u64 InitrdStart;
  sec_u64 InitrdEnd;
  sec_u64 ParseStatus;
  sec_u64 MemoryReserved;
  sec_u64 CpuMmfr0;
  sec_u64 CpuSctlr;
  sec_u64 TablePoolBase;
  sec_u64 TablePoolSize;
  sec_u64 WrapperCodeBase;
  sec_u64 WrapperCodeEnd;
  sec_u64 ModuleCodeBase;
  sec_u64 ModuleCodeEnd;
  sec_u64 TableBase;
  sec_u64 TablePages;
  sec_u64 MappedPages;
  sec_u64 TranslationChecks;
  sec_u64 TranslationStatus;
  sec_u64 PaBits;
  sec_u64 Granule4K;
  sec_u64 PlanTcr;
  sec_u64 PlanMair;
  sec_u64 TranslationError;
  sec_u64 WalkChecks;
  sec_u64 MmuOn;
  sec_u64 GuardChecks;
  sec_u64 TranslationReserved;
  N976N_DXE_BOOT_INFO BootInfo;
  sec_u64 PrepareChecks;
  sec_u64 PrepareStatus;
  sec_u64 PrepareError;
  sec_u64 DxeHobAddress;
  sec_u64 DxeHobUsed;
  sec_u64 DxeHobCount;
  sec_u64 DxeFreeBottom;
  sec_u64 DxeFreeTop;
  sec_u64 HeapTested;
} SEC_PROBE_HANDOFF;
#endif
#endif
