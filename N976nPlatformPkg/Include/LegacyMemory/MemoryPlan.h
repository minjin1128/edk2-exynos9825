/* SPDX-License-Identifier: MIT */
#ifndef N976N_MEMORY_PLAN_H
#define N976N_MEMORY_PLAN_H
#include <Base.h>
#include "TranslationProbe.h"

#define MAX_RAM_RANGES       16
#define MAX_FIXED_RANGES     64
#define MAX_MAP_RANGES       32
#define MAX_DYNAMIC_NODES    16
#define MAX_SEGMENTS         192
#define MAX_EXCLUSIONS       (MAX_FIXED_RANGES + MAX_MAP_RANGES + 4)
#define FRAMEBUFFER_BASE     0xCA000000ULL
#define FRAMEBUFFER_SIZE     0x010B3000ULL
#define REASON_FIXED         0x01ULL
#define REASON_MEMRESERVE    0x02ULL
#define REASON_IMAGE         0x04ULL
#define REASON_DTB           0x08ULL
#define REASON_INITRD        0x10ULL
#define REASON_FRAMEBUFFER   0x20ULL
#define POLICY_QUARANTINE    0x01ULL
#define POLICY_DYNAMIC       0x02ULL
#define POLICY_NOT_DXE_READY 0x04ULL

typedef struct { UINT64 Base; UINT64 Size; } MEMORY_RANGE;
typedef struct { UINT64 Base; UINT64 Size; UINT64 Reasons; } MEMORY_SEGMENT;

typedef struct {
  UINT64 Version;
  UINT64 DtbSize;
  UINT64 RamCount;
  UINT64 FixedCount;
  UINT64 DynamicCount;
  UINT64 ReserveMapCount;
  UINT64 SegmentCount;
  UINT64 PolicyFlags;
  UINT64 RamBytes;
  UINT64 ProtectedBytes;
  UINT64 CandidateBytes;
  UINT64 Reserved;
} MEMORY_MAP_INFO;

typedef struct {
  MEMORY_MAP_INFO Info;
  MEMORY_RANGE Ram[MAX_RAM_RANGES];
  MEMORY_RANGE Fixed[MAX_FIXED_RANGES];
  MEMORY_RANGE ReserveMap[MAX_MAP_RANGES];
  MEMORY_SEGMENT Exclusions[MAX_EXCLUSIONS];
  MEMORY_SEGMENT Segments[MAX_SEGMENTS];
  UINT64 ExclusionCount;
  UINT64 InitrdStart;
  UINT64 InitrdEnd;
  UINT64 DynamicWhitelistMask;
} MEMORY_PLAN;

// ParseStatus: 0 success; 1 pointer,2 magic,3 size,4 layout,5 version,
// 6 reserve map,7 overflow/zero interval,8 token/bounds,9 tree/depth,
// 10 name/string,11 property/cells,12 duplicate/unsupported memory shape,
// 13 fixed array cap,14 missing required RAM/initrd,15 RAM alignment/overlap,
// 16 live-range coverage/overlap,17 segment cap/coverage.
UINT64 EFIAPI ParseRuntimeDtb (CONST SEC_PROBE_HANDOFF *H, MEMORY_PLAN *Plan);
UINT64 EFIAPI BuildMemoryPlan (CONST SEC_PROBE_HANDOFF *H, MEMORY_PLAN *Plan);
BOOLEAN EFIAPI ValidateMemoryPlan (CONST SEC_PROBE_HANDOFF *H, CONST MEMORY_PLAN *Plan);
CONST MEMORY_PLAN *GetValidatedMemoryPlan (VOID);
BOOLEAN EFIAPI ValidateExternalMemoryPolicy (CONST SEC_PROBE_HANDOFF *H, CONST MEMORY_PLAN *P, UINT64 *Checks);
#endif
