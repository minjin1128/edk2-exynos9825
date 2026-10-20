/** @file
  Bounded read-only FDT inventory and conservative, image-owned memory plan.
  Every standard resource HOB remains RESERVED, including intervals with no
  known fixed exclusion. Dynamic allocations and platform ownership are not
  resolved by this inspection milestone.
  SPDX-License-Identifier: MIT
**/
#include <Base.h>
#include <Library/BaseMemoryLib.h>
#include <LegacyMemory/MemoryPlan.h>

#define DTB_MIN       0x80000000ULL
#define DTB_MAX       0xBAB00000ULL
#define DTB_MAX_SIZE  0x100000ULL
#define MAX_DEPTH     16
#define KIND_OTHER    0
#define KIND_ROOT     1
#define KIND_RAM      2
#define KIND_CHOSEN   3
#define KIND_RESERVED 4
#define KIND_FIXED    5
#define KIND_SNAPSHOT 6
#define KIND_NESTED   7
#define SEEN_ADDR     0x01
#define SEEN_SIZECELL 0x02
#define SEEN_REG      0x04
#define SEEN_DYNAMIC  0x08
#define SEEN_RANGES   0x10
#define SEEN_ALLOC    0x20
#define SEEN_ALIGN    0x40
#define SEEN_STATUS   0x80

typedef struct {
  UINT32 AddressCells;
  UINT32 SizeCells;
  UINT32 Kind;
  UINT32 Seen;
  BOOLEAN HadChild;
  UINT32 DynamicId;
  UINT32 DynamicSeen;
} NODE;

STATIC UINT32 Be32 (CONST UINT8 *P)
{
  return ((UINT32)P[0] << 24) | ((UINT32)P[1] << 16) |
         ((UINT32)P[2] << 8) | P[3];
}

STATIC UINT64 Be64 (CONST UINT8 *P)
{
  return ((UINT64)Be32 (P) << 32) | Be32 (P + 4);
}

STATIC BOOLEAN Same (CONST UINT8 *P, UINTN Length, CONST CHAR8 *Text)
{
  UINTN I;
  for (I = 0; I < Length; I++) {
    if (P[I] != (UINT8)Text[I]) { return FALSE; }
    if (Text[I] == 0) { return (BOOLEAN)(I + 1 == Length); }
  }
  return FALSE;
}

STATIC BOOLEAN Prefix (CONST UINT8 *P, UINTN Length, CONST CHAR8 *Text)
{
  UINTN I;
  for (I = 0; Text[I] != 0; I++) {
    if (I >= Length || P[I] != (UINT8)Text[I]) { return FALSE; }
  }
  return TRUE;
}

STATIC BOOLEAN Extent (UINT64 Base, UINT64 Size)
{
  return (BOOLEAN)(Size != 0 && Base <= MAX_UINT64 - Size);
}

STATIC BOOLEAN Overlap (UINT64 A, UINT64 AS, UINT64 B, UINT64 BS)
{
  return (BOOLEAN)(AS != 0 && BS != 0 && A < B + BS && B < A + AS);
}

STATIC BOOLEAN Fits (UINT64 Start, UINT64 Size, UINT64 Total)
{
  return (BOOLEAN)(Start <= Total && Size <= Total - Start);
}

STATIC BOOLEAN CellWidth (UINT32 Width)
{
  return (BOOLEAN)(Width == 1 || Width == 2);
}

STATIC UINT64 ReadCells (CONST UINT8 *P, UINT32 Width)
{
  return Width == 1 ? Be32 (P) : Be64 (P);
}

STATIC UINT64 AppendRange (MEMORY_RANGE *Array, UINT64 *Count, UINT64 Cap,
                          UINT64 Base, UINT64 Size)
{
  if (!Extent (Base, Size)) { return 7; }
  if (*Count >= Cap) { return 13; }
  Array[*Count].Base = Base;
  Array[*Count].Size = Size;
  (*Count)++;
  return 0;
}

/* These are exactly the captured size-only Linux requests. Unknown properties
   (including reg/no-map/reusable/status changes) fail closed; Samsung's ion,
   properties are distinct from generic reserved-memory allocation properties.
   This permits a bounded experiment before Linux runs, not arbitrary DRAM. */
STATIC BOOLEAN DynamicProperty (NODE *N, CONST UINT8 *Name, UINTN NameLength,
                                CONST UINT8 *Value, UINTN Length)
{
  UINT32 Bit = 0;
  BOOLEAN Good = FALSE;
  UINT64 ExpectedSize = N->DynamicId == 1 ? 0x4800000 : N->DynamicId == 2 ? 0x1800000 : 0x4000000;
  if (Same (Name, NameLength, "compatible")) {
    Bit = 1; Good = Same (Value, Length, N->DynamicId == 3 ? "exynos,abox_rmem" : "exynos9820-ion");
  } else if (Same (Name, NameLength, "size")) {
    Bit = 2; Good = Length == 4 && Be32 (Value) == ExpectedSize;
  } else if (Same (Name, NameLength, "alignment")) {
    Bit = 4; Good = Length == 8 && Be64 (Value) == 0x400000;
  } else if (Same (Name, NameLength, "alloc-ranges")) {
    Bit = 8; Good = N->DynamicId != 2 && Length == 12 &&
      Be64 (Value) == (N->DynamicId == 1 ? 0x40000000ULL : 0xC0000000ULL) &&
      Be32 (Value + 8) == (N->DynamicId == 1 ? 0xB0000000U : 0x20000000U);
  } else if (N->DynamicId != 3 && Same (Name, NameLength, "ion,heapname")) {
    Bit = 0x10; Good = Same (Value, Length, N->DynamicId == 1 ? "vstream_heap" : "crypto_heap");
  } else if (N->DynamicId != 3 && Same (Name, NameLength, "ion,reusable")) {
    Bit = 0x20; Good = Length == 0;
  } else if (N->DynamicId != 3 && Same (Name, NameLength, "ion,alignment")) {
    Bit = 0x40; Good = Length == 4 && Be32 (Value) == 0x10000;
  } else if (N->DynamicId == 1 && Same (Name, NameLength, "ion,secure")) {
    Bit = 0x80; Good = Length == 0;
  } else if (N->DynamicId == 1 && Same (Name, NameLength, "ion,protection_id")) {
    Bit = 0x100; Good = Length == 4 && Be32 (Value) == 3;
  } else if (N->DynamicId == 3 && Same (Name, NameLength, "linux,phandle")) {
    Bit = 0x200; Good = Length == 4 && Be32 (Value) == 0x5F;
  } else if (N->DynamicId == 3 && Same (Name, NameLength, "phandle")) {
    Bit = 0x400; Good = Length == 4 && Be32 (Value) == 0x5F;
  }
  if (!Good || !Bit || (N->DynamicSeen & Bit)) { return FALSE; }
  N->DynamicSeen |= Bit;
  return TRUE;
}

__attribute__((noinline))
UINT64 EFIAPI ParseRuntimeDtb (CONST SEC_PROBE_HANDOFF *H, MEMORY_PLAN *Plan)
{
  CONST UINT8 *D;
  NODE Nodes[MAX_DEPTH];
  NODE *N;
  NODE *Parent;
  UINT64 Total, StructStart, StructSize, StructEnd, Strings, StringsSize;
  UINT64 Map, MapEnd, Cursor, Token, Depth, Length, NameStart, NameLength;
  UINT64 NameOff, ValueStart, ValueEnd, Next, Addr, Size, Width, Offset, Error;
  UINT64 RootSeen, ChosenSeen, ReservedSeen, InitrdSeen;
  UINT32 Bit;
  BOOLEAN IsReg, IsDynamic, IsAlloc, IsAlignment, Relevant;

  ZeroMem (Plan, sizeof (*Plan));
  ZeroMem (Nodes, sizeof (Nodes));
  if ((H->Dtb & 7) != 0 || H->Dtb < DTB_MIN || H->Dtb > DTB_MAX - 40) { return 1; }
  D = (CONST UINT8 *)(UINTN)H->Dtb;
  if (Be32 (D) != 0xD00DFEED) { return 2; }
  Total = Be32 (D + 4);
  if (Total < 40 || Total > DTB_MAX_SIZE || Total > DTB_MAX - H->Dtb) { return 3; }
  Plan->Info.DtbSize = Total;
  if (Be32 (D + 20) != 17 || Be32 (D + 24) > 17) { return 5; }
  StructStart = Be32 (D + 8); StructSize = Be32 (D + 36);
  Strings = Be32 (D + 12); StringsSize = Be32 (D + 32); Map = Be32 (D + 16);
  if (StructStart < 40 || (StructStart & 3) != 0 || StructSize < 4 ||
      (StructSize & 3) != 0 || !Fits (StructStart, StructSize, Total) ||
      Strings < 40 || !Fits (Strings, StringsSize, Total) ||
      Overlap (StructStart, StructSize, Strings, StringsSize) ||
      Map < 40 || (Map & 7) != 0 || Map >= Total) { return 4; }
  StructEnd = StructStart + StructSize;
  MapEnd = Total;
  if (Map >= StructStart && Map < StructEnd) { return 4; }
  if (StringsSize != 0 && Map >= Strings && Map < Strings + StringsSize) { return 4; }
  if (StructStart > Map && StructStart < MapEnd) { MapEnd = StructStart; }
  if (StringsSize != 0 && Strings > Map && Strings < MapEnd) { MapEnd = Strings; }
  for (Cursor = Map; ; Cursor += 16) {
    if (!Fits (Cursor, 16, MapEnd)) { return 6; }
    Addr = Be64 (D + Cursor); Size = Be64 (D + Cursor + 8);
    if (Addr == 0 && Size == 0) { break; }
    Error = AppendRange (Plan->ReserveMap, &Plan->Info.ReserveMapCount, MAX_MAP_RANGES, Addr, Size);
    if (Error != 0) { return Error; }
  }
  Cursor = StructStart; Depth = 0; RootSeen = 0; ChosenSeen = 0; ReservedSeen = 0; InitrdSeen = 0;
  while (Fits (Cursor, 4, StructEnd)) {
    Token = Be32 (D + Cursor); Cursor += 4;
    if (Token == 4) { continue; }
    if (Token == 9) {
      if (Depth != 0 || RootSeen != 1 || Cursor != StructEnd) { return 9; }
      if (Plan->Info.RamCount == 0 || InitrdSeen != 3 ||
          Plan->InitrdStart >= Plan->InitrdEnd) { return 14; }
      if (Plan->Info.DynamicCount != 3 || Plan->DynamicWhitelistMask != 7) { return 18; }
      Plan->Info.Version = 1;
      Plan->Info.PolicyFlags = POLICY_QUARANTINE | POLICY_NOT_DXE_READY |
                              (Plan->Info.DynamicCount != 0 ? POLICY_DYNAMIC : 0);
      return 0;
    }
    if (Token == 1) {
      if (Depth >= MAX_DEPTH) { return 9; }
      NameStart = Cursor;
      while (Cursor < StructEnd && Cursor - NameStart < 256 && D[Cursor] != 0) { Cursor++; }
      if (Cursor >= StructEnd || Cursor - NameStart >= 256) { return 10; }
      NameLength = Cursor - NameStart + 1;
      Cursor = (Cursor + 4) & ~3ULL;
      if (Cursor > StructEnd) { return 8; }
      N = &Nodes[Depth]; ZeroMem (N, sizeof (*N));
      N->AddressCells = 2; N->SizeCells = 1; N->Kind = KIND_OTHER;
      if (Depth == 0) {
        if (RootSeen != 0 || NameLength != 1) { return 9; }
        RootSeen = 1; N->Kind = KIND_ROOT;
      } else {
        Parent = &Nodes[Depth - 1]; Parent->HadChild = TRUE;
        if (Depth == 1) {
          if (Same (D + NameStart, NameLength, "memory") || Prefix (D + NameStart, NameLength, "memory@")) {
            N->Kind = KIND_RAM;
          } else if (Same (D + NameStart, NameLength, "chosen")) {
            if (ChosenSeen++ != 0) { return 12; } N->Kind = KIND_CHOSEN;
          } else if (Same (D + NameStart, NameLength, "reserved-memory")) {
            if (ReservedSeen++ != 0) { return 12; } N->Kind = KIND_RESERVED;
          }
        } else if (Parent->Kind == KIND_RESERVED) {
          N->Kind = Same (D + NameStart, NameLength, "debug_snapshot") ? KIND_SNAPSHOT : KIND_FIXED;
          if (Same (D + NameStart, NameLength, "ion_video_stream")) { N->DynamicId = 1; }
          else if (Same (D + NameStart, NameLength, "ion_crypto")) { N->DynamicId = 2; }
          else if (Same (D + NameStart, NameLength, "abox-rmem")) { N->DynamicId = 3; }
          if (N->DynamicId && (Depth != 2 || Parent->AddressCells != 2 || Parent->SizeCells != 1)) { return 18; }
        } else if (Parent->Kind == KIND_SNAPSHOT) {
          N->Kind = KIND_FIXED;
        } else if (Parent->Kind == KIND_FIXED || Parent->Kind == KIND_NESTED) {
          N->Kind = KIND_NESTED;
        }
      }
      Depth++; continue;
    }
    if (Token == 2) {
      if (Depth == 0) { return 9; }
      N = &Nodes[Depth - 1];
      if (N->DynamicId) {
        UINT32 Expected = N->DynamicId == 1 ? 0x1FF : N->DynamicId == 2 ? 0x77 : 0x60F;
        UINT64 Mask = 1ULL << (N->DynamicId - 1);
        if (N->HadChild || N->DynamicSeen != Expected || (Plan->DynamicWhitelistMask & Mask)) { return 18; }
        Plan->DynamicWhitelistMask |= Mask;
        Plan->Info.DynamicCount++;
        Depth--; continue;
      }
      if (N->Kind == KIND_RAM && (N->Seen & SEEN_REG) == 0) { return 14; }
      if (N->Kind == KIND_RESERVED && (N->Seen & SEEN_RANGES) == 0) { return 12; }
      if ((N->Seen & (SEEN_REG | SEEN_DYNAMIC)) == (SEEN_REG | SEEN_DYNAMIC)) { return 12; }
      if ((N->Kind == KIND_FIXED || N->Kind == KIND_SNAPSHOT) &&
          (N->Seen & (SEEN_ALLOC | SEEN_ALIGN)) != 0 && (N->Seen & SEEN_DYNAMIC) == 0) { return 12; }
      Depth--; continue;
    }
    if (Token != 3) { return 8; }
    if (Depth == 0 || Nodes[Depth - 1].HadChild || !Fits (Cursor, 8, StructEnd)) { return 9; }
    Length = Be32 (D + Cursor); NameOff = Be32 (D + Cursor + 4); Cursor += 8;
    ValueStart = Cursor;
    if (!Fits (Cursor, Length, StructEnd)) { return 8; }
    ValueEnd = Cursor + Length; Next = (ValueEnd + 3) & ~3ULL;
    if (Next > StructEnd || NameOff >= StringsSize) { return 10; }
    NameStart = Strings + NameOff; NameLength = 0;
    while (NameLength < 128 && NameOff + NameLength < StringsSize && D[NameStart + NameLength] != 0) { NameLength++; }
    if (NameLength >= 128 || NameOff + NameLength >= StringsSize) { return 10; }
    NameLength++;
    N = &Nodes[Depth - 1]; Parent = Depth > 1 ? &Nodes[Depth - 2] : NULL;
    if (N->DynamicId) {
      if (!DynamicProperty (N, D + NameStart, NameLength, D + ValueStart, Length)) { return 18; }
      Cursor = Next; continue;
    }
    if ((N->Kind == KIND_RAM || N->Kind == KIND_RESERVED || N->Kind == KIND_FIXED ||
         N->Kind == KIND_SNAPSHOT || N->Kind == KIND_NESTED) && Same (D + NameStart, NameLength, "status")) {
      if ((N->Seen & SEEN_STATUS) != 0 ||
          (!Same (D + ValueStart, Length, "okay") && !Same (D + ValueStart, Length, "ok"))) { return 12; }
      N->Seen |= SEEN_STATUS; Cursor = Next; continue;
    }
    if (Same (D + NameStart, NameLength, "#address-cells") || Same (D + NameStart, NameLength, "#size-cells")) {
      Bit = Same (D + NameStart, NameLength, "#address-cells") ? SEEN_ADDR : SEEN_SIZECELL;
      if (Length != 4 || (N->Seen & Bit) != 0) { return 11; }
      N->Seen |= Bit;
      if (Bit == SEEN_ADDR) { N->AddressCells = Be32 (D + ValueStart); }
      else { N->SizeCells = Be32 (D + ValueStart); }
      Cursor = Next; continue;
    }
    if ((N->Kind == KIND_RESERVED || N->Kind == KIND_SNAPSHOT || N->Kind == KIND_FIXED || N->Kind == KIND_NESTED) &&
        Same (D + NameStart, NameLength, "ranges")) {
      if (Length != 0 || (N->Seen & SEEN_RANGES) != 0) { return 12; }
      N->Seen |= SEEN_RANGES; Cursor = Next; continue;
    }
    if (N->Kind == KIND_CHOSEN && (Same (D + NameStart, NameLength, "linux,initrd-start") ||
                                  Same (D + NameStart, NameLength, "linux,initrd-end"))) {
      Bit = Same (D + NameStart, NameLength, "linux,initrd-start") ? 1 : 2;
      if ((Length != 4 && Length != 8) || (InitrdSeen & Bit) != 0) { return 11; }
      Addr = Length == 4 ? Be32 (D + ValueStart) : Be64 (D + ValueStart);
      if (Bit == 1) { Plan->InitrdStart = Addr; } else { Plan->InitrdEnd = Addr; }
      InitrdSeen |= Bit; Cursor = Next; continue;
    }
    IsReg = Same (D + NameStart, NameLength, "reg");
    IsDynamic = Same (D + NameStart, NameLength, "size");
    IsAlloc = Same (D + NameStart, NameLength, "alloc-ranges");
    IsAlignment = Same (D + NameStart, NameLength, "alignment");
    Relevant = (BOOLEAN)(N->Kind == KIND_RAM || N->Kind == KIND_FIXED || N->Kind == KIND_SNAPSHOT);
    if ((N->Kind == KIND_NESTED || N->Kind == KIND_RESERVED) && (IsReg || IsDynamic || IsAlloc || IsAlignment)) { return 12; }
    if (!Relevant || (!IsReg && !IsDynamic && !IsAlloc && !IsAlignment)) { Cursor = Next; continue; }
    if (Parent == NULL || !CellWidth (Parent->AddressCells) || !CellWidth (Parent->SizeCells)) { return 11; }
    if (N->Kind == KIND_RAM && !IsReg) { return 12; }
    Bit = IsReg ? SEEN_REG : IsDynamic ? SEEN_DYNAMIC : IsAlloc ? SEEN_ALLOC : SEEN_ALIGN;
    if ((N->Seen & Bit) != 0) { return 12; }
    N->Seen |= Bit;
    // Samsung's three dynamic reservations encode alignment as two cells
    // even though their parent size-cells is one. Accept this bounded vendor
    // representation; no allocation is performed from these requests.
    Width = IsAlignment ? Length : (IsReg || IsAlloc) ? 4 * (Parent->AddressCells + Parent->SizeCells) : 4 * Parent->SizeCells;
    if (IsAlignment && Length != 4 && Length != 8) { return 11; }
    if (Length == 0 || Length % Width != 0 || ((IsDynamic || IsAlignment) && Length != Width)) { return 11; }
    if (IsDynamic || IsAlignment) {
      Size = ReadCells (D + ValueStart, IsAlignment ? (UINT32)(Length / 4) : Parent->SizeCells);
      if (Size == 0 || (IsAlignment && (Size & (Size - 1)) != 0)) { return 7; }
      if (IsDynamic) {
        // A size-only reservation not matched above has unknown ownership.
        return 18;
      }
    } else {
      for (Offset = 0; Offset < Length; Offset += Width) {
        Addr = ReadCells (D + ValueStart + Offset, Parent->AddressCells);
        Size = ReadCells (D + ValueStart + Offset + 4 * Parent->AddressCells, Parent->SizeCells);
        if (!Extent (Addr, Size)) { return 7; }
        if (!IsAlloc) {
          if (N->Kind == KIND_RAM) { Error = AppendRange (Plan->Ram, &Plan->Info.RamCount, MAX_RAM_RANGES, Addr, Size); }
          else { Error = AppendRange (Plan->Fixed, &Plan->Info.FixedCount, MAX_FIXED_RANGES, Addr, Size); }
          if (Error != 0) { return Error; }
        }
      }
    }
    Cursor = Next;
  }
  return 8;
}

STATIC BOOLEAN Covered (CONST MEMORY_PLAN *P, UINT64 Base, UINT64 Size)
{
  UINT64 I, End, Cursor;
  if (!Extent (Base, Size)) { return FALSE; }
  End = Base + Size; Cursor = Base;
  for (I = 0; I < P->Info.RamCount && Cursor < End; I++) {
    if (P->Ram[I].Base > Cursor) { return FALSE; }
    if (P->Ram[I].Base + P->Ram[I].Size > Cursor) { Cursor = P->Ram[I].Base + P->Ram[I].Size; }
  }
  return (BOOLEAN)(Cursor >= End);
}

STATIC BOOLEAN AddExclusion (MEMORY_PLAN *P, UINT64 Base, UINT64 Size, UINT64 Reason)
{
  UINT64 End;
  if (!Extent (Base, Size) || Base + Size > MAX_UINT64 - 0xFFF || P->ExclusionCount >= MAX_EXCLUSIONS) { return FALSE; }
  End = (Base + Size + 0xFFF) & ~0xFFFULL; Base &= ~0xFFFULL;
  P->Exclusions[P->ExclusionCount].Base = Base;
  P->Exclusions[P->ExclusionCount].Size = End - Base;
  P->Exclusions[P->ExclusionCount].Reasons = Reason;
  P->ExclusionCount++;
  return TRUE;
}

STATIC BOOLEAN ExclusionMatches (CONST MEMORY_SEGMENT *E, UINT64 Base, UINT64 Size, UINT64 Reason)
{
  UINT64 End;
  if (!Extent (Base, Size) || Base + Size > MAX_UINT64 - 0xFFF) { return FALSE; }
  End = (Base + Size + 0xFFF) & ~0xFFFULL; Base &= ~0xFFFULL;
  return (BOOLEAN)(E->Base == Base && E->Size == End - Base && E->Reasons == Reason);
}

__attribute__((noinline))
UINT64 EFIAPI BuildMemoryPlan (CONST SEC_PROBE_HANDOFF *H, MEMORY_PLAN *P)
{
  MEMORY_RANGE Temp;
  MEMORY_SEGMENT *S;
  UINT64 I, J, Base, End, Cursor, Next, Reasons, EBase, EEnd;
  if (P->Info.RamCount == 0 || P->Info.RamCount > MAX_RAM_RANGES ||
      P->Info.FixedCount > MAX_FIXED_RANGES || P->Info.ReserveMapCount > MAX_MAP_RANGES ||
      P->Info.DynamicCount > MAX_DYNAMIC_NODES) { return 13; }
  for (I = 0; I < P->Info.RamCount; I++) {
    if (!Extent (P->Ram[I].Base, P->Ram[I].Size) || ((P->Ram[I].Base | P->Ram[I].Size) & 0xFFF) != 0) { return 15; }
    for (J = I; J > 0 && P->Ram[J - 1].Base > P->Ram[J].Base; J--) {
      Temp = P->Ram[J - 1]; P->Ram[J - 1] = P->Ram[J]; P->Ram[J] = Temp;
    }
  }
  for (I = 0; I < P->Info.RamCount; I++) {
    if (I != 0 && P->Ram[I - 1].Base + P->Ram[I - 1].Size > P->Ram[I].Base) { return 15; }
    if (P->Info.RamBytes > MAX_UINT64 - P->Ram[I].Size) { return 15; }
    P->Info.RamBytes += P->Ram[I].Size;
  }
  if (H->ImageBase >= H->ImageEnd || P->InitrdStart >= P->InitrdEnd ||
      !Covered (P, H->ImageBase, H->ImageEnd - H->ImageBase) ||
      !Covered (P, H->Dtb, P->Info.DtbSize) ||
      !Covered (P, P->InitrdStart, P->InitrdEnd - P->InitrdStart) ||
      Overlap (H->ImageBase, H->ImageEnd - H->ImageBase, H->Dtb, P->Info.DtbSize) ||
      Overlap (H->ImageBase, H->ImageEnd - H->ImageBase, P->InitrdStart, P->InitrdEnd - P->InitrdStart) ||
      Overlap (H->Dtb, P->Info.DtbSize, P->InitrdStart, P->InitrdEnd - P->InitrdStart)) { return 16; }
  for (I = 0; I < P->Info.FixedCount; I++) {
    if (!AddExclusion (P, P->Fixed[I].Base, P->Fixed[I].Size, REASON_FIXED)) { return 7; }
  }
  for (I = 0; I < P->Info.ReserveMapCount; I++) {
    if (!AddExclusion (P, P->ReserveMap[I].Base, P->ReserveMap[I].Size, REASON_MEMRESERVE)) { return 7; }
  }
  if (!AddExclusion (P, H->ImageBase, H->ImageEnd - H->ImageBase, REASON_IMAGE) ||
      !AddExclusion (P, H->Dtb, P->Info.DtbSize, REASON_DTB) ||
      !AddExclusion (P, P->InitrdStart, P->InitrdEnd - P->InitrdStart, REASON_INITRD) ||
      !AddExclusion (P, FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE, REASON_FRAMEBUFFER)) { return 7; }
  for (I = 0; I < P->Info.RamCount; I++) {
    Base = P->Ram[I].Base; End = Base + P->Ram[I].Size; Cursor = Base;
    while (Cursor < End) {
      Next = End; Reasons = 0;
      for (J = 0; J < P->ExclusionCount; J++) {
        EBase = P->Exclusions[J].Base; EEnd = EBase + P->Exclusions[J].Size;
        if (EBase > Cursor && EBase < Next) { Next = EBase; }
        if (EEnd > Cursor && EEnd < Next) { Next = EEnd; }
        if (EBase <= Cursor && Cursor < EEnd) { Reasons |= P->Exclusions[J].Reasons; }
      }
      if (Next <= Cursor || P->Info.SegmentCount >= MAX_SEGMENTS) { return 17; }
      S = &P->Segments[P->Info.SegmentCount++];
      S->Base = Cursor; S->Size = Next - Cursor; S->Reasons = Reasons;
      if (Reasons != 0) { P->Info.ProtectedBytes += S->Size; }
      else { P->Info.CandidateBytes += S->Size; }
      Cursor = Next;
    }
  }
  return ValidateMemoryPlan (H, P) ? 0 : 17;
}

__attribute__((noinline))
BOOLEAN EFIAPI ValidateMemoryPlan (CONST SEC_PROBE_HANDOFF *H, CONST MEMORY_PLAN *P)
{
  UINT64 I, J, K, Cursor, BankEnd, Expected, Protected, Candidate, Total;
  CONST MEMORY_SEGMENT *S;
  if (P->Info.Version != 1 || P->Info.Reserved != 0 || P->Info.RamCount == 0 ||
      P->Info.RamCount > MAX_RAM_RANGES || P->Info.SegmentCount == 0 || P->Info.SegmentCount > MAX_SEGMENTS ||
      P->Info.FixedCount > MAX_FIXED_RANGES || P->Info.ReserveMapCount > MAX_MAP_RANGES ||
      P->Info.DynamicCount != 3 || P->DynamicWhitelistMask != 7 || P->ExclusionCount != P->Info.FixedCount + P->Info.ReserveMapCount + 4 ||
      P->Info.PolicyFlags != (POLICY_QUARANTINE | POLICY_NOT_DXE_READY | (P->Info.DynamicCount != 0 ? POLICY_DYNAMIC : 0))) { return FALSE; }
  if (H->Dtb < DTB_MIN || H->Dtb > DTB_MAX - 40 || (H->Dtb & 7) != 0 ||
      P->Info.DtbSize < 40 || P->Info.DtbSize > DTB_MAX_SIZE || P->Info.DtbSize > DTB_MAX - H->Dtb ||
      H->ImageBase >= H->ImageEnd || P->InitrdStart >= P->InitrdEnd ||
      Overlap (H->ImageBase, H->ImageEnd - H->ImageBase, H->Dtb, P->Info.DtbSize) ||
      Overlap (H->ImageBase, H->ImageEnd - H->ImageBase, P->InitrdStart, P->InitrdEnd - P->InitrdStart) ||
      Overlap (H->Dtb, P->Info.DtbSize, P->InitrdStart, P->InitrdEnd - P->InitrdStart)) { return FALSE; }
  K = 0;
  for (I = 0; I < P->Info.FixedCount; I++, K++) {
    if (!ExclusionMatches (&P->Exclusions[K], P->Fixed[I].Base, P->Fixed[I].Size, REASON_FIXED)) { return FALSE; }
  }
  for (I = 0; I < P->Info.ReserveMapCount; I++, K++) {
    if (!ExclusionMatches (&P->Exclusions[K], P->ReserveMap[I].Base, P->ReserveMap[I].Size, REASON_MEMRESERVE)) { return FALSE; }
  }
  if (!ExclusionMatches (&P->Exclusions[K], H->ImageBase, H->ImageEnd - H->ImageBase, REASON_IMAGE) ||
      !ExclusionMatches (&P->Exclusions[K+1], H->Dtb, P->Info.DtbSize, REASON_DTB) ||
      !ExclusionMatches (&P->Exclusions[K+2], P->InitrdStart, P->InitrdEnd - P->InitrdStart, REASON_INITRD) ||
      !ExclusionMatches (&P->Exclusions[K+3], FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE, REASON_FRAMEBUFFER)) { return FALSE; }
  J = 0; Total = 0; Protected = 0; Candidate = 0;
  for (I = 0; I < P->Info.RamCount; I++) {
    if (!Extent (P->Ram[I].Base, P->Ram[I].Size) || ((P->Ram[I].Base | P->Ram[I].Size) & 0xFFF) != 0 ||
        (I != 0 && P->Ram[I-1].Base + P->Ram[I-1].Size > P->Ram[I].Base) || Total > MAX_UINT64 - P->Ram[I].Size) { return FALSE; }
    Cursor = P->Ram[I].Base; BankEnd = Cursor + P->Ram[I].Size; Total += P->Ram[I].Size;
    while (Cursor < BankEnd) {
      if (J >= P->Info.SegmentCount) { return FALSE; }
      S = &P->Segments[J++];
      if (S->Base != Cursor || !Extent (S->Base, S->Size) || S->Size > BankEnd - Cursor || ((S->Base | S->Size) & 0xFFF) != 0) { return FALSE; }
      Expected = 0;
      for (K = 0; K < P->ExclusionCount; K++) {
        if (!Extent (P->Exclusions[K].Base, P->Exclusions[K].Size)) { return FALSE; }
        if (Overlap (S->Base, S->Size, P->Exclusions[K].Base, P->Exclusions[K].Size)) {
          if (S->Base < P->Exclusions[K].Base || S->Base + S->Size > P->Exclusions[K].Base + P->Exclusions[K].Size) { return FALSE; }
          Expected |= P->Exclusions[K].Reasons;
        }
      }
      if (S->Reasons != Expected || (Expected & ~0x3FULL) != 0) { return FALSE; }
      if (Expected != 0) { Protected += S->Size; } else { Candidate += S->Size; }
      Cursor += S->Size;
    }
  }
  if (J != P->Info.SegmentCount || Total != P->Info.RamBytes || Protected != P->Info.ProtectedBytes ||
      Candidate != P->Info.CandidateBytes || Protected > Total || Candidate != Total - Protected) { return FALSE; }
  return (BOOLEAN)(Covered (P, H->ImageBase, H->ImageEnd - H->ImageBase) &&
                   Covered (P, H->Dtb, P->Info.DtbSize) &&
                   Covered (P, P->InitrdStart, P->InitrdEnd - P->InitrdStart));
}

__attribute__((noinline))
BOOLEAN EFIAPI ValidateExternalMemoryPolicy (CONST SEC_PROBE_HANDOFF *H, CONST MEMORY_PLAN *P, UINT64 *Checks)
{
  UINT64 Base = N976N_EXT_WINDOW_BASE, Size = N976N_EXT_WINDOW_SIZE, CoveredBytes = 0;
  BOOLEAN InBank = FALSE;
  *Checks = 0;
  if (H->BootInfo.ExternalBase != Base || H->BootInfo.ExternalSize != Size ||
      H->BootInfo.ExternalPolicyChecks || H->BootInfo.ExternalPolicyStatus ||
      !ValidateMemoryPlan (H, P)) { return FALSE; }
  *Checks |= 1;
  if (P->Info.DynamicCount != 3 || P->DynamicWhitelistMask != 7) { return FALSE; }
  *Checks |= 2;
  for (UINTN I = 0; I < P->Info.RamCount; I++) {
    if (Base >= P->Ram[I].Base && Size <= P->Ram[I].Size && Base - P->Ram[I].Base <= P->Ram[I].Size - Size) { InBank = TRUE; }
  }
  if (!InBank) { return FALSE; }
  *Checks |= 4;
  for (UINTN I = 0; I < P->Info.FixedCount; I++) {
    if (Overlap (Base, Size, P->Fixed[I].Base, P->Fixed[I].Size)) { return FALSE; }
  }
  *Checks |= 8;
  for (UINTN I = 0; I < P->Info.ReserveMapCount; I++) {
    if (Overlap (Base, Size, P->ReserveMap[I].Base, P->ReserveMap[I].Size)) { return FALSE; }
  }
  *Checks |= 0x10;
  if (Overlap (Base, Size, H->ImageBase, H->ImageEnd - H->ImageBase) ||
      Overlap (Base, Size, H->Dtb, P->Info.DtbSize) ||
      Overlap (Base, Size, P->InitrdStart, P->InitrdEnd - P->InitrdStart) ||
      Overlap (Base, Size, FRAMEBUFFER_BASE, FRAMEBUFFER_SIZE)) { return FALSE; }
  *Checks |= 0x20;
  for (UINTN I = 0; I < P->Info.SegmentCount; I++) {
    CONST MEMORY_SEGMENT *S = &P->Segments[I];
    if (Overlap (Base, Size, S->Base, S->Size)) {
      UINT64 A = S->Base > Base ? S->Base : Base;
      UINT64 E = S->Base + S->Size < Base + Size ? S->Base + S->Size : Base + Size;
      if (S->Reasons) { return FALSE; }
      CoveredBytes += E - A;
    }
  }
  if (CoveredBytes != Size) { return FALSE; }
  *Checks |= 0x40;
  if ((Base | Size) & 4095 || Base + Size > 0x100000000ULL ||
      N976N_EXT_USABLE_BASE != Base + 4096 || N976N_EXT_USABLE_SIZE != Size - 8192) { return FALSE; }
  *Checks |= 0x80;
  return TRUE;
}
