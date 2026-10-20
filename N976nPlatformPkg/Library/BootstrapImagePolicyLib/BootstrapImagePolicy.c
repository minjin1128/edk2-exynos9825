/** @file Bounded image admission against the immutable SEC49 FV.
 * The upstream loader still loads and relocates each image. This hook verifies
 * its result independently and only then publishes executable pages. No Windows
 * call sequence, filename allowlist, service replacement, or allocator is added.
 * FV provenance is the build/launch binding plus the RO mapping, not signature
 * authentication. The current bootstrap trusts its pinned Core and HOB producer.
 */
// SPDX-License-Identifier: MIT
#include <Uefi.h>
#include <Pi/PiBootMode.h>
#include <Pi/PiHob.h>
#include <AArch64/AArch64Mmu.h>
#include <Library/ArmMmuLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/CacheMaintenanceLib.h>
#include <Library/DebugLib.h>
#include <Library/HobLib.h>
#include <Library/PeCoffExtraActionLib.h>
#include <Library/N976nBootstrapPolicy.h>
#include <N976nPlatform.h>

#define PAGE 4096U
#define MAX_SECTIONS 24U
#define READ_BIT  0x40000000U
#define WRITE_BIT 0x80000000U
#define EXEC_BIT  0x20000000U
STATIC CONST EFI_GUID mPolicyGuid = N976N_BOOTSTRAP_POLICY_HOB_GUID;
STATIC CONST EFI_GUID mFfs2Guid = {0x8c8ce578,0x8a3d,0x4f1c,{0x99,0x35,0x89,0x61,0x85,0xc3,0x2d,0xd3}};

typedef struct {
  CONST UINT8 *Source;
  UINTN Bytes, Pe, Optional, Sections, Count, Headers, Size, Entry;
  UINTN RelocRva, RelocBytes;
  UINT64 Preferred;
  UINT16 Subsystem;
} PE_VIEW;

STATIC UINT64 ReadLe (CONST UINT8 *P, UINTN N)
{ UINT64 V = 0; for (UINTN I = 0; I < N; I++) V |= (UINT64)P[I] << (I * 8); return V; }
STATIC UINTN Round (UINTN V, UINTN A) { return (V + A - 1) & ~(A - 1); }
STATIC BOOLEAN Span (UINT64 A, UINT64 N, UINT64 Base, UINT64 End)
{ return N && A >= Base && A < End && N <= End - A; }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return N && M && A < B + M && B < A + N; }
STATIC CONST UINT8 *Section (CONST PE_VIEW *V, UINTN I)
{ return V->Source + V->Sections + 40 * I; }
STATIC UINTN Copied (CONST UINT8 *S)
{ UINTN V = ReadLe (S + 8, 4), R = ReadLe (S + 16, 4); return V < R ? V : R; }
STATIC UINTN SectionSpan (CONST UINT8 *S)
{ UINTN V = ReadLe (S + 8, 4), R = ReadLe (S + 16, 4); return Round (V > R ? V : R, PAGE); }
STATIC CONST UINT8 *Rva (CONST PE_VIEW *V, UINTN Address, UINTN Bytes)
{
  for (UINTN I = 0; I < V->Count; I++) {
    CONST UINT8 *S = Section (V, I); UINTN A = ReadLe (S + 12, 4);
    if (Span (Address, Bytes, A, A + Copied (S))) return V->Source + ReadLe (S + 20, 4) + Address - A;
  }
  return NULL;
}

// The security directory is a file offset, not an RVA. Retain the established
// ChainCertificates framing contract: a complete aligned suffix beyond every
// raw section, containing bounded WIN_CERTIFICATE records and zero padding.
// Its contents remain opaque; this is not publisher/signature authentication.
STATIC BOOLEAN Certificates (CONST PE_VIEW *V, UINTN Offset, UINTN Bytes)
{
  if ((Offset & 7) || (Bytes & 7) || Bytes < 8 || Offset < V->Headers ||
      Offset > V->Bytes || Bytes != V->Bytes - Offset) return FALSE;
  for (UINTN I = 0; I < V->Count; I++) {
    CONST UINT8 *S = Section (V, I); UINTN Raw = ReadLe (S + 16, 4);
    if (Raw && Offset < ReadLe (S + 20, 4) + Raw) return FALSE;
  }
  for (UINTN Done = 0; Done < Bytes; ) {
    CONST UINT8 *C = V->Source + Offset + Done; UINTN Length, Padded;
    if (Bytes - Done < 8) return FALSE;
    Length = ReadLe (C, 4);
    if (Length < 8 || Length > Bytes - Done || ReadLe (C + 4, 2) != 0x200 ||
        ReadLe (C + 6, 2) != 2) return FALSE;
    Padded = Round (Length, 8);
    if (Padded > Bytes - Done) return FALSE;
    for (UINTN I = Length; I < Padded; I++) if (C[I]) return FALSE;
    Done += Padded;
  }
  return TRUE;
}

STATIC BOOLEAN ParsePe (CONST UINT8 *P, UINTN N, PE_VIEW *V)
{
  UINTN O, A, Count, Opt, Dirs, End, FileAlignment; BOOLEAN Entry = FALSE;
  ZeroMem (V, sizeof (*V));
  if (N < 256 || N > N976N_BOOTSTRAP_IMAGE_BYTES || ReadLe (P, 2) != 0x5A4D) return FALSE;
  O = ReadLe (P + 60, 4);
  if (!Span (O, 24, 64, N) || ReadLe (P + O, 4) != 0x4550 || ReadLe (P + O + 4, 2) != 0xAA64) return FALSE;
  Count = ReadLe (P + O + 6, 2); Opt = ReadLe (P + O + 20, 2); A = O + 24;
  if (!Count || Count > MAX_SECTIONS || !Span (A, Opt, 0, N) || Opt < 112 ||
      ReadLe (P + A, 2) != 0x20B || (ReadLe (P + O + 22, 2) & 1) ||
      !(ReadLe (P + O + 22, 2) & 2)) return FALSE;
  V->Subsystem = ReadLe (P + A + 68, 2);
  if (V->Subsystem != 10 && V->Subsystem != 11 && V->Subsystem != 12) return FALSE;
  Dirs = ReadLe (P + A + 108, 4);
  FileAlignment = ReadLe (P + A + 36, 4);
  if (Dirs > 16 || 112 + 8 * Dirs > Opt || !Span (A + Opt, Count * 40, 0, N) ||
      ReadLe (P + A + 32, 4) != PAGE || FileAlignment < 512 || FileAlignment > PAGE ||
      (FileAlignment & (FileAlignment - 1))) return FALSE;
  V->Source = P; V->Bytes = N; V->Pe = O; V->Optional = A; V->Sections = A + Opt; V->Count = Count;
  V->Headers = ReadLe (P + A + 60, 4); V->Size = ReadLe (P + A + 56, 4);
  V->Entry = ReadLe (P + A + 16, 4); V->Preferred = ReadLe (P + A + 24, 8);
  if (!V->Size || V->Size > N976N_BOOTSTRAP_IMAGE_BYTES || (V->Size & (PAGE - 1)) ||
      V->Headers < V->Sections + 40 * Count || V->Headers > N || V->Headers > V->Size ||
      (V->Headers & (FileAlignment - 1)) || (V->Entry & 3)) return FALSE;
  // File headers may occupy less than a page; their entire page stays RO/XN.
  End = Round (V->Headers, PAGE);
  for (UINTN I = 0; I < Count; I++) {
    CONST UINT8 *S = Section (V, I); UINTN Z = ReadLe (S + 8, 4), R = ReadLe (S + 12, 4);
    UINTN Raw = ReadLe (S + 16, 4), Offset = ReadLe (S + 20, 4), Flags = ReadLe (S + 36, 4);
    if (!Z || (R & (PAGE - 1)) || R < End || !Span (R, SectionSpan (S), 0, V->Size) ||
        !(Flags & READ_BIT) || ((Flags & EXEC_BIT) && (Flags & WRITE_BIT)) ||
        (Raw && (!Span (Offset, Raw, V->Headers, N) || ((Offset | Raw) & (FileAlignment - 1))))) return FALSE;
    for (UINTN J = 0; J < I; J++) {
      CONST UINT8 *T = Section (V, J);
      if (Overlap (Offset, Raw, ReadLe (T + 20, 4), ReadLe (T + 16, 4))) return FALSE;
    }
    End = R + SectionSpan (S);
    if ((Flags & EXEC_BIT) && Span (V->Entry, 4, R, R + Copied (S))) Entry = TRUE;
  }
  if (!Entry) return FALSE;
  for (UINTN I = 0; I < Dirs; I++) {
    UINTN R = ReadLe (P + A + 112 + 8 * I, 4), Z = ReadLe (P + A + 116 + 8 * I, 4);
    if (!R && !Z) continue;
    if (!R || !Z) return FALSE;
    if (I == 4) { if (!Certificates (V, R, Z)) return FALSE; continue; }
    // Only inert export/resource/unwind/debug metadata and base relocations.
    // No imports, TLS or other execution-time format is admitted.
    if ((I != 0 && I != 2 && I != 3 && I != 5 && I != 6) || !Rva (V, R, Z)) return FALSE;
    if (I == 5) { V->RelocRva = R; V->RelocBytes = Z; }
    if (I == 6) {
      CONST UINT8 *D = Rva (V, R, Z);
      if (Z % 28) return FALSE;
      for (UINTN J = 0; J < Z; J += 28) {
        UINTN Data = ReadLe (D + J + 20, 4), Bytes = ReadLe (D + J + 16, 4);
        // Reject the loader's out-of-image CodeView append path.
        if (Bytes && !Rva (V, Data, Bytes)) return FALSE;
      }
    }
  }
  return TRUE;
}

// The sealed profile uses monotonically ordered DIR64 relocations. This avoids
// an allocation-sized relocation index and rejects duplicate/overlapping fixups.
// Exact source fixups in RX sections are valid while the actual allocation is
// RW-XN. Their relocated values are checked before ROX publication and again on
// unload. Never patch headers, zero-fill or a declared image directory.
STATIC BOOLEAN Relocations (CONST PE_VIEW *V, UINT64 Loaded, BOOLEAN Check, BOOLEAN ImmutableOnly)
{
  CONST UINT8 *P = Rva (V, V->RelocRva, V->RelocBytes);
  UINTN O = 0, Last = 0; BOOLEAN Seen = FALSE;
  if (!V->RelocBytes) return TRUE;
  if (!P) return FALSE;
  while (O < V->RelocBytes) {
    UINTN Page, Bytes;
    if (V->RelocBytes - O < 8) return FALSE;
    Page = ReadLe (P + O, 4); Bytes = ReadLe (P + O + 4, 4);
    if ((Page & (PAGE - 1)) || Bytes < 8 || (Bytes & 3) || Bytes > V->RelocBytes - O) return FALSE;
    for (UINTN J = 8; J < Bytes; J += 2) {
      UINTN Item = ReadLe (P + O + J, 2), R = Page + (Item & 0xFFF); CONST UINT8 *Original;
      if (!(Item >> 12)) continue;
      if ((Item >> 12) != 10 || (R & 7) || (Seen && R < Last + 8) ||
          !(Original = Rva (V, R, 8))) return FALSE;
      for (UINTN K = 0; K < ReadLe (V->Source + V->Optional + 108, 4); K++) {
        CONST UINT8 *D = V->Source + V->Optional + 112 + 8 * K;
        if (K != 4 && Overlap (R, 8, ReadLe (D, 4), ReadLe (D + 4, 4))) return FALSE;
      }
      BOOLEAN Writable = FALSE;
      for (UINTN K = 0; K < V->Count; K++) {
        CONST UINT8 *S = Section (V, K);
        if ((ReadLe (S + 36, 4) & WRITE_BIT) && Span (R, 8, ReadLe (S + 12, 4), ReadLe (S + 12, 4) + SectionSpan (S))) Writable = TRUE;
      }
      if (Check && !(ImmutableOnly && Writable) &&
          ReadLe ((CONST UINT8 *)(UINTN)(Loaded + R), 8) != ReadLe (Original, 8) + Loaded - V->Preferred) return FALSE;
      Last = R; Seen = TRUE;
    }
    O += Bytes;
  }
  return O == V->RelocBytes;
}

STATIC BOOLEAN SameSection (CONST PE_VIEW *V, CONST UINT8 *S, UINT64 Loaded)
{
  UINTN R = ReadLe (S + 12, 4), N = Copied (S), Cursor = 0;
  CONST UINT8 *Original = V->Source + ReadLe (S + 20, 4), *Actual = (VOID *)(UINTN)(Loaded + R);
  CONST UINT8 *Rel = Rva (V, V->RelocRva, V->RelocBytes);
  for (UINTN O = 0; O < V->RelocBytes; ) {
    UINTN Page = ReadLe (Rel + O, 4), Bytes = ReadLe (Rel + O + 4, 4);
    for (UINTN J = 8; J < Bytes; J += 2) {
      UINTN Item = ReadLe (Rel + O + J, 2), Fix = Page + (Item & 0xFFF);
      if (!(Item >> 12) || !Span (Fix, 8, R, R + N)) continue;
      if (CompareMem (Actual + Cursor, Original + Cursor, Fix - R - Cursor)) return FALSE;
      Cursor = Fix - R + 8; // Value independently checked in Relocations().
    }
    O += Bytes;
  }
  if (N && CompareMem (Actual + Cursor, Original + Cursor, N - Cursor)) return FALSE;
  for (UINTN I = N; I < ReadLe (S + 8, 4); I++) if (Actual[I]) return FALSE;
  return TRUE;
}

STATIC BOOLEAN SameImage (CONST PE_VIEW *V, PE_COFF_LOADER_IMAGE_CONTEXT *C, BOOLEAN ImmutableOnly)
{
  CONST UINT8 *P = (VOID *)(UINTN)C->ImageAddress; UINTN BaseField = V->Optional + 24;
  if (C->IsTeImage || C->DestinationAddress || C->RelocationsStripped || C->Machine != 0xAA64 ||
      C->ImageType != V->Subsystem || C->ImageSize != V->Size || C->SizeOfHeaders != V->Headers ||
      C->PeCoffHeaderOffset != V->Pe || C->SectionAlignment != PAGE || C->EntryPoint != C->ImageAddress + V->Entry ||
      CompareMem (P, V->Source, BaseField) || ReadLe (P + BaseField, 8) != C->ImageAddress ||
      CompareMem (P + BaseField + 8, V->Source + BaseField + 8, V->Headers - BaseField - 8) ||
      !Relocations (V, C->ImageAddress, TRUE, ImmutableOnly)) return FALSE;
  for (UINTN I = 0; I < V->Count; I++) {
    CONST UINT8 *S = Section (V, I);
    if (!(ImmutableOnly && (ReadLe (S + 36, 4) & WRITE_BIT)) && !SameSection (V, S, C->ImageAddress)) return FALSE;
  }
  return TRUE;
}

// The immutable source is carried by the validated platform HOB rather than a
// QEMU address. The fixed heap budget is unchanged; the phone producer admits
// the source Image and runtime DT before constructing this HOB.
STATIC CONST N976N_PLATFORM_HANDOFF *Platform (VOID)
{
  VOID *Hob = GetFirstGuidHob (&gN976nPlatformHandoffGuid);
  if (!Hob || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (N976N_PLATFORM_HANDOFF)) return NULL;
  CONST N976N_PLATFORM_HANDOFF *H = GET_GUID_HOB_DATA (Hob);
  if (H->Magic != N976N_PLATFORM_HANDOFF_MAGIC || H->Version != N976N_PLATFORM_ABI_VERSION ||
      H->Size != sizeof (*H) || H->Profile > 1 || H->Reserved ||
      H->HeapBase != N976N_BOOTSTRAP_HEAP_BASE ||
      H->HeapSize != N976N_BOOTSTRAP_HEAP_END-N976N_BOOTSTRAP_HEAP_BASE ||
      H->FirmwareSize != N976N_BOOTSTRAP_FV_BYTES || (H->FirmwareBase & (PAGE-1)) ||
      !Span (H->FirmwareBase, H->FirmwareSize, 0x80002000, 0x100000000ULL) ||
      Overlap (H->FirmwareBase, H->FirmwareSize, H->HeapBase, H->HeapSize) ||
      H->ImageSize > MAX_UINT64-H->ImageBase ||
      !Span (H->FirmwareBase, H->FirmwareSize, H->ImageBase, H->ImageBase+H->ImageSize) ||
      !Span (H->StackBase, H->StackSize, H->ImageBase, H->ImageBase+H->ImageSize) ||
      Overlap (H->FirmwareBase, H->FirmwareSize, H->StackBase, H->StackSize)) return NULL;
  return H;
}

STATIC EFI_STATUS Catalog (N976N_BOOTSTRAP_POLICY *State)
{
  CONST N976N_PLATFORM_HANDOFF *H = Platform ();
  if (!H) return EFI_COMPROMISED_DATA;
  CONST UINT8 *P = (VOID *)(UINTN)H->FirmwareBase; UINTN N = H->FirmwareSize;
  UINTN Header, O, Sum = 0, Blocks = 0, I, Core = 0;
  if (ReadLe (P + 32, 8) != N || ReadLe (P + 40, 4) != 0x4856465F || P[55] != 2 ||
      P[54] || CompareMem (P + 16, &mFfs2Guid, 16) || !(ReadLe (P + 44, 4) & 0x800)) return EFI_VOLUME_CORRUPTED;
  Header = ReadLe (P + 48, 2);
  if (Header < 72 || Header > N || (Header & 7)) return EFI_VOLUME_CORRUPTED;
  for (I = 0; I < Header; I += 2) Sum += ReadLe (P + I, 2);
  if (Sum & 0xFFFF) return EFI_VOLUME_CORRUPTED;
  for (I = 56; I + 8 <= Header; I += 8) {
    UINTN Count = ReadLe (P + I, 4), Size = ReadLe (P + I + 4, 4);
    if (!Count && !Size) break;
    if (!Size || !Count || Count > N / Size || Count * Size > N - Blocks) return EFI_VOLUME_CORRUPTED;
    Blocks += Count * Size;
  }
  if (I + 8 > Header || Blocks != N) return EFI_VOLUME_CORRUPTED;
  O = Header; I = ReadLe (P + 52, 2);
  if (I) {
    if (!Span (I, 20, 0, N)) return EFI_VOLUME_CORRUPTED;
    UINTN Size = ReadLe (P + I + 16, 4);
    if (Size < 20 || !Span (I, Size, 0, N) || I + Size < Header) return EFI_VOLUME_CORRUPTED;
    O = Round (I + Size, 8);
  }
  ZeroMem (State, sizeof (*State));
  State->Magic = N976N_BOOTSTRAP_POLICY_MAGIC; State->FvBase = H->FirmwareBase; State->FvBytes = N;
  while (O < N) {
    UINTN Size, Type, Next, PeCount = 0;
    if (N - O < 24 || (ReadLe (P + O, 8) == MAX_UINT64 && ReadLe (P + O + 8, 8) == MAX_UINT64 && ReadLe (P + O + 16, 8) == MAX_UINT64)) {
      for (; O < N; O++) if (P[O] != 0xFF) return EFI_VOLUME_CORRUPTED;
      break;
    }
    Size = ReadLe (P + O + 20, 3); Type = P[O + 18]; Next = Round (O + Size, 8);
    if (Size < 24 || Size == 0xFFFFFF || Size > N - O || Next > N || (P[O + 19] & 1) ||
        ((~P[O + 23]) & 0xFF) != 7) return EFI_VOLUME_CORRUPTED;
    Sum = 0; for (I = 0; I < 24; I++) if (I != 17 && I != 23) Sum += P[O + I];
    if (Sum & 255) return EFI_VOLUME_CORRUPTED;
    if (P[O + 19] & 0x40) {
      Sum = P[O + 17]; for (I = 24; I < Size; I++) Sum += P[O + I];
      if (Sum & 255) return EFI_VOLUME_CORRUPTED;
    } else if (P[O + 17] != 0xAA) return EFI_VOLUME_CORRUPTED;
    if (Type != 0xF0) {
      if (Type != 5 && Type != 7 && Type != 9 && Type != 2) return EFI_UNSUPPORTED;
      if (Type == 5 && Core++) return EFI_VOLUME_CORRUPTED;
      for (UINTN S = O + 24; S < O + Size; ) {
        if (O + Size - S < 4) return EFI_VOLUME_CORRUPTED;
        UINTN Z = ReadLe (P + S, 3), Kind = P[S + 3];
        if (Z < 4 || Z == 0xFFFFFF || Z > O + Size - S) return EFI_VOLUME_CORRUPTED;
        if (Kind == 0x10) {
          PE_VIEW V;
          if (Type == 2 || PeCount++ || State->SourceCount == N976N_BOOTSTRAP_IMAGE_LIMIT ||
              !ParsePe (P + S + 4, Z - 4, &V) || !Relocations (&V, 0, FALSE, FALSE) ||
              ((Type == 9) != (V.Subsystem == 10)) || (Type == 5 && V.Subsystem != 11)) return EFI_UNSUPPORTED;
          N976N_BOOTSTRAP_IMAGE *R = &State->Images[State->SourceCount++];
          R->SourceOffset = S + 4; R->SourceBytes = Z - 4; R->Subsystem = V.Subsystem; R->FileType = Type;
        } else if (Kind != 0x13 && Kind != 0x14 && Kind != 0x15 && Kind != 0x19) return EFI_UNSUPPORTED;
        S = Round (S + Z, 4) > O + Size ? S + Z : Round (S + Z, 4);
      }
      if (PeCount != (Type == 2 ? 0 : 1)) return EFI_VOLUME_CORRUPTED;
    }
    O = Next;
  }
  return Core == 1 && State->SourceCount ? EFI_SUCCESS : EFI_VOLUME_CORRUPTED;
}

EFI_STATUS EFIAPI N976nBootstrapPolicyValidateFv (VOID)
{ N976N_BOOTSTRAP_POLICY State; return Catalog (&State); }

EFI_STATUS EFIAPI N976nBootstrapPolicyInitialize (VOID)
{
  N976N_BOOTSTRAP_POLICY State; EFI_STATUS Status;
  if (GetFirstGuidHob (&mPolicyGuid)) return EFI_ALREADY_STARTED;
  Status = Catalog (&State); if (EFI_ERROR (Status)) return Status;
  if (!BuildGuidDataHob (&mPolicyGuid, &State, sizeof (State))) return EFI_OUT_OF_RESOURCES;
  return ArmSetMemoryAttributes (State.FvBase, State.FvBytes, EFI_MEMORY_RO | EFI_MEMORY_XP,
                                 EFI_MEMORY_RO | EFI_MEMORY_XP);
}

STATIC N976N_BOOTSTRAP_POLICY *Policy (VOID)
{
  VOID *Hob = GetFirstGuidHob (&mPolicyGuid); N976N_BOOTSTRAP_POLICY *S; UINTN Active = 0;
  CONST N976N_PLATFORM_HANDOFF *H = Platform ();
  if (!H || !Hob || GET_GUID_HOB_DATA_SIZE (Hob) != sizeof (*S)) return NULL;
  S = GET_GUID_HOB_DATA (Hob);
  if (S->Magic != N976N_BOOTSTRAP_POLICY_MAGIC || S->FvBase != H->FirmwareBase ||
      S->FvBytes != N976N_BOOTSTRAP_FV_BYTES || !S->SourceCount || S->SourceCount > N976N_BOOTSTRAP_IMAGE_LIMIT ||
      S->ActiveCount > S->SourceCount || S->Failure) return NULL;
  for (UINTN I = 0; I < S->SourceCount; I++) {
    N976N_BOOTSTRAP_IMAGE *R = &S->Images[I];
    if (!Span (R->SourceOffset, R->SourceBytes, 0, S->FvBytes) ||
        (R->FileType != 5 && R->FileType != 7 && R->FileType != 9) ||
        (R->Subsystem != 10 && R->Subsystem != 11 && R->Subsystem != 12) ||
        ((R->FileType == 9) != (R->Subsystem == 10)) || (R->FileType == 5 && R->Subsystem != 11) ||
        (!R->LoadedBase != !R->LoadedBytes)) return NULL;
    if (R->LoadedBase) {
      if (((R->LoadedBase | R->LoadedBytes) & (PAGE - 1)) ||
          !Span (R->LoadedBase, R->LoadedBytes, N976N_BOOTSTRAP_HEAP_BASE, N976N_BOOTSTRAP_HEAP_END)) return NULL;
      Active++;
      for (UINTN J = 0; J < I; J++)
        if (S->Images[J].LoadedBase && Overlap (R->LoadedBase, R->LoadedBytes,
            S->Images[J].LoadedBase, S->Images[J].LoadedBytes)) return NULL;
    }
  }
  // PublishedCount is cumulative. An application is automatically unloaded by
  // native StartImage when it returns, leaving its immutable source reusable.
  if (Active != S->ActiveCount || S->PublishedCount < S->ActiveCount) return NULL;
  return S;
}

__attribute__((noinline, noreturn)) VOID EFIAPI N976nBootstrapPolicyFail (UINT32 Code)
{
  N976N_BOOTSTRAP_POLICY *S = Policy (); if (S) S->Failure = Code;
  DEBUG ((DEBUG_ERROR, "SEC49 IMAGE POLICY FAIL %u\n", Code)); CpuDeadLoop ();
  for (;;) { }
}

#ifdef N976N_POLICY_DXE
extern EFI_STATUS EFIAPI CoreGetMemoryMap (UINTN *, EFI_MEMORY_DESCRIPTOR *, UINTN *, UINTN *, UINT32 *);
STATIC UINT64 mMapStorage[16384 / sizeof (UINT64)];
#endif
STATIC BOOLEAN OwnedCode (UINT64 Base, UINT64 Bytes, UINT32 Type)
{
  EFI_PEI_HOB_POINTERS H; UINT64 Covered = 0;
  if ((Base | Bytes) & (PAGE - 1) || !Span (Base, Bytes, N976N_BOOTSTRAP_HEAP_BASE, N976N_BOOTSTRAP_HEAP_END)) return FALSE;
  H.Raw = GetHobList ();
  UINT64 HobBase = (UINTN)H.Raw;
  while (!END_OF_HOB_LIST (H)) H.Raw = GET_NEXT_HOB (H);
  if (Overlap (Base, Bytes, HobBase, (UINTN)H.Raw + sizeof (EFI_HOB_GENERIC_HEADER) - HobBase)) return FALSE;
#ifdef N976N_POLICY_DXE
  UINTN N = sizeof (mMapStorage), Key = 0, Ds = 0; UINT32 Version = 0;
  if (EFI_ERROR (CoreGetMemoryMap (&N, (VOID *)mMapStorage, &Key, &Ds, &Version)) ||
      !N || N > sizeof (mMapStorage) || Ds < sizeof (EFI_MEMORY_DESCRIPTOR) || N % Ds || Version != 1) return FALSE;
  for (UINTN O = 0; O < N; O += Ds) {
    EFI_MEMORY_DESCRIPTOR *D = (VOID *)((UINT8 *)mMapStorage + O);
    UINT64 Z, Lo, Hi;
    if (!D->NumberOfPages || D->NumberOfPages > MAX_UINT64 / PAGE) return FALSE;
    Z = D->NumberOfPages * PAGE;
    if (D->PhysicalStart > MAX_UINT64 - Z) return FALSE;
    Lo = MAX (Base, D->PhysicalStart); Hi = MIN (Base + Bytes, D->PhysicalStart + Z);
    if (Lo < Hi) {
      // CoreGetMemoryMap carries supported cache capabilities, not the active
      // cache mode. The actual WB mapping is checked from the page tables below.
      if (D->Type != Type || !(D->Attribute & EFI_MEMORY_WB) || Hi - Lo > Bytes - Covered) {
        DEBUG ((DEBUG_ERROR, "SEC49 IMAGE OWNER REJECT base=%lx type=%u expected=%u capabilities=%lx\n",
                D->PhysicalStart, D->Type, Type, D->Attribute));
        return FALSE;
      }
      Covered += Hi - Lo;
    }
  }
#else
  H.Raw = GetFirstHob (EFI_HOB_TYPE_MEMORY_ALLOCATION);
  while (H.Raw) {
    EFI_HOB_MEMORY_ALLOCATION *A = H.MemoryAllocation;
    if (A->AllocDescriptor.MemoryLength <= MAX_UINT64 - A->AllocDescriptor.MemoryBaseAddress &&
        A->AllocDescriptor.MemoryType == Type &&
        Span (Base, Bytes, A->AllocDescriptor.MemoryBaseAddress, A->AllocDescriptor.MemoryBaseAddress + A->AllocDescriptor.MemoryLength)) Covered = Bytes;
    H.Raw = GetNextHob (EFI_HOB_TYPE_MEMORY_ALLOCATION, GET_NEXT_HOB (H));
  }
#endif
  return Covered == Bytes;
}

// Read the actual EL1 tables; the bootstrap supports 4K, non-LPA2 identity maps.
// Staging pages must remain RW-XN until publication. A running Core instead
// has the exact per-section permissions established by its SEC publication.
STATIC BOOLEAN PublishedPermissions (CONST PE_VIEW *V, UINT64 Base, BOOLEAN Staging)
{
  UINT64 El, Sctlr, Tcr, Root, Mair;
  __asm__ volatile ("mrs %0, CurrentEL" : "=r" (El));
  if (El != 4) return FALSE;
  __asm__ volatile ("mrs %0, sctlr_el1" : "=r" (Sctlr));
  __asm__ volatile ("mrs %0, tcr_el1" : "=r" (Tcr));
  __asm__ volatile ("mrs %0, ttbr0_el1" : "=r" (Root));
  __asm__ volatile ("mrs %0, mair_el1" : "=r" (Mair));
  UINTN T0 = Tcr & 63;
  if (!(Sctlr & 1) || T0 < 16 || T0 > 39 ||
      (Tcr & (BIT7 | BIT14 | BIT15 | BIT39 | BIT40 | BIT59))) return FALSE;
  for (UINTN Offset = 0; Offset < V->Size; Offset += PAGE) {
    UINT64 Address = Base + Offset, Table = Root & TT_ADDRESS_MASK_DESCRIPTION_TABLE;
    UINT64 Entry = 0, Attributes = Staging ? EFI_MEMORY_XP : EFI_MEMORY_RO | EFI_MEMORY_XP;
    for (UINTN I = 0; !Staging && I < V->Count; I++) {
      CONST UINT8 *S = Section (V, I); UINTN Flags = ReadLe (S + 36, 4);
      if (Span (Offset, PAGE, ReadLe (S + 12, 4), ReadLe (S + 12, 4) + SectionSpan (S)))
        Attributes = (Flags & EXEC_BIT) ? EFI_MEMORY_RO : EFI_MEMORY_XP | ((Flags & WRITE_BIT) ? 0 : EFI_MEMORY_RO);
    }
    for (UINTN Level = (T0 - 16) / 9; Level <= 3; Level++) {
      UINTN Shift = 12 + (3 - Level) * 9;
      if (!Span (Table, PAGE, N976N_BOOTSTRAP_HEAP_BASE, N976N_BOOTSTRAP_HEAP_END)) return FALSE;
      Entry = ((volatile UINT64 *)(UINTN)Table)[(Address >> Shift) & 511];
      if (!(Entry & 1)) return FALSE;
      if (Level < 3 && (Entry & 3) == 3) {
        if (Entry & (BIT59 | BIT60 | BIT61 | BIT62 | BIT63)) return FALSE;
        Table = Entry & TT_ADDRESS_MASK_DESCRIPTION_TABLE;
        continue;
      }
      if (!Level || (Entry & 3) != (Level == 3 ? 3U : 1U) ||
          ((Entry & TT_ADDRESS_MASK_BLOCK_ENTRY) & ~((1ULL << Shift) - 1)) != (Address & ~((1ULL << Shift) - 1))) return FALSE;
      break;
    }
    if (!(Entry & TT_AF) || (Entry & TT_AP_MASK) != ((Attributes & EFI_MEMORY_RO) ? TT_AP_NO_RO : TT_AP_NO_RW) ||
        (Entry & (TT_PXN_MASK | TT_UXN_MASK)) != ((Attributes & EFI_MEMORY_XP) ? TT_PXN_MASK | TT_UXN_MASK : 0) ||
        (Entry & TT_SH_MASK) != TT_SH_INNER_SHAREABLE || ((Mair >> (((Entry >> 2) & 7) * 8)) & 255) != 255) return FALSE;
  }
  return TRUE;
}

#ifdef N976N_POLICY_DXE
// DxeMain reports its already-running Core a second time, with a deliberately
// partial context. This is not a load/publication and must not remap live code.
STATIC BOOLEAN CoreNotification (N976N_BOOTSTRAP_POLICY *State, PE_COFF_LOADER_IMAGE_CONTEXT *C)
{
  STATIC BOOLEAN Reported = FALSE;
  PE_COFF_LOADER_IMAGE_CONTEXT Remaining, Empty;
  PE_VIEW V; N976N_BOOTSTRAP_IMAGE *Record = NULL;
  if (Reported || State->ActiveCount != 1 || C->ImageSize ||
      C->Handle != (VOID *)(UINTN)C->ImageAddress || C->ImageRead != PeCoffLoaderImageReadFromMemory) return FALSE;
  for (UINTN I = 0; I < State->SourceCount; I++)
    if (State->Images[I].FileType == 5 && State->Images[I].LoadedBase == C->ImageAddress) Record = &State->Images[I];
  if (!Record || !ParsePe ((VOID *)(UINTN)(State->FvBase + Record->SourceOffset), Record->SourceBytes, &V) ||
      Record->LoadedBytes != V.Size || C->SizeOfHeaders != V.Headers || C->EntryPoint != C->ImageAddress + V.Entry ||
      !OwnedCode (C->ImageAddress, V.Size, EfiBootServicesCode) || !Relocations (&V, 0, FALSE, FALSE)) return FALSE;
  CONST UINT8 *P = (VOID *)(UINTN)C->ImageAddress; UINTN BaseField = V.Optional + 24;
  if (CompareMem (P, V.Source, BaseField) || ReadLe (P + BaseField, 8) != C->ImageAddress ||
      CompareMem (P + BaseField + 8, V.Source + BaseField + 8, V.Headers - BaseField - 8) ||
      (C->PdbPointer && !Span ((UINTN)C->PdbPointer, 1, C->ImageAddress, C->ImageAddress + V.Size))) return FALSE;
  Remaining = *C; ZeroMem (&Empty, sizeof (Empty));
  Remaining.ImageAddress = 0; Remaining.SizeOfHeaders = 0; Remaining.EntryPoint = 0;
  Remaining.Handle = NULL; Remaining.ImageRead = NULL; Remaining.PdbPointer = NULL;
  if (CompareMem (&Remaining, &Empty, sizeof (Empty))) return FALSE;
  // Writable globals have legitimately changed since Core entry. Instructions,
  // headers and all immutable data must still match the admitted source.
  for (UINTN I = 0; I < V.Count; I++) {
    CONST UINT8 *S = Section (&V, I); UINTN R = ReadLe (S + 12, 4), N = Copied (S);
    if (ReadLe (S + 36, 4) & WRITE_BIT) continue;
    if (!SameSection (&V, S, C->ImageAddress)) return FALSE;
    CONST UINT8 *Rel = Rva (&V, V.RelocRva, V.RelocBytes);
    for (UINTN O = 0; O < V.RelocBytes; ) {
      UINTN Page = ReadLe (Rel + O, 4), Bytes = ReadLe (Rel + O + 4, 4);
      for (UINTN J = 8; J < Bytes; J += 2) {
        UINTN Item = ReadLe (Rel + O + J, 2), Fix = Page + (Item & 0xFFF);
        if ((Item >> 12) && Span (Fix, 8, R, R + N) &&
            ReadLe (P + Fix, 8) != ReadLe (Rva (&V, Fix, 8), 8) + C->ImageAddress - V.Preferred) return FALSE;
      }
      O += Bytes;
    }
  }
  if (!PublishedPermissions (&V, C->ImageAddress, FALSE)) return FALSE;
  Reported = TRUE;
  DEBUG ((DEBUG_INFO, "SEC49 CORE NOTIFICATION VERIFIED base=%lx size=%lx\n", C->ImageAddress, Record->LoadedBytes));
  return TRUE;
}
#endif

VOID EFIAPI PeCoffLoaderRelocateImageExtraAction (PE_COFF_LOADER_IMAGE_CONTEXT *C)
{
  N976N_BOOTSTRAP_POLICY *State = Policy (); PE_VIEW V; N976N_BOOTSTRAP_IMAGE *Record = NULL;
  UINT32 Type; UINTN End;
  if (!State || !C || C->ImageError || C->IsTeImage || C->DestinationAddress) N976nBootstrapPolicyFail (1);
#ifdef N976N_POLICY_DXE
  if (!C->ImageSize) {
    if (!CoreNotification (State, C)) N976nBootstrapPolicyFail (9);
    return;
  }
#endif
  Type = C->ImageType == 10 ? EfiLoaderCode : C->ImageType == 12 ? EfiRuntimeServicesCode : EfiBootServicesCode;
  if (!OwnedCode (C->ImageAddress, C->ImageSize, Type)) N976nBootstrapPolicyFail (2);
  for (UINTN I = 0; I < State->SourceCount; I++) {
    N976N_BOOTSTRAP_IMAGE *R = &State->Images[I];
    if (R->LoadedBase && Overlap (C->ImageAddress, C->ImageSize, R->LoadedBase, R->LoadedBytes)) N976nBootstrapPolicyFail (3);
  }
  for (UINTN I = 0; I < State->SourceCount; I++) {
    N976N_BOOTSTRAP_IMAGE *R = &State->Images[I];
    if (!R->LoadedBase && Span (R->SourceOffset, R->SourceBytes, 0, State->FvBytes) &&
        ParsePe ((VOID *)(UINTN)(State->FvBase + R->SourceOffset), R->SourceBytes, &V) && SameImage (&V, C, FALSE)) { Record = R; break; }
  }
  if (!Record) N976nBootstrapPolicyFail (4);
  if (!PublishedPermissions (&V, C->ImageAddress, TRUE)) N976nBootstrapPolicyFail (10);
  // First force NX over the whole image. Undefined gaps/padding are cleared so
  // page-rounded executable tails cannot expose allocator residue.
  if (EFI_ERROR (ArmSetMemoryAttributes (C->ImageAddress, C->ImageSize, EFI_MEMORY_XP,
                                        EFI_MEMORY_RO | EFI_MEMORY_XP))) N976nBootstrapPolicyFail (5);
  End = V.Headers;
  for (UINTN I = 0; I < V.Count; I++) {
    CONST UINT8 *S = Section (&V, I); UINTN R = ReadLe (S + 12, 4), Z = ReadLe (S + 8, 4);
    ZeroMem ((VOID *)(UINTN)(C->ImageAddress + End), R - End);
    ZeroMem ((VOID *)(UINTN)(C->ImageAddress + R + Z), SectionSpan (S) - Z);
    End = R + SectionSpan (S);
  }
  ZeroMem ((VOID *)(UINTN)(C->ImageAddress + End), V.Size - End);
  WriteBackDataCacheRange ((VOID *)(UINTN)C->ImageAddress, C->ImageSize);
  InvalidateInstructionCacheRange ((VOID *)(UINTN)C->ImageAddress, C->ImageSize);
  if (EFI_ERROR (ArmSetMemoryAttributes (C->ImageAddress, C->ImageSize, EFI_MEMORY_RO | EFI_MEMORY_XP,
                                        EFI_MEMORY_RO | EFI_MEMORY_XP))) N976nBootstrapPolicyFail (6);
  for (UINTN I = 0; I < V.Count; I++) {
    CONST UINT8 *S = Section (&V, I); UINTN Flags = ReadLe (S + 36, 4);
    UINT64 Attr = (Flags & EXEC_BIT) ? EFI_MEMORY_RO : EFI_MEMORY_XP | ((Flags & WRITE_BIT) ? 0 : EFI_MEMORY_RO);
    if (EFI_ERROR (ArmSetMemoryAttributes (C->ImageAddress + ReadLe (S + 12, 4), SectionSpan (S), Attr,
                                          EFI_MEMORY_RO | EFI_MEMORY_XP))) N976nBootstrapPolicyFail (7);
  }
  if (!PublishedPermissions (&V, C->ImageAddress, FALSE) || State->PublishedCount == MAX_UINT32)
    N976nBootstrapPolicyFail (11);
  Record->LoadedBase = C->ImageAddress; Record->LoadedBytes = C->ImageSize;
  State->ActiveCount++; State->PublishedCount++;
  DEBUG ((DEBUG_INFO, "SEC49 IMAGE PUBLISH %u base=%lx size=%lx\n", State->PublishedCount, C->ImageAddress, C->ImageSize));
}

VOID EFIAPI PeCoffLoaderUnloadImageExtraAction (PE_COFF_LOADER_IMAGE_CONTEXT *C)
{
  N976N_BOOTSTRAP_POLICY *State = Policy (); N976N_BOOTSTRAP_IMAGE *Record = NULL; PE_VIEW V;
  if (!State || !C || C->ImageError || C->ImageType != 10 || C->ImageCodeMemoryType != EfiLoaderCode ||
      C->ImageDataMemoryType != EfiLoaderData) N976nBootstrapPolicyFail (8);
  for (UINTN I = 0; I < State->SourceCount; I++) {
    N976N_BOOTSTRAP_IMAGE *R = &State->Images[I];
    if (R->FileType == 9 && R->Subsystem == 10 && R->LoadedBase == C->ImageAddress &&
        R->LoadedBytes == C->ImageSize) Record = R;
  }
  // No driver, unknown image, partial load or second unload is admitted here.
  // Writable globals may have changed during execution; headers, instructions,
  // immutable data, ownership and exact section permissions must still match.
  if (!Record || !State->ActiveCount ||
      !ParsePe ((VOID *)(UINTN)(State->FvBase + Record->SourceOffset), Record->SourceBytes, &V) ||
      !OwnedCode (C->ImageAddress, C->ImageSize, EfiLoaderCode) ||
      !SameImage (&V, C, TRUE) || !PublishedPermissions (&V, C->ImageAddress, FALSE))
    N976nBootstrapPolicyFail (12);
  // CoreUnloadAndCloseImage calls this hook before CoreFreePages. Revoke all
  // execution and make storage writable before allocator cleanup can touch it.
  if (EFI_ERROR (ArmSetMemoryAttributes (C->ImageAddress, C->ImageSize, EFI_MEMORY_XP,
                                        EFI_MEMORY_RO | EFI_MEMORY_XP)) ||
      !PublishedPermissions (&V, C->ImageAddress, TRUE)) N976nBootstrapPolicyFail (13);
  Record->LoadedBase = 0; Record->LoadedBytes = 0; State->ActiveCount--;
  DEBUG ((DEBUG_INFO, "SEC49 APPLICATION REVOKE base=%lx size=%lx active=%u published=%u\n",
          C->ImageAddress, C->ImageSize, State->ActiveCount, State->PublishedCount));
}
