/* SPDX-License-Identifier: MIT
 * N976N runtime-DT identity gate for the inherited UFS controller. This only
 * admits three pages already described by the exact observed 9825 DT node;
 * it does not enable clocks, change coherency, initialize a link or touch MMIO.
 * ParseRuntimeDtb has independently admitted the supplied DT memory first.
 */
#include <N976nUfsAdmission.h>
#include <Library/BaseMemoryLib.h>

#define MAX_DEPTH 16U
#define ROOT 1U
#define UFS 2U
#define COHERENCY 3U
#define ADDR 1U
#define SIZE 2U
#define RANGES 4U
#define COMPAT 8U
#define REV 16U
#define DMA 32U
#define REG 64U
#define STATUS 128U
#define MASK 256U
#define BITS 512U
#define DMA_RANGES 1024U

typedef struct {
  UINT32 Kind, Seen;
  BOOLEAN HadChild;
} NODE;

STATIC UINT32 Be32 (CONST UINT8 *P)
{ return ((UINT32)P[0]<<24) | ((UINT32)P[1]<<16) | ((UINT32)P[2]<<8) | P[3]; }
STATIC UINT64 Be64 (CONST UINT8 *P)
{ return ((UINT64)Be32 (P)<<32) | Be32 (P+4); }
STATIC BOOLEAN Fits (UINT64 Start, UINT64 Size, UINT64 End)
{ return Start <= End && Size <= End-Start; }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 An, UINT64 B, UINT64 Bn)
{ return An && Bn && A < B+Bn && B < A+An; }
STATIC BOOLEAN Same (CONST UINT8 *P, UINTN Bytes, CONST CHAR8 *S)
{
  for (UINTN I=0; I<Bytes; I++) {
    if (P[I] != (UINT8)S[I]) return FALSE;
    if (!S[I]) return I+1 == Bytes;
  }
  return FALSE;
}
STATIC UINT64 Property (NODE *N, CONST UINT8 *Name, UINTN NameBytes,
                       CONST UINT8 *Value, UINTN Bytes)
{
  UINT32 Bit = 0; BOOLEAN Good = FALSE;
  if (Same(Name,NameBytes,"iommus") || Same(Name,NameBytes,"iommu-map") ||
      Same(Name,NameBytes,"iommu-map-mask") || Same(Name,NameBytes,"ios-sysmmu") ||
      Same(Name,NameBytes,"dma-noncoherent")) {
    /* This milestone submits owned physical addresses, not IOVAs, and does
       not configure a translation domain or change a coherency contract. */
    return N976N_UFS_DT_BAD_VALUE;
  } else if (Same(Name,NameBytes,"dma-ranges")) {
    Bit=DMA_RANGES; Good=Bytes==0;
  } else if (Same (Name, NameBytes, "#address-cells")) {
    Bit=ADDR; Good=Bytes==4 && Be32(Value)==2;
  } else if (Same (Name, NameBytes, "#size-cells")) {
    Bit=SIZE; Good=Bytes==4 && Be32(Value)==1;
  } else if (Same (Name, NameBytes, "ranges")) {
    Bit=RANGES; Good=Bytes==0;
  } else if (Same (Name, NameBytes, "status")) {
    Bit=STATUS; Good=Same(Value,Bytes,"okay") || Same(Value,Bytes,"ok");
  } else if (N->Kind==UFS && Same(Name,NameBytes,"compatible")) {
    Bit=COMPAT; Good=Same(Value,Bytes,"samsung,exynos-ufs");
  } else if (N->Kind==UFS && Same(Name,NameBytes,"hw-rev")) {
    Bit=REV; Good=Bytes==4 && Be32(Value)==6;
  } else if (N->Kind==UFS && Same(Name,NameBytes,"dma-coherent")) {
    Bit=DMA; Good=Bytes==0;
  } else if (N->Kind==UFS && Same(Name,NameBytes,"reg")) {
    STATIC CONST UINT64 Bases[4]={0x13D60000,0x13D61100,0x13D50000,0x13D70000};
    STATIC CONST UINT32 Sizes[4]={0x200,0x200,0x8000,0x100};
    Bit=REG; Good=Bytes==48;
    if (Good) for (UINTN I=0; I<4; I++)
      if (Be64(Value+I*12)!=Bases[I] || Be32(Value+I*12+8)!=Sizes[I]) Good=FALSE;
  } else if (N->Kind==COHERENCY && Same(Name,NameBytes,"reg")) {
    Bit=REG; Good=Bytes==12 && Be64(Value)==0x13C10700 && Be32(Value+8)==4;
  } else if (N->Kind==COHERENCY && Same(Name,NameBytes,"mask")) {
    Bit=MASK; Good=Bytes==4 && Be32(Value)==0x00C00000;
  } else if (N->Kind==COHERENCY && Same(Name,NameBytes,"bits")) {
    Bit=BITS; Good=Bytes==4 && Be32(Value)==0x00C00000;
  } else {
    return 0; /* Unrelated clock, regulator, PHY and Linux metadata is inert. */
  }
  if (N->Seen & Bit) return N976N_UFS_DT_DUPLICATE;
  if (!Good) return N976N_UFS_DT_BAD_VALUE;
  N->Seen |= Bit;
  return 0;
}

STATIC UINT64 Parse (CONST UINT8 *D, UINT64 Bytes)
{
  NODE Nodes[MAX_DEPTH];
  UINT64 Struct, StructBytes, End, Strings, StringsBytes, Map, MapEnd;
  UINT64 Cursor, Length, NameStart, NameBytes, Offset, Next, Error;
  UINT32 Depth=0, Roots=0, UfsNodes=0, CoherencyNodes=0;
  BOOLEAN RootDone=FALSE, UfsDone=FALSE, CoherencyDone=FALSE;
  if (!D || Bytes<40 || Bytes>0x100000) return N976N_UFS_DT_BAD_BUFFER;
  if (Be32(D)!=0xD00DFEED || Be32(D+4)!=Bytes || Be32(D+20)!=17 || Be32(D+24)>17)
    return N976N_UFS_DT_BAD_HEADER;
  Struct=Be32(D+8); Strings=Be32(D+12); Map=Be32(D+16);
  StringsBytes=Be32(D+32); StructBytes=Be32(D+36);
  if (Struct<40 || (Struct&3) || StructBytes<4 || (StructBytes&3) ||
      !Fits(Struct,StructBytes,Bytes) || Strings<40 || !StringsBytes ||
      !Fits(Strings,StringsBytes,Bytes) || Overlap(Struct,StructBytes,Strings,StringsBytes) ||
      Map<40 || (Map&7) || Map>=Bytes) return N976N_UFS_DT_BAD_HEADER;
  End=Struct+StructBytes; MapEnd=Bytes;
  if ((Map>=Struct && Map<End) || (Map>=Strings && Map<Strings+StringsBytes))
    return N976N_UFS_DT_BAD_HEADER;
  if (Struct>Map && Struct<MapEnd) MapEnd=Struct;
  if (Strings>Map && Strings<MapEnd) MapEnd=Strings;
  for (Cursor=Map; ; Cursor+=16) {
    if (!Fits(Cursor,16,MapEnd)) return N976N_UFS_DT_BAD_HEADER;
    if (!Be64(D+Cursor) && !Be64(D+Cursor+8)) break;
  }
  ZeroMem(Nodes,sizeof(Nodes)); Cursor=Struct;
  while (Fits(Cursor,4,End)) {
    UINT32 Token=Be32(D+Cursor); Cursor+=4;
    if (Token==4) continue;
    if (Token==9) {
      if (Depth || Cursor!=End || Roots!=1) return N976N_UFS_DT_BAD_TREE;
      return RootDone && UfsDone && CoherencyDone ? 0 : N976N_UFS_DT_MISSING;
    }
    if (Token==1) {
      if (Depth>=MAX_DEPTH) return N976N_UFS_DT_BAD_TREE;
      NameStart=Cursor;
      while (Cursor<End && Cursor-NameStart<256 && D[Cursor]) Cursor++;
      if (Cursor>=End || Cursor-NameStart>=256) return N976N_UFS_DT_BAD_TREE;
      NameBytes=Cursor-NameStart+1; Cursor=(Cursor+4)&~3ULL;
      if (Cursor>End) return N976N_UFS_DT_BAD_TREE;
      NODE *N=&Nodes[Depth]; ZeroMem(N,sizeof(*N));
      if (Depth==0) {
        if (Roots++ || NameBytes!=1) return N976N_UFS_DT_BAD_TREE;
        N->Kind=ROOT;
      } else {
        Nodes[Depth-1].HadChild=TRUE;
        if (Depth==1 && Same(D+NameStart,NameBytes,"ufs@0x13D60000")) {
          if (UfsNodes++) return N976N_UFS_DT_DUPLICATE;
          N->Kind=UFS;
        } else if (Depth==2 && Nodes[Depth-1].Kind==UFS &&
                   Same(D+NameStart,NameBytes,"ufs-io-coherency")) {
          if (CoherencyNodes++) return N976N_UFS_DT_DUPLICATE;
          N->Kind=COHERENCY;
        }
      }
      Depth++; continue;
    }
    if (Token==2) {
      if (!Depth) return N976N_UFS_DT_BAD_TREE;
      NODE *N=&Nodes[Depth-1]; UINT32 Required=0;
      if (N->Kind==ROOT) Required=ADDR|SIZE;
      if (N->Kind==UFS) Required=ADDR|SIZE|RANGES|COMPAT|REV|DMA|REG;
      if (N->Kind==COHERENCY) Required=ADDR|SIZE|RANGES|REG|MASK|BITS;
      if ((N->Seen&Required)!=Required || (N->Kind==COHERENCY && N->HadChild))
        return N976N_UFS_DT_MISSING;
      if (N->Kind==ROOT) RootDone=TRUE;
      if (N->Kind==UFS) UfsDone=TRUE;
      if (N->Kind==COHERENCY) CoherencyDone=TRUE;
      Depth--; continue;
    }
    if (Token!=3 || !Depth || Nodes[Depth-1].HadChild || !Fits(Cursor,8,End))
      return N976N_UFS_DT_BAD_TREE;
    Length=Be32(D+Cursor); Offset=Be32(D+Cursor+4); Cursor+=8;
    if (!Fits(Cursor,Length,End) || Offset>=StringsBytes) return N976N_UFS_DT_BAD_TREE;
    Next=(Cursor+Length+3)&~3ULL;
    if (Next>End) return N976N_UFS_DT_BAD_TREE;
    NameStart=Strings+Offset; NameBytes=0;
    while (NameBytes<128 && Offset+NameBytes<StringsBytes && D[NameStart+NameBytes]) NameBytes++;
    if (NameBytes>=128 || Offset+NameBytes>=StringsBytes) return N976N_UFS_DT_BAD_TREE;
    if (Nodes[Depth-1].Kind) {
      Error=Property(&Nodes[Depth-1],D+NameStart,NameBytes+1,D+Cursor,Length);
      if (Error) return Error;
    }
    Cursor=Next;
  }
  return N976N_UFS_DT_BAD_TREE;
}

BOOLEAN EFIAPI N976nAdmitUfs (
  CONST VOID *Dtb, UINT64 DtbBytes, N976N_UFS_ADMISSION *Admission)
{
  if (!Admission) return FALSE;
  ZeroMem(Admission,sizeof(*Admission));
  Admission->Magic=N976N_UFS_ADMISSION_MAGIC;
  Admission->Version=1; Admission->Size=sizeof(*Admission);
  Admission->Reason=Parse(Dtb,DtbBytes);
  if (Admission->Reason) return FALSE;
  Admission->Hci=0x13D60000; Admission->Vendor=0x13D61100;
  Admission->Coherency=0x13C10700; Admission->Admitted=1;
  return TRUE;
}
