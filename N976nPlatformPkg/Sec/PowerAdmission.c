/* SPDX-License-Identifier: MIT
 * SEC62 exact DT gate for three power/key pages. No MMIO here. The caller has
 * already bounded and admitted this whole DT source via ParseRuntimeDtb.
 * Token/bounds walker reused from this platform's UfsAdmission.c.
 */
#include <N976nPowerOff.h>
#include <Library/BaseMemoryLib.h>
#define MAX_DEPTH 16U
#define ROOT 1U
#define PMU 2U
#define GPIO 3U
#define KEYS 4U
#define REBOOT 5U
#define GPA0 6U
#define GPA2 7U
#define POWER 8U
#define DOWN 9U
#define ALL_KINDS 0x3FEU
#define ADDR 1U
#define SIZE 2U
#define COMPAT 4U
#define REG 8U
#define PHANDLE 16U
#define LPHANDLE 32U
#define CELLS 64U
#define CONTROLLER 128U
#define CODE 256U
#define GP 512U
#define STATUS 1024U
#define RANGES 2048U
typedef struct { UINT32 Kind, Seen, Phandle, GpioPhandle; BOOLEAN HadChild; } NODE;
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
STATIC BOOLEAN Compatible (CONST UINT8 *P, UINTN N, CONST CHAR8 *A, CONST CHAR8 *B) {
  UINTN ABytes=0; while(A[ABytes]) ABytes++; ABytes++;
  if (B==NULL) return Same(P,N,A);
  return N>ABytes && Same(P,ABytes,A) && Same(P+ABytes,N-ABytes,B);
}
STATIC UINT64 Property (NODE *N, CONST UINT8 *Name, UINTN NameBytes, CONST UINT8 *V, UINTN Bytes) {
  UINT32 Bit=0; BOOLEAN Good=FALSE;
  if (Same(Name,NameBytes,"status")) { Bit=STATUS; Good=Same(V,Bytes,"okay")||Same(V,Bytes,"ok"); }
  else if (Same(Name,NameBytes,"ranges") || Same(Name,NameBytes,"dma-ranges")) { Bit=RANGES;Good=Bytes==0; }
  else if (Same(Name,NameBytes,"#address-cells") && N->Kind==ROOT) {Bit=ADDR;Good=Bytes==4&&Be32(V)==2;}
  else if (Same(Name,NameBytes,"#size-cells") && N->Kind==ROOT) {Bit=SIZE;Good=Bytes==4&&Be32(V)==1;}
  else if (Same(Name,NameBytes,"compatible")) {
    Bit=COMPAT;
    if(N->Kind==ROOT) Good=Compatible(V,Bytes,"samsung,armv8","samsung,exynos9820");
    if(N->Kind==PMU) Good=Compatible(V,Bytes,"samsung,exynos9820-pmu","syscon");
    if(N->Kind==GPIO) Good=Same(V,Bytes,"samsung,exynos9820-pinctrl");
    if(N->Kind==KEYS) Good=Same(V,Bytes,"gpio-keys");
    if(N->Kind==REBOOT) Good=Same(V,Bytes,"exynos,reboot");
  } else if (Same(Name,NameBytes,"reg") && (N->Kind==PMU||N->Kind==GPIO)) {
    Bit=REG;Good=Bytes==12&&Be64(V)==(N->Kind==PMU?N976N_POWER_PMU:N976N_POWER_GPIO)&&
      Be32(V+8)==(N->Kind==PMU?0x10000U:0x1000U);
  } else if (Same(Name,NameBytes,"pmu_base") && N->Kind==REBOOT) {Bit=REG;Good=Bytes==4&&Be32(V)==N976N_POWER_PMU;}
  else if ((N->Kind==PMU||N->Kind==GPA0||N->Kind==GPA2) &&
      (Same(Name,NameBytes,"phandle")||Same(Name,NameBytes,"linux,phandle"))) {
    Bit=Same(Name,NameBytes,"phandle")?PHANDLE:LPHANDLE;
    Good=Bytes==4&&Be32(V)!=0&&Be32(V)!=MAX_UINT32&&(!N->Phandle||N->Phandle==Be32(V));
    if(Good) N->Phandle=Be32(V);
  } else if ((N->Kind==GPA0||N->Kind==GPA2)&&Same(Name,NameBytes,"#gpio-cells")) {Bit=CELLS;Good=Bytes==4&&Be32(V)==2;}
  else if ((N->Kind==GPA0||N->Kind==GPA2)&&Same(Name,NameBytes,"gpio-controller")) {Bit=CONTROLLER;Good=Bytes==0;}
  else if ((N->Kind==POWER||N->Kind==DOWN)&&Same(Name,NameBytes,"linux,code")) {Bit=CODE;Good=Bytes==4&&Be32(V)==(N->Kind==POWER?116U:114U);}
  else if ((N->Kind==POWER||N->Kind==DOWN)&&Same(Name,NameBytes,"gpios")) {
    Bit=GP;Good=Bytes==12&&Be32(V)!=0&&Be32(V)!=MAX_UINT32&&Be32(V+4)==4&&Be32(V+8)==1;
    if(Good)N->GpioPhandle=Be32(V);
  } else return 0;
  if(N->Seen&Bit)return 4;
  if(!Good)return 5;
  N->Seen|=Bit;return 0;
}

STATIC UINT64 Parse (CONST UINT8 *D, UINT64 Bytes, N976N_POWER_ADMISSION *A)
{
  NODE Nodes[MAX_DEPTH];
  UINT64 Struct, StructBytes, End, Strings, StringsBytes, Map, MapEnd;
  UINT64 Cursor, Length, NameStart, NameBytes, Offset, Next, Error;
  UINT32 Depth=0, Roots=0, SeenKinds=0, DoneKinds=0;
  UINT32 PmuPhandle=0, Gpa0=0, Gpa2=0, KeyPower=0, KeyDown=0;
  
  if (!D || Bytes<40 || Bytes>0x100000) return 1;
  if (Be32(D)!=0xD00DFEED || Be32(D+4)!=Bytes || Be32(D+20)!=17 || Be32(D+24)>17)
    return 2;
  Struct=Be32(D+8); Strings=Be32(D+12); Map=Be32(D+16);
  StringsBytes=Be32(D+32); StructBytes=Be32(D+36);
  if (Struct<40 || (Struct&3) || StructBytes<4 || (StructBytes&3) ||
      !Fits(Struct,StructBytes,Bytes) || Strings<40 || !StringsBytes ||
      !Fits(Strings,StringsBytes,Bytes) || Overlap(Struct,StructBytes,Strings,StringsBytes) ||
      Map<40 || (Map&7) || Map>=Bytes) return 2;
  End=Struct+StructBytes; MapEnd=Bytes;
  if ((Map>=Struct && Map<End) || (Map>=Strings && Map<Strings+StringsBytes))
    return 2;
  if (Struct>Map && Struct<MapEnd) MapEnd=Struct;
  if (Strings>Map && Strings<MapEnd) MapEnd=Strings;
  for (Cursor=Map; ; Cursor+=16) {
    if (!Fits(Cursor,16,MapEnd)) return 2;
    if (!Be64(D+Cursor) && !Be64(D+Cursor+8)) break;
  }
  ZeroMem(Nodes,sizeof(Nodes)); Cursor=Struct;
  while (Fits(Cursor,4,End)) {
    UINT32 Token=Be32(D+Cursor); Cursor+=4;
    if (Token==4) continue;
    if (Token==9) {
      if (Depth || Cursor!=End || Roots!=1) return 3;
      if (DoneKinds != ALL_KINDS || !PmuPhandle || !Gpa0 || !Gpa2 || Gpa0==Gpa2 ||
          PmuPhandle==Gpa0 || PmuPhandle==Gpa2 || KeyPower!=Gpa2 || KeyDown!=Gpa0) return 6;
      A->PowerPhandle=Gpa2; A->DownPhandle=Gpa0; return 0;
    }
    if (Token==1) {
      if (Depth>=MAX_DEPTH) return 3;
      NameStart=Cursor;
      while (Cursor<End && Cursor-NameStart<256 && D[Cursor]) Cursor++;
      if (Cursor>=End || Cursor-NameStart>=256) return 3;
      NameBytes=Cursor-NameStart+1; Cursor=(Cursor+4)&~3ULL;
      if (Cursor>End) return 3;
      NODE *N=&Nodes[Depth]; ZeroMem(N,sizeof(*N));
      if (Depth==0) {
        if (Roots++ || NameBytes!=1) return 3;
        N->Kind=ROOT;
      } else {
        Nodes[Depth-1].HadChild=TRUE;
        if (Depth==1 && Same(D+NameStart,NameBytes,"system-controller@15860000")) N->Kind=PMU;
        else if (Depth==1 && Same(D+NameStart,NameBytes,"pinctrl@15850000")) N->Kind=GPIO;
        else if (Depth==1 && Same(D+NameStart,NameBytes,"gpio_keys")) N->Kind=KEYS;
        else if (Depth==1 && Same(D+NameStart,NameBytes,"reboot")) N->Kind=REBOOT;
        else if (Depth==2 && Nodes[Depth-1].Kind==GPIO && Same(D+NameStart,NameBytes,"gpa0")) N->Kind=GPA0;
        else if (Depth==2 && Nodes[Depth-1].Kind==GPIO && Same(D+NameStart,NameBytes,"gpa2")) N->Kind=GPA2;
        else if (Depth==2 && Nodes[Depth-1].Kind==KEYS && Same(D+NameStart,NameBytes,"button@4")) N->Kind=POWER;
        else if (Depth==2 && Nodes[Depth-1].Kind==KEYS && Same(D+NameStart,NameBytes,"button@2")) N->Kind=DOWN;
        if (N->Kind) { if (SeenKinds & (1U<<N->Kind)) return 4; SeenKinds |= 1U<<N->Kind; }
      }
      Depth++; continue;
    }
    if (Token==2) {
      if (!Depth) return 3;
      NODE *N=&Nodes[Depth-1]; UINT32 Required=0;
      if (N->Kind==ROOT) Required=ADDR|SIZE|COMPAT;
      if (N->Kind==PMU) Required=REG|COMPAT|PHANDLE;
      if (N->Kind==GPIO) Required=REG|COMPAT;
      if (N->Kind==KEYS) Required=COMPAT;
      if (N->Kind==REBOOT) Required=COMPAT|REG;
      if (N->Kind==GPA0 || N->Kind==GPA2) Required=PHANDLE|CELLS|CONTROLLER;
      if (N->Kind==POWER || N->Kind==DOWN) Required=CODE|GP;
      if ((N->Seen&Required)!=Required) return 6;
      if (N->Kind==PMU) PmuPhandle=N->Phandle;
      if (N->Kind==GPA0) Gpa0=N->Phandle;
      if (N->Kind==GPA2) Gpa2=N->Phandle;
      if (N->Kind==POWER) KeyPower=N->GpioPhandle;
      if (N->Kind==DOWN) KeyDown=N->GpioPhandle;
      if (N->Kind) DoneKinds |= 1U<<N->Kind;
      Depth--; continue;
    }
    if (Token!=3 || !Depth || Nodes[Depth-1].HadChild || !Fits(Cursor,8,End))
      return 3;
    Length=Be32(D+Cursor); Offset=Be32(D+Cursor+4); Cursor+=8;
    if (!Fits(Cursor,Length,End) || Offset>=StringsBytes) return 3;
    Next=(Cursor+Length+3)&~3ULL;
    if (Next>End) return 3;
    NameStart=Strings+Offset; NameBytes=0;
    while (NameBytes<128 && Offset+NameBytes<StringsBytes && D[NameStart+NameBytes]) NameBytes++;
    if (NameBytes>=128 || Offset+NameBytes>=StringsBytes) return 3;
    if (Nodes[Depth-1].Kind) {
      Error=Property(&Nodes[Depth-1],D+NameStart,NameBytes+1,D+Cursor,Length);
      if (Error) return Error;
    }
    Cursor=Next;
  }
  return 3;
}

BOOLEAN EFIAPI N976nAdmitPower (CONST VOID *Dtb, UINT64 Bytes, N976N_POWER_ADMISSION *Out) {
  if(!Out)return FALSE;
  ZeroMem(Out,sizeof(*Out));Out->Magic=N976N_POWER_ADMISSION_MAGIC;Out->Version=1;Out->Size=sizeof(*Out);
  Out->Reason=Parse(Dtb,Bytes,Out);
  if(Out->Reason){Out->PowerPhandle=Out->DownPhandle=0;return FALSE;}
  Out->PmuBase=N976N_POWER_PMU;Out->GpioBase=N976N_POWER_GPIO;
  Out->PowerPin=Out->DownPin=4;Out->Checks=0xFF;Out->Admitted=1;return TRUE;
}
