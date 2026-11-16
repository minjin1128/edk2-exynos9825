/* SPDX-License-Identifier: MIT
 * Pure N976N ACPM/PMIC/touch DT admission. No hardware access. The bounded
 * walker is retained from TouchAdmission, with separately checked resources.
 * DT boot-on/initial-mode are declarations, never a current rail measurement.
 */
#include <N976nAcpm.h>
#include <N976nPlatform.h>
#include <Library/BaseMemoryLib.h>
#include "RootCompatible.h"

#define DEPTH_MAX 16U
#define PHANDLE_MAX 2048U
enum { NONE, ROOT, IPC, SPEEDY, PMIC, REGS, IO, AVDD, HSI, TOUCH, KINDS };
enum { P_COMPAT, P_REG, P_STATUS, P_ADDR, P_SIZE, P_INIT, P_CHANNEL,
       P_SPEEDY, P_NAME, P_MIN, P_MAX, P_BOOT, P_MODE, P_DVDD, P_AVDD,
       P_FIRMWARE, P_ALWAYS, P_PARENT, P_INTS };
#define PB(P) (1ULL << (P))
typedef struct {
  UINT32 Kind, Phandle, LinuxPhandle;
  UINT64 Seen;
  BOOLEAN Child, HavePhandle, HaveLinuxPhandle;
} NODE;
typedef struct {
  UINT32 Counts[KINDS], Used[PHANDLE_MAX], UsedCount;
  BOOLEAN Done[KINDS];
} STATE;

STATIC UINT32 Be32 (CONST UINT8 *P)
{ return ((UINT32)P[0]<<24)|((UINT32)P[1]<<16)|((UINT32)P[2]<<8)|P[3]; }
STATIC UINT64 Be64 (CONST UINT8 *P)
{ return ((UINT64)Be32(P)<<32)|Be32(P+4); }
STATIC BOOLEAN Fits (UINT64 A, UINT64 N, UINT64 End)
{ return A<=End && N<=End-A; }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return N && M && A<B+M && B<A+N; }
STATIC BOOLEAN Same (CONST UINT8 *P, UINTN N, CONST CHAR8 *S)
{
  for (UINTN I=0; I<N; I++) {
    if (P[I]!=(UINT8)S[I]) return FALSE;
    if (!S[I]) return I+1==N;
  }
  return FALSE;
}
STATIC BOOLEAN Cell (CONST UINT8 *P, UINTN N, UINT32 V)
{ return N==4 && Be32(P)==V; }
STATIC BOOLEAN Reg (CONST UINT8 *P, UINTN N, UINT64 A, UINT32 Bytes)
{ return N==12 && Be64(P)==A && Be32(P+8)==Bytes; }


STATIC UINT64 Property (NODE *N, CONST UINT8 *Name, UINTN NameBytes,
  CONST UINT8 *V, UINTN Bytes)
{
  UINT32 K=N->Kind, P=0; BOOLEAN Good=FALSE;
  if (Same(Name,NameBytes,"phandle") || Same(Name,NameBytes,"linux,phandle")) {
    BOOLEAN Linux=Same(Name,NameBytes,"linux,phandle");
    if (Bytes!=4 || !Be32(V) || Be32(V)==MAX_UINT32) return 5;
    if (Linux ? N->HaveLinuxPhandle : N->HavePhandle) return 4;
    if (Linux) { N->HaveLinuxPhandle=TRUE; N->LinuxPhandle=Be32(V); }
    else { N->HavePhandle=TRUE; N->Phandle=Be32(V); }
    return 0;
  }
  if (!K) return 0;
  if (Same(Name,NameBytes,"compatible")) {
    P=P_COMPAT;
    if (K==ROOT) Good=N976nRootCompatible(V,Bytes);
    else if (K==IPC) Good=Same(V,Bytes,"samsung,exynos-acpm-ipc");
    else if (K==SPEEDY) Good=Same(V,Bytes,"samsung,exynos-speedy");
    else if (K==PMIC) Good=Same(V,Bytes,"samsung,s2mps19mfd");
    else if (K==HSI) Good=Same(V,Bytes,"samsung,exynos5-hsi2c");
    else if (K==TOUCH) Good=Same(V,Bytes,"sec,sec_ts");
  } else if (Same(Name,NameBytes,"status")) {
    P=P_STATUS; Good=Same(V,Bytes,"okay") || Same(V,Bytes,"ok");
  } else if (Same(Name,NameBytes,"reg")) {
    P=P_REG;
    if (K==IPC) Good=Bytes==24 && Reg(V,12,N976N_ACPM_MAILBOX,0x1000) &&
      Reg(V+12,12,N976N_ACPM_SRAM,0x30000);
    else if (K==SPEEDY) Good=Reg(V,Bytes,0x15970000,0x2000);
    else if (K==PMIC) Good=Cell(V,Bytes,0);
    else if (K==HSI) Good=Reg(V,Bytes,0x104B0000,0x1000);
    else if (K==TOUCH) Good=Cell(V,Bytes,0x48);
  } else if (Same(Name,NameBytes,"#address-cells")) {
    P=P_ADDR; Good=Cell(V,Bytes,(K==ROOT || K==IPC) ? 2 :
      (K==SPEEDY || K==HSI) ? 1 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"#size-cells")) {
    P=P_SIZE; Good=Cell(V,Bytes,(K==ROOT || K==IPC) ? 1 :
      (K==SPEEDY || K==HSI) ? 0 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"initdata-base") && K==IPC) {
    P=P_INIT; Good=Cell(V,Bytes,0x7000);
  } else if (Same(Name,NameBytes,"acpm-ipc-channel") && K==PMIC) {
    P=P_CHANNEL; Good=Cell(V,Bytes,2);
  } else if (Same(Name,NameBytes,"acpm-speedy-channel") && K==PMIC) {
    P=P_SPEEDY; Good=Cell(V,Bytes,0);
  } else if (Same(Name,NameBytes,"regulator-name") && (K==IO || K==AVDD)) {
    P=P_NAME; Good=Same(V,Bytes,K==IO ? "tsp_io" : "tsp_avdd");
  } else if ((Same(Name,NameBytes,"regulator-min-microvolt") ||
              Same(Name,NameBytes,"regulator-max-microvolt")) && (K==IO || K==AVDD)) {
    P=Same(Name,NameBytes,"regulator-min-microvolt") ? P_MIN : P_MAX;
    Good=Cell(V,Bytes,K==IO ? 1800000 : 3000000);
  } else if (Same(Name,NameBytes,"regulator-boot-on") && (K==IO || K==AVDD)) {
    P=P_BOOT; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"regulator-initial-mode") && (K==IO || K==AVDD)) {
    P=P_MODE; Good=Cell(V,Bytes,K==IO ? 2 : 3);
  } else if (Same(Name,NameBytes,"regulator-always-on") && (K==IO || K==AVDD)) {
    /* This source profile explicitly lacks an always-on claim. */
    return 5;
  } else if (Same(Name,NameBytes,"sec,regulator_dvdd") && K==TOUCH) {
    P=P_DVDD; Good=Same(V,Bytes,"tsp_io");
  } else if (Same(Name,NameBytes,"sec,regulator_avdd") && K==TOUCH) {
    P=P_AVDD; Good=Same(V,Bytes,"tsp_avdd");
  } else if (Same(Name,NameBytes,"sec,firmware_name") && K==TOUCH) {
    P=P_FIRMWARE; Good=Same(V,Bytes,"tsp_sec/y771_d2.bin");
  } else if (Same(Name,NameBytes,"interrupts") && K==IPC) {
    P=P_INTS; Good=Bytes==12 && !Be32(V) && Be32(V+4)==40 && !Be32(V+8);
  } else if (Same(Name,NameBytes,"ranges") || Same(Name,NameBytes,"dma-ranges") ||
             Same(Name,NameBytes,"interrupts-extended") || Same(Name,NameBytes,"interrupt-map")) {
    return 5;
  } else return 0;
  if (N->Seen&PB(P)) return 4;
  if (!Good) return 5;
  N->Seen|=PB(P); return 0;
}

STATIC UINT64 Required (UINT32 K)
{
  UINT64 Identity=PB(P_COMPAT)|PB(P_REG), Cells=PB(P_ADDR)|PB(P_SIZE);
  if (K==ROOT) return PB(P_COMPAT)|Cells;
  if (K==IPC) return Identity|Cells|PB(P_INIT)|PB(P_INTS);
  if (K==SPEEDY || K==HSI) return Identity|Cells|PB(P_STATUS);
  if (K==PMIC) return Identity|PB(P_CHANNEL)|PB(P_SPEEDY);
  if (K==TOUCH) return Identity|PB(P_DVDD)|PB(P_AVDD)|PB(P_FIRMWARE);
  if (K==IO || K==AVDD) return PB(P_NAME)|PB(P_MIN)|PB(P_MAX)|PB(P_BOOT)|PB(P_MODE);
  return 0;
}
STATIC UINT64 Parse (CONST UINT8 *D, UINT64 Bytes)
{
  NODE Nodes[DEPTH_MAX]; STATE S;
  UINT64 Struct, StructBytes, End, Strings, StringsBytes, Map, MapEnd, Cursor;
  UINT32 Depth=0;
  if (!D || Bytes<40 || Bytes>0x100000 || (UINTN)D>MAX_UINTN-Bytes) return 1;
  if (Be32(D)!=0xD00DFEED || Be32(D+4)!=Bytes || Be32(D+20)!=17 || Be32(D+24)>17) return 2;
  Struct=Be32(D+8); Strings=Be32(D+12); Map=Be32(D+16);
  StringsBytes=Be32(D+32); StructBytes=Be32(D+36);
  if (Struct<40 || (Struct&3) || StructBytes<4 || (StructBytes&3) ||
      !Fits(Struct,StructBytes,Bytes) || Strings<40 || !StringsBytes ||
      !Fits(Strings,StringsBytes,Bytes) || Overlap(Struct,StructBytes,Strings,StringsBytes) ||
      Map<40 || (Map&7) || Map>=Bytes) return 2;
  End=Struct+StructBytes; MapEnd=Bytes;
  if ((Map>=Struct && Map<End) || (Map>=Strings && Map<Strings+StringsBytes)) return 2;
  if (Struct>Map && Struct<MapEnd) MapEnd=Struct;
  if (Strings>Map && Strings<MapEnd) MapEnd=Strings;
  for (Cursor=Map; ; Cursor+=16) {
    if (!Fits(Cursor,16,MapEnd)) return 2;
    if (!Be64(D+Cursor) && !Be64(D+Cursor+8)) break;
  }
  ZeroMem(Nodes,sizeof(Nodes)); ZeroMem(&S,sizeof(S)); Cursor=Struct;
  while (Fits(Cursor,4,End)) {
    UINT32 Token=Be32(D+Cursor); Cursor+=4;
    if (Token==4) continue;
    if (Token==9) {
      if (Depth || Cursor!=End || S.Counts[ROOT]!=1) return 3;
      for (UINTN I=ROOT; I<KINDS; I++) if (!S.Done[I]) return 6;
      return 0;
    }
    if (Token==1) {
      if (Depth>=DEPTH_MAX) return 3;
      UINT64 Start=Cursor;
      while (Cursor<End && Cursor-Start<256 && D[Cursor]) Cursor++;
      if (Cursor>=End || Cursor-Start>=256) return 3;
      UINT64 NBytes=Cursor-Start+1; Cursor=(Cursor+4)&~3ULL;
      if (Cursor>End) return 3;
      NODE *N=&Nodes[Depth]; ZeroMem(N,sizeof(*N));
      if (Depth==0) {
        if (S.Counts[ROOT] || NBytes!=1) return 3;
        N->Kind=ROOT;
      } else {
        UINT32 Parent=Nodes[Depth-1].Kind;
        Nodes[Depth-1].Child=TRUE;
        if (Depth==1) {
          if (Same(D+Start,NBytes,"acpm_ipc")) N->Kind=IPC;
          else if (Same(D+Start,NBytes,"speedy@15970000")) N->Kind=SPEEDY;
          else if (Same(D+Start,NBytes,"hsi2c@104B0000")) N->Kind=HSI;
        } else if (Depth==2) {
          if (Parent==SPEEDY && Same(D+Start,NBytes,"s2mps19mfd@00")) N->Kind=PMIC;
          if (Parent==HSI && Same(D+Start,NBytes,"touchscreen@48")) N->Kind=TOUCH;
        } else if (Depth==3) {
          if (Parent==PMIC && Same(D+Start,NBytes,"regulators")) N->Kind=REGS;
        } else if (Depth==4 && Parent==REGS) {
          if (Same(D+Start,NBytes,"LDO19M")) N->Kind=IO;
          if (Same(D+Start,NBytes,"LDO27M")) N->Kind=AVDD;
        }
      }
      if (N->Kind && ++S.Counts[N->Kind]>1) return 4;
      Depth++; continue;
    }
    if (Token==2) {
      if (!Depth) return 3;
      NODE *N=&Nodes[Depth-1]; UINT64 Need=Required(N->Kind);
      if ((N->Seen&Need)!=Need || ((N->Kind==IO || N->Kind==AVDD || N->Kind==TOUCH) && N->Child)) return 6;
      if (N->HavePhandle && N->HaveLinuxPhandle && N->Phandle!=N->LinuxPhandle) return 5;
      UINT32 Handle=N->HavePhandle ? N->Phandle : N->LinuxPhandle;
      if (Handle) {
        if (S.UsedCount>=PHANDLE_MAX) return 3;
        for (UINTN I=0; I<S.UsedCount; I++) if (S.Used[I]==Handle) return 4;
        S.Used[S.UsedCount++]=Handle;
      }
      if (N->Kind) S.Done[N->Kind]=TRUE;
      Depth--; continue;
    }
    if (Token!=3 || !Depth || Nodes[Depth-1].Child || !Fits(Cursor,8,End)) return 3;
    UINT64 Length=Be32(D+Cursor), Offset=Be32(D+Cursor+4); Cursor+=8;
    if (!Fits(Cursor,Length,End) || Offset>=StringsBytes) return 3;
    UINT64 Next=(Cursor+Length+3)&~3ULL; if (Next>End) return 3;
    UINT64 Name=Strings+Offset, NameBytes=0;
    while (NameBytes<128 && Offset+NameBytes<StringsBytes && D[Name+NameBytes]) NameBytes++;
    if (NameBytes>=128 || Offset+NameBytes>=StringsBytes) return 3;
    UINT64 Error=Property(&Nodes[Depth-1],D+Name,NameBytes+1,D+Cursor,Length);
    if (Error) return Error;
    Cursor=Next;
  }
  return 3;
}

BOOLEAN EFIAPI N976nAdmitAcpm (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile, N976N_ACPM_ADMISSION *Out)
{
  if (!Out || (UINTN)Out>MAX_UINTN-sizeof(*Out) ||
      (Dtb && DtbBytes && (UINTN)Dtb<=MAX_UINTN-DtbBytes &&
       Overlap((UINTN)Dtb,DtbBytes,(UINTN)Out,sizeof(*Out)))) return FALSE;
  ZeroMem(Out,sizeof(*Out));
  Out->Magic=N976N_ACPM_ADMISSION_MAGIC; Out->Version=1; Out->Size=sizeof(*Out); Out->Profile=Profile;
  Out->Reason=Profile>N976N_PLATFORM_PROFILE_QEMU ? 7 : Parse(Dtb,DtbBytes);
  if (Out->Reason) return FALSE;
  Out->Mailbox=N976N_ACPM_MAILBOX; Out->MailboxBytes=0x1000;
  Out->Sram=N976N_ACPM_SRAM; Out->SramBytes=0x30000; Out->InitOffset=0x7000;
  Out->Channel=2; Out->PmicType=1; Out->SpeedyChannel=0; Out->ReadRegisters=0x6058;
  Out->Checks=0xFFULL; Out->Admitted=1;
  return TRUE;
}
