/* SPDX-License-Identifier: MIT
 * SEC67 read-only ACPI facts. The bounded token walker follows the retained
 * UfsAdmission implementation. Samsung N976N runtime DT is the phone source;
 * the separate QEMU profile uses its captured virt/GICv2/smp1 description.
 * No MMIO, PSCI call, device programming, or memory publication occurs here.
 */
#include <N976nAcpiAdmission.h>
#include <Library/BaseMemoryLib.h>

#define MAX_DEPTH 16U
#define ROOT 1U
#define CPUS 2U
#define CPU  3U
#define GIC  4U
#define TIMER 5U
#define PSCI 6U
#define ADDR BIT0
#define SIZE BIT1
#define COMPAT BIT2
#define REG BIT3
#define STATUS BIT4
#define INTPARENT BIT5
#define INTCELLS BIT6
#define INTCONTROLLER BIT7
#define INTERRUPTS BIT8
#define PHANDLE BIT9
#define LINUXPHANDLE BIT10
#define DEVTYPE BIT11
#define METHOD BIT12
#define FREQUENCY BIT13
#define SUSPEND BIT14
#define OFF BIT15
#define ON BIT16

typedef struct {
  UINT32 Kind, Seen;
  BOOLEAN HadChild;
  UINT64 Mpidr;
} NODE;
typedef struct {
  N976N_ACPI_ADMISSION *Out;
  UINT32 RootParent, GicPhandle, GicLinuxPhandle, CpuMask;
  UINT32 Counts[7];
  BOOLEAN Done[7];
} PARSE_STATE;

STATIC UINT32 Be32 (CONST UINT8 *P)
{ return ((UINT32)P[0]<<24) | ((UINT32)P[1]<<16) | ((UINT32)P[2]<<8) | P[3]; }
STATIC UINT64 Be64 (CONST UINT8 *P)
{ return ((UINT64)Be32(P)<<32) | Be32(P+4); }
STATIC BOOLEAN Fits (UINT64 A, UINT64 N, UINT64 E)
{ return A <= E && N <= E-A; }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 An, UINT64 B, UINT64 Bn)
{ return An && Bn && A < B+Bn && B < A+An; }
STATIC BOOLEAN Same (CONST UINT8 *P, UINTN Bytes, CONST CHAR8 *S)
{
  for (UINTN I=0; I<Bytes; I++) {
    if (P[I] != (UINT8)S[I]) return FALSE;
    if (!S[I]) return I+1==Bytes;
  }
  return FALSE;
}
STATIC BOOLEAN Literal (CONST UINT8 *P, UINTN Bytes, CONST VOID *V, UINTN N)
{ return Bytes==N && CompareMem(P,V,N)==0; }
STATIC UINTN CpuIndex (UINT64 Mpidr)
{
  if (Mpidr<=5) return (UINTN)Mpidr;
  if (Mpidr==0x100 || Mpidr==0x101) return (UINTN)(Mpidr-0x100+6);
  return 8;
}

STATIC UINT64 Property (PARSE_STATE *S, NODE *N,
  CONST UINT8 *Name, UINTN NameBytes, CONST UINT8 *V, UINTN Bytes)
{
  UINT32 Bit=0; BOOLEAN Good=FALSE;
  // Captured N976N DT retains the Exynos 9820 family compatible string.
  STATIC CONST CHAR8 RootCompat[]="samsung,armv8\0samsung,exynos9820";
  STATIC CONST CHAR8 GicCompat[]="arm,cortex-a15-gic\0arm,cortex-a9-gic";
  STATIC CONST CHAR8 LittleCompat[]="arm,ananke\0arm,armv8";
  STATIC CONST CHAR8 MiddleCompat[]="arm,prometheus\0arm,armv8";
  STATIC CONST CHAR8 BigCompat[]="arm,cheetah\0arm,armv8";
  if (Same(Name,NameBytes,"status")) {
    Bit=STATUS; Good=Same(V,Bytes,"okay") || Same(V,Bytes,"ok");
  } else if (Same(Name,NameBytes,"#address-cells")) {
    Bit=ADDR; Good=Bytes==4 && Be32(V)==(N->Kind==GIC ? 0U : 2U);
  } else if (Same(Name,NameBytes,"#size-cells")) {
    Bit=SIZE; Good=Bytes==4 && Be32(V)==(N->Kind==CPUS ? 0U : 1U);
  } else if (Same(Name,NameBytes,"compatible")) {
    Bit=COMPAT;
    if (N->Kind==ROOT) Good=Literal(V,Bytes,RootCompat,sizeof(RootCompat));
    if (N->Kind==GIC) Good=Literal(V,Bytes,GicCompat,sizeof(GicCompat));
    if (N->Kind==TIMER) Good=Same(V,Bytes,"arm,armv8-timer");
    if (N->Kind==PSCI) Good=Same(V,Bytes,"arm,psci");
    if (N->Kind==CPU) {
      UINTN I=CpuIndex(N->Mpidr);
      Good=I<4 ? Literal(V,Bytes,LittleCompat,sizeof(LittleCompat)) :
        I<6 ? Literal(V,Bytes,MiddleCompat,sizeof(MiddleCompat)) :
        I<8 && Literal(V,Bytes,BigCompat,sizeof(BigCompat));
    }
  } else if (Same(Name,NameBytes,"interrupt-parent")) {
    Bit=INTPARENT; Good=N->Kind==ROOT && Bytes==4 && Be32(V)!=0;
    if (Good) S->RootParent=Be32(V);
  } else if (N->Kind==CPU && Same(Name,NameBytes,"reg")) {
    Bit=REG; Good=Bytes==8 && Be64(V)==N->Mpidr;
  } else if (N->Kind==CPU && Same(Name,NameBytes,"device_type")) {
    Bit=DEVTYPE; Good=Same(V,Bytes,"cpu");
  } else if (N->Kind==CPU && Same(Name,NameBytes,"enable-method")) {
    Bit=METHOD; Good=Same(V,Bytes,"psci");
  } else if (N->Kind==GIC && Same(Name,NameBytes,"reg")) {
    STATIC CONST UINT64 B[4]={0x10101000,0x10102000,0x10104000,0x10106000};
    STATIC CONST UINT64 Z[4]={0x1000,0x1000,0x2000,0x2000};
    Bit=REG; Good=Bytes==48;
    if (Good) for (UINTN I=0; I<4; I++) {
      if (Be64(V+12*I)!=B[I] || Be32(V+12*I+8)!=Z[I]) Good=FALSE;
      S->Out->GicBase[I]=B[I]; S->Out->GicBytes[I]=Z[I];
    }
  } else if (N->Kind==GIC && Same(Name,NameBytes,"#interrupt-cells")) {
    Bit=INTCELLS; Good=Bytes==4 && Be32(V)==3;
  } else if (N->Kind==GIC && Same(Name,NameBytes,"interrupt-controller")) {
    Bit=INTCONTROLLER; Good=Bytes==0;
  } else if (N->Kind==GIC && Same(Name,NameBytes,"phandle")) {
    Bit=PHANDLE; Good=Bytes==4 && Be32(V)!=0;
    if (Good) S->GicPhandle=Be32(V);
  } else if (N->Kind==GIC && Same(Name,NameBytes,"linux,phandle")) {
    Bit=LINUXPHANDLE; Good=Bytes==4 && Be32(V)!=0;
    if (Good) S->GicLinuxPhandle=Be32(V);
  } else if (N->Kind==GIC && Same(Name,NameBytes,"interrupts")) {
    Bit=INTERRUPTS; Good=Bytes==12 && Be32(V)==1 &&
      Be32(V+4)==9 && Be32(V+8)==0xF04;
    if (Good) { S->Out->GicMaintenanceGsiv=25; S->Out->GicMaintenanceFlags=0; }
  } else if (N->Kind==TIMER && Same(Name,NameBytes,"interrupts")) {
    STATIC CONST UINT32 Ppi[4]={13,14,11,10};
    Bit=INTERRUPTS; Good=Bytes==48;
    if (Good) for (UINTN I=0; I<4; I++) {
      if (Be32(V+12*I)!=1 || Be32(V+12*I+4)!=Ppi[I] ||
          Be32(V+12*I+8)!=0xFF08) Good=FALSE;
      S->Out->TimerGsiv[I]=16+Ppi[I]; S->Out->TimerFlags[I]=2;
    }
  } else if (N->Kind==TIMER && Same(Name,NameBytes,"clock-frequency")) {
    Bit=FREQUENCY; Good=Bytes==4 && Be32(V)==26000000;
  } else if (N->Kind==TIMER && Same(Name,NameBytes,"always-on")) {
    return 0x674; /* This observed phone source makes no always-on guarantee. */
  } else if (N->Kind==PSCI && Same(Name,NameBytes,"method")) {
    Bit=METHOD; Good=Same(V,Bytes,"smc");
  } else if (N->Kind==PSCI && Same(Name,NameBytes,"cpu_suspend")) {
    Bit=SUSPEND; Good=Bytes==4 && Be32(V)==0xC4000001;
  } else if (N->Kind==PSCI && Same(Name,NameBytes,"cpu_off")) {
    Bit=OFF; Good=Bytes==4 && Be32(V)==0x84000002;
  } else if (N->Kind==PSCI && Same(Name,NameBytes,"cpu_on")) {
    Bit=ON; Good=Bytes==4 && Be32(V)==0xC4000003;
  } else if (Same(Name,NameBytes,"ranges") || Same(Name,NameBytes,"interrupts-extended") ||
             Same(Name,NameBytes,"interrupt-map") || Same(Name,NameBytes,"cpu-release-addr")) {
    return 0x674; /* A changed addressing/interrupt/CPU startup contract. */
  } else {
    return 0; /* Unrelated scheduler, idle, clocksource and phandle metadata. */
  }
  if (N->Seen & Bit) return 0x673;
  if (!Good) return 0x674;
  N->Seen |= Bit; return 0;
}

STATIC UINT64 Parse (CONST UINT8 *D, UINT64 Bytes, N976N_ACPI_ADMISSION *Out)
{
  NODE Nodes[MAX_DEPTH]; PARSE_STATE S;
  UINT64 Struct, StructBytes, End, Strings, StringsBytes, Map, MapEnd;
  UINT64 Cursor, Length, NameStart, NameBytes, Offset, Next, Error;
  UINT32 Depth=0;
  STATIC CONST CHAR8 CpuNames[8][9]={"cpu@0000","cpu@0001","cpu@0002","cpu@0003",
    "cpu@0004","cpu@0005","cpu@0100","cpu@0101"};
  if (!D || Bytes<40 || Bytes>0x100000) return 0x670;
  if (Be32(D)!=0xD00DFEED || Be32(D+4)!=Bytes || Be32(D+20)!=17 || Be32(D+24)>17) return 0x671;
  Struct=Be32(D+8); Strings=Be32(D+12); Map=Be32(D+16);
  StringsBytes=Be32(D+32); StructBytes=Be32(D+36);
  if (Struct<40 || (Struct&3) || StructBytes<4 || (StructBytes&3) ||
      !Fits(Struct,StructBytes,Bytes) || Strings<40 || !StringsBytes ||
      !Fits(Strings,StringsBytes,Bytes) || Overlap(Struct,StructBytes,Strings,StringsBytes) ||
      Map<40 || (Map&7) || Map>=Bytes) return 0x671;
  End=Struct+StructBytes; MapEnd=Bytes;
  if ((Map>=Struct && Map<End) || (Map>=Strings && Map<Strings+StringsBytes)) return 0x671;
  if (Struct>Map && Struct<MapEnd) MapEnd=Struct;
  if (Strings>Map && Strings<MapEnd) MapEnd=Strings;
  for (Cursor=Map; ; Cursor+=16) {
    if (!Fits(Cursor,16,MapEnd)) return 0x671;
    if (!Be64(D+Cursor) && !Be64(D+Cursor+8)) break;
  }
  ZeroMem(Nodes,sizeof(Nodes)); ZeroMem(&S,sizeof(S)); S.Out=Out; Cursor=Struct;
  while (Fits(Cursor,4,End)) {
    UINT32 Token=Be32(D+Cursor); Cursor+=4;
    if (Token==4) continue;
    if (Token==9) {
      if (Depth || Cursor!=End || S.Counts[ROOT]!=1) return 0x672;
      for (UINTN I=ROOT; I<=PSCI; I++) if (!S.Done[I]) return 0x675;
      if (S.CpuMask!=0xFF || S.Counts[CPU]!=8 ||
          S.RootParent!=S.GicPhandle || S.GicLinuxPhandle!=S.GicPhandle) return 0x675;
      Out->CpuCount=8; Out->GicVersion=2;
      return 0;
    }
    if (Token==1) {
      if (Depth>=MAX_DEPTH) return 0x672;
      NameStart=Cursor;
      while (Cursor<End && Cursor-NameStart<256 && D[Cursor]) Cursor++;
      if (Cursor>=End || Cursor-NameStart>=256) return 0x672;
      NameBytes=Cursor-NameStart+1; Cursor=(Cursor+4)&~3ULL;
      if (Cursor>End) return 0x672;
      NODE *N=&Nodes[Depth]; ZeroMem(N,sizeof(*N));
      if (Depth==0) {
        if (S.Counts[ROOT] || NameBytes!=1) return 0x672;
        N->Kind=ROOT;
      } else {
        Nodes[Depth-1].HadChild=TRUE;
        if (Depth==1) {
          if (Same(D+NameStart,NameBytes,"cpus")) N->Kind=CPUS;
          else if (Same(D+NameStart,NameBytes,"interrupt-controller@10100000")) N->Kind=GIC;
          else if (Same(D+NameStart,NameBytes,"timer")) N->Kind=TIMER;
          else if (Same(D+NameStart,NameBytes,"psci")) N->Kind=PSCI;
        } else if (Depth==2 && Nodes[Depth-1].Kind==CPUS) {
          for (UINTN I=0; I<8; I++) if (Same(D+NameStart,NameBytes,CpuNames[I])) {
            if (S.CpuMask & (1U<<I)) return 0x673;
            N->Kind=CPU; N->Mpidr=I<6 ? I : I-6+0x100;
            S.CpuMask |= 1U<<I; Out->CpuMpidr[I]=N->Mpidr;
          }
          if (!N->Kind && NameBytes>=5 && CompareMem(D+NameStart,"cpu@",4)==0) return 0x674;
        }
      }
      if (N->Kind && ++S.Counts[N->Kind] > (N->Kind==CPU ? 8U : 1U)) return 0x673;
      Depth++; continue;
    }
    if (Token==2) {
      if (!Depth) return 0x672;
      NODE *N=&Nodes[Depth-1]; UINT32 Required=0;
      if (N->Kind==ROOT) Required=ADDR|SIZE|COMPAT|INTPARENT;
      if (N->Kind==CPUS) Required=ADDR|SIZE;
      if (N->Kind==CPU) Required=COMPAT|REG|DEVTYPE|METHOD;
      if (N->Kind==GIC) Required=COMPAT|REG|ADDR|INTCELLS|INTCONTROLLER|INTERRUPTS|PHANDLE|LINUXPHANDLE;
      if (N->Kind==TIMER) Required=COMPAT|INTERRUPTS|FREQUENCY;
      if (N->Kind==PSCI) Required=COMPAT|METHOD|SUSPEND|OFF|ON;
      if ((N->Seen&Required)!=Required || (N->Kind>=CPU && N->HadChild)) return 0x675;
      if (N->Kind) S.Done[N->Kind]=TRUE;
      Depth--; continue;
    }
    if (Token!=3 || !Depth || Nodes[Depth-1].HadChild || !Fits(Cursor,8,End)) return 0x672;
    Length=Be32(D+Cursor); Offset=Be32(D+Cursor+4); Cursor+=8;
    if (!Fits(Cursor,Length,End) || Offset>=StringsBytes) return 0x672;
    Next=(Cursor+Length+3)&~3ULL; if (Next>End) return 0x672;
    NameStart=Strings+Offset; NameBytes=0;
    while (NameBytes<128 && Offset+NameBytes<StringsBytes && D[NameStart+NameBytes]) NameBytes++;
    if (NameBytes>=128 || Offset+NameBytes>=StringsBytes) return 0x672;
    if (Nodes[Depth-1].Kind) {
      Error=Property(&S,&Nodes[Depth-1],D+NameStart,NameBytes+1,D+Cursor,Length);
      if (Error) return Error;
    }
    Cursor=Next;
  }
  return 0x672;
}

BOOLEAN EFIAPI N976nAdmitAcpi (CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  UINT64 RawMpidr, UINT64 CounterFrequency, N976N_ACPI_ADMISSION *Out)
{
  UINT64 Error;
  if (Out==NULL) return FALSE;
  ZeroMem(Out,sizeof(*Out)); Out->Magic=N976N_ACPI_ADMISSION_MAGIC;
  Out->Version=N976N_ACPI_ABI_VERSION; Out->Size=sizeof(*Out); Out->Profile=Profile;
  Out->Reason=Parse(Dtb,DtbBytes,Out);
  if (Out->Reason) return FALSE;
  Out->BspMpidr=RawMpidr & 0xFF00FFFFFFULL;
  Out->CounterFrequency=CounterFrequency;
  Error=0x676;
  if (Profile==N976N_PLATFORM_PROFILE_PHONE) {
    if (CpuIndex(Out->BspMpidr)>=8 || CounterFrequency!=26000000) goto Bad;
  } else if (Profile==N976N_PLATFORM_PROFILE_QEMU) {
    /* The harness intentionally feeds the same phone ownership DT to SEC.
     * Virtual CPU/GIC/timer facts come from the separately pinned QEMU profile,
     * not from those physical-controller nodes. Actual generated DT is retained. */
    if (Out->BspMpidr!=0 || CounterFrequency!=62500000) goto Bad;
    Out->CpuCount=1; ZeroMem(Out->CpuMpidr,sizeof(Out->CpuMpidr));
    Out->GicBase[0]=0x08000000; Out->GicBase[1]=0x08010000;
    Out->GicBytes[0]=Out->GicBytes[1]=0x10000;
    Out->GicBase[2]=Out->GicBase[3]=Out->GicBytes[2]=Out->GicBytes[3]=0;
    Out->GicMaintenanceGsiv=Out->GicMaintenanceFlags=0; Out->PsciUseHvc=1;
    for (UINTN I=0; I<4; I++) Out->TimerFlags[I]=4;
  } else goto Bad;
  Out->Checks=0x7F; return TRUE;
Bad:
  Out->Reason=Error; return FALSE;
}

BOOLEAN EFIAPI N976nCompleteAcpiAdmission (
  N976N_ACPI_ADMISSION *Out, UINT32 GicTyper, UINT32 TargetMask)
{
  UINT32 Interfaces=((GicTyper>>5)&7)+1, Index=0;
  if (Out==NULL) return FALSE;
  if (Out->Magic!=N976N_ACPI_ADMISSION_MAGIC || Out->Version!=1 ||
      Out->Size!=sizeof(*Out) || Out->Checks!=0x7F || Out->Admitted || Out->Reason) return FALSE;
  Out->Reason=0x677;
  if (Out->Profile==N976N_PLATFORM_PROFILE_QEMU &&
      (Interfaces!=1 || Out->CpuCount!=1)) return FALSE;
  if (TargetMask==0) {
    /* GICv2 uniprocessor ITARGETSR is RAZ in this exact QEMU profile. */
    if (Out->Profile!=N976N_PLATFORM_PROFILE_QEMU || Interfaces!=1 || Out->CpuCount!=1) return FALSE;
  } else {
    if ((TargetMask & ~255U) || (TargetMask & (TargetMask-1))) return FALSE;
    while ((TargetMask>>Index)!=1) Index++;
    if (Index>=Interfaces || (Out->Profile==N976N_PLATFORM_PROFILE_QEMU && Index!=0)) return FALSE;
  }
  Out->BspInterfaceNumber=Index;
  Out->Reason=0; Out->Checks=N976N_ACPI_ADMISSION_CHECKS; Out->Admitted=1;
  return TRUE;
}
