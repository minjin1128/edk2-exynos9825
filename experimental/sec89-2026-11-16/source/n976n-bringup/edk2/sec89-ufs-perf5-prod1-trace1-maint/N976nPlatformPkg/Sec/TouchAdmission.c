/* SPDX-License-Identifier: MIT
 * SEC70: pure admission of the captured N976N Y771 touch path. The bounded
 * token walker follows retained AcpiAdmission/UfsAdmission. Samsung N976N
 * DT and driver constants are separate facts; neither proves powered MMIO.
 */
#include <N976nTouch.h>
#include <Library/BaseMemoryLib.h>
#include "RootCompatible.h"

#define DEPTH_MAX 16U
#define PHANDLE_MAX 2048U
enum { NONE, ROOT, HSI, TOUCH, USI, USI_ALT, ALIVE, PERIC, CLOCK,
       GPA1, GPP1, BUS_PIN, IRQ_PIN, OFF_PIN, KINDS };
enum { P_COMPAT, P_REG, P_STATUS, P_ADDR, P_SIZE, P_INTPARENT, P_INTS,
       P_GPIO, P_GPIOCELLS, P_INTCTL, P_INTCELLS, P_PINS, P_FUNC, P_PUD,
       P_DRV, P_PINNAMES, P_PIN0, P_PIN1, P_CLOCKS, P_CLOCKNAMES, P_HZ,
       P_SCL, P_SDA, P_USIMODE, P_IRQGPIO, P_IRQTYPE, P_COORDS,
       P_DVDD, P_AVDD, P_BOOTON, P_FIRMWARE, P_CHECKDONE, P_STRETCH,
       P_USIV2, P_RESET, P_STOP };
#define PB(P) (1ULL << (P))
typedef struct {
  UINT32 Kind, Phandle, LinuxPhandle;
  UINT64 Seen;
  BOOLEAN Child, HavePhandle, HaveLinuxPhandle;
} NODE;
typedef struct {
  UINT32 Counts[KINDS], Handles[KINDS], Used[PHANDLE_MAX], UsedCount;
  UINT32 RootParent, GpaParent, ClockRefs[2], BusRef, OnRef, OffRef;
  UINT32 SclRef, SdaRef, IrqRef;
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
STATIC BOOLEAN Literal (CONST UINT8 *P, UINTN N, CONST CHAR8 *V, UINTN Bytes)
{ return N==Bytes && !CompareMem(P,V,Bytes); }
STATIC BOOLEAN Cell (CONST UINT8 *P, UINTN N, UINT32 V)
{ return N==4 && Be32(P)==V; }
STATIC BOOLEAN Reg (CONST UINT8 *P, UINTN N, UINT64 A, UINT32 Bytes)
{ return N==12 && Be64(P)==A && Be32(P+8)==Bytes; }

STATIC UINT64 Property (STATE *S, NODE *N, CONST UINT8 *Name, UINTN NameBytes,
  CONST UINT8 *V, UINTN Bytes)
{
  UINT32 K=N->Kind, P=0;
  BOOLEAN Good=FALSE;
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
    else if (K==HSI) Good=Same(V,Bytes,"samsung,exynos5-hsi2c");
    else if (K==TOUCH) Good=Same(V,Bytes,"sec,sec_ts");
    else if (K==USI || K==USI_ALT) Good=Same(V,Bytes,"samsung,exynos-usi-v2");
    else if (K==ALIVE || K==PERIC) Good=Same(V,Bytes,"samsung,exynos9820-pinctrl");
    else if (K==CLOCK) Good=Same(V,Bytes,"samsung,exynos9820-clock");
  } else if (Same(Name,NameBytes,"status")) {
    P=P_STATUS; Good=K==USI_ALT ? Same(V,Bytes,"disabled") :
      (Same(V,Bytes,"okay") || Same(V,Bytes,"ok"));
  } else if (Same(Name,NameBytes,"reg")) {
    P=P_REG;
    if (K==HSI) Good=Reg(V,Bytes,N976N_TOUCH_HSI2C,0x1000);
    if (K==TOUCH) Good=Cell(V,Bytes,0x48);
    if (K==USI) Good=Reg(V,Bytes,N976N_TOUCH_SYSREG_USI,4);
    if (K==USI_ALT) Good=Reg(V,Bytes,0x10421020,4);
    if (K==ALIVE) Good=Reg(V,Bytes,N976N_TOUCH_GPIO_ALIVE,0x1000);
    if (K==PERIC) Good=Reg(V,Bytes,N976N_TOUCH_GPIO_PERIC0,0x1000);
    if (K==CLOCK) Good=Reg(V,Bytes,0x1A240000,0x8000);
  } else if (Same(Name,NameBytes,"#address-cells")) {
    P=P_ADDR; Good=Cell(V,Bytes,K==ROOT ? 2 : K==HSI ? 1 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"#size-cells")) {
    P=P_SIZE; Good=Cell(V,Bytes,K==ROOT ? 1 : K==HSI ? 0 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"interrupt-parent") && (K==ROOT || K==GPA1)) {
    P=P_INTPARENT; Good=Bytes==4 && Be32(V)!=0;
    if (Good) { if (K==ROOT) S->RootParent=Be32(V); else S->GpaParent=Be32(V); }
  } else if (Same(Name,NameBytes,"interrupts") && (K==HSI || K==GPA1)) {
    P=P_INTS;
    if (K==HSI) Good=Bytes==12 && Be32(V)==0 && Be32(V+4)==388 && Be32(V+8)==0;
    else {
      Good=Bytes==8*12;
      if (Good) for (UINTN I=0; I<8; I++)
        if (Be32(V+12*I)!=0 || Be32(V+12*I+4)!=13+I || Be32(V+12*I+8)!=0) Good=FALSE;
    }
  } else if (Same(Name,NameBytes,"gpio-controller")) {
    P=P_GPIO; Good=(K==GPA1 || K==GPP1) && Bytes==0;
  } else if (Same(Name,NameBytes,"#gpio-cells")) {
    P=P_GPIOCELLS; Good=(K==GPA1 || K==GPP1) && Cell(V,Bytes,2);
  } else if (Same(Name,NameBytes,"interrupt-controller")) {
    P=P_INTCTL; Good=(K==GPA1 || K==GPP1) && Bytes==0;
  } else if (Same(Name,NameBytes,"#interrupt-cells")) {
    P=P_INTCELLS; Good=Cell(V,Bytes,K==GPA1 ? 3 : K==GPP1 ? 2 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"samsung,pins")) {
    STATIC CONST CHAR8 Bus[]="gpp1-4\0gpp1-5";
    P=P_PINS; Good=K==BUS_PIN ? Literal(V,Bytes,Bus,sizeof(Bus)) :
      (K==IRQ_PIN || K==OFF_PIN) && Same(V,Bytes,"gpa1-0");
  } else if (Same(Name,NameBytes,"samsung,pin-function")) {
    P=P_FUNC; Good=Cell(V,Bytes,K==BUS_PIN ? 2 : K==IRQ_PIN ? 15 : K==OFF_PIN ? 0 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"samsung,pin-pud")) {
    P=P_PUD; Good=Cell(V,Bytes,K==OFF_PIN ? 1 : (K==BUS_PIN || K==IRQ_PIN) ? 0 : MAX_UINT32);
  } else if (Same(Name,NameBytes,"samsung,pin-drv")) {
    P=P_DRV; Good=(K==BUS_PIN || K==IRQ_PIN) && Cell(V,Bytes,0);
  } else if (Same(Name,NameBytes,"pinctrl-names") && (K==HSI || K==TOUCH)) {
    STATIC CONST CHAR8 Names[]="on_state\0off_state";
    P=P_PINNAMES; Good=K==HSI ? Same(V,Bytes,"default") : Literal(V,Bytes,Names,sizeof(Names));
  } else if (Same(Name,NameBytes,"pinctrl-0") && (K==HSI || K==TOUCH)) {
    P=P_PIN0; Good=Bytes==4 && Be32(V)!=0;
    if (Good) { if (K==HSI) S->BusRef=Be32(V); else S->OnRef=Be32(V); }
  } else if (Same(Name,NameBytes,"pinctrl-1") && K==TOUCH) {
    P=P_PIN1; Good=Bytes==4 && Be32(V)!=0; if (Good) S->OffRef=Be32(V);
  } else if (Same(Name,NameBytes,"clocks") && K==HSI) {
    P=P_CLOCKS; Good=Bytes==16 && Be32(V)!=0 && Be32(V+4)==0x1FD &&
      Be32(V+8)!=0 && Be32(V+12)==0x1ED;
    if (Good) { S->ClockRefs[0]=Be32(V); S->ClockRefs[1]=Be32(V+8); }
  } else if (Same(Name,NameBytes,"clock-names") && K==HSI) {
    STATIC CONST CHAR8 Names[]="ipclk_hsi2c\0gate_hsi2c_clk";
    P=P_CLOCKNAMES; Good=Literal(V,Bytes,Names,sizeof(Names));
  } else if (Same(Name,NameBytes,"#clock-cells") && K==CLOCK) {
    P=P_CLOCKS; Good=Cell(V,Bytes,1);
  } else if (Same(Name,NameBytes,"default-clk") && K==HSI) {
    P=P_HZ; Good=Cell(V,Bytes,200000000);
  } else if ((Same(Name,NameBytes,"gpio_scl") || Same(Name,NameBytes,"gpio_sda")) && K==HSI) {
    BOOLEAN Scl=Same(Name,NameBytes,"gpio_scl");
    P=Scl ? P_SCL : P_SDA; Good=Bytes==12 && Be32(V)!=0 && Be32(V+4)==(Scl ? 4U : 5U) && Be32(V+8)==1;
    if (Good) { if (Scl) S->SclRef=Be32(V); else S->SdaRef=Be32(V); }
  } else if (Same(Name,NameBytes,"usi_v2_mode") && K==USI) {
    P=P_USIMODE; Good=Same(V,Bytes,"i2c");
  } else if (Same(Name,NameBytes,"sec,irq_gpio") && K==TOUCH) {
    P=P_IRQGPIO; Good=Bytes==12 && Be32(V)!=0 && Be32(V+4)==0 && Be32(V+8)==0;
    if (Good) S->IrqRef=Be32(V);
  } else if (Same(Name,NameBytes,"sec,irq_type") && K==TOUCH) {
    P=P_IRQTYPE; Good=Cell(V,Bytes,0x2008);
  } else if (Same(Name,NameBytes,"sec,max_coords") && K==TOUCH) {
    P=P_COORDS; Good=Bytes==8 && Be32(V)==4096 && Be32(V+4)==4096;
  } else if (Same(Name,NameBytes,"sec,regulator_dvdd") && K==TOUCH) {
    P=P_DVDD; Good=Same(V,Bytes,"tsp_io");
  } else if (Same(Name,NameBytes,"sec,regulator_avdd") && K==TOUCH) {
    P=P_AVDD; Good=Same(V,Bytes,"tsp_avdd");
  } else if (Same(Name,NameBytes,"sec,regulator_boot_on") && K==TOUCH) {
    P=P_BOOTON; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"sec,firmware_name") && K==TOUCH) {
    P=P_FIRMWARE; Good=Same(V,Bytes,"tsp_sec/y771_d2.bin");
  } else if (Same(Name,NameBytes,"samsung,check-transdone-int") && K==HSI) {
    P=P_CHECKDONE; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"samsung,scl-clk-stretching") && K==HSI) {
    P=P_STRETCH; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"samsung,usi-i2c-v2") && K==HSI) {
    P=P_USIV2; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"samsung,reset-before-trans") && K==HSI) {
    P=P_RESET; Good=Bytes==0;
  } else if (Same(Name,NameBytes,"samsung,stop-after-trans") && K==HSI) {
    P=P_STOP; Good=Bytes==0;
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
  UINT64 Identity=PB(P_COMPAT)|PB(P_REG), Pins=PB(P_PINS)|PB(P_FUNC)|PB(P_PUD);
  if (K==ROOT) return PB(P_COMPAT)|PB(P_ADDR)|PB(P_SIZE)|PB(P_INTPARENT);
  if (K==HSI) return Identity|PB(P_STATUS)|PB(P_ADDR)|PB(P_SIZE)|PB(P_INTS)|
    PB(P_PINNAMES)|PB(P_PIN0)|PB(P_CLOCKS)|PB(P_CLOCKNAMES)|PB(P_HZ)|
    PB(P_SCL)|PB(P_SDA)|PB(P_CHECKDONE)|PB(P_STRETCH)|PB(P_USIV2)|PB(P_RESET)|PB(P_STOP);
  if (K==TOUCH) return Identity|PB(P_PINNAMES)|PB(P_PIN0)|PB(P_PIN1)|PB(P_IRQGPIO)|
    PB(P_IRQTYPE)|PB(P_COORDS)|PB(P_DVDD)|PB(P_AVDD)|PB(P_BOOTON)|PB(P_FIRMWARE);
  if (K==USI) return Identity|PB(P_STATUS)|PB(P_USIMODE);
  if (K==USI_ALT) return Identity|PB(P_STATUS);
  if (K==ALIVE || K==PERIC) return Identity;
  if (K==CLOCK) return Identity|PB(P_CLOCKS);
  if (K==GPA1 || K==GPP1) return PB(P_GPIO)|PB(P_GPIOCELLS)|PB(P_INTCTL)|PB(P_INTCELLS)|
    (K==GPA1 ? PB(P_INTPARENT)|PB(P_INTS) : 0);
  if (K==BUS_PIN || K==IRQ_PIN) return Pins|PB(P_DRV);
  if (K==OFF_PIN) return Pins;
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
      if (S.RootParent!=S.GpaParent || S.ClockRefs[0]!=S.Handles[CLOCK] ||
          S.ClockRefs[1]!=S.Handles[CLOCK] || S.BusRef!=S.Handles[BUS_PIN] ||
          S.OnRef!=S.Handles[IRQ_PIN] || S.OffRef!=S.Handles[OFF_PIN] ||
          S.SclRef!=S.Handles[GPP1] || S.SdaRef!=S.Handles[GPP1] ||
          S.IrqRef!=S.Handles[GPA1]) return 8;
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
          if (Same(D+Start,NBytes,"hsi2c@104B0000")) N->Kind=HSI;
          else if (Same(D+Start,NBytes,"usi@1042101C")) N->Kind=USI;
          else if (Same(D+Start,NBytes,"usi@10421020")) N->Kind=USI_ALT;
          else if (Same(D+Start,NBytes,"pinctrl@15850000")) N->Kind=ALIVE;
          else if (Same(D+Start,NBytes,"pinctrl@10430000")) N->Kind=PERIC;
          else if (Same(D+Start,NBytes,"clock-controller@0x1a240000")) N->Kind=CLOCK;
        } else if (Depth==2) {
          if (Parent==HSI && Same(D+Start,NBytes,"touchscreen@48")) N->Kind=TOUCH;
          if (Parent==ALIVE && Same(D+Start,NBytes,"gpa1")) N->Kind=GPA1;
          if (Parent==ALIVE && Same(D+Start,NBytes,"attn-irq")) N->Kind=IRQ_PIN;
          if (Parent==ALIVE && Same(D+Start,NBytes,"attn-input")) N->Kind=OFF_PIN;
          if (Parent==PERIC && Same(D+Start,NBytes,"gpp1")) N->Kind=GPP1;
          if (Parent==PERIC && Same(D+Start,NBytes,"hsi2c10-bus")) N->Kind=BUS_PIN;
        }
      }
      if (N->Kind && ++S.Counts[N->Kind]>1) return 4;
      Depth++; continue;
    }
    if (Token==2) {
      if (!Depth) return 3;
      NODE *N=&Nodes[Depth-1]; UINT64 Need=Required(N->Kind);
      if ((N->Seen&Need)!=Need || (N->Kind>=TOUCH && N->Kind!=ALIVE &&
          N->Kind!=PERIC && N->Child)) return 6;
      if (N->HavePhandle && N->HaveLinuxPhandle && N->Phandle!=N->LinuxPhandle) return 5;
      UINT32 Handle=N->HavePhandle ? N->Phandle : N->LinuxPhandle;
      if (Handle) {
        if (S.UsedCount>=PHANDLE_MAX) return 3;
        for (UINTN I=0; I<S.UsedCount; I++) if (S.Used[I]==Handle) return 4;
        S.Used[S.UsedCount++]=Handle;
      }
      if (N->Kind==CLOCK || N->Kind>=GPA1) {
        if (!Handle) return 6;
        S.Handles[N->Kind]=Handle;
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
    UINT64 Error=Property(&S,&Nodes[Depth-1],D+Name,NameBytes+1,D+Cursor,Length);
    if (Error) return Error;
    Cursor=Next;
  }
  return 3;
}

BOOLEAN EFIAPI N976nAdmitTouch (
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile, N976N_TOUCH_ADMISSION *Out)
{
  if (!Out || (UINTN)Out>MAX_UINTN-sizeof(*Out) ||
      (Dtb && DtbBytes && (UINTN)Dtb<=MAX_UINTN-DtbBytes &&
       Overlap((UINTN)Dtb,DtbBytes,(UINTN)Out,sizeof(*Out)))) return FALSE;
  ZeroMem(Out,sizeof(*Out));
  Out->Magic=N976N_TOUCH_ADMISSION_MAGIC; Out->Version=1; Out->Size=sizeof(*Out); Out->Profile=Profile;
  Out->Reason=Profile>N976N_PLATFORM_PROFILE_QEMU ? 7 : Parse(Dtb,DtbBytes);
  if (Out->Reason) return FALSE;
  Out->Hsi2c=N976N_TOUCH_HSI2C; Out->Hsi2cBytes=0x1000;
  Out->GpioAlive=N976N_TOUCH_GPIO_ALIVE; Out->GpioAliveBytes=0x1000;
  Out->GpioPeric0=N976N_TOUCH_GPIO_PERIC0; Out->GpioPeric0Bytes=0x1000;
  Out->SysregUsi=N976N_TOUCH_SYSREG_USI; Out->SysregUsiBytes=4;
  Out->CmuPeric0=N976N_TOUCH_CMU_PERIC0; Out->CmuPeric0Bytes=0x8000;
  Out->I2cAddress=0x48; Out->I2cGsiv=420; Out->ClockHz=200000000;
  Out->ClockIds[0]=0x1FD; Out->ClockIds[1]=0x1ED;
  Out->IrqPin=0; Out->IrqGsiv=45; Out->IrqFlags=0x2008;
  Out->SclPin=4; Out->SdaPin=5; Out->PinFunction=2;
  Out->MaxX=4096; Out->MaxY=4096; Out->EventBytes=16; Out->BootOn=1;
  Out->Checks=N976N_TOUCH_ADMISSION_CHECKS; Out->Admitted=1;
  return TRUE;
}
