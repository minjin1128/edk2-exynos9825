/* SPDX-License-Identifier: MIT
 * Runtime DT admission for Samsung UART_DBG and the MAX77705 HSI2C45 route.
 * Upstream FdtLib performs traversal; no hardware is touched here. Pin groups
 * and clock providers are resolved, never assumed from fixed phandle numbers.
 */
#include <N976nBootAdmission.h>
#include <N976nBatteryAdmission.h>
#include <N976nChargeObservation.h>
#include <N976nAdcPreflight.h>
#include <N976nThermalAdmission.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FdtLib.h>
#include "RootCompatible.h"

/* Stack-owned only inside N976nAdmitBootDevices. The unchanged full walks
 * remain the fallback. Positive entries cannot turn a failed check into a hit.
 * No MMIO, callbacks, DT mutation or external publication occurs in the batch. */
#define BOOT_HANDLE_CACHE_SIZE 8
typedef struct {
  CONST VOID *Dtb;
  UINT64 Bytes, Profile;
  BOOLEAN LayoutValid, UartValid;
  UINTN HandleCount;
  struct { INT32 Target; UINT32 Handle; } Handles[BOOT_HANDLE_CACHE_SIZE];
  N976N_UART_ADMISSION Uart;
} BOOT_CONTEXT;

STATIC UINT32 Be32 (CONST VOID *P)
{
  CONST UINT8 *B=P;
  return ((UINT32)B[0]<<24)|((UINT32)B[1]<<16)|((UINT32)B[2]<<8)|B[3];
}
STATIC UINTN TextBytes (CONST CHAR8 *S)
{ UINTN N=0; while (S[N]) N++; return N; }
STATIC BOOLEAN Text (CONST VOID *P, INT32 N, CONST CHAR8 *S)
{ UINTN B=TextBytes(S)+1; return P!=NULL && N==(INT32)B && !CompareMem(P,S,B); }
STATIC BOOLEAN Overlap (UINT64 A, UINT64 N, UINT64 B, UINT64 M)
{ return N && M && A<B+M && B<A+N; }

/* Get one property. Unlike a first-match lookup, duplicate critical fields
 * cannot silently choose one of two incompatible resource descriptions. */
STATIC CONST VOID *Prop (CONST VOID *D, INT32 Node, CONST CHAR8 *Name, INT32 *Len)
{
  CONST VOID *Found=NULL;
  INT32 At, N, L;
  if (Node<0) { *Len=-FDT_ERR_BADOFFSET; return NULL; }
  At=FdtFirstPropertyOffset(D,Node); *Len=-FDT_ERR_NOTFOUND;
  while (At>=0) {
    CONST FDT_PROPERTY *P=FdtGetPropertyByOffset(D,At,&N);
    CONST CHAR8 *S;
    if (P==NULL || N<0) { *Len=-FDT_ERR_BADSTRUCTURE; return NULL; }
    S=FdtGetString(D,(INT32)Be32(&P->NameOffset),&L);
    if (S==NULL || L<0) { *Len=-FDT_ERR_BADSTRUCTURE; return NULL; }
    if (Text(S,L+1,Name)) {
      if (Found!=NULL) { *Len=-FDT_ERR_EXISTS; return NULL; }
      Found=P->Data; *Len=N;
    }
    At=FdtNextPropertyOffset(D,At);
  }
  if (At!=-FDT_ERR_NOTFOUND) { *Len=At; return NULL; }
  return Found;
}
STATIC BOOLEAN String (CONST VOID *D, INT32 Node, CONST CHAR8 *Name, CONST CHAR8 *Value)
{ INT32 N; CONST VOID *P=Prop(D,Node,Name,&N); return Text(P,N,Value); }
STATIC BOOLEAN Cells (CONST VOID *D, INT32 Node, CONST CHAR8 *Name,
                      CONST UINT32 *Values, UINTN Count)
{
  INT32 N; CONST UINT8 *P=Prop(D,Node,Name,&N);
  if (P==NULL || N!=(INT32)(Count*4)) return FALSE;
  for (UINTN I=0; I<Count; I++) if (Be32(P+I*4)!=Values[I]) return FALSE;
  return TRUE;
}
STATIC BOOLEAN Cell (CONST VOID *D, INT32 Node, CONST CHAR8 *Name, UINT32 Value)
{ return Cells(D,Node,Name,&Value,1); }
STATIC BOOLEAN Flag (CONST VOID *D, INT32 Node, CONST CHAR8 *Name, BOOLEAN Required)
{
  INT32 N; CONST VOID *P=Prop(D,Node,Name,&N);
  return Required ? P!=NULL && N==0 : P==NULL && N==-FDT_ERR_NOTFOUND;
}
STATIC BOOLEAN Enabled (CONST VOID *D, INT32 Node)
{
  INT32 N; CONST VOID *P=Prop(D,Node,"status",&N);
  return (P==NULL && N==-FDT_ERR_NOTFOUND) || Text(P,N,"okay") || Text(P,N,"ok");
}
STATIC BOOLEAN Reg (CONST VOID *D, INT32 Node, UINT32 Base, UINT32 Bytes)
{ CONST UINT32 V[]={0,Base,Bytes}; return Cells(D,Node,"reg",V,3); }

/* All resources in this DT are direct children, apart from fixed pin groups
 * and the I2C device. Requiring a unique exact child avoids alias/path-prefix
 * matching and does not rely on non-contractual labels or phandle values. */
STATIC INT32 Child (CONST VOID *D, INT32 Parent, CONST CHAR8 *Name)
{
  INT32 Found=-1, At, N;
  if (Parent<0) return -1;
  for (At=FdtFirstSubnode(D,Parent); At>=0; At=FdtNextSubnode(D,At)) {
    CONST CHAR8 *S=FdtGetName(D,At,&N);
    if (Text(S,N+1,Name)) {
      if (Found>=0) return -1;
      Found=At;
    }
  }
  return At==-FDT_ERR_NOTFOUND ? Found : -1;
}
STATIC BOOLEAN UniqueHandleFull (CONST VOID *D, INT32 Target, UINT32 Handle)
{
  INT32 At=-1, Depth=-1, N, Count=0;
  if (Handle==0 || Handle==MAX_UINT32 || Target<0) return FALSE;
  while ((At=FdtNextNode(D,At,&Depth))>=0 && Depth>=0) {
    CONST UINT8 *P=Prop(D,At,"phandle",&N);
    UINT32 Value=0, Legacy=0;
    if (P!=NULL) { if (N!=4) return FALSE; Value=Be32(P); }
    else if (N!=-FDT_ERR_NOTFOUND) return FALSE;
    P=Prop(D,At,"linux,phandle",&N);
    if (P!=NULL) { if (N!=4) return FALSE; Legacy=Be32(P); }
    else if (N!=-FDT_ERR_NOTFOUND) return FALSE;
    if (Value==Handle || Legacy==Handle) {
      if (At!=Target || (Value && Legacy && Value!=Legacy)) return FALSE;
      Count++;
    }
  }
  return Depth<0 && Count==1;
}
STATIC BOOLEAN UniqueHandle (BOOT_CONTEXT *Context, CONST VOID *D,
                             INT32 Target, UINT32 Handle)
{
  if (Context!=NULL && Context->Dtb==D) {
    for (UINTN I=0; I<Context->HandleCount; I++)
      if (Context->Handles[I].Target==Target && Context->Handles[I].Handle==Handle)
        return TRUE;
  }
  if (!UniqueHandleFull(D,Target,Handle)) return FALSE;
  if (Context!=NULL && Context->Dtb==D && Context->HandleCount<BOOT_HANDLE_CACHE_SIZE) {
    Context->Handles[Context->HandleCount].Target=Target;
    Context->Handles[Context->HandleCount].Handle=Handle;
    Context->HandleCount++;
  }
  return TRUE;
}
STATIC BOOLEAN Ref (BOOT_CONTEXT *Context, CONST VOID *D, INT32 Node, CONST CHAR8 *Name, INT32 Target)
{
  INT32 N; CONST UINT8 *P=Prop(D,Node,Name,&N);
  return P!=NULL && N==4 && Be32(P)!=0 && Be32(P)!=MAX_UINT32 &&
         FdtNodeOffsetByPhandle(D,Be32(P))==Target && UniqueHandle(Context,D,Target,Be32(P));
}
STATIC BOOLEAN Clocks (BOOT_CONTEXT *Context, CONST VOID *D, INT32 Node, INT32 Provider,
                       UINT32 First, UINT32 Second)
{
  INT32 N; CONST UINT8 *P=Prop(D,Node,"clocks",&N);
  return P!=NULL && N==16 && Be32(P+4)==First && Be32(P+12)==Second &&
         Be32(P)!=0 && Be32(P)!=MAX_UINT32 && Be32(P+8)==Be32(P) &&
         FdtNodeOffsetByPhandle(D,Be32(P))==Provider && UniqueHandle(Context,D,Provider,Be32(P));
}

/* Header is checked against the caller-owned span before FdtLib sees it.
 * FdtNextNode supplies a bounded tree walk and rejects truncated tokens.
 * Reserve entries and property names also pass upstream bounds checks. */
STATIC BOOLEAN LayoutFull (CONST VOID *D, UINT64 Bytes)
{
  CONST UINT8 *B=D;
  UINT32 S, SN, T, TN, R;
  INT32 At=-1, Depth=-1, NameLen, PAt, Len;
  if (Bytes<40 || Bytes>0x100000 || ((UINTN)D&7)!=0 || Be32(B+4)!=Bytes ||
      Be32(B+20)!=17 || FdtCheckHeader(D)!=0) return FALSE;
  S=Be32(B+8); T=Be32(B+12); R=Be32(B+16); TN=Be32(B+32); SN=Be32(B+36);
  if ((S&3)!=0 || (R&7)!=0 || S<40 || T<40 || R<40 || SN<12 ||
      S>Bytes || SN>Bytes-S || T>Bytes || TN>Bytes-T ||
      Overlap(S,SN,T,TN) || FdtGetNumberOfReserveMapEntries(D)<0) return FALSE;
  /* Parsing its bounded terminator is upstream-owned; reject map/block alias. */
  INT32 Count=FdtGetNumberOfReserveMapEntries(D);
  UINT64 RBytes=((UINT64)Count+1)*16;
  if (R>Bytes || RBytes>Bytes-R || Overlap(R,RBytes,S,SN) || Overlap(R,RBytes,T,TN))
    return FALSE;
  for (UINT64 Budget=0; Budget<Bytes/4; Budget++) {
    At=FdtNextNode(D,At,&Depth);
    if (At<0) return FALSE;
    if (Depth<0)
      return (UINT32)At<=SN-4 && Be32(B+S+(UINT32)At)==9;
    CONST CHAR8 *Name=FdtGetName(D,At,&NameLen);
    if (Name==NULL || NameLen<0 || (Depth==0 && (At!=0 || NameLen!=0))) return FALSE;
    PAt=FdtFirstPropertyOffset(D,At);
    while (PAt>=0) {
      CONST FDT_PROPERTY *P=FdtGetPropertyByOffset(D,PAt,&Len);
      if (P==NULL || Len<0 || FdtGetString(D,(INT32)Be32(&P->NameOffset),&Len)==NULL)
        return FALSE;
      PAt=FdtNextPropertyOffset(D,PAt);
    }
    if (PAt!=-FDT_ERR_NOTFOUND) return FALSE;
  }
  return FALSE;
}

STATIC BOOLEAN Layout (BOOT_CONTEXT *Context, CONST VOID *D, UINT64 Bytes)
{
  if (Context!=NULL && Context->Dtb==D && Context->Bytes==Bytes && Context->LayoutValid)
    return TRUE;
  if (!LayoutFull(D,Bytes)) return FALSE;
  if (Context!=NULL && Context->Dtb==D && Context->Bytes==Bytes) Context->LayoutValid=TRUE;
  return TRUE;
}

STATIC BOOLEAN AdmitUart (BOOT_CONTEXT *Context,

  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile, N976N_UART_ADMISSION *Out)
{
  INT32 U, H, G, C, S, K, UP, HP, M, N;
  CONST VOID *P;
  STATIC CONST CHAR8 UPins[]="gpp3-2\0gpp3-3";
  STATIC CONST CHAR8 HPins[]="gpm12-0\0gpm13-0";
  STATIC CONST CHAR8 UClockNames[]="gate_uart_clk0\0ipclk_uart0";
  STATIC CONST CHAR8 HClockNames[]="ipclk_hsi2c\0gate_hsi2c_clk";
  if (Out==NULL || (UINTN)Out>MAX_UINTN-sizeof(*Out) ||
      (Dtb!=NULL && (UINTN)Dtb<=MAX_UINTN-DtbBytes &&
       Overlap((UINTN)Dtb,DtbBytes,(UINTN)Out,sizeof(*Out)))) return FALSE;
  ZeroMem(Out,sizeof(*Out)); Out->Magic=N976N_UART_ADMISSION_MAGIC;
  Out->Version=1; Out->Size=sizeof(*Out); Out->Profile=Profile; Out->Reason=1;
  if (Dtb==NULL || DtbBytes>MAX_UINTN || (UINTN)Dtb>MAX_UINTN-DtbBytes ||
      Profile>N976N_PLATFORM_PROFILE_QEMU || !Layout(Context,Dtb,DtbBytes)) return FALSE;
  if (Context!=NULL && Context->Dtb==Dtb && Context->Bytes==DtbBytes &&
      Context->Profile==Profile && Context->UartValid) {
    CopyMem(Out,&Context->Uart,sizeof(*Out)); return TRUE;
  }
  Out->Reason=2;
  P=Prop(Dtb,0,"compatible",&N);
  if (P==NULL || N<0 || !N976nRootCompatible(P,(UINTN)N) ||
      !Cell(Dtb,0,"#address-cells",2) || !Cell(Dtb,0,"#size-cells",1)) return FALSE;
  U=Child(Dtb,0,"uart@10440000"); H=Child(Dtb,0,"hsi2c@15D60000");
  G=Child(Dtb,0,"pinctrl@10430000"); C=Child(Dtb,0,"pinctrl@15C30000");
  S=Child(Dtb,0,"usi@15C22030"); K=Child(Dtb,0,"clock-controller@0x1a240000");
  Out->Reason=3;
  if (U<0 || H<0 || G<0 || C<0 || S<0 || K<0 ||
      !Enabled(Dtb,U) || !Enabled(Dtb,H) || !Enabled(Dtb,G) || !Enabled(Dtb,C) ||
      !Enabled(Dtb,S) || !Enabled(Dtb,K) ||
      !String(Dtb,U,"compatible","samsung,exynos-uart") || !Reg(Dtb,U,N976N_UART_BASE,N976N_UART_BYTES) ||
      !String(Dtb,H,"compatible","samsung,exynos5-hsi2c") || !Reg(Dtb,H,N976N_UART_HSI2C,0x1000) ||
      !String(Dtb,G,"compatible","samsung,exynos9820-pinctrl") || !Reg(Dtb,G,N976N_UART_GPIO_PERIC0,0x1000) ||
      !String(Dtb,C,"compatible","samsung,exynos9820-pinctrl") || !Reg(Dtb,C,N976N_UART_GPIO_CMGP,0x1000) ||
      !String(Dtb,S,"compatible","samsung,exynos-usi-v2") || !Reg(Dtb,S,N976N_UART_SYSREG_CMGP,4) ||
      !String(Dtb,S,"usi_v2_mode","i2c")) return FALSE;
  /* Samsung describes alternate personalities at the same USI address.
   * Their DT disabled state is necessary; live idle ownership is separate. */
  if (!String(Dtb,Child(Dtb,0,"spi@15D60000"),"status","disabled") ||
      !String(Dtb,Child(Dtb,0,"uart@15D60000"),"status","disabled") ||
      !String(Dtb,Child(Dtb,0,"usi@15C22034"),"status","disabled")) return FALSE;
  Out->Reason=4;
  if (!String(Dtb,K,"compatible","samsung,exynos9820-clock") ||
      !Reg(Dtb,K,N976N_UART_CMU_TOP,N976N_UART_CMU_BYTES) || !Cell(Dtb,K,"#clock-cells",1) ||
      !Clocks(Context,Dtb,U,K,0x1E5,0x201) || !Clocks(Context,Dtb,H,K,0x82,0x7D)) return FALSE;
  P=Prop(Dtb,U,"clock-names",&N);
  if (P==NULL || N!=sizeof(UClockNames) || CompareMem(P,UClockNames,sizeof(UClockNames))) return FALSE;
  P=Prop(Dtb,H,"clock-names",&N);
  if (P==NULL || N!=sizeof(HClockNames) || CompareMem(P,HClockNames,sizeof(HClockNames))) return FALSE;
  Out->Reason=5;
  UP=Child(Dtb,G,"uart0-bus"); HP=Child(Dtb,C,"hsi2c45-bus");
  if (UP<0 || HP<0 || !String(Dtb,U,"pinctrl-names","default") ||
      !String(Dtb,H,"pinctrl-names","default") || !Ref(Context,Dtb,U,"pinctrl-0",UP) ||
      !Ref(Context,Dtb,H,"pinctrl-0",HP) || !Cell(Dtb,UP,"samsung,pin-function",3) ||
      !Cell(Dtb,HP,"samsung,pin-function",2) || !Cell(Dtb,UP,"samsung,pin-pud",0) ||
      !Cell(Dtb,HP,"samsung,pin-pud",0) || !Cell(Dtb,HP,"samsung,pin-drv",0)) return FALSE;
  P=Prop(Dtb,UP,"samsung,pins",&N);
  if (P==NULL || N!=sizeof(UPins) || CompareMem(P,UPins,sizeof(UPins))) return FALSE;
  P=Prop(Dtb,HP,"samsung,pins",&N);
  if (P==NULL || N!=sizeof(HPins) || CompareMem(P,HPins,sizeof(HPins))) return FALSE;
  Out->Reason=6;
  M=Child(Dtb,H,"max77705@66");
  if (!Cell(Dtb,H,"#address-cells",1) || !Cell(Dtb,H,"#size-cells",0) || M<0 ||
      !Enabled(Dtb,M) || !String(Dtb,M,"compatible","maxim,max77705") ||
      !Cell(Dtb,M,"reg",0x66) || !Flag(Dtb,H,"samsung,check-transdone-int",TRUE) ||
      !Flag(Dtb,H,"samsung,scl-clk-stretching",TRUE) || !Flag(Dtb,H,"samsung,usi-i2c-v2",TRUE) ||
      !Flag(Dtb,H,"samsung,stop-after-trans",FALSE)) return FALSE;
  Out->Uart=N976N_UART_BASE; Out->UartBytes=N976N_UART_BYTES;
  Out->GpioPeric0=N976N_UART_GPIO_PERIC0; Out->GpioPeric0Bytes=0x1000;
  Out->Hsi2c=N976N_UART_HSI2C; Out->Hsi2cBytes=0x1000;
  Out->GpioCmgp=N976N_UART_GPIO_CMGP; Out->GpioCmgpBytes=0x1000;
  Out->SysregCmgp=N976N_UART_SYSREG_CMGP; Out->SysregCmgpBytes=4;
  Out->CmuPeric0=N976N_UART_CMU_PERIC0; Out->CmuPeric0Bytes=N976N_UART_CMU_BYTES;
  Out->CmuCmgp=N976N_UART_CMU_CMGP; Out->CmuCmgpBytes=N976N_UART_CMU_BYTES;
  Out->CmuAlive=N976N_UART_CMU_ALIVE; Out->CmuAliveBytes=N976N_UART_CMU_BYTES;
  Out->CmuTop=N976N_UART_CMU_TOP; Out->CmuTopBytes=N976N_UART_CMU_BYTES;
  Out->UartClockIds[0]=0x1E5; Out->UartClockIds[1]=0x201;
  Out->HsiClockIds[0]=0x82; Out->HsiClockIds[1]=0x7D;
  Out->Reason=0; Out->Checks=N976N_UART_ADMISSION_CHECKS; Out->Admitted=1;
  if (Context!=NULL && Context->Dtb==Dtb && Context->Bytes==DtbBytes && Context->Profile==Profile) {
    CopyMem(&Context->Uart,Out,sizeof(*Out)); Context->UartValid=TRUE;
  }
  return TRUE;
}

/* The gauge's scale is board-specific: Samsung d2x KOR DTs contain both 2 and
 * 5. This optional calibration does not replace the independent HSI45/MFD
 * admission, and a missing scale cannot turn into an assumed value of 5.
 * Device addresses36/69 are created by the admitted MAX77705 MFD driver;
 * they are not fabricated child nodes in this DT.
 */
STATIC BOOLEAN AdmitBattery (BOOT_CONTEXT *Context,
  CONST VOID *Dtb, UINT64 DtbBytes, UINT64 Profile,
  N976N_BATTERY_ADMISSION *Out
  )
{
  N976N_UART_ADMISSION Bus;
  INT32 At, Node, N, Matches=0;
  CONST UINT8 *P;
  UINT32 Factor;
  if (Out==NULL || ((UINTN)Out&7)!=0 || (UINTN)Out>MAX_UINTN-sizeof(*Out)) return FALSE;
  if (Dtb!=NULL && (DtbBytes>MAX_UINTN || (UINTN)Dtb>MAX_UINTN-DtbBytes ||
      Overlap((UINTN)Dtb,DtbBytes,(UINTN)Out,sizeof(*Out)))) return FALSE;
  ZeroMem(Out,sizeof(*Out));
  Out->Magic=N976N_BATTERY_ADMISSION_MAGIC;
  Out->Version=N976N_BATTERY_ADMISSION_VERSION;
  Out->Size=sizeof(*Out); Out->Profile=Profile; Out->Reason=1;
  if (Profile!=N976N_PLATFORM_PROFILE_PHONE) return FALSE;
  /* The actual production parser independently validates layout, exact root
   * identity, clocks/pins/USI alias exclusion and max77705@66. No caller's
   * claimed UART HOB is trusted as a replacement for these runtime DT facts.
   */
  Out->Reason=2;
  if (!AdmitUart(Context,Dtb,DtbBytes,Profile,&Bus)) return FALSE;
  if (Bus.Magic!=N976N_UART_ADMISSION_MAGIC || Bus.Version!=1 ||
      Bus.Size!=sizeof(Bus) || Bus.Profile!=Profile || Bus.Admitted!=1 ||
      Bus.Reason!=0 || Bus.Checks!=N976N_UART_ADMISSION_CHECKS ||
      Bus.Hsi2c!=N976N_UART_HSI2C || Bus.Hsi2cBytes!=0x1000) return FALSE;

  /* Layout is already validated by N976nAdmitUart. Count exact root names to
   * distinguish an absent optional node from ambiguous duplicates. A same
   * name below another node or a unit-address suffix is not this binding.
   */
  for (At=FdtFirstSubnode(Dtb,0); At>=0; At=FdtNextSubnode(Dtb,At)) {
    CONST CHAR8 *Name=FdtGetName(Dtb,At,&N);
    if (Text(Name,N+1,"max77705-fuelgauge")) ++Matches;
  }
  if (At!=-FDT_ERR_NOTFOUND) {
    Out->FactorStatus=N976N_BATTERY_FACTOR_MALFORMED;
  } else if (Matches>1) {
    Out->FactorStatus=N976N_BATTERY_FACTOR_AMBIGUOUS;
  } else if (Matches==0) {
    Out->FactorStatus=N976N_BATTERY_FACTOR_MISSING;
  } else {
    Node=Child(Dtb,0,"max77705-fuelgauge");
    if (Node<0) {
      Out->FactorStatus=N976N_BATTERY_FACTOR_MALFORMED;
    } else if (!Enabled(Dtb,Node)) {
      P=Prop(Dtb,Node,"status",&N);
      Out->FactorStatus=Text(P,N,"disabled") ? N976N_BATTERY_FACTOR_DISABLED :
                                             N976N_BATTERY_FACTOR_MALFORMED;
    } else {
      P=Prop(Dtb,Node,"fuelgauge,fg_resistor",&N);
      if (P==NULL) {
        Out->FactorStatus=N==-FDT_ERR_NOTFOUND ? N976N_BATTERY_FACTOR_MISSING :
                                               N976N_BATTERY_FACTOR_MALFORMED;
      } else if (N!=4) {
        Out->FactorStatus=N976N_BATTERY_FACTOR_MALFORMED;
      } else {
        Factor=Be32(P);
        if (Factor==2 || Factor==5) {
          Out->Factor=Factor;
          Out->FactorStatus=N976N_BATTERY_FACTOR_KNOWN;
        } else Out->FactorStatus=N976N_BATTERY_FACTOR_UNSUPPORTED;
      }
    }
  }
  Out->Reason=0; Out->Checks=N976N_BATTERY_ADMISSION_CHECKS; Out->Admitted=1;
  return TRUE;
}

STATIC BOOLEAN AdmitChargeObservation(BOOT_CONTEXT *Context,CONST VOID *D,UINT64 Bytes,
 UINT64 Profile,N976N_CHARGE_ADMISSION *Out)
{
 N976N_UART_ADMISSION Bus;INT32 H,P,At,N;UINT32 Mfd=0,Pca=0;
 if(!Out||((UINTN)Out&7)||(UINTN)Out>MAX_UINTN-sizeof(*Out))return FALSE;
 if(D&&(Bytes>MAX_UINTN||(UINTN)D>MAX_UINTN-Bytes||
   Overlap((UINTN)D,Bytes,(UINTN)Out,sizeof(*Out))))return FALSE;
 ZeroMem(Out,sizeof(*Out));Out->Magic=N976N_CHARGE_ADMISSION_MAGIC;
 Out->Version=1;Out->Size=sizeof(*Out);Out->Profile=Profile;Out->Reason=1;
 if(Profile!=N976N_PLATFORM_PROFILE_PHONE)return FALSE;
 Out->Reason=2;if(!AdmitUart(Context,D,Bytes,Profile,&Bus))return FALSE;
 H=Child(D,0,"hsi2c@15D60000");P=Child(D,H,"pca9468@57");Out->Reason=3;
 if(H<0||P<0||!Cell(D,H,"#address-cells",1)||!Cell(D,H,"#size-cells",0)||
   !Enabled(D,P)||!Cell(D,P,"reg",0x57)||!String(D,P,"compatible","nxp,pca9468"))return FALSE;
 Out->Reason=4;
 for(At=FdtFirstSubnode(D,H);At>=0;At=FdtNextSubnode(D,At)){
  CONST UINT8 *R;UINT32 Address;
  if(!Enabled(D,At)){if(String(D,At,"status","disabled"))continue;return FALSE;}
  R=Prop(D,At,"reg",&N);if(!R||N!=4)return FALSE;Address=Be32(R);
  if(Address==0x66)Mfd++;
  if(Address==0x57)Pca++;
  /* Same-adapter MFD-derived endpoints in pinned Samsung max77705.c.
   * An enabled explicit sibling here would create ambiguous ownership. */
  if(Address==0x25||Address==0x36||Address==0x69)return FALSE;
 }
 if(At!=-FDT_ERR_NOTFOUND||Mfd!=1||Pca!=1)return FALSE;
 Out->Hsi=0x15D60000;Out->Mfd=0x66;Out->Ccic=0x25;Out->Pca=0x57;Out->ReadPlan=1;
 Out->Checks=N976N_CHARGE_ADMISSION_CHECKS;Out->Admitted=1;Out->Reason=0;return TRUE;
}

/* Separate from the unchanged charger read-plan. No ADC MMIO is authorized. */
STATIC BOOLEAN AdmitAdcPreflight(BOOT_CONTEXT *Context,CONST VOID *D,UINT64 Bytes,
 UINT64 Profile,N976N_ADC_ADMISSION *Out)
{
 N976N_UART_ADMISSION Bus;INT32 A,K,G,N;CONST UINT8 *C;
 CONST UINT32 Irq[]={0,84,0};
 if(!Out||((UINTN)Out&7)||(UINTN)Out>MAX_UINTN-sizeof(*Out))return FALSE;
 if(D&&(Bytes>MAX_UINTN||(UINTN)D>MAX_UINTN-Bytes||
   Overlap((UINTN)D,Bytes,(UINTN)Out,sizeof(*Out))))return FALSE;
 ZeroMem(Out,sizeof(*Out));Out->Magic=N976N_ADC_ADMISSION_MAGIC;
 Out->Version=1;Out->Size=sizeof(*Out);Out->Profile=Profile;Out->Reason=1;
 if(Profile!=N976N_PLATFORM_PROFILE_PHONE)return FALSE;
 Out->Reason=2;if(!AdmitUart(Context,D,Bytes,Profile,&Bus))return FALSE;
 A=Child(D,0,"adc@15C40000");K=Child(D,0,"clock-controller@0x1a240000");
 G=Child(D,0,"interrupt-controller@10100000");Out->Reason=3;
 if(A<0||K<0||G<0||!Enabled(D,A)||!String(D,A,"compatible","samsung,exynos-adc-v3")||
   !Reg(D,A,0x15C40000,0x100)||!Cell(D,A,"#io-channel-cells",1)||
   !Cells(D,A,"interrupts",Irq,3)||!Flag(D,A,"interrupt-parent",FALSE)||
   !Flag(D,A,"interrupts-extended",FALSE)||!Ref(Context,D,0,"interrupt-parent",G)||
   !Flag(D,A,"sysreg",FALSE)||!Flag(D,A,"samsung,adc-phy-control",FALSE)||
   !String(D,A,"clock-names","gate_adcif"))return FALSE;
 Out->Reason=4;C=Prop(D,A,"clocks",&N);
 if(!C||N!=8||Be32(C+4)!=110||FdtNodeOffsetByPhandle(D,Be32(C))!=K||
   !UniqueHandle(Context,D,K,Be32(C)))return FALSE;
 Out->Adc=0x15C40000;Out->AdcBytes=0x100;Out->Cmu=0x15C00000;
 Out->Irq=116;Out->Clock=110;Out->ReadPlan=1;
 Out->Checks=7;Out->Admitted=1;Out->Reason=0;return TRUE;
}

STATIC BOOLEAN AdmitThermal(BOOT_CONTEXT *Context,CONST VOID *D,UINT64 Bytes,UINT64 Profile,
 CONST N976N_ADC_ADMISSION *Identity,N976N_THERMAL_ADMISSION *Out)
{
 INT32 B,A,N,NamesBytes,At;CONST UINT8 *Refs,*Names,*Raw;
 UINT32 Handle,Seen=0,Index=0;NCA_THERMAL_CONTRACT *P;
 STATIC CONST CHAR8 NamesWanted[3][13]={"adc-temp","adc-chg-temp","adc-usb-temp"};
 STATIC CONST CHAR8 Source[3][27]={"battery,thermal_source","battery,chg_thermal_source","battery,usb_thermal_source"};
 STATIC CONST CHAR8 Check[3][28]={"battery,temp_check_type","battery,chg_temp_check_type","battery,usb_temp_check_type"};
 STATIC CONST CHAR8 Adc[3][27]={"battery,temp_table_adc","battery,chg_temp_table_adc","battery,usb_temp_table_adc"};
 STATIC CONST CHAR8 Temp[3][28]={"battery,temp_table_data","battery,chg_temp_table_data","battery,usb_temp_table_data"};
 if(!Out||((UINTN)Out&7)||(UINTN)Out>MAX_UINTN-sizeof(*Out))return FALSE;
 if(D&&(Bytes>MAX_UINTN||(UINTN)D>MAX_UINTN-Bytes||Overlap((UINTN)D,Bytes,(UINTN)Out,sizeof(*Out))))return FALSE;
 if(!Identity||((UINTN)Identity&7)||(UINTN)Identity>MAX_UINTN-sizeof(*Identity)||
  Overlap((UINTN)Identity,sizeof(*Identity),(UINTN)Out,sizeof(*Out)))return FALSE;
 ZeroMem(Out,sizeof(*Out));Out->Magic=N976N_THERMAL_ADMISSION_MAGIC;
 Out->Version=1;Out->Size=sizeof(*Out);Out->Profile=Profile;Out->Reason=1;
 if(Profile!=N976N_PLATFORM_PROFILE_PHONE||!D||!Layout(Context,D,Bytes)||
  Identity->Magic!=N976N_ADC_ADMISSION_MAGIC||Identity->Version!=1||Identity->Size!=sizeof(*Identity)||
  Identity->Profile!=Profile||Identity->Admitted!=1||Identity->Reason||Identity->Checks!=7||
  Identity->Adc!=0x15C40000||Identity->AdcBytes!=0x100||Identity->Cmu!=0x15C00000||
  Identity->Irq!=116||Identity->Clock!=110||Identity->ReadPlan!=1)return FALSE;
 Out->Checks=1;Out->Reason=2;
 B=Child(D,0,"battery");A=Child(D,0,"adc@15C40000");
 if(B<0||A<0||!Enabled(D,B)||!Enabled(D,A)||!String(D,B,"compatible","samsung,sec-battery")||
  !String(D,A,"compatible","samsung,exynos-adc-v3")||!Reg(D,A,0x15C40000,0x100)||
  !Cell(D,A,"#io-channel-cells",1))return FALSE;
 Out->Checks|=2;Out->Reason=3;P=&Out->Contract;
 if(!Cell(D,B,"battery,temp_adc_type",1)||!Cell(D,B,"battery,adc_check_count",5))return FALSE;
 for(UINTN I=0;I<3;I++)if(!Cell(D,B,Source[I],2)||!Cell(D,B,Check[I],2))return FALSE;
 P->AdcType=1;P->SampleCount=5;
 Out->Checks|=4;Out->Reason=4;
 Refs=Prop(D,B,"io-channels",&N);Names=Prop(D,B,"io-channel-names",&NamesBytes);
 if(!Refs||N<24||(N%8)||!Names||NamesBytes<=0)return FALSE;
 Handle=Be32(Refs);
 if(FdtNodeOffsetByPhandle(D,Handle)!=A||!UniqueHandle(Context,D,A,Handle))return FALSE;
 /* Resolve channel names, not phandle constants or consumer #io-channel-cells.
  * This profile's optional named channels use the same one-cell provider. */
 for(At=0;At<NamesBytes;Index++){
  INT32 End=At;while(End<NamesBytes&&Names[End])End++;
  if(End==At||End==NamesBytes||Index>=(UINT32)N/8||Be32(Refs+Index*8)!=Handle)return FALSE;
  for(UINTN I=0;I<3;I++)if(Text(Names+At,End-At+1,NamesWanted[I])){
   if(Seen&(1U<<I))return FALSE;
   P->Channels[I]=Be32(Refs+Index*8+4);if(P->Channels[I]!=NcaThermalChannels[I])return FALSE;
   Seen|=1U<<I;
  }
  At=End+1;
 }
 if(Index!=(UINT32)N/8||Seen!=7)return FALSE;
 Out->Checks|=8;Out->Reason=5;
 for(UINTN I=0;I<3;I++){
  Raw=Prop(D,B,Adc[I],&N);if(!Raw||N!=23*4)return FALSE;
  for(UINTN J=0;J<23;J++){P->Adc[I][J]=Be32(Raw+J*4);if(P->Adc[I][J]!=NcaThermalAdc[I][J])return FALSE;}
  Raw=Prop(D,B,Temp[I],&N);if(!Raw||N!=23*4)return FALSE;
  for(UINTN J=0;J<23;J++){
   UINT32 V=Be32(Raw+J*4);P->DeciC[I][J]=V<=0x7FFFFFFFU?(INT32)V:-1-(INT32)(0xFFFFFFFFU-V);
   if(P->DeciC[I][J]!=NcaThermalDeciC[J])return FALSE;
  }
  P->Sources[I]=P->CheckTypes[I]=2;
 }
 Out->Checks|=16;P->Version=1;P->Bytes=sizeof(*P);P->Checks=Out->Checks;
 P->AdcAddress=Identity->Adc;P->AdcBytes=(UINT32)Identity->AdcBytes;
 P->Irq=(UINT32)Identity->Irq;P->Clock=(UINT32)Identity->Clock;P->PointCount=23;
 if(!NcaThermalContractValid(P))return FALSE;
 Out->Admitted=1;Out->Reason=0;return TRUE;
}

/* Public single-resource APIs deliberately have no shared context. */
BOOLEAN EFIAPI N976nAdmitUart(CONST VOID *D,UINT64 B,UINT64 P,N976N_UART_ADMISSION *O)
{ return AdmitUart(NULL,D,B,P,O); }
BOOLEAN EFIAPI N976nAdmitBattery(CONST VOID *D,UINT64 B,UINT64 P,N976N_BATTERY_ADMISSION *O)
{ return AdmitBattery(NULL,D,B,P,O); }
BOOLEAN EFIAPI N976nAdmitChargeObservation(CONST VOID *D,UINT64 B,UINT64 P,N976N_CHARGE_ADMISSION *O)
{ return AdmitChargeObservation(NULL,D,B,P,O); }
BOOLEAN EFIAPI N976nAdmitAdcPreflight(CONST VOID *D,UINT64 B,UINT64 P,N976N_ADC_ADMISSION *O)
{ return AdmitAdcPreflight(NULL,D,B,P,O); }
BOOLEAN EFIAPI N976nAdmitThermal(CONST VOID *D,UINT64 B,UINT64 P,
 CONST N976N_ADC_ADMISSION *I,N976N_THERMAL_ADMISSION *O)
{ return AdmitThermal(NULL,D,B,P,I,O); }

BOOLEAN EFIAPI N976nAdmitBootDevices(CONST VOID *D,UINT64 B,UINT64 P,N976N_BOOT_ADMISSION *O)
{
  BOOT_CONTEXT Context;
  if (O==NULL || ((UINTN)O&7)!=0 || (UINTN)O>MAX_UINTN-sizeof(*O)) return FALSE;
  if (D!=NULL && (B>MAX_UINTN || (UINTN)D>MAX_UINTN-B ||
      Overlap((UINTN)D,B,(UINTN)O,sizeof(*O)))) return FALSE;
  ZeroMem(&Context,sizeof(Context)); Context.Dtb=D; Context.Bytes=B; Context.Profile=P;
  ZeroMem(O,sizeof(*O));
  /* Do not short-circuit: consumers retain each original failure/result. */
  AdmitUart(&Context,D,B,P,&O->Uart);
  AdmitBattery(&Context,D,B,P,&O->Battery);
  AdmitChargeObservation(&Context,D,B,P,&O->Charge);
  AdmitAdcPreflight(&Context,D,B,P,&O->Adc);
  AdmitThermal(&Context,D,B,P,&O->Adc,&O->Thermal);
  return TRUE;
}
