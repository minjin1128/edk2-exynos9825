/* SPDX-License-Identifier: MIT
 * Runtime DT admission for Samsung UART_DBG and the MAX77705 HSI2C45 route.
 * Upstream FdtLib performs traversal; no hardware is touched here. Pin groups
 * and clock providers are resolved, never assumed from fixed phandle numbers.
 */
#include <N976nUartAdmission.h>
#include <Library/BaseMemoryLib.h>
#include <Library/FdtLib.h>
#include "RootCompatible.h"

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
STATIC BOOLEAN UniqueHandle (CONST VOID *D, INT32 Target, UINT32 Handle)
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
STATIC BOOLEAN Ref (CONST VOID *D, INT32 Node, CONST CHAR8 *Name, INT32 Target)
{
  INT32 N; CONST UINT8 *P=Prop(D,Node,Name,&N);
  return P!=NULL && N==4 && Be32(P)!=0 && Be32(P)!=MAX_UINT32 &&
         FdtNodeOffsetByPhandle(D,Be32(P))==Target && UniqueHandle(D,Target,Be32(P));
}
STATIC BOOLEAN Clocks (CONST VOID *D, INT32 Node, INT32 Provider,
                       UINT32 First, UINT32 Second)
{
  INT32 N; CONST UINT8 *P=Prop(D,Node,"clocks",&N);
  return P!=NULL && N==16 && Be32(P+4)==First && Be32(P+12)==Second &&
         Be32(P)!=0 && Be32(P)!=MAX_UINT32 && Be32(P+8)==Be32(P) &&
         FdtNodeOffsetByPhandle(D,Be32(P))==Provider && UniqueHandle(D,Provider,Be32(P));
}

/* Header is checked against the caller-owned span before FdtLib sees it.
 * FdtNextNode supplies a bounded tree walk and rejects truncated tokens.
 * Reserve entries and property names also pass upstream bounds checks. */
STATIC BOOLEAN Layout (CONST VOID *D, UINT64 Bytes)
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

BOOLEAN EFIAPI N976nAdmitUart (
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
      Profile>N976N_PLATFORM_PROFILE_QEMU || !Layout(Dtb,DtbBytes)) return FALSE;
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
      !Clocks(Dtb,U,K,0x1E5,0x201) || !Clocks(Dtb,H,K,0x82,0x7D)) return FALSE;
  P=Prop(Dtb,U,"clock-names",&N);
  if (P==NULL || N!=sizeof(UClockNames) || CompareMem(P,UClockNames,sizeof(UClockNames))) return FALSE;
  P=Prop(Dtb,H,"clock-names",&N);
  if (P==NULL || N!=sizeof(HClockNames) || CompareMem(P,HClockNames,sizeof(HClockNames))) return FALSE;
  Out->Reason=5;
  UP=Child(Dtb,G,"uart0-bus"); HP=Child(Dtb,C,"hsi2c45-bus");
  if (UP<0 || HP<0 || !String(Dtb,U,"pinctrl-names","default") ||
      !String(Dtb,H,"pinctrl-names","default") || !Ref(Dtb,U,"pinctrl-0",UP) ||
      !Ref(Dtb,H,"pinctrl-0",HP) || !Cell(Dtb,UP,"samsung,pin-function",3) ||
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
  return TRUE;
}
