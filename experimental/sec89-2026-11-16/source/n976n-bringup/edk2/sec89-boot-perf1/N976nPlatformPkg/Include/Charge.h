/* SPDX-License-Identifier: MIT
 * SEC89 observation/policy contract. No charger write API or watchdog kick.
 * Register meanings: pinned Samsung N976N max77705_charger.c/.h. Input limit
 * configuration is NOT a source contract; FG TEMP is NOT a fresh thermistor.
 */
#ifndef N976N_CHARGE_H
#define N976N_CHARGE_H
#include "N976nBattery.h"
enum N976N_POWER_FIELD {
 N976N_PWR_INT_OK, N976N_PWR_DETAIL0, N976N_PWR_DETAIL1, N976N_PWR_MODE,
 N976N_PWR_TIMER, N976N_PWR_CC, N976N_PWR_TOPOFF, N976N_PWR_CV,
 N976N_PWR_PROTECTION, N976N_PWR_ICL, N976N_PWR_ROUTE, N976N_PWR_COUNT
};
#define N976N_PWR_ALL ((1U<<N976N_PWR_COUNT)-1U)
typedef struct {
 N976N_BAT_U64 Sequence;
 N976N_BAT_U32 ValidMask;
 N976N_BAT_U8 Byte[N976N_PWR_COUNT];
} N976N_POWER_RAW;
/* Only non-clearing status/config bytes read by the Samsung getters. B0 IRQ,
 * USB-C response/mailbox and PCA registers are deliberately not admitted. */
static inline int N976nPowerReadSpec(unsigned Field,N976N_BATTERY_READ *S)
{
 static const N976N_BAT_U8 Reg[]={0xB2,0xB3,0xB4,0xB7,0xB8,0xB9,0xBA,0xBB,0xBD,0xC0,0xC3};
 if(!S||Field>=N976N_PWR_COUNT)return 0;
 S->Address=0x69;S->Register=Reg[Field];S->Bytes=1;return 1;
}
static inline int N976nPowerReadAllowed(unsigned Address,unsigned Register,unsigned Bytes)
{
 N976N_BATTERY_READ S;
 for(unsigned I=0;I<N976N_PWR_COUNT;I++)
  if(N976nPowerReadSpec(I,&S)&&Address==S.Address&&Register==S.Register&&Bytes==S.Bytes)return 1;
 return 0;
}
typedef struct {
 unsigned IntOk,ObservedCharge,Valid,Mode,ChargingMode,BoostMode,ReservedMode,WdtEnabled,WdtExpired;
 unsigned ChginDetail,BatteryDetail,ChargeDetail,AutoIbus,InputMa,ChargeMa;
 unsigned CvMv,CvValid,TopoffMa,RouteRaw,TimerRaw,ProtectionRaw;
} N976N_POWER_VALUES;
enum N976N_POWER_REASON {
 N976N_POWER_NO_SAMPLE=1U, N976N_POWER_STALE=2U, N976N_POWER_OWNER=4U,
 N976N_POWER_SOURCE=8U, N976N_POWER_THERMAL=16U, N976N_POWER_DIRECT=32U,
 N976N_POWER_PROTECTION=64U, N976N_POWER_MODE=128U, N976N_POWER_DEVICE=256U,
 N976N_POWER_CONTROL_DISABLED=512U, N976N_POWER_INCONSISTENT=1024U
};
enum N976N_POWER_STATE {
 N976N_POWER_UNKNOWN, N976N_POWER_NONCHARGING_MODE,
 N976N_POWER_EXISTING_UNMANAGED, N976N_POWER_STOP_REQUIRED
};
typedef struct {
 N976N_BAT_U64 Now,SampleAt,Generation,SampleGeneration,SourceEpoch,SampleSourceEpoch;
 unsigned MaxAge,OwnerReady,SourceContractValid,SourceMa,SourceMv;
 unsigned SourceSink,SourceWired;
 unsigned FreshThermistors,ThermalAllowed,DirectInactive,ProtectionProven;
} N976N_POWER_FACTS;
typedef struct {
 N976N_BAT_U64 EvaluatedAt,SampleAt,Generation,ValidUntil;
 unsigned State,Reasons,GatesPresent,WriteCapability;
} N976N_POWER_DECISION;
int N976nPowerDecode(const N976N_POWER_RAW *R,N976N_POWER_VALUES *V);
/* Host policy can explain missing facts. This candidate cannot emit enable,
 * current/CV, disable or WDT writes, even if every synthetic fact is valid. */
void N976nPowerEvaluate(const N976N_POWER_VALUES *V,const N976N_POWER_FACTS *F,
 N976N_POWER_DECISION *D);
#endif
