/* SPDX-License-Identifier: MIT */
#ifndef N976N_BAT_LIVE_RESOURCES_H
#define N976N_BAT_LIVE_RESOURCES_H
#include "Lease.h"
#define N976N_BAT_FIXED_RESOURCES 27U
#define N976N_BAT_RESOURCES 28U /* memory mappings only, never the IRQ */
#define N976N_BAT_DESCRIPTOR_COUNT 29U
#define N976N_BAT_IRQ_INDEX 28U
#define N976N_BAT_ADC_INDEX 18U
#define N976N_BAT_TOP_INDEX 17U
#define N976N_BAT_NVS_INDEX 27U
typedef struct {N976N_BAT_U64 Address;N976N_BAT_U32 Bytes,Writable;} N976N_BAT_RESOURCE;
static const N976N_BAT_RESOURCE N976nBatResources[N976N_BAT_FIXED_RESOURCES]={
 {0x15D60000,0x1000,1},{0x15C22030,4,1},{0x15C0304C,4,1},
 {0x15C30180,16,1},{0x15C301A0,16,1},
 {0x15C00100,4,0},{0x15C01020,4,0},{0x15C01824,4,0},
 {0x15800100,0x44,0},{0x15801004,4,0},{0x15801804,4,0},{0x1580200C,4,0},
 {0x15C02010,4,0},{0x15C0206C,4,0},{0x15C0205C,4,0},
 {0x15C02088,4,0},{0x15C0208C,4,0},
 {0x1A240000,0x3000,0},
 {0x15C40000,0x100,1},
 {0x15C01000,4,0},{0x15C01800,4,0},{0x15C01804,4,0},
 {0x15C02004,4,0},{0x15C02008,4,0},{0x15C03000,4,0},
 {0x15C03008,4,0},{0x15C0300C,4,0}};
/* ADC has a separate caller and fence; HSI writes do not gain this authority. */
static int N976nBatAdcWriteAllowed(N976N_BAT_U64 A) {
 return A==0x15C40000||A==0x15C40004||A==0x15C40010||A==0x15C40014;
}
/* Even writable mappings do not permit writes to GPIO DAT or a clock register.
 * Bus implementation owns protocol semantics; this is a second address fence.
 */
static int N976nBatWriteAllowed(N976N_BAT_U64 A) {
 if(A==0x15C22030||A==0x15C0304C)return 1;
 if(A==0x15C30180||A==0x15C30188||A==0x15C3018C||
    A==0x15C301A0||A==0x15C301A8||A==0x15C301AC)return 1;
 if(A>=0x15D60000&&A<=0x15D600C8) {
  switch((unsigned)(A-0x15D60000)) {
   case 0:case 4:case 8:case 0x20:case 0x24:case 0x34:case 0x40:case 0x44:
   case 0x48:case 0x54:case 0x58:case 0x5C:case 0x60:case 0x64:case 0x68:
   case 0x70:case 0xC4:case 0xC8:return 1;
  }
 }
 return 0;
}
#endif
