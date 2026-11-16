/* SPDX-License-Identifier: MIT
 * Native little-endian, pointer-free HOB/NVS thermal profile. Types intentionally
 * avoid CRT/WDK/EDK2 headers so the producer and consumer share one definition.
 */
#ifndef N976N_THERMAL_CONTRACT_H
#define N976N_THERMAL_CONTRACT_H
typedef unsigned int NCA_U32;
typedef int NCA_S32;
typedef unsigned long long NCA_U64;
#define NCA_THERMAL_CHECKS 0x1FU
typedef struct {
 NCA_U64 AdcAddress;
 NCA_U32 Version,Bytes,Checks,AdcBytes,Irq,Clock,AdcType,SampleCount,PointCount;
 NCA_U32 Channels[3],Sources[3],CheckTypes[3];
 NCA_U32 Adc[3][23];NCA_S32 DeciC[3][23];
} NCA_THERMAL_CONTRACT;
typedef char NcaThermalTypes[(sizeof(NCA_U32)==4&&sizeof(NCA_S32)==4&&sizeof(NCA_U64)==8)?1:-1];
typedef char NcaThermalAbi[(sizeof(NCA_THERMAL_CONTRACT)==632)?1:-1];
static const NCA_U32 NcaThermalChannels[3]={4,3,1};
static const NCA_U32 NcaThermalAdc[3][23]={
 {329,368,426,474,557,652,764,893,1040,1207,1390,1594,1812,2041,2275,2511,2738,2951,3135,3321,3431,3546,3621},
 {275,325,388,457,538,633,744,872,1009,1184,1366,1570,1786,2014,2248,2483,2710,2916,3111,3294,3384,3535,3582},
 {293,343,409,479,562,657,770,899,1045,1212,1395,1598,1815,2042,2275,2507,2733,2945,3139,3301,3426,3541,3654}};
static const NCA_S32 NcaThermalDeciC[23]={900,850,800,750,700,650,600,550,500,450,400,350,
 300,250,200,150,100,50,0,-50,-100,-150,-200};
static inline int NcaThermalContractValid(const NCA_THERMAL_CONTRACT *p)
{
 unsigned i,j;
 if(!p||p->Version!=1||p->Bytes!=sizeof(*p)||p->Checks!=NCA_THERMAL_CHECKS||
 p->AdcAddress!=0x15C40000ULL||p->AdcBytes!=0x100||p->Irq!=116||p->Clock!=110||
 p->AdcType!=1||p->SampleCount!=5||p->PointCount!=23)return 0;
 for(i=0;i<3;i++){
  if(p->Channels[i]!=NcaThermalChannels[i]||p->Sources[i]!=2||p->CheckTypes[i]!=2)return 0;
  for(j=0;j<23;j++)if(p->Adc[i][j]!=NcaThermalAdc[i][j]||p->DeciC[i][j]!=NcaThermalDeciC[j])return 0;
 }
 return 1;
}
#endif
