/* Pure fixed ABI/CRC/ownership checks using actual Bus and Lease code. */
#if defined(N976N_TEST_UEFI_TYPES)
#include <N976nBatteryTypes.h>
#endif
#include <stddef.h>
#define main BusCasesMain
#include "bus_cases.c"
#undef main
#include "../Lease.c"
static N976N_BAT_LEASE lease,expected;
static void seal(void){lease.Crc32=N976nBatLeaseCrc(&lease);}
static void initial(void)
{
 seed(0);memset(&lease,0,sizeof(lease));
 lease.Magic=N976N_BAT_LEASE_MAGIC;lease.BootCounter=1;lease.CounterHz=26000000;
 lease.Version=N976N_BAT_LEASE_VERSION;lease.Bytes=sizeof(lease);lease.ImmutableBytes=N976N_BAT_LEASE_IMMUTABLE_BYTES;
 lease.ProducerStage=N976N_BAT_LEASE_RELEASED;lease.Factor=5;lease.FactorStatus=1;
 lease.Gic114Masked=lease.ProducerRetired=lease.ProducerRestored=1;
 lease.ProducerKind=N976N_BAT_PRODUCER_GAUGE_USB;
 lease.Adc.Generation=1;lease.Adc.Original[0]=2;lease.Adc.Original[1]=0x24;
 lease.Adc.FirmwareRetired=lease.Adc.FirmwareRestored=lease.Adc.FirmwareIrqDetached=1;
 lease.Adc.Clocks[4]=lease.Adc.Clocks[5]=1U<<21;lease.Adc.Clocks[7]=lease.Adc.Clocks[8]=2;lease.Adc.AdmissionDigest[0]=1;
 NCA_THERMAL_CONTRACT *t=&lease.Adc.Thermal;t->Version=1;t->Bytes=sizeof(*t);t->Checks=0x1F;
 t->AdcAddress=0x15C40000;t->AdcBytes=0x100;t->Irq=116;t->Clock=110;t->AdcType=1;t->SampleCount=5;t->PointCount=23;
 for(unsigned i=0;i<3;i++){t->Channels[i]=NcaThermalChannels[i];t->Sources[i]=t->CheckTypes[i]=2;
 for(unsigned j=0;j<23;j++){t->Adc[i][j]=NcaThermalAdc[i][j];t->DeciC[i][j]=NcaThermalDeciC[j];}}
 lease.SelectedConfig[0]=8;lease.SelectedConfig[14]=1;lease.SelectedConfig[15]=1;
 lease.Binding=Binding;lease.Binding.CounterHz=26000000;lease.Guard=N976N_BAT_LEASE_GUARD;seal();expected=lease;
}
int main(void)
{
 initial();
 need(sizeof(lease)==1392&&offsetof(N976N_BAT_LEASE,ClaimState)==1384&&
  offsetof(N976N_BAT_LEASE,Crc32)==36&&offsetof(N976N_BAT_LEASE,Binding)==72&&offsetof(N976N_BAT_LEASE,SelectedConfig)==576&&offsetof(N976N_BAT_LEASE,Guard)==1376,
  "lease_exact_layout_matches_crc_constants");
 need(N976nBatLeaseValid(&lease,2),"lease_released_crc_bound");
 need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"ready_is_not_ownership");
 lease.ClaimState=1;
 need(N976nBatLeaseValid(&lease,2)&&N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"claim_excluded_crc_and_owned_immutable_matches");
 need(!N976nBatLeaseOwned(&expected,&lease,0),"page_end_guard_refused");
 lease.Binding.Config[0]^=1;
 need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"live_immutable_corruption_refused");
 seal();need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"changed_immutable_resealed_still_refused");
 initial();lease.Binding.ClockReserved=1;seal();need(!N976nBatLeaseValid(&lease,2),"binding_reserved_rejected_even_with_valid_crc");
 initial();lease.ClaimReserved=1;need(!N976nBatLeaseValid(&lease,2),"claim_reserved_refused");
 initial();lease.ProducerStage=1;seal();need(N976nBatLeaseValid(&lease,1)&&!N976nBatLeaseValid(&lease,2),"prepared_is_not_accepted_ebs_release");
 initial();lease.Gic114Masked=0;seal();need(!N976nBatLeaseValid(&lease,2),"irq_mask_proof_required");
 initial();lease.ProducerRetired=0;seal();need(!N976nBatLeaseValid(&lease,2),"uart_retirement_required");
 initial();lease.ProducerRestored=0;seal();need(!N976nBatLeaseValid(&lease,2),"uart_restore_required");
 initial();lease.Binding.ClockAddress[0]=0xBAD00000;seal();need(!N976nBatLeaseValid(&lease,2),"unowned_clock_refused");
 initial();lease.Binding.ClockValue[31]=1;seal();need(!N976nBatLeaseValid(&lease,2),"unused_clock_slot_zero_required");
 initial();lease.Binding.Config[3]=0x80;seal();need(!N976nBatLeaseValid(&lease,2),"inherited_irq_enable_refused");
 initial();lease.FactorStatus=2;lease.Factor=0;seal();need(N976nBatLeaseValid(&lease,2),"explicit_unknown_factor_admitted");
 initial();lease.Factor=3;seal();need(!N976nBatLeaseValid(&lease,2),"unsupported_factor_refused");
 initial();lease.ClaimState=3;need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"quarantine_never_owned");
 need(!N976nBatLeaseValid(NULL,2)&&!N976nBatLeaseOwned(NULL,&lease,N976N_BAT_LEASE_GUARD)&&
      !N976nBatLeaseOwned(&expected,NULL,N976N_BAT_LEASE_GUARD)&&!N976nBatLeaseCrc(NULL),"null_input_refused_without_read");
 initial();lease.Version=1;seal();need(!N976nBatLeaseValid(&lease,2),"v1_producer_consumer_mix_refused");
 initial();lease.ClaimState=1;lease.SelectedConfig[1]^=1;
 need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"selected_image_crc_corruption_refused");
 seal();need(!N976nBatLeaseOwned(&expected,&lease,N976N_BAT_LEASE_GUARD),"resealed_selected_image_cannot_replace_claimed_image");
 initial();lease.SelectedConfig[3]=0x80;seal();need(!N976nBatLeaseValid(&lease,2),"selected_irq_enabled_invalid_even_resealed");
 printf("PASS %u cases\n",tests);return 0;
}
