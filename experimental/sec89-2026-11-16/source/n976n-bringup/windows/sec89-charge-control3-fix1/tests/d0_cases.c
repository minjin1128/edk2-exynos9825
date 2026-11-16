/* SEC89: actual core with two register views. This fixture models the observed
 * MODE0/MODE4 contrast, not a claim about undocumented silicon banking. */
#define main LegacyLifecycleMain
#define N976N_LIFECYCLE_INCLUDE
#include "lifecycle_cases.c"
#undef main
static BAT_U32 Pre[16],Selected[16],Original[16];
static unsigned selects,releases,outer_drift,reset_fifo;
static N976N_BAT_U32 BankRead(void *o,N976N_BAT_U64 a)
{
 if(a==HSI+FIFO_ST&&*reg(MODE)==4&&*reg(HSI+USI_CON)==1&&reset_fifo)return reset_fifo==1?0:1;
 return Read(o,a);
}
static void BankWrite(void *o,N976N_BAT_U64 a,N976N_BAT_U32 v)
{
 if(a==MODE && v!=*reg(MODE)) {
  if(v==4) {for(unsigned i=0;i<16;i++)*reg(HSI+mConfigOffsets[i])=Selected[i];selects++;}
  else if(v==0) {
   for(unsigned i=0;i<16;i++){Selected[i]=*reg(HSI+mConfigOffsets[i]);*reg(HSI+mConfigOffsets[i])=Pre[i];}
   releases++;
  }
 }
 Write(o,a,v);
 if(a==MODE&&v==4&&outer_drift)*reg(QCH)^=1;
}
static const N976N_BAT_BUS_OPS BankOps={BankRead,BankWrite,Barrier,Counter,Stall,Cancel};
static void bank_seed(void)
{
 dormant(0);selects=releases=outer_drift=reset_fifo=0;
 for(unsigned i=0;i<16;i++)Pre[i]=*reg(HSI+mConfigOffsets[i]);
 const BAT_U32 actual[16]={8,0x80083,0xFFFFFF,0,0x980110FF,0x300FF,0x800000FF,
 0x180FF00,0x30003F8,0xFF0000,0x180FF00,0x30003F8,0xFF0000,0xFF0FFFFF,1,1};
 memcpy(Selected,actual,sizeof(actual));memcpy(Original,actual,sizeof(actual));
 need(N976nBatBackendInit(&Backend,&BankOps,NULL,&Binding,5,Original),"v2_selected_image_bound_separately_from_pre_view");
}
static int bank_restored(void)
{return !memcmp(Selected,Original,sizeof(Selected))&&exact_restored();}
int D0CasesMain(void)
{
 N976N_BAT_BACKEND_SAMPLE out;N976N_BAT_BUS_SAMPLE_STATE saved;unsigned w;
 bank_seed();
 need(!N976nBatBusAcquireD0(C)&&C->D0Active&&resets==1&&starts==0&&selects==1,
      "postselect_usi_reset_with_strict_fifo_and_exact_producer_image_acquired");
 saved=C->S;w=writes;
 need(!N976nBatBusValidateBinding(C)&&writes==w&&!memcmp(&saved,&C->S,sizeof(saved)),
      "pre_binding_validator_cannot_erase_active_owner_snapshot");
 need(N976nBatBusAcquireD0(C)==N976N_BAT_BUS_BUSY&&writes==w,"double_acquire_no_write");
 for(unsigned i=0;i<3;i++)
  need(!N976nBatBackendReadActive(&Backend,&out)&&out.Publishable&&C->D0Active&&
       !C->Report.Restored&&C->Report.Retired&&resets==1&&releases==0&&
       !memcmp(C->S.Saved,Original,sizeof(Original)),"samples_reuse_owner_not_reset_or_restore");
 need(starts==54&&txcount==27,"three_samples_exact_54_messages_27_pointer_bytes");
 need(!N976nBatBusReleaseD0(C)&&!C->D0Active&&C->Report.Restored&&bank_restored()&&releases==1,
      "release_restores_selected_domain_then_pre_view_exactly");
 w=writes;need(!N976nBatBusReleaseD0(C)&&writes==w,"duplicate_release_no_write");
 need(!N976nBatBusAcquireD0(C)&&resets==2&&!N976nBatBackendReadActive(&Backend,&out)&&
      !N976nBatBusReleaseD0(C)&&bank_restored(),"repeated_d0_uses_same_immutable_images");
 bank_seed();reset_fifo=1;
 need(!N976nBatBusAcquireD0(C)&&C->D0Active&&resets==1&&!starts,
      "selected_reset_fifo_zero_admitted_then_strict_configure");
 need(!N976nBatBackendReadActive(&Backend,&out)&&out.Publishable&&
      !N976nBatBusReleaseD0(C)&&bank_restored(),"reset_fifo_zero_sample_retirement_and_exact_restore");
 bank_seed();reset_fifo=1;Selected[4]^=1;
 need(N976nBatBusAcquireD0(C)&&C->Report.Reason==0xB152&&!resets&&!starts&&!acks&&
      C->Quarantined&&C->Report.Restored&&*reg(MODE)==0,
      "reset_fifo_zero_image_mismatch_outer_only_restored_quarantine");
 bank_seed();reset_fifo=2;
 need(N976nBatBusAcquireD0(C)&&!resets&&!starts&&!acks&&C->Quarantined&&!C->Report.Restored,
      "reset_fifo_payload_still_refused_no_owner_reconstruction");
 bank_seed();Selected[4]^=1;
 need(N976nBatBusAcquireD0(C)&&C->Report.Reason==0xB152&&!resets&&!starts&&!acks&&C->Quarantined,
      "selected_image_drift_refused_without_reset_or_ack");
 need(C->Report.Restored&&*reg(MODE)==Binding.Mode&&*reg(QCH)==Binding.Qch&&
      !memcmp(Pre,Binding.Config,sizeof(Pre))&&Selected[4]==(Original[4]^1)&&
      Selected[14]==Original[14],"refused_selected_image_untouched_outer_restored_and_quarantine_retained");
 w=writes;need(N976nBatBusAcquireD0(C)==N976N_BAT_BUS_NOT_READY&&writes==w,
      "restored_selection_mismatch_is_not_reusable");
 bank_seed();Selected[4]^=1;outer_drift=1;
 need(N976nBatBusAcquireD0(C)&&C->Report.Reason==0xB152&&C->Quarantined&&
      !C->Report.Restored&&!releases&&!resets&&!acks&&*reg(MODE)==4,
      "selection_mismatch_with_foreign_outer_drift_cannot_restore");
 bank_seed();need(!N976nBatBusAcquireD0(C),"acquire_before_owned_completion_latch");
 *reg(HSI+INT_ST)=INT_DONE;
 need(N976nBatBackendReadActive(&Backend,&out)&&!out.Publishable&&
      C->Report.Reason==0xB153&&!C->S.RestoreBlocked&&C->Report.Restored&&
      !C->Quarantined&&bank_restored(),"owned_readiness_failure_retired_acknowledged_and_restored");
 bank_seed();force_ready_fifo_zero=1;Selected[14]=0;
 need(N976nBatBusAcquireD0(C)&&!starts&&!resets&&C->Quarantined,
      "postselect_empty_absent_refused_before_initialization");
 bank_seed();Selected[5]|=BAT_BIT31;
 /* Never run Write(AUTO) for this injected inherited RUN value. */
 need(N976nBatBusAcquireD0(C)&&!starts&&!resets&&!acks&&C->Quarantined,
      "inherited_run_not_reset_to_claim_ownership");
 bank_seed();need(!N976nBatBusAcquireD0(C),"acquire_before_owner_drift");
 *reg(GPIO+0x180)=0;w=writes;
 need(N976nBatBackendReadActive(&Backend,&out)&&!out.Publishable&&C->Quarantined&&writes==w,
      "foreign_pin_drift_quarantines_without_restoring_over_other_owner");
 for(unsigned i=0;i<6;i++) {
  bank_seed();need(!N976nBatBusAcquireD0(C),"acquire_before_stop_owner_drift");
  if(i==0)*reg(GPIO+0x180)=0;
  if(i==1)*reg(QCH)^=2;
  if(i==2)*reg(HSI+USI_CON)=1;
  if(i==3)*reg(MODE)=0;
  if(i==4)*reg(HSI+USI_CON)=2;
  if(i==5)*reg(HSI+USI_OPTION)=8;
  w=writes;
  need(N976nBatBusReleaseD0(C)&&C->Quarantined&&writes==w,
       "stop_foreign_owner_drift_refused_before_cleanup_writes");
 }
 bank_seed();need(!N976nBatBusAcquireD0(C),"acquire_before_cancel");cancel_mode=2;
 need(N976nBatBackendReadActive(&Backend,&out)==N976N_BAT_BUS_ABORTED&&!out.Publishable&&
      starts==2&&C->Report.RxBytes==2&&C->Report.Retired&&C->Report.Restored&&!C->Quarantined&&bank_restored(),
      "cancel_after_run_drains_exact_rx_and_ack_then_releases_no_publication");
 printf("PASS %u cases\n",tests);return 0;
}

#ifndef N976N_D0_INCLUDE
int main(void){return D0CasesMain();}
#endif
