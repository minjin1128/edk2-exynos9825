/* FIX1 actual Bus/Backend state-transition tests. No physical MMIO.
 * Inactive FIFO0 is the observed DIAG1 fixture; it is not declared a silicon
 * guarantee. Positive counts, busy/RUN/IRQ, unknown/mixed states still reject. */
#ifdef N976N_LIFECYCLE_INCLUDE
#undef main
#endif
#define main BusCasesMain
#include "bus_cases.c"
#undef main
#ifdef N976N_LIFECYCLE_INCLUDE
#define main LegacyLifecycleMain
#endif

static void dormant(int f)
{
  seed(0);reset_model=1;fault=f;
  *reg(MODE)=0;*reg(QCH)=0x003F0002;
  for(unsigned i=0;i<16;i++)*reg(HSI+mConfigOffsets[i])=0;
  *reg(HSI+FIFO_CTL)=6;*reg(HSI+USI_CON)=1;*reg(HSI+USI_OPTION)=1;
  *reg(HSI+TRANS)=0;
  *reg(GPIO+0x180)=*reg(GPIO+0x1A0)=1;
  *reg(GPIO+0x184)=*reg(GPIO+0x1A4)=0;
  *reg(GPIO+0x188)=*reg(GPIO+0x1A8)=0;
  *reg(GPIO+0x18C)=*reg(GPIO+0x1AC)=2;
  bind();
}
static int exact_restored(void)
{
  if(*reg(MODE)!=Binding.Mode||*reg(QCH)!=Binding.Qch)return 0;
  for(unsigned i=0;i<16;i++)if(*reg(HSI+mConfigOffsets[i])!=Binding.Config[i])return 0;
  for(unsigned i=0;i<6;i++)if((*reg(GPIO+mGpioOffsets[i])&15)!=(Binding.Gpio[i]&15))return 0;
  return *reg(GPIO+0x184)==0&&*reg(GPIO+0x1A4)==0;
}
static void refuse_capture(const char *name)
{
  N976N_BAT_BUS_BINDING b,zero={0};N976N_BAT_BUS_REPORT r;
  memset(&b,0xA5,sizeof(b));
  need(!N976nBatBusCaptureBinding(&Ops,NULL,1000000,&b,&r)&&
       !writes&&!starts&&!memcmp(&b,&zero,sizeof(b))&&
       r.Status==N976N_BAT_BUS_NOT_READY&&r.Reason==0xB150,name);
}
static void refuse_sample(const char *name)
{
  N976N_BAT_BACKEND_SAMPLE out;
  need(N976nBatBackendSample(&Backend,&out)!=0&&!writes&&!starts&&!out.Publishable,name);
}
int main(void)
{
  N976N_BAT_BUS_BINDING captured;
  N976N_BAT_BUS_REPORT report;
  N976N_BAT_BACKEND_SAMPLE out;
  N976N_BAT_U64 status;
  dormant(0);
  need(N976nBatBusCaptureBinding(&Ops,NULL,1000000,&captured,&report)&&
       !writes&&!memcmp(&captured,&Binding,sizeof(Binding))&&inactive_fifo_reads,
       "dormant_diag1_fifo_zero_capture_exact_read_only");
  need(N976nBatBusValidateBinding(C)&&!writes,
       "dormant_final_binding_validation_does_not_initialize");
  status=N976nBatBackendSample(&Backend,&out);
  need(!status&&out.Publishable&&starts==18&&txcount==9&&C->Report.RxBytes==16&&
       C->Report.Restored&&C->Report.Retired&&!C->Quarantined&&
       inactive_fifo_reads&&configured_fifo_reads&&resets==1&&exact_restored(),
       "dormant_initialize_nine_reads_restore_reset_state_exactly");
  for(unsigned i=0;i<4;i++)
    need(!N976nBatBackendSample(&Backend,&out)&&out.Publishable&&
         starts==(i+2)*18&&resets==i+2&&exact_restored()&&!C->Quarantined,
         "dormant_repeated_samples_reinitialize_and_restore_same_binding");
  unsigned written=writes;
  need(N976nBatBusValidateBinding(C)&&writes==written,
       "dormant_post_sample_binding_validates_without_mmio_write");

  /* Both EMPTY flags are meaningful only after initialization; positive
   * FIFO payload/full flags and inaccessible reads are never ignored. */
  const BAT_U32 empty_variants[]={0,BAT_BIT8,BAT_BIT24,BAT_BIT24|BAT_BIT8};
  for(unsigned i=0;i<4;i++){
    dormant(0);inherited_fifo=empty_variants[i];
    need(N976nBatBusCaptureBinding(&Ops,NULL,1000000,&captured,&report)&&!writes,
         "dormant_empty_flag_encoding_does_not_define_ownership");
  }
  const BAT_U32 nonempty[]={1,1U<<16,BAT_BIT7,BAT_BIT23,BAT_MAX_U32};
  for(unsigned i=0;i<5;i++){
    dormant(0);inherited_fifo=nonempty[i];refuse_capture("dormant_payload_full_or_inaccessible_fifo_capture_refused");
    refuse_sample("dormant_payload_full_or_inaccessible_fifo_sample_refused_without_mutation");
  }
  const BAT_U32 transfers[]={BAT_BIT17,BAT_BIT16,2,BAT_MAX_U32};
  for(unsigned i=0;i<4;i++){
    dormant(0);*reg(HSI+TRANS)=transfers[i];refuse_capture("dormant_busy_slave_or_active_fsm_capture_refused");
    refuse_sample("dormant_busy_slave_or_active_fsm_sample_refused");
  }
  for(unsigned i=0;i<2;i++){
    dormant(0);*reg(HSI+INT_ST)=i?BAT_BIT31:BAT_BIT7;
    refuse_capture("dormant_pending_or_unknown_interrupt_refused");
    refuse_sample("dormant_pending_irq_sample_refused_without_ack");
  }
  dormant(0);*reg(HSI+AUTO)=BAT_BIT31;refuse_capture("dormant_inherited_run_refused");
  dormant(0);*reg(HSI+INT_EN)=BAT_BIT7;refuse_capture("dormant_inherited_interrupt_enable_refused");
  dormant(0);*reg(HSI+CTL)=BAT_BIT31;refuse_capture("dormant_software_reset_in_progress_refused");

  /* Capture checks newly read snapshots, not just drift from an old lease. */
  const struct { BAT_U32 offset,value; } mixed[]={
    {CTL,8},{CONF,BAT_BIT31},{USI_CON,0},{USI_CON,3},{USI_OPTION,8}
  };
  for(unsigned i=0;i<sizeof(mixed)/sizeof(mixed[0]);i++){
    dormant(0);*reg(HSI+mixed[i].offset)=mixed[i].value;
    refuse_capture("mixed_unclassified_dormant_snapshot_refused");
  }
  dormant(0);*reg(MODE)=4;refuse_capture("mixed_dormant_registers_in_selected_i2c_mode_refused");
  seed(0);force_ready_fifo_zero=1;refuse_capture("initialized_state_still_requires_both_empty_flags");
  refuse_sample("initialized_fifo_zero_never_admitted_by_dormant_exception");
  seed(0);*reg(HSI+CONF)=0;refuse_capture("initialized_state_without_auto_mode_refused");
  seed(0);*reg(HSI+CTL)|=1;refuse_capture("initialized_slave_function_refused");

  /* Mutations before Configure must unwind without claiming an I2C request
   * exists or touching HSI registers that remained in the saved reset state. */
  dormant(16);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&!starts&&!resets&&!hsi_writes&&
       C->Report.Restored&&!C->Quarantined&&exact_restored(),
       "preconfigure_lines_low_restores_pins_and_outer_without_hsi_writes");
  dormant(30);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&!starts&&!resets&&!hsi_writes&&setup_faults&&
       C->Report.Restored&&!C->Quarantined&&exact_restored(),
       "preconfigure_alt_function_readback_failure_restores_dormant_state");
  dormant(33);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&!starts&&!resets&&!hsi_writes&&setup_faults&&C->Quarantined,
       "preconfigure_foreign_hsi_drift_quarantines_without_reset_or_ack");
  written=writes;
  need(N976nBatBackendSample(&Backend,&out)!=0&&writes==written&&!out.Publishable,
       "preconfigure_drift_quarantine_remains_sticky");

  dormant(31);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&!starts&&hsi_writes&&setup_faults&&!C->Quarantined&&C->Report.Restored&&exact_restored(),
       "usi_release_failure_with_strict_selected_idle_restores_without_submission");
  dormant(0);force_ready_fifo_zero=1;status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&!starts&&resets==1&&C->Quarantined&&configured_fifo_reads&&ticks<300000,
       "configured_fifo_zero_has_bounded_failure_and_no_bus_submission");

  /* Existing active-transfer safety must hold on the new dormant entry path. */
  dormant(7);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&C->Report.Received==1&&C->Report.Restored&&!C->Quarantined&&exact_restored(),
       "dormant_short_read_restores_without_publishing_partial_value");
  dormant(8);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&C->Quarantined&&C->Report.Received==2,
       "dormant_extra_fifo_payload_still_quarantined");
  dormant(10);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&C->Quarantined,
       "dormant_sticky_done_ack_still_quarantined");
  dormant(5);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&starts==2&&C->Report.FirstWaitExit==1&&C->Quarantined&&ticks<210000,
       "dormant_rx_deadline_preserved_and_unretired_not_reset");
  dormant(4);status=N976nBatBackendSample(&Backend,&out);
  need(status&&!out.Publishable&&C->Report.FirstWaitExit==2&&C->Quarantined,
       "dormant_frozen_clock_watchdog_preserved");
  dormant(0);cancel_mode=1;status=N976nBatBackendSample(&Backend,&out);
  need(status==N976N_BAT_BUS_ABORTED&&!writes&&!starts&&!out.Publishable,
       "dormant_cancellation_before_ownership_mutation");
  printf("PASS %u cases\n",tests);return 0;
}
