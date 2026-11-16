/* Fable F1 regression: actual Bus.c, no physical I/O. */
#define main preserved_bus_cases
#include "bus_cases.c"
#undef main
int main(void){
 N976N_BAT_BACKEND_SAMPLE out;N976N_POWER_RAW power;N976N_BAT_U64 status;
 seed(0);late_jump_us=381810;
 need(N976nBatBusAcquireD0(C)==0,"acquire");C->KeepControlOwner=1;
 status=N976nBatBackendReadActive(&Backend,&out);
 need(!status&&out.Publishable&&!C->Quarantined&&C->Report.Retired&&C->Report.RxBytes==16,"late_2byte_first_INT_zero_then_DONE_exact_ACK_retired");
 need(N976nBatBusReleaseD0(C)==0,"late_2byte_release");
 seed(0);late_jump_us=381810;
 need(N976nBatBusAcquireD0(C)==0,"acquire_1byte");C->KeepControlOwner=1;
 status=N976nBatBusReadChargeActive(C,1,&power);
 need(!status&&power.ValidMask==N976N_PWR_ALL&&!C->Quarantined&&C->Report.Retired,"late_1byte_exact_ACK_retired");
 need(N976nBatBusReleaseD0(C)==0,"late_1byte_release");
 for(unsigned f=5;f<=12;f++){
  seed((int)f);late_jump_us=381810;need(N976nBatBusAcquireD0(C)==0,"acquire_fault");C->KeepControlOwner=1;
  status=N976nBatBackendReadActive(&Backend,&out);
  need(status&&!out.Publishable,"late_fault_never_published");
  if(f==7||f==9)need(out.CleanReadFailure,"clean_error_proof_captured_at_gauge_retirement");
  if(C->Quarantined)need(!out.CleanReadFailure,"quarantine_never_clean_error");
  if(f==5||f==6||f==8||f==10||f==11||f==12)need(C->Quarantined,"late_uncertain_is_quarantined");
 }
 seed(20);late_jump_us=381810;need(N976nBatBusAcquireD0(C)==0,"acquire_late_ACK_error");C->KeepControlOwner=1;
 status=N976nBatBackendReadActive(&Backend,&out);need(status&&!out.Publishable&&C->Report.FirstInterrupt==(BAT_BIT7|BAT_BIT10),"late_ACK_error_rejected");need(!out.CleanReadFailure,"ACK_failure_is_not_cache_fallback");
 seed(21);late_jump_us=381810;need(N976nBatBusAcquireD0(C)==0,"acquire_completed_B112");C->KeepControlOwner=1;
 status=N976nBatBackendReadActive(&Backend,&out);need(status&&!out.Publishable&&out.CleanReadFailure&&!C->Quarantined,"late_completed_B112_error_clean_retirement");
 seed(0);late_jump_us=381810;reverse_on_rx=1;need(N976nBatBusAcquireD0(C)==0,"acquire_clock_reverse");C->KeepControlOwner=1;
 status=N976nBatBackendReadActive(&Backend,&out);need(status&&!out.Publishable&&C->Report.FirstWaitExit==3,"clock_reverse_not_extended");need(!out.CleanReadFailure,"clock_fault_not_cache_fallback");
 seed(0);late_jump_us=381810;need(N976nBatBusAcquireD0(C)==0,"acquire_cancel");C->KeepControlOwner=1;cancel_mode=2;
 status=N976nBatBackendReadActive(&Backend,&out);need(status==N976N_BAT_BUS_ABORTED&&!out.Publishable&&starts==2&&C->Report.Retired&&!C->Quarantined,"cancel_retires_without_new_pair_or_publish");need(!out.CleanReadFailure,"cancel_not_cache_fallback");
 seed(18);status=N976nBatBackendReadActive(&Backend,&out);need(status&&!out.CleanReadFailure,"unknown_preexisting_IRQ_no_clean_proof");
 printf("PASS %u cases\n",tests);return 0;
}
