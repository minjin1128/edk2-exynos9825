/* Actual Bus.c payload path, fake MMIO, no physical PMIC accesses. */
#define N976N_D0_INCLUDE
#include "d0_cases.c"
static unsigned guard_n,deny_at;
static int Guard(void *p,const NCC_TICKET *t)
{
 (void)p;++guard_n;
 if(guard_n==deny_at)return 0;
 if(!t||t->OwnerGeneration!=1||!C->D0Active||C->Quarantined)return 0;
 if(!C->Report.Retired&&!(C->ControlPayload&&C->S.InTransaction&&C->ControlTicket==t))return 0;
 if(!C->Report.Retired&&C->ControlPayload&&C->S.InTransaction&&C->ControlTicket==t)return 1;
 return t->Cleanup||(!cancel_mode&&t->SourceEpoch==1&&ticks/1000<t->NotAfter);
}
static NCC_TICKET Ticket(unsigned cleanup,unsigned before)
{NCC_TICKET t={0};t.OwnerGeneration=1;t.SourceEpoch=cleanup?0:1;t.NotAfter=cleanup?0:100000;t.Cleanup=cleanup;t.CompareBefore=1;t.Before=(uint8_t)before;return t;}
static void Setup(void)
{bank_seed();need(!N976nBatBusAcquireD0(C),"control_acquire");C->KeepControlOwner=1;control_model=1;pmic[0xB7]=0x15;pmic[0xB9]=0x52;pmic[0xBD]=0x0C;guard_n=deny_at=0;}
int main(void)
{
 unsigned n;BAT_U8 v;NCC_TICKET t;
 Setup();t=Ticket(1,0x15);v=0x14;cancel_mode=1;
 need(N976nBatBusControl(C,1,0xB7,&v,&t,Guard,0)==NCC_IO_OK&&payloads==1&&pmic[0xB7]==0x14&&C->Report.Retired&&C->D0Active,"cancelled_owned_mode4_retired_before_release");
 need(!N976nBatBusReleaseD0(C)&&bank_restored(),"release_after_mode4");
 Setup();t=Ticket(0,0x52);v=0x46;
 need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)==NCC_IO_OK&&pmic[0xB9]==0x46&&payloads==1,"cc_rmw_preserves_high_bits");n=guard_n;
 for(unsigned k=1;k<=n;k++){
  Setup();t=Ticket(0,0x52);v=0x46;deny_at=k;
  need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)!=NCC_IO_OK&&!payloads,"deny_each_admission_and_byte_boundary_no_payload");
  if(C->Quarantined){unsigned starts_before=starts;v=0x14;t=Ticket(1,0x15);
   need(N976nBatBusControl(C,1,0xB7,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&starts==starts_before,"quarantine_no_optimistic_stop");}
 }
 Setup();t=Ticket(0,0x53);v=0x46;
 need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!payloads,"compare_before_change_no_payload");
 Setup();t=Ticket(0,0x52);v=0x86;
 need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!starts,"upper_bits_write_rejected");
 Setup();t=Ticket(1,0x52);v=0x46;
 need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!starts,"cleanup_cannot_set_current");
 Setup();t=Ticket(1,0x15);v=0x15;
 need(N976nBatBusControl(C,1,0xB7,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!starts,"cleanup_cannot_enable");
 Setup();t=Ticket(0,0x0C);v=0x0D;
 need(N976nBatBusControl(C,1,0xBD,&v,&t,Guard,0)==NCC_IO_OK&&pmic[0xBD]==0x0C,"wdt_command_self_clear");
 Setup();t=Ticket(0,0x15);v=0x14;fault=20;
 need(N976nBatBusControl(C,1,0xB7,&v,&t,Guard,0)!=NCC_IO_OK&&!payloads,"late_error_in_compare_read_not_accepted");
 Setup();t=Ticket(0,0x52);v=0x46;cancel_payload=1;
 need(N976nBatBusControl(C,1,0xB9,&v,&t,Guard,0)==NCC_IO_OK&&!C->Quarantined&&payloads==1&&C->Report.Retired,"cancel_after_payload_run_finishes_exact_retired_message");
 Setup();t=Ticket(0,0x15);v=0x14;fault=4;
 need(N976nBatBusControl(C,1,0xB7,&v,&t,Guard,0)==NCC_IO_UNKNOWN&&C->Quarantined&&!payloads,"frozen_clock_bounded_unknown");
 Setup();t=Ticket(0,0x15);v=0;need(N976nBatBusControl(C,0,0xB7,&v,&t,Guard,0)==NCC_IO_OK&&v==0x15&&!payloads,"read_retired_no_mutating_payload");
 Setup();pmic[0xB7]=0x14;pmic[0xC0]=0x8f;t=Ticket(0,0x8f);t.InputSetup=1;v=0xa3;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_OK&&pmic[0xC0]==0xa3&&payloads==1&&C->Report.Retired,"icl900_mode4_upperbit_preserved");
 t=Ticket(1,0xa3);v=0x83;cancel_mode=1;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_OK&&pmic[0xC0]==0x83&&payloads==2,"cancelled_owned_fallback100_after_mode4");
 Setup();pmic[0xC0]=0x8f;t=Ticket(0,0x8f);t.InputSetup=1;v=0xa3;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!payloads,"icl_setup_mode5_refused");
 Setup();pmic[0xB7]=0x14;pmic[0xC0]=0x8f;t=Ticket(0,0x8f);t.InputSetup=1;v=0x23;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!payloads,"icl_upperbit_change_refused");
 Setup();pmic[0xB7]=0x14;pmic[0xC0]=0x8f;t=Ticket(0,0x8f);t.InputSetup=1;v=0xa4;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!payloads,"arbitrary_icl_limit_refused");
 Setup();pmic[0xB7]=0x14;pmic[0xC0]=0xa3;t=Ticket(1,0xa3);v=0xa3;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED&&!payloads,"cleanup_cannot_retain_raised_input");
 Setup();pmic[0xB7]=0x14;pmic[0xC0]=0x8f;t=Ticket(0,0x8f);t.InputSetup=1;v=0xa3;fault=4;
 need(N976nBatBusControl(C,1,0xC0,&v,&t,Guard,0)==NCC_IO_UNKNOWN&&C->Quarantined&&!payloads,"icl_frozen_clock_quarantines");
 for(unsigned r=0;r<256;r++)if(r!=0xB7&&r!=0xB9&&r!=0xBD){v=0;t=Ticket(0,0);need(N976nBatBusControl(C,1,r,&v,&t,Guard,0)==NCC_IO_NOT_ISSUED,"normal_ticket_forbids_other_registers");}
 printf("PASS %u cases\n",tests);return 0;
}
