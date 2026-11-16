/* SEC76 retained SEC73 FIX1 deterministic fixtures. Included after exact production helpers.
 * Mock WDF memory/queue operations are serial only: not a WDF race/cancel test. */
static unsigned groups;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
#define GROUP(name) do { puts(name); ++groups; } while(0)
static void packet(uint8_t b[16], unsigned id, unsigned action, unsigned x, unsigned y, unsigned type, unsigned remaining) {
    memset(b,0,16); b[0]=(uint8_t)((action<<6)|(id<<2)); b[1]=(uint8_t)(x>>4); b[2]=(uint8_t)(y>>4);
    b[3]=(uint8_t)((x<<4)|(y&15)); b[6]=(uint8_t)((type>>2)<<6); b[7]=(uint8_t)(((type&3)<<6)|remaining);
}
static BOOLEAN feed(DEVICE_CONTEXT *d,unsigned id,unsigned action,unsigned x,unsigned y) {
    uint8_t b[16]; N976N_Y771_EVENT e; packet(b,id,action,x,y,0,0);
    CHECK(N976nY771DecodeEvent(b,sizeof(b),&e)==N976nY771Coordinate);
    return TouchApplyDecodedEventLocked(d,&e);
}
static inputReport54_t *queued(DEVICE_CONTEXT *d,unsigned n) {
    CHECK(n<d->InputReportCount); return &d->InputReports[(d->InputReportHead+n)%64];
}
static unsigned px(const inputReport54_t *r,unsigned i) {return r->points[6*i+2]|(r->points[6*i+3]<<8);}
static unsigned py(const inputReport54_t *r,unsigned i) {return r->points[6*i+4]|(r->points[6*i+5]<<8);}
static void setup(DEVICE_CONTEXT *d,MOCK_QUEUE *q) {
    CHECK(mockLockDepth==0);mockCompleteHook=NULL;mockCompletionOrdinal=0;mockTimerStarts=0;
    memset(d,0,sizeof(*d));memset(q,0,sizeof(*q));d->ManualQueue=q;d->HoldTimer=d;
}
static void submit(MOCK_QUEUE *q,MOCK_REQUEST *r,size_t n) {
    CHECK(q->count<8);memset(r,0,sizeof(*r));memset(r->data,0xA5,sizeof(r->data));r->length=n;q->requests[q->count++]=r;
}
static DEVICE_CONTEXT *hookDevice;
static MOCK_REQUEST *hookNext;
static unsigned hookMode;
static void before_completion(WDFREQUEST request,NTSTATUS status) {
    DEVICE_CONTEXT *d=hookDevice;
    CHECK(status==0&&request->information==64&&!request->completed);
    CHECK(d->InputDrainActive==1&&mockLockDepth==0);
    CHECK(hookNext&&!hookNext->completed);
    if(hookMode==1) {
        CHECK(d->CommittedContacts[0].Active&&d->CommittedContacts[0].X==100&&d->CommittedContacts[0].Y==200);
        TouchQueueAllUpReport(d);
        CHECK(d->RecoveryPending&&px(&d->RecoveryReport,0)==100&&py(&d->RecoveryReport,0)==200);
    } else if(hookMode==2) {
        CHECK(!d->RecoveryPending&&!d->CommittedContacts[0].Active);
        CHECK(feed(d,1,1,300,400));
        TouchDrainInputReports(d);
        CHECK(d->InputReportCount==1&&!d->CommittedContacts[0].Active);
    } else if(hookMode==3) {
        CHECK(d->CommittedContacts[0].Active);
        TouchStopInput(d);
        CHECK(d->InputStopping&&d->InputResetPending&&d->InputDrainActive==1);
        CHECK(d->CommittedContacts[0].Active); /* retained until owned completion retires */
        CHECK(!feed(d,1,2,300,400));TouchDrainInputReports(d);
    } else CHECK(0);
    CHECK(d->InputDrainActive==1&&!hookNext->completed&&mockLockDepth==0);
}
static void drain_one(DEVICE_CONTEXT *d,MOCK_QUEUE *q,MOCK_REQUEST *request) {
    submit(q,request,64);TouchDrainInputReports(d);
    CHECK(request->completed==1&&request->status==0&&request->information==64&&d->InputDrainActive==0);
}
static void committed(DEVICE_CONTEXT *d,unsigned i,unsigned active,unsigned x,unsigned y) {
    CHECK(d->CommittedContacts[i].Active==active);
    if(active)CHECK(d->CommittedContacts[i].X==x&&d->CommittedContacts[i].Y==y);
}
int main(void) {
    uint8_t b[32]={0}; N976N_Y771_EVENT e; DEVICE_CONTEXT d; MOCK_QUEUE q; MOCK_REQUEST req[4];
    struct {uint64_t pre;N976N_Y771_EVENT e;uint64_t post;} canary={0x1122334455667788ULL,{0},0x8877665544332211ULL};
    GROUP("decoder_exact_length_null_and_zero_output");
    CHECK(N976nY771DecodeEvent(NULL,16,&e)==N976nY771Invalid);CHECK(N976nY771DecodeEvent(b,16,NULL)==N976nY771Invalid);
    for(size_t n=0;n<=32;n++)if(n!=16){memset(&canary.e,0xA5,sizeof(e));CHECK(N976nY771DecodeEvent(b,n,&canary.e)==N976nY771Invalid);CHECK(canary.e.X==0&&canary.e.WireId==0);}
    CHECK(canary.pre==0x1122334455667788ULL&&canary.post==0x8877665544332211ULL);
    GROUP("decoder_empty_precedes_class_and_stale_payload");
    memset(b,0xFF,16);b[0]=0;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771Empty);CHECK(e.Remaining==0&&e.X==0);
    GROUP("decoder_all_first_bytes_bounds");
    memset(b,0,16);for(unsigned v=0;v<256;v++){b[0]=(uint8_t)v;N976N_Y771_RESULT r=N976nY771DecodeEvent(b,16,&e);
      if(v==0)CHECK(r==N976nY771Empty);else if((v&3)==3)CHECK(r==N976nY771Invalid);else if((v&3)==2)CHECK(r==N976nY771Gesture);
      else if((v&3)==0){unsigned id=(v>>2)&15;CHECK(r==((id>=1&&id<=10&&(v>>6)!=0)?N976nY771Coordinate:N976nY771Invalid));}}
    GROUP("decoder_tool_types_and_remaining_fields");
    for(unsigned t=0;t<16;t++)for(unsigned rem=0;rem<32;rem++){
      packet(b,10,2,4095,0,t,rem);b[7]|=0x20;
      CHECK(N976nY771DecodeEvent(b,16,&e)==((t==0||t==3||t==5||t==6)?N976nY771Coordinate:N976nY771OtherTool));
      CHECK(e.Type==t&&e.Remaining==rem&&e.ContactIndex==9&&e.X==4095&&e.Y==0);}
    GROUP("decoder_coordinate_nibbles_and_telemetry");
    for(unsigned n=0;n<16;n++){packet(b,1,1,0xAB0+n,0xCD0+15-n,0,0);b[4]=255;b[5]=127;b[6]|=63;
      CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771Coordinate);CHECK(e.X==0xAB0+n&&e.Y==0xCD0+15-n&&e.Pressure==63&&e.Major==255&&e.Minor==127);}
    GROUP("decoder_status_error_and_running_boot");
    memset(b,0,16);b[0]=5;b[1]=7;b[2]=42;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771ErrorStatus);CHECK(e.StatusId==7&&e.StatusData==42);
    b[0]=9;b[1]=0;b[2]=0x20;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771UnexpectedBoot);
    b[0]=29;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771UnexpectedBoot);
    b[1]=1;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771Status);b[0]=13;CHECK(N976nY771DecodeEvent(b,16,&e)==N976nY771Status);
    GROUP("physical_sec71_two_full_packets");
    CHECK(N976nY771DecodeEvent(sec71_first,16,&e)==N976nY771Coordinate);CHECK(e.X==2245&&e.Y==2725&&e.Action==1&&e.Remaining==2);
    CHECK(N976nY771DecodeEvent(sec71_last,16,&e)==N976nY771Coordinate);CHECK(e.X==3547&&e.Y==2372&&e.Action==2&&e.Remaining==2);
    GROUP("physical_sec72_prefixes_with_explicit_synthetic_tails");
    CHECK(N976nY771DecodeEvent(sec72_first_synthetic,16,&e)==N976nY771Coordinate);CHECK(e.X==542&&e.Y==587&&e.Action==1);
    CHECK(N976nY771DecodeEvent(sec72_last_synthetic,16,&e)==N976nY771Coordinate);CHECK(e.X==2459&&e.Y==1459&&e.Action==3);
    GROUP("production_report_layout_identity_and_zero_padding");
    CHECK(sizeof(inputpoint)==6&&sizeof(inputReport54_t)==64);setup(&d,&q);CHECK(feed(&d,1,1,0,4095));
    inputReport54_t *r=queued(&d,0);CHECK(r->reportId==0x54&&r->DIG_TouchScreenContactCount==1&&px(r,0)==0&&py(r,0)==4095);
    for(unsigned i=6;i<60;i++)CHECK(r->points[i]==0);
    GROUP("production_first_down_moves_release_keep_last_tip_coordinates");
    setup(&d,&q);mockTime=1000;CHECK(feed(&d,1,1,100,200));mockTime=2000;CHECK(feed(&d,1,2,110,220));mockTime=3000;CHECK(feed(&d,1,2,120,230));CHECK(feed(&d,1,3,2459,1459));
    CHECK(d.InputReportCount==3&&d.InputReportCoalesceCount==1);CHECK(px(queued(&d,0),0)==100&&queued(&d,0)->DIG_TouchScreenScanTimeLow==1);
    CHECK(px(queued(&d,1),0)==120&&px(queued(&d,2),0)==120&&py(queued(&d,2),0)==230&&queued(&d,2)->points[0]==0);
    GROUP("production_duplicate_release_move_without_down_and_duplicate_press_rejected");
    CHECK(!feed(&d,1,3,0,0)&&d.InputReportCount==3);setup(&d,&q);CHECK(!feed(&d,1,2,12,13));CHECK(d.InputReportCount==0);
    CHECK(feed(&d,1,1,12,13));CHECK(!feed(&d,1,1,400,500));CHECK(d.InputReportCount==1&&d.Contacts[0].X==12);
    GROUP("production_reused_contact_order");
    setup(&d,&q);CHECK(feed(&d,1,1,1,2));CHECK(feed(&d,1,3,99,99));CHECK(feed(&d,1,1,3,4));CHECK(feed(&d,1,3,88,88));
    CHECK(d.InputReportCount==4);for(unsigned i=0;i<4;i++)CHECK(queued(&d,i)->points[0]==(i%2==0));CHECK(px(queued(&d,1),0)==1&&px(queued(&d,3),0)==3);
    GROUP("production_contact_set_change_does_not_coalesce");
    setup(&d,&q);CHECK(feed(&d,1,1,1,2));CHECK(feed(&d,1,2,2,3));CHECK(feed(&d,10,1,4,5));CHECK(feed(&d,10,2,6,7));
    CHECK(d.InputReportCount==4&&queued(&d,2)->DIG_TouchScreenContactCount==2&&queued(&d,2)->points[7]==9);
    GROUP("production_ten_contacts_endpoint_and_lift_count");
    setup(&d,&q);for(unsigned i=1;i<=10;i++)CHECK(feed(&d,i,1,4095,4095));CHECK(queued(&d,9)->DIG_TouchScreenContactCount==10);
    CHECK(feed(&d,10,3,0,0));r=queued(&d,10);CHECK(r->DIG_TouchScreenContactCount==10&&r->points[54]==0&&px(r,9)==4095);
    GROUP("production_normal_drain_commits_press_coalesced_move_release");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));CHECK(feed(&d,1,2,110,220));CHECK(feed(&d,1,2,120,230));CHECK(feed(&d,1,3,999,999));
    CHECK(d.InputReportCount==3);committed(&d,0,0,0,0);
    drain_one(&d,&q,&req[0]);committed(&d,0,1,100,200);CHECK(req[0].data[1]==1&&d.InputReportCount==2);
    drain_one(&d,&q,&req[1]);committed(&d,0,1,120,230);CHECK(req[1].data[1]==1&&d.InputReportCount==1);
    drain_one(&d,&q,&req[2]);committed(&d,0,0,0,0);CHECK(req[2].data[1]==0&&req[2].data[3]==120&&req[2].data[5]==230);
    GROUP("production_same_id_normal_release_repress_commits_in_order");
    setup(&d,&q);CHECK(feed(&d,1,1,1,2));CHECK(feed(&d,1,3,99,99));CHECK(feed(&d,1,1,3,4));CHECK(feed(&d,1,3,88,88));
    for(unsigned i=0;i<4;i++){drain_one(&d,&q,&req[i]);committed(&d,0,i%2==0,i<2?1:3,i<2?2:4);CHECK(req[i].data[1]==(i%2==0));CHECK(req[i].data[3]==(i<2?1:3));CHECK(req[i].completionOrdinal==i+1);}
    GROUP("production_two_contacts_normal_drain_ledger_and_coalescing");
    setup(&d,&q);CHECK(feed(&d,1,1,10,20));CHECK(feed(&d,2,1,30,40));CHECK(feed(&d,1,2,11,22));CHECK(feed(&d,2,2,33,44));
    CHECK(d.InputReportCount==3&&d.InputReportCoalesceCount==1);
    drain_one(&d,&q,&req[0]);committed(&d,0,1,10,20);committed(&d,1,0,0,0);
    drain_one(&d,&q,&req[1]);committed(&d,0,1,10,20);committed(&d,1,1,30,40);
    drain_one(&d,&q,&req[2]);committed(&d,0,1,11,22);committed(&d,1,1,33,44);
    CHECK(feed(&d,1,3,999,999));drain_one(&d,&q,&req[0]);committed(&d,0,0,0,0);committed(&d,1,1,33,44);
    CHECK(feed(&d,2,3,888,888));drain_one(&d,&q,&req[1]);committed(&d,1,0,0,0);
    GROUP("production_short_request_does_not_dequeue_partial_copy_or_commit");
    setup(&d,&q);CHECK(feed(&d,1,1,11,22));inputReport54_t saved=*queued(&d,0);submit(&q,&req[0],63);TouchDrainInputReports(&d);
    CHECK(req[0].completed==1&&req[0].status==STATUS_INVALID_BUFFER_SIZE&&req[0].information==0&&d.InputReportCount==1);
    CHECK(memcmp(queued(&d,0),&saved,sizeof(saved))==0);committed(&d,0,0,0,0);
    for(unsigned i=0;i<64;i++)CHECK(req[0].data[i]==0xA5);
    drain_one(&d,&q,&req[1]);CHECK(d.InputReportCount==0&&memcmp(req[1].data,&saved,64)==0);committed(&d,0,1,11,22);
    GROUP("production_request_memory_errors_preserve_report_and_ledger");
    setup(&d,&q);CHECK(feed(&d,1,1,1,2));saved=*queued(&d,0);
    submit(&q,&req[0],64);req[0].memoryError=-7;TouchDrainInputReports(&d);CHECK(d.InputReportCount==1&&req[0].status==-7);
    submit(&q,&req[1],64);req[1].copyError=-8;TouchDrainInputReports(&d);CHECK(d.InputReportCount==1&&req[1].status==-8);
    CHECK(memcmp(queued(&d,0),&saved,64)==0);committed(&d,0,0,0,0);CHECK(req[0].information==0&&req[1].information==0);
    drain_one(&d,&q,&req[2]);committed(&d,0,1,1,2);CHECK(memcmp(req[2].data,&saved,64)==0);
    GROUP("production_commit_rejects_malformed_reports_atomically");
    setup(&d,&q);CHECK(feed(&d,1,1,10,20));drain_one(&d,&q,&req[0]);
    inputReport54_t valid;TouchInitializeReport(&valid);TouchAppendContact(&valid,0,1,11,22);TouchAppendContact(&valid,1,1,33,44);
    S6SY761_COMMITTED_CONTACT_STATE ledger[S6SY761_MAX_CONTACTS];memcpy(ledger,d.CommittedContacts,sizeof(ledger));
    for(unsigned bad=0;bad<11;bad++){
      inputReport54_t invalid=valid;
      switch(bad){case 0:invalid.reportId=0;break;case 1:invalid.DIG_TouchScreenContactCount=0;break;
      case 2:invalid.DIG_TouchScreenContactCount=11;break;case 3:invalid.points[7]=10;break;
      case 4:invalid.points[6]=2;break;case 5:invalid.points[9]=0x10;break;case 6:invalid.points[11]=0x10;break;
      case 7:invalid.points[7]=0;break;case 8:invalid.points[0]=0;break; /* wrong lift coordinates */
      case 9:invalid.points[6]=0;break; /* lift without committed press */
      case 10:invalid.DIG_TouchScreenContactCount=1;invalid.points[1]=1;break; /* missing committed active ID */
      }
      CHECK(!TouchCommitReportLocked(&d,&invalid));CHECK(memcmp(ledger,d.CommittedContacts,sizeof(ledger))==0);
    }
    GROUP("production_corrupt_internal_report_fails_without_dequeue_or_ledger_commit");
    CHECK(feed(&d,1,2,11,22));saved=*queued(&d,0);queued(&d,0)->points[1]=10;
    submit(&q,&req[1],64);TouchDrainInputReports(&d);
    CHECK(req[1].completed==1&&req[1].status==STATUS_DATA_ERROR&&req[1].information==0&&d.InputReportCount==1);
    CHECK(memcmp(ledger,d.CommittedContacts,sizeof(ledger))==0);*queued(&d,0)=saved;
    drain_one(&d,&q,&req[2]);committed(&d,0,1,11,22);
    GROUP("production_ring_wrap_exact_delivery");
    setup(&d,&q);d.InputReportHead=d.InputReportTail=63;CHECK(feed(&d,1,1,100,200));CHECK(feed(&d,1,3,0,0));CHECK(d.InputReportTail==1);
    submit(&q,&req[0],64);submit(&q,&req[1],64);TouchDrainInputReports(&d);CHECK(d.InputReportHead==1&&d.InputReportCount==0&&req[0].completed==1&&req[1].completed==1);
    CHECK(req[0].data[1]==1&&req[1].data[1]==0&&req[0].completionOrdinal<req[1].completionOrdinal);committed(&d,0,0,0,0);
    GROUP("regression_fault_up_uses_committed_not_unsent_move_coordinates");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));drain_one(&d,&q,&req[0]);CHECK(feed(&d,1,2,150,250));TouchQueueAllUpReport(&d);
    CHECK(d.RecoveryPending&&d.InputReportCount==0&&d.RecoveryReport.DIG_TouchScreenContactCount==1&&d.RecoveryReport.points[0]==0);
    CHECK(px(&d.RecoveryReport,0)==100&&py(&d.RecoveryReport,0)==200);saved=d.RecoveryReport;
    drain_one(&d,&q,&req[1]);CHECK(memcmp(req[1].data,&saved,64)==0&&!d.RecoveryPending);committed(&d,0,0,0,0);
    GROUP("regression_fault_with_undelivered_down_emits_no_orphan_up");
    setup(&d,&q);CHECK(feed(&d,1,1,50,60));TouchQueueAllUpReport(&d);
    CHECK(d.InputReportCount==0&&!d.RecoveryPending&&!TouchAnyContactActiveLocked(&d));committed(&d,0,0,0,0);
    submit(&q,&req[0],64);TouchDrainInputReports(&d);CHECK(!req[0].completed&&q.count==1);
    GROUP("regression_repeated_fault_preserves_entire_pending_release_and_scan_time");
    setup(&d,&q);CHECK(feed(&d,1,1,9,10));drain_one(&d,&q,&req[0]);mockTime=1234ULL*1000;TouchQueueAllUpReport(&d);saved=d.RecoveryReport;
    for(unsigned i=0;i<4;i++){mockTime+=100000;TouchQueueAllUpReport(&d);CHECK(d.RecoveryPending&&memcmp(&d.RecoveryReport,&saved,64)==0&&d.InputReportCount==0);}
    CHECK(px(&saved,0)==9&&py(&saved,0)==10);drain_one(&d,&q,&req[1]);CHECK(memcmp(req[1].data,&saved,64)==0);
    TouchQueueAllUpReport(&d);CHECK(!d.RecoveryPending&&d.InputReportCount==0);
    GROUP("recovery_short_memory_and_copy_failure_keep_exact_snapshot_and_ledger");
    setup(&d,&q);CHECK(feed(&d,1,1,101,202));drain_one(&d,&q,&req[0]);TouchQueueAllUpReport(&d);saved=d.RecoveryReport;
    for(unsigned i=0;i<3;i++){
      submit(&q,&req[i],i==0?63:64);if(i==1)req[i].memoryError=-7;if(i==2)req[i].copyError=-8;
      TouchDrainInputReports(&d);CHECK(req[i].completed==1&&req[i].status<0&&req[i].information==0);
      CHECK(d.RecoveryPending&&memcmp(&d.RecoveryReport,&saved,64)==0);committed(&d,0,1,101,202);
      for(unsigned j=0;j<64;j++)CHECK(req[i].data[j]==0xA5);
    }
    drain_one(&d,&q,&req[3]);CHECK(memcmp(req[3].data,&saved,64)==0&&!d.RecoveryPending);committed(&d,0,0,0,0);
    GROUP("serial_fault_after_commit_before_completion_preserves_success_then_recovery_order");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));submit(&q,&req[0],64);submit(&q,&req[1],64);
    hookDevice=&d;hookNext=&req[1];hookMode=1;mockCompleteHook=before_completion;TouchDrainInputReports(&d);
    CHECK(req[0].completed==1&&req[1].completed==1&&req[0].status==0&&req[1].status==0);
    CHECK(req[0].data[1]==1&&req[1].data[1]==0&&req[0].completionOrdinal<req[1].completionOrdinal&&!d.RecoveryPending);committed(&d,0,0,0,0);
    GROUP("full_queue_without_committed_contacts_discards_without_orphan_up");
    setup(&d,&q);for(unsigned i=0;i<32;i++){CHECK(feed(&d,1,1,i,i));CHECK(feed(&d,1,3,0,0));}CHECK(d.InputReportCount==64);
    CHECK(!feed(&d,10,1,50,60));CHECK(d.InputQueueFlushCount==1&&d.InputReportCount==0&&!d.RecoveryPending&&!TouchAnyContactActiveLocked(&d));
    GROUP("full_queue_mixed_committed_uncommitted_contacts_recovers_only_committed_coordinates");
    setup(&d,&q);CHECK(feed(&d,1,1,10,20));drain_one(&d,&q,&req[0]);CHECK(feed(&d,2,1,30,40));drain_one(&d,&q,&req[1]);
    CHECK(feed(&d,1,2,1000,2000));CHECK(feed(&d,3,1,50,60));
    for(unsigned i=0;i<31;i++){CHECK(feed(&d,4,1,i,i));CHECK(feed(&d,4,3,0,0));}CHECK(d.InputReportCount==64);
    CHECK(feed(&d,5,1,70,80));CHECK(d.RecoveryPending&&d.InputReportCount==0&&d.InputQueueFlushCount==1);
    CHECK(d.RecoveryReport.DIG_TouchScreenContactCount==2&&d.RecoveryReport.points[1]==0&&d.RecoveryReport.points[7]==1);
    CHECK(px(&d.RecoveryReport,0)==10&&py(&d.RecoveryReport,0)==20&&px(&d.RecoveryReport,1)==30&&py(&d.RecoveryReport,1)==40);
    saved=d.RecoveryReport;drain_one(&d,&q,&req[2]);CHECK(memcmp(req[2].data,&saved,64)==0);for(unsigned i=0;i<10;i++)committed(&d,i,0,0,0);
    GROUP("repeated_overflow_fault_barrier_blocks_new_generations_and_hold_timer");
    setup(&d,&q);CHECK(feed(&d,1,1,10,20));drain_one(&d,&q,&req[0]);TouchQueueAllUpReport(&d);saved=d.RecoveryReport;
    for(unsigned i=0;i<70;i++){
      CHECK(!feed(&d,1,1,300,400));CHECK(!feed(&d,1,2,301,401));CHECK(!feed(&d,1,3,302,402));
      CHECK(!TouchQueueCurrentReportLocked(&d,TRUE));TouchQueueAllUpReport(&d);mockTime+=1000;
      TouchArmHoldTimer(&d);TouchHoldTimerFunc(d.HoldTimer);
      CHECK(d.RecoveryPending&&memcmp(&d.RecoveryReport,&saved,64)==0&&d.InputReportCount==0&&d.HoldRepeatCount==0&&mockTimerStarts==0);
    }
    CHECK(!d.HoldTimerArmed);drain_one(&d,&q,&req[1]);
    GROUP("recovery_requires_fresh_press_orphan_move_and_release_rejected");
    CHECK(!feed(&d,1,2,555,666));CHECK(!feed(&d,1,3,555,666));CHECK(d.InputReportCount==0&&!d.Contacts[0].Active);
    CHECK(feed(&d,1,1,700,800));drain_one(&d,&q,&req[2]);committed(&d,0,1,700,800);
    GROUP("serial_same_id_reuse_after_recovery_commit_cannot_overtake_release_completion");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));drain_one(&d,&q,&req[0]);TouchQueueAllUpReport(&d);
    submit(&q,&req[1],64);submit(&q,&req[2],64);hookDevice=&d;hookNext=&req[2];hookMode=2;mockCompleteHook=before_completion;TouchDrainInputReports(&d);
    CHECK(req[1].data[1]==0&&req[2].data[1]==1&&req[1].completionOrdinal<req[2].completionOrdinal);committed(&d,0,1,300,400);
    GROUP("production_hold_timer_repeats_only_empty_live_queue");
    setup(&d,&q);CHECK(feed(&d,1,1,25,35));TouchHoldTimerFunc(d.HoldTimer);CHECK(d.InputReportCount==1&&d.HoldRepeatCount==0&&mockTimerStarts==1);
    drain_one(&d,&q,&req[0]);TouchHoldTimerFunc(d.HoldTimer);CHECK(d.InputReportCount==1&&d.HoldRepeatCount==1&&mockTimerStarts==2);
    drain_one(&d,&q,&req[1]);committed(&d,0,1,25,35);TouchStopInput(&d);unsigned starts=mockTimerStarts;
    TouchHoldTimerFunc(d.HoldTimer);TouchArmHoldTimer(&d);CHECK(mockTimerStarts==starts&&d.InputReportCount==0);
    GROUP("serial_mock_pending_read_cancel_never_advances_committed_state");
    setup(&d,&q);submit(&q,&req[0],64);q.count=0;req[0].completed=1;req[0].status=-9;
    CHECK(feed(&d,1,1,77,88));TouchDrainInputReports(&d);CHECK(d.Contacts[0].Active&&d.InputReportCount==1);committed(&d,0,0,0,0);
    drain_one(&d,&q,&req[1]);CHECK(req[0].completed==1&&req[1].data[1]==1);committed(&d,0,1,77,88);
    GROUP("serial_stop_after_copy_commit_defers_reset_until_completion_retirement");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));submit(&q,&req[0],64);submit(&q,&req[1],64);
    hookDevice=&d;hookNext=&req[1];hookMode=3;mockCompleteHook=before_completion;TouchDrainInputReports(&d);
    CHECK(req[0].completed==1&&req[0].status==0&&req[0].information==64&&!req[1].completed);
    CHECK(d.InputStopping&&!d.InputResetPending&&!d.InputDrainActive&&!d.RecoveryPending&&d.InputReportCount==0);committed(&d,0,0,0,0);
    GROUP("production_stop_rejects_ingress_and_clears_idle_recovery_state");
    setup(&d,&q);CHECK(feed(&d,1,1,1,2));drain_one(&d,&q,&req[0]);TouchQueueAllUpReport(&d);CHECK(d.RecoveryPending);
    TouchStopInput(&d);CHECK(d.InputStopping&&!d.InputResetPending&&d.InputReportCount==0&&!TouchAnyContactActiveLocked(&d)&&!d.RecoveryPending);CHECK(!feed(&d,1,2,2,3));committed(&d,0,0,0,0);
    GROUP("production_adapter_bounds_and_scan_time_rollover");
    setup(&d,&q);memset(&e,0,sizeof(e));e.Action=1;e.ContactIndex=10;CHECK(!TouchApplyDecodedEventLocked(&d,&e));e.ContactIndex=0;e.X=4096;CHECK(!TouchApplyDecodedEventLocked(&d,&e));CHECK(!TouchApplyDecodedEventLocked(&d,NULL));
    mockTime=65537ULL*1000;CHECK(feed(&d,1,1,1,2));CHECK(queued(&d,0)->DIG_TouchScreenScanTimeLow==1&&queued(&d,0)->DIG_TouchScreenScanTimeHigh==0);


    GROUP("EXP8_actual_producer_one60_one61_complete_batch_and_no_countdown_assumption");
    setup(&d,&q);d.Runtime.Stage=29;d.PollTimer=&d;d.LastDiagnosticTick=mockTime;
    poll_index=poll_records=poll_stops=poll_callbacks=poll_fail_at=poll_gap_at=poll_tail_calls=poll_clear_calls=poll_clear_fail=0;poll_count=3;
    packet(poll_packets[0],1,1,100,200,0,2);packet(poll_packets[1],1,2,300,400,0,7);packet(poll_packets[2],1,3,300,400,0,5);
    N976nPollTimer(&d);CHECK(poll_index==3&&poll_tail_calls==1&&!poll_clear_calls&&!poll_stops&&d.Runtime.Events==3&&d.Runtime.Lifecycle.Service.Completed==1&&d.Runtime.Lifecycle.Service.Packets==3);
    CHECK(d.InputReportCount==3&&mockTimerStarts==1);drain_one(&d,&q,&req[0]);drain_one(&d,&q,&req[1]);drain_one(&d,&q,&req[2]);CHECK(req[0].data[1]==1&&req[2].data[1]==0);
    GROUP("EXP8_actual_producer_max31_packets_stops_at_one_burst");
    setup(&d,&q);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;poll_index=poll_tail_calls=0;poll_count=31;
    for(unsigned k=0;k<31;++k)packet(poll_packets[k],1,k?2:1,100+k,200+k,0,k?30:30);
    N976nPollTimer(&d);CHECK(poll_index==31&&poll_tail_calls==1&&d.Runtime.Lifecycle.Service.Packets==31&&d.Runtime.Events==31&&mockTimerStarts==2);
    GROUP("EXP8_actual_producer_tail_semantic_error_delivers_none_and_keeps_committed_allup");
    setup(&d,&q);CHECK(feed(&d,1,1,100,200));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
    poll_index=poll_stops=poll_callbacks=poll_records=poll_tail_calls=0;poll_count=2;
    packet(poll_packets[0],1,2,300,400,0,1);memset(poll_packets[1],0,16);poll_packets[1][0]=3;
    N976nPollTimer(&d);CHECK(poll_stops==1&&d.Runtime.StopRequested&&!d.Runtime.Events&&!d.Runtime.Lifecycle.Service.Completed&&d.RecoveryPending&&!d.InputReportCount);
    CHECK(px(&d.RecoveryReport,0)==100&&py(&d.RecoveryReport,0)==200);
    GROUP("EXP8_actual_producer_remaining31_one_clear_allup_no_first_or_tail_delivery");
    setup(&d,&q);CHECK(feed(&d,1,1,101,202));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
    poll_index=poll_stops=poll_callbacks=poll_records=poll_tail_calls=poll_clear_calls=0;poll_count=1;packet(poll_packets[0],1,2,500,600,0,31);
    N976nPollTimer(&d);CHECK(poll_clear_calls==1&&!poll_tail_calls&&!poll_stops&&!d.Runtime.Events&&poll_records==1&&d.RecoveryPending&&!d.InputReportCount&&mockTimerStarts==1);
    drain_one(&d,&q,&req[1]);CHECK(req[1].data[1]==0&&!d.RecoveryPending);CHECK(!feed(&d,1,2,600,700)&&feed(&d,1,1,600,700));
    GROUP("EXP8_actual_producer_clear_failure_is_fatal_without_clear_loop");
    setup(&d,&q);d.Runtime.Stage=29;poll_index=poll_stops=poll_records=poll_clear_calls=poll_tail_calls=0;poll_clear_fail=1;
    N976nPollTimer(&d);CHECK(poll_clear_calls==1&&!poll_tail_calls&&poll_stops==1&&d.Runtime.StopRequested&&!mockTimerStarts);poll_clear_fail=0;
    GROUP("EXP8_actual_producer_60_recovery_discards_any_class_and_skips61");
    for(unsigned k=0;k<2;++k){setup(&d,&q);CHECK(feed(&d,1,1,111,222));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
      poll_index=poll_stops=poll_records=poll_tail_calls=poll_clear_calls=0;poll_gap_at=poll_count=1;memset(poll_packets[0],k?0xff:0,16);
      N976nPollTimer(&d);CHECK(!poll_stops&&!poll_tail_calls&&!poll_clear_calls&&poll_records==1&&!d.Runtime.Events&&d.RecoveryPending&&!d.Runtime.Lifecycle.Recovery.GapPending);
    }
    GROUP("EXP8_actual_producer_empty_no_tail_and_tail_failure_no_partial_HID");
    setup(&d,&q);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;poll_index=poll_gap_at=poll_tail_calls=poll_stops=0;poll_count=1;memset(poll_packets[0],0,16);
    N976nPollTimer(&d);CHECK(poll_index==1&&!poll_tail_calls&&!d.Runtime.Events&&!poll_stops&&mockTimerStarts==1);
    poll_index=0;poll_count=2;poll_fail_at=2;packet(poll_packets[0],1,1,300,400,0,1);
    N976nPollTimer(&d);CHECK(poll_tail_calls==1&&poll_stops==1&&!d.Runtime.Events&&!d.InputReportCount&&d.Runtime.StopRequested);
    GROUP("EXP8_actual_producer_failed61_defers_original_error_wipes_batch_committed_allup_20ms");
    setup(&d,&q);CHECK(feed(&d,1,1,101,202));drain_one(&d,&q,&req[0]);CHECK(feed(&d,1,2,999,888));
    d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;poll_index=poll_stops=poll_records=poll_tail_calls=poll_gap_at=0;
    poll_count=2;poll_fail_at=2;poll_tail_defer=1;packet(poll_packets[0],1,2,300,400,0,1);
    N976nPollTimer(&d);CHECK(poll_tail_calls==1&&!poll_stops&&!d.Runtime.StopRequested&&d.Runtime.Status==(ULONG)-20&&mockTimerStarts==1);
    CHECK(d.RecoveryPending&&px(&d.RecoveryReport,0)==101&&py(&d.RecoveryReport,0)==202&&!d.InputReportCount);
    CHECK(!d.Runtime.Lifecycle.Tail.GapPending&&d.Runtime.Lifecycle.Tail.AwaitingFresh&&!d.Runtime.Events&&poll_records==1);
    for(unsigned k=0;k<sizeof(d.Runtime.EventBatch);++k)CHECK(((UCHAR*)d.Runtime.EventBatch)[k]==0);
    GROUP("EXP8_actual_producer_empty_60gap_overflow_do_not_mark61_resumed_or_reset_streak");
    poll_tail_defer=poll_fail_at=0;poll_index=0;poll_count=1;memset(poll_packets[0],0,16);
    N976nPollTimer(&d);CHECK(d.Runtime.Lifecycle.Tail.Streak==1&&!d.Runtime.Lifecycle.Tail.Resumed&&d.RecoveryPending);
    poll_index=0;poll_gap_at=1;N976nPollTimer(&d);CHECK(d.Runtime.Lifecycle.Tail.Streak==1&&!d.Runtime.Lifecycle.Tail.Resumed);
    poll_index=poll_gap_at=0;packet(poll_packets[0],1,2,400,500,0,31);N976nPollTimer(&d);
    CHECK(d.Runtime.Lifecycle.Tail.Streak==1&&!d.Runtime.Lifecycle.Tail.Resumed&&d.RecoveryPending);
    GROUP("EXP8_actual_producer_validated_fresh_batch_resumes_but_MOVE_cannot_cross_allup_barrier");
    poll_index=0;packet(poll_packets[0],1,2,500,600,0,0);N976nPollTimer(&d);
    CHECK(d.Runtime.Lifecycle.Tail.Resumed==1&&!d.Runtime.Lifecycle.Tail.Streak&&!d.InputReportCount&&d.RecoveryPending);
    drain_one(&d,&q,&req[1]);CHECK(req[1].data[1]==0);poll_index=0;N976nPollTimer(&d);CHECK(!d.InputReportCount);
    poll_index=0;packet(poll_packets[0],1,1,700,800,0,0);N976nPollTimer(&d);CHECK(d.InputReportCount==1&&d.Runtime.Lifecycle.Tail.Resumed==1);
    drain_one(&d,&q,&req[2]);committed(&d,0,1,700,800);
    GROUP("EXP8_actual_producer_third61_terminal_keeps_original_pending_allup_and_stops");
    setup(&d,&q);CHECK(feed(&d,1,1,123,234));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
    poll_count=2;poll_fail_at=2;poll_tail_defer=1;poll_tail_calls=poll_stops=0;
    packet(poll_packets[0],1,2,700,800,0,1);
    for(unsigned k=0;k<2;++k){poll_index=0;N976nPollTimer(&d);if(!k)saved=d.RecoveryReport;CHECK(!memcmp(&saved,&d.RecoveryReport,sizeof(saved))&&!poll_stops);}
    CHECK(d.Runtime.Lifecycle.Tail.Streak==2&&mockTimerStarts==2);poll_index=0;poll_tail_defer=0;
    d.Runtime.Lifecycle.Tail.Streak=3;d.Runtime.Lifecycle.Tail.Disposition=N976nTailTerminal;
    N976nPollTimer(&d);CHECK(poll_tail_calls==3&&poll_stops==1&&d.Runtime.StopRequested&&mockTimerStarts==2);
    CHECK(!memcmp(&saved,&d.RecoveryReport,sizeof(saved))&&!d.Runtime.Events&&!d.InputReportCount);
    GROUP("EXP8_actual_producer_cancel_after61_eligibility_drops_without_reschedule_or_replay");
    setup(&d,&q);CHECK(feed(&d,1,1,111,222));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
    poll_index=poll_tail_calls=poll_stops=0;poll_count=2;poll_fail_at=2;poll_tail_defer=poll_tail_cancel=1;
    packet(poll_packets[0],1,2,600,700,0,1);N976nPollTimer(&d);
    CHECK(poll_tail_calls==1&&!poll_stops&&d.Runtime.StopRequested&&!mockTimerStarts&&d.RecoveryPending&&!d.InputReportCount);
    CHECK(!d.Runtime.Lifecycle.Tail.GapPending&&!d.Runtime.Events);poll_tail_defer=poll_tail_cancel=0;
    GROUP("RX1_real_service_lifts_old_contact_after_retired_head_and_accepts_only_fresh_press");
    setup(&d,&q);CHECK(feed(&d,1,1,101,202));drain_one(&d,&q,&req[0]);
    d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;poll_count=1;poll_index=poll_stops=poll_tail_calls=0;
    poll_gap_at=poll_tail_defer=0;poll_fail_at=poll_head_defer=1;poll_ready_mode=0;
    memset(d.Runtime.EventBatch,0xff,sizeof(d.Runtime.EventBatch));
    N976nPollTimer(&d);
    CHECK(d.RecoveryPending && !poll_stops && !d.Runtime.StopRequested && !d.Runtime.FirstRead.GapPending);
    CHECK(d.Runtime.FirstRead.AwaitingFresh && !poll_tail_calls && !d.InputReportCount && mockTimerStarts==1);
    for(unsigned k=0;k<sizeof(d.Runtime.EventBatch);++k) CHECK(!((UCHAR*)d.Runtime.EventBatch)[k]);
    drain_one(&d,&q,&req[1]);CHECK(!req[1].data[1]);
    poll_index=poll_fail_at=poll_head_defer=0;packet(poll_packets[0],1,2,444,555,0,0);
    N976nPollTimer(&d);CHECK(!d.InputReportCount && d.Runtime.FirstRead.Resumed==1);
    poll_index=0;packet(poll_packets[0],1,1,777,888,0,0);N976nPollTimer(&d);
    CHECK(d.InputReportCount==1);drain_one(&d,&q,&req[2]);committed(&d,0,1,777,888);
    GROUP("RX1_D0_cancel_joins_service_without_second_stop_or_rearm");
    setup(&d,&q);d.Runtime.Stage=29;poll_index=0;poll_count=poll_head_cancel=1;poll_stops=0;
    N976nPollTimer(&d);
    CHECK(d.Runtime.StopRequested && d.Runtime.Stage==29 && !poll_stops && !mockTimerStarts);
    poll_head_cancel=0;
    GROUP("EXP9_actual_producer_HIGH_skips_bus_preserves_error_allup_barrier_and_20ms");
    setup(&d,&q);CHECK(feed(&d,1,1,101,202));drain_one(&d,&q,&req[0]);TouchQueueAllUpReport(&d);
    d.Runtime.Stage=29;d.Runtime.Status=(ULONG)-20;d.Runtime.Lifecycle.Tail.Streak=1;d.Runtime.Lifecycle.Tail.AwaitingFresh=1;
    d.LastDiagnosticTick=mockTime;poll_index=poll_tail_calls=poll_clear_calls=poll_stops=poll_records=poll_ready_calls=0;poll_ready_mode=1;
    saved=d.RecoveryReport;N976nPollTimer(&d);
    CHECK(poll_ready_calls==1&&!poll_index&&!poll_tail_calls&&!poll_clear_calls&&!poll_stops&&mockTimerStarts==1);
    CHECK(d.Runtime.Status==(ULONG)-20&&d.Runtime.Lifecycle.Tail.Streak==1&&d.Runtime.Lifecycle.Tail.AwaitingFresh&&!memcmp(&saved,&d.RecoveryReport,sizeof(saved))&&d.RecoveryPending);
    GROUP("EXP9_actual_producer_LOW_normal_batch_one_gate_and_HIGH_keeps_hold_path");
    setup(&d,&q);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;poll_ready_mode=0;poll_ready_calls=poll_index=poll_fail_at=poll_gap_at=0;
    poll_count=2;packet(poll_packets[0],1,1,300,400,0,1);packet(poll_packets[1],1,2,500,600,0,0);
    N976nPollTimer(&d);CHECK(poll_ready_calls==1&&poll_index==2&&d.Runtime.Events==2&&!d.Runtime.StopRequested);
    poll_ready_mode=1;N976nPollTimer(&d);CHECK(poll_ready_calls==2&&poll_index==2&&d.HoldTimerArmed&&mockTimerStarts>=2);
    GROUP("EXP9_actual_producer_ready_failure_stops_before_service_and_keeps_allup");
    setup(&d,&q);CHECK(feed(&d,1,1,111,222));drain_one(&d,&q,&req[0]);d.Runtime.Stage=29;d.LastDiagnosticTick=mockTime;
    poll_ready_mode=2;poll_index=poll_stops=poll_ready_calls=0;N976nPollTimer(&d);
    CHECK(poll_ready_calls==1&&!poll_index&&poll_stops==1&&d.Runtime.StopRequested&&d.RecoveryPending&&!mockTimerStarts);poll_ready_mode=0;
    printf("PASS %u groups\n",groups);return 0;
}
