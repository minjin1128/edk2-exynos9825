/* Exercise the real miniport and core with the preserved bounded HCI fixture. */
#define main preserved_lifecycle_main
#include "lifecycle_cases.c"
#undef main
#include <stdlib.h>
static _Alignas(8) U8 Packet[NUF_TRACE_WIRE_OFFSET+sizeof(NUF_TRACE_SNAPSHOT)+16];
static NUF_TRACE_SNAPSHOT Before;
static void packet(void){
 memset(Packet,0,sizeof(Packet));memset(Packet+sizeof(Packet)-16,0xE7,16);
 SRB_IO_CONTROL *c=(void*)Packet;c->HeaderLength=28;c->ControlCode=NUF_TRACE_CONTROL;
 c->Length=sizeof(NUF_TRACE_SNAPSHOT)+4;c->ReturnCode=0xDEADBEEF;memcpy(c->Signature,"N976UFS",8);
 NUF_TRACE_SNAPSHOT *r=(void*)(Packet+32);r->Magic=NUF_TRACE_MAGIC;r->Version=NUF_TRACE_VERSION;
 r->Bytes=sizeof(*r);r->Driver=NUF_TRACE_DRIVER;
}
static U32 query(U32 bytes){
 SCSI_REQUEST_BLOCK s={0};s.Function=SRB_FUNCTION_IO_CONTROL;s.DataBuffer=Packet;s.DataTransferLength=bytes;
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;
 for(U32 i=sizeof(Packet)-16;i<sizeof(Packet);i++)assert(Packet[i]==0xE7);
 return s.SrbStatus;
}
static NUF_TRACE_RECORD *last(void){return &Adapter.Trace.Record[(Adapter.Trace.NextRecord+NUF_TRACE_CAPACITY-1)%NUF_TRACE_CAPACITY];}
static void rd(SCSI_REQUEST_BLOCK *s,NUF_REQUEST *q){read_srb(s,q,Buffer,0x222300);submit(s);run_worker();assert(s->SrbStatus==SRB_STATUS_SUCCESS);}
static void emit(const char *name){
 const char *dir=getenv("N976N_TRACE_EVIDENCE");if(!dir)return;char path[1024];
 assert(snprintf(path,sizeof(path),"%s/%s",dir,name)>0);FILE *f=fopen(path,"wb");assert(f);
 assert(fwrite(&Adapter.Trace,1,sizeof(Adapter.Trace),f)==sizeof(Adapter.Trace));assert(!fclose(f));
}
int main(void){
 SCSI_REQUEST_BLOCK s;NUF_REQUEST q;U32 start,reads,writes;
 NufTraceLatest=NULL;setup();find();assert(!NufTraceLatest);PassiveEnabled=FALSE;assert(!initialize()&&!NufTraceLatest);
 NufTraceLatest=NULL;setup();find();assert(initialize());MapFailure=1;assert(!passive()&&!NufTraceLatest);
 ready();assert(NufTraceLatest==&Adapter.Trace);
 for(U32 fault=0;fault<2;fault++){
  SCSI_PNP_REQUEST_BLOCK pnp={0};pnp.Function=SRB_FUNCTION_PNP;pnp.Length=sizeof(pnp)-(fault==0);
  pnp.SrbPnPFlags=SRB_PNP_FLAGS_ADAPTER_REQUEST|(fault==1?0x80:0);pnp.PnPAction=StorRemoveDevice;
  Irql=2;assert(StartIo(&Adapter,(PSCSI_REQUEST_BLOCK)&pnp));Irql=0;
  assert(pnp.SrbStatus==SRB_STATUS_INVALID_REQUEST&&NufTraceLatest==&Adapter.Trace);
 }
 pass("trace1_locator_only_after_admission_invalid_pnp_cannot_clear");

 ready();start=Submits;rd(&s,&q);NUF_TRACE_RECORD *r=last();NUF_TRACE_BIN *b=&Adapter.Trace.Bin[PerfRead4K];
 assert(NufTraceHeaderValid(&Adapter.Trace)&&Submits==start+1&&Adapter.Trace.Attempts==1&&Adapter.Trace.Published==1);
 assert(r->Flags==NUF_TRACE_VALID_TIMING&&r->Sequence==1&&r->T0<r->Worker&&r->Worker<r->T1[0]&&r->T1[0]<r->T2[0]&&r->T2[0]<r->T3);
 assert(r->GuardPreTicks&&r->GuardPostTicks&&r->ReadCopyTicks&&!r->WriteCopyTicks&&r->Commands==1);
 assert(b->Valid==1&&b->TotalTicks==b->QueueTicks+b->PrepareTicks+b->DeviceTicks+b->BetweenTicks+b->FinishTicks);
 assert(b->GuardPreTicks+b->GuardPostTicks==Adapter.Engine.PerfGuardTicks&&b->ReadCopyTicks==r->ReadCopyTicks);
 pass("trace1_four_boundaries_guard_pre_post_and_read_copy_real_core");
 Before=Adapter.Trace;reads=Reads;writes=Writes;packet();
 assert(query(sizeof(Packet)-16)==SRB_STATUS_SUCCESS&&!memcmp(&Before,Packet+32,sizeof(Before)));
 assert(!memcmp(&Before,&Adapter.Trace,sizeof(Before))&&reads==Reads&&writes==Writes&&Submits==start+1);
 pass("trace1_snapshot_is_exact_readonly_ram_no_clock_mmio_or_io_sequence");
 for(U32 fault=0;fault<10;fault++){
  packet();SRB_IO_CONTROL *c=(void*)Packet;NUF_TRACE_SNAPSHOT *in=(void*)(Packet+32);U32 bytes=sizeof(Packet)-16;
  if(fault==0)c->HeaderLength--;if(fault==1)c->Signature[0]^=1;if(fault==2)c->ControlCode++;
  if(fault==3)c->Length--;if(fault==4)Packet[28]=1;if(fault==5)in->Version++;
  if(fault==6)in->Magic++;if(fault==7)in->Bytes--;if(fault==8)bytes--;if(fault==9)in->Driver++;
  assert(query(bytes)==SRB_STATUS_INVALID_REQUEST&&!memcmp(&Before,&Adapter.Trace,sizeof(Before)));
 }
 pass("trace1_query_rejects_malformed_length_signature_control_pad_version_magic");
 ready();U32 cursorSeen=0;start=Submits;
 for(U32 i=0;i<1040;i++){
  rd(&s,&q);if(i%65==0){r=last();assert(r->Sequence==i+1);cursorSeen|=1U<<r->CursorBefore;}
 }
 assert(Submits==start+1040&&Adapter.Trace.Published==16&&cursorSeen==0xFFFF&&Adapter.Trace.Bin[0].Valid==16);
 assert(Adapter.Trace.Attempts==1040&&Adapter.Trace.Period==65);emit("before.bin");Before=Adapter.Trace;
 for(U32 i=1040;i<65*(NUF_TRACE_CAPACITY+2);i++)rd(&s,&q);
 assert(Adapter.Trace.Published==NUF_TRACE_CAPACITY+2&&Adapter.Trace.Overwritten==2&&Adapter.Trace.RecordCount==NUF_TRACE_CAPACITY);
 assert(last()->Sequence==65*(NUF_TRACE_CAPACITY+1)+1&&NufTraceHeaderValid(&Adapter.Trace));emit("after.bin");
 pass("trace1_65_interval_visits_all_guard_phases_and_bounded_ring_wrap_is_explicit");
 ready();write_srb(&s,&q,Buffer,0x222300,0,1);submit(&s);run_worker();r=last();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&r->Commands==2&&r->Flags==(NUF_TRACE_VALID_TIMING|NUF_TRACE_TWO_COMMANDS));
 assert(r->T0<r->T1[0]&&r->T1[0]<r->T2[0]&&r->T2[0]<r->T1[1]&&r->T1[1]<r->T2[1]&&r->T2[1]<r->T3);
 assert(r->WriteCopyTicks&&!r->ReadCopyTicks&&Flushes==1&&r->GuardPreTicks&&r->GuardPostTicks);
 pass("trace1_fua_two_commands_write_copy_and_real_flush_preserved");
 ready();CommandFault=3;FaultOpcode=0x35;write_srb(&s,&q,Buffer,0x222300,0,1);submit(&s);run_worker();r=last();
 assert(s.SrbStatus!=SRB_STATUS_SUCCESS&&(r->Flags&NUF_TRACE_STORAGE_FAILED)&&!(r->Flags&NUF_TRACE_VALID_TIMING));
 assert(r->Commands==2&&Adapter.Trace.Bin[PerfFua4K].Failed==1&&!Adapter.Trace.Bin[PerfFua4K].Valid);
 pass("trace1_failed_fua_never_becomes_success_latency_sample");
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);Dma[0]^=1;run_worker();r=last();
 assert((r->Flags&NUF_TRACE_STORAGE_FAILED)&&r->Commands==0&&!r->ReadCopyTicks&&!r->T1[0]&&!r->T2[0]);
 assert(r->GuardPreTicks&&!r->GuardPostTicks&&Adapter.Engine.Quarantined);
 pass("trace1_pre_guard_failure_keeps_partial_evidence_without_issue_copy");
 ready();Fault=2;read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();r=last();
 assert((r->Flags&NUF_TRACE_STORAGE_FAILED)&&r->Commands==1&&!r->ReadCopyTicks&&r->GuardPostTicks);
 pass("trace1_post_guard_failure_never_publishes_payload_copy");
 ready();RejectPerfClock=1;rd(&s,&q);RejectPerfClock=0;r=last();
 assert((r->Flags&NUF_TRACE_TIMING_INVALID)&&!(r->Flags&NUF_TRACE_STORAGE_FAILED)&&Adapter.Trace.Bin[0].Invalid==1);
 assert(!Adapter.Trace.Bin[0].Valid&&Adapter.Trace.InvalidTimings==1&&!Adapter.Stop);emit("clock-invalid.bin");
 pass("trace1_invalid_clock_only_invalidates_diagnostics");
 for(U32 mode=0;mode<3;mode++){
  ready();rd(&s,&q);Adapter.Perf.QueueAttempts[0]=65;
  ZeroPerfClock=mode==0;ReversePerfClock=mode==1;PerfFrequencyOverride=mode==2?2000000:0;
  rd(&s,&q);ZeroPerfClock=ReversePerfClock=0;PerfFrequencyOverride=0;r=last();
  assert((r->Flags&NUF_TRACE_TIMING_INVALID)&&!(r->Flags&NUF_TRACE_STORAGE_FAILED)&&!Adapter.Stop);
 }
 pass("trace1_zero_reverse_frequency_drift_never_changes_io_success");

 ready();WorkerQueueStatus=STOR_STATUS_BUSY;read_srb(&s,&q,Buffer,0x222300);submit(&s);r=last();
 assert(s.SrbStatus==SRB_STATUS_BUSY&&r->Sequence==1&&!r->Worker&&!r->Commands&&NufTraceHeaderValid(&Adapter.Trace));
 U64 first=r->T0;WorkerQueueStatus=0;Irql=2;assert(StartIo(&Adapter,&s));Irql=0;run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&q.StartIoTick>first&&Adapter.Trace.Attempts==2&&!q.TraceActive);
 pass("trace1_queue_failure_and_no_buildio_resubmit_do_not_reuse_timestamp");
 ready();SCSI_REQUEST_BLOCK second;NUF_REQUEST q2;read_srb(&second,&q2,Buffer,0x222301);
 read_srb(&s,&q,Buffer,0x222300);submit(&s);ReenterSrb=&second;run_worker();run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&second.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Trace.Attempts==2&&Adapter.Trace.Published==1);
 assert(NufTraceHeaderValid(&Adapter.Trace)&&!Adapter.Busy&&!q.TraceActive&&!q2.TraceActive);
 pass("trace1_completion_reentry_preserves_finished_record_and_new_request");
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);assert(Adapter.Trace.Generation&1);packet();
 assert(query(sizeof(Packet)-16)==SRB_STATUS_BUSY&&(Adapter.Trace.Generation&1));run_worker();
 assert(NufTraceHeaderValid(&Adapter.Trace));
 pass("trace1_busy_inflight_snapshot_refused_then_idle_even_publication");
 printf("ABI %zu %zu %zu %zu %zu\n",sizeof(NUF_TRACE_SNAPSHOT),sizeof(NUF_TRACE_RECORD),sizeof(NUF_TRACE_BIN),offsetof(NUF_TRACE_SNAPSHOT,Bin),offsetof(NUF_TRACE_SNAPSHOT,Record));
 return 0;
}
