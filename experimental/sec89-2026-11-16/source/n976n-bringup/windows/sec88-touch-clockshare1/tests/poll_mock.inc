
#include "N976nDemoLifecycle.h"
typedef struct {volatile LONG StopRequested;ULONG Quarantined,Stage,Status,Events,LastX,LastY,LastAction;
 N976N_FIRST_RECOVERY FirstRead;N976N_DEMO_LIFECYCLE Lifecycle;UCHAR EventBatch[31][16];} N976N_DEMO_RUNTIME;
typedef N976N_DEMO_RUNTIME POLL_RUNTIME;
static unsigned poll_ready_mode,poll_ready_calls;
static NTSTATUS N976nDemoEventReady(POLL_RUNTIME *R,BOOLEAN *Ready){
 ++poll_ready_calls;*Ready=poll_ready_mode==0;(void)R;return poll_ready_mode==2?-20:0;
}
static unsigned poll_head_defer,poll_head_cancel;
#define STATUS_CANCELLED ((NTSTATUS)0xC0000120L)
static unsigned poll_index,poll_count,poll_records,poll_stops,poll_callbacks,poll_gap_at,poll_fail_at;
static unsigned char poll_packets[32][16];
static unsigned poll_tail_calls,poll_clear_calls,poll_clear_fail,poll_tail_defer,poll_tail_cancel;
static NTSTATUS N976nDemoReadEvent(POLL_RUNTIME *R,UCHAR B[16]){
 ++R->Lifecycle.Service.ReadOne;R->Lifecycle.Service.LastRemaining=R->Lifecycle.Service.LastCount=R->Lifecycle.Service.LastBytes=0;
 mockAssert(poll_index<poll_count,"unexpected producer read");++poll_index;
 if(poll_head_cancel){R->StopRequested=1;return STATUS_CANCELLED;}
 if(poll_fail_at==poll_index){
    if(poll_head_defer){R->Status=(ULONG)-20; R->FirstRead.GapPending=R->FirstRead.AwaitingFresh=1; ++R->FirstRead.Clears; ++R->FirstRead.Streak;}
    return -20;
 }
 memcpy(B,poll_packets[poll_index-1],16);
 if(poll_gap_at==poll_index){R->Lifecycle.Recovery.GapPending=1;++R->Lifecycle.Recovery.Recovered;}
 return 0;
}
static NTSTATUS N976nDemoReadTail(POLL_RUNTIME *R,ULONG N){
 mockAssert(N>=1&&N<=30&&poll_index+N<=poll_count,"bounded tail");++poll_tail_calls;++R->Lifecycle.Service.ReadAll;
 if(poll_fail_at==poll_index+1){
  if(poll_tail_defer){++R->Lifecycle.Tail.Deferred;R->Lifecycle.Tail.GapPending=R->Lifecycle.Tail.AwaitingFresh=1;
   R->Lifecycle.Tail.Disposition=N976nTailDeferred;++R->Lifecycle.Tail.Streak;
   R->Status=(ULONG)-20;if(poll_tail_cancel)R->StopRequested=1;}
  return -20;
 }
 memcpy(((UCHAR*)R->EventBatch)+16,((UCHAR*)poll_packets)+poll_index*16,N*16);poll_index+=N;R->Lifecycle.Service.LastBytes=N*16;return 0;
}
static NTSTATUS N976nDemoClearEvents(POLL_RUNTIME *R){++poll_clear_calls;++R->Lifecycle.Service.ClearAttempts;
 if(poll_clear_fail)return -20;++R->Lifecycle.Service.Cleared;return 0;}
static void N976nDemoRecord(POLL_RUNTIME *R){(void)R;++poll_records;}
static void N976nDemoCallback(POLL_RUNTIME *R,unsigned C){(void)R;(void)C;++poll_callbacks;}
static int N976nDemoStop(POLL_RUNTIME *R){(void)R;++poll_stops;return 0;}
#define N976nLifePollFailure 6
#define STATUS_DEVICE_DATA_ERROR (-21)
