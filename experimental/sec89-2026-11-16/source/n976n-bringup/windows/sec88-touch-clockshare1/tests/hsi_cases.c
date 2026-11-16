/* Actual SEC76 engine with a scripted peripheral, not physical MMIO proof. */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "N976nHsi2c.h"
#ifndef N976N_EXP4_TRANSPORT_BASELINE
#include "N976nHsiWaitShape.h"
#endif
static uint64_t trace=1469598103934665603ULL;
static void tr(uint64_t A){trace^=A;trace*=1099511628211ULL;}
static unsigned groups;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while (0)
#define GROUP(n) do { puts(n); ++groups; } while (0)
enum { Normal, ReadbackDiff, ShortRx, ExtraRx, MissingDone, BusyForever,
       ControllerError, UnknownIrq, AckStuck, RxIoFailure, RunIoFailure,
       LoseOwner, CancelAfterTx, CancelDuringRx, StalledCounter,
       BackwardCounter, SetupIoFailure, ErrorAtIdle, ConfBad, UsiBad,
       InitialBusy, InitialPending, Inaccessible, RxFull, ZeroId,
       UnknownAfterFirst, WrongAuto, ExtraDuringTx, LiveTimingBad, TimingChanged,
       RxNoDataWall, RxNoDataLoop, RxWallLastLoop, RxDoneLastLoop, RxBackward, RxPartialSample, RxProgressLong, RxRollbackAboveStart,
       RxStallAfterAdvance, RxLongPlateauProgress, IdleLongProgress, IdleFrozen, ArmBadTx, ArmBadRx, MaskedNoAck, MaskedErrorDone, MaskedAbort, MaskedNoDevice, MaskedTimeout, AckMaskBad, AckPendingIo, AckAfterIo, InitialOwnerLoss, AckZeroPending };
typedef struct {
    uint32_t regs[64];
    unsigned mode, phase, tx, rx, reads, writes, run, cycles, acks;
    unsigned rx_empty_reads, all_acks, lost_reads, io_failed, now_calls;
    unsigned cancel_calls, owned_calls, read_log[4];
    uint64_t now;
    struct { unsigned offset,value; } log[80];
} MODEL;

static void Tick(MODEL *M)
{
    if (!M->phase) return;
    ++M->cycles;
    if (M->phase==1 && M->tx==0) {
        M->regs[0x24/4]=0; M->regs[0x50/4]=0x2000A;
        M->regs[0x30/4]=0x01000100; return;
    }
    if (M->mode==BusyForever || M->mode==RunIoFailure) {
        M->regs[0x24/4]=0;M->regs[0x50/4]=0x2000A;return;
    }
    if(M->phase==2 && M->mode>=MaskedNoAck && M->mode<=MaskedTimeout){
        unsigned error=M->mode==MaskedAbort?0x100:M->mode==MaskedNoDevice?0x400:M->mode==MaskedTimeout?0x800:0x200;
        /* Scripted visibility model: source-enabled error persists until W1C.
         * This conditional latch is a hypothesis test, not hardware proof. */
        M->regs[0x24/4]|=error&M->regs[0x20/4];
        if(M->mode==MaskedErrorDone && (M->regs[0x24/4]&error))M->regs[0x24/4]|=0x80;
        M->regs[0x50/4]=0x80001;M->regs[0x30/4]=0x01000100;M->regs[0x44/4]&=~0x80000000U;return;
    }
    if(M->phase==2 && M->mode>=RxNoDataWall&&M->mode<IdleLongProgress){
        M->regs[0x24/4]=0;M->regs[0x50/4]=0x80001;M->regs[0x30/4]=0x01000100;M->regs[0x44/4]&=~0x80000000U;
        if(M->mode==RxProgressLong){
            if(M->cycles<6){M->regs[0x50/4]=0xA0002;M->regs[0x44/4]|=0x80000000U;}
            if(M->cycles>=25000){if(M->rx<3){M->regs[0x30/4]=0x100;M->regs[0x50/4]=0x20009;}
                else M->regs[0x24/4]=0x80;}
        }
        if(M->mode==RxDoneLastLoop){
            if(M->rx<3){M->regs[0x30/4]=0x100;M->regs[0x50/4]=0x20009;}
            else if(M->cycles>=N976N_HSI_MAX_POLLS)M->regs[0x24/4]=0x80;
        }
        return;
    }
    if (M->phase==2) {
        unsigned count=M->mode==ShortRx?2U:M->mode==ExtraRx?4U:3U;
        if(M->rx<count) {
            M->regs[0x24/4]=0; M->regs[0x50/4]=0x20009;
            /* Level0 deliberately disagrees; RX_EMPTY still authorizes one. */
            M->regs[0x30/4]=0x100;
            if(M->mode==RxFull)M->regs[0x30/4]|=0x800000;
            return;
        }
    }
    M->regs[0x24/4]=M->mode==MissingDone || M->mode==StalledCounter || M->mode==BackwardCounter?0:0x80;
    M->regs[0x50/4]=1;M->regs[0x30/4]=0x01000100;
    M->regs[0x44/4]&=~0x80000000U;
    if(M->mode==ControllerError)M->regs[0x24/4]=0x200;
    if(M->mode==UnknownIrq)M->regs[0x24/4]=0x1000;
    if(M->mode==ErrorAtIdle && M->cycles>2)M->regs[0x24/4]|=0x200;
    if(M->mode==UnknownAfterFirst)M->regs[0x24/4]=M->cycles<=2?0x200:0x1000;
    if(M->mode==WrongAuto)M->regs[0x44/4]|=0x80000000U;
    if((M->mode==IdleLongProgress&&M->cycles<25005)||M->mode==IdleFrozen){M->regs[0x50/4]=0x2000A;M->regs[0x44/4]|=0x80000000U;}
    if(M->mode==ExtraDuringTx && M->phase==1)M->regs[0x30/4]=0x100;
}
static int read32(void *P,uint32_t O,uint32_t *V)
{
    MODEL *M=P;tr(0x100000000ULL|O);
    CHECK(O%4==0 && O<=0xC4);
    CHECK(O==0 || O==4 || O==8 || O==0x20 || O==0x24 || O==0x30 || O==0x38 ||
          O==0x40 || O==0x44 || O==0x48 || O==0x50 || O==0x60 || O==0x64 || O==0x68 || O==0x70 || O==0xC4);
    ++M->reads;
    if(M->mode==LoseOwner && M->tx)++M->lost_reads;
    if(O==0x24)Tick(M);
    if(O==0x50&&M->phase==2&&M->mode==RxPartialSample&&!M->io_failed){M->io_failed=1;return 0;}
    if(O==0x38) {
        static const uint32_t bytes[]={0x5D420CAC,0xC0FFEE37,0xFEDCBA71};
        CHECK(!(M->regs[0x30/4]&0x01000000));
        CHECK(M->phase==2 && M->rx<3);
        if(M->mode==RxIoFailure && !M->io_failed){M->io_failed=1;return 0;}
        M->read_log[M->rx]=M->regs[0x30/4];
        *V=M->mode==ZeroId?0:bytes[M->rx];++M->rx;return 1;
    }
    if(O==0x24 && !M->regs[0x20/4] && M->run && !M->io_failed &&
       ((M->mode==AckPendingIo && M->phase)||(M->mode==AckAfterIo && !M->phase))){M->io_failed=1;return 0;}
    *V=M->regs[O/4];
    if(O==0x20 && M->regs[O/4] && ((M->mode==ArmBadTx && M->run==0)||(M->mode==ArmBadRx && M->run==1)))*V=0x80;
    if(O==0x20 && M->mode==AckMaskBad && !M->regs[O/4] && M->run)*V=0x80;
    if(O==0 && M->mode==ReadbackDiff)*V&=~0xC0U;
    if(O==0x30 && (*V&0x01000000))++M->rx_empty_reads;
    return 1;
}
static int write32(void *P,uint32_t O,uint32_t V)
{
    MODEL *M=P;tr(0x200000000ULL|O);tr(O==0x20&&V==0xF80?0x80:V); /* authorized arm-mask difference only */
    CHECK(O==0 || O==4 || O==0x20 || O==0x24 || O==0x34 || O==0x44 || O==0x70);
    CHECK(!(O==0 && (V&0x80000000))); /* no software reset */
    CHECK(M->writes<80);M->log[M->writes].offset=O;M->log[M->writes].value=V;++M->writes;
    if(M->mode==SetupIoFailure && O==4 && !M->io_failed){M->io_failed=1;return 0;}
    if(O==0x34){CHECK(M->phase==1 && M->tx==0 && V==0x52);++M->tx;return 1;}
    if(O==0x24){
        CHECK(V!=0 && !(V&~0xFFFU));++M->all_acks;
        CHECK(V==M->regs[0x24/4]);
        if(M->mode!=AckStuck){M->regs[0x24/4]&=~V;M->phase=0;++M->acks;}
        if(M->mode==TimingChanged)M->regs[0x68/4]^=0x10000;
        return 1;
    }
    if(O==0x20&&V==0&&M->mode==AckZeroPending&&M->phase){M->regs[0x24/4]=0;M->phase=0;}
    M->regs[O/4]=V;
    if(O==0x44 && (V&0x80000000)) {
        CHECK(V&0x20000); /* mandatory STOP on both standalone messages */
        CHECK(M->run<2);++M->run;M->phase=V&0x10000?2U:1U;M->cycles=0;
        CHECK((M->phase==1 && V==0x80020001) || (M->phase==2 && V==0x80030003));
        if(M->mode==RunIoFailure && !M->io_failed){M->io_failed=1;return 0;}
    }
    return 1;
}
static uint64_t now_us(void *P)
{
    MODEL *M=P;++M->now_calls;tr(3);
    if(M->mode==IdleLongProgress)return M->cycles;
    if(M->mode==IdleFrozen)return 0;
    if(M->mode>=RxNoDataWall&&M->run==2){
        if(M->mode==RxBackward)return !M->cycles?500:M->cycles==1?600:0;
        if(M->mode==RxNoDataLoop)return 0;
        if(M->mode==RxProgressLong)return M->cycles;
        if(M->mode==RxRollbackAboveStart)return !M->cycles?500:M->cycles==1?600:550;
        if(M->mode==RxStallAfterAdvance)return M->cycles<5?(uint64_t)M->cycles*100:500;
        if(M->mode==RxLongPlateauProgress)return ((uint64_t)M->cycles/19000)*40000;
        if(M->mode==RxWallLastLoop||M->mode==RxDoneLastLoop)return (uint64_t)M->cycles*5;
    }
    if(M->mode==StalledCounter)return 0;
    if(M->mode==BackwardCounter)return M->now_calls==1?100:0;
    M->now+=10000;return M->now;
}
static int still_owned(void *P,uint64_t Generation)
{
    MODEL *M=P;++M->owned_calls;tr(4);tr(Generation);CHECK(Generation==17);
    return M->mode!=InitialOwnerLoss && !(M->mode==LoseOwner && M->tx);
}
static int cancelled(void *P)
{
    MODEL *M=P;++M->cancel_calls;tr(5);
    return (M->mode==CancelAfterTx && M->acks==1) ||
           (M->mode==CancelDuringRx && M->rx==2);
}
static void fixture(MODEL *M,unsigned Mode,N976N_HSI_IO *Io,N976N_HSI_LEASE *L)
{
    memset(M,0,sizeof(*M));M->mode=Mode;
    M->regs[0x30/4]=0x01000100;M->regs[0x50/4]=1;
    M->regs[0x40/4]=0x80000000;M->regs[0]=8;
    M->regs[8/4]=0xFFFFFF;M->regs[0x60/4]=0xFC0000;
    M->regs[0x64/4]=0xF8;M->regs[0x68/4]=0x3E0000;
    if(Mode==ConfBad)M->regs[0x40/4]=0xC0000000;
    if(Mode==UsiBad)M->regs[0xC4/4]=1;
    if(Mode==InitialBusy)M->regs[0x50/4]=0x2000A;
    if(Mode==InitialPending)M->regs[0x24/4]=0x80;
    if(Mode==Inaccessible)M->regs[0x30/4]=0xFFFFFFFF;
    if(Mode==LiveTimingBad)M->regs[0x60/4]^=0x10000;
    *Io=(N976N_HSI_IO){M,read32,write32,now_us,still_owned,cancelled};
    *L=(N976N_HSI_LEASE){17,0x104B0000,0x1000,100000000,N976nHsiLeaseRequired,0x48,100000,
        0xFC0000,0xF8,0x3E0000,0,0xFFFFFF};
}
static N976N_HSI_RESULT run(unsigned Mode,MODEL *M)
{
    N976N_HSI_IO Io;N976N_HSI_LEASE L;
    struct {uint64_t before;N976N_HSI_RESULT r;uint64_t after;} out;
    fixture(M,Mode,&Io,&L);memset(&out,0xA5,sizeof(out));out.before=0x123456789ABCDEF0ULL;out.after=~out.before;
    CHECK(N976nHsiReadId(&Io,&L,&out.r)==out.r.Status);
    CHECK(out.before==0x123456789ABCDEF0ULL && out.after==~out.before);
    CHECK(M->rx<=3 && M->run<=2 && out.r.Polls<=N976N_HSI_MAX_POLLS*5);
    CHECK(!(out.r.Retired && out.r.Quarantined));
    CHECK(out.r.Reads==M->reads && out.r.Writes==M->writes);
    tr(out.r.Status);tr(out.r.FirstPhase);tr(out.r.CleanupStatus);tr(out.r.MessagesIssued);tr(out.r.TxBytes);tr(out.r.RxBytes);tr(out.r.Retired);tr(out.r.Quarantined);tr(out.r.Reads);tr(out.r.Writes);tr(out.r.Polls);tr(out.r.Id);
    return out.r;
}
int main(void)
{
    MODEL M;N976N_HSI_RESULT R;N976N_HSI_IO Io;N976N_HSI_LEASE L;
    GROUP("hsi_id_exact_stop_pair_and_completion_retirement");
    R=run(Normal,&M);CHECK(R.Status==0 && R.IdValid && R.Id==0xAC3771 && R.Retired);
    CHECK(R.MessagesIssued==2 && R.TxBytes==1 && R.RxBytes==3 && M.acks==2 && R.SetupSeen==10);
    CHECK(M.regs[0x20/4]==0 && M.regs[0x24/4]==0 && !(M.regs[0x44/4]&0x80000000));
    GROUP("hsi_rx_empty_controls_each_dequeue_upper24bits_not_payload");
    CHECK(M.rx==3 && M.rx_empty_reads>3);for(unsigned i=0;i<3;i++)CHECK(M.read_log[i]==0x100);
    GROUP("hsi_readback_difference_is_evidence_not_false_stop");
    R=run(ReadbackDiff,&M);CHECK(R.IdValid && R.SetupMismatch==2 && R.FirstSetupOffset==0);
    CHECK(R.FirstSetupExpected==0x88 && R.FirstSetupActual==8);
    GROUP("hsi_zero_id_is_raw_transport_not_chip_identity_claim");
    R=run(ZeroId,&M);CHECK(R.IdValid && R.Id==0);
    GROUP("hsi_invalid_lease_no_callbacks_or_register_access");
    for(unsigned i=0;i<13;i++) {
        fixture(&M,Normal,&Io,&L);
        switch(i){case 0:L.Generation=0;break;case 1:L.Base+=4;break;case 2:L.Bytes=0x1001;break;
          case 3:L.Address=0x49;break;case 4:L.SpeedHz=400000;break;
          case 5:L.Flags|=128;break;default:L.Flags&=~(1U<<(i-6));break;}
        CHECK(N976nHsiReadId(&Io,&L,&R)==N976nHsiInvalid);
        CHECK(M.reads==0 && M.writes==0 && M.owned_calls==0 && M.now_calls==0 && !R.IdValid);
    }
    GROUP("hsi_null_callbacks_and_result_rejected");
    fixture(&M,Normal,&Io,&L);CHECK(N976nHsiReadId(&Io,&L,NULL)==N976nHsiInvalid);
    CHECK(N976nHsiReadId(NULL,&L,&R)==N976nHsiInvalid);
    CHECK(N976nHsiReadId(&Io,NULL,&R)==N976nHsiInvalid);
    for(unsigned i=0;i<4;i++){fixture(&M,Normal,&Io,&L);switch(i){case 0:Io.Read32=NULL;break;case 1:Io.Write32=NULL;break;case 2:Io.NowUs=NULL;break;case 3:Io.StillOwned=NULL;break;}CHECK(N976nHsiReadId(&Io,&L,&R)==N976nHsiInvalid);CHECK(!M.reads&&!M.writes);}
    GROUP("hsi_unprepared_unknown_or_foreign_initial_state_no_writes");
    for(unsigned i=ConfBad;i<=Inaccessible;i++){R=run(i,&M);CHECK(R.Status==N976nHsiInitialState && !M.writes && !M.run && !R.IdValid);}
    GROUP("hsi_short_receive_retires_but_never_publishes_id");
    R=run(ShortRx,&M);CHECK(R.Status==N976nHsiTimeout && R.RxBytes==2 && R.Retired && !R.IdValid);
    GROUP("hsi_extra_receive_is_not_dequeued_and_quarantines");
    R=run(ExtraRx,&M);CHECK(R.Status==N976nHsiExcess && M.rx==3 && R.Quarantined && !R.IdValid);
    GROUP("hsi_rx_full_flag_without_overrun_drains_bounded_payload");
    R=run(RxFull,&M);CHECK(R.Status==N976nHsiOk && M.rx==3 && R.Retired && !R.Quarantined && R.IdValid);
    GROUP("hsi_missing_done_does_not_invent_completion");
    R=run(MissingDone,&M);CHECK(R.Status==N976nHsiTimeout && R.Retired && M.run==1 && !R.IdValid);
    GROUP("hsi_busy_timeout_no_reset_retry_or_fake_retirement");
    R=run(BusyForever,&M);CHECK(R.Status==N976nHsiTimeout && R.CleanupStatus==N976nHsiIdle && R.Quarantined && M.run==1 && !M.acks);
    GROUP("hsi_known_controller_error_ack_preserves_failure");
    R=run(ControllerError,&M);CHECK(R.Status==N976nHsiController && R.FirstPhase==3 && R.FirstFailure.Interrupt==0x200 && R.Retired && M.run==1);
    GROUP("hsi_unknown_irq_never_acknowledged");
    R=run(UnknownIrq,&M);CHECK(R.Status==N976nHsiController && R.Quarantined && !M.all_acks && M.run==1);
    GROUP("hsi_error_during_idle_prevents_second_message");
    R=run(ErrorAtIdle,&M);CHECK(R.Status==N976nHsiController && R.Retired && M.run==1 && !R.IdValid);
    GROUP("hsi_ack_failure_blocks_reuse_and_quarantines");
    R=run(AckStuck,&M);CHECK(R.Status==N976nHsiAck && R.Quarantined && M.run==1 && !R.IdValid);
    GROUP("hsi_failed_rx_read_never_counts_payload");
    R=run(RxIoFailure,&M);CHECK(R.Status==N976nHsiIo && M.rx==0 && R.RxBytes==0 && R.Quarantined);
    GROUP("hsi_failed_run_write_is_potentially_submitted");
    R=run(RunIoFailure,&M);CHECK(R.Status==N976nHsiIo && R.MessagesIssued==1 && M.run==1 && R.Quarantined);
    GROUP("hsi_lease_loss_stops_all_further_mmio");
    R=run(LoseOwner,&M);CHECK(R.Status==N976nHsiOwnership && R.Quarantined && !M.lost_reads && M.run==1);
    GROUP("hsi_cancel_between_messages_preserves_retired_tx");
    R=run(CancelAfterTx,&M);CHECK(R.Status==N976nHsiCancelled && R.Retired && M.run==1 && !R.RxBytes);
    GROUP("hsi_cancel_with_pending_rx_does_not_drain_or_reset");
    R=run(CancelDuringRx,&M);CHECK(R.Status==N976nHsiCancelled && R.Quarantined && M.rx==2 && !R.IdValid);
    GROUP("hsi_stalled_counter_still_has_finite_poll_bound");
    R=run(StalledCounter,&M);CHECK(R.Status==N976nHsiTimeout && R.Polls>=N976N_HSI_MAX_POLLS && R.Retired);
    GROUP("hsi_backward_counter_is_failure_not_extended_wait");
    R=run(BackwardCounter,&M);CHECK(R.Status==N976nHsiClock && R.Retired && !R.IdValid);
    GROUP("hsi_setup_io_failure_no_submission_safe_retirement");
    R=run(SetupIoFailure,&M);CHECK(R.Status==N976nHsiIo && !M.run && R.Retired && !M.all_acks);
    GROUP("hsi_first_failure_immutable_across_different_cleanup_failure");
    R=run(UnknownAfterFirst,&M);CHECK(R.Status==N976nHsiController && R.FirstPhase==3 && R.FirstFailure.Interrupt==0x200 && R.Last.Interrupt==0x1000 && R.Quarantined && !M.all_acks);
    GROUP("hsi_auto_run_still_set_prevents_idle_claim");
    R=run(WrongAuto,&M);CHECK(R.Status==N976nHsiIdle && R.Quarantined && M.run==1);
    GROUP("hsi_unexpected_rx_during_tx_is_not_consumed");
    R=run(ExtraDuringTx,&M);CHECK(R.Status==N976nHsiExcess && !M.rx && R.Quarantined && M.run==1);
    GROUP("hsi_standard_speed_timing_evidence_required_not_reference_400k_policy");
    for(unsigned i=0;i<7;i++) {
        fixture(&M,Normal,&Io,&L);
        switch(i){case 0:L.InputHz=1599999;break;case 1:L.InputHz=400000001;break;
          case 2:L.TimingFs1^=0x10000;break;case 3:L.TimingFs2^=1;break;
          case 4:L.TimingFs3^=0x10000;break;case 5:L.Timeout=0x80000000;break;
          case 6:L.Trailing=0xFFFFFE;break;}
        CHECK(N976nHsiReadId(&Io,&L,&R)==N976nHsiInvalid && !M.reads && !M.writes);
    }
    GROUP("hsi_prepared_timing_live_readback_required_before_any_write");
    R=run(LiveTimingBad,&M);CHECK(R.Status==N976nHsiInitialState && !M.writes && !M.run);
    GROUP("hsi_timing_change_between_messages_stops_second_submission");
    R=run(TimingChanged,&M);CHECK(R.Status==N976nHsiInitialState && R.Retired && M.run==1);
    /* Same script against preserved EXP3 verifies callback order/count and
     * original results across all30 original cases. No hardware timing claim. */
    fprintf(stderr,"EXP4_MASK_NORMALIZED_TRACE %016llX\n",(unsigned long long)trace);
#ifdef N976N_EXP4_TRANSPORT_BASELINE
    GROUP("EXP4_preserved_DONE_only_hides_scripted_NO_ACK_until_timeout");
    R=run(MaskedNoAck,&M);CHECK(R.Status==N976nHsiTimeout&&R.Retired&&R.RxBytes==0&&R.Wait.Exit==N976nWaitDeadline);
    GROUP("EXP4_preserved_80_arm_readback_is_still_accepted");
    R=run(ArmBadRx,&M);CHECK(R.Status==0&&R.IdValid&&R.MessagesIssued==2);
#else
    GROUP("EXP4_RX_wall_deadline_distinct_no_data_and_frozen_before_retire");
    R=run(RxNoDataWall,&M);CHECK(R.Status==N976nHsiTimeout&&R.Retired&&!R.Quarantined&&R.RxBytes==0);
    CHECK(R.Wait.Exit==N976nWaitDeadline&&R.Wait.MessageIndex==2&&R.Wait.Receive==1&&R.Wait.Requested==3);
    CHECK(R.Wait.Iterations==10&&R.Wait.ClockChecks==10&&R.Wait.ElapsedUs==100000&&N976nHsiWaitShape(&R.Wait));
    CHECK(R.Wait.First.Transfer==0x80001&&R.Wait.Last.Transfer==0x80001&&R.Wait.First.Interrupt==0&&R.Wait.Last.Interrupt==0&&R.Wait.Seen==0&&!R.Wait.RunClear.Iteration&&!R.Wait.BusyClear.Iteration);
    GROUP("EXP4_stopped_clock_finite_watchdog_not_wall_timeout");
    R=run(RxNoDataLoop,&M);CHECK(R.Status==N976nHsiTimeout&&R.Retired&&R.Wait.Exit==N976nWaitClockStall);
    CHECK(R.Wait.Iterations==20000&&R.Wait.ClockChecks==20000&&R.Wait.SameClock==20000&&R.Wait.MaxSameClock==20000&&!R.Wait.ElapsedUs&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_wall_at_final_iteration_wins_before_loop_exhaustion");
    R=run(RxWallLastLoop,&M);CHECK(R.Wait.Exit==N976nWaitDeadline&&R.Wait.Iterations==20000&&R.Wait.ElapsedUs==100000&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_completion_final_iteration_wins_without_extra_clock_read");
    R=run(RxDoneLastLoop,&M);CHECK(R.Status==0&&R.Wait.Exit==N976nWaitComplete&&R.Wait.Iterations==20000);
    CHECK(R.Wait.ClockChecks==19999&&R.Wait.ElapsedUs==99995&&R.Wait.Last.Interrupt==0x80&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_backwards_clock_distinguished_without_unsigned_elapsed");
    R=run(RxBackward,&M);CHECK(R.Status==N976nHsiClock&&R.Wait.Exit==N976nWaitClock&&R.Wait.ClockChecks==2);
    CHECK(R.Wait.StartUs==500&&!R.Wait.LastNowUs&&!R.Wait.ElapsedUs&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_partial_sample_keeps_no_false_complete_snapshot");
    R=run(RxPartialSample,&M);CHECK(R.Status==N976nHsiIo&&R.Wait.Exit==N976nWaitOther&&R.Wait.Iterations==1);
    CHECK(!R.Wait.First.Valid&&!R.Wait.Last.Valid&&!R.Wait.ClockChecks&&R.FirstFailure.Valid==1&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_completion_idle_failure_separate_from_poll_wait_success");
    R=run(WrongAuto,&M);CHECK(R.Status==N976nHsiIdle&&R.Wait.Status==N976nHsiIdle&&R.Wait.Exit==N976nWaitComplete&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP3_all_original_outcomes_have_valid_new_wait_shape");
    for(unsigned mode=Normal;mode<=TimingChanged;++mode){R=run(mode,&M);CHECK(N976nHsiWaitShape(&R.Wait));}
    GROUP("EXP4_progressing_clock_success_after_total20000_no_bound_relaxation");
    R=run(RxProgressLong,&M);CHECK(R.Status==0&&R.Retired&&R.Wait.Iterations==25003&&R.Wait.ClockChecks==25002&&R.Wait.ElapsedUs==25002);
    CHECK(!R.Wait.SameClock&&!R.Wait.MaxSameClock&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_RUN_BUSY_first_clear_freeze_existing_RX_DONE_operands");
    CHECK(R.Wait.RunClear.Iteration==6&&R.Wait.BusyClear.Iteration==6&&R.Wait.RunClear.Sample.Valid==15);
    CHECK(R.Wait.RunClear.Sample.Auto==0x30003&&R.Wait.BusyClear.Sample.Transfer==0x80001);
    CHECK(R.Wait.RunClear.Sample.Fifo==0x01000100&&R.Wait.RunClear.Sample.Interrupt==0);
    CHECK((R.Wait.Seen&(N976nSeenRx|N976nSeenDone))==(N976nSeenRx|N976nSeenDone));
    GROUP("EXP4_clock_rollback_above_start_still_rejected_against_previous");
    R=run(RxRollbackAboveStart,&M);CHECK(R.Status==N976nHsiClock&&R.Wait.StartUs==500&&R.Wait.PreviousUs==600&&R.Wait.LastNowUs==550&&R.Wait.Exit==N976nWaitClock&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_watchdog_resets_on_forward_clock_then_stalled_clock_finite");
    R=run(RxStallAfterAdvance,&M);CHECK(R.Wait.Exit==N976nWaitClockStall&&R.Wait.Iterations==20005&&R.Wait.SameClock==20000&&R.Wait.ElapsedUs==500&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_progressing_long_plateaus_cross_total20000_reach_same100ms_deadline");
    R=run(RxLongPlateauProgress,&M);CHECK(R.Wait.Exit==N976nWaitDeadline&&R.Wait.Iterations==57000&&R.Wait.ElapsedUs==120000&&R.Wait.MaxSameClock==18999&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_natural_idle_wait_uses_time_not_total20000");
    R=run(IdleLongProgress,&M);CHECK(R.Status==0&&R.IdValid&&R.Retired&&R.Polls>50000&&R.Wait.Exit==N976nWaitComplete&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_natural_idle_stopped_clock_still_quarantines_finitely");
    R=run(IdleFrozen,&M);CHECK(R.Status==N976nHsiIdle&&R.Quarantined&&R.Wait.Exit==N976nWaitComplete&&R.Polls<50000&&N976nHsiWaitShape(&R.Wait));
    GROUP("EXP4_diagnostic_counter_width_and_proven_finite_bound");
    CHECK(sizeof(R.Polls)==8&&sizeof(R.Reads)==8&&sizeof(R.Wait.Iterations)==8&&sizeof(R.Wait.ClockChecks)==8);
    CHECK(N976N_HSI_WAIT_MAX_ITERATIONS*5*4>0xFFFFFFFFULL&&N976N_HSI_WAIT_MAX_ITERATIONS*5*4<0xFFFFFFFFFFFFFFFFULL);
    GROUP("EXP3_wait_evidence_shape_rejects_malformed_exit_operands");
    R=run(RxNoDataLoop,&M);
    for(unsigned i=0;i<14;++i){N976N_HSI_WAIT W=R.Wait;
      switch(i){case 0:W.Valid=2;break;case 1:W.Receive=0;break;case 2:W.Requested=17;break;
       case 3:W.Iterations=19999;break;case 4:W.ClockChecks=1;break;case 5:W.Exit=N976nWaitDeadline;break;
       case 6:W.ElapsedUs=1;break;case 7:W.StartUs=1;break;case 8:W.First.Valid=7;break;
       case 9:W.Last.Valid=0;break;case 10:W.Seen=32;break;case 11:W.Status=0;break;
       case 12:W.ClockStarted=0;break;case 13:W.RunIssued=0;break;}
      CHECK(!N976nHsiWaitShape(&W));}
    GROUP("EXP4_transition_and_watchdog_shape_rejects_inconsistent_raw_evidence");
    R=run(RxProgressLong,&M);
    for(unsigned i=0;i<9;++i){N976N_HSI_WAIT W=R.Wait;
      switch(i){case 0:W.RunClear.Iteration=1;break;case 1:W.RunClear.Iteration=W.Iterations+1;break;
       case 2:W.RunClear.Sample.Auto|=0x80000000U;break;case 3:W.BusyClear.Sample.Transfer|=0x10000;break;
       case 4:W.RunClear.Reserved=1;break;case 5:W.RunClear.Iteration=0;break;case 6:W.SameClock=20001;break;
       case 7:W.MaxSameClock=20000;break;case 8:W.PreviousUs=W.LastNowUs+1;break;}
      CHECK(!N976nHsiWaitShape(&W));}
    GROUP("EXP5_initial_admission_failure_has_no_message_boundary_or_writes");
    R=run(InitialPending,&M);CHECK(R.Status==N976nHsiInitialState&&!R.MessagesIssued&&!M.writes&&!R.Boundary[0].Valid&&R.FirstFailure.Interrupt==0x80&&N976nHsiEvidenceShape(&R));
    R=run(InitialOwnerLoss,&M);CHECK(R.Status==N976nHsiOwnership&&!M.reads&&!M.writes&&!R.Boundary[0].Valid&&R.Quarantined&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_zero_pending_after_prior_DONE_keeps_existing_no_W1C_success");
    R=run(AckZeroPending,&M);CHECK(!R.Status&&R.IdValid&&!M.all_acks&&R.Boundary[0].Valid==767&&R.Boundary[1].Valid==767&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_normal_TX_RX_arm_error_mask_and_exact_ACK_order_operands");
    R=run(Normal,&M);CHECK(N976nHsiEvidenceShape(&R));
    for(unsigned I=0;I<2;++I){N976N_HSI_BOUNDARY *B=&R.Boundary[I];CHECK(B->Valid==1023&&B->ArmWanted==0xF80&&B->ArmRead==0xF80&&!B->PreStatus&&!B->PreEnable&&B->IdleStatus==0x80&&!B->MaskRead&&B->Pending==0x80&&!B->After);}
    CHECK(R.Boundary[2].Valid==752&&!R.Boundary[2].Pending&&!R.Boundary[2].After);
    GROUP("EXP5_exact_arm_readback_before_TX_RUN_not_CTL_log_only");
    R=run(ArmBadTx,&M);CHECK(R.Status==N976nHsiController&&!M.run&&R.Retired&&R.Boundary[0].ArmRead==0x80&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_exact_arm_readback_before_RX_RUN_keeps_completed_TX");
    R=run(ArmBadRx,&M);CHECK(R.Status==N976nHsiController&&M.run==1&&R.Retired&&!R.RxBytes&&R.Boundary[0].Valid==1023&&R.Boundary[1].ArmRead==0x80&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_source_enabled_NO_ACK_visible_before_deadline_no_payload");
    R=run(MaskedNoAck,&M);CHECK(R.Status==N976nHsiController&&R.FirstPhase==5&&R.FirstFailure.Interrupt==0x200&&R.Retired&&!R.RxBytes&&R.Wait.Exit==N976nWaitOther&&N976nHsiEvidenceShape(&R));
    CHECK(R.Boundary[1].Valid==15&&R.Boundary[2].Valid==1008&&R.Boundary[2].IdleStatus==0x200&&R.Boundary[2].Pending==0x200&&!R.Boundary[2].After);
    GROUP("EXP5_ERROR_and_DONE_same_sample_error_wins_no_payload_acceptance");
    R=run(MaskedErrorDone,&M);CHECK(R.Status==N976nHsiController&&R.FirstFailure.Interrupt==0x280&&!R.RxBytes&&!R.IdValid&&R.Retired&&R.Boundary[2].Pending==0x280&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_all_four_source_transfer_error_bits_fail_closed");
    for(unsigned Mode=MaskedAbort;Mode<=MaskedTimeout;++Mode){R=run(Mode,&M);CHECK(R.Status==N976nHsiController&&R.FirstPhase==5&&!R.RxBytes&&R.Retired&&N976nHsiEvidenceShape(&R));}
    GROUP("EXP5_mask_disable_readback_failure_no_W1C_permission");
    R=run(AckMaskBad,&M);CHECK(R.Status==N976nHsiAck&&R.Quarantined&&!M.all_acks&&R.Boundary[0].Valid==127&&R.Boundary[0].MaskRead==0x80&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_failed_pending_read_not_zero_or_acknowledged");
    R=run(AckPendingIo,&M);CHECK(R.Status==N976nHsiIo&&R.Boundary[0].Valid==127&&!R.Boundary[0].Pending&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_failed_after_read_not_completed_ACK_proof");
    R=run(AckAfterIo,&M);CHECK(R.Status==N976nHsiIo&&R.Boundary[0].Valid==511&&R.Boundary[0].Pending==0x80&&N976nHsiEvidenceShape(&R));
    GROUP("EXP5_boundary_immutable_under_terminal_cleanup");
    R=run(MaskedNoAck,&M);CHECK(R.Boundary[0].Pending==0x80&&R.Boundary[1].Valid==15&&R.Boundary[2].Pending==0x200&&R.Wait.Last.Interrupt==0x200&&R.Last.Interrupt==0);
    GROUP("EXP5_boundary_valid_bits_reject_malformed_current_evidence");
    R=run(Normal,&M);
    for(unsigned I=0;I<12;++I){N976N_HSI_RESULT T=R;N976N_HSI_BOUNDARY *B=&T.Boundary[1];
      switch(I){case 0:B->Valid|=1024;break;case 1:B->Valid&=~1U;break;case 2:B->Valid&=~4U;break;
      case 3:B->ArmWanted=0x80;break;case 4:B->ArmRead=0x80;break;case 5:B->PreStatus=0x80;break;
      case 6:B->Valid&=~16U;break;case 7:B->MaskRead=1;break;case 8:B->Pending=0x1000;break;
      case 9:B->Valid&=~256U;break;case 10:T.Boundary[2].Valid|=1;break;case 11:B->Valid=0;break;}
      CHECK(!N976nHsiEvidenceShape(&T));}
    GROUP("EXP5_all_original_failure_and_long_wait_cases_have_valid_boundaries");
    for(unsigned Mode=Normal;Mode<=IdleFrozen;++Mode){R=run(Mode,&M);CHECK(N976nHsiEvidenceShape(&R));}
#endif
    printf("PASS %u groups\n",groups);return 0;
}
