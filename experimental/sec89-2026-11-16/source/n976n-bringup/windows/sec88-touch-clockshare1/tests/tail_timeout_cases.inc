/* Uses the real prepare, event command, retained batch, fresh read and
 * diagnostic persistence paths; the only mocked dependencies are MMIO/WDF. */
static void start_timeout_runtime(N976N_DEMO_RUNTIME *r)
{
    MOCK_LIST raw, translated;
    fixture(&raw, &translated);
    memset(r, 0, sizeof(*r));
    time_runtime = r;
    CHECK(NT_SUCCESS(N976nDemoPrepare(r, (void *)1, &raw, &translated)));
    CHECK(NT_SUCCESS(N976nDemoStart(r)));
}

static void arm_gap(enum TailScenario scenario, unsigned command, unsigned cut)
{
    memset(&tail_mock, 0, sizeof(tail_mock));
    tail_mock.scenario = scenario;
    tail_mock.command = command;
    tail_mock.cut = cut;
}

static NTSTATUS issue_timed_tail(N976N_DEMO_RUNTIME *r, enum TailScenario scenario)
{
    CHECK(NT_SUCCESS(N976nDemoReadEvent(r, r->EventBatch[0])));
    r->EventBatch[0][7] = 29; /* READ_ONE revealed 29 additional 16B records. */
    memset(tail_packet, 0xa5, sizeof(tail_packet));
    arm_gap(scenario, 0x61, scenario == TailZeroBytes ? 0 : 273);
    unsigned prior_runs = runs;
    NTSTATUS status = N976nDemoReadTail(r, 29);
    CHECK(status == STATUS_IO_TIMEOUT && runs == prior_runs + 2);
    CHECK(r->Last.Status == N976nHsiTimeout && r->Last.FirstPhase == 5);
    CHECK(r->Last.Wait.MessageIndex == 2 && r->Last.Wait.Requested == 464);
    return status;
}

static void run_tail_timeout_cases(void)
{
    N976N_DEMO_RUNTIME r;
    start_timeout_runtime(&r);
    GROUP("SEC88_live_464B_273B_deadline_175ms_gap_discards_exact_residual_without_replaying");
    issue_timed_tail(&r, TailDrains);
    const N976N_HSI_RESULT *h = &r.Last;
    CHECK(h->RxBytes == 273 && h->DiscardedBytes == 191 && tail_mock.rx == 464);
    CHECK(h->Wait.Exit == N976nWaitDeadline && h->Wait.ElapsedUs == 200422);
    CHECK(h->Wait.LastNowUs - h->Wait.PreviousUs == 174666);
    CHECK(h->FirstFailure.Interrupt == 0 && h->FirstFailure.Fifo == 0xc00100);
    CHECK(h->FirstFailure.Transfer == 0xa000b && h->FirstFailure.Auto == 0x301d0);
    CHECK(h->Retired && !h->Quarantined && !h->CleanupStatus && tail_mock.ackAttempts == 1);
    CHECK(h->Boundary[2].IdleStatus == 0x80 && h->Boundary[2].Pending == 0x80);
    CHECK(h->Boundary[2].MaskRead == 0 && h->Boundary[2].After == 0);
    for (unsigned i = 0; i < h->Wait.Requested; ++i)
        CHECK(((UCHAR *)r.EventBatch)[16 + i] == 0); /* discarded bytes never published */
    CHECK(r.Stage == 29 && !r.Quarantined && !r.Events && command_counts[0x61] == 1);
    CHECK(r.Lifecycle.Tail.GapPending && r.Lifecycle.Tail.AwaitingFresh);
    CHECK(r.Lifecycle.Tail.Deferred == 1 && !r.Lifecycle.FirstFailure.Valid);
    CHECK(N976nTailRecoveryShape(&r.Lifecycle.Tail));
    N976nDemoRecord(&r);
    CHECK(N976nTailRecoveryShape(&registry_lifecycle.Tail));
    CHECK(registry_lifecycle.Tail.FirstDeferred.State.Status == (ULONG)STATUS_IO_TIMEOUT);

    GROUP("SEC88_retired_timeout_gap_blocks_commands_then_resumes_only_after_fresh_validated_read");
    unsigned before = writes;
    CHECK(N976nDemoReadEvent(&r, r.EventBatch[0]) == STATUS_DEVICE_BUSY);
    CHECK(N976nDemoReadTail(&r, 29) == STATUS_INVALID_PARAMETER && writes == before);
    /* The real poll producer's all-up/discard is exercised by the queue suite.
     * Here emulate only its completion boundary before the next fresh read. */
    r.Lifecycle.Tail.GapPending = 0;
    CHECK(NT_SUCCESS(N976nDemoReadEvent(&r, r.EventBatch[0])));
    CHECK(r.EventBatch[0][0] == 0x44 && !r.Lifecycle.Tail.Resumed);
    N976nDemoValidatedBatch(&r);
    CHECK(!r.Lifecycle.Tail.AwaitingFresh && r.Lifecycle.Tail.Resumed == 1);
    CHECK(r.Lifecycle.Tail.Streak == 0 && command_counts[0x61] == 1);
    N976nDemoRelease(&r);

    GROUP("SEC88_third_consecutive_retired_partial_timeout_is_terminal");
    start_timeout_runtime(&r);
    for (unsigned attempt = 1; attempt <= 3; ++attempt) {
        issue_timed_tail(&r, TailDrains);
        CHECK(r.Lifecycle.Tail.Streak == attempt && command_counts[0x61] == attempt);
        CHECK(r.Lifecycle.Tail.GapPending == (attempt < 3));
        if (attempt < 3) r.Lifecycle.Tail.GapPending = 0;
    }
    CHECK(r.Stage == 90 && r.Lifecycle.Tail.Deferred == 2 && r.Lifecycle.Tail.Fatal == 1);
    CHECK(r.Lifecycle.FirstFailure.Command == 0x61 && r.Lifecycle.Tail.Decision == N976nTailLimit);
    N976nDemoRelease(&r);

    const struct { enum TailScenario fault; const char *name; } failures[] = {
        {TailShort, "SEC88_one_missing_byte_without_DONE_is_terminal"},
        {TailExtra, "SEC88_unowned_extra_byte_is_never_dequeued"},
        {TailOverrun, "SEC88_real_overrun_during_discard_is_terminal"},
        {TailDrainDeadline, "SEC88_second_wall_deadline_during_discard_is_terminal"},
        {TailDrainClockStop, "SEC88_stopped_clock_in_discard_cannot_hang"},
        {TailDrainClockReverse, "SEC88_reverse_clock_in_discard_is_terminal"},
        {TailOwnerLost, "SEC88_revoked_lease_during_discard_has_no_subsequent_HSI_access"},
        {TailCancelled, "SEC88_cancel_during_discard_is_terminal"},
        {TailStaleAuto, "SEC88_changed_AUTO_length_stops_further_dequeues"},
        {TailPrematureDone, "SEC88_premature_DONE_short_receive_is_terminal"},
        {TailDoneMissing, "SEC88_all_bytes_without_DONE_never_authorize_resume"},
        {TailAckDoesNotClear, "SEC88_failed_W1C_never_authorizes_resume"},
        {TailInitialClockStop, "SEC88_original_clock_watchdog_never_admits_discard"},
        {TailZeroBytes, "SEC88_timeout_without_any_RX_never_admits_discard"}
    };
    for (unsigned i = 0; i < sizeof(failures)/sizeof(failures[0]); ++i) {
        enum TailScenario fault = failures[i].fault;
        GROUP(failures[i].name);
        start_timeout_runtime(&r);
        issue_timed_tail(&r, fault);
        CHECK(r.Stage == 90 && !r.Lifecycle.Tail.GapPending && !r.Lifecycle.Tail.Deferred);
        CHECK(r.Lifecycle.FirstFailure.Valid && r.Lifecycle.Tail.Fatal == 1);
        CHECK(r.Last.Quarantined && !r.Last.Retired && r.Quarantined);
        CHECK(r.Last.RxBytes == (fault == TailZeroBytes ? 0U : 273U));
        CHECK(r.Last.Wait.Exit == (fault == TailInitialClockStop ? N976nWaitClockStall : N976nWaitDeadline));
        CHECK(tail_mock.rx == r.Last.RxBytes + r.Last.DiscardedBytes);
        if (fault == TailExtra || fault == TailDoneMissing || fault == TailAckDoesNotClear)
            CHECK(tail_mock.rx == 464);
        if (fault == TailOwnerLost || fault == TailCancelled || fault == TailOverrun ||
            fault == TailStaleAuto || fault == TailPrematureDone)
            CHECK(tail_mock.rx == 275);
        if (fault == TailInitialClockStop || fault == TailZeroBytes) CHECK(r.Last.DiscardedBytes == 0);
        CHECK(command_counts[0x61] == 1 && r.Events == 0);
        N976nDemoRelease(&r);
    }

    GROUP("RX1_live_60_15_of_16_timeout_preserves_failure_discards_one_and_clears_once");
    start_timeout_runtime(&r);
    const unsigned original_heads=command_counts[0x60], original_clears=command_counts[0x62];
    arm_gap(TailDrains, 0x60, 15);
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0]) == STATUS_IO_TIMEOUT);
    const N976N_HSI_RESULT *one = &r.FirstRead.LastFailure.Hsi;
    CHECK(r.Stage == 29 && r.FirstRead.GapPending && !r.Quarantined && r.FirstRead.Clears == 1);
    CHECK(one->RxBytes==15 && one->DiscardedBytes==1 && one->Retired && !one->Quarantined);
    CHECK(one->Wait.ElapsedUs==173151 && one->Wait.LastNowUs-one->Wait.PreviousUs==171687);
    CHECK(command_counts[0x60]==original_heads+1 && command_counts[0x62]==original_clears+1 && !command_counts[0x61]);
    for(unsigned i=0;i<16;++i)CHECK(r.EventBatch[0][i]==0);
    CHECK(!r.Events && r.FirstRead.AwaitingFresh && !r.Lifecycle.FirstFailure.Valid);
    GROUP("RX1_head_gap_blocks_bus_only_new_validated_batch_completes_recovery");
    unsigned no_writes=writes;
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_DEVICE_BUSY && writes==no_writes);
    CHECK(N976nDemoReadTail(&r,1)==STATUS_INVALID_PARAMETER && writes==no_writes);
    r.FirstRead.GapPending=0; memset(&tail_mock,0,sizeof(tail_mock));
    CHECK(NT_SUCCESS(N976nDemoReadEvent(&r,r.EventBatch[0])));
    CHECK(r.FirstRead.AwaitingFresh && !r.FirstRead.Resumed);
    N976nDemoValidatedBatch(&r);
    CHECK(r.FirstRead.Resumed==1 && !r.FirstRead.AwaitingFresh && !r.FirstRead.Streak);
    N976nDemoRelease(&r);

    GROUP("RX1_three_consecutive_partial_heads_stop_without_third_clear_or_replay");
    start_timeout_runtime(&r);
    for(unsigned n=1;n<=3;++n){
        arm_gap(TailDrains,0x60,15);
        CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_IO_TIMEOUT);
        CHECK(r.FirstRead.Streak==n && r.FirstRead.GapPending==(n<3));
        r.FirstRead.GapPending=0;
    }
    CHECK(r.Stage==90 && r.FirstRead.Clears==2 && !r.FirstRead.Resumed && !r.Lifecycle.Tail.Faults);
    N976nDemoRelease(&r);

    GROUP("RX1_successful_new_D0_starts_new_loss_budget_keeps_prior_evidence");
    start_timeout_runtime(&r);
    for(unsigned n=0;n<2;++n){
        arm_gap(TailDrains,0x60,15);
        CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_IO_TIMEOUT);
        r.FirstRead.GapPending=0;
    }
    CHECK(r.FirstRead.Streak==2 && r.FirstRead.AwaitingFresh);
    memset(&tail_mock,0,sizeof(tail_mock));
    r.StopRequested=1;CHECK(NT_SUCCESS(N976nDemoStop(&r)));
    CHECK(NT_SUCCESS(N976nDemoStart(&r)) && r.FirstRead.Streak==0 && !r.FirstRead.AwaitingFresh &&
        r.FirstRead.Faults==2 && r.FirstRead.LastFailure.Hsi.RxBytes==15 && !r.FirstRead.Resumed);
    arm_gap(TailDrains,0x60,15);
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_IO_TIMEOUT && r.Stage==29 && r.FirstRead.Streak==1);
    N976nDemoRelease(&r);

    GROUP("RX1_D0_cancel_after_clean_CLEAR_has_no_poll_failure_or_fresh_admission");
    start_timeout_runtime(&r);arm_gap(TailDrains,0x60,15);runtime_cancel_after_clear=1;
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_CANCELLED && r.StopRequested &&
        r.Stage==29 && !r.FirstRead.GapPending && !r.FirstRead.Resumed && !r.Quarantined &&
        r.FirstRead.LastFailure.Hsi.Retired && !r.Lifecycle.FirstFailure.Valid);
    CHECK(NT_SUCCESS(N976nDemoStop(&r)));
    N976nDemoRelease(&r);

    GROUP("RX1_missing_16th_byte_never_clears_sensor_or_delivers_partial_data");
    start_timeout_runtime(&r); arm_gap(TailShort,0x60,15);
    unsigned previous_clears=command_counts[0x62];
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_IO_TIMEOUT);
    CHECK(r.Stage==90 && r.Quarantined && !r.FirstRead.GapPending && !r.FirstRead.Clears &&
        command_counts[0x62]==previous_clears && r.FirstRead.LastFailure.Hsi.RxBytes==15);
    N976nDemoRelease(&r);

    GROUP("RX1_changed_pad_during_clear_stops_before_gap_or_resume");
    start_timeout_runtime(&r); arm_gap(TailDrains,0x60,15); after_clear_drift=1;
    CHECK(N976nDemoReadEvent(&r,r.EventBatch[0])==STATUS_DEVICE_NOT_READY);
    CHECK(r.Stage==90 && r.Quarantined && !r.FirstRead.GapPending && !r.FirstRead.Resumed &&
          r.FirstRead.LastFailure.Hsi.Retired);
    N976nDemoRelease(&r);
    GROUP("RX1_checked_sensor_clear_failure_stops_without_another_event");
    start_timeout_runtime(&r); arm_gap(TailDrains,0x60,15); fail_write_command=0x62;
    CHECK(!NT_SUCCESS(N976nDemoReadEvent(&r,r.EventBatch[0])));
    CHECK(r.Stage==90 && !r.FirstRead.GapPending && !r.FirstRead.Clears &&
        r.FirstRead.LastFailure.Command==0x60 && r.FirstRead.LastFailure.Hsi.Retired &&
        r.Lifecycle.FirstFailure.Command==0x62);
    N976nDemoRelease(&r);
}
