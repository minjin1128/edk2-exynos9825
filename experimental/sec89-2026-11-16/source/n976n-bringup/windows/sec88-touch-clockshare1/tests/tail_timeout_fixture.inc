/* Fault injection for a single already-issued receive in the transport model.
 * Only the clock and controller responses are modeled; the driver decides every
 * register access, retirement and subsequent event admission. */
enum TailScenario {
    TailDrains = 1, TailShort, TailExtra, TailOverrun, TailDrainDeadline,
    TailDrainClockStop, TailDrainClockReverse, TailOwnerLost, TailCancelled,
    TailDoneMissing, TailStaleAuto, TailPrematureDone, TailAckDoesNotClear, TailInitialClockStop, TailZeroBytes
};

static struct {
    enum TailScenario scenario;
    unsigned command, cut, jumped, rx, ackAttempts, revoked;
    uint64_t start, last;
} tail_mock;

static int tail_rx_active(void)
{
    return tail_mock.scenario && receive && messageLen && currentCommand == tail_mock.command;
}

static ULONGLONG tail_clock(ULONGLONG tick100)
{
    if (!tail_rx_active()) return tick100;
    if (!tail_mock.start) {
        tail_mock.start = tail_mock.last = tick100;
        return tick100;
    }
    if (!tail_mock.jumped) {
        if (done < tail_mock.cut) {
            /* Cut=273 places the previous check at the observed 25,756us. */
            const ULONGLONG before = tail_mock.command == 0x60 ? 1464ULL : 25756ULL;
            tail_mock.last = tail_mock.start + 10ULL * (before * done / (tail_mock.cut - 1U));
        } else {
            tail_mock.jumped = 1;
            if (tail_mock.scenario != TailInitialClockStop)
                tail_mock.last = tail_mock.start + (tail_mock.command == 0x60 ? 1731510ULL : 2004220ULL);
        }
    } else if (tail_mock.scenario == TailDrainClockReverse && done > tail_mock.cut) {
        tail_mock.last -= 10;
    } else if (tail_mock.scenario == TailDrainDeadline && done > tail_mock.cut) {
        tail_mock.last += 2000000ULL;
    } else if (tail_mock.scenario != TailInitialClockStop &&
               !(tail_mock.scenario == TailDrainClockStop && done > tail_mock.cut)) {
        tail_mock.last += 100;
    }
    clock100 = tail_mock.last;
    return tail_mock.last;
}

static void tail_sample(void)
{
    if (!tail_rx_active()) return;
    if (tail_mock.command == 0x61 && done + 1U == tail_mock.cut) {
        regs[0][0x30/4] = 0xC00100; /* physical last sample, RX_FULL+level64 */
        regs[0][0x50/4] = 0xA000B;
        regs[0][0x44/4] &= ~0x80000000U;
    }
    if (tail_mock.scenario == TailZeroBytes ||
        (tail_mock.scenario == TailInitialClockStop && done >= tail_mock.cut) ||
        (tail_mock.scenario == TailShort && done == messageLen - 1) ||
        (tail_mock.scenario == TailDrainClockStop && done > tail_mock.cut)) {
        regs[0][0x24/4] = 0;
        regs[0][0x30/4] = 0x01000100;
        regs[0][0x50/4] = 0xA000B;
    }
    if (tail_mock.scenario == TailOverrun && done >= tail_mock.cut + 2)
        regs[0][0x24/4] = 0x20;
    if (tail_mock.scenario == TailStaleAuto && done >= tail_mock.cut + 2)
        regs[0][0x44/4] = 0x30010;
    if (tail_mock.scenario == TailPrematureDone && done >= tail_mock.cut + 2) {
        regs[0][0x24/4] = 0x80;
        regs[0][0x30/4] = 0x01000100;
        regs[0][0x50/4] = 1;
        regs[0][0x44/4] &= ~0x80000000U;
    }
    if (done == messageLen && tail_mock.scenario == TailExtra)
        regs[0][0x30/4] = 0x00010100;
    if (done == messageLen && tail_mock.scenario == TailDoneMissing)
        regs[0][0x24/4] = 0;
}

static void tail_dequeue(void)
{
    if (!tail_rx_active()) return;
    ++tail_mock.rx;
    if (done != tail_mock.cut + 2) return;
    if (tail_mock.scenario == TailOwnerLost) {
        tail_mock.revoked = 1;
        ((N976N_TOUCH_HANDOFF *)page.bytes)->ClaimState = 2;
    }
    if (tail_mock.scenario == TailCancelled) time_runtime->StopRequested = 1;
}

static int tail_ack(ULONG value)
{
    if (!tail_rx_active()) return 0;
    ++tail_mock.ackAttempts;
    CHECK(value == 0x80 && done == messageLen);
    return tail_mock.scenario == TailAckDoesNotClear;
}
