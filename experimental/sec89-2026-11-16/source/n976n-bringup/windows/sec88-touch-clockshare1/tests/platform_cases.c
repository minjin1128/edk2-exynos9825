/* Real production platform/GPIO helpers, synthetic records and register words.
 * This is not a trusted handoff producer, MMIO execution, or IRQ/DDI test.
 */
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "platform_fixture.h"
static unsigned groups;
#define CHECK(x) do { if (!(x)) { fprintf(stderr,"FAIL %s:%d: %s\n",__FILE__,__LINE__,#x); exit(1); } } while(0)
#define GROUP(name) do { puts(name); ++groups; } while(0)
static int zero_bytes(const void *P, size_t N)
{
    const unsigned char *B = P;
    for (size_t I = 0; I < N; ++I) if (B[I]) return 0;
    return 1;
}
static void bad_platform(const N976N_PLATFORM_HANDOFF *H,
    const N976N_PLATFORM_FRESH *F, uint64_t Generation)
{
    struct { uint64_t before; N976N_PLATFORM_PLAN p; uint64_t after; } O;
    memset(&O, 0xA5, sizeof(O)); O.before = 0x123456789ABCDEF0ULL; O.after = ~O.before;
    CHECK(N976nPlatformCheckIdReady(H, F, Generation, &O.p) != N976nPlatformOk);
    CHECK(zero_bytes(&O.p, sizeof(O.p)));
    CHECK(O.before == 0x123456789ABCDEF0ULL && O.after == ~O.before);
}
static N976N_PLATFORM_RETIREMENT retired(void)
{
    N976N_PLATFORM_RETIREMENT R = {0};
    R.Generation = 17; R.Submitted = R.Retired = 2;
    R.Owners = N976N_PLATFORM_OWNERS; R.Revoked = 1;
    R.HsiConfigurationRestored = R.PrimaryIrqRetired = 1;
    return R;
}
static void bad_restore(const N976N_PLATFORM_HANDOFF *H,
    const N976N_PLATFORM_FRESH *F, const N976N_PLATFORM_RETIREMENT *R)
{
    N976N_PLATFORM_RESTORE_PLAN P;
    memset(&P, 0xA5, sizeof(P));
    CHECK(N976nPlatformPlanRestore(H, F, R, 17, &P) != N976nPlatformOk);
    CHECK(zero_bytes(&P, sizeof(P)));
}
int main(void)
{
    N976N_PLATFORM_HANDOFF H;
    N976N_PLATFORM_FRESH F;
    N976N_PLATFORM_PLAN P;
    N976N_PLATFORM_RETIREMENT R;
    N976N_PLATFORM_RESTORE_PLAN Restore;
    N976N_GPIO_LAYOUT L;
    N976N_GPIO_SNAPSHOT G, C;
    N976N_GPIO_PLAN GP;
    N976N_U32 Value;

    GROUP("platform_valid_synthetic_fresh_handoff_only");
    platform_fixture(&H, &F);
    CHECK(N976nPlatformCheckIdReady(&H, &F, 17, &P) == N976nPlatformOk);
    CHECK(P.Valid == 1 && P.Generation == 17 && P.Sequence == 11);
    CHECK(P.ChangedFields == 0x1F && P.ChangedRails == 3 && P.PrimaryIrqMaskedOwned == 1);
    CHECK(P.InputClockHz == 200000000);

    GROUP("platform_null_version_size_canaries");
    bad_platform(NULL, &F, 17); bad_platform(&H, NULL, 17);
    CHECK(N976nPlatformCheckIdReady(&H, &F, 17, NULL) == N976nPlatformInvalid);
    for (unsigned I = 0; I < 4; ++I) {
        platform_fixture(&H, &F);
        if (I == 0) H.Version = 0;
        if (I == 1) H.Version = 2;
        if (I == 2) H.Size--;
        if (I == 3) H.Size = UINT32_MAX;
        bad_platform(&H, &F, 17);
    }
    GROUP("platform_stale_generation_sequence_rejected");
    for (unsigned I = 0; I < 7; ++I) {
        platform_fixture(&H, &F);
        if (I == 0) H.Generation = 16;
        if (I == 1) F.Generation = 18;
        if (I == 2) H.Sequence = 0;
        if (I == 3) F.Sequence = H.Sequence;
        if (I == 4) F.Sequence = H.Sequence - 1;
        if (I == 5) H.Sequence = UINT64_MAX;
        bad_platform(&H, &F, I == 6 ? 0 : 17);
    }
    GROUP("platform_missing_owner_unretired_firmware_quarantine");
    for (unsigned I = 0; I < 6; ++I) {
        platform_fixture(&H, &F); H.Owners &= ~(1U << I); bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); F.Owners &= ~(1U << I); bad_platform(&H, &F, 17);
    }
    platform_fixture(&H, &F); H.FirmwareRetired = 0; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.FirmwareRetired = 2; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.FirmwareOutstanding = 1; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.Quarantined = 1; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.Owners |= 0x40; bad_platform(&H, &F, 17);

    GROUP("platform_exact_mmio_spans_and_owned_field_addresses");
    for (unsigned I = 0; I < N976N_PLATFORM_SPANS; ++I) {
        platform_fixture(&H, &F); H.Span[I].Base++; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Span[I].Bytes--; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Span[I].Base = UINT64_MAX; bad_platform(&H, &F, 17);
    }
    for (unsigned I = 0; I < N976N_PLATFORM_FIELDS; ++I) {
        platform_fixture(&H, &F); H.Field[I].Address += 4; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Field[I].Mask ^= 1; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); F.Field[I] ^= H.Field[I].Mask; bad_platform(&H, &F, 17);
    }
    GROUP("platform_stale_original_cannot_overwrite_unowned_fields");
    for (unsigned I = 1; I < N976N_PLATFORM_FIELDS; ++I) {
        platform_fixture(&H, &F); H.Field[I].Prepared ^= 0x80000000U;
        F.Field[I] = H.Field[I].Prepared; bad_platform(&H, &F, 17);
    }
    platform_fixture(&H, &F); H.Field[2].Original |= 0x00100000; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.Field[0].Original = 1; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.Field[1].Original = H.Field[1].Prepared = F.Field[1] = 0x40;
    bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.Field[5].Original &= ~1U; bad_platform(&H, &F, 17);

    GROUP("platform_fresh_shared_sibling_bits_allowed_clock_dependency_stable");
    platform_fixture(&H, &F);
    for (unsigned I = 2; I < N976N_PLATFORM_FIELDS; ++I) F.Field[I] ^= 0x80000000U;
    CHECK(N976nPlatformCheckIdReady(&H, &F, 17, &P) == N976nPlatformOk);
    F.Field[1] ^= 1U; bad_platform(&H, &F, 17);

    GROUP("platform_rail_register_voltage_enable_and_order");
    for (unsigned I = 0; I < 2; ++I) {
        platform_fixture(&H, &F); H.Rail[I].Register++; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Rail[I].Enabled ^= 1; F.Rail[I] = H.Rail[I].Enabled; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); F.Rail[I] ^= 1; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Rail[I].Original |= 0x40; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Rail[I].Original |= 0x80; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.Rail[I].Original |= 0x100; bad_platform(&H, &F, 17);
    }
    platform_fixture(&H, &F); H.Rail[1].Original = H.Rail[1].Enabled; bad_platform(&H, &F, 17);
    GROUP("platform_enable_bytes_do_not_prove_power_settle");
    platform_fixture(&H, &F); H.PowerIoToAnalogUs = 999; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.PowerSettleUs = 69999; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.PowerSettleUs = 0; bad_platform(&H, &F, 17);
    GROUP("platform_gate_stability_and_clock_rate_provenance_required");
    for (unsigned I = 0; I < N976N_PLATFORM_GATES; ++I) {
        platform_fixture(&H, &F); H.ClockGate[I] = F.ClockGate[I] = UINT32_MAX; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.ClockGate[I] = F.ClockGate[I] = 1U << 20; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); H.ClockGate[I] = F.ClockGate[I] = 1U << 28; bad_platform(&H, &F, 17);
        platform_fixture(&H, &F); F.ClockGate[I] ^= 1; bad_platform(&H, &F, 17);
    }
    platform_fixture(&H, &F); F.ClockMux++; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); F.ClockDiv++; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.InputClockHz = F.InputClockHz = 0; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); F.InputClockHz = 26000000; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.ClockMux = F.ClockMux = 0x11; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.ClockDiv = F.ClockDiv = 16; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.InputClockHz = F.InputClockHz = 1599999; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.InputClockHz = F.InputClockHz = 400000001; bad_platform(&H, &F, 17);
    platform_fixture(&H, &F); H.ClockMux = F.ClockMux = 0;
    bad_platform(&H, &F, 17);
    H.InputClockHz = F.InputClockHz = 26000000;
    CHECK(N976nPlatformCheckIdReady(&H, &F, 17, &P) == N976nPlatformOk);

    GROUP("platform_polled_done_needs_owned_masked_primary_irq_not_gpio_irq");
    for (unsigned I = 0; I < 4; ++I) {
        platform_fixture(&H, &F);
        if (I == 0) H.PrimaryGsiv = 45;
        if (I == 1) F.PrimaryGsiv = 45;
        if (I == 2) H.PrimaryIrqMaskedOwned = 0;
        if (I == 3) F.PrimaryIrqMaskedOwned = 0;
        bad_platform(&H, &F, 17);
    }
    GROUP("platform_restore_revocation_and_retirement_required");
    platform_fixture(&H, &F); R = retired();
    bad_restore(&H, &F, NULL);
    R.Revoked = 0; bad_restore(&H, &F, &R);
    R = retired(); R.Submitted++; bad_restore(&H, &F, &R);
    R = retired(); R.Retired++; bad_restore(&H, &F, &R);
    R = retired(); R.Outstanding = 1; bad_restore(&H, &F, &R);
    R = retired(); R.Quarantined = 1; bad_restore(&H, &F, &R);
    R = retired(); R.Generation++; bad_restore(&H, &F, &R);
    R = retired(); R.Owners &= ~N976nOwnHsi; bad_restore(&H, &F, &R);
    R = retired(); R.HsiConfigurationRestored = 0; bad_restore(&H, &F, &R);
    R = retired(); R.PrimaryIrqRetired = 0; bad_restore(&H, &F, &R);
    GROUP("platform_restore_fresh_owned_configuration_cannot_drift");
    R = retired();
    platform_fixture(&H, &F); F.Field[2] ^= 0x10000; bad_restore(&H, &F, &R);
    platform_fixture(&H, &F); F.Rail[1] ^= 1; bad_restore(&H, &F, &R);
    platform_fixture(&H, &F); F.Sequence = 10; bad_restore(&H, &F, &R);
    GROUP("platform_restore_exact_masked_fields_then_analog_delay_io");
    platform_fixture(&H, &F); R = retired();
    CHECK(N976nPlatformPlanRestore(&H, &F, &R, 17, &Restore) == N976nPlatformOk);
    CHECK(Restore.Count == 8 && Restore.Count <= N976N_PLATFORM_RESTORE_MAX);
    CHECK(Restore.Op[0].Address == 0x10430020 && Restore.Op[3].Address == 0x1042101C);
    CHECK(Restore.Op[4].Address == 0x10403038 && Restore.Op[4].Mask == 2);
    CHECK(Restore.Op[5].Kind == N976nOpPmicEnable && Restore.Op[5].Address == 0x60 && Restore.Op[5].Mask == 0xC0 && Restore.Op[5].Value == 0);
    CHECK(Restore.Op[6].Kind == N976nOpDelayUs && Restore.Op[6].Value == 4000);
    CHECK(Restore.Op[7].Kind == N976nOpPmicEnable && Restore.Op[7].Address == 0x58 && Restore.Op[7].Mask == 0xC0);
    GROUP("platform_already_enabled_rails_never_get_disabled");
    H.Rail[0].Original = H.Rail[0].Enabled; H.Rail[1].Original = H.Rail[1].Enabled;
    CHECK(N976nPlatformPlanRestore(&H, &F, &R, 17, &Restore) == N976nPlatformOk);
    CHECK(Restore.Count == 5);
    for (unsigned I = 0; I < Restore.Count; ++I) CHECK(Restore.Op[I].Kind == N976nOpField);

    GROUP("gpio_exact_window_all34_pin_map_and_boundary");
    for (unsigned I = 0; I < 34; ++I) {
        CHECK(N976nGpioDescribePin(0x15850000, 0x1000, I, &L) == N976nPlatformOk);
        CHECK(L.ParentGsiv == 37 + I && L.Con == (I / 8) * 0x20);
        CHECK(L.Pending + 4 <= 0x1000 && L.Filter + 4 <= 0x1000);
        CHECK(L.FieldShift <= 28 && L.FilterShift <= 24);
    }
    CHECK(N976nGpioDescribePin(0x15850000, 0x1000, 34, &L) != N976nPlatformOk && zero_bytes(&L, sizeof(L)));
    CHECK(N976nGpioDescribePin(0x15850000, 0x1000, UINT32_MAX, &L) != N976nPlatformOk);
    CHECK(N976nGpioDescribePin(0x15850004, 0x1000, 8, &L) != N976nPlatformOk);
    CHECK(N976nGpioDescribePin(0x15850000, UINT64_MAX, 8, &L) != N976nPlatformOk);
    CHECK(N976nGpioDescribePin(UINT64_MAX, 0x1000, 8, &L) != N976nPlatformOk);
    CHECK(N976nGpioDescribePin(0x15850000, 0x1000, 8, &L) == N976nPlatformOk);
    CHECK(L.Con == 0x20 && L.Data == 0x24 && L.Pull == 0x28 && L.ParentGsiv == 45);
    CHECK(L.Trigger == 0x704 && L.Filter == 0x808 && L.Mask == 0x904 && L.Pending == 0xA04);
    GROUP("gpio_mask_first_owned_ack_only_no_unmask_for_id");
    G = (N976N_GPIO_SNAPSHOT){ 0x12345670, 0x87654320, 0x87654322, 0x11223344, 0xFFFFFFFD, 2 };
    CHECK(N976nGpioPlanTouchMasked(&L, &G, &GP) == N976nPlatformOk);
    CHECK(GP.Count == 5 && GP.Op[0].Address == 0x15850904 && GP.Op[0].Mask == 1 && GP.Op[0].Value == 1);
    CHECK(GP.Op[4].Kind == N976nOpW1c && GP.Op[4].Address == 0x15850A04 && GP.Op[4].Value == 1);
    CHECK(N976nApplyPlatformOp(&GP.Op[4], UINT32_MAX, &Value) == N976nPlatformOk && Value == 1);
    for (unsigned I = 0; I < GP.Count; ++I)
        if (GP.Op[I].Address == 0x15850904) CHECK(GP.Op[I].Value == 1);
    GROUP("gpio_other_pin_bits_preserved_by_fresh_rmw");
    for (unsigned I = 0; I < 4; ++I) {
        uint32_t Now = 0xA5A5A5A5U ^ (I * 0x11111111U);
        CHECK(N976nApplyPlatformOp(&GP.Op[I], Now, &Value) == N976nPlatformOk);
        CHECK((Value & ~GP.Op[I].Mask) == (Now & ~GP.Op[I].Mask));
        CHECK((Value & GP.Op[I].Mask) == GP.Op[I].Value);
    }
    GROUP("gpio_unsafe_inherited_or_forged_layout_rejected");
    for (unsigned I = 0; I < 5; ++I) {
        N976N_GPIO_SNAPSHOT Bad = G; N976N_GPIO_LAYOUT BL = L;
        if (I == 0) Bad.Con = 0x12345671;
        if (I == 1) Bad.Mask &= ~1U;
        if (I == 2) Bad.Pending |= 1;
        if (I == 3) BL.Pending = 0xA00;
        if (I == 4) BL.Pin = 9;
        memset(&GP, 0xA5, sizeof(GP));
        CHECK(N976nGpioPlanTouchMasked(&BL, &Bad, &GP) != N976nPlatformOk);
        CHECK(zero_bytes(&GP, sizeof(GP)));
    }
    GROUP("gpio_restore_masked_no_pending_retired_and_same_owned_fields");
    C = G; C.Con |= 15; C.Trigger &= ~15U; C.Filter = (C.Filter & ~255U) | 0xC0;
    CHECK(N976nGpioPlanTouchRestore(&L, &G, &C, 1, &GP) == N976nPlatformOk);
    CHECK(GP.Count == 5 && GP.Op[0].Address == 0x15850904 && GP.Op[4].Value == 1);
    for (unsigned I = 0; I < 6; ++I) {
        N976N_GPIO_SNAPSHOT Bad = C;
        if (I == 0) Bad.Pending |= 1;
        if (I == 1) Bad.Mask &= ~1U;
        if (I == 2) Bad.Con ^= 1;
        if (I == 3) Bad.Trigger ^= 1;
        if (I == 4) Bad.Filter ^= 1;
        if (I == 5) Bad.Pull ^= 1;
        CHECK(N976nGpioPlanTouchRestore(&L, &G, &Bad, 1, &GP) != N976nPlatformOk);
        CHECK(zero_bytes(&GP, sizeof(GP)));
    }
    CHECK(N976nGpioPlanTouchRestore(&L, &G, &C, 0, &GP) == N976nPlatformBusy);
    C.Con ^= 0x100; C.Pull ^= 0x100; C.Trigger ^= 0x100; C.Filter ^= 0x100;
    CHECK(N976nGpioPlanTouchRestore(&L, &G, &C, 1, &GP) == N976nPlatformOk);
    GROUP("gpio_query_active_subset_enabled_and_owned");
    for (unsigned I = 0; I < 256; ++I) {
        uint32_t Active = N976nGpioActiveMask(I, 0x44, 0xAA, 0xF0);
        CHECK(Active == (I & ~0x44U & 0xAAU & 0xF0U));
        CHECK((Active & ~0xAAU) == 0 && (Active & ~0xF0U) == 0);
    }
    GROUP("gpio_illegal_full_word_w1c_or_foreign_address_rejected");
    {
        N976N_PLATFORM_OP O = { N976nOpW1c, UINT32_MAX, UINT32_MAX, 0x15850A04 };
        CHECK(N976nApplyPlatformOp(&O, 0, &Value) == N976nPlatformOwnership && Value == 0);
        O.Mask = O.Value = 1; O.Address = 0x15850A00;
        CHECK(N976nApplyPlatformOp(&O, 0, &Value) == N976nPlatformOwnership);
        O.Kind = N976nOpField;
        CHECK(N976nApplyPlatformOp(&O, 0, &Value) == N976nPlatformOwnership);
        O.Kind = N976nOpPmicEnable;
        CHECK(N976nApplyPlatformOp(&O, 0, &Value) == N976nPlatformInvalid);
        CHECK(N976nApplyPlatformOp(NULL, 0, &Value) == N976nPlatformInvalid);
    }
    printf("PASS %u groups\n", groups);
    return 0;
}
