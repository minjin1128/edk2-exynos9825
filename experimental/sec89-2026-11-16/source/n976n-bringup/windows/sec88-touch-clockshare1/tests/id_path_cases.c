/* End-to-end software contract: real resource/handoff/ID functions, scripted IO.
 * Reuse the same peripheral fixture without rerunning its separate test main. */
#define main hsi_fixture_test_main_unused
#include "hsi_cases.c"
#undef main
#include "N976nIdPath.h"
#include "platform_fixture.h"
static void resources(N976N_RESOURCE *R, N976N_RESOURCE *T)
{
    static const uint64_t base[4]={0x104B0000,0x10400000,0x10421000,0x10430000};
    static const uint64_t bytes[4]={0x1000,0x8000,0x1000,0x1000};
    memset(R,0,5*sizeof(*R));
    for(unsigned i=0;i<4;i++) {
        R[i].Kind=N976nResourceMemory;R[i].Share=N976nShareExclusive;
        R[i].Start=base[i];R[i].Length=bytes[i];
    }
    R[4].Kind=N976nResourceInterrupt;R[4].Share=N976nShareExclusive;
    R[4].Vector=420;R[4].Affinity=1;
    memcpy(T,R,5*sizeof(*R));T[4].Vector=501;T[4].Level=7;
}
int main(void)
{
    MODEL M;N976N_HSI_IO Io;N976N_HSI_LEASE L;
    N976N_PLATFORM_HANDOFF H;N976N_PLATFORM_FRESH F;
    N976N_RESOURCE R[5],T[5];N976N_ID_SESSION S;
    struct { uint64_t first; N976N_ID_RESULT r; uint64_t last; } out;
    unsigned reads,writes;
#define INIT(mode) do { fixture(&M,(mode),&Io,&L); platform_fixture(&H,&F); \
    H.InputClockHz=F.InputClockHz=(uint32_t)L.InputHz; \
    resources(R,T); memset(&S,0,sizeof(S));S.Generation=17; \
    memset(&out,0xCC,sizeof(out));out.first=0x12345678;out.last=0xABCDEF12; } while(0)
#define RUN() N976nRunIdOnce(&S,R,T,5,&H,&F,&L,&Io,&out.r)
#define NO_IO() CHECK(!M.reads && !M.writes && !M.owned_calls && !M.now_calls)
    GROUP("id_path_resource_handoff_prepared_engine_integration");
    INIT(Normal);CHECK(RUN()==N976nIdOk);CHECK(out.r.IdValid && out.r.Id==0xAC3771);
    CHECK(S.Attempted==1 && !S.Running && !S.Quarantined && out.r.Submitted==2 && out.r.Retired);
    CHECK(out.first==0x12345678 && out.last==0xABCDEF12);
    GROUP("id_path_second_attempt_refused_without_IO");
    reads=M.reads;writes=M.writes;CHECK(RUN()==N976nIdAlreadyUsed);
    CHECK(M.reads==reads && M.writes==writes && !out.r.IdValid);
    GROUP("id_path_bad_resources_prevent_IO_and_attempt");
    INIT(Normal);R[0].Start++;CHECK(RUN()==N976nIdResourceRejected);NO_IO();CHECK(!S.Attempted);
    GROUP("id_path_bad_power_prevents_IO");
    INIT(Normal);F.Rail[0]^=1;CHECK(RUN()==N976nIdHandoffRejected);NO_IO();
    GROUP("id_path_stale_generation_prevents_IO");
    INIT(Normal);F.Generation++;CHECK(RUN()==N976nIdHandoffRejected);NO_IO();
    GROUP("id_path_controller_preparation_not_inferred_from_platform");
    INIT(Normal);L.Flags &= ~N976nHsiLeaseControllerPrepared;
    CHECK(RUN()==N976nIdPreparationRejected);NO_IO();
    INIT(Normal);L.InputHz++;CHECK(RUN()==N976nIdPreparationRejected);NO_IO();
    GROUP("id_path_missing_independent_controller_record_refused");
    INIT(Normal);CHECK(N976nRunIdOnce(&S,R,T,5,&H,&F,NULL,&Io,&out.r)==N976nIdPreparationRejected);NO_IO();
    GROUP("id_path_live_loss_preserves_quarantine_and_no_identity");
    INIT(LoseOwner);CHECK(RUN()==N976nIdTransferFailed);
    CHECK(S.Attempted && S.Quarantined && !out.r.IdValid && !out.r.Retired);
    reads=M.reads;writes=M.writes;CHECK(RUN()==N976nIdAlreadyUsed);
    CHECK(M.reads==reads && M.writes==writes);
    GROUP("id_path_cancel_after_TX_retires_but_never_returns_ID");
    INIT(CancelAfterTx);CHECK(RUN()==N976nIdTransferFailed);
    CHECK(out.r.Transfer.Status==N976nHsiCancelled && out.r.Submitted==1 && out.r.Retired);
    CHECK(!out.r.IdValid && !out.r.Id && !S.Quarantined);
    GROUP("id_path_null_callback_and_reentrancy_refused");
    INIT(Normal);Io.Write32=NULL;CHECK(RUN()==N976nIdInvalid);NO_IO();
    INIT(Normal);S.Running=1;CHECK(RUN()==N976nIdAlreadyUsed);NO_IO();
    GROUP("id_path_no_power_restore_from_transport_result");
    INIT(Normal);CHECK(RUN()==N976nIdOk);
    /* This API emits no platform write plan and fixture only admits HSI offsets. */
    CHECK(M.rx==3 && M.run==2);
    printf("PASS %u groups\n",groups);return 0;
}
