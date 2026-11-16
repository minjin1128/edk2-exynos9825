/* Test-only synthetic provider record. No firmware/Windows producer exists.
 * Values are not evidence of actual N976N ownership, timing, or power handoff.
 */
#ifndef SEC76_TEST_PLATFORM_FIXTURE_H
#define SEC76_TEST_PLATFORM_FIXTURE_H
#include <string.h>
#include "N976nPlatform.h"
static void platform_fixture(N976N_PLATFORM_HANDOFF *H, N976N_PLATFORM_FRESH *F)
{
    static const N976N_PLATFORM_SPAN S[5] = {
        { 0x104B0000, 0x1000 }, { 0x10400000, 0x8000 },
        { 0x10421000, 0x1000 }, { 0x10430000, 0x1000 }, { 0x15850000, 0x1000 }
    };
    static const N976N_PLATFORM_FIELD W[6] = {
        { 0x1042101C, 0xFFFFFFFFU, 0, 4 },
        { 0x10403038, 2, 0, 2 },
        { 0x10430020, 0x00FF0000, 0xA000000A, 0xA022000A },
        { 0x10430028, 0x00FF0000, 0xB033000B, 0xB000000B },
        { 0x1043002C, 0x00FF0000, 0xC022000C, 0xC000000C },
        { 0x15850904, 1, 0xABCD0011, 0xABCD0011 }
    };
    memset(H, 0, sizeof(*H)); memset(F, 0, sizeof(*F));
    H->Version = 1; H->Size = sizeof(*H); H->Generation = 17; H->Sequence = 10;
    H->Owners = N976N_PLATFORM_OWNERS; H->FirmwareRetired = 1;
    memcpy(H->Span, S, sizeof(S)); memcpy(H->Field, W, sizeof(W));
    H->Rail[0].Register = 0x58; H->Rail[0].Original = 0x2C; H->Rail[0].Enabled = 0xEC;
    H->Rail[1].Register = 0x60; H->Rail[1].Original = 0x30; H->Rail[1].Enabled = 0xF0;
    H->PowerIoToAnalogUs = 1000; H->PowerSettleUs = 70000;
    for (unsigned I = 0; I < N976N_PLATFORM_GATES; ++I)
        H->ClockGate[I] = F->ClockGate[I] = 0x00300000;
    H->ClockMux = F->ClockMux = 0x10; H->ClockDiv = F->ClockDiv = 0;
    H->InputClockHz = F->InputClockHz = 200000000;
    H->PrimaryGsiv = F->PrimaryGsiv = 420;
    H->PrimaryIrqMaskedOwned = F->PrimaryIrqMaskedOwned = 1;
    F->Generation = H->Generation; F->Sequence = 11; F->Owners = H->Owners;
    for (unsigned I = 0; I < N976N_PLATFORM_FIELDS; ++I) F->Field[I] = H->Field[I].Prepared;
    for (unsigned I = 0; I < 2; ++I) F->Rail[I] = H->Rail[I].Enabled;
}
#endif
