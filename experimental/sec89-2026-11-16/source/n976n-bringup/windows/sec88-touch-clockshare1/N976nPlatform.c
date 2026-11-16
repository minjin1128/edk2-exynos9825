/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 source-backed, inert platform/GPIO preparation helpers.
 * Samsung N976N pinctrl-exynos.c and sec_ts power ordering are authoritative;
 * 9820 GPIO structure is referenced, not its live callback/locking code.
 */
#include "N976nPlatform.h"
static void PlatformZero(void *Buffer, N976N_SIZE Bytes)
{
    N976N_U8 *P = (N976N_U8 *)Buffer;
    while (Bytes != 0U) { *P++ = 0; --Bytes; }
}
#define ZERO(p) PlatformZero((p), sizeof(*(p)))

static const N976N_PLATFORM_SPAN Spans[N976N_PLATFORM_SPANS] = {
    { 0x104B0000ULL, 0x1000 }, { 0x10400000ULL, 0x8000 },
    { 0x10421000ULL, 0x1000 }, { 0x10430000ULL, 0x1000 },
    { N976N_GPIO_ALIVE_BASE, N976N_GPIO_ALIVE_BYTES }
};
static const N976N_U64 FieldAddress[N976N_PLATFORM_FIELDS] = {
    0x1042101CULL, 0x10403038ULL, 0x10430020ULL,
    0x10430028ULL, 0x1043002CULL, 0x15850904ULL
};
static const N976N_U32 FieldMask[N976N_PLATFORM_FIELDS] = {
    0xFFFFFFFFU, 2U, 0x00FF0000U, 0x00FF0000U, 0x00FF0000U, 1U
};

static int GatePass(N976N_U32 Value)
{
    return Value != 0xFFFFFFFFU &&
        ((Value & (1U << 20)) ? (Value & (1U << 21)) != 0 :
        (Value & (1U << 28)) == 0);
}

N976N_PLATFORM_RESULT N976nPlatformCheckIdReady(
    const N976N_PLATFORM_HANDOFF *H, const N976N_PLATFORM_FRESH *F,
    N976N_U64 Generation, N976N_PLATFORM_PLAN *P)
{
    N976N_U32 I, ChangedFields = 0, ChangedRails = 0;
    if (!P) return N976nPlatformInvalid;
    ZERO(P);
    if (!H || !F || H->Version != N976N_PLATFORM_VERSION ||
        H->Size != sizeof(*H)) return N976nPlatformInvalid;
    if (!Generation || H->Generation != Generation ||
        F->Generation != Generation || !H->Sequence ||
        F->Sequence <= H->Sequence) return N976nPlatformStale;
    if (H->Quarantined) return N976nPlatformQuarantined;
    if (H->Owners != N976N_PLATFORM_OWNERS || F->Owners != H->Owners ||
        H->FirmwareRetired != 1 || H->FirmwareOutstanding)
        return N976nPlatformOwnership;
    for (I = 0; I < N976N_PLATFORM_SPANS; ++I)
        if (H->Span[I].Base != Spans[I].Base ||
            H->Span[I].Bytes != Spans[I].Bytes)
            return N976nPlatformResource;
    for (I = 0; I < N976N_PLATFORM_FIELDS; ++I) {
        const N976N_PLATFORM_FIELD *W = &H->Field[I];
        if (W->Address != FieldAddress[I] || W->Mask != FieldMask[I])
            return N976nPlatformResource;
        if ((W->Original ^ W->Prepared) & ~W->Mask)
            return N976nPlatformOwnership;
        /* Only owned fields are compared: unrelated shared-word bits may be
         * legitimately changed by another pin owner. Execution must use fresh
         * locked RMW, never a stale prepared full-register value.
         */
        if ((W->Prepared ^ F->Field[I]) & W->Mask)
            return N976nPlatformChanged;
        if ((W->Original ^ W->Prepared) & W->Mask)
            ChangedFields |= 1U << I;
    }
    if ((H->Field[0].Original != 0 && H->Field[0].Original != 4) ||
        H->Field[0].Prepared != 4 ||
        (H->Field[1].Original & ~0x003F0003U) ||
        H->Field[1].Prepared != (H->Field[1].Original |
            ((H->Field[1].Original & 1U) ? 0U : 2U)) ||
        F->Field[1] != H->Field[1].Prepared ||
        (H->Field[2].Prepared & 0x00FF0000U) != 0x00220000U ||
        (H->Field[3].Prepared & 0x00FF0000U) ||
        (H->Field[4].Prepared & 0x00FF0000U) ||
        !(H->Field[5].Prepared & 1U) || !(H->Field[5].Original & 1U))
        return N976nPlatformResource;
    /* Do not seize SCL/SDA from a third alternate function. */
    for (I = 16; I <= 20; I += 4) {
        N976N_U32 Mode = (H->Field[2].Original >> I) & 15U;
        if (Mode != 0 && Mode != 2) return N976nPlatformOwnership;
    }
    for (I = 0; I < 2; ++I) {
        const N976N_PLATFORM_RAIL *R = &H->Rail[I];
        N976N_U32 Mode = R->Original & 0xC0U;
        if (R->Register != (I ? 0x60U : 0x58U) || R->Original > 255U ||
            R->Enabled > 255U || (Mode != 0 && Mode != 0xC0U) ||
            R->Enabled != (R->Original | 0xC0U) || F->Rail[I] != R->Enabled)
            return N976nPlatformPower;
        if (R->Original != R->Enabled) ChangedRails |= 1U << I;
    }
    /* AVDD-on with IO-off cannot be restored in the source-backed order. */
    if (!(H->Rail[0].Original & 0xC0U) && (H->Rail[1].Original & 0xC0U))
        return N976nPlatformPower;
    if (H->PowerIoToAnalogUs < 1000U || H->PowerSettleUs < 70000U)
        return N976nPlatformPower;
    for (I = 0; I < N976N_PLATFORM_GATES; ++I)
        if (!GatePass(H->ClockGate[I]) || F->ClockGate[I] != H->ClockGate[I])
            return N976nPlatformClock;
    if ((H->ClockMux & ~0x10U) || (H->ClockDiv & ~15U) ||
        H->ClockMux != F->ClockMux || H->ClockDiv != F->ClockDiv ||
        H->InputClockHz < 1600000U || H->InputClockHz > 400000000U ||
        H->InputClockHz != F->InputClockHz ||
        (!(H->ClockMux & 0x10U) &&
            H->InputClockHz != 26000000U / (H->ClockDiv + 1U)))
        return N976nPlatformClock;
    /* Polled HSI INT_DONE may still assert its primary IRQ. Only its real
     * owning provider may attest that the parent is masked; a GPIO interrupt
     * handle or touch pin mask is not an alternative to this prerequisite.
     */
    if (H->PrimaryGsiv != N976N_HSI_IRQ_GSIV || F->PrimaryGsiv != H->PrimaryGsiv ||
        H->PrimaryIrqMaskedOwned != 1 || F->PrimaryIrqMaskedOwned != 1)
        return N976nPlatformOwnership;
    P->Valid = 1; P->Owners = H->Owners; P->Generation = Generation;
    P->Sequence = F->Sequence; P->InputClockHz = H->InputClockHz;
    P->PrimaryIrqMaskedOwned = 1;
    P->ChangedFields = ChangedFields; P->ChangedRails = ChangedRails;
    return N976nPlatformOk;
}

static void AddOp(N976N_PLATFORM_RESTORE_PLAN *P, N976N_U32 Kind,
    N976N_U64 Address, N976N_U32 Mask, N976N_U32 Value)
{
    N976N_PLATFORM_OP *O = &P->Op[P->Count++];
    O->Kind = Kind; O->Address = Address; O->Mask = Mask; O->Value = Value;
}

N976N_PLATFORM_RESULT N976nPlatformPlanRestore(
    const N976N_PLATFORM_HANDOFF *H, const N976N_PLATFORM_FRESH *F,
    const N976N_PLATFORM_RETIREMENT *R, N976N_U64 Generation,
    N976N_PLATFORM_RESTORE_PLAN *P)
{
    N976N_PLATFORM_PLAN Ready;
    N976N_PLATFORM_RESULT Result;
    N976N_U32 I;
    if (!P) return N976nPlatformInvalid;
    ZERO(P);
    if (!R) return N976nPlatformInvalid;
    if (R->Quarantined) return N976nPlatformQuarantined;
    if (!Generation || R->Generation != Generation) return N976nPlatformStale;
    if (R->Owners != N976N_PLATFORM_OWNERS || R->Revoked != 1)
        return N976nPlatformOwnership;
    if (R->Outstanding || R->Submitted != R->Retired) return N976nPlatformBusy;
    if (R->HsiConfigurationRestored != 1 || R->PrimaryIrqRetired != 1)
        return N976nPlatformBusy;
    Result = N976nPlatformCheckIdReady(H, F, Generation, &Ready);
    if (Result != N976nPlatformOk) return Result;
    /* HSI register restoration and IRQ retirement must already be completed
     * by its owner. Retire peripheral dependency before touching rails. Do not
     * unmask EINT8 in this ID-only plan, even when inherited mask was clear.
     */
    if (!(H->Field[N976nFieldTouchMask].Original & 1U))
        return N976nPlatformOwnership;
    for (I = N976nFieldPinsCon; I <= N976nFieldPinsDrive; ++I)
        if (Ready.ChangedFields & (1U << I))
            AddOp(P, N976nOpField, H->Field[I].Address,
                H->Field[I].Mask, H->Field[I].Original & H->Field[I].Mask);
    for (I = 0; I < 2; ++I)
        if (Ready.ChangedFields & (1U << I))
            AddOp(P, N976nOpField, H->Field[I].Address,
                H->Field[I].Mask, H->Field[I].Original & H->Field[I].Mask);
    /* Analog rail -> 4ms -> IO rail. Masked updates preserve voltage bits.
     * These are descriptions only; this module sends no ACPM request.
     */
    if (Ready.ChangedRails & 2U) {
        AddOp(P, N976nOpPmicEnable, H->Rail[1].Register, 0xC0U,
            H->Rail[1].Original & 0xC0U);
        AddOp(P, N976nOpDelayUs, 0, 0, 4000);
    }
    if (Ready.ChangedRails & 1U)
        AddOp(P, N976nOpPmicEnable, H->Rail[0].Register, 0xC0U,
            H->Rail[0].Original & 0xC0U);
    return N976nPlatformOk;
}

N976N_PLATFORM_RESULT N976nGpioDescribePin(
    N976N_U64 Base, N976N_U64 Bytes, N976N_U32 Pin, N976N_GPIO_LAYOUT *L)
{
    N976N_U32 Bank, Bit;
    if (!L) return N976nPlatformInvalid;
    ZERO(L);
    if (Base != N976N_GPIO_ALIVE_BASE || Bytes != N976N_GPIO_ALIVE_BYTES ||
        Pin >= 34U) return N976nPlatformResource;
    Bank = Pin / 8U; Bit = Pin % 8U;
    L->Pin = Pin; L->ParentGsiv = 37U + Pin;
    L->Con = Bank * 0x20U; L->Data = L->Con + 4U; L->Pull = L->Con + 8U;
    L->Trigger = 0x700U + Bank * 4U;
    L->Filter = 0x800U + Bank * 8U + (Bit >= 4U ? 4U : 0U);
    L->Mask = 0x900U + Bank * 4U; L->Pending = 0xA00U + Bank * 4U;
    L->Bit = 1U << Bit; L->FieldShift = Bit * 4U;
    L->FieldMask = 15U << L->FieldShift;
    L->FilterShift = (Bit % 4U) * 8U; L->FilterMask = 255U << L->FilterShift;
    return N976nPlatformOk;
}

static int TouchLayoutValid(const N976N_GPIO_LAYOUT *L)
{
    N976N_GPIO_LAYOUT Expected;
    if (!L || N976nGpioDescribePin(N976N_GPIO_ALIVE_BASE,
        N976N_GPIO_ALIVE_BYTES, N976N_GPIO_TOUCH_PIN, &Expected) != N976nPlatformOk)
        return 0;
    return L->Pin == Expected.Pin && L->ParentGsiv == Expected.ParentGsiv &&
        L->Con == Expected.Con && L->Data == Expected.Data &&
        L->Pull == Expected.Pull && L->Trigger == Expected.Trigger &&
        L->Filter == Expected.Filter && L->Mask == Expected.Mask &&
        L->Pending == Expected.Pending && L->Bit == Expected.Bit &&
        L->FieldMask == Expected.FieldMask && L->FieldShift == Expected.FieldShift &&
        L->FilterMask == Expected.FilterMask && L->FilterShift == Expected.FilterShift;
}

static void GpioOp(N976N_GPIO_PLAN *P, N976N_U32 Kind, N976N_U32 Offset,
    N976N_U32 Mask, N976N_U32 Value)
{
    N976N_PLATFORM_OP *O = &P->Op[P->Count++];
    O->Kind = Kind; O->Address = N976N_GPIO_ALIVE_BASE + Offset;
    O->Mask = Mask; O->Value = Value;
}

N976N_PLATFORM_RESULT N976nGpioPlanTouchMasked(
    const N976N_GPIO_LAYOUT *L, const N976N_GPIO_SNAPSHOT *O, N976N_GPIO_PLAN *P)
{
    N976N_U32 Function;
    if (!P) return N976nPlatformInvalid;
    ZERO(P);
    if (!TouchLayoutValid(L) || !O) return N976nPlatformResource;
    Function = O->Con & L->FieldMask;
    if ((Function != 0 && Function != L->FieldMask) ||
        !(O->Mask & L->Bit)) return N976nPlatformOwnership;
    if (O->Pending & L->Bit) return N976nPlatformBusy;
    if ((O->Trigger & L->FieldMask) > 4U) return N976nPlatformResource;
    GpioOp(P, N976nOpField, L->Mask, L->Bit, L->Bit);
    GpioOp(P, N976nOpField, L->Con, L->FieldMask, L->FieldMask);
    GpioOp(P, N976nOpField, L->Trigger, L->FieldMask, 0);
    GpioOp(P, N976nOpField, L->Filter, L->FilterMask, 0xC0U);
    /* Samsung exynos_irq_ack: no read-modify-write on W1C. Still masked. */
    GpioOp(P, N976nOpW1c, L->Pending, L->Bit, L->Bit);
    return N976nPlatformOk;
}

N976N_PLATFORM_RESULT N976nGpioPlanTouchRestore(
    const N976N_GPIO_LAYOUT *L, const N976N_GPIO_SNAPSHOT *O,
    const N976N_GPIO_SNAPSHOT *C, N976N_U32 Retired, N976N_GPIO_PLAN *P)
{
    N976N_GPIO_PLAN Prepared;
    N976N_PLATFORM_RESULT Result;
    if (!P) return N976nPlatformInvalid;
    ZERO(P);
    if (!C || Retired != 1) return N976nPlatformBusy;
    Result = N976nGpioPlanTouchMasked(L, O, &Prepared);
    if (Result != N976nPlatformOk) return Result;
    if ((C->Pending & L->Bit) || !(C->Mask & L->Bit)) return N976nPlatformBusy;
    if ((C->Con & L->FieldMask) != L->FieldMask ||
        (C->Trigger & L->FieldMask) != 0 ||
        (C->Filter & L->FilterMask) != 0xC0U ||
        ((C->Pull ^ O->Pull) & L->FieldMask)) return N976nPlatformChanged;
    GpioOp(P, N976nOpField, L->Mask, L->Bit, L->Bit);
    GpioOp(P, N976nOpField, L->Filter, L->FilterMask, O->Filter & L->FilterMask);
    GpioOp(P, N976nOpField, L->Trigger, L->FieldMask, O->Trigger & L->FieldMask);
    GpioOp(P, N976nOpField, L->Con, L->FieldMask, O->Con & L->FieldMask);
    GpioOp(P, N976nOpField, L->Mask, L->Bit, O->Mask & L->Bit);
    return N976nPlatformOk;
}

N976N_U32 N976nGpioActiveMask(N976N_U32 Pending, N976N_U32 HardwareMask,
    N976N_U32 EnabledMask, N976N_U32 OwnedMask)
{
    return Pending & ~HardwareMask & EnabledMask & OwnedMask;
}

N976N_PLATFORM_RESULT N976nApplyPlatformOp(
    const N976N_PLATFORM_OP *O, N976N_U32 Current, N976N_U32 *Value)
{
    if (!Value) return N976nPlatformInvalid;
    *Value = 0;
    if (!O || !O->Mask || (O->Value & ~O->Mask)) return N976nPlatformInvalid;
    if (O->Kind == N976nOpW1c) {
        /* Only EINT8's admitted bit is modeled, never another bank's pending. */
        if (O->Address != 0x15850A04ULL || O->Mask != 1U || O->Value != 1U)
            return N976nPlatformOwnership;
        *Value = O->Value;
    } else if (O->Kind == N976nOpField) {
        N976N_U32 I, Admitted = 0;
        for (I = 0; I < N976N_PLATFORM_FIELDS; ++I)
            if (O->Address == FieldAddress[I] && O->Mask == FieldMask[I])
                Admitted = 1;
        if ((O->Address == 0x15850020ULL || O->Address == 0x15850704ULL) &&
            O->Mask == 15U) Admitted = 1;
        if (O->Address == 0x15850808ULL && O->Mask == 255U) Admitted = 1;
        if (!Admitted) return N976nPlatformOwnership;
        *Value = (Current & ~O->Mask) | O->Value;
    } else return N976nPlatformInvalid;
    return N976nPlatformOk;
}
