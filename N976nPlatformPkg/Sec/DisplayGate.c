/* SPDX-License-Identifier: MIT
 * Validate the inherited linear scanout without writing any display register
 * or framebuffer byte. Primary-source register definitions are preserved in
 * references/sec14-display/register-audit.json; its inferred pixel order is
 * superseded by hardware evidence in build-sec14-fix2/format-audit.json.
 * SEC49 retains that complete register gate and replaces only its old wrapper
 * metadata/FP precondition with the actual EL1, DAIF-masked, MMU-off contract.
 */
#include <N976nFramebuffer.h>
#include <stddef.h>
#include <stdint.h>

#define DECON UINT64_C(0x19030000)
#define NATIVE_SIZE UINT32_C(0x0BE005A0)
#define NATIVE_END UINT32_C(0x0BDF059F)
#define FB_BASE UINT64_C(0xCA000000)
#define FB_BYTES UINT64_C(0x10B3000)
#define UNSUPPORTED UINT64_C(0x8000000000000003)

_Static_assert(sizeof(N976N_PLATFORM_FB_INFO) == 128, "framebuffer info ABI");
_Static_assert(offsetof(N976N_PLATFORM_FB_REPORT, Info) == 256, "framebuffer info offset");

enum {
    CHECKS, STATUS, ERROR, GLOBAL, BG, PATH0, PATH1, PATH2, ORDER, SCALED,
    WINDOW, CHANNEL, WIN0, WIN1, START, END, DMA_BASE, DPP_BASE, DMA_ENABLE,
    IN_CON, OUT_CON, SRC_SIZE, SRC_OFFSET, IMG_SIZE, BUFFER_BASE,
    DPP_ENABLE, DPP_CON, DPP_SIZE, DPP_SCALED, H_RATIO, V_RATIO, UNSTABLE
};

static UINT32 read32(UINT64 address)
{
    return *(const volatile UINT32 *)(UINTN)address;
}

/* Low word is the programmed register; high word is its active shadow. */
static UINT64 pair(UINT64 base, UINT32 offset, UINT32 shadow)
{
    UINT64 programmed = read32(base + offset);
    UINT64 active = read32(base + offset + shadow);
    return programmed | (active << 32);
}

static int same_pair(UINT64 value)
{
    return (UINT32)value == (UINT32)(value >> 32);
}

static UINT64 fail(volatile UINT64 *r, UINT64 error)
{
    r[STATUS] = UNSUPPORTED;
    r[ERROR] = error;
    return UNSUPPORTED;
}

static UINT64 dma_base(unsigned channel)
{
    /* DECON channel numbering differs from physical block ordering. */
    static const UINT32 bases[6] = {
        0x19071000, 0x19076000, 0x19072000,
        0x19075000, 0x19073000, 0x19074000
    };
    return bases[channel];
}

static UINT64 dpp_base(unsigned channel)
{
    /* The second reg tuple of each matching live-DTB dpp node. */
    static const UINT32 bases[6] = {
        0x19021000, 0x19026000, 0x19022000,
        0x19024000, 0x19023000, 0x19025000
    };
    return bases[channel];
}

static void compare(volatile UINT64 *r, unsigned slot, UINT64 observed)
{
    if (r[slot] != observed) r[UNSTABLE] |= UINT64_C(1) << slot;
}

EFI_STATUS N976nValidateDisplay(N976N_PLATFORM_FB_REPORT *Report)
{
    if (Report == NULL || ((UINTN)Report & 7) != 0) return EFI_INVALID_PARAMETER;
    volatile N976N_PLATFORM_FB_REPORT *fb = Report;
    volatile UINT64 *r = fb->Raw;
    volatile UINT64 *info_words = (volatile UINT64 *)&fb->Info;
    UINT32 active, path, format, global, win_offset;
    unsigned window = 0, channel;
    UINT64 dma, dpp;

    for (unsigned i = 0; i < 32; ++i) r[i] = 0;
    for (unsigned i = 0; i < 16; ++i) info_words[i] = 0;
    for (unsigned i = 0; i < 16; ++i) fb->Reserved[i] = 0;
    r[WINDOW] = r[CHANNEL] = UINT64_MAX;
    r[STATUS] = UNSUPPORTED;
    /* SEC49 invokes this read-only gate after DT/ownership admission and before
     * creating mappings. The old witness/FP-report dependency is not a display
     * requirement; these are the actual entry conditions for this new phase. */
    UINT64 CurrentEl, Daif, Sctlr;
    __asm__ __volatile__("mrs %0, CurrentEL" : "=r"(CurrentEl));
    __asm__ __volatile__("mrs %0, daif" : "=r"(Daif));
    __asm__ __volatile__("mrs %0, sctlr_el1" : "=r"(Sctlr));
    if (CurrentEl != 4 || (Daif & 0x3c0) != 0x3c0 || (Sctlr & 1) != 0)
        return fail(r, 1);
    r[CHECKS] |= 1;

    r[GLOBAL] = global = read32(DECON);
    r[BG] = pair(DECON, 0x200, 0x7000);
    r[PATH0] = pair(DECON, 0x214, 0x7000);
    r[PATH1] = pair(DECON, 0x218, 0x7000);
    r[PATH2] = pair(DECON, 0x230, 0x7000);
    r[ORDER] = pair(DECON, 0x130, 0x7000);
    r[SCALED] = pair(DECON, 0xA0, 0x7000);
    for (unsigned i = BG; i <= SCALED; ++i)
        if (!same_pair(r[i])) return fail(r, 2);
    path = (UINT32)r[PATH2];
    if ((global & 3) != 3 || (global & ((1u << 28) | (1u << 20))) ||
        (UINT32)r[BG] != NATIVE_SIZE || (path & 0x03007000) ||
        ((path & 255) != 0x11 && (path & 255) != 0xB1) ||
        ((UINT32)r[ORDER] & 0x70))
        return fail(r, 2);
    r[CHECKS] |= 2;

    active = (UINT32)r[PATH0] & 0x00111111;
    if (!active || (active & (active - 1))) return fail(r, 3);
    while (!(active & (1u << (window * 4)))) ++window;
    r[WINDOW] = window;
    channel = ((UINT32)r[PATH1] >> (window * 4)) & 7;
    r[CHANNEL] = channel;
    if (window >= 6 || channel >= 6 ||
        ((UINT32)r[PATH0] & (1u << (window * 4 + 1))))
        return fail(r, 3);
    r[CHECKS] |= 4;

    win_offset = 0x1000 + window * 0x30;
    r[WIN0] = pair(DECON, win_offset, 0x7000);
    r[WIN1] = pair(DECON, win_offset + 4, 0x7000);
    r[START] = pair(DECON, win_offset + 8, 0x7000);
    r[END] = pair(DECON, win_offset + 12, 0x7000);
    for (unsigned i = WIN0; i <= END; ++i)
        if (!same_pair(r[i])) return fail(r, 4);
    /* COPY is the kernel's no-blending function. It must make the high
     * reserved byte irrelevant even for clients that directly write GOP. */
    if ((((UINT32)r[WIN0] >> 8) & 15) != 1 ||
        ((UINT32)r[WIN0] & (1u << 4)) ||
        (UINT32)r[START] != 0 || (UINT32)r[END] != NATIVE_END)
        return fail(r, 4);
    r[CHECKS] |= 8;

    r[DMA_BASE] = dma = dma_base(channel);
    r[DPP_BASE] = dpp = dpp_base(channel);
    r[DMA_ENABLE] = read32(dma);
    r[IN_CON] = pair(dma, 8, 0x800);
    r[OUT_CON] = pair(dma, 12, 0x800);
    r[SRC_SIZE] = pair(dma, 16, 0x800);
    r[SRC_OFFSET] = pair(dma, 20, 0x800);
    r[IMG_SIZE] = pair(dma, 24, 0x800);
    r[BUFFER_BASE] = pair(dma, 64, 0x800);
    r[DPP_ENABLE] = read32(dpp);
    r[DPP_CON] = read32(dpp + 8);
    r[DPP_SIZE] = read32(dpp + 24);
    if (channel == 1 || channel == 5) {
        r[DPP_SCALED] = read32(dpp + 0x2C);
        r[H_RATIO] = read32(dpp + 0x44);
        r[V_RATIO] = read32(dpp + 0x48);
    }
    /* Only channel1 has the internal LSI HDR capability (DTB attr bit6).
     * ENABLE.HDR_SEL below rejects the separate MCD path on every channel;
     * it does not disable this internal HDR/EOTF/gamut/tone-map block. */
    if (channel == 1) {
        fb->Reserved[0] = dpp + 0x600;
        fb->Reserved[1] = read32(dpp + 0x600);
    }
    for (unsigned i = IN_CON; i <= BUFFER_BASE; ++i)
        if (!same_pair(r[i])) return fail(r, 5);
    format = ((UINT32)r[IN_CON] >> 11) & 63;
    /* The captured N976N format0 pipeline displays little-endian B,G,R,X.
     * FIX1's known words and hardware photo establish this effective order;
     * register names alone do not establish scanout byte order. Admit only
     * that observed configuration. Do not rewrite any format register. */
    if (format != 0 ||
        ((UINT32)r[IN_CON] & 0x80000798) ||
        ((UINT32)r[DMA_ENABLE] & ((1u << 24) | 2)) ||
        (UINT32)r[SRC_SIZE] != NATIVE_SIZE ||
        (UINT32)r[SRC_OFFSET] || (UINT32)r[IMG_SIZE] != NATIVE_SIZE ||
        (UINT32)r[BUFFER_BASE] != FB_BASE)
        return fail(r, 5);
    r[CHECKS] |= 0x10;

    if (((UINT32)r[DPP_ENABLE] & ((1u << 24) | (1u << 11))) ||
        ((UINT32)r[DPP_CON] & 7) || r[DPP_SIZE] != NATIVE_SIZE ||
        (channel == 1 && (fb->Reserved[1] & 15)) ||
        ((channel == 1 || channel == 5) &&
         (r[DPP_SCALED] != NATIVE_SIZE || r[H_RATIO] != 0x100000 ||
          r[V_RATIO] != 0x100000)))
        return fail(r, 6);
    r[CHECKS] |= 0x20;

    /* Command-mode operation status may change between triggers. Compare
     * configuration, masking only those documented live status bits. */
    if ((read32(DECON) ^ global) & ~UINT32_C(0x30))
        r[UNSTABLE] |= UINT64_C(1) << GLOBAL;
    compare(r, BG, pair(DECON, 0x200, 0x7000));
    compare(r, PATH0, pair(DECON, 0x214, 0x7000));
    compare(r, PATH1, pair(DECON, 0x218, 0x7000));
    compare(r, PATH2, pair(DECON, 0x230, 0x7000));
    compare(r, ORDER, pair(DECON, 0x130, 0x7000));
    compare(r, SCALED, pair(DECON, 0xA0, 0x7000));
    for (unsigned i = 0; i < 4; ++i)
        compare(r, WIN0 + i, pair(DECON, win_offset + i * 4, 0x7000));
    if ((read32(dma) ^ (UINT32)r[DMA_ENABLE]) & ~UINT32_C(4))
        r[UNSTABLE] |= UINT64_C(1) << DMA_ENABLE;
    for (unsigned i = 0; i < 5; ++i)
        compare(r, IN_CON + i, pair(dma, 8 + i * 4, 0x800));
    compare(r, BUFFER_BASE, pair(dma, 64, 0x800));
    if ((read32(dpp) ^ (UINT32)r[DPP_ENABLE]) & ~UINT32_C(4))
        r[UNSTABLE] |= UINT64_C(1) << DPP_ENABLE;
    compare(r, DPP_CON, read32(dpp + 8));
    compare(r, DPP_SIZE, read32(dpp + 24));
    if (channel == 1 || channel == 5) {
        compare(r, DPP_SCALED, read32(dpp + 0x2C));
        compare(r, H_RATIO, read32(dpp + 0x44));
        compare(r, V_RATIO, read32(dpp + 0x48));
    }
    if (channel == 1) {
        fb->Reserved[2] = read32(dpp + 0x600);
        if (fb->Reserved[1] != fb->Reserved[2])
            r[UNSTABLE] |= UINT64_C(1) << 32;
    }
    if (r[UNSTABLE]) return fail(r, 7);
    r[CHECKS] |= 0x40;

    fb->Info.Size = sizeof (N976N_PLATFORM_FB_INFO);
    fb->Info.Version = N976N_PLATFORM_FB_INFO_VERSION;
    fb->Info.Flags = N976N_PLATFORM_FB_INFO_FLAGS;
    fb->Info.Base = FB_BASE;
    fb->Info.VisibleBytes = FB_BYTES;
    fb->Info.Width = 1440;
    fb->Info.Height = 3040;
    fb->Info.PitchBytes = 5760;
    fb->Info.PixelFormat = 1; /* PixelBlueGreenRedReserved8BitPerColor */
    fb->Info.RedMask = 0x00FF0000;
    fb->Info.GreenMask = 0x0000FF00;
    fb->Info.BlueMask = 0x000000FF;
    fb->Info.ReservedMask = 0xFF000000;
    fb->Info.ReservedByteValue = 0xFF;
    fb->Info.Reserved = 0;
    __asm__ __volatile__("dsb sy" ::: "memory");
    fb->Info.Magic = N976N_PLATFORM_FB_INFO_MAGIC;
    r[CHECKS] |= 0x80;
    r[ERROR] = 0;
    r[STATUS] = 0;
    return 0;
}
