// SPDX-License-Identifier: MIT
// SEC62 renderer: 4.5MiB bounded lower-screen diagnostic band.
// Pixel stores only in [0xcac00000,0xcb080000), 32-bit, no stack or UART.
// Framebuffer base0xca000000; glyph base0xcab40000 = base +2048*5760.
// Width1440, stride5760; original5x7 font enlarged toscale3 (15x21pixels).
// Two columns x40/x760; titlelogicaly160,16rows y204..864 in steps of44.
// Physical titley2208; last fieldbottom2933; visibleend0xcb0b3000.
//
// Caller supplies a proven identity address environment (M clear, or the SEC11
// verified Device framebuffer mapping) and matching SCTLR in x25 for cache cleaning. The
// renderer does not read system registers, switch translation or touch clocks.
//
// Interfaces (all preserve x18-x30 unless init, which preserves x19-x30):
//   probe_diag_init / .Ldiag_init: no arguments; clear white, publish, draw title.
//     Clobbers x0-x18/NZCV. Returns after drawing title; use publish after updates.
//   probe_diag_text / .Ldiag_text: x0=NUL string, w1=x,w2=y; w1=nextx.
//     Clobbers x0-x17/NZCV. Constant strings must be readable and terminated.
//   probe_diag_hex64 / .Ldiag_hex64: x0=value,w1=x,w2=y; w1=nextx.
//     Clobbers x0-x17/NZCV. Exactly16 uppercase hexadecimal digits.
//   probe_diag_publish / .Ldiag_publish: clobbers x0-x1/NZCV only.
//     DSB always; owned M1 Device mapping needs no cache clean. The inherited
//     M0/C1 path retains the earlier bounded band cleaning recipe.
// Every interface restores incoming x30, including the callable text helpers.
//
// The single DECON write exactly reuses the proven PROBE3 sequence: 0x1281 to
// 0x19030070, after initial white fill. Individual bits' effects were not
// isolated by that result. This recipe was sourced from Mu-Silicium commit
// 3ec9169f308c01030a7e698072aca5acb2c0a144:
// https://github.com/Project-Silicium/Mu-Silicium/blob/3ec9169f308c01030a7e698072aca5acb2c0a144/Silicon/Samsung/S5E9820Pkg/Library/PlatformSecLib/PlatformSec.c
// Cache cleaning is a pragmatic inherited-C check, not full coherency proof;
// higher-level traps and HCR.DC overrides remain outside this renderer.

.global probe_diag_init, probe_diag_text, probe_diag_hex64, probe_diag_publish
.global probe_diag_font, probe_diag_characters
.global probe_diag_glyph, probe_diag_glyph_end
probe_diag_init:
.Ldiag_init:
    mov     x18, x30
    movz    x0, #0xcac0, lsl #16
    mov     w1, #-1
    movz    w2, #0x12, lsl #16      // 1179648pixels = exactly4.5MiB
.Ldiag_clear_band:
    str     w1, [x0], #4
    subs    w2, w2, #1
    b.ne    .Ldiag_clear_band
    bl      .Ldiag_publish
    movz    x0, #0x1903, lsl #16
    mov     w1, #0x1281
    str     w1, [x0, #0x70]
    dsb     sy
    adr     x0, .Ldiag_title
    mov     w1, #40
    mov     w2, #160
    bl      .Ldiag_text
    mov     x30, x18
    ret

probe_diag_publish:
.Ldiag_publish:
    dsb     sy
    tbnz    x25, #0, .Ldiag_publish_return // Owned M1 framebuffer is Device.
    tbz     x25, #2, .Ldiag_publish_return
    movz    x0, #0xcac0, lsl #16
    movz    x1, #0xcb08, lsl #16
.Ldiag_clean_next:
    dc      cvac, x0
    add     x0, x0, #4
    cmp     x0, x1
    b.lo    .Ldiag_clean_next
    dsb     sy
.Ldiag_publish_return:
    ret

// x0=NUL-terminated text; w1=x, w2=y. Return w1=next x. The leaf glyph helper
// preserves x13-x18: x18 belongs to the caller; x17 saves this helper's LR.
probe_diag_text:
.Ldiag_text:
    mov     x17, x30
    mov     x16, x0
    mov     w15, w1
    mov     w14, w2
.Ldiag_text_next:
    ldrb    w0, [x16], #1
    cbz     w0, .Ldiag_text_return
    mov     w1, w15
    mov     w2, w14
    bl      .Ldiag_glyph
    add     w15, w15, #18          // Five scaled columns + one scaled spacer
    b       .Ldiag_text_next
.Ldiag_text_return:
    mov     w1, w15
    mov     x30, x17
    ret

// x0=value, w1=x, w2=y; exactly 16 uppercase hex digits. Return next x in w1.
probe_diag_hex64:
.Ldiag_hex64:
    mov     x17, x30
    mov     x16, x0
    mov     w15, w1
    mov     w14, w2
    mov     w13, #60
.Ldiag_hex_next:
    lsr     x0, x16, x13
    and     w0, w0, #15
    cmp     w0, #10
    add     w3, w0, #55
    add     w0, w0, #48
    csel    w0, w0, w3, lo
    mov     w1, w15
    mov     w2, w14
    bl      .Ldiag_glyph
    add     w15, w15, #18
    subs    w13, w13, #4
    b.ge    .Ldiag_hex_next
    mov     w1, w15
    mov     x30, x17
    ret

// Leaf: w0=ASCII, w1=x, w2=y. Only x0-x12 and flags are modified. Lookup data
// is PC-relative and read-only. Space and unsupported characters draw nothing.
probe_diag_glyph:
.Ldiag_glyph:
    // Preserve logical bounds; the base translates every pixel by2048 rows.
    // Unsigned comparisons also reject negative x/y values.
    cmp     w1, #1425
    b.hi    .Ldiag_glyph_return
    cmp     w2, #137
    b.lo    .Ldiag_glyph_return
    cmp     w2, #934
    b.hi    .Ldiag_glyph_return
    adr     x3, .Ldiag_characters
    mov     w4, #0
.Ldiag_lookup:
    ldrb    w5, [x3, x4]
    cbz     w5, .Ldiag_glyph_return
    cmp     w5, w0
    b.eq    .Ldiag_found
    add     w4, w4, #1
    b       .Ldiag_lookup
.Ldiag_found:
    adr     x3, .Ldiag_font
    mov     w5, #7
    madd    x3, x4, x5, x3         // Seven 5-bit rows per character
    mov     w4, #0                 // Glyph row 0..6
    // Proven diagnostic black, also correct for the photo-supported BGRX
    // pipeline admitted by FIX2. The low byte is blue, not reserved.
    movz    w0, #0xff00, lsl #16
    movz    x12, #0xcab4, lsl #16 // Translated base; all computed writes in band
.Ldiag_glyph_row:
    ldrb    w5, [x3, x4]
    mov     w6, #0                 // Vertical replication 0..2
.Ldiag_subrow:
    mov     w11, #3
    madd    w7, w4, w11, w2
    add     w7, w7, w6
    mov     w11, #5760
    madd    x10, x7, x11, x12
    add     x10, x10, x1, lsl #2
    mov     w8, #0                 // Glyph column 0..4
.Ldiag_glyph_column:
    mov     w11, #4
    sub     w11, w11, w8
    lsr     w11, w5, w11
    tbz     w11, #0, .Ldiag_skip_column
    mov     w9, #3
.Ldiag_black_pixels:
    str     w0, [x10], #4
    subs    w9, w9, #1
    b.ne    .Ldiag_black_pixels
    b       .Ldiag_column_done
.Ldiag_skip_column:
    add     x10, x10, #12
.Ldiag_column_done:
    add     w8, w8, #1
    cmp     w8, #5
    b.lo    .Ldiag_glyph_column
    add     w6, w6, #1
    cmp     w6, #3
    b.lo    .Ldiag_subrow
    add     w4, w4, #1
    cmp     w4, #7
    b.lo    .Ldiag_glyph_row
.Ldiag_glyph_return:
    ret
probe_diag_glyph_end:

// Original 5x7 bitmap rows, bits4..0 left-to-right; unsupported bytes/space
// draw nothing and still advance by18pixels. Glyphs are clipped as a whole.
#if MMU_CONSOLE
.Ldiag_title: .asciz "N976N SEC68"
#elif TRANSLATION_CONSOLE
.Ldiag_title:  .asciz "N976N EDK2 SEC10"
#elif MEMORY_CONSOLE
.Ldiag_title:  .asciz "N976N EDK2 SEC9"
#elif HOB_CONSOLE
.Ldiag_title: .asciz "N976N EDK2 SEC8"
#elif SEC_CONSOLE
.Ldiag_title: .asciz "N976N EDK2 SEC7"
#elif C_RUNTIME_CONSOLE
.Ldiag_title: .asciz "N976N PROBE6"
#elif EXCEPTION_CONSOLE
.Ldiag_title: .asciz "N976N PROBE5"
#else
.Ldiag_title: .asciz "N976N PROBE4"
#endif
probe_diag_characters:
.Ldiag_characters: .asciz "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ:-+=/.?_\\"
probe_diag_font:
.Ldiag_font:
    .byte 0x0e,0x11,0x13,0x15,0x19,0x11,0x0e // 0
    .byte 0x04,0x0c,0x04,0x04,0x04,0x04,0x0e // 1
    .byte 0x0e,0x11,0x01,0x02,0x04,0x08,0x1f // 2
    .byte 0x1e,0x01,0x01,0x0e,0x01,0x01,0x1e // 3
    .byte 0x02,0x06,0x0a,0x12,0x1f,0x02,0x02 // 4
    .byte 0x1f,0x10,0x10,0x1e,0x01,0x01,0x1e // 5
    .byte 0x0e,0x10,0x10,0x1e,0x11,0x11,0x0e // 6
    .byte 0x1f,0x01,0x02,0x04,0x08,0x08,0x08 // 7
    .byte 0x0e,0x11,0x11,0x0e,0x11,0x11,0x0e // 8
    .byte 0x0e,0x11,0x11,0x0f,0x01,0x01,0x0e // 9
    .byte 0x0e,0x11,0x11,0x1f,0x11,0x11,0x11 // A
    .byte 0x1e,0x11,0x11,0x1e,0x11,0x11,0x1e // B
    .byte 0x0e,0x11,0x10,0x10,0x10,0x11,0x0e // C
    .byte 0x1e,0x11,0x11,0x11,0x11,0x11,0x1e // D
    .byte 0x1f,0x10,0x10,0x1e,0x10,0x10,0x1f // E
    .byte 0x1f,0x10,0x10,0x1e,0x10,0x10,0x10 // F
    .byte 0x0e,0x11,0x10,0x17,0x11,0x11,0x0e // G
    .byte 0x11,0x11,0x11,0x1f,0x11,0x11,0x11 // H
    .byte 0x0e,0x04,0x04,0x04,0x04,0x04,0x0e // I
    .byte 0x07,0x02,0x02,0x02,0x12,0x12,0x0c // J
    .byte 0x11,0x12,0x14,0x18,0x14,0x12,0x11 // K
    .byte 0x10,0x10,0x10,0x10,0x10,0x10,0x1f // L
    .byte 0x11,0x1b,0x15,0x15,0x11,0x11,0x11 // M
    .byte 0x11,0x19,0x19,0x15,0x13,0x13,0x11 // N
    .byte 0x0e,0x11,0x11,0x11,0x11,0x11,0x0e // O
    .byte 0x1e,0x11,0x11,0x1e,0x10,0x10,0x10 // P
    .byte 0x0e,0x11,0x11,0x11,0x15,0x12,0x0d // Q
    .byte 0x1e,0x11,0x11,0x1e,0x14,0x12,0x11 // R
    .byte 0x0f,0x10,0x10,0x0e,0x01,0x01,0x1e // S
    .byte 0x1f,0x04,0x04,0x04,0x04,0x04,0x04 // T
    .byte 0x11,0x11,0x11,0x11,0x11,0x11,0x0e // U
    .byte 0x11,0x11,0x11,0x11,0x11,0x0a,0x04 // V
    .byte 0x11,0x11,0x11,0x15,0x15,0x1b,0x11 // W
    .byte 0x11,0x11,0x0a,0x04,0x0a,0x11,0x11 // X
    .byte 0x11,0x11,0x0a,0x04,0x04,0x04,0x04 // Y
    .byte 0x1f,0x01,0x02,0x04,0x08,0x10,0x1f // Z
    .byte 0x00,0x04,0x04,0x00,0x04,0x04,0x00 // :
    .byte 0x00,0x00,0x00,0x1f,0x00,0x00,0x00 // -
    .byte 0x00,0x04,0x04,0x1f,0x04,0x04,0x00 // +
    .byte 0x00,0x00,0x1f,0x00,0x1f,0x00,0x00 // =
    .byte 0x01,0x02,0x02,0x04,0x08,0x08,0x10 // /
    .byte 0x00,0x00,0x00,0x00,0x00,0x06,0x06 // .
    .byte 0x0e,0x11,0x01,0x02,0x04,0x00,0x04 // ?
    .byte 0x00,0x00,0x00,0x00,0x00,0x00,0x1f // _
    .byte 0x10,0x08,0x08,0x04,0x02,0x02,0x01 // backslash
.balign 4
