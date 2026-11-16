; SPDX-License-Identifier: BSD-2-Clause-Patent
; Owned DMA RAM only: caller proves alignment, exact word count, ownership.
; All pointers must be 8-byte aligned. No MMIO, barriers, pair/SIMD accesses,
; stack, callee-saved registers or hidden overread. Zero words touches nothing.
; One call per range instead of per word. Caller handles byte prologue/tail.
        AREA |.text|, CODE, READONLY, ALIGN=2
        EXPORT NufNcFillWords
        EXPORT NufNcCopyWords
        EXPORT NufNcMatchWords

NufNcFillWords PROC
        cbz w2, fill_end
fill_loop
        str x1, [x0], #8
        subs w2, w2, #1
        b.ne fill_loop
fill_end
        ret
        ENDP

NufNcCopyWords PROC
        cbz w2, copy_end
copy_loop
        ldr x3, [x1], #8
        str x3, [x0], #8
        subs w2, w2, #1
        b.ne copy_loop
copy_end
        ret
        ENDP

; x0=DMA, x1=independent aligned WB expected or NULL, x2=fill,
; w3=count, x4=actual/expected capture. Return first mismatch or count.
; Four independent scalar loads per full block; no pair/vector/speculative
; address beyond count. First mismatch is captured without volatile reread.
NufNcMatchWords PROC
        mov w5, #0
        cbz w3, match_end
        cbnz x1, expected_block_test
fill_block_test
        sub w8, w3, w5
        cmp w8, #4
        b.lo fill_tail
        ldr x6, [x0]
        ldr x9, [x0, #8]
        ldr x10, [x0, #16]
        ldr x11, [x0, #24]
        mov x7, x2
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x9
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x10
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x11
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        add x0, x0, #32
        b fill_block_test
fill_tail
        cmp w5, w3
        b.hs match_end
        ldr x6, [x0], #8
        mov x7, x2
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        b fill_tail
expected_block_test
        sub w8, w3, w5
        cmp w8, #4
        b.lo expected_tail
        ldr x6, [x0]
        ldr x9, [x0, #8]
        ldr x10, [x0, #16]
        ldr x11, [x0, #24]
        ldr x7, [x1]
        ldr x12, [x1, #8]
        ldr x13, [x1, #16]
        ldr x14, [x1, #24]
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x9
        mov x7, x12
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x10
        mov x7, x13
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        mov x6, x11
        mov x7, x14
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        add x0, x0, #32
        add x1, x1, #32
        b expected_block_test
expected_tail
        cmp w5, w3
        b.hs match_end
        ldr x6, [x0], #8
        ldr x7, [x1], #8
        cmp x6, x7
        b.ne match_bad
        add w5, w5, #1
        b expected_tail
match_bad
        str x6, [x4]
        str x7, [x4, #8]
match_end
        mov w0, w5
        ret
        ENDP
        END
