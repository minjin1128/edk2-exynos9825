// SPDX-License-Identifier: MIT
// SEC62: preserved bounded Android entry, cache synchronization and display.
#define MMU_CONSOLE 1
.section .text.boot,"ax"
.global image_start, probe_entry
image_start:
 b probe_entry
 .long 0
 .quad 0x80000
 .quad image_size
 .quad 0x0a
 .quad 0
 .quad 0xecefecef
 .quad 0
 .ascii "ARM\x64"
 .long 0
probe_entry:
 mov x19,x0
 adr x23,image_start
 msr DAIFSet,#15
 mrs x24,CurrentEL
 cmp x24,#4
 b.ne probe_halt
 mrs x25,SCTLR_EL1
 mov x0,#0x1005
 tst x25,x0
 b.ne probe_halt
 b .Lruntime
.section .text,"ax"
.global probe_halt
probe_halt:
 b probe_halt
.macro addr reg,symbol
 adrp \reg,\symbol
 add \reg,\reg,:lo12:\symbol
.endm
.Lruntime:
 tst x23,#0xfff
 b.ne probe_halt
 movz x0,#0x8000,lsl #16
 add x0,x0,#2,lsl #12
 cmp x23,x0
 b.lo probe_halt
 addr x1,image_end
 movz x0,#0x8700,lsl #16
 cmp x1,x0
 b.hi probe_halt
 cmp x1,x23
 b.ls probe_halt
 mov x0,x23
 bl probe_invalidate_data_range
 cbnz x0,probe_halt
 addr x0,__bss_start
 addr x1,__bss_end
1: cmp x0,x1
 b.hs 2f
 str xzr,[x0],#8
 b 1b
2:
 addr x28,probe_stack_top
 msr SPSel,#1
 mov sp,x28
 mov x18,xzr
 addr x0,probe_exception_vectors
 msr VBAR_EL1,x0
 mrs x0,CPACR_EL1
 orr x0,x0,#0x300000
 msr CPACR_EL1,x0
 isb
 movz x0,#0xa55a
 movk x0,#0xa55a,lsl #16
 movk x0,#0xa55a,lsl #32
 movk x0,#0xa55a,lsl #48
 addr x1,probe_stack_guard_low
 stp x0,x0,[x1]
 addr x1,probe_stack_guard_high
 stp x0,x0,[x1]
 bl probe_diag_init
 mov x0,x19
 bl probe_sec_load
 b probe_halt

// Preserved bounded pre-cache invalidation: no stack or external stores.
.global probe_invalidate_data_range
probe_invalidate_data_range:
 cmp x0,x1
 b.hs 9f
 orr x2,x0,x1
 tst x2,#0xfff
 b.ne 9f
 mrs x2,SCTLR_EL1
 mov x3,#0x1005
 tst x2,x3
 b.ne 9f
 mrs x2,CTR_EL0
 ubfx x2,x2,#16,#4
 mov x3,#4
 lsl x3,x3,x2
 cmp x3,#16
 b.lo 9f
 cmp x3,#2048
 b.hi 9f
 dsb sy
1: dc ivac,x0
 add x0,x0,x3
 cmp x0,x1
 b.lo 1b
 dsb sy
 isb
 mov x0,#0
 ret
9: mov x0,#1
 ret

.global probe_sec_sync
probe_sec_sync:
 mov x2,x0
1: dc cvac,x2
 add x2,x2,#4
 cmp x2,x1
 b.lo 1b
 dsb sy
2: ic ivau,x0
 add x0,x0,#4
 cmp x0,x1
 b.lo 2b
 dsb sy
 isb
 ret

// Callback uses the bounded scale3 renderer, translated down2048 rows.
// Redraw [0xcac00000,0xcb080000) after GOP clear,
// without repeating the initial hardware trigger. No stale text survives.
.global probe_sec_screen
probe_sec_screen:
 stp x29,x30,[sp,#-112]!
 stp x18,x19,[sp,#16]
 stp x20,x21,[sp,#32]
 stp x22,x23,[sp,#48]
 stp x24,x25,[sp,#64]
 stp x26,x27,[sp,#80]
 str x28,[sp,#96]
 cmp x0,#1
 b.lo 9f
 cmp x0,#32
 b.hi 9f
 addr x20,probe_screen_values
 sub x0,x0,#1
 str x1,[x20,x0,lsl #3]
 // BDS IDs1..8 paint immediately; RAM IDs9..32 form one snapshot.
 cmp x0,#8
 b.lo 8f
 cmp x0,#31
 b.ne 9f
8:
 mrs x25,SCTLR_EL1
 movz x0,#0xcac0,lsl #16
 mov w1,#-1
 movz w2,#0x12,lsl #16
1: str w1,[x0],#4
 subs w2,w2,#1
 b.ne 1b
 adr x0,.Ldiag_title
 mov w1,#40
 mov w2,#160
 bl probe_diag_text
 adr x21,screen_labels
 mov x22,#0
2:
 add x0,x21,x22,lsl #4
 mov w23,w22
 mov w24,#40
 cmp w23,#16
 b.lo 3f
 sub w23,w23,#16
 mov w24,#760
3:
 mov w1,w24
 mov w2,#44
 madd w2,w23,w2,wzr
 add w2,w2,#204
 bl probe_diag_text
 ldr x0,[x20,x22,lsl #3]
 add w1,w24,#270
 mov w2,#44
 madd w2,w23,w2,wzr
 add w2,w2,#204
 bl probe_diag_hex64
 add x22,x22,#1
 cmp x22,#32
 b.lo 2b
 bl probe_diag_publish
9:
 ldp x18,x19,[sp,#16]
 ldp x20,x21,[sp,#32]
 ldp x22,x23,[sp,#48]
 ldp x24,x25,[sp,#64]
 ldp x26,x27,[sp,#80]
 ldr x28,[sp,#96]
 ldp x29,x30,[sp],#112
 ret
.balign 16
screen_labels:
 .asciz "STAGE:"
 .space 9
 .asciz "STATUS:"
 .space 8
 .asciz "CHECKS:"
 .space 8
 .asciz "ARCH:"
 .space 10
 .asciz "DT CHECK:"
 .space 6
 .asciz "DISPLAY:"
 .space 7
 .asciz "SCTLR:"
 .space 9
 .asciz "COMPLETE:"
 .space 6
 .asciz "WIN OUTCOME:"
 .space 3
 .asciz "WIN STATUS:"
 .space 4
 .asciz "EBS PHASE:"
 .space 5
 .asciz "EBS REASON:"
 .space 4
 .asciz "ACPI PHASE:"
 .space 4
 .asciz "ACPI STATUS:"
 .space 3
 .asciz "ACPI CHECKS:"
 .space 3
 .asciz "ACPI REASON:"
 .space 3
 .asciz "RUN READ N:"
 .space 4
 .asciz "RUN BYTES:"
 .space 5
 .asciz "SDI READ:"
 .space 6
 .asciz "WIM READ:"
 .space 6
 .asciz "HIGH READ N:"
 .space 3
 .asciz "HIGH BYTES:"
 .space 4
 .asciz "RUN REJECT:"
 .space 4
 .asciz "EBS CHECKS:"
 .space 4
 .asciz "MEM CHECKS:"
 .space 4
 .asciz "RAM CHECKS:"
 .space 4
 .asciz "UFS PHASE:"
 .space 5
 .asciz "UFS STATUS:"
 .space 4
 .asciz "DMA CHECKS:"
 .space 4
 .asciz "TIMER CTRL:"
 .space 4
 .asciz "VALID BYTES:"
 .space 3
 .asciz "EBS RETRY:"
 .space 5
#include "sec68_framebuffer.inc"

.balign 2048
.global probe_exception_vectors
probe_exception_vectors:
.rept 16
 b probe_exception
 .space 124
.endr
probe_exception:
 msr DAIFSet,#15
 addr x9,probe_sec49_report
 mov x10,#0x43ee
 str x10,[x9,#128]
 mrs x10,ESR_EL1
 str x10,[x9,#136]
 mrs x10,ELR_EL1
 str x10,[x9,#144]
 mrs x10,FAR_EL1
 str x10,[x9,#152]
 mrs x10,SPSR_EL1
 str x10,[x9,#160]
 mrs x10,CurrentEL
 str x10,[x9,#168]
 mov x0,#2
 mov x1,#0x43ee
 bl probe_sec_screen
 b probe_halt

.section .bss,"aw",%nobits
.balign 16
probe_screen_values: .space 256
.section .stack,"aw"
.balign 4096
.space 4080
.global probe_stack_guard_low,probe_stack_bottom,probe_stack_top,probe_stack_guard_high
probe_stack_guard_low: .space 16
probe_stack_bottom: .space 65536
probe_stack_top:
probe_stack_guard_high: .space 16
.balign 4096

// Preserve typed symbols for the existing retained-relocation ELF auditor.
.type image_start,%object
.type image_end,%object
.type image_size,%object
.type wrapper_code_end,%object
.type __writable_start,%object
.type __writable_end,%object
.type __data_start,%object
.type __data_end,%object
.type __bss_start,%object
.type __bss_end,%object
.type probe_stack_bottom,%object
.type probe_stack_top,%object
.type probe_stack_guard_low,%object
.type probe_stack_guard_high,%object
.type probe_entry,%function
.type probe_halt,%function
.type probe_sec_screen,%function
.type probe_sec_sync,%function
.type probe_invalidate_data_range,%function
