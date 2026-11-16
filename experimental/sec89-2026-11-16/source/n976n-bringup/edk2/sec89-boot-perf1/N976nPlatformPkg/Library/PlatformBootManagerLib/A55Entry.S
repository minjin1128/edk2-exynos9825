/* SPDX-License-Identifier: MIT
 * Stackless entry witness for Samsung legacy CPU_ON. Do not rely on x0 being
 * the submitted context_id: preserve it as evidence, never dereference it.
 * All code-relative references remain within the copied [Start,End) block.
 */
#include <N976nA55Entry.h>

    .text
    .p2align 3
    .global N976nA55EntryStart
    .global N976nA55EntryEnd
    .global N976nA55EntryConfig
N976nA55EntryStart:
    mov     x12, x0
    mrs     x3, CurrentEL
    cmp     x3, #4
    b.eq    .La55_el1
    cmp     x3, #8
    b       .La55_park

    mrs     x5, DAIF
    msr     DAIFSet, #15
    mrs     x4, SCTLR_EL2
    b       .La55_state
.La55_el1:
    mrs     x5, DAIF
    msr     DAIFSet, #15
    mrs     x4, SCTLR_EL1
.La55_state:
    /* Unknown active translation/cache state is not repaired in this probe.
     * No config or witness data access occurs until M/C/I are all clear.
     */
    mov     x8, #0x1005
    tst     x4, x8
    b.ne    .La55_park

    adr     x9, .La55_config
    ldr     x8, [x9, #N976N_A55_CONFIG_MAGIC_OFF]
    movz    x14, #(N976N_A55_ENTRY_CONFIG_MAGIC & 0xffff)
    movk    x14, #((N976N_A55_ENTRY_CONFIG_MAGIC >> 16) & 0xffff), lsl #16
    movk    x14, #((N976N_A55_ENTRY_CONFIG_MAGIC >> 32) & 0xffff), lsl #32
    movk    x14, #((N976N_A55_ENTRY_CONFIG_MAGIC >> 48) & 0xffff), lsl #48
    cmp     x8, x14
    b.ne    .La55_park
    ldr     x10, [x9, #N976N_A55_CONFIG_WITNESS_OFF]
    cbz     x10, .La55_park
    tst     x10, #0xfff
    b.ne    .La55_park
    lsr     x8, x10, #32
    cbnz    x8, .La55_park
    ldr     x11, [x9, #N976N_A55_CONFIG_AFFINITY_OFF]
    ldr     x15, [x9, #N976N_A55_CONFIG_TARGET_OFF]
    /* Exact platform pairs, not a generic target-to-MPIDR shift rule. */
    cmp     x15, #N976N_A55_TARGET1
    b.eq    .La55_target1
    cmp     x15, #N976N_A55_TARGET2
    b.eq    .La55_target2
    cmp     x15, #N976N_A55_TARGET3
    b.ne    .La55_park
    cmp     x11, #N976N_A55_AFFINITY3
    b       .La55_pair_checked
.La55_target1:
    cmp     x11, #N976N_A55_AFFINITY1
    b       .La55_pair_checked
.La55_target2:
    cmp     x11, #N976N_A55_AFFINITY2
.La55_pair_checked:
    b.ne    .La55_park

    mrs     x1, MPIDR_EL1
    mrs     x2, MIDR_EL1
    mrs     x6, CNTFRQ_EL0
    mov     x7, #-1
    cmp     x3, #8
    b.ne    .La55_counter_done
    /* EL2 can read its virtual counter. At EL1 CNTHCTL_EL2 may trap this
     * access; leave the explicit UNREAD sentinel instead of risking a fault.
     */
    isb
    mrs     x7, CNTVCT_EL0
.La55_counter_done:
    mov     x13, #N976N_A55_ENTRY_STATUS_OK
    tbz     x1, #24, .La55_wrong_id
    and     x8, x1, #0xffffff
    cmp     x8, x11
    b.ne    .La55_wrong_id
    ubfx    x8, x1, #32, #8
    cbz     x8, .La55_identity_done
.La55_wrong_id:
    mov     x13, #N976N_A55_ENTRY_STATUS_MPIDR
.La55_identity_done:
    /* New handoff only accepts measured EL1/A55, with caches/MMU off. */
    cbnz    x13, .La55_record
    ubfx    x8, x2, #24, #8
    cmp     x8, #0x41
    b.ne    .La55_bad_platform
    ubfx    x8, x2, #4, #12
    cmp     x8, #0xd05
    b.ne    .La55_bad_platform
    tbnz    x4, #25, .La55_bad_platform
    ldr     x16, [x9, #N976N_A55_CONFIG_MAILBOX_OFF]
    cbz     x16, .La55_bad_platform
    tst     x16, #0xfff
    b.ne    .La55_bad_platform
    lsr     x8, x16, #32
    cbnz    x8, .La55_bad_platform
    /* GIC bases are admitted N976N constants, not arbitrary config MMIO. */
    ldr     x17, [x9, #N976N_A55_CONFIG_GICD_OFF]
    movz    x8, #0x1000
    movk    x8, #0x1010, lsl #16
    cmp     x17, x8
    b.eq    .La55_phone_gic
    /* The other explicit pair is for generic QEMU instruction tests. */
    mov     x8, #0x08000000
    cmp     x17, x8
    b.ne    .La55_bad_platform
    mov     x8, #0x08010000
    b       .La55_check_gicc
.La55_phone_gic:
    add     x8, x8, #0x1000
.La55_check_gicc:
    ldr     x18, [x9, #N976N_A55_CONFIG_GICC_OFF]
    cmp     x18, x8
    b.ne    .La55_bad_platform
    /* Banked SGI target identifies this GICv2 interface, not MPIDR. */
    ldr     w8, [x17, #0x800]
    and     w19, w8, #0xff
    cbz     w19, .La55_bad_platform
    sub     w8, w19, #1
    tst     w8, w19
    b.ne    .La55_bad_platform
    rbit    w20, w19
    clz     w20, w20
    /* Only banked SGI/PPI registers are changed. No shared SPI routing. */
    mov     w8, #0xffff0000
    str     w8, [x17, #0x180]
    str     w8, [x17, #0x280]
    mov     w8, #0xffff
    str     w8, [x17, #0x100]
    mov     w8, #0x80808080
    mov     x21, #0
.La55_priorities:
    add     x22, x17, #0x400
    str     w8, [x22, x21]
    add     x21, x21, #4
    cmp     x21, #32
    b.ne    .La55_priorities
    mov     w8, #0xff
    str     w8, [x18, #4]
    str     wzr, [x18, #8]
    mov     w8, #1
    str     w8, [x18]
    /* Architectural physical timer is disarmed, as on BSP EBS. SGIs stay on. */
    msr     CNTP_CTL_EL0, xzr
    ic      iallu
    dsb     sy
    isb
    ldr     w8, [x18]
    tbz     w8, #0, .La55_bad_platform
    str     x8, [x10, #N976N_A55_W_GICCTLR_OFF]
    ldr     w8, [x18, #4]
    cmp     w8, #0x80
    b.ls    .La55_bad_platform
    str     x8, [x10, #N976N_A55_W_GICPMR_OFF]
    str     x20, [x10, #N976N_A55_W_INTERFACE_OFF]
    str     x19, [x10, #N976N_A55_W_GICTARGET_OFF]
    mrs     x8, CNTP_CTL_EL0
    str     x8, [x10, #N976N_A55_W_TIMER_OFF]
    tbnz    x8, #0, .La55_bad_platform
    mrs     x8, DAIF
    str     x8, [x10, #N976N_A55_W_READYDAIF_OFF]
    b       .La55_record
.La55_bad_platform:
    mov     x13, #2
.La55_record:
    str     xzr, [x10, #N976N_A55_W_PARKED_OFF]
    movz    x14, #(N976N_A55_ENTRY_MAGIC & 0xffff)
    movk    x14, #((N976N_A55_ENTRY_MAGIC >> 16) & 0xffff), lsl #16
    movk    x14, #((N976N_A55_ENTRY_MAGIC >> 32) & 0xffff), lsl #32
    movk    x14, #((N976N_A55_ENTRY_MAGIC >> 48) & 0xffff), lsl #48
    str     x14, [x10, #N976N_A55_W_MAGIC_OFF]
    mov     x8, #N976N_A55_ENTRY_VERSION
    str     x8, [x10, #N976N_A55_W_VERSION_OFF]
    mov     x8, #N976N_A55_ENTRY_WITNESS_BYTES
    str     x8, [x10, #N976N_A55_W_BYTES_OFF]
    str     x11, [x10, #N976N_A55_W_EXPECTED_OFF]
    str     x1, [x10, #N976N_A55_W_MPIDR_OFF]
    str     x2, [x10, #N976N_A55_W_MIDR_OFF]
    str     x3, [x10, #N976N_A55_W_EL_OFF]
    str     x4, [x10, #N976N_A55_W_SCTLR_OFF]
    str     x5, [x10, #N976N_A55_W_DAIF_OFF]
    str     x12, [x10, #N976N_A55_W_CONTEXT_OFF]
    str     x6, [x10, #N976N_A55_W_CNTFRQ_OFF]
    str     x7, [x10, #N976N_A55_W_CNTVCT_OFF]
    str     x13, [x10, #N976N_A55_W_STATUS_OFF]
    str     x15, [x10, #N976N_A55_W_TARGET_OFF]
    str     xzr, [x10, #N976N_A55_W_RESERVED1_OFF]
    dsb     sy
    movz    x14, #(N976N_A55_ENTRY_PARKED & 0xffff)
    movk    x14, #((N976N_A55_ENTRY_PARKED >> 16) & 0xffff), lsl #16
    movk    x14, #((N976N_A55_ENTRY_PARKED >> 32) & 0xffff), lsl #32
    movk    x14, #((N976N_A55_ENTRY_PARKED >> 48) & 0xffff), lsl #48
    str     x14, [x10, #N976N_A55_W_PARKED_OFF]
    dsb     sy
    cbnz    x13, .La55_park
    /* Standard mailbox: ID is GICC interface number (u32), jump at +8.
     * No writes into OS-reserved +16..+2047. No execution before the ID matches.
     */
.La55_mailbox:
    ldr     w8, [x16]
    cmp     w8, w20
    b.ne    .La55_wait_irq
    dsb     sy
    ldr     x23, [x16, #8]
    cbz     x23, .La55_wait_irq
    tst     x23, #3
    b.ne    .La55_wait_irq
    /* Retire a pending wake SGI before OS entry. Preserve full IAR token. */
    ldr     w8, [x18, #0xc]
    and     w9, w8, #0x3ff
    cmp     w9, #1020
    b.hs    .La55_ack_jump
    str     w8, [x18, #0x10]
.La55_ack_jump:
    str     xzr, [x16, #8]
    dsb     sy
    isb
    mov     x0, x16
    br      x23
.La55_wait_irq:
    dsb     sy
    wfi
    ldr     w8, [x18, #0xc]
    and     w9, w8, #0x3ff
    cmp     w9, #1020
    b.hs    .La55_mailbox
    str     w8, [x18, #0x10]
    dsb     sy
    b       .La55_mailbox
.La55_park:
    wfe
    b       .La55_park

    .p2align 3
N976nA55EntryConfig:
.La55_config:
    .quad   N976N_A55_ENTRY_CONFIG_MAGIC
    .quad   0 /* BSP patches the owned physical witness page before RO/X. */
    .quad   0 /* BSP patches exact ExpectedAffinity before RO/X. */
    .quad   0 /* Independent DT CPU_ON target, still 1, 2 or 3. */
    .quad   0 /* Owned, dedicated OS mailbox page. */
    .quad   0 /* N976N GICD, banked private registers only. */
    .quad   0 /* N976N GICC. */
N976nA55EntryEnd:

    /* BSP checks copied size/config alignment from these exported symbols.
     * LLVM cannot evaluate distances across the alignment fragment in .if.
     */
    .if (N976nA55EntryEnd - N976nA55EntryConfig) != N976N_A55_ENTRY_CONFIG_BYTES
    .error "A55 embedded config size disagrees with its C contract"
    .endif
