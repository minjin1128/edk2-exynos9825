/* SPDX-License-Identifier: MIT. Zero-linked, bounded Android ARM64 Image. */
OUTPUT_FORMAT(elf64-littleaarch64)
OUTPUT_ARCH(aarch64)
ENTRY(probe_entry)
SECTIONS {
  . = 0;
  .text : ALIGN(2048) {
    KEEP(*(.text.boot))
    *(.text .text.*)
    *(.rodata .rodata.*)
    . = ALIGN(4096);
  }
  wrapper_code_end = .;
  __writable_start = .;
  .data : ALIGN(4096) {
    __data_start = .;
    *(.data .data.*)
    . = ALIGN(16);
    __data_end = .;
  }
  .bss (NOLOAD) : ALIGN(16) {
    __bss_start = .;
    *(.bss .bss.*) *(COMMON)
    . = ALIGN(16);
    __bss_end = .;
  }
  .stack : ALIGN(4096) { KEEP(*(.stack)) . = ALIGN(4096); }
  __writable_end = .;
  .rodata : ALIGN(4096) { KEEP(*(.secimage)) }
  .bootpayload : ALIGN(4096) { KEEP(*(.bootpayload)) }
  . = ALIGN(4096);
  image_end = .;
  image_size = image_end - image_start;
  /DISCARD/ : { *(.comment .note .note.* .eh_frame .eh_frame_hdr .llvm_addrsig) }
  ASSERT(image_start == 0 && probe_entry == 64, "ARM64 entry layout")
  ASSERT(image_size <= 0xC00000, "12MiB Image limit")
  ASSERT(__data_start == wrapper_code_end, "Code/data boundary")
  ASSERT(__writable_end == sec_payload_begin, "Writable/SEC boundary")
  ASSERT(probe_stack_top - probe_stack_bottom == 0x10000, "64KiB stack")
  ASSERT(probe_stack_bottom % 4096 == 0 && probe_stack_top % 4096 == 0, "Stack alignment")
  ASSERT(dxe_fv_end == image_end, "FV immutable tail")
}
