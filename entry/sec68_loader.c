/* SPDX-License-Identifier: MIT
 * Narrow adapter for the existing audited, offline-expanded SEC PE loader.
 * No allocator or firmware service is reimplemented here. */
#include <stdint.h>
#include <stddef.h>
#include "sec_payload_config.h"
#define HIDDEN __attribute__((visibility("hidden")))
extern HIDDEN uint8_t image_start[];
extern HIDDEN uint8_t sec_payload_begin[], sec_payload_end[];
extern HIDDEN uint8_t dxe_fv_begin[], dxe_fv_end[], probe_stack_bottom[], probe_stack_top[];
extern HIDDEN const uint32_t sec_fixups_begin[], sec_fixups_end[];
extern HIDDEN void probe_sec_screen(uint64_t, uint64_t), probe_sec_sync(uint64_t,uint64_t);
HIDDEN uint64_t probe_phone_input[16];
HIDDEN volatile uint64_t probe_sec49_report[64];
#define LINK_ADDRESS(symbol) ({ uint64_t p; __asm__("adrp %0, " #symbol "\n\tadd %0, %0, :lo12:" #symbol : "=r"(p)); p; })
static uint64_t address(const void *p) { return (uint64_t)(uintptr_t)p; }
static uint32_t crc32(const uint8_t *p, uint64_t size) {
  uint32_t crc=~0U;
  while (size--) { crc ^= *p++; for (unsigned n=0;n<8;n++) crc=(crc>>1)^(0xedb88320U & (0U-(crc&1))); }
  return ~crc;
}
static uint64_t fail(uint64_t code) {
  probe_sec49_report[1]=code;
  probe_sec_screen(2,code);
  return code;
}
HIDDEN uint64_t probe_sec_load(uint64_t dtb) {
  uint64_t base=address(sec_payload_begin), end=address(sec_payload_end);
  probe_sec49_report[0]=0x5345433433535444ULL;
  probe_sec49_report[2]=1;
  probe_sec_screen(1,1);
  if ((base&4095) || end<base || end-base!=SEC_PE_SIZE ||
      address(dxe_fv_end)-address(dxe_fv_begin)!=SEC_FV_SIZE ||
      address(sec_fixups_end)-address(sec_fixups_begin)!=SEC_PE_FIXUP_COUNT*4 ||
      SEC_PE_ENTRY>=SEC_PE_SIZE || SEC_PE_IMAGEBASE_OFFSET>SEC_PE_SIZE-8)
    return fail(0x4300);
  if (crc32(sec_payload_begin, SEC_PE_SIZE)!=SEC_PE_CRC) return fail(0x4301);
  if (crc32(dxe_fv_begin, SEC_FV_SIZE)!=SEC_FV_CRC) return fail(0x4302);
  uint32_t previous=0;
  for (unsigned i=0;i<SEC_PE_FIXUP_COUNT;i++) {
    uint32_t off=sec_fixups_begin[i];
    if ((off&7) || off>SEC_PE_SIZE-8 || (i && off<=previous) || !sec_pe_writable(off,8))
      return fail(0x4303);
    if (!sec_pe_address(*(const uint64_t *)(uintptr_t)(base+off))) return fail(0x4304);
    previous=off;
  }
  for (unsigned i=0;i<SEC_PE_FIXUP_COUNT;i++) *(uint64_t *)(uintptr_t)(base+sec_fixups_begin[i])+=base;
  *(uint64_t *)(uintptr_t)(base+SEC_PE_IMAGEBASE_OFFSET)=base;
  /* Same proven clean-to-PoC + I invalidation boundary as SEC29 FIX1 onward. */
  probe_sec_sync(base,end);
  uint64_t *h=probe_phone_input;
  h[0]=0x534543343350484eULL; h[1]=sizeof(probe_phone_input);
  h[2]=address(image_start); h[3]=LINK_ADDRESS(image_end);
  h[4]=LINK_ADDRESS(wrapper_code_end); h[5]=LINK_ADDRESS(__writable_start); h[6]=LINK_ADDRESS(__writable_end);
  h[7]=base; h[8]=end-base; h[9]=address(dxe_fv_begin); h[10]=SEC_FV_SIZE; h[11]=dtb;
  h[12]=address(probe_stack_bottom); h[13]=address(probe_stack_top)-h[12];
  h[14]=(uint64_t)(uintptr_t)probe_sec_screen; h[15]=address((const void *)probe_sec49_report);
  ((void (*)(uint64_t *))(uintptr_t)(base+SEC_PE_ENTRY))(h);
  return fail(0x4305); /* SEC/DXE/BDS must never return into Android entry. */
}
