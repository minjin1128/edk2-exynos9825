/* SPDX-License-Identifier: MIT */
#ifndef N976N_HIGH_RAM_ADMISSION_H_
#define N976N_HIGH_RAM_ADMISSION_H_
#include <N976nHighRam.h>
#include <LegacyMemory/MemoryPlan.h>

/* Pure software gate. H and Plan are the already parsed SEC-owned inputs;
   Admission is separate writable SEC storage. No candidate CPU access, MMU
   mapping, HOB resource grant or secure-hardware ownership proof occurs. */
BOOLEAN EFIAPI N976nAdmitHighRam (
  CONST SEC_PROBE_HANDOFF *H,
  CONST MEMORY_PLAN *Plan,
  N976N_HIGH_RAM_ADMISSION *Admission
  );
#endif
