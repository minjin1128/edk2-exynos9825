/* SPDX-License-Identifier: BSD-2-Clause-Patent */
#ifndef N976N_SYSTEM_VOLUME_FIXTURE_H_
#define N976N_SYSTEM_VOLUME_FIXTURE_H_
#include <N976nPlatform.h>
/* [magic, version, size, checks, status, file reads, active, GPT reads].
 * This fixture is synthetic host media, never physical GPT/UFS evidence. */
extern volatile UINT64 mN976nSystemVolumeFixture[8];
EFI_STATUS N976nRunSystemVolumeFixture (CONST N976N_PLATFORM_HANDOFF *Handoff);
#endif
