/* SPDX-License-Identifier: GPL-2.0-only */
#ifndef N976N_ID_PATH_H
#define N976N_ID_PATH_H
#include "N976nPlatform.h"
#include "N976nHsi2c.h"

/* One provider-owned diagnostic per lifetime. The future adapter initializes
 * a fresh zeroed session with its actual nonzero Generation. This is not a
 * user IOCTL or firmware wire format. Never clear Attempted/Quarantined to
 * retry within that lifetime. All arguments/output storage must be disjoint.
 */
typedef struct {
    N976N_U64 Generation;
    N976N_U32 Attempted, Running, Quarantined;
} N976N_ID_SESSION;
typedef enum {
    N976nIdOk = 0, N976nIdInvalid = 1, N976nIdAlreadyUsed = 2,
    N976nIdResourceRejected = 3, N976nIdHandoffRejected = 4,
    N976nIdTransferFailed = 5, N976nIdPreparationRejected = 6
} N976N_ID_STATUS;
typedef struct {
    N976N_U32 Status, Submitted, Retired, IdValid, Id;
    N976N_RESOURCE_RESULT ResourceStatus;
    N976N_PLATFORM_RESULT PlatformStatus;
    N976N_HSI_RESULT Transfer;
} N976N_ID_RESULT;

/* Caller holds continuous single-owner serialization and owns the callbacks.
 * No IRQ provider, firmware producer, MMIO mapper or WDF activation is implied.
 * Readiness metadata is checked before any injected I/O can occur.
 * Success retires only the ID transaction, not GPIO/clock/power configuration.
 */
N976N_ID_STATUS N976nRunIdOnce(N976N_ID_SESSION *Session,
    const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE ResourceCount,
    const N976N_PLATFORM_HANDOFF *Handoff, const N976N_PLATFORM_FRESH *Fresh,
    const N976N_HSI_LEASE *PreparedController,
    const N976N_HSI_IO *Io, N976N_ID_RESULT *Result);
#endif
