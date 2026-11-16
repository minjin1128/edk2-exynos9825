/* SPDX-License-Identifier: GPL-2.0-only
 * SEC76 offline connection of resource/handoff checks to the ID-only engine.
 */
#include "N976nIdPath.h"
static void Zero(void *P, N976N_SIZE N)
{
    N976N_U8 *B = (N976N_U8 *)P;
    while (N != 0U) { *B++ = 0; --N; }
}
N976N_ID_STATUS N976nRunIdOnce(N976N_ID_SESSION *Session,
    const N976N_RESOURCE *Raw, const N976N_RESOURCE *Translated,
    N976N_SIZE ResourceCount,
    const N976N_PLATFORM_HANDOFF *Handoff, const N976N_PLATFORM_FRESH *Fresh,
    const N976N_HSI_LEASE *PreparedController,
    const N976N_HSI_IO *Io, N976N_ID_RESULT *Result)
{
    N976N_CONTROLLER_RESOURCE_PLAN Resource;
    N976N_PLATFORM_PLAN Platform;
    N976N_HSI_STATUS Status;
    if (!Result) return N976nIdInvalid;
    Zero(Result, sizeof(*Result));
    Result->Status = N976nIdInvalid;
    Result->ResourceStatus = N976nResourceInvalid;
    Result->PlatformStatus = N976nPlatformInvalid;
    if (!Session || !Session->Generation || !Io || !Io->Read32 || !Io->Write32 ||
        !Io->NowUs || !Io->StillOwned) return N976nIdInvalid;
    if (Session->Attempted || Session->Running || Session->Quarantined) {
        Result->Status = N976nIdAlreadyUsed;
        return N976nIdAlreadyUsed;
    }
    Result->ResourceStatus = N976nValidateControllerResources(
        Raw, Translated, ResourceCount, &Resource);
    if (Result->ResourceStatus != N976nResourceOk) {
        Result->Status = N976nIdResourceRejected;
        return N976nIdResourceRejected;
    }
    Result->PlatformStatus = N976nPlatformCheckIdReady(
        Handoff, Fresh, Session->Generation, &Platform);
    if (Result->PlatformStatus != N976nPlatformOk || !Platform.Valid ||
        !Platform.PrimaryIrqMaskedOwned) {
        Result->Status = N976nIdHandoffRejected;
        return N976nIdHandoffRejected;
    }
    /* Platform/power metadata does not establish controller initialization.
     * A separate controller owner supplies its prepared timing evidence; the
     * engine independently checks actual timing registers before any write. */
    if (!PreparedController || PreparedController->Generation != Platform.Generation ||
        PreparedController->Base != Resource.Base[0] ||
        PreparedController->Bytes != Resource.Bytes[0] ||
        PreparedController->InputHz != Platform.InputClockHz ||
        PreparedController->Address != N976N_I2C_ADDRESS ||
        PreparedController->SpeedHz != N976N_HSI_ID_SPEED_HZ ||
        PreparedController->Flags != N976nHsiLeaseRequired) {
        Result->Status = N976nIdPreparationRejected;
        return N976nIdPreparationRejected;
    }
    Session->Attempted = 1;
    Session->Running = 1;
    Status = N976nHsiReadId(Io, PreparedController, &Result->Transfer);
    Session->Running = 0;
    Session->Quarantined = Result->Transfer.Quarantined;
    Result->Submitted = Result->Transfer.MessagesIssued;
    Result->Retired = Result->Transfer.Retired;
    if (Status != N976nHsiOk || !Result->Transfer.IdValid ||
        !Result->Transfer.Retired || Result->Transfer.Quarantined) {
        Result->Status = N976nIdTransferFailed;
        return N976nIdTransferFailed;
    }
    Result->Id = Result->Transfer.Id;
    Result->IdValid = 1;
    Result->Status = N976nIdOk;
    return N976nIdOk;
}
