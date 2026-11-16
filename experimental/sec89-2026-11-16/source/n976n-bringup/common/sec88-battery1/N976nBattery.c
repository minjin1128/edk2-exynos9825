/* SPDX-License-Identifier: MIT
 * Independently written from Samsung N976N KOR12 register/encoding facts.
 * Reference provenance and exact Samsung getter lines are recorded in
 * references/sec88-battery1/reference-analysis.md and codec-provenance.md.
 */
#include "N976nBattery.h"

static const N976N_BATTERY_READ mReads[N976N_BAT_FIELD_COUNT] = {
  {0x36, 0x00, 2}, /* STATUS: bit3 is battery absent. */
  {0x36, 0x06, 2}, /* SOCREP. */
  {0x36, 0x09, 2}, /* VCELL. */
  {0x36, 0x0A, 2}, /* CURRENT. */
  {0x36, 0x0B, 2}, /* AVG_CURRENT. */
  {0x36, 0x05, 2}, /* RemCapRep. */
  {0x36, 0x35, 2}, /* FullCapRep. */
  {0x69, 0xB2, 1}, /* INT_OK live inputs; not clear-on-read INT at B0. */
  {0x69, 0xB4, 1}  /* DETAILS01 live charge-state nibble. */
};

int N976nBatteryReadSpec(N976N_BAT_U32 Field, N976N_BATTERY_READ *Read)
{
  if (!Read) return 0;
  Read->Address = Read->Register = Read->Bytes = 0;
  if (Field >= N976N_BAT_FIELD_COUNT) return 0;
  *Read = mReads[Field];
  return 1;
}

int N976nBatteryReadAllowed(N976N_BAT_U32 Address, N976N_BAT_U32 Register,
                          N976N_BAT_U32 Bytes)
{
  N976N_BAT_U32 I;
  for (I = 0; I < N976N_BAT_FIELD_COUNT; ++I)
    if (Address == mReads[I].Address && Register == mReads[I].Register &&
        Bytes == mReads[I].Bytes) return 1;
  return 0;
}

int N976nBatteryBegin(N976N_BATTERY_RAW *Raw, N976N_BAT_U64 SampleId)
{
  N976N_BAT_U32 I;
  if (!Raw) return 0;
  Raw->SampleId = SampleId;
  Raw->AttemptedMask = Raw->ValidMask = Raw->FailedMask = 0;
  for (I = 0; I < N976N_BAT_FIELD_COUNT; ++I) {
    Raw->Raw[I] = 0;
    Raw->Result[I] = N976N_BAT_OK;
  }
  return SampleId != 0;
}

enum N976N_BATTERY_RESULT N976nBatteryRecord(
  N976N_BATTERY_RAW *Raw, N976N_BAT_U32 Field, int TransferOk,
  const N976N_BAT_U8 *Data, N976N_BAT_U32 BytesReceived)
{
  N976N_BAT_U32 Bit;
  N976N_BAT_U16 Word = 0;
  enum N976N_BATTERY_RESULT Result;
  if (!Raw || Field >= N976N_BAT_FIELD_COUNT) return N976N_BAT_BAD_ARGUMENT;
  Bit = N976N_BAT_FIELD_BIT(Field);
  if (!Raw->SampleId || !Data) Result = N976N_BAT_BAD_ARGUMENT;
  else if (!TransferOk) Result = N976N_BAT_TRANSPORT_FAILED;
  else if (BytesReceived != mReads[Field].Bytes) Result = N976N_BAT_BAD_LENGTH;
  else {
    /* Read before clearing the field, so a caller-owned input slice may also
     * point at that raw word. Never read payload bytes on transfer failure. */
    Word = Data[0];
    if (BytesReceived == 2) Word |= (N976N_BAT_U16)Data[1] << 8;
    Result = N976N_BAT_OK;
  }
  Raw->AttemptedMask |= Bit;
  Raw->ValidMask &= ~Bit;
  Raw->FailedMask &= ~Bit;
  Raw->Raw[Field] = Word;
  Raw->Result[Field] = (N976N_BAT_U8)Result;
  if (Result == N976N_BAT_OK) Raw->ValidMask |= Bit;
  else Raw->FailedMask |= Bit;
  return Result;
}

static N976N_BAT_I32 CurrentMa(N976N_BAT_U16 Word, N976N_BAT_U32 Resistor)
{
  N976N_BAT_U32 Magnitude = (Word & 0x8000U) ? 0x10000U - Word : Word;
  N976N_BAT_U64 Value = (N976N_BAT_U64)Magnitude * 15625U *
                        Resistor / 100000U;
  return (Word & 0x8000U) ? -(N976N_BAT_I32)Value : (N976N_BAT_I32)Value;
}

static int RawValid(const N976N_BATTERY_RAW *Raw)
{
  N976N_BAT_U32 I;
  if (!Raw || !Raw->SampleId ||
      ((Raw->AttemptedMask | Raw->ValidMask | Raw->FailedMask) & ~N976N_BAT_ALL_FIELDS) ||
      (Raw->ValidMask & Raw->FailedMask) ||
      (Raw->ValidMask | Raw->FailedMask) != Raw->AttemptedMask) return 0;
  for (I = 0; I < N976N_BAT_FIELD_COUNT; ++I) {
    N976N_BAT_U32 Bit = N976N_BAT_FIELD_BIT(I);
    if (Raw->ValidMask & Bit) {
      if (Raw->Result[I] != N976N_BAT_OK ||
          (mReads[I].Bytes == 1 && Raw->Raw[I] > 255U)) return 0;
    } else if (Raw->FailedMask & Bit) {
      if (Raw->Result[I] < N976N_BAT_BAD_ARGUMENT ||
          Raw->Result[I] > N976N_BAT_BAD_LENGTH || Raw->Raw[I]) return 0;
    } else if (Raw->Result[I] || Raw->Raw[I]) return 0;
  }
  return 1;
}

int N976nBatteryDecode(const N976N_BATTERY_RAW *Raw,
                      N976N_BAT_U32 AdmittedResistor,
                      N976N_BATTERY_VALUES *Values)
{
  N976N_BAT_U32 Word, Soc;
  N976N_BATTERY_VALUES V = {0};
  if (!Values) return 0;
  *Values = V;
  if (!RawValid(Raw) || (AdmittedResistor != 0 && AdmittedResistor != 2 &&
                        AdmittedResistor != 5)) return 0;
  V.SampleId = Raw->SampleId;
  V.FgResistor = AdmittedResistor;
  V.RawValidMask = V.ValueValidMask = Raw->ValidMask;
  if (!AdmittedResistor) V.ValueValidMask &= ~(
    N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT) | N976N_BAT_FIELD_BIT(N976N_BAT_AVG_CURRENT) |
    N976N_BAT_FIELD_BIT(N976N_BAT_REMAINING) | N976N_BAT_FIELD_BIT(N976N_BAT_FULL));
  if (Raw->ValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_STATUS)) {
    Word = Raw->Raw[N976N_BAT_STATUS];
    if (Word == 0xFFFFU) {
      /* Local observation policy, not an invented MAX77705 sentinel. Preserve
       * the successful raw read but do not call all-ones a known absence. */
      V.SuspiciousMask |= N976N_BAT_FIELD_BIT(N976N_BAT_STATUS);
      V.ValueValidMask &= ~N976N_BAT_FIELD_BIT(N976N_BAT_STATUS);
    } else V.Present = (Word & 8U) == 0;
  }
  if (Raw->ValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_SOCREP)) {
    Word = Raw->Raw[N976N_BAT_SOCREP];
    Soc = (((Word >> 8) * 100U) + ((Word & 255U) * 100U / 256U)) / 10U;
    V.SocClamped = Soc > 1000U;
    V.SocPermille = V.SocClamped ? 1000U : Soc;
  }
  if (Raw->ValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_VCELL)) {
    Word = Raw->Raw[N976N_BAT_VCELL];
    /* Preserve Samsung's two-part integer mV rounding, not a floating-point
     * equivalent with a different final truncation. */
    V.VoltageMv = ((Word & 0x0FFFU) * 78125U / 1000000U) +
                 (((((Word & 0xF000U) >> 4) * 78125U) / 1000000U) << 4);
  }
  if (V.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT))
    V.CurrentMa = CurrentMa(Raw->Raw[N976N_BAT_CURRENT], AdmittedResistor);
  if (V.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_AVG_CURRENT))
    V.AverageCurrentMa = CurrentMa(Raw->Raw[N976N_BAT_AVG_CURRENT], AdmittedResistor);
  if (V.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_REMAINING))
    V.RemainingMah = (N976N_BAT_U32)Raw->Raw[N976N_BAT_REMAINING] *
                     AdmittedResistor / 2U;
  if (V.ValueValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_FULL))
    V.FullMah = (N976N_BAT_U32)Raw->Raw[N976N_BAT_FULL] * AdmittedResistor / 2U;
  if (Raw->ValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_INPUT)) {
    V.WiredInput = !!(Raw->Raw[N976N_BAT_INPUT] & 0x40U);
    V.WirelessInput = !!(Raw->Raw[N976N_BAT_INPUT] & 0x20U);
  }
  if (Raw->ValidMask & N976N_BAT_FIELD_BIT(N976N_BAT_CHARGE_DETAIL)) {
    Word = Raw->Raw[N976N_BAT_CHARGE_DETAIL] & 15U;
    if (Word <= 2U) V.ChargeState = N976N_BAT_CHARGING;
    else if (Word <= 4U) V.ChargeState = N976N_BAT_FULLY_CHARGED;
    else if (Word <= 7U) V.ChargeState = N976N_BAT_NOT_CHARGING;
    else if (Word == 8U || Word == 10U || Word == 11U) V.ChargeState = N976N_BAT_DISCHARGING;
    else V.ValueValidMask &= ~N976N_BAT_FIELD_BIT(N976N_BAT_CHARGE_DETAIL);
  }
  *Values = V;
  return 1;
}
