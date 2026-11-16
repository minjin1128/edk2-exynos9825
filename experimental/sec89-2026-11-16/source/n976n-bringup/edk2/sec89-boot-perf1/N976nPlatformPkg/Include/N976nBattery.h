/* SPDX-License-Identifier: MIT
 * Pure N976N MAX77705 observation contract. No register writes, transport,
 * Windows/UEFI calls, charging policy or protection claims live in this file.
 */
#ifndef N976N_BATTERY_H
#define N976N_BATTERY_H

/* Firmware may supply these exact-width types before including this header.
 * This keeps the same implementation usable with EDK2, WDK and host tests. */
#ifndef N976N_BATTERY_EXTERNAL_TYPES
#include <stdint.h>
typedef uint8_t  N976N_BAT_U8;
typedef uint16_t N976N_BAT_U16;
typedef uint32_t N976N_BAT_U32;
typedef uint64_t N976N_BAT_U64;
typedef int32_t  N976N_BAT_I32;
#endif

typedef char N976nBatteryTypeWidths[(sizeof(N976N_BAT_U8) == 1 &&
  sizeof(N976N_BAT_U16) == 2 && sizeof(N976N_BAT_U32) == 4 &&
  sizeof(N976N_BAT_U64) == 8 && sizeof(N976N_BAT_I32) == 4) ? 1 : -1];

#define N976N_BATTERY_RESISTOR_UNKNOWN 0U

enum N976N_BATTERY_FIELD {
  N976N_BAT_STATUS,
  N976N_BAT_SOCREP,
  N976N_BAT_VCELL,
  N976N_BAT_CURRENT,
  N976N_BAT_AVG_CURRENT,
  N976N_BAT_REMAINING,
  N976N_BAT_FULL,
  N976N_BAT_INPUT,
  N976N_BAT_CHARGE_DETAIL,
  N976N_BAT_FIELD_COUNT
};

#define N976N_BAT_FIELD_BIT(Field) (1U << (Field))
#define N976N_BAT_ALL_FIELDS ((1U << N976N_BAT_FIELD_COUNT) - 1U)

enum N976N_BATTERY_RESULT {
  N976N_BAT_OK = 0,
  N976N_BAT_BAD_ARGUMENT,
  N976N_BAT_TRANSPORT_FAILED,
  N976N_BAT_BAD_LENGTH
};

enum N976N_BATTERY_CHARGE_STATE {
  N976N_BAT_CHARGE_UNKNOWN = 0,
  N976N_BAT_CHARGING,
  N976N_BAT_FULLY_CHARGED,
  N976N_BAT_NOT_CHARGING,
  N976N_BAT_DISCHARGING
};

typedef struct {
  N976N_BAT_U8 Address;   /* Seven-bit address, not the shifted wire byte. */
  N976N_BAT_U8 Register;
  N976N_BAT_U8 Bytes;     /* Exactly one or two RX bytes; little-endian word. */
} N976N_BATTERY_READ;

typedef struct {
  N976N_BAT_U64 SampleId; /* Nonzero caller identity; not a freshness clock. */
  N976N_BAT_U32 AttemptedMask;
  N976N_BAT_U32 ValidMask;
  N976N_BAT_U32 FailedMask;
  N976N_BAT_U16 Raw[N976N_BAT_FIELD_COUNT];
  N976N_BAT_U8 Result[N976N_BAT_FIELD_COUNT];
} N976N_BATTERY_RAW;

typedef struct {
  N976N_BAT_U64 SampleId;
  N976N_BAT_U32 RawValidMask;
  N976N_BAT_U32 ValueValidMask;
  N976N_BAT_U32 SuspiciousMask; /* STATUS=FFFF is retained, not called absent. */
  N976N_BAT_U32 FgResistor;     /* DT scaling factor, not a guessed ohm value. */
  N976N_BAT_U32 Present;
  N976N_BAT_U32 SocPermille;    /* Samsung SOCREP getter: 0..1000. */
  N976N_BAT_U32 SocClamped;
  N976N_BAT_U32 VoltageMv;
  N976N_BAT_I32 CurrentMa;      /* Positive charge, negative discharge. */
  N976N_BAT_I32 AverageCurrentMa;
  N976N_BAT_U32 RemainingMah;
  N976N_BAT_U32 FullMah;
  N976N_BAT_U32 WiredInput;
  N976N_BAT_U32 WirelessInput;
  N976N_BAT_U32 ChargeState;
} N976N_BATTERY_VALUES;

/* Returns only the immutable observation allowlist; no write descriptor API.
 * Transport must send one register-pointer byte followed by the exact read.
 * A successful RX alone is insufficient: caller supplies TransferOk only after
 * exact completion, ACK and retirement. Bus lifetime is the caller's job. */
int N976nBatteryReadSpec(N976N_BAT_U32 Field, N976N_BATTERY_READ *Read);
int N976nBatteryReadAllowed(N976N_BAT_U32 Address, N976N_BAT_U32 Register,
                          N976N_BAT_U32 Bytes);

/* Begin clears every validity bit and raw value, including on SampleId=0.
 * Each failed Record clears that field's previous success. BytesReceived is
 * the actual RX length, never the requested capacity. A zero-length, short or
 * oversized result cannot become valid. Data must cover BytesReceived bytes. */
int N976nBatteryBegin(N976N_BATTERY_RAW *Raw, N976N_BAT_U64 SampleId);
enum N976N_BATTERY_RESULT N976nBatteryRecord(
  N976N_BATTERY_RAW *Raw, N976N_BAT_U32 Field, int TransferOk,
  const N976N_BAT_U8 *Data, N976N_BAT_U32 BytesReceived);

/* Decode succeeds for a structurally valid partial sample. Inspect each bit
 * in ValueValidMask; zero is not an implicit measurement. No atomic-snapshot,
 * timer freshness, battery health or Windows power-policy claim is made.
 * AdmittedResistor is 2 or 5 only after binding it to the actual platform DT.
 * Zero means unknown: voltage/SOC/status remain independently usable but
 * current and capacity values stay invalid. Samsung d2x board revisions use
 * different factors; model name is insufficient. This is not an ohm value.
 * Values is cleared on invalid input. Raw and Values must not overlap. */
int N976nBatteryDecode(const N976N_BATTERY_RAW *Raw,
                      N976N_BAT_U32 AdmittedResistor,
                      N976N_BATTERY_VALUES *Values);

#endif
