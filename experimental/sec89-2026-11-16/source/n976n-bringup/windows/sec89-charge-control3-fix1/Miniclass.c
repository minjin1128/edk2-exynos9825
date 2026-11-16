/* SPDX-License-Identifier: MIT
 * Battc callback contract follows pinned Microsoft SimBatt and 9820 S10eBattery;
 * live freshness, partial-value semantics and tags are implemented locally.
 */
#include "Miniclass.h"

static int Bound(const N976N_BATTERY_MINICLASS_CONTEXT *Context)
{
  return Context && Context->Cache && Context->Lock && Context->Unlock &&
         Context->Now100ns;
}

static NTSTATUS Fresh(PVOID Opaque, ULONG Tag, int RequireTag,
                      N976N_BATTERY_CACHE_VIEW *View)
{
  N976N_BATTERY_MINICLASS_CONTEXT *Context = Opaque;
  int Available;
  if (!Bound(Context)) return STATUS_INVALID_PARAMETER;
  Context->Lock(Context->Owner);
  Available = N976nBatteryCacheRead(Context->Cache,
                                  Context->Now100ns(Context->Owner), View);
  if (Available && RequireTag && (!Tag || Tag != View->Tag)) Available = 0;
  Context->Unlock(Context->Owner);
  return Available ? STATUS_SUCCESS : STATUS_NO_SUCH_DEVICE;
}

int N976nBatteryMiniBind(PBATTERY_MINIPORT_INFO Info,
                       N976N_BATTERY_MINICLASS_CONTEXT *Context)
{
  if (!Info || !Bound(Context)) return 0;
  Info->Context = Context;
  Info->QueryTag = N976nBatteryQueryTag;
  Info->QueryInformation = N976nBatteryQueryInformation;
  Info->SetInformation = N976nBatterySetInformation;
  Info->QueryStatus = N976nBatteryQueryStatus;
  Info->SetStatusNotify = N976nBatterySetStatusNotify;
  Info->DisableStatusNotify = N976nBatteryDisableStatusNotify;
  return 1;
}

_Use_decl_annotations_
NTSTATUS N976nBatteryQueryTag(PVOID Context, PULONG BatteryTag)
{
  N976N_BATTERY_CACHE_VIEW View;
  NTSTATUS Status;
  if (!BatteryTag) return STATUS_INVALID_PARAMETER;
  *BatteryTag = 0;
  Status = Fresh(Context, 0, 0, &View);
  if (NT_SUCCESS(Status)) *BatteryTag = View.Tag;
  return Status;
}

_Use_decl_annotations_
NTSTATUS N976nBatteryQueryInformation(PVOID Context, ULONG BatteryTag,
  BATTERY_QUERY_INFORMATION_LEVEL Level, LONG AtRate, PVOID Buffer,
  ULONG BufferLength, PULONG ReturnedLength)
{
  static const WCHAR Name[] = {
    'N','9','7','6','N',' ','s','y','s','t','e','m',' ',
    'b','a','t','t','e','r','y',0
  };
  N976N_BATTERY_CACHE_VIEW View;
  BATTERY_INFORMATION Information;
  ULONG Value;
  const void *Source;
  ULONG Length;
  NTSTATUS Status;
  UNREFERENCED_PARAMETER(AtRate);
  if (!ReturnedLength) return STATUS_INVALID_PARAMETER;
  *ReturnedLength = 0;
  Status = Fresh(Context, BatteryTag, 1, &View);
  if (!NT_SUCCESS(Status)) return Status;

  switch (Level) {
  case BatteryInformation:
    RtlZeroMemory(&Information, sizeof(Information));
    Information.Capabilities = BATTERY_SYSTEM_BATTERY | BATTERY_CAPACITY_RELATIVE;
    Information.Technology = 1;
    Information.Chemistry[0] = 'L'; Information.Chemistry[1] = 'I';
    Information.Chemistry[2] = 'O'; Information.Chemistry[3] = 'N';
    /* 1000 is the SOC normalization scale, never the gauge's learned full
     * capacity or a health estimate. The actual design capacity is unknown. */
    Information.DesignedCapacity = BATTERY_UNKNOWN_CAPACITY;
    Information.FullChargedCapacity = 1000;
    /* No manufacturer alert threshold, bias or cycle counter was read.
     * Zero alert fields do not assert a sampled critical state. */
    Source = &Information;
    Length = (ULONG)sizeof(Information);
    break;
  case BatteryEstimatedTime:
    Value = BATTERY_UNKNOWN_TIME;
    Source = &Value;
    Length = (ULONG)sizeof(Value);
    break;
  case BatteryDeviceName:
    Source = Name;
    Length = (ULONG)sizeof(Name);
    break;
  case BatteryGranularityInformation:
  case BatteryTemperature:
  case BatteryManufactureDate:
  case BatteryManufactureName:
  case BatteryUniqueID:
  case BatterySerialNumber:
    return STATUS_INVALID_DEVICE_REQUEST;
  default:
    return STATUS_INVALID_PARAMETER;
  }
  *ReturnedLength = Length;
  if (BufferLength < Length) return STATUS_BUFFER_TOO_SMALL;
  if (!Buffer) return STATUS_INVALID_PARAMETER;
  RtlCopyMemory(Buffer, Source, Length);
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS N976nBatteryQueryStatus(PVOID Context, ULONG BatteryTag,
                                PBATTERY_STATUS BatteryStatus)
{
  N976N_BATTERY_CACHE_VIEW View;
  N976N_BAT_U32 Valid;
  NTSTATUS Status;
  if (!BatteryStatus) return STATUS_INVALID_PARAMETER;
  RtlZeroMemory(BatteryStatus, sizeof(*BatteryStatus));
  BatteryStatus->Capacity = BATTERY_UNKNOWN_CAPACITY;
  BatteryStatus->Voltage = BATTERY_UNKNOWN_VOLTAGE;
  BatteryStatus->Rate = BATTERY_UNKNOWN_RATE;
  Status = Fresh(Context, BatteryTag, 1, &View);
  if (!NT_SUCCESS(Status)) return Status;
  Valid = View.Values.ValueValidMask;
  if (Valid & N976N_BAT_FIELD_BIT(N976N_BAT_SOCREP))
    BatteryStatus->Capacity = View.Values.SocPermille;
  if (Valid & N976N_BAT_FIELD_BIT(N976N_BAT_VCELL))
    BatteryStatus->Voltage = View.Values.VoltageMv;

  /* A separately bracketed, fresh CCIC+charger observation establishes online,
   * independently of managed charging. Charger detail and
   * current must agree before claiming a charge/discharge direction. These
   * sequential fields can disagree; that means no directional claim.
   * mA is not relative-capacity units/hour: Rate remains UNKNOWN. */
  if(View.OnlineKnown&&View.Online)BatteryStatus->PowerState|=BATTERY_POWER_ON_LINE;
  if ((Valid & (N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT) |
                N976N_BAT_FIELD_BIT(N976N_BAT_CHARGE_DETAIL))) ==
               (N976N_BAT_FIELD_BIT(N976N_BAT_CURRENT) |
                N976N_BAT_FIELD_BIT(N976N_BAT_CHARGE_DETAIL))) {
    if (View.OnlineKnown&&View.Online&&View.ChargingObserved&&View.Values.CurrentMa > 0 &&
        View.Values.ChargeState == N976N_BAT_CHARGING)
      BatteryStatus->PowerState |= BATTERY_CHARGING;
    else if (View.Values.CurrentMa < 0 &&
             (View.Values.ChargeState == N976N_BAT_DISCHARGING ||
              View.Values.ChargeState == N976N_BAT_NOT_CHARGING ||
              View.Values.ChargeState == N976N_BAT_FULLY_CHARGED))
      BatteryStatus->PowerState |= BATTERY_DISCHARGING;
  }
  return STATUS_SUCCESS;
}

_Use_decl_annotations_
NTSTATUS N976nBatterySetInformation(PVOID Context, ULONG BatteryTag,
  BATTERY_SET_INFORMATION_LEVEL Level, PVOID Buffer)
{
  N976N_BATTERY_CACHE_VIEW View;
  NTSTATUS Status;
  UNREFERENCED_PARAMETER(Level);
  UNREFERENCED_PARAMETER(Buffer);
  Status = Fresh(Context, BatteryTag, 1, &View);
  return NT_SUCCESS(Status) ? STATUS_NOT_SUPPORTED : Status;
}

_Use_decl_annotations_
NTSTATUS N976nBatterySetStatusNotify(PVOID Context, ULONG BatteryTag,
                                   PBATTERY_NOTIFY BatteryNotify)
{
  N976N_BATTERY_CACHE_VIEW View;
  NTSTATUS Status;
  if (!BatteryNotify) return STATUS_INVALID_PARAMETER;
  Status = Fresh(Context, BatteryTag, 1, &View);
  /* No threshold/IRQ program exists. Battc may poll; Device also explicitly
   * calls BatteryClassStatusNotify after publishing, outside the state lock. */
  return NT_SUCCESS(Status) ? STATUS_NOT_SUPPORTED : Status;
}

_Use_decl_annotations_
NTSTATUS N976nBatteryDisableStatusNotify(PVOID Context)
{
  return Bound(Context) ? STATUS_NOT_SUPPORTED : STATUS_INVALID_PARAMETER;
}
