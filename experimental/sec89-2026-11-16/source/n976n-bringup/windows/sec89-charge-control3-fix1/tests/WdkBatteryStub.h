/* Test-only WDK ABI subset. Production compilation always uses the real WDK.
 * This is not a replacement for the required Windows ARM64 build. */
#ifndef N976N_WDK_BATTERY_STUB_H
#define N976N_WDK_BATTERY_STUB_H
#include <stdint.h>
#include <string.h>
typedef void *PVOID;
typedef uint32_t ULONG, *PULONG;
typedef int32_t LONG, NTSTATUS;
typedef uint16_t WCHAR;
typedef uint8_t UCHAR;
#define _Use_decl_annotations_
#define UNREFERENCED_PARAMETER(x) ((void)(x))
#define RtlZeroMemory(p,n) memset((p),0,(n))
#define RtlCopyMemory(d,s,n) memcpy((d),(s),(n))
#define NT_SUCCESS(s) ((NTSTATUS)(s)>=0)
#define STATUS_SUCCESS ((NTSTATUS)0)
#define STATUS_INVALID_PARAMETER ((NTSTATUS)0xC000000D)
#define STATUS_NO_SUCH_DEVICE ((NTSTATUS)0xC000000E)
#define STATUS_INVALID_DEVICE_REQUEST ((NTSTATUS)0xC0000010)
#define STATUS_BUFFER_TOO_SMALL ((NTSTATUS)0xC0000023)
#define STATUS_NOT_SUPPORTED ((NTSTATUS)0xC00000BB)
#define BATTERY_SYSTEM_BATTERY 0x80000000U
#define BATTERY_CAPACITY_RELATIVE 0x40000000U
#define BATTERY_POWER_ON_LINE 1U
#define BATTERY_DISCHARGING 2U
#define BATTERY_CHARGING 4U
#define BATTERY_CRITICAL 8U
#define BATTERY_UNKNOWN_CAPACITY 0xFFFFFFFFU
#define BATTERY_UNKNOWN_VOLTAGE 0xFFFFFFFFU
#define BATTERY_UNKNOWN_RATE ((LONG)0x80000000)
#define BATTERY_UNKNOWN_TIME 0xFFFFFFFFU
typedef enum {
  BatteryInformation, BatteryGranularityInformation, BatteryTemperature,
  BatteryEstimatedTime, BatteryDeviceName, BatteryManufactureDate,
  BatteryManufactureName, BatteryUniqueID, BatterySerialNumber
} BATTERY_QUERY_INFORMATION_LEVEL;
typedef enum {
  BatteryCriticalBias, BatteryCharge, BatteryDischarge,
  BatteryChargingSource, BatteryChargerStatus
} BATTERY_SET_INFORMATION_LEVEL;
typedef struct {
  ULONG Capabilities;
  UCHAR Technology, Reserved[3], Chemistry[4];
  ULONG DesignedCapacity, FullChargedCapacity, DefaultAlert1, DefaultAlert2,
        CriticalBias, CycleCount;
} BATTERY_INFORMATION;
typedef struct {
  ULONG PowerState, Capacity, Voltage;
  LONG Rate;
} BATTERY_STATUS, *PBATTERY_STATUS;
typedef struct {ULONG PowerState, LowCapacity, HighCapacity;}
  BATTERY_NOTIFY, *PBATTERY_NOTIFY;
typedef NTSTATUS BCLASS_QUERY_TAG_CALLBACK(PVOID, PULONG);
typedef NTSTATUS BCLASS_QUERY_INFORMATION_CALLBACK(PVOID, ULONG,
  BATTERY_QUERY_INFORMATION_LEVEL, LONG, PVOID, ULONG, PULONG);
typedef NTSTATUS BCLASS_QUERY_STATUS_CALLBACK(PVOID, ULONG, PBATTERY_STATUS);
typedef NTSTATUS BCLASS_SET_INFORMATION_CALLBACK(PVOID, ULONG,
  BATTERY_SET_INFORMATION_LEVEL, PVOID);
typedef NTSTATUS BCLASS_SET_STATUS_NOTIFY_CALLBACK(PVOID, ULONG, PBATTERY_NOTIFY);
typedef NTSTATUS BCLASS_DISABLE_STATUS_NOTIFY_CALLBACK(PVOID);
typedef struct {
  ULONG MajorVersion, MinorVersion;
  PVOID Context;
  BCLASS_QUERY_TAG_CALLBACK *QueryTag;
  BCLASS_QUERY_INFORMATION_CALLBACK *QueryInformation;
  BCLASS_SET_INFORMATION_CALLBACK *SetInformation;
  BCLASS_QUERY_STATUS_CALLBACK *QueryStatus;
  BCLASS_SET_STATUS_NOTIFY_CALLBACK *SetStatusNotify;
  BCLASS_DISABLE_STATUS_NOTIFY_CALLBACK *DisableStatusNotify;
  PVOID Pdo, DeviceName;
} BATTERY_MINIPORT_INFO, *PBATTERY_MINIPORT_INFO;
#endif

#ifndef BATTERY_POWER_ON_LINE
#define BATTERY_POWER_ON_LINE 0x1
#endif
