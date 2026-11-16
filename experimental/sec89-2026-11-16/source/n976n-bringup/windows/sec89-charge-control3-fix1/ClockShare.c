/* SPDX-License-Identifier: MIT */
#include "ClockShare.h"

static int AllowedFlags(USHORT Flags)
{
  return Flags == CM_RESOURCE_MEMORY_READ_WRITE ||
         Flags == CM_RESOURCE_MEMORY_READ_ONLY;
}

static int ExactRequirement(PIO_RESOURCE_DESCRIPTOR Descriptor)
{
  ULONGLONG Minimum, Maximum, Length;
  if (!Descriptor || Descriptor->Type != CmResourceTypeMemory ||
      !AllowedFlags(Descriptor->Flags)) return 0;
  /* Use the WDK decoder instead of assuming the union's address encoding. */
  Length = RtlIoDecodeMemIoResource(Descriptor, NULL, &Minimum, &Maximum);
  return Minimum == N976N_CLOCK_SHARE_BASE &&
         Maximum == N976N_CLOCK_SHARE_END && Length == N976N_CLOCK_SHARE_BYTES;
}

_Use_decl_annotations_
NTSTATUS N976nClockShareFilter(WDFDEVICE Device, WDFIORESREQLIST Requirements)
{
  ULONG Alternatives, A, I, Pass;
  UNREFERENCED_PARAMETER(Device);
  if (!Requirements) return STATUS_INVALID_PARAMETER;
  Alternatives = WdfIoResourceRequirementsListGetCount(Requirements);
  if (!Alternatives) return STATUS_DEVICE_CONFIGURATION_ERROR;
  /* Validate every logical configuration first. No partial mutation if a later
   * alternative lacks the exact fixed TOP or contains an invalid descriptor.
   * Preserve Option, alignment, flags, spare fields and the entire union.
   */
  for (Pass = 0; Pass < 2; ++Pass) {
    for (A = 0; A < Alternatives; ++A) {
      WDFIORESLIST List = WdfIoResourceRequirementsListGetIoResList(Requirements, A);
      ULONG Count, Matches = 0;
      if (!List) return STATUS_DEVICE_CONFIGURATION_ERROR;
      Count = WdfIoResourceListGetCount(List);
      for (I = 0; I < Count; ++I) {
        PIO_RESOURCE_DESCRIPTOR Descriptor = WdfIoResourceListGetDescriptor(List, I);
        IO_RESOURCE_DESCRIPTOR Replacement;
        if (!Descriptor) return STATUS_DEVICE_CONFIGURATION_ERROR;
        if (!ExactRequirement(Descriptor)) continue;
        if (Descriptor->ShareDisposition != CmResourceShareDeviceExclusive &&
            Descriptor->ShareDisposition != CmResourceShareShared)
          return STATUS_DEVICE_CONFIGURATION_ERROR;
        ++Matches;
        if (!Pass || Descriptor->ShareDisposition == CmResourceShareShared) continue;
        Replacement = *Descriptor;
        Replacement.ShareDisposition = CmResourceShareShared;
        WdfIoResourceListUpdateDescriptor(List, &Replacement, I);
      }
      if (!Matches) return STATUS_DEVICE_CONFIGURATION_ERROR;
    }
  }
  return STATUS_SUCCESS;
}

VOID N976nClockShareRegister(PWDFDEVICE_INIT DeviceInit)
{
  WDF_FDO_EVENT_CALLBACKS Callbacks;
  WDF_FDO_EVENT_CALLBACKS_INIT(&Callbacks);
  Callbacks.EvtDeviceFilterRemoveResourceRequirements = N976nClockShareFilter;
  WdfFdoInitSetEventCallbacks(DeviceInit, &Callbacks);
}

int N976nClockSharePreparePair(PCM_PARTIAL_RESOURCE_DESCRIPTOR Raw,
                             PCM_PARTIAL_RESOURCE_DESCRIPTOR Translated)
{
  if (!Raw || !Translated || Raw->Type != CmResourceTypeMemory ||
      Translated->Type != CmResourceTypeMemory ||
      Raw->ShareDisposition != CmResourceShareShared ||
      Translated->ShareDisposition != CmResourceShareShared ||
      Raw->Flags != Translated->Flags || !AllowedFlags(Raw->Flags)) return 0;
  return (ULONGLONG)Raw->u.Memory.Start.QuadPart == N976N_CLOCK_SHARE_BASE &&
         (ULONGLONG)Translated->u.Memory.Start.QuadPart == N976N_CLOCK_SHARE_BASE &&
         Raw->u.Memory.Length == N976N_CLOCK_SHARE_BYTES &&
         Translated->u.Memory.Length == N976N_CLOCK_SHARE_BYTES;
}
