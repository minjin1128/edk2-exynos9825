/* SPDX-License-Identifier: MIT
 * Microsoft DBG2 standard layout, using upstream EDK2 declarations.
 * https://learn.microsoft.com/en-us/windows-hardware/drivers/bringup/acpi-debug-port-table
 * This table describes the SAM5250-compatible UART only. It neither configures
 * clocks/mux/pins nor claims that a Windows debugger has connected.
 */
#include <N976nUartKd.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>

volatile N976N_UART_DBG2_REPORT mN976nUartDbg2Report;

EFI_STATUS N976nBuildUartDbg2 (N976N_UART_DBG2 *Dbg2)
{
  if (Dbg2 == NULL || (UINTN)Dbg2 > MAX_UINTN - sizeof (*Dbg2)) {
    return EFI_INVALID_PARAMETER;
  }
  ZeroMem (Dbg2, sizeof (*Dbg2));
  Dbg2->Table.Header.Signature = EFI_ACPI_6_5_DEBUG_PORT_2_TABLE_SIGNATURE;
  Dbg2->Table.Header.Length = sizeof (*Dbg2);
  Dbg2->Table.Header.Revision = EFI_ACPI_DEBUG_PORT_2_TABLE_REVISION;
  CopyMem (Dbg2->Table.Header.OemId, "N976N ", 6);
  CopyMem (&Dbg2->Table.Header.OemTableId, "N976NUAR", 8);
  Dbg2->Table.Header.OemRevision = 1;
  Dbg2->Table.Header.CreatorId = SIGNATURE_32 ('N', '9', '7', '6');
  Dbg2->Table.Header.CreatorRevision = 1;
  Dbg2->Table.OffsetDbgDeviceInfo = OFFSET_OF (N976N_UART_DBG2, Device);
  Dbg2->Table.NumberDbgDeviceInfo = 1;
  Dbg2->Device.Revision = EFI_ACPI_DBG2_DEBUG_DEVICE_INFORMATION_STRUCT_REVISION;
  Dbg2->Device.Length = sizeof (*Dbg2) - OFFSET_OF (N976N_UART_DBG2, Device);
  Dbg2->Device.NumberofGenericAddressRegisters = 1;
  Dbg2->Device.NameSpaceStringLength = sizeof (Dbg2->Namespace);
  Dbg2->Device.NameSpaceStringOffset = OFFSET_OF (N976N_UART_DBG2, Namespace) -
    OFFSET_OF (N976N_UART_DBG2, Device);
  Dbg2->Device.PortType = EFI_ACPI_DBG2_PORT_TYPE_SERIAL;
  Dbg2->Device.PortSubtype = N976N_UART_KD_SAM5250;
  Dbg2->Device.BaseAddressRegisterOffset = OFFSET_OF (N976N_UART_DBG2, Register) -
    OFFSET_OF (N976N_UART_DBG2, Device);
  Dbg2->Device.AddressSizeOffset = OFFSET_OF (N976N_UART_DBG2, AddressSize) -
    OFFSET_OF (N976N_UART_DBG2, Device);
  Dbg2->Register.AddressSpaceId = EFI_ACPI_6_5_SYSTEM_MEMORY;
  Dbg2->Register.RegisterBitWidth = 32;
  Dbg2->Register.AccessSize = EFI_ACPI_6_5_DWORD;
  Dbg2->Register.Address = N976N_UART_KD_BASE;
  Dbg2->AddressSize = N976N_UART_KD_BYTES;
  /* No namespace device is exposed for a second driver to own the KD UART. */
  Dbg2->Namespace[0] = '.';
  Dbg2->Table.Header.Checksum = CalculateCheckSum8 ((UINT8 *)Dbg2, sizeof (*Dbg2));
  return EFI_SUCCESS;
}
