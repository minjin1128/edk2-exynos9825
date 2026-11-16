/* SPDX-License-Identifier: MIT
 * SEC76 private polling touch demo. Only this ACPI device owns these resources.
 * No GPIO or HSI interrupt is enumerated. SYSREG/CMU/TOP/PERIC are read-only
 * consumers; firmware owns configuration. Resource5 is normal WB NVS.
 * Resource6 appends read-only ALIVE for GPIO input sampling; no IRQ resource.
 * DSDT producer patches unique NVS sentinel and _STA only after lease validation.
 */
DefinitionBlock ("AcpiBspDsdt.aml", "DSDT", 2, "N976N ", "SEC76   ", 1)
{
    Scope (\_SB)
    {
        Device (CPU0)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, Zero)
            Name (_STA, 0x0F)
        }
        Device (TSP0)
        {
            Name (_HID, "NNTC0076")
            Name (_UID, Zero)
            Name (_STA, 0xDA)
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x104B0000, 0x1000)
                Memory32Fixed (ReadOnly, 0x10400000, 0x8000)
                Memory32Fixed (ReadOnly, 0x10421000, 0x1000)
                Memory32Fixed (ReadOnly, 0x10430000, 0x1000)
                Memory32Fixed (ReadOnly, 0x1A240000, 0x3000)
                Memory32Fixed (ReadWrite, 0x8BADF000, 0x1000)
                Memory32Fixed (ReadOnly, 0x15850000, 0x1000)
            })
        }
        Device (UFS0)
        {
            Name (_HID, "NNUF0078")
            Name (_UID, Zero)
            Name (_STA, 0xDB)
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x13D60000, 0x2000)
                Memory32Fixed (ReadOnly, 0x13C10000, 0x1000)
                Memory32Fixed (ReadWrite, 0x8BADB000, 0x2000)
                Memory32Fixed (ReadWrite, 0x8BADC000, 0x16000)
                // N976N Samsung DT SPI249 => GIC INTID281. Polling remains
                // unchanged; firmware requires IE0 and a clear, level line.
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) { 281 }
            })
        }
    }
}
