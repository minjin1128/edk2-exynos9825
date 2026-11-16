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
        Device (CPU1)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, 1)
            Name (_STA, 0xDC)
        }
        Device (CPU2)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, 2)
            Name (_STA, 0xDD)
        }
        Device (CPU3)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, 3)
            Name (_STA, 0xDE)
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
        // LIVE1 HSI45 owner; polling only, GIC114 remains masked. TOP is
        // read-only and explicitly shared by both paired Windows drivers.
        Device (BAT0)
        {
            Name (_HID, "NNBT0089")
            Name (_UID, Zero)
            Name (_STA, 0xDF)
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x15D60000, 0x1000)
                Memory32Fixed (ReadWrite, 0x15C22030, 0x4)
                Memory32Fixed (ReadWrite, 0x15C0304C, 0x4)
                Memory32Fixed (ReadWrite, 0x15C30180, 0x10)
                Memory32Fixed (ReadWrite, 0x15C301A0, 0x10)
                Memory32Fixed (ReadOnly, 0x15C00100, 0x4)
                Memory32Fixed (ReadOnly, 0x15C01020, 0x4)
                Memory32Fixed (ReadOnly, 0x15C01824, 0x4)
                Memory32Fixed (ReadOnly, 0x15800100, 0x44)
                Memory32Fixed (ReadOnly, 0x15801004, 0x4)
                Memory32Fixed (ReadOnly, 0x15801804, 0x4)
                Memory32Fixed (ReadOnly, 0x1580200C, 0x4)
                Memory32Fixed (ReadOnly, 0x15C02010, 0x4)
                Memory32Fixed (ReadOnly, 0x15C0206C, 0x4)
                Memory32Fixed (ReadOnly, 0x15C0205C, 0x4)
                Memory32Fixed (ReadOnly, 0x15C02088, 0x4)
                Memory32Fixed (ReadOnly, 0x15C0208C, 0x4)
                Memory32Fixed (ReadOnly, 0x1A240000, 0x3000)
                Memory32Fixed (ReadWrite, 0x15C40000, 0x100)
                Memory32Fixed (ReadOnly, 0x15C01000, 0x4)
                Memory32Fixed (ReadOnly, 0x15C01800, 0x4)
                Memory32Fixed (ReadOnly, 0x15C01804, 0x4)
                Memory32Fixed (ReadOnly, 0x15C02004, 0x4)
                Memory32Fixed (ReadOnly, 0x15C02008, 0x4)
                Memory32Fixed (ReadOnly, 0x15C03000, 0x4)
                Memory32Fixed (ReadOnly, 0x15C03008, 0x4)
                Memory32Fixed (ReadOnly, 0x15C0300C, 0x4)
                Memory32Fixed (ReadWrite, 0x8BADE000, 0x1000)
                Interrupt (ResourceConsumer, Level, ActiveHigh, Exclusive) {116}
            })
        }
    }
}
