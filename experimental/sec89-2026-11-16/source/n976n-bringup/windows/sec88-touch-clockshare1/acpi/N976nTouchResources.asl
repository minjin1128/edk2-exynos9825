/* SPDX-License-Identifier: MIT
 * SEC76 OFFLINE RESOURCE DRAFT. Not installed or included in firmware.
 * All three devices are unconditionally absent (_STA=0). Private development
 * IDs below are local contract names, not assigned production vendor IDs.
 * Samsung N976N runtime DT and 9820 code provenance: references/sec76/.
 * Resource payload/table identity deliberately remain the SEC74 draft.
 * SEC76's separate polled ID core uses the physically exercised 100kHz timing;
 * this inactive 400kHz future SPB profile is NOT used by that core and must be
 * reconciled before any later activation. ID polling needs no touch IRQ delivery.
 */
DefinitionBlock ("", "SSDT", 2, "N976N ", "S74TOUCH", 0x00000001)
{
    Scope (\_SB)
    {
        Device (I2C0)
        {
            Name (_HID, "NNTC0001")
            Name (_UID, 10)
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x104B0000, 0x00001000)
                Memory32Fixed (ReadWrite, 0x10400000, 0x00008000)
                Memory32Fixed (ReadWrite, 0x10421000, 0x00001000)
                Memory32Fixed (ReadWrite, 0x10430000, 0x00001000)
                // SPI388 +32. Samsung DT trigger=0 (unspecified).
                // Edge/High is 9820 draft policy, NOT N976N hardware proof.
                Interrupt (ResourceConsumer, Edge, ActiveHigh, Exclusive) { 420 }
            })
            Method (_STA, 0, NotSerialized) { Return (Zero) }
        }

        Device (GPA0)
        {
            Name (_HID, "NNTC0002")
            Name (_UID, Zero)
            Name (_CRS, ResourceTemplate ()
            {
                Memory32Fixed (ReadWrite, 0x15850000, 0x00001000)
                // Proposed full ALIVE provider ABI: gpa0..3 each8 + gpa4 two.
                // Array index is provider-local pin; EINT8/gpa1-0 => GSIV45.
                // Parent IRQ mode follows 9820 provider draft. It is not the
                // ActiveLow peripheral trigger; GpioClx/provider must own EINT.
                Interrupt (ResourceConsumer, Level, ActiveHigh, Shared)
                {
                    37, 38, 39, 40, 41, 42, 43, 44,
                    45, 46, 47, 48, 49, 50, 51, 52,
                    53, 54, 55, 56, 57, 58, 59, 60,
                    61, 62, 63, 64, 65, 66, 67, 68,
                    69, 70
                }
            })
            Method (_STA, 0, NotSerialized) { Return (Zero) }
        }

        Device (TSP0)
        {
            Name (_HID, "NNTC0003")
            Name (_UID, Zero)
            Name (_DEP, Package (2) { \_SB.I2C0, \_SB.GPA0 })
            Name (_CRS, ResourceTemplate ()
            {
                I2cSerialBusV2 (0x0048, ControllerInitiated, 400000,
                    AddressingMode7Bit, "\\_SB.I2C0", 0, ResourceConsumer,
                    , Exclusive)
                // Samsung sec,irq_type=0x2008: ONESHOT + LEVEL_LOW.
                // No raw GSIV or ALIVE mapping in the HID function device.
                GpioInt (Level, ActiveLow, Exclusive, PullDefault, 0,
                    "\\_SB.GPA0", 0, ResourceConsumer, , ) { 8 }
            })
            Method (_STA, 0, NotSerialized) { Return (Zero) }
        }
    }
}
