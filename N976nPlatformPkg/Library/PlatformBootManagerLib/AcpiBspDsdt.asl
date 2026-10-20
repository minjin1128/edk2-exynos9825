/* SPDX-License-Identifier: MIT
 * One admitted BSP, ACPI UID0 matching MADT. No secondary-CPU readiness claim.
 * Compile with upstream ACPICA iasl; AcpiBspDsdt.h records the resulting AML.
 */
DefinitionBlock ("AcpiBspDsdt.aml", "DSDT", 2, "N976N ", "SEC67   ", 1)
{
    Scope (\_SB)
    {
        Device (CPU0)
        {
            Name (_HID, "ACPI0007")
            Name (_UID, Zero)
            Name (_STA, 0x0F)
        }
    }
}
