/* SPDX-License-Identifier: GPL-2.0-only
 * SEC73 modification, 2026-10-22. Wire fields derived from Samsung N976N
 * drivers/input/touchscreen/sec_ts/y771_d/sec_ts.h:655-682 and sec_ts.c.
 * Field provenance and preserved Samsung copyrights are recorded in README.md.
 */
#include "Y771Event.h"

N976N_Y771_RESULT N976nY771DecodeEvent(const N976N_U8 *Bytes, N976N_SIZE Length,
                                    N976N_Y771_EVENT *Event)
{
    N976N_Y771_EVENT Value = {0};
    N976N_U8 Class;
    if (Event == NULL) return N976nY771Invalid;
    *Event = Value;
    if (Bytes == NULL || Length != N976N_Y771_EVENT_BYTES) return N976nY771Invalid;
    if (Bytes[0] == 0) return N976nY771Empty;
    Class = Bytes[0] & 3U;
    Value.Remaining = Bytes[7] & N976N_Y771_REMAINING_MASK;
    if (Class == 3) return N976nY771Invalid;
    if (Class == 1) {
        Value.StatusSubtype = (Bytes[0] >> 2) & 15U;
        Value.StatusId = Bytes[1];
        Value.StatusData = Bytes[2];
        *Event = Value;
        if (Value.StatusSubtype == 1) return N976nY771ErrorStatus;
        if ((Value.StatusSubtype == 2 || Value.StatusSubtype == 7) && Value.StatusId == 0)
            return N976nY771UnexpectedBoot;
        return N976nY771Status;
    }
    if (Class == 2) { *Event = Value; return N976nY771Gesture; }
    Value.WireId = (Bytes[0] >> 2) & 15U;
    Value.Action = Bytes[0] >> 6;
    Value.Type = (N976N_U8)(((Bytes[6] >> 6) << 2) | (Bytes[7] >> 6));
    /* Only ten finger slots are admitted, before subtraction or array access. */
    if (Value.WireId == 0 || Value.WireId > N976N_Y771_CONTACTS || Value.Action == 0)
        return N976nY771Invalid;
    Value.ContactIndex = Value.WireId - 1U;
    Value.X = (N976N_U16)(((N976N_U16)Bytes[1] << 4) | (Bytes[3] >> 4));
    Value.Y = (N976N_U16)(((N976N_U16)Bytes[2] << 4) | (Bytes[3] & 15U));
    Value.Pressure = Bytes[6] & 63U;
    Value.Major = Bytes[4];
    Value.Minor = Bytes[5];
    *Event = Value;
    if (Value.Type != 0 && Value.Type != 3 && Value.Type != 5 && Value.Type != 6)
        return N976nY771OtherTool;
    return N976nY771Coordinate;
}
