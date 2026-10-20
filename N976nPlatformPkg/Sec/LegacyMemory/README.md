The N976N runtime DT parser and conservative external-memory policy are retained
from SEC41 FIX5 (`N976nDxeSecPkg/Sec/MemoryPlan.c`). The accompanying
`Include/LegacyMemory` headers retain its ABI and constants. The only changes
to the copied source and headers are the three include paths required by the
new package directory. Parsing, exclusions, dynamic reservation checks and the
64 MiB ownership contract are unchanged.

`PhoneSec.c` constructs a zeroed legacy input solely for this memory gate. It
does not execute the old diagnostic SEC, translation tables, `PrepareDxe`,
Windows service sequencing or old DXE report logic.
