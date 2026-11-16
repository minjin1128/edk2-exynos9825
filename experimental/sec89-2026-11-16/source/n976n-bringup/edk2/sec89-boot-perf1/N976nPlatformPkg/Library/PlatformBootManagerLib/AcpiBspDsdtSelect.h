/* SPDX-License-Identifier: MIT; B/C use the same preserved legacy AML. */
#include <N976nSec78DiagnosticMode.h>
#if N976N_SEC78_DIAG_MODE == 1
#include "AcpiBspDsdt.h"
#else
#include "AcpiBspDsdtSec77.h"
#endif
