/* SPDX-License-Identifier: MIT; immutable build-selected SEC78 FIX1 mode. */
#ifndef N976N_SEC78_DIAGNOSTIC_MODE_H_
#define N976N_SEC78_DIAGNOSTIC_MODE_H_
#ifndef N976N_SEC78_DIAG_MODE
#define N976N_SEC78_DIAG_MODE 1
#endif
#if N976N_SEC78_DIAG_MODE < 1 || N976N_SEC78_DIAG_MODE > 3
#error Unsupported SEC78 diagnostic mode
#endif
/* 1=A full; 2=B legacy ACPI with new DMA; 3=C legacy ACPI/memory. */
extern CONST UINT32 N976nSec78DiagnosticMode;
#endif
