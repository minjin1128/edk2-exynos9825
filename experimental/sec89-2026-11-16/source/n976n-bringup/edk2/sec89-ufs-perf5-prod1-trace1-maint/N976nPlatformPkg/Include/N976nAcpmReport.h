/* SPDX-License-Identifier: MIT */
#ifndef N976N_ACPM_REPORT_H_
#define N976N_ACPM_REPORT_H_
#include <N976nAcpm.h>
BOOLEAN N976nAcpmReportValid (CONST N976N_ACPM_SNAPSHOT *R, UINT64 Profile);
CONST CHAR16 *N976nAcpmLayoutFieldName (CONST N976N_ACPM_SNAPSHOT *R);
#endif
