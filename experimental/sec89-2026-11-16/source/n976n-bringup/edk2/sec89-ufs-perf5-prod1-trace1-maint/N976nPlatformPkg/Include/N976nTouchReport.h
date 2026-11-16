/* SPDX-License-Identifier: MIT */
#ifndef N976N_TOUCH_REPORT_H_
#define N976N_TOUCH_REPORT_H_
#include <N976nTouchProbe.h>
extern N976N_TOUCH_SNAPSHOT mN976nTouchSnapshot;
BOOLEAN N976nTouchReportValid (CONST N976N_TOUCH_SNAPSHOT *R, UINT64 Profile);
#endif
