#ifndef SEC78_FAKE_NTDDSCSI_H
#define SEC78_FAKE_NTDDSCSI_H
#include "ntddk.h"
typedef struct {ULONG HeaderLength;UCHAR Signature[8];ULONG Timeout,ControlCode,ReturnCode,Length;} SRB_IO_CONTROL,*PSRB_IO_CONTROL;
#endif
