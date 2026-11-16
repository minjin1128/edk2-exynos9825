/* SPDX-License-Identifier: MIT */
#ifndef N976N_BATTERY_BUS_H_
#define N976N_BATTERY_BUS_H_
#include <Uefi.h>
#include <N976nBatteryTypes.h>
#include <N976nBattery.h>
#include <N976nChargeObservation.h>

/* One serialized boot-time snapshot, after exact DT/MMIO/clock-domain
 * admission and exclusive HSI45 ownership. The adapter calls this before the
 * first UART mux attempt, proves its phase is still zero and no other HSI45
 * owner remains, then runs UART mux only after this probe restores. No boot
 * service timer, runtime callback or OS handoff is installed by this core.
 * A second call returns EFI_ALREADY_STARTED without touching MMIO or Raw.
 * Values are sequential observations, not an atomic or live Windows sample.
 */
typedef struct {
  UINT64 Phase, Status, Reason, FailurePhase;
  UINT64 InputHz, Input, ClockAddress, ClockValue;
  UINT64 SampleId, SampledMask, Field, Address, Register, Requested, Received;
  UINT64 Transfers, TxBytes, RxBytes, Interrupt, Transfer, Fifo, Auto;
  UINT64 WaitUs, WaitExit, Retired, Restored, Quarantine;
  UINT64 NoMutation; /* 1 until the first MMIO write; not a retirement proof. */
  UINT64 SetupOffset, SetupExpected, SetupActual, SetupDiff;
  /* DIAG1: append-only cached observations, never additional MMIO reads.
   * CaptureValid: bit0 first failure; bit1 comparison; bit2 first transaction
   * snapshot; bit3 first wait; bit4 gate; bit5 QCH; bit6 mode; bits7..12 pins;
   * bits13..17 inherited CTL/FIFO_CTL/INT_EN/USI_CON/USI_OPTION.
   * FirstCompare: 1 masked equal, 2 masked not-equal, 3 maximum,
   * 4 boolean predicate. Not-equal is used for the inaccessible all-ones value.
   * FirstAddress is an MMIO address or0 for a local
   * predicate. A clear comparison-valid bit means no register predicate applies.
   */
  UINT64 CaptureValid, FirstAddress, FirstExpected, FirstActual, FirstMask, FirstCompare;
  UINT64 FirstInterrupt, FirstTransfer, FirstFifo, FirstAuto, FirstWaitUs, FirstWaitExit;
  UINT64 FirstTransfers, FirstTxBytes, FirstRxBytes;
  UINT64 GateAddress, GateValue, InheritedQch, InheritedMode, InheritedPin[6];
  UINT64 InheritedControl, InheritedFifoControl, InheritedInterruptEnable;
  UINT64 InheritedUsiControl, InheritedUsiOption;
  /* FIX1: CON is a function selector; DAT observations are sampled pin levels,
   * not proof of the stored output latch. DAT is never written by this core.
   * PinDataValid pairs: bits0/1 before,2/3 released,4/5 I2C-ready,6/7 restored.
   * PinPhase:1 saved,2 owned handover,3 released/HIGH,4 I2C-selected,5 ready,
   * 8 restored. PinFailurePhase freezes at the first fatal failure.
   * Changed/Restored masks identify SCL(bit0) and SDA(bit1); Changed records
   * attempted owned pin-configuration writes, including failed readback.
   */
  UINT64 PinPhase, PinFailurePhase, PinOutputMask, PinChangedMask, PinRestoredMask, PinDataValid;
  UINT64 PinDataBefore[2], PinDataReleased[2], PinDataReady[2], PinDataRestored[2];
} N976N_BATTERY_BUS_REPORT;
extern volatile N976N_BATTERY_BUS_REPORT mN976nBatteryBusReport;
EFI_STATUS N976nBatteryBusSample (UINT64 SampleId, N976N_BATTERY_RAW *Raw);
EFI_STATUS N976nBatteryBusObserve(UINT64 Id,N976N_BATTERY_RAW *R,N976N_CHARGE_OBSERVATION *O);
BOOLEAN N976nBatteryBusGetRestoredSelectedConfig(UINT32 Config[16]);
#endif
