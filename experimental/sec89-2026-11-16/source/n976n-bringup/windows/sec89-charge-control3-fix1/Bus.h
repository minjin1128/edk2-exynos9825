/* SPDX-License-Identifier: MIT
 * Repeated, exclusively owned Windows HSI45 observation. Portable transport;
 * caller supplies validated mappings/lease and serializes every entry point.
 * No pointer into a lease selects arbitrary MMIO: fixed address allowlists below
 * bind the descriptor set before any clock register is read.
 */
#ifndef N976N_BAT_BUS_H
#define N976N_BAT_BUS_H
#include "N976nBattery.h"
#include "Charge.h"
#include "ChargeControl.h"
#define N976N_BAT_BUS_MAX_CLOCKS 32U
#define N976N_BAT_BUS_SUCCESS 0ULL
#define N976N_BAT_BUS_INVALID_PARAMETER 0x8000000000000002ULL
#define N976N_BAT_BUS_UNSUPPORTED 0x8000000000000003ULL
#define N976N_BAT_BUS_NOT_READY 0x8000000000000006ULL
#define N976N_BAT_BUS_DEVICE_ERROR 0x8000000000000007ULL
#define N976N_BAT_BUS_TIMEOUT 0x8000000000000012ULL
#define N976N_BAT_BUS_BUSY 0x8000000000000014ULL
#define N976N_BAT_BUS_ABORTED 0x8000000000000015ULL
typedef struct {
  N976N_BAT_U32 (*Read32)(void *Opaque, N976N_BAT_U64 Address);
  void (*Write32)(void *Opaque, N976N_BAT_U64 Address, N976N_BAT_U32 Value);
  void (*Barrier)(void *Opaque);
  N976N_BAT_U64 (*Counter)(void *Opaque);
  void (*StallUs)(void *Opaque, N976N_BAT_U32 Us);
  int (*Cancelled)(void *Opaque);
} N976N_BAT_BUS_OPS;
typedef struct {
  N976N_BAT_U64 CounterHz, InputHz;
  N976N_BAT_U32 ClockCount, ClockReserved;
  N976N_BAT_U64 ClockAddress[N976N_BAT_BUS_MAX_CLOCKS];
  N976N_BAT_U32 ClockValue[N976N_BAT_BUS_MAX_CLOCKS];
  N976N_BAT_U32 Qch, Mode, Gpio[6], Config[16];
} N976N_BAT_BUS_BINDING;
typedef char N976nBatBusBindingAbi[(sizeof(N976N_BAT_BUS_BINDING)==504)?1:-1];
typedef struct {
  N976N_BAT_U64 Phase, Status, Reason, FailurePhase;
  N976N_BAT_U64 InputHz, Input, ClockAddress, ClockValue;
  N976N_BAT_U64 SampleId, SampledMask, Field, Address, Register, Requested, Received;
  N976N_BAT_U64 Transfers, TxBytes, RxBytes, Interrupt, Transfer, Fifo, Auto;
  N976N_BAT_U64 WaitUs, WaitExit, Retired, Restored, Quarantine;
  N976N_BAT_U64 NoMutation; /* 1 until the first MMIO write; not a retirement proof. */
  N976N_BAT_U64 SetupOffset, SetupExpected, SetupActual, SetupDiff;
  /* DIAG1: append-only cached observations, never additional MMIO reads.
   * CaptureValid: bit0 first failure; bit1 comparison; bit2 first transaction
   * snapshot; bit3 first wait; bit4 gate; bit5 QCH; bit6 mode; bits7..12 pins;
   * bits13..17 inherited CTL/FIFO_CTL/INT_EN/USI_CON/USI_OPTION.
   * FirstCompare: 1 masked equal, 2 masked not-equal, 3 maximum,
   * 4 boolean predicate. Not-equal is used for the inaccessible all-ones value.
   * FirstAddress is an MMIO address or0 for a local
   * predicate. A clear comparison-valid bit means no register predicate applies.
   */
  N976N_BAT_U64 CaptureValid, FirstAddress, FirstExpected, FirstActual, FirstMask, FirstCompare;
  N976N_BAT_U64 FirstInterrupt, FirstTransfer, FirstFifo, FirstAuto, FirstWaitUs, FirstWaitExit;
  N976N_BAT_U64 FirstTransfers, FirstTxBytes, FirstRxBytes;
  N976N_BAT_U64 GateAddress, GateValue, InheritedQch, InheritedMode, InheritedPin[6];
  N976N_BAT_U64 InheritedControl, InheritedFifoControl, InheritedInterruptEnable;
  N976N_BAT_U64 InheritedUsiControl, InheritedUsiOption;
  /* FIX1: CON is a function selector; DAT observations are sampled pin levels,
   * not proof of the stored output latch. DAT is never written by this core.
   * PinDataValid pairs: bits0/1 before,2/3 released,4/5 I2C-ready,6/7 restored.
   * PinPhase:1 saved,2 owned handover,3 released/HIGH,4 I2C-selected,5 ready,
   * 8 restored. PinFailurePhase freezes at the first fatal failure.
   * Changed/Restored masks identify SCL(bit0) and SDA(bit1); Changed records
   * attempted owned pin-configuration writes, including failed readback.
   */
  N976N_BAT_U64 PinPhase, PinFailurePhase, PinOutputMask, PinChangedMask, PinRestoredMask, PinDataValid;
  N976N_BAT_U64 PinDataBefore[2], PinDataReleased[2], PinDataReady[2], PinDataRestored[2];
} N976N_BAT_BUS_REPORT;

typedef struct {
  unsigned InTransaction, Held, HsiSaved, HsiChanged, OuterChanged, PinsChanged, RestoreBlocked;
  unsigned CompareValid, CompareLocked, SampleValid, WaitValid, Cleanup, Capturing;
  N976N_BAT_U64 Hz, CompareAddress, CompareExpected, CompareActual, CompareMask, CompareKind;
  N976N_BAT_U32 SavedQch, SavedMode, Gpio[6], Saved[16];
  N976N_BAT_U64 ClockAddress[N976N_BAT_BUS_MAX_CLOCKS];
  N976N_BAT_U32 ClockValue[N976N_BAT_BUS_MAX_CLOCKS];
  N976N_BAT_U32 ClockCount;
} N976N_BAT_BUS_SAMPLE_STATE;
typedef struct {
  N976N_BAT_BUS_OPS Ops;
  void *Opaque;
  N976N_BAT_BUS_BINDING Binding;
  N976N_BAT_BUS_REPORT Report;
  N976N_BAT_BUS_SAMPLE_STATE S;
  unsigned Initialized, Running, Quarantined, D0Active, SelectedValid;
  N976N_BAT_U32 SelectedConfig[16];
  N976N_BAT_BUS_REPORT AcquireReport, FirstFailure;
  N976N_BAT_U64 Samples;
  /* Single producer owns this mode through final charge STOP then ReleaseD0. */
  unsigned KeepControlOwner,ControlPayload;
  const NCC_TICKET *ControlTicket;
  int (*ControlGuard)(void *,const NCC_TICKET *);
  void *ControlOpaque;
} N976N_BAT_BUS_CONTEXT;
/* Init is one-time for a newly claimed controller. It does no MMIO. Caller has
 * independently verified final firmware release, GIC114 masked, NVS integrity,
 * exact translated resources and single ownership. Never Init to clear Q. */
int N976nBatBusInit(N976N_BAT_BUS_CONTEXT *Context,
  const N976N_BAT_BUS_OPS *Ops, void *Opaque,
  const N976N_BAT_BUS_BINDING *Binding);
/* Capture final post-UART state without changing MMIO. Caller establishes that
 * the register domain is accessible and final UART transaction is retired.
 * The same fixed resolver is used for capture and every later validation. */
int N976nBatBusCaptureBinding(const N976N_BAT_BUS_OPS *Ops,void *Opaque,
  N976N_BAT_U64 CounterHz,N976N_BAT_BUS_BINDING *Binding,
  N976N_BAT_BUS_REPORT *Report);
/* No writes or waits; requires serialized, idle Context (outside Sample). */
int N976nBatBusValidateBinding(N976N_BAT_BUS_CONTEXT *Context);
int N976nBatBusClockAddressAllowed(N976N_BAT_U64 Address);
/* Pure descriptor validation shared by lease producer and consumer. Only a
 * reset-held dormant controller or an initialized MASTER/AUTO I2C controller
 * is admitted; the live predicate then checks the appropriate no-I/O state.
 * Reset-held admission never substitutes for post-initialization FIFO checks.
 */
int N976nBatBusBindingValid(const N976N_BAT_BUS_BINDING *Binding);
/* SEC89: immutable selected-domain image comes from the final UART producer,
 * not from a MODE0 read of gated protocol registers. Bind before AcquireD0.
 * D0 ownership is distinct from S.Held (an unfinished repeated-START pair). */
int N976nBatBusSelectedValid(const N976N_BAT_U32 Config[16]);
int N976nBatBusBindSelected(N976N_BAT_BUS_CONTEXT *Context,
  const N976N_BAT_U32 Config[16]);
N976N_BAT_U64 N976nBatBusAcquireD0(N976N_BAT_BUS_CONTEXT *Context);
N976N_BAT_U64 N976nBatBusReadActive(N976N_BAT_BUS_CONTEXT *Context,
  N976N_BAT_U64 SampleId,N976N_BATTERY_RAW *Raw);
N976N_BAT_U64 N976nBatBusReadChargeActive(N976N_BAT_BUS_CONTEXT *Context,
  N976N_BAT_U64 SampleId,N976N_POWER_RAW *Raw);
/* Exact control API, no arbitrary PMIC payload. Serialized by the producer;
 * Running covers pre-read/compare/issuance/retirement and guard is rechecked
 * before each payload byte. Cleanup admits only B7 MODE4, never WDT or enable. */
enum NCC_IO_RESULT N976nBatBusControl(N976N_BAT_BUS_CONTEXT *,int Write,
 unsigned Register,unsigned char *Value,const NCC_TICKET *,
 int (*Guard)(void *,const NCC_TICKET *),void *);
N976N_BAT_U64 N976nBatBusReleaseD0(N976N_BAT_BUS_CONTEXT *Context);
/* One-shot adapter for firmware/host diagnostics. Public success requires
 * all 9 reads AND final ACK/retire/exact restoration.
 * A failed sample's Raw may retain diagnostic fields but is never publishable.
 * Cancellation blocks new work; bounded retirement/restore remains mandatory.
 * No simultaneous call, stop or unmap is permitted; caller joins its worker. */
N976N_BAT_U64 N976nBatBusSample(N976N_BAT_BUS_CONTEXT *Context,
  N976N_BAT_U64 SampleId, N976N_BATTERY_RAW *Raw);
#endif
