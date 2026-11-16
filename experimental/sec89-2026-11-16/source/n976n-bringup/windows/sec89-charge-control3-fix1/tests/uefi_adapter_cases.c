/* Actual EDK2 AArch64 types + the same portable transport and functional MMIO.
 * Capture/Validate are exercised through firmware-style callback adapters.
 * This is a host fixture, not evidence that post-UART MMIO is accessible. */
#include <N976nBatteryTypes.h>
#define main BusCasesMain
#include "bus_cases.c"
#undef main

static UINT32 FirmwareRead(VOID *Context,UINT64 Address)
{return Read(Context,Address);}
static VOID FirmwareWrite(VOID *Context,UINT64 Address,UINT32 Value)
{Write(Context,Address,Value);}
static VOID FirmwareBarrier(VOID *Context)
{Barrier(Context);}
static UINT64 FirmwareCounter(VOID *Context)
{return Counter(Context);}
static VOID FirmwareStall(VOID *Context,UINT32 Us)
{Stall(Context,Us);}
static int FirmwareCancelled(VOID *Context)
{return Cancel(Context);}
static const N976N_BAT_BUS_OPS FirmwareOps={
 FirmwareRead,FirmwareWrite,FirmwareBarrier,FirmwareCounter,FirmwareStall,FirmwareCancelled
};
int main(void)
{
 N976N_BAT_BUS_CONTEXT firmware;
 N976N_BAT_BUS_BINDING binding;
 N976N_BAT_BUS_REPORT report;
 seed(0);
 *reg(CMGP+0x1020)=1;*reg(CMGP+0x100)=BAT_BIT4;
 *reg(APM+0x1004)=1;*reg(APM+0x100)=BAT_BIT4;
 *reg(TOP+0x160)=BAT_BIT31|BAT_BIT29|BAT_BIT4|(200U<<16)|(13U<<8);
 need(N976nBatBusCaptureBinding(&FirmwareOps,NULL,26000000,&binding,&report)&&
      binding.CounterHz==26000000&&binding.InputHz==400000000&&!writes,
      "uefi_types_firmware_adapter_capture_400MHz_no_writes");
 need(N976nBatBusInit(&firmware,&FirmwareOps,NULL,&binding)&&
      N976nBatBusBindSelected(&firmware,binding.Config)&&
      N976nBatBusValidateBinding(&firmware)&&!writes,
      "uefi_types_accepted_ebs_binding_validation_read_only");
 *reg(HSI+TRANS)|=BAT_BIT17;
 need(!N976nBatBusValidateBinding(&firmware)&&!writes,
      "uefi_adapter_refuses_unretired_bus_without_write");
 *reg(HSI+TRANS)=1;*reg(TOP+0x1800)=1;
 need(!N976nBatBusValidateBinding(&firmware)&&!writes,
      "uefi_adapter_refuses_clock_drift_without_write");
 need(!N976nBatBusCaptureBinding(&FirmwareOps,NULL,0,&binding,&report)&&!writes,
      "uefi_adapter_invalid_counter_no_write");
 /* DIAG1 reset-state fixture through actual UEFI types/callbacks. */
 seed(0);reset_model=1;
 *reg(MODE)=0;*reg(QCH)=0x003F0002;
 for(unsigned i=0;i<16;i++)*reg(HSI+mConfigOffsets[i])=0;
 *reg(HSI+FIFO_CTL)=6;*reg(HSI+USI_CON)=1;*reg(HSI+USI_OPTION)=1;
 *reg(HSI+TRANS)=0;
 *reg(GPIO+0x180)=*reg(GPIO+0x1A0)=1;
 *reg(GPIO+0x184)=*reg(GPIO+0x1A4)=0;
 *reg(GPIO+0x188)=*reg(GPIO+0x1A8)=0;
 *reg(GPIO+0x18C)=*reg(GPIO+0x1AC)=2;
 need(N976nBatBusCaptureBinding(&FirmwareOps,NULL,26000000,&binding,&report)&&
      binding.Mode==0&&binding.Config[14]==1&&inactive_fifo_reads&&!writes,
      "uefi_adapter_dormant_fifo_zero_capture_read_only");
 need(N976nBatBusInit(&firmware,&FirmwareOps,NULL,&binding)&&
      N976nBatBusBindSelected(&firmware,binding.Config)&&
      N976nBatBusValidateBinding(&firmware)&&!writes,
      "uefi_adapter_dormant_accepted_ebs_validation_read_only");
 *reg(HSI+USI_CON)=0;
 need(!N976nBatBusValidateBinding(&firmware)&&!writes,
      "uefi_adapter_dormant_reset_release_drift_refused_before_mutation");
 printf("PASS %u cases\n",tests);return 0;
}
