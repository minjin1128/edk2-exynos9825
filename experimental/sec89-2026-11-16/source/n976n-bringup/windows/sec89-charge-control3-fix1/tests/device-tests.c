/* Actual Device.c adapter with mocked kernel/Battc scheduling and mapping.
 * Bus/register algorithms have separate tests; no hardware-success claim. */
#include "device_mocks/ntddk.h"
#include "../Device.c"
#include "../AdcWdf.c"
#include <setjmp.h>
#include <stdio.h>
#include "../../../common/sec89-charge-win1/tests/twrp_dt_fixture.h"
static unsigned Cases;
#define CHECK(x) do{Cases++;if(!(x)){fprintf(stderr,"FAIL %d: %s\n",__LINE__,#x);return 0;}}while(0)
static struct {
 WDFDEVICE Device; MOCK_LOCK Locks[2];unsigned LocksMade,Irql;
 union{uint64_t Align;UCHAR Bytes[4096];}Page;
 void*Memory[N976N_BAT_FIXED_RESOURCES];ULONG Protection[N976N_BAT_RESOURCES];unsigned Maps,Unmaps,MapFail,MutateOnMap;
 unsigned Acquires,Releases,AcquireFail,ReleaseFail,ChargeFail;
 unsigned IdentityFail,IdentityInjected,PayloadsAtIdentity,KicksAtIdentity;
 unsigned ChargeReadDelayMs,Scenario,Offline,GaugeFailureCycle,AfterGaugeFault;ULONG SeenTags[4];
 unsigned AfterInputFailure,ControlModel,CycleLimit,Sleeps,Payloads,Stops,Enables,MaxManaged,StopReadFail,ChargeReads,ReadsAtFailure,BackendAtFailure;UCHAR Pmic[256];
 unsigned Reads,Writes,BackendInitFail,BindingFail,BackendCalls,SampleMode;
 int64_t Hz;ULONGLONG Time;unsigned ThreadFail,ThreadActive,ThreadWaits,ThreadCloses,Terminated;
 void(*ThreadRoutine)(void*);void*ThreadArgument;
 BATTERY_MINIPORT_INFO ClassInfo;unsigned ClassInitFail,ClassInits,ClassUnloads,Notifies,Reentries;
 NTSTATUS ClassIoctlStatus,ClassWmiStatus;SYSCTL_IRP_DISPOSITION Disposition;
 unsigned Forwarded,Completed,WmiRegisters,WmiDeregisters,QueuePower;
 WDFINTERRUPT Irq;WDF_INTERRUPT_CONFIG IrqConfig;WDF_PNPPOWER_EVENT_CALLBACKS Pnp;
 unsigned IrqLocked,AdcWaits,AdcMode,Starts,Irqs,Dpcs,ThreadRuns,JoinTimeout,BugPhase;
 unsigned LockTimeout,TrapExpected,PendingDpc,DpcRuns;
} M;
static jmp_buf Trap;
static N976N_BAT_LEASE*Lease(void){return (N976N_BAT_LEASE*)M.Page.Bytes;}
static void FillLease(void)
{
 N976N_BAT_LEASE*l=Lease();memset(M.Page.Bytes,0,4096);l->Magic=N976N_BAT_LEASE_MAGIC;
 l->BootCounter=1;l->CounterHz=26000000;l->Version=N976N_BAT_LEASE_VERSION;l->Bytes=sizeof(*l);
 l->ImmutableBytes=N976N_BAT_LEASE_IMMUTABLE_BYTES;l->ProducerStage=N976N_BAT_LEASE_RELEASED;
 l->Factor=2;l->FactorStatus=1;l->Gic114Masked=l->ProducerRetired=l->ProducerRestored=1;l->ProducerKind=N976N_BAT_PRODUCER_GAUGE_USB;
 l->Binding.CounterHz=26000000;l->Binding.InputHz=100000000;l->Guard=N976N_BAT_LEASE_GUARD;
 l->Adc.Generation=l->BootCounter;l->Adc.Original[0]=2;l->Adc.Original[1]=0x24;
 l->Adc.FirmwareRetired=l->Adc.FirmwareRestored=l->Adc.FirmwareIrqDetached=1;
 l->Adc.Clocks[4]=l->Adc.Clocks[5]=1U<<21;l->Adc.Clocks[7]=l->Adc.Clocks[8]=2;l->Adc.AdmissionDigest[0]=1;
 NCA_THERMAL_CONTRACT*t=&l->Adc.Thermal;t->Version=1;t->Bytes=sizeof(*t);t->Checks=0x1F;
 t->AdcAddress=NCA_BASE;t->AdcBytes=0x100;t->Irq=116;t->Clock=110;t->AdcType=1;t->SampleCount=5;t->PointCount=23;
 for(unsigned i=0;i<3;i++){t->Channels[i]=NcaThermalChannels[i];t->Sources[i]=t->CheckTypes[i]=2;
  for(unsigned j=0;j<23;j++){t->Adc[i][j]=NcaThermalAdc[i][j];t->DeciC[i][j]=NcaThermalDeciC[j];}}
 l->Crc32=N976nBatLeaseCrc(l);*(uint64_t*)(M.Page.Bytes+4088)=N976N_BAT_LEASE_GUARD;
}
static void Dispose(void)
{unsigned i;if(M.Device){for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++){free(M.Memory[i]);M.Memory[i]=NULL;}free(M.Device->Context);free(M.Device);M.Device=NULL;if(M.Irq){free(M.Irq->Context);free(M.Irq);M.Irq=NULL;}}}
static void Reset(void)
{Dispose();memset(&M,0,sizeof(M));M.Hz=10000000;M.Time=1000;M.ClassIoctlStatus=STATUS_NOT_SUPPORTED;M.Disposition=IrpForward;M.ClassWmiStatus=STATUS_NOT_SUPPORTED;FillLease();}
static BAT_DEVICE*Context(void){return BatGet(M.Device);}
static int Add(void)
{struct MOCK_INIT init={0};CHECK(BatAdd(NULL,&init)==STATUS_SUCCESS);CHECK(init.Fdo.EvtDeviceFilterRemoveResourceRequirements==N976nClockShareFilter);CHECK(init.Preprocess[IRP_MJ_DEVICE_CONTROL]==BatIoctl);CHECK(init.Preprocess[IRP_MJ_SYSTEM_CONTROL]==BatSystemControl);CHECK(M.QueuePower==WdfFalse);return 1;}
static void Resources(MOCK_CM*r,MOCK_CM*t)
{unsigned i;memset(r,0,sizeof(*r));r->Count=N976N_BAT_DESCRIPTOR_COUNT;
 for(i=0;i<N976N_BAT_RESOURCES;i++){PCM_PARTIAL_RESOURCE_DESCRIPTOR d=&r->Items[i];d->Type=CmResourceTypeMemory;d->ShareDisposition=i==N976N_BAT_TOP_INDEX?CmResourceShareShared:CmResourceShareDeviceExclusive;
 d->u.Memory.Start.QuadPart=i==N976N_BAT_NVS_INDEX?N976N_BAT_LEASE_LOW:N976nBatResources[i].Address;
 d->u.Memory.Length=i==N976N_BAT_NVS_INDEX?4096:N976nBatResources[i].Bytes;
 d->Flags=i<N976N_BAT_FIXED_RESOURCES&&!N976nBatResources[i].Writable?CM_RESOURCE_MEMORY_READ_ONLY:0;}
 r->Items[N976N_BAT_IRQ_INDEX].Type=CmResourceTypeInterrupt;
 r->Items[N976N_BAT_IRQ_INDEX].ShareDisposition=CmResourceShareDeviceExclusive;
 r->Items[N976N_BAT_IRQ_INDEX].u.Interrupt.Vector=116;
 *t=*r;t->Items[N976N_BAT_IRQ_INDEX].u.Interrupt.Vector=0x150;}
static int Prepared(void){MOCK_CM r,t;CHECK(Add());Resources(&r,&t);CHECK(BatPrepare(M.Device,&r,&t)==STATUS_SUCCESS);return 1;}

ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG*q){M.Time+=100;*q=M.Time;return M.Time;}
LARGE_INTEGER KeQueryPerformanceCounter(LARGE_INTEGER*h){LARGE_INTEGER x={(int64_t)M.Time};if(h)h->QuadPart=M.Hz;return x;}
void KeStallExecutionProcessor(ULONG u){assert(u<=100);}
static ULONG *AdcReg(unsigned offset){return (ULONG*)((UCHAR*)M.Memory[N976N_BAT_ADC_INDEX]+offset);}
static void AdcInterrupt(void){
 assert(!M.IrqLocked);unsigned ch=*AdcReg(4)&7;
 *AdcReg(8)=0x80000000U|(ch==4?1812:ch==3?1786:1815);M.Time+=1040;
 M.IrqLocked=1;M.Irql=7;assert(M.IrqConfig.Isr(M.Irq,0));M.Irqs++;M.IrqLocked=0;M.Irql=2;
 if(M.PendingDpc){M.PendingDpc=0;M.DpcRuns++;M.IrqConfig.Dpc(M.Irq,NULL);}M.Irql=0;
}
NTSTATUS KeWaitForSingleObject(void*e,int r,int m,int a,LARGE_INTEGER*t){
 (void)r;(void)m;(void)a;assert(t&&t->QuadPart<0&&M.Irql==0&&!M.IrqLocked);
 if(e==&Context()->Adc->Completion){
  M.AdcWaits++;assert(t->QuadPart>=-1000000);
  if(M.AdcMode==1){M.Time+=(uint64_t)-t->QuadPart;return STATUS_TIMEOUT;}
  if(M.AdcMode==2){Context()->StopRequested=1;NcaWdfRequestStop(Context()->Adc);KeSetEvent(&Context()->StopEvent,0,0);}
  AdcInterrupt();return Context()->Adc->Completion.Signaled?STATUS_SUCCESS:STATUS_TIMEOUT;
 }
 assert(e==&Context()->StopEvent&&t->QuadPart>=-10000000&&t->QuadPart<=-10000);
 if(M.ControlModel&&++M.Sleeps<M.CycleLimit){
  if(Context()->Control.State==NCC_MANAGED)M.MaxManaged++;
  if(M.AfterInputFailure&&Context()->Control.InputTouched&&!M.Enables)M.ChargeFail=1;
  if(M.Scenario==1){M.Offline=M.Sleeps>=6&&M.Sleeps<10;}
  if(M.Scenario==2&&M.Sleeps==6)M.Pmic[0xB4]=0x33;
  if(M.Scenario==3)M.ChargeFail=M.Sleeps==6;
  if(M.Scenario==4&&M.Sleeps==6)M.Pmic[0xB4]=0x34;
  M.Time+=(uint64_t)-t->QuadPart;return STATUS_TIMEOUT;
 }
 /* Deterministic external stop, after bounded integration cycles. */
 Context()->StopRequested=1;NcaWdfRequestStop(Context()->Adc);KeSetEvent(&Context()->StopEvent,0,0);
 return STATUS_SUCCESS;
}
NTSTATUS PsCreateSystemThread(HANDLE*h,ULONG access,OBJECT_ATTRIBUTES*o,void*p,void*i,void(*f)(void*),void*c){(void)p;(void)i;assert(access==SYNCHRONIZE&&o->Flags==OBJ_KERNEL_HANDLE);if(M.ThreadFail)return STATUS_INSUFFICIENT_RESOURCES;M.ThreadRoutine=f;M.ThreadArgument=c;M.ThreadActive=1;*h=&M.ThreadActive;return STATUS_SUCCESS;}
static void RunWorker(void){assert(M.ThreadActive&&M.ThreadRoutine&&!M.ThreadRuns);M.ThreadRuns++;M.ThreadRoutine(M.ThreadArgument);assert(!M.ThreadActive);}
NTSTATUS ZwWaitForSingleObject(HANDLE h,int alert,LARGE_INTEGER*t){BAT_DEVICE*c=Context();
 assert(h==&M.ThreadActive&&!alert&&t&&t->QuadPart==-100000000);
 assert(c->StopRequested&&c->StopEvent.Signaled&&!M.Locks[0].Held&&!M.Locks[1].Held);
 assert(c->Maps[N976N_BAT_NVS_INDEX]);M.ThreadWaits++;
 if(M.JoinTimeout)return STATUS_TIMEOUT;
 if(M.ThreadActive)RunWorker();assert(!M.ThreadActive&&M.Terminated==1);return STATUS_SUCCESS;
}
_Noreturn void KeBugCheckEx(ULONG code,ULONG_PTR magic,ULONG_PTR phase,ULONG_PTR status,ULONG_PTR c){
 assert(code==0xE0000089U&&magic==0x4E4E4144&&(void*)c==Context());assert(status==STATUS_TIMEOUT);
 M.BugPhase=(unsigned)phase;assert(M.TrapExpected);longjmp(Trap,1);
}
NTSTATUS ZwClose(HANDLE h){assert(h==&M.ThreadActive&&!M.ThreadActive);M.ThreadCloses++;return STATUS_SUCCESS;}
void PsTerminateSystemThread(NTSTATUS s){assert(s==STATUS_SUCCESS);M.Terminated++;M.ThreadActive=0;}
void*MmMapIoSpaceEx(PHYSICAL_ADDRESS p,SIZE_T bytes,ULONG prot){unsigned i;++M.Maps;if(M.MapFail==M.Maps)return NULL;
 if(M.MutateOnMap==M.Maps)Lease()->BootCounter++;
 if((ULONGLONG)p.QuadPart==N976N_BAT_LEASE_LOW){assert(bytes==4096);M.Protection[N976N_BAT_NVS_INDEX]=prot;return M.Page.Bytes;}
 for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++)if((ULONGLONG)p.QuadPart==N976nBatResources[i].Address){assert(bytes==N976nBatResources[i].Bytes);M.Protection[i]=prot;M.Memory[i]=calloc(1,bytes);assert(M.Memory[i]);
 if(i==N976N_BAT_ADC_INDEX){ULONG*q=M.Memory[i];q[0]=2;q[1]=0x24;}
 for(unsigned k=0;k<NCA_CLOCKS;k++)if(N976nBatResources[i].Address==NcaClockAddresses[k])*(ULONG*)M.Memory[i]=Lease()->Adc.Clocks[k];
 return M.Memory[i];}assert(0);return NULL;}
void MmUnmapIoSpace(void*p,SIZE_T n){unsigned i;assert(!M.ThreadActive);M.Unmaps++;if(p==M.Page.Bytes){assert(n==4096);return;}for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++)if(p==M.Memory[i]){assert(n==N976nBatResources[i].Bytes);free(p);M.Memory[i]=NULL;return;}assert(0);}
ULONG READ_REGISTER_ULONG(volatile ULONG*r){M.Reads++;return *r;}
void WRITE_REGISTER_ULONG(volatile ULONG*r,ULONG v){M.Writes++;if(r==AdcReg(0)&&v==3)M.Starts++;*r=v;}
unsigned KeGetCurrentIrql(void){return M.Irql;}
void IoCompleteRequest(PIRP i,int boost){assert(!boost&&!i->Completed);i->Completed++;M.Completed++;}
NTSTATUS WdfWaitLockAcquire(WDFWAITLOCK l,LONGLONG*t){assert(l&&!l->Held);if(t){assert(*t==-100000000);if(M.LockTimeout)return STATUS_TIMEOUT;}l->Held=1;return STATUS_SUCCESS;}
void WdfWaitLockRelease(WDFWAITLOCK l){assert(l&&l->Held);l->Held=0;}
NTSTATUS WdfWaitLockCreate(WDF_OBJECT_ATTRIBUTES*a,WDFWAITLOCK*l){assert(a->ParentObject==M.Device&&M.LocksMade<2);*l=&M.Locks[M.LocksMade++];return STATUS_SUCCESS;}
NTSTATUS WdfDeviceCreate(PWDFDEVICE_INIT*i,WDF_OBJECT_ATTRIBUTES*a,WDFDEVICE*d){(void)i;assert(a->ContextSize==sizeof(BAT_DEVICE)&&a->ExecutionLevel==WdfExecutionLevelPassive&&a->SynchronizationScope==WdfSynchronizationScopeNone);M.Device=calloc(1,sizeof(*M.Device));M.Device->Context=calloc(1,a->ContextSize);M.Device->Object.Wdf=M.Device;*d=M.Device;return STATUS_SUCCESS;}
NTSTATUS WdfDeviceWdmDispatchPreprocessedIrp(WDFDEVICE d,PIRP i){assert(d==M.Device&&i->Skipped&&!i->Completed);M.Forwarded++;i->Forwarded++;return STATUS_NOT_SUPPORTED;}
NTSTATUS WdfDeviceInitAssignWdmIrpPreprocessCallback(PWDFDEVICE_INIT i,EVT_WDFDEVICE_WDM_IRP_PREPROCESS*f,UCHAR major,void*sub,ULONG count){assert(!sub&&!count&&major<24);i->Preprocess[major]=f;return STATUS_SUCCESS;}
void WdfDeviceInitSetPnpPowerEventCallbacks(PWDFDEVICE_INIT i,WDF_PNPPOWER_EVENT_CALLBACKS*c){i->Pnp=*c;M.Pnp=*c;}
NTSTATUS WdfIoQueueCreate(WDFDEVICE d,WDF_IO_QUEUE_CONFIG*c,WDF_OBJECT_ATTRIBUTES*a,void*h){assert(d==M.Device&&!a&&!h&&c->EvtIoDeviceControl==BatUnsupported);M.QueuePower=c->PowerManaged;return STATUS_SUCCESS;}
static void Reenter(void){ULONG tag=0;BATTERY_STATUS s;assert(M.Locks[1].Held&&!M.Locks[0].Held);M.Reentries++;if(M.ClassInfo.QueryTag(M.ClassInfo.Context,&tag)==STATUS_SUCCESS)assert(M.ClassInfo.QueryStatus(M.ClassInfo.Context,tag,&s)==STATUS_SUCCESS);else assert(!tag);}
NTSTATUS BatteryClassInitializeDevice(PBATTERY_MINIPORT_INFO info,PVOID*h){M.ClassInits++;M.ClassInfo=*info;Reenter();if(M.ClassInitFail)return STATUS_INSUFFICIENT_RESOURCES;*h=&M.ClassInfo;return 0;}
void BatteryClassStatusNotify(PVOID h){assert(h==&M.ClassInfo);M.Notifies++;Reenter();if(M.GaugeFailureCycle&&Context()->Samples>0&&Context()->Samples<=4)M.SeenTags[Context()->Samples-1]=Context()->Cache.View.Tag;}
void BatteryClassUnload(PVOID h){assert(h==&M.ClassInfo&&!M.ThreadActive);Reenter();M.ClassUnloads++;}
NTSTATUS BatteryClassIoctl(PVOID h,PIRP i){assert(h==&M.ClassInfo);Reenter();if(M.ClassIoctlStatus==STATUS_SUCCESS)IoCompleteRequest(i,0);return M.ClassIoctlStatus;}
NTSTATUS BatteryClassSystemControl(PVOID h,WMILIB_CONTEXT*w,PDEVICE_OBJECT o,PIRP i,SYSCTL_IRP_DISPOSITION*d){(void)w;(void)o;assert(h==&M.ClassInfo);Reenter();*d=M.Disposition;if(*d==IrpProcessed)IoCompleteRequest(i,0);return M.ClassWmiStatus;}
NTSTATUS BatteryClassQueryWmiDataBlock(PVOID h,PDEVICE_OBJECT o,PIRP i,ULONG g,PULONG z,ULONG n,PUCHAR b){(void)o;(void)i;(void)g;(void)z;(void)n;(void)b;assert(h==&M.ClassInfo);return STATUS_WMI_GUID_NOT_FOUND;}
NTSTATUS WmiCompleteRequest(PDEVICE_OBJECT o,PIRP i,NTSTATUS s,ULONG n,int boost){(void)o;i->IoStatus.Status=s;i->IoStatus.Information=n;IoCompleteRequest(i,boost);return s;}
NTSTATUS IoWMIRegistrationControl(PDEVICE_OBJECT o,ULONG action){assert(o==&M.Device->Object);if(action==WMIREG_ACTION_REGISTER)M.WmiRegisters++;else{assert(action==WMIREG_ACTION_DEREGISTER);M.WmiDeregisters++;}return 0;}
int N976nBatBusSelectedValid(const N976N_BAT_U32*v){return v&&v[3]==0;}
int N976nBatBusBindingValid(const N976N_BAT_BUS_BINDING*b){return b&&b->InputHz==100000000;}
int N976nBatBusValidateBinding(N976N_BAT_BUS_CONTEXT*c){assert(c->Initialized);return !M.BindingFail;}
int N976nBatBackendInit(N976N_BAT_BACKEND*b,const N976N_BAT_BUS_OPS*o,void*p,const N976N_BAT_BUS_BINDING*binding,N976N_BAT_U32 factor,const N976N_BAT_U32 selected[16]){assert(selected);assert(o==&Ops&&p==Context()&&factor==2&&binding->CounterHz==(ULONGLONG)M.Hz);if(M.BackendInitFail)return 0;memset(b,0,sizeof(*b));b->Bus.Initialized=1;b->Bus.Ops=*o;b->Bus.Opaque=p;b->Bus.Binding=*binding;return 1;}
N976N_BAT_U64 N976nBatBusAcquireD0(N976N_BAT_BUS_CONTEXT*b){assert(b==&Context()->Backend.Bus&&!b->D0Active&&!b->Quarantined);M.Acquires++;if(M.AcquireFail)return N976N_BAT_BUS_NOT_READY;b->D0Active=1;b->Report.Retired=1;return 0;}
N976N_BAT_U64 N976nBatBusReleaseD0(N976N_BAT_BUS_CONTEXT*b){assert(b==&Context()->Backend.Bus&&Context()->Mapped==N976N_BAT_RESOURCES);M.Releases++;if(M.ControlModel&&M.Enables)assert((M.Pmic[0xB7]&15)==4&&M.Stops>=2);assert(Lease()->ClaimState==N976N_BAT_CLAIM_OWNED);if(b->Quarantined||M.ReleaseFail){b->Quarantined=1;return N976N_BAT_BUS_NOT_READY;}b->D0Active=0;return 0;}
N976N_BAT_U64 N976nBatBusReadChargeActive(N976N_BAT_BUS_CONTEXT*b,N976N_BAT_U64 id,N976N_POWER_RAW*r){assert(b->D0Active&&id);M.ChargeReads++;M.Time+=(uint64_t)M.ChargeReadDelayMs*10000;memset(r,0,sizeof(*r));r->Sequence=id;if(M.ChargeFail){if(!b->KeepControlOwner)N976nBatBusReleaseD0(b);return N976N_BAT_BUS_DEVICE_ERROR;}r->ValidMask=N976N_PWR_ALL;
 if(M.ControlModel){static const unsigned char regs[11]={0xB2,0xB3,0xB4,0xB7,0xB8,0xB9,0xBA,0xBB,0xBD,0xC0,0xC3};
  for(unsigned i=0;i<11;i++)r->Byte[i]=M.Pmic[regs[i]];
  r->Byte[11]=0x27;r->Byte[12]=0x81;r->Byte[13]=0xA1;r->Byte[14]=8;r->Byte[15]=0x19;r->Byte[16]=0x47;r->Byte[17]=4;r->Byte[18]=0x73;
  if(M.Offline){r->Byte[0]&=~0x60;r->Byte[12]&=0x7F;r->Byte[13]&=~7;}
 }return 0;}
enum NCC_IO_RESULT N976nBatBusControl(N976N_BAT_BUS_CONTEXT *b,int write,unsigned reg,unsigned char *value,const NCC_TICKET *t,int(*guard)(void *,const NCC_TICKET *),void *o){
 assert(M.ControlModel&&b->D0Active&&!b->Quarantined&&b->Report.Retired&&guard(o,t));
 assert(reg==0xB7||reg==0xB9||reg==0xBD||(reg==0xC0&&(t->InputSetup||t->Cleanup)));
 if(M.StopReadFail&&!write&&reg==0xB7&&t->Cleanup){M.ReadsAtFailure=M.ChargeReads;M.BackendAtFailure=M.BackendCalls;return NCC_IO_RETIRED_ERROR;}
 if(write){assert(t->CompareBefore&&M.Pmic[reg]==t->Before);M.Payloads++;
  if(reg==0xB7){if((*value&15)==4)M.Stops++;else{assert((*value&15)==5);M.Enables++;}}
  M.Pmic[reg]=*value;
  if(reg==0xBD){M.Pmic[reg]&=0xFC;M.Pmic[0xB4]=0x31;}
 }else *value=M.Pmic[reg];
 return NCC_IO_OK;
}
static void RawField(N976N_BATTERY_RAW*r,unsigned f,unsigned value){N976N_BATTERY_READ spec;N976N_BAT_U8 bytes[2]={(UCHAR)value,(UCHAR)(value>>8)};assert(N976nBatteryReadSpec(f,&spec));assert(N976nBatteryRecord(r,f,1,bytes,spec.Bytes)==N976N_BAT_OK);}
N976N_BAT_U64 N976nBatBackendReadActive(N976N_BAT_BACKEND*b,N976N_BAT_BACKEND_SAMPLE*s){BAT_DEVICE*c=Context();assert(b==&c->Backend&&!M.Locks[0].Held&&!M.Locks[1].Held&&c->Mapped==N976N_BAT_RESOURCES);assert(b->Bus.D0Active);M.BackendCalls++;memset(s,0,sizeof(*s));N976nBatteryBegin(&s->Raw,++b->Sequence);RawField(&s->Raw,N976N_BAT_STATUS,0);RawField(&s->Raw,N976N_BAT_SOCREP,0x4000);RawField(&s->Raw,N976N_BAT_VCELL,0xC000);s->Publishable=M.SampleMode!=1;
 if(M.GaugeFailureCycle==M.BackendCalls){s->Publishable=0;s->CleanReadFailure=1;s->Status=N976N_BAT_BUS_TIMEOUT;if(M.AfterGaugeFault==1)c->AccessRefused=1;if(M.AfterGaugeFault==2)b->Bus.Quarantined=1;if(M.AfterGaugeFault==3)c->StopRequested=1;}
 if(M.SampleMode==2)c->StopRequested=1;if(M.SampleMode==3)Lease()->BootCounter++;if(M.SampleMode==4)b->Bus.Quarantined=1;if(M.SampleMode==5)c->AccessRefused=1;return 0;}

NTSTATUS WdfInterruptCreate(WDFDEVICE d,WDF_INTERRUPT_CONFIG*cfg,WDF_OBJECT_ATTRIBUTES*a,WDFINTERRUPT*out){
 assert(d==M.Device&&!M.Irq&&!cfg->PassiveHandling&&!cfg->AutomaticSerialization&&cfg->ShareVector==WdfFalse);
 M.Irq=calloc(1,sizeof(*M.Irq));assert(M.Irq);M.Irq->Context=calloc(1,a->ContextSize);assert(M.Irq->Context);
 M.IrqConfig=*cfg;*out=M.Irq;return STATUS_SUCCESS;
}
BOOLEAN WdfInterruptQueueDpcForIsr(WDFINTERRUPT irq){assert(irq==M.Irq&&M.Irql==7&&M.IrqLocked);assert(!M.PendingDpc);M.Dpcs++;M.PendingDpc=1;return TRUE;}
BOOLEAN WdfInterruptSynchronize(WDFINTERRUPT irq,EVT_WDF_INTERRUPT_SYNCHRONIZE*fn,WDFCONTEXT c){
 assert(irq==M.Irq&&M.Irql==0&&!M.IrqLocked);M.IrqLocked=1;M.Irql=7;BOOLEAN r;
 if(M.IdentityFail&&!M.IdentityInjected&&fn==NcaWdfSync&&((SYNC_REQUEST*)c)->Action==SYNC_IDENTITY&&Context()->Control.State==NCC_MANAGED&&Context()->Control.Busy){
  M.IdentityInjected++;M.PayloadsAtIdentity=M.Payloads;M.KicksAtIdentity=Context()->Control.Kicks;((SYNC_REQUEST*)c)->Result=0;r=FALSE;
 }else r=fn(irq,c);
 M.Irql=M.IrqLocked=0;return r;
}
static NTSTATUS Enable(void){M.IrqLocked=1;M.Irql=7;NTSTATUS s=M.IrqConfig.EvtInterruptEnable(M.Irq,M.Device);M.Irql=M.IrqLocked=0;return s;}
static NTSTATUS Disable(void){assert(!M.ThreadActive);M.IrqLocked=1;M.Irql=7;NTSTATUS s=M.IrqConfig.EvtInterruptDisable(M.Irq,M.Device);M.Irql=M.IrqLocked=0;return s;}
static int Start(void){CHECK(M.Pnp.EvtDeviceD0Entry(M.Device,0)==0);CHECK(!Context()->Thread);CHECK(Enable()==0);CHECK(M.Pnp.EvtDeviceD0EntryPostInterruptsEnabled(M.Device,0)==0);CHECK(M.ThreadActive);return 1;}
static void Down(void){assert(M.Pnp.EvtDeviceD0ExitPreInterruptsDisabled(M.Device,0)==0);(void)Disable();(void)M.Pnp.EvtDeviceD0Exit(M.Device,0);}
static int ResourceTests(void)
{
 MOCK_CM r,t;unsigned i,j;
 Reset();CHECK(Prepared());CHECK(M.Maps==28&&Context()->Claimed&&Lease()->ClaimState==1);
 CHECK(Context()->ThermalOps.Convert==NcaWdfConvert&&Context()->ThermalOwner==Context()->Adc);
 CHECK(M.Protection[27]==PAGE_READWRITE&&M.Protection[18]==(PAGE_READWRITE|PAGE_NOCACHE)&&M.Protection[17]==(PAGE_READONLY|PAGE_NOCACHE));
 CHECK(BatPrepare(M.Device,&r,&t)==STATUS_DEVICE_CONFIGURATION_ERROR);CHECK(BatRelease(M.Device,NULL)==0);
 CHECK(M.Unmaps==28&&Lease()->ClaimState==0&&!Context()->Thermal.Initialized&&!Context()->Adc->Prepared);
 Resources(&r,&t);CHECK(BatPrepare(M.Device,&r,&t)==0);CHECK(BatRelease(M.Device,NULL)==0);
 for(i=0;i<28;i++)for(j=0;j<4;j++){
  Reset();CHECK(Add());Resources(&r,&t);if(j==0)t.Items[i].u.Memory.Start.QuadPart+=4;if(j==1)t.Items[i].u.Memory.Length++;
  if(j==2)t.Items[i].ShareDisposition=i==17?1:3;if(j==3)t.Items[i].Flags=2;
  CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(!M.Maps&&!Context()->Mapped);
 }
 for(i=0;i<6;i++){
  Reset();CHECK(Add());Resources(&r,&t);if(i==0)r.Count--;if(i==1)t.Count++;
  if(i==2)r.Items[28].u.Interrupt.Vector=117;if(i==3)t.Items[28].u.Interrupt.Vector=0;
  if(i==4)t.Items[28].Flags=1;if(i==5)t.Items[28].ShareDisposition=3;
  CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(!M.Maps);
 }
 for(i=1;i<=28;i++){
  Reset();CHECK(Add());Resources(&r,&t);M.MapFail=i;CHECK(BatPrepare(M.Device,&r,&t)==STATUS_INSUFFICIENT_RESOURCES);
  CHECK(M.Unmaps==i-1&&!Context()->Claimed&&!Context()->Lease&&Lease()->ClaimState==0);
 }
 for(i=1;i<=3;i++){
  Reset();CHECK(Add());Resources(&r,&t);Lease()->ClaimState=i;
  CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(Lease()->ClaimState==i&&M.Maps==1&&M.Unmaps==1);
 }
 for(i=0;i<5;i++){
  Reset();CHECK(Add());Resources(&r,&t);
  if(i==0)Lease()->Version=3;if(i==1)Lease()->ProducerKind=1;if(i==2)Lease()->ProducerKind=0;
  if(i==3)Lease()->ProducerRetired=0;if(i==4)Lease()->ProducerRestored=0;
  Lease()->Crc32=N976nBatLeaseCrc(Lease());
  CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(M.Maps==1&&M.Unmaps==1&&Lease()->ClaimState==0);
 }
 Reset();CHECK(Add());Resources(&r,&t);Lease()->Crc32^=1;CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(M.Maps==1&&M.Unmaps==1);
 Reset();CHECK(Add());Resources(&r,&t);M.BackendInitFail=1;CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(M.Unmaps==28&&Lease()->ClaimState==0);
 Reset();CHECK(Add());Resources(&r,&t);M.MutateOnMap=2;M.BackendInitFail=1;CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(M.Unmaps==28&&Lease()->ClaimState==3);
 /* NctInit succeeds, then ADC preparation refuses an already prepared object. */
 Reset();CHECK(Add());Resources(&r,&t);Context()->Adc->Prepared=1;
 CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(!Context()->Thermal.Initialized&&!Context()->Adc->Prepared&&Lease()->ClaimState==0);
 CHECK(BatPrepare(M.Device,&r,&t)==0);CHECK(BatRelease(M.Device,NULL)==0);return 1;
}
static int LifecycleTests(void)
{
 ULONG tag,old;BATTERY_STATUS status;unsigned reads,writes;
 Reset();CHECK(Prepared());CHECK(BatClassInit(M.Device)==0);CHECK(N976nBatteryQueryTag(&Context()->Mini,&tag)==STATUS_NO_SUCH_DEVICE);
 CHECK(Start());RunWorker();CHECK(M.Acquires==1&&M.Releases==1&&!Context()->Backend.Bus.D0Active);
 CHECK(M.Starts==15&&M.Irqs==15&&M.Dpcs==15&&M.DpcRuns==15&&!M.PendingDpc&&M.AdcWaits==15&&Context()->Adc->Engine.LastSequence==15&&Context()->Adc->Engine.Record.Retired);
 CHECK(Context()->PowerDecision.State==N976N_POWER_UNKNOWN&&!Context()->PowerDecision.GatesPresent);
 CHECK(N976nBatteryQueryTag(&Context()->Mini,&tag)==0);old=tag;CHECK(N976nBatteryQueryStatus(&Context()->Mini,tag,&status)==0&&status.Capacity==640);
 Down();CHECK(M.ThreadWaits==1&&M.ThreadCloses==1&&!Context()->Thread&&!Context()->Cache.Running&&Context()->Adc->ReleaseReady);
 CHECK(N976nBatteryQueryTag(&Context()->Mini,&tag)==STATUS_NO_SUCH_DEVICE);
 CHECK(N976nBatteryQueryStatus(&Context()->Mini,old,&status)==STATUS_NO_SUCH_DEVICE);
 CHECK(BatD0Entry(M.Device,0)==STATUS_DEVICE_NOT_READY);
 reads=M.Reads;writes=M.Writes;BatClassCleanup(M.Device);CHECK(BatRelease(M.Device,NULL)==0);
 CHECK(M.Reads==reads&&M.Writes==writes&&M.Unmaps==28&&Lease()->ClaimState==N976N_BAT_CLAIM_CONSUMED);
 /* Delayed DPC cannot touch an unmapped controller or its prior owner. */
 M.Irql=2;if(M.PendingDpc){M.PendingDpc=0;M.DpcRuns++;M.IrqConfig.Dpc(M.Irq,NULL);}M.Irql=0;CHECK(M.Reads==reads&&M.Writes==writes);
 /* Re-enumeration with a new context must still reject this used NVS page. */
 Dispose();M.LocksMade=0;memset(M.Locks,0,sizeof(M.Locks));MOCK_CM r,t;CHECK(Add());Resources(&r,&t);
 CHECK(!NT_SUCCESS(BatPrepare(M.Device,&r,&t)));CHECK(Lease()->ClaimState==N976N_BAT_CLAIM_CONSUMED);
 /* ADC timeout does not take HSI cleanup ownership away. */
 Reset();CHECK(Prepared());CHECK(Start());M.AdcMode=1;RunWorker();
 CHECK(M.Releases==1&&Context()->QuarantinePending&&Context()->Adc->Engine.Quarantined&&!Context()->Backend.Bus.Quarantined);
 CHECK(Lease()->ClaimState==N976N_BAT_CLAIM_OWNED);Down();CHECK(Lease()->ClaimState==N976N_BAT_CLAIM_QUARANTINED);CHECK(BatRelease(M.Device,NULL)==0);
 /* Cancellation while an issued conversion finishes must retire and then stop. */
 Reset();CHECK(Prepared());CHECK(Start());M.AdcMode=2;RunWorker();
 CHECK(M.Releases==1&&Context()->Adc->Engine.Record.Retired&&!Context()->Adc->Engine.Quarantined&&!Context()->QuarantinePending);Down();CHECK(BatRelease(M.Device,NULL)==0);CHECK(Lease()->ClaimState==N976N_BAT_CLAIM_CONSUMED);
 /* Losing a claim blocks MMIO; a foreign state must not be overwritten. */
 Reset();CHECK(Prepared());CHECK(Start());Lease()->ClaimState=77;reads=M.Reads;writes=M.Writes;RunWorker();Down();
 CHECK(M.Reads==reads&&M.Writes==writes&&Lease()->ClaimState==77);CHECK(BatRelease(M.Device,NULL)==0);CHECK(Lease()->ClaimState==77);
 /* Stop before the scheduled producer starts: join runs the cancelled worker. */
 Reset();CHECK(Prepared());CHECK(Start());Down();CHECK(M.ThreadRuns==1&&M.Terminated==1&&!M.Acquires&&!M.Starts);CHECK(BatRelease(M.Device,NULL)==0);
 /* Creation failure after IRQ enable still masks, retires and consumes D0. */
 Reset();CHECK(Prepared());CHECK(BatD0Entry(M.Device,0)==0);CHECK(Enable()==0);M.ThreadFail=1;
 CHECK(BatPostIrq(M.Device,0)==STATUS_INSUFFICIENT_RESOURCES);Down();CHECK(BatRelease(M.Device,NULL)==0);CHECK(Lease()->ClaimState==N976N_BAT_CLAIM_CONSUMED);
 /* IRQ-disable live check detects drift after successful retirement. */
 for(unsigned drift=0;drift<3;drift++){
  Reset();CHECK(Prepared());CHECK(Start());RunWorker();CHECK(BatPreIrq(M.Device,0)==0);
  if(drift<2)*AdcReg(drift*4)^=8;else *(ULONG*)M.Memory[19]^=1;
  CHECK(Disable()==STATUS_DEVICE_HARDWARE_ERROR);CHECK(BatD0Exit(M.Device,0)==STATUS_DEVICE_HARDWARE_ERROR);CHECK(BatRelease(M.Device,NULL)==0);CHECK(Lease()->ClaimState==3);
 }
 /* Failed thread join is a non-returning failure, never fake completion. */
 Reset();CHECK(Prepared());CHECK(Start());M.JoinTimeout=M.TrapExpected=1;
 if(!setjmp(Trap)){BatPreIrq(M.Device,0);CHECK(0);}
 CHECK(M.BugPhase==1&&M.ThreadActive&&Context()->Adc->Enabled&&!M.Unmaps&&!M.ThreadCloses);
 M.JoinTimeout=M.TrapExpected=0;Down();CHECK(BatRelease(M.Device,NULL)==0);
 Reset();CHECK(Prepared());M.LockTimeout=M.TrapExpected=1;
 if(!setjmp(Trap)){BatRelease(M.Device,NULL);CHECK(0);}
 CHECK(M.BugPhase==3&&!M.Unmaps&&Context()->Claimed);M.LockTimeout=M.TrapExpected=0;CHECK(BatRelease(M.Device,NULL)==0);
 return 1;
}
static int IrpAndFenceTests(void)
{
 IRP irp;unsigned i,read;MOCK_REQUEST request={0};
 Reset();CHECK(Prepared());memset(&irp,0,sizeof(irp));CHECK(BatIoctl(M.Device,&irp)==STATUS_NOT_SUPPORTED&&irp.Forwarded==1&&!irp.Completed);CHECK(BatClassInit(M.Device)==0);
 M.ClassIoctlStatus=STATUS_SUCCESS;memset(&irp,0,sizeof(irp));CHECK(BatIoctl(M.Device,&irp)==0&&irp.Completed==1&&!irp.Forwarded);
 M.ClassIoctlStatus=STATUS_PENDING;memset(&irp,0,sizeof(irp));CHECK(BatIoctl(M.Device,&irp)==STATUS_PENDING&&!irp.Completed&&!irp.Forwarded);
 M.ClassIoctlStatus=STATUS_NOT_SUPPORTED;memset(&irp,0,sizeof(irp));CHECK(BatIoctl(M.Device,&irp)==STATUS_NOT_SUPPORTED&&irp.Forwarded==1&&!irp.Completed);
 for(i=0;i<4;i++){M.Disposition=(SYSCTL_IRP_DISPOSITION)i;M.ClassWmiStatus=STATUS_SUCCESS;memset(&irp,0,sizeof(irp));BatSystemControl(M.Device,&irp);CHECK(irp.Completed==(i<=1)&&irp.Forwarded==(i>=2));}
 M.Irql=2;memset(&irp,0,sizeof(irp));CHECK(BatIoctl(M.Device,&irp)==STATUS_INVALID_DEVICE_STATE&&irp.Completed==1&&!irp.Forwarded);memset(&irp,0,sizeof(irp));CHECK(BatSystemControl(M.Device,&irp)==STATUS_INVALID_DEVICE_STATE&&irp.Completed==1&&!irp.Forwarded);M.Irql=0;
 BatUnsupported(NULL,&request,0,0,0);CHECK(request.Completed==1&&request.Status==STATUS_NOT_SUPPORTED);
 for(i=0;i<N976N_BAT_FIXED_RESOURCES;i++){N976N_BAT_U64 a=N976nBatResources[i].Address;CHECK(Register(Context(),a,FALSE)!=NULL);CHECK(Register(Context(),a+N976nBatResources[i].Bytes-4,FALSE)!=NULL);}
 CHECK(Register(Context(),0x15C02010,FALSE)!=NULL&&Register(Context(),0x15C0206C,FALSE)!=NULL&&Register(Context(),0x15C0205C,FALSE)!=NULL&&Register(Context(),0x15C02088,FALSE)!=NULL&&Register(Context(),0x15C0208C,FALSE)!=NULL);
 read=M.Reads;Write(Context(),N976N_CLOCK_SHARE_BASE,1);CHECK(!M.Writes&&Context()->AccessRefused&&M.Reads==read);Context()->AccessRefused=0;
 Write(Context(),0x15C30184,1);CHECK(!M.Writes&&Context()->AccessRefused);Context()->AccessRefused=0;CHECK(Register(Context(),0x15D60001,FALSE)==NULL&&Context()->AccessRefused);Context()->AccessRefused=0;
 Write(Context(),0x15D60004,0x1234);CHECK(M.Writes==1&&Read(Context(),0x15D60004)==0x1234);
 BatClassCleanup(M.Device);CHECK(BatRelease(M.Device,NULL)==0);return 1;
}
static int ManagedTests(void){
 Reset();CHECK(Prepared());M.ControlModel=1;M.CycleLimit=6;
 static const unsigned char regs[11]={0xB2,0xB3,0xB4,0xB7,0xB8,0xB9,0xBA,0xBB,0xBD,0xC0,0xC3};
 static const unsigned char raw[11]={0xDF,0xE0,0x31,0x15,0x38,0x52,0x99,0x13,0x0C,0x0f,0x68};
 for(unsigned i=0;i<11;i++)M.Pmic[regs[i]]=raw[i];
 CHECK(Start());RunWorker();
 if(!M.Enables)fprintf(stderr,"control preflight=%u state=%u reason=%u evidence=%x source=%u temp=%d/%d/%d\n",Context()->ControlPreflight,Context()->Control.State,Context()->Control.Reason,Context()->ControlFacts.Evidence,Context()->Source.Valid,Context()->ControlFacts.PackDeciC,Context()->ControlFacts.ChargerDeciC,Context()->ControlFacts.UsbDeciC);
 CHECK(M.Enables==1&&M.Stops==2&&M.MaxManaged>=2);
 CHECK(Context()->Control.State==NCC_MODE4_CONFIRMED&&!Context()->Control.Uncertain);
 CHECK((M.Pmic[0xB9]&63)==12&&M.Releases==1&&M.Pmic[0xC0]==3);
 CHECK(Context()->ControlAttempt==3&&Context()->Control.Kicks>=2);
 CHECK(Context()->Control.InputBefore==15&&Context()->Control.InputAfter==35&&Context()->Control.InputWrites==2&&Context()->Control.InputFallbackConfirmed&&!Context()->Control.InputTouched);
 Down();CHECK(BatRelease(M.Device,NULL)==0&&Lease()->ClaimState==N976N_BAT_CLAIM_CONSUMED);
 return 1;
}
static int UnknownStopTest(void){
 Reset();CHECK(Prepared());M.ControlModel=M.StopReadFail=1;M.CycleLimit=6;
 static const unsigned char regs[11]={0xB2,0xB3,0xB4,0xB7,0xB8,0xB9,0xBA,0xBB,0xBD,0xC0,0xC3};
 static const unsigned char raw[11]={0xDF,0xE0,0x31,0x15,0x38,0x52,0x99,0x13,0x0C,0x0f,0x68};
 for(unsigned i=0;i<11;i++)M.Pmic[regs[i]]=raw[i];
 CHECK(Start());RunWorker();CHECK(Context()->Control.Uncertain&&Context()->Backend.Bus.Quarantined);
 CHECK(M.ReadsAtFailure&&M.ReadsAtFailure==M.ChargeReads&&!M.Payloads&&M.BackendCalls==M.BackendAtFailure);
 Down();CHECK(BatRelease(M.Device,NULL)==0&&Lease()->ClaimState==N976N_BAT_CLAIM_QUARANTINED);return 1;
}
static int SourceTests(void){
 N976N_SOURCE_STATE s;N976N_POWER_RAW r={0};NCC_FACTS f={0};
 unsigned char raw[19]={0xDF,0xE0,0x31,0x15,0x38,0x52,0x99,0x13,0x0C,0x23,0x68,0x27,0x81,0xA1,8,0x19,0x47,4,0x73};
 r.ValidMask=N976N_PWR_ALL;r.Sequence=1;memcpy(r.Byte,raw,19);N976nSourceInit(&s,1);
 CHECK(!N976nSourceFinish(&s,&r,10000));
 CHECK(N976nSourceBegin(&s,&r,10000));CHECK(!N976nSourceBegin(&s,&r,10000)&&!s.Valid);
 CHECK(N976nSourceBegin(&s,&r,10000));CHECK(!N976nSourceFinish(&s,&r,10010001));
 CHECK(N976nSourceBegin(&s,&r,11000000));CHECK(N976nSourceFinish(&s,&r,11000100)&&s.Online);
 f.Now=1100;f.OwnerGeneration=1;CHECK(N976nBenchFacts(&s,&r,11000200,&f));CHECK(f.SourceMv==5500&&f.SourceMa==1500&&f.InputLimitEnforced&&f.QualifiedWatchdogMs==0);
 CHECK(!N976nBenchFacts(&s,&r,21000000,&f));
 r.Byte[16]|=0x10;CHECK(!N976nSourceMatches(&s,&r));
 CHECK(N976nSourceBegin(&s,&r,22000000));CHECK(N976nSourceFinish(&s,&r,22000100));memset(&f,0,sizeof(f));
 CHECK(N976nBenchFacts(&s,&r,22000200,&f)&&!(f.Evidence&NCC_SOURCE_CURRENT));
 CHECK(!N976nSourceBegin(&s,&r,21999999));
 N976nSourceInit(&s,1);s.Epoch=UINT64_MAX;CHECK(!N976nSourceBegin(&s,&r,1)&&s.Exhausted);
 return 1;
}
static void ChargeFixture(void){
 static const unsigned char regs[11]={0xB2,0xB3,0xB4,0xB7,0xB8,0xB9,0xBA,0xBB,0xBD,0xC0,0xC3};
 static const unsigned char raw[11]={0xDF,0xE0,0x31,0x15,0x38,0x52,0x99,0x13,0x0C,0x0f,0x68};
 M.ControlModel=1;for(unsigned i=0;i<11;i++)M.Pmic[regs[i]]=raw[i];
}
static int PreparedInputAbortTests(void){
 for(unsigned failed=0;failed<2;failed++){
  Reset();CHECK(Prepared());ChargeFixture();M.CycleLimit=failed?6:3;M.AfterInputFailure=failed;
  CHECK(Start());RunWorker();
  CHECK(!M.Enables&&M.Pmic[0xC0]==3&&Context()->Control.InputFallbackConfirmed&&!Context()->Control.InputTouched&&!Context()->Control.InputConfigured);
  CHECK(Context()->Control.Mode4Confirmed&&!Context()->Control.Uncertain&&M.Releases==1);
  Down();CHECK(BatRelease(M.Device,NULL)==0);
 }
 return 1;
}
static int SnapshotSourceLossTest(void){
 for(unsigned mismatch=0;mismatch<2;mismatch++){
  NCC_FACTS f;NCC_TICKET t={0};N976N_POWER_RAW raw;
  Reset();CHECK(Prepared());ChargeFixture();M.Time=10000000;
  CHECK(BatD0Entry(M.Device,0)==0&&Enable()==0);
  BAT_DEVICE*c=Context();CHECK(N976nBatBusAcquireD0(&c->Backend.Bus)==0);
  c->Backend.Bus.KeepControlOwner=1;c->Samples=1;
  CHECK(N976nBatBusReadChargeActive(&c->Backend.Bus,1,&raw)==0);
  CHECK(N976nSourceBegin(&c->Source,&raw,M.Time));CHECK(N976nSourceFinish(&c->Source,&raw,M.Time+100));M.Time+=200;
  t.OwnerGeneration=c->Generation;t.SourceEpoch=c->Source.Epoch;t.CheckedAt=M.Time/10000;t.NotAfter=t.CheckedAt+1000;
  CHECK(ControlGuard(c,&t));
  c->Backend.Bus.ControlPayload=c->Backend.Bus.S.InTransaction=1;c->Backend.Bus.Report.Retired=0;c->Backend.Bus.ControlTicket=&t;
  c->StopRequested=1;t.NotAfter=t.CheckedAt;CHECK(ControlGuard(c,&t));
  t.OwnerGeneration++;CHECK(!ControlGuard(c,&t));t.OwnerGeneration--;
  c->Backend.Bus.ControlPayload=c->Backend.Bus.S.InTransaction=0;c->Backend.Bus.Report.Retired=1;c->Backend.Bus.ControlTicket=NULL;
  CHECK(!ControlGuard(c,&t));c->StopRequested=0;t.NotAfter=t.CheckedAt+1000;
  if(mismatch)M.Pmic[0xC0]++;else M.ChargeFail=1;
  CHECK(ControlSnapshot(c,&f)==1&&!c->Source.Valid);
  CHECK(c->Backend.Bus.D0Active&&c->Backend.Bus.Report.Retired&&!c->Backend.Bus.Quarantined);
  M.ChargeFail=0;M.Pmic[0xC0]=0x23;
  CHECK(ControlSnapshot(c,&f)==1&&!c->Source.Valid&&!f.SourceEpoch&&!f.Evidence&&!ControlGuard(c,&t));
  CHECK(N976nSourceBegin(&c->Source,&raw,M.Time));CHECK(N976nSourceFinish(&c->Source,&raw,M.Time+100));M.Time+=200;
  CHECK(c->Source.Epoch>t.SourceEpoch&&!ControlGuard(c,&t));
  CHECK(N976nBatBusReleaseD0(&c->Backend.Bus)==0);Down();CHECK(BatRelease(M.Device,NULL)==0);
 }
 return 1;
}
static int AdcIdentityFailureStopsManagedTest(void){
 Reset();CHECK(Prepared());ChargeFixture();M.CycleLimit=6;M.IdentityFail=1;
 CHECK(Start());RunWorker();BAT_DEVICE*c=Context();
 CHECK(M.IdentityInjected==1&&M.Enables==1&&M.Stops==2);
 CHECK(c->Control.State==NCC_MODE4_CONFIRMED&&!c->Control.Uncertain);
 CHECK(c->Thermal.Quarantined&&c->QuarantinePending&&c->StopRequested);
 CHECK(!c->Backend.Bus.Quarantined&&M.Releases==1&&!c->Backend.Bus.D0Active);
 CHECK(M.Payloads==M.PayloadsAtIdentity+2&&c->Control.Kicks==M.KicksAtIdentity);
 Down();CHECK(BatRelease(M.Device,NULL)==0&&Lease()->ClaimState==N976N_BAT_CLAIM_QUARANTINED);return 1;
}

/* Full-register snapshots were previously free in this adapter mock. Give
 * every 19-byte read a bounded transport cost; never renew source/ADC ages. */
static int SnapshotLatencyTests(void){
 for(unsigned delay=60;delay<=90;delay+=30){
  Reset();CHECK(Prepared());ChargeFixture();M.ChargeReadDelayMs=delay;M.CycleLimit=8;
  CHECK(Start());RunWorker();BAT_DEVICE*c=Context();
  CHECK(c->DiagStartCalls==1&&c->SnapshotMaxMs>=delay&&c->SnapshotTotalMs>=c->SnapshotCalls*delay);
  CHECK(c->Control.Mode4Confirmed&&c->Control.InputFallbackConfirmed&&!c->Control.InputTouched&&!c->Control.Uncertain);
  CHECK(M.Pmic[0xC0]==3&&(M.Pmic[0xB7]&15)==4&&M.Releases==1);
  if(delay==60){CHECK(c->DiagManagedStarts==1&&M.Enables==1&&c->StartSnapshotCalls==9&&c->StartElapsedMs>=540&&c->StartElapsedMs<1000);}
  else{
   CHECK(!c->DiagManagedStarts&&!M.Enables&&c->Control.FirstReason==NCC_STALE);
   CHECK(c->Control.First.Reason==NCC_STALE&&c->Control.First.Facts.SnapshotIssue==5);
   CHECK(c->Control.First.Now>=c->Control.First.Facts.SourceAt+1000);
   NCC_FAILURE first=c->Control.First;NccStop(&c->Control);
   CHECK(!memcmp(&first,&c->Control.First,sizeof(first)));
   CHECK(c->Diag.FirstControlReason==NCC_STALE&&c->Diag.FirstSnapshotIssue==5&&c->Diag.FirstSourceMs==first.Facts.SourceAt);
  }
  Down();CHECK(BatRelease(M.Device,NULL)==0);
 }
 return 1;
}

static int ConnectionTests(void){
 NCL_CONNECTION c={0};
 CHECK(NclObserve(&c,100,90,95,1,1,1)&&c.Id==1);
 CHECK(!NclObserve(&c,200,190,195,1,1,1)&&c.Id==1);
 CHECK(!NclObserve(&c,300,290,295,1,1,0)&&c.OfflineSamples==1);
 CHECK(!NclObserve(&c,1400,290,295,1,1,0)&&!c.OfflineSamples&&c.Attached); /* stale/duplicate */
 CHECK(!NclObserve(&c,1500,1490,1495,1,1,0));
 CHECK(!NclObserve(&c,1600,1590,1595,0,0,0)&&!c.OfflineSamples);
 CHECK(!NclObserve(&c,1700,1690,1695,1,1,0));
 CHECK(!NclObserve(&c,2600,2590,2595,1,1,0)&&c.Attached);
 CHECK(!NclObserve(&c,2700,2690,2695,1,1,0)&&!c.Attached&&c.Detaches==1);
 CHECK(NclObserve(&c,2800,2790,2795,1,1,1)&&c.Id==2&&!c.Detached);
 CHECK(!NclObserve(&c,2700,2690,2695,1,1,0)&&c.Fault);
 CHECK(!NclObserve(&c,2900,2890,2895,1,1,1)&&c.Fault&&c.Id==2);
 memset(&c,0,sizeof(c));c.Id=UINT64_MAX;
 CHECK(!NclObserve(&c,100,90,95,1,1,1)&&c.Fault);
 memset(&c,0,sizeof(c));c.Attached=1;c.Detaches=UINT64_MAX;
 CHECK(!NclObserve(&c,100,90,95,1,1,0));
 CHECK(!NclObserve(&c,1200,1190,1195,1,1,0)&&c.Fault);
 return 1;
}
static int ContinuousLifecycleTests(void){
 for(unsigned scenario=1;scenario<=4;scenario++){
  Reset();CHECK(Prepared());ChargeFixture();M.Scenario=scenario;M.CycleLimit=24;
  CHECK(Start());RunWorker();BAT_DEVICE*c=Context();
  CHECK(c->Control.Mode4Confirmed&&!c->Control.Uncertain&&!c->Backend.Bus.Quarantined);
  CHECK(!c->Control.InputTouched&&!c->Control.InputConfigured&&c->Control.InputFallbackConfirmed&&M.Pmic[0xC0]==3);
  if(scenario==1){CHECK(c->Connection.Id==2&&c->Connection.Detaches==1&&M.Enables==2&&c->DiagManagedStarts==2);}
  else{CHECK(c->Connection.Id==1&&!c->Connection.Detaches&&M.Enables==1&&c->DiagManagedStarts==1);
   CHECK(c->HoldReason==(scenario==3?NCC_STALE:NCC_FULL));}
  Down();CHECK(BatRelease(M.Device,NULL)==0);
 }
 return 1;
}

static NTSTATUS DiagIo(NCD_REPORT *r,unsigned in,unsigned out){
 IRP irp={0};irp.Stack.Parameters.DeviceIoControl.IoControlCode=NCD_IOCTL;
 irp.Stack.Parameters.DeviceIoControl.InputBufferLength=in;irp.Stack.Parameters.DeviceIoControl.OutputBufferLength=out;
 irp.AssociatedIrp.SystemBuffer=r;NTSTATUS status=BatIoctl(M.Device,&irp);
 assert(irp.Completed==1&&!irp.Forwarded&&irp.IoStatus.Status==status);
 assert(irp.IoStatus.Information==(status==STATUS_SUCCESS?sizeof(*r):0));return status;
}
static int DiagTests(void){
 struct{NCD_REPORT r;unsigned char tail[16];}buf;unsigned reads,writes,charger,adc,backend,payload;
 Reset();CHECK(Prepared());memset(&buf,0xA5,sizeof(buf));
 CHECK(DiagIo(&buf.r,0,sizeof(buf))==STATUS_SUCCESS);
 CHECK(buf.r.Magic==NCD_MAGIC&&buf.r.Driver==606&&buf.r.Bytes==sizeof(buf.r)&&!buf.r.Sequence&&!buf.r.WorkerLive&&!buf.r.PowerValidMask);
 for(unsigned i=0;i<sizeof(buf.tail);i++)CHECK(buf.tail[i]==0xA5);
 CHECK(DiagIo(&buf.r,1,sizeof(buf.r))==STATUS_INVALID_PARAMETER);
 CHECK(DiagIo(&buf.r,0,sizeof(buf.r)-1)==STATUS_BUFFER_TOO_SMALL);
 CHECK(DiagIo(NULL,0,sizeof(buf.r))==STATUS_INVALID_PARAMETER);
 M.Irql=2;CHECK(DiagIo(&buf.r,0,sizeof(buf.r))==STATUS_INVALID_DEVICE_STATE);M.Irql=0;
 CHECK(BatClassInit(M.Device)==0&&M.ClassInfo.QueryStatus==DiagQueryStatus);
 BATTERY_STATUS bs;CHECK(M.ClassInfo.QueryStatus(M.ClassInfo.Context,42,&bs)==STATUS_NO_SUCH_DEVICE);
 CHECK(Context()->DiagQuery.Count==1&&Context()->DiagQuery.Status==(ULONG)STATUS_NO_SUCH_DEVICE&&Context()->DiagQuery.Tag==42);
 ChargeFixture();M.CycleLimit=270;CHECK(Start());RunWorker();
 CHECK(Context()->Control.State==NCC_MODE4_CONFIRMED&&Context()->Control.Reason==NCC_OK);
 CHECK(Context()->Diag.ManagedStarts==1&&Context()->Diag.StartCalls==1&&Context()->Diag.StoppedMs>=Context()->Diag.StartedMs+60000);
 CHECK(Context()->Diag.Mode4Confirmed&&!Context()->Diag.Uncertain&&Context()->Diag.PowerValidMask==N976N_PWR_ALL);
 CHECK(Context()->Diag.PowerDecoded&&Context()->Diag.Mode==5&&(M.Pmic[0xB7]&15)==4&&Context()->Diag.Point==3&&!Context()->Diag.WorkerLive);
 CHECK(Context()->Diag.LastQuery.Count==0); /* callback overlay is separate */
 reads=M.Reads;writes=M.Writes;charger=M.ChargeReads;adc=M.Starts;backend=M.BackendCalls;payload=M.Payloads;
 M.Time+=200000000;
 CHECK(DiagIo(&buf.r,0,sizeof(buf.r))==0&&buf.r.Query100ns>buf.r.Published100ns+150000000);
 CHECK(buf.r.LastQuery.Count>1&&buf.r.LastQuery.Status==0&&buf.r.ManagedStarts==1);
 CHECK(M.Reads==reads&&M.Writes==writes&&M.ChargeReads==charger&&M.Starts==adc&&M.BackendCalls==backend&&M.Payloads==payload);
 /* Cancellation is sticky; no restart even with a later source observation. */
 ControlCycle(Context());CHECK(Context()->DiagStartCalls==1&&M.Payloads==payload);
 Down();BatClassCleanup(M.Device);CHECK(BatRelease(M.Device,NULL)==0);
 /* Inherited MODE5 is visible without implying a managed start. */
 Reset();CHECK(Prepared());ChargeFixture();Context()->Samples=1;
 CHECK(N976nBatBusAcquireD0(&Context()->Backend.Bus)==0);
 CHECK(ObserveCharge(Context(),&Context()->PowerRaw)==0);
 BatStateLock(Context());PublishDiagLocked(Context(),2,1);BatStateUnlock(Context());
 CHECK(DiagIo(&buf.r,0,sizeof(buf.r))==0&&buf.r.Mode==5&&!buf.r.ManagedStarts&&!buf.r.StartCalls);
 ULONGLONG old=buf.r.PowerAt100ns;M.ChargeFail=1;N976N_POWER_RAW raw;Context()->Backend.Bus.KeepControlOwner=1;
 CHECK(ObserveCharge(Context(),&raw)!=0);BatStateLock(Context());PublishDiagLocked(Context(),2,1);BatStateUnlock(Context());
 CHECK(DiagIo(&buf.r,0,sizeof(buf.r))==0&&buf.r.PowerReadStatus!=0&&buf.r.PowerAt100ns==old);
 memset(Context()->DiagPower.Byte,255,sizeof(Context()->DiagPower.Byte));Context()->DiagPower.ValidMask=N976N_PWR_ALL;
 BatStateLock(Context());PublishDiagLocked(Context(),2,1);BatStateUnlock(Context());
 CHECK(DiagIo(&buf.r,0,sizeof(buf.r))==0&&!buf.r.PowerDecoded&&buf.r.PowerValidMask==N976N_PWR_ALL&&buf.r.PowerRaw[0]==255);
 CHECK(N976nBatBusReleaseD0(&Context()->Backend.Bus)==0);CHECK(BatRelease(M.Device,NULL)==0);return 1;
}

static int CleanFailureWorkerTest(void){
 Reset();CHECK(Prepared());CHECK(BatClassInit(M.Device)==0);ChargeFixture();M.GaugeFailureCycle=2;M.CycleLimit=3;
 CHECK(Start());RunWorker();CHECK(M.SeenTags[0]&&M.SeenTags[0]==M.SeenTags[1]&&M.SeenTags[1]==M.SeenTags[2]);
 CHECK(Context()->Failures==1&&!Context()->QuarantinePending);
 Down();BatClassCleanup(M.Device);CHECK(BatRelease(M.Device,NULL)==0);return 1;
}
static int FailedGaugeUnsafeWorkerTests(void){
 for(unsigned f=1;f<=3;f++){
  Reset();CHECK(Prepared());CHECK(BatClassInit(M.Device)==0);ChargeFixture();M.GaugeFailureCycle=2;M.CycleLimit=3;M.AfterGaugeFault=f;
  CHECK(Start());RunWorker();CHECK(M.SeenTags[0]&&M.SeenTags[1]==0&&!Context()->Cache.HaveSample);
  Down();BatClassCleanup(M.Device);CHECK(BatRelease(M.Device,NULL)==0);
 }return 1;
}
static int CleanFailureCacheTests(void){
 Reset();CHECK(Prepared());CHECK(BatD0Entry(M.Device,0)==0&&Enable()==0);
 BAT_DEVICE*c=Context();CHECK(N976nBatBusAcquireD0(&c->Backend.Bus)==0);
 N976N_BATTERY_RAW raw;N976N_BATTERY_CACHE_VIEW view;
 N976nBatteryBegin(&raw,1);RawField(&raw,N976N_BAT_STATUS,0);RawField(&raw,N976N_BAT_SOCREP,0x4000);
 M.Time=10000000;CHECK(N976nBatteryCachePublish(&c->Cache,&raw,2,c->Generation,M.Time,M.Time,M.Time)==N976N_BAT_CACHE_OK);
 ULONG tag=c->Cache.View.Tag;ULONGLONG stamp=c->Cache.View.SampleStart100ns;
 c->Last.Publishable=0;c->Last.CleanReadFailure=1;c->Last.Status=N976N_BAT_BUS_TIMEOUT;
 CHECK(KeepFailedGaugeLocked(c,M.Time+10,M.Time+20,M.Time+30));
 CHECK(c->Cache.View.Tag==tag&&c->Cache.View.SampleStart100ns==stamp&&c->Cache.LastAcceptedSampleId==1);
 /* Source flags keep their separate 2s lifetime, never refreshed by failure. */
 CHECK(N976nBatteryCachePower(&c->Cache,c->Generation,M.Time+30,M.Time+30,1,1,1));
 CHECK(KeepFailedGaugeLocked(c,M.Time+30000000,M.Time+30000010,M.Time+30000020));
 CHECK(N976nBatteryCacheRead(&c->Cache,M.Time+30000021,&view)&&!view.OnlineKnown&&!view.ChargingObserved);
 for(unsigned f=0;f<8;f++){
  c->Last.CleanReadFailure=f!=0;c->Last.Publishable=f==1;c->StopRequested=f==2;
  c->AccessRefused=f==3;c->QuarantinePending=f==4;c->Backend.Bus.Quarantined=f==5;
  c->Control.Uncertain=f==6;c->Last.Status=f==7?0:N976N_BAT_BUS_TIMEOUT;
  CHECK(!KeepFailedGaugeLocked(c,M.Time+40000000,M.Time+40000010,M.Time+40000020));
 }
 c->Last.CleanReadFailure=1;c->Last.Publishable=c->StopRequested=c->AccessRefused=c->QuarantinePending=c->Backend.Bus.Quarantined=c->Control.Uncertain=0;c->Last.Status=N976N_BAT_BUS_TIMEOUT;
 CHECK(!KeepFailedGaugeLocked(c,M.Time+2,M.Time+1,M.Time+3));
 CHECK(!KeepFailedGaugeLocked(c,M.Time,M.Time,M.Time));CHECK(!c->Cache.HaveSample); /* backwards clock */
 M.Time+=50000000;N976nBatteryBegin(&raw,2);RawField(&raw,N976N_BAT_STATUS,0);
 CHECK(N976nBatteryCachePublish(&c->Cache,&raw,2,c->Generation,M.Time,M.Time,M.Time)==N976N_BAT_CACHE_OK);
 CHECK(!KeepFailedGaugeLocked(c,M.Time+c->Cache.Ttl100ns,M.Time+c->Cache.Ttl100ns,M.Time+c->Cache.Ttl100ns));CHECK(!c->Cache.HaveSample);
 CHECK(N976nBatBusReleaseD0(&c->Backend.Bus)==0);Down();CHECK(BatRelease(M.Device,NULL)==0);return 1;
}
static int QuarantineDiagnosticTests(void){
 Reset();CHECK(Prepared());BAT_DEVICE*c=Context();
 c->Backend.Bus.FirstFailure.SampleId=1450;c->Backend.Bus.FirstFailure.Reason=0xB116;
 c->Backend.Bus.Report.SampleId=1455;c->Backend.Bus.Report.Reason=0xB116;
 c->Backend.Bus.Report.Received=1;c->Backend.Bus.Report.Requested=2;c->Backend.Bus.Report.FirstWaitUs=381810;
 Quarantine(c,NCD_Q_BUS_OR_ACCESS);ULONGLONG first=c->QuarantineAt100ns;
 c->Backend.Bus.Report.SampleId=1500;Quarantine(c,NCD_Q_BUS_RELEASE);
 BatStateLock(c);PublishDiagLocked(c,3,0);BatStateUnlock(c);
 NCD_REPORT r;unsigned reads=M.Reads,writes=M.Writes;CHECK(DiagIo(&r,0,sizeof(r))==0);
 CHECK(sizeof(NCD_REPORT)==848&&offsetof(NCD_REPORT,LastQuery)==360);
 CHECK(r.QuarantineSite==NCD_Q_BUS_OR_ACCESS&&r.QuarantineAt100ns==first&&r.QuarantineBus.SampleId==1455&&r.FirstBus.SampleId==1450);
 CHECK(r.QuarantineBus.Received==1&&r.QuarantineBus.Requested==2&&r.QuarantineBus.FirstWaitUs==381810);
 CHECK(reads==M.Reads&&writes==M.Writes);CHECK(BatRelease(M.Device,NULL)==0);return 1;
}
int main(void){int ok=FailedGaugeUnsafeWorkerTests()&&CleanFailureWorkerTest()&&CleanFailureCacheTests()&&QuarantineDiagnosticTests()&&ResourceTests()&&LifecycleTests()&&IrpAndFenceTests()&&ManagedTests()&&SourceTests()&&PreparedInputAbortTests()&&UnknownStopTest()&&SnapshotSourceLossTest()&&AdcIdentityFailureStopsManagedTest()&&ConnectionTests()&&ContinuousLifecycleTests()&&DiagTests()&&SnapshotLatencyTests();Dispose();if(!ok)return 1;printf("PASS %u checks: actual Device+AdcWdf lifecycle, IRQ conversions and class/mapping fences\n",Cases);return 0;}
