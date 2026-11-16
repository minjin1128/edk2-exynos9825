/* Actual AdcWdf.c and NCA core, deterministic callback interleavings.
 * Not a Windows scheduler/physical IRQ proof. */
#include <stdio.h>
#include "../AdcWdf.c"
static unsigned Checks,Irql,Locked,Waits,Dpcs,Writes,Mode,CancelAtBegin;static uint64_t Time;
static NCA_WDF *C;static uint32_t Reg[6],Clocks[9];static int Owner;
#define CHECK(X) do{Checks++;if(!(X)){fprintf(stderr,"FAIL line %d: %s\n",__LINE__,#X);exit(1);}}while(0)
LONG InterlockedCompareExchange(volatile LONG*p,LONG n,LONG old){LONG v=*p;if(v==old)*p=n;return v;}
LONG InterlockedExchange(volatile LONG*p,LONG n){LONG v=*p;*p=n;return v;}
unsigned KeGetCurrentIrql(void){return Irql;}
void KeInitializeEvent(KEVENT*e,int type,int set){(void)type;e->Set=set;}
void KeClearEvent(KEVENT*e){e->Set=0;}
LONG KeSetEvent(KEVENT*e,int priority,int wait){(void)priority;(void)wait;CHECK(Irql<=2);e->Set=1;return 0;}
NTSTATUS WdfInterruptCreate(WDFDEVICE d,WDF_INTERRUPT_CONFIG *cfg,WDF_OBJECT_ATTRIBUTES *attr,WDFINTERRUPT *out){(void)d;CHECK(!cfg->PassiveHandling&&!cfg->AutomaticSerialization&&cfg->ShareVector==WdfFalse);CHECK(cfg->Isr&&cfg->Dpc&&cfg->EvtInterruptEnable&&cfg->EvtInterruptDisable);*out=calloc(1,attr->ContextSize);CHECK(*out!=NULL);return STATUS_SUCCESS;}
BOOLEAN WdfInterruptQueueDpcForIsr(WDFINTERRUPT irq){CHECK(irq==C&&Irql==7&&Locked);Dpcs++;return TRUE;}
BOOLEAN WdfInterruptSynchronize(WDFINTERRUPT irq,EVT_WDF_INTERRUPT_SYNCHRONIZE *fn,WDFCONTEXT context){BOOLEAN r;CHECK(!Locked&&Irql==0);Irql=7;Locked=1;if(CancelAtBegin&&((SYNC_REQUEST*)context)->Action==SYNC_BEGIN){CancelAtBegin=0;NcaWdfRequestStop(C);}r=fn(irq,context);Locked=0;Irql=0;return r;}
static void Interrupt(void){CHECK(!Locked);Reg[2]=0x80000715;Time+=1040;Locked=1;Irql=7;CHECK(NcaWdfIsr(C,0));Irql=0;Locked=0;}
static void Dpc(void){Irql=2;NcaWdfDpc(C,NULL);Irql=0;}
NTSTATUS KeWaitForSingleObject(KEVENT*event,int why,int mode,int alert,LARGE_INTEGER*delay){(void)why;(void)mode;(void)alert;CHECK(Irql==0&&!Locked&&event==&C->Completion);CHECK(delay->QuadPart<0&&delay->QuadPart>=-1000000);Waits++;
 if(Mode==1){Time+=(uint64_t)(-delay->QuadPart);return STATUS_TIMEOUT;}
 if(Mode==2)return STATUS_TIMEOUT; /* observed OS expiry despite frozen sample clock */
 if(Mode==3){Interrupt();return STATUS_TIMEOUT;} /* durable IRQ beat delayed DPC */
 if(Mode==4){NcaWdfRequestStop(C);Interrupt();Dpc();return STATUS_SUCCESS;}
 if(Mode==5){Time+=1;return STATUS_SUCCESS;} /* stale/spurious notification */
 if(Mode==6)return STATUS_INVALID_DEVICE_STATE;
 Interrupt();Dpc();return STATUS_SUCCESS;
}
static uint32_t Read(void*p,uint64_t a){(void)p;CHECK(Locked&&Irql==7);if(a>=NCA_BASE&&a<=NCA_BASE+0x14)return Reg[(a-NCA_BASE)/4];for(unsigned i=0;i<9;i++)if(a==NcaClockAddresses[i])return Clocks[i];CHECK(0);return UINT32_MAX;}
static void Write(void*p,uint64_t a,uint32_t v){(void)p;CHECK(Locked&&Irql==7);CHECK(a==NCA_BASE||a==NCA_BASE+4||a==NCA_BASE+0x10||a==NCA_BASE+0x14);Reg[(a-NCA_BASE)/4]=v;Writes++;}
static void Fence(void*p){(void)p;CHECK(Locked);}
static uint64_t Now(void*p){(void)p;return Time;}
static int Owned(void*p){(void)p;CHECK(Locked);return Owner;}
static NCA_OPS Ops={Read,Write,Fence,Now,Owned};
static NCA_BINDING Binding;
static CM_PARTIAL_RESOURCE_DESCRIPTOR Raw,Translated;
static void Setup(void){C=NULL;Irql=Locked=Waits=Dpcs=Writes=Mode=CancelAtBegin=0;Time=10000000;Owner=1;memset(Reg,0,sizeof(Reg));memset(Clocks,0,sizeof(Clocks));Reg[0]=2;Reg[1]=0x24;Clocks[4]=Clocks[5]=1U<<21;Clocks[7]=Clocks[8]=2;memset(&Binding,0,sizeof(Binding));Binding.Original[0]=2;Binding.Original[1]=0x24;memcpy(Binding.Clocks,Clocks,sizeof(Clocks));Binding.Generation=7;Binding.FirmwareRetired=Binding.FirmwareRestored=Binding.FirmwareIrqDetached=1;
 memset(&Raw,0,sizeof(Raw));Raw.Type=CmResourceTypeInterrupt;Raw.ShareDisposition=CmResourceShareDeviceExclusive;Raw.u.Interrupt.Vector=116;Translated=Raw;Translated.u.Interrupt.Vector=0x150;
 CHECK(NcaWdfCreate(NULL,&C)==STATUS_SUCCESS);CHECK(NcaWdfPrepare(C,&Ops,NULL,&Binding,&Raw,&Translated)==STATUS_SUCCESS);
 Locked=1;Irql=7;CHECK(NcaWdfEnable(C,NULL)==STATUS_SUCCESS);Irql=Locked=0;
}
static NCT_TICKET Ticket(void){NCT_TICKET t={1,C->Engine.LastSequence+1,7,0,Time,Time+1000000,4};return t;}
static void Finish(void){NcaWdfRequestStop(C);CHECK(!C->Active);Locked=1;Irql=7;NTSTATUS disabled=NcaWdfDisable(C,NULL);Irql=Locked=0;NTSTATUS released=NcaWdfRelease(C);if(C->Engine.Quarantined){CHECK(disabled==STATUS_DEVICE_HARDWARE_ERROR&&released==STATUS_DEVICE_HARDWARE_ERROR&&!C->ReleaseReady);}else CHECK(disabled==STATUS_SUCCESS&&released==STATUS_SUCCESS&&C->ReleaseReady);unsigned writes=Writes;Dpc();CHECK(Writes==writes);free(C);C=NULL;}
int main(void){NCT_COMPLETION_RECORD r;NCT_IDENTITY i;NCT_TICKET t;
 Setup();CHECK(NcaWdfIdentity(C,&i)&&i.Ready&&i.Retired&&i.AdcGeneration==7&&!i.SourceEpoch);t=Ticket();CHECK(NcaWdfConvert(C,&t,&r));CHECK(r.Retired&&r.Irq&&r.Ack&&!r.Quarantined&&r.Raw==0x80000715&&Waits==1);t=Ticket();CHECK(NcaWdfConvert(C,&t,&r));CHECK(Waits==2);CHECK(NcaWdfRelease(C)==STATUS_INVALID_DEVICE_STATE);Finish();
 for(unsigned mode=1;mode<=6;mode++){Setup();Mode=mode;t=Ticket();int ok=NcaWdfConvert(C,&t,&r);CHECK(!C->Active);if(mode==3)CHECK(ok&&r.Retired&&!r.Quarantined);else if(mode==4)CHECK(!ok&&r.Cancelled&&r.Retired&&!r.Quarantined);else CHECK(!ok&&!r.Retired&&r.Quarantined);if(mode==2)CHECK(C->Engine.Reason==NCA_WAIT_TIMEOUT);if(mode==5)CHECK(Waits==33);if(mode==6)CHECK(C->Engine.Reason==NCA_WAIT_FAILED);Finish();}
 Setup();NcaWdfRequestStop(C);t=Ticket();unsigned before=Writes;CHECK(!NcaWdfConvert(C,&t,&r)&&Writes==before&&!Waits&&r.Retired&&r.Cancelled&&!r.Issued&&!r.Irq&&!r.Ack&&r.Ticket.Sequence==t.Sequence);Finish();
 Setup();CancelAtBegin=1;t=Ticket();before=Writes;CHECK(!NcaWdfConvert(C,&t,&r)&&Writes==before&&r.Retired&&r.Cancelled&&!r.Quarantined);Finish();
 Setup();t=Ticket();CHECK(NcaWdfConvert(C,&t,&r));t=Ticket();t.Channel=2;before=Writes;CHECK(!NcaWdfConvert(C,&t,&r)&&r.Retired&&!r.Issued&&!r.Irq&&!r.Ack&&!r.Raw&&!r.Cancelled&&r.Ticket.Channel==2&&Writes==before);Finish();
 Setup();t=Ticket();Time=t.Deadline100ns;before=Writes;CHECK(!NcaWdfConvert(C,&t,&r)&&r.Retired&&!r.Issued&&!r.Cancelled&&!r.Quarantined&&Writes==before);Finish();
 Setup();C->Active=1;t=Ticket();CHECK(!NcaWdfConvert(C,&t,&r));CHECK(NcaWdfRelease(C)==STATUS_INVALID_DEVICE_STATE);C->Active=0;Finish();
 Setup();Locked=1;Irql=7;NcaWdfDisable(C,NULL);Irql=Locked=0;t=Ticket();CHECK(!NcaWdfConvert(C,&t,&r)&&!Waits);CHECK(NcaWdfRelease(C)==STATUS_SUCCESS);CHECK(NcaWdfPrepare(C,&Ops,NULL,&Binding,&Raw,&Translated)==STATUS_INVALID_DEVICE_STATE);free(C);
 Setup();Locked=1;Irql=7;NcaWdfDisable(C,NULL);Irql=Locked=0;free(C);
 for(unsigned bad=0;bad<6;bad++){CHECK(NcaWdfCreate(NULL,&C)==STATUS_SUCCESS);CM_PARTIAL_RESOURCE_DESCRIPTOR x=Raw,y=Translated;if(bad==0)x.u.Interrupt.Vector=117;if(bad==1)x.Flags=1;if(bad==2)y.Flags=1;if(bad==3)y.ShareDisposition=2;if(bad==4)y.u.Interrupt.Vector=0;if(bad==5)x.Type=3;CHECK(NcaWdfPrepare(C,&Ops,NULL,&Binding,&x,&y)==STATUS_DEVICE_CONFIGURATION_ERROR);free(C);}
 printf("PASS %u assertions: actual ADC WDF callback/wait/retirement component\n",Checks);return 0;}
