/* Compile actual miniport + core against bounded fake Windows DDI/MMIO.
 * Tests callback behavior, not Windows' scheduling or real hardware/cache. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#ifndef NUF_MINIPORT_SOURCE
#define NUF_MINIPORT_SOURCE "../N976nUfs.c"
#endif
#include NUF_MINIPORT_SOURCE
#include "../N976nUfsGpt.h"
#include "../N976nUfsNtfsExpected.h"
#include "system_fat_boot.h"
#define LAST 0x3B94A04U
static NUF_ADAPTER Adapter;
static PORT_CONFIGURATION_INFORMATION Config;
static ACCESS_RANGE Ranges[4];
static _Alignas(8) U8 Lease[8192],Dma[NUF_DMA_BYTES];
static U32 Hci[8192/4],Coherency[4096/4];
static unsigned Irql,MapCalls,UnmapCalls,ActiveMaps,MapFailure,Reads,Writes,Submits,EnableCalls;
static unsigned StopAt,Fault,Notifications,HeaderFault,FailSubmit,SurpriseAt,PartialDma;
static PSCSI_REQUEST_BLOCK ReenterSrb;
static void submit(SCSI_REQUEST_BLOCK *s);
static unsigned MediaFault,DataWrites,Flushes,Readbacks,CommandFault,FaultOpcode;
static unsigned BarrierSeenWrites,CompletionSeenWrites,CompletionSeenFlushes;
static U8 Table[16384],BackupTable[16384],Boot[4096],BackupBoot[4096],MediaData[65536];
static U32 MediaLba,MediaBlocks;
static U8 SystemBoot[4096],SystemBackup[4096];
static ULONG WorkerInitStatus,WorkerQueueStatus,WorkerFreeStatus;
static unsigned WorkerAllocated,WorkerQueued,WorkerFreed,WorkerLive,LastTag,WorkerBusyRejects,WorkerDeferredFrees;
typedef struct {unsigned Live,Queued,Running;PHW_WORKITEM Callback;PVOID Context;} FAKE_WORK;
static FAKE_WORK Workers[8];
static void run_worker(void){
 FAKE_WORK *w=NULL;for(unsigned i=0;i<8;i++)if(Workers[i].Queued){assert(!w);w=&Workers[i];}
 assert(w&&Adapter.Busy&&!w->Running);w->Queued=0;w->Running=1;Irql=0;
 PHW_WORKITEM callback=w->Callback;PVOID context=w->Context;w->Callback=NULL;
 callback(&Adapter,context,w);
 /* Target28000: Running is cleared only AFTER the miniport callback returns.
  * A FreeWorker during callback marks deferred release rather than freeing it. */
 unsigned release=w->Running==2;w->Running=0;
 if(release){assert(w->Live&&!w->Queued);w->Live=0;WorkerLive--;WorkerFreed++;}
}
ULONG StorPortInitializeWorker(PVOID a,PVOID *out){assert(a==&Adapter&&Irql<=2);*out=NULL;
 if(WorkerInitStatus)return WorkerInitStatus;
 for(unsigned i=0;i<8;i++)if(!Workers[i].Live){memset(&Workers[i],0,sizeof(Workers[i]));Workers[i].Live=1;*out=&Workers[i];WorkerAllocated++;WorkerLive++;return 0;}
 assert(0);return STOR_STATUS_INSUFFICIENT_RESOURCES;
}
ULONG StorPortQueueWorkItem(PVOID a,PHW_WORKITEM cb,PVOID ptr,PVOID context){FAKE_WORK *w=ptr;
 assert(a==&Adapter&&Irql==2&&w->Live&&Adapter.Busy);
 if(w->Running||w->Queued){WorkerBusyRejects++;return STOR_STATUS_BUSY;}
 if(WorkerQueueStatus)return WorkerQueueStatus;
 w->Queued=1;w->Callback=cb;w->Context=context;WorkerQueued++;return 0;
}
ULONG StorPortFreeWorker(PVOID a,PVOID ptr){FAKE_WORK *w=ptr;assert(a==&Adapter&&Irql<=2&&w->Live);
 if(w->Queued)return STOR_STATUS_BUSY;
 if(WorkerFreeStatus)return WorkerFreeStatus;
 if(w->Running){assert(w->Running==1);w->Running=2;WorkerDeferredFrees++;return STOR_STATUS_SUCCESS;}
 w->Live=0;WorkerLive--;WorkerFreed++;return STOR_STATUS_SUCCESS;
}
static void le32(U8*p,U32 v){memcpy(p,&v,4);}static void le64(U8*p,U64 v){memcpy(p,&v,8);}
static void header(U8*p,U32 lba){memset(p,0,4096);memcpy(p,"EFI PART",8);le32(p+8,0x10000);le32(p+12,512);
 le64(p+24,lba);le64(p+32,lba==1?LAST:1);le64(p+40,6);le64(p+48,LAST-5);p[56]=1;
 le64(p+72,lba==1?2:LAST-4);le32(p+80,128);le32(p+84,128);
 le32(p+88,NufCrc32(lba==1?Table:BackupTable,16384));
 le32(p+16,NufCrc32(p,512));if(HeaderFault==1||(HeaderFault==2&&lba==LAST))p[16]^=1;
}
static void media(U32 fault){
 memset(Table,0,sizeof(Table));memset(MediaData,0,sizeof(MediaData));MediaLba=MediaBlocks=0;
 NUF_GPT_ENTRY *p=(void*)Table;NUF_GPT_GUID basic={0xEBD0A0A2,0xB9E5,0x4433,{0x87,0xC0,0x68,0xB6,0xB7,0x26,0x99,0xC7}};
 NUF_GPT_GUID esp={0xC12A7328,0xF81F,0x11D2,{0xBA,0x4B,0,0xA0,0xC9,0x3E,0xC9,0x3B}};
 NUF_GPT_GUID system={0x52444E41,0x494F,0x2044,{0x73,0x79,0x73,0x74,0x65,0x6D,0,0}};
 p[0].PartitionTypeGUID=esp;p[0].UniquePartitionGUID=system;for(U32 n=0;n<6;n++)p[0].PartitionName[n]=(uint16_t)"system"[n];p[0].StartingLBA=0x17A00;p[0].EndingLBA=0x199DFF;
 p[1].PartitionTypeGUID=basic;p[1].UniquePartitionGUID.Data1=0x87654321;p[1].StartingLBA=NUF_SCOPE_USERDATA_START;
 p[1].EndingLBA=NUF_SCOPE_USERDATA_START+NUF_SCOPE_USERDATA_BLOCKS-1;
 for(U32 n=0;n<8;n++)p[1].PartitionName[n]=(uint16_t)"userdata"[n];
 if(fault==1)p[1].PartitionName[0]='U';if(fault==2)p[1].PartitionTypeGUID.Data1++;
 if(fault==3)p[1].Attributes=1;if(fault==4)p[1].StartingLBA++;if(fault==5)p[1].EndingLBA--;
 if(fault==6)p[1].UniquePartitionGUID=p[0].UniquePartitionGUID;
 if(fault==7)p[0].EndingLBA=p[1].StartingLBA;
 memcpy(BackupTable,Table,sizeof(Table));if(fault==8)BackupTable[16]^=2;
 memcpy(SystemBoot,SystemFatBootFixture,4096);memcpy(SystemBackup,SystemBoot,4096);
 memcpy(Boot,NufNtfsExpectedBoot,4096);memcpy(BackupBoot,Boot,4096);
 if(fault==9)Boot[64]^=1;if(fault==10)BackupBoot[68]^=1;if(fault==11)Boot[72]^=1;
 if(fault==12)Boot[12]=0;if(fault==13)Table[100]^=1;
}
static void media_read(U32 lba,U8 *out){
 if(lba==0)memcpy(out,Lease+4096,4096);
 else if(lba==1||lba==LAST)header(out,lba);
 else if(lba>=2&&lba<=5)memcpy(out,Table+(lba-2)*4096,4096);
 else if(lba>=LAST-4&&lba<LAST)memcpy(out,BackupTable+(lba-(LAST-4))*4096,4096);
 else if(lba==NUF_SYSTEM_PARTITION_START)memcpy(out,SystemBoot,4096);
 else if(lba==NUF_SYSTEM_PARTITION_START+NUF_SYSTEM_BACKUP_SECTOR)memcpy(out,SystemBackup,4096);
 else if(lba==NUF_SCOPE_USERDATA_START)memcpy(out,Boot,4096);
 else if(lba==NUF_SCOPE_USERDATA_START+NUF_SCOPE_VOLUME_BLOCKS-1)memcpy(out,BackupBoot,4096);
 else if(lba>=MediaLba&&lba-MediaLba<MediaBlocks){memcpy(out,MediaData+(lba-MediaLba)*4096,4096);Readbacks++;if(CommandFault==5)out[2]^=1;}
 else memset(out,0x6C,4096);
}
static U64 PerfTick;
static unsigned RejectPerfClock,ZeroPerfClock,ReversePerfClock;
static U64 PerfFrequencyOverride;
ULONG StorPortQueryPerformanceCounter(PVOID a,LARGE_INTEGER *frequency,LARGE_INTEGER *value){
 assert(a==&Adapter&&Irql<=2);
 if(RejectPerfClock)return STOR_STATUS_INVALID_PARAMETER;
 if(frequency)frequency->QuadPart=(LONGLONG)(PerfFrequencyOverride?PerfFrequencyOverride:1000000);
 value->QuadPart=ZeroPerfClock?0:ReversePerfClock?(LONGLONG)(--PerfTick):(LONGLONG)(PerfTick+=10);
 return STOR_STATUS_SUCCESS;
}
void KeQuerySystemTimePrecise(LARGE_INTEGER *value){assert(Irql<=2);value->QuadPart=133700000000000000LL+(LONGLONG)PerfTick;}
static U64 Now;
static U64 PendingUntil;
static U32 CompletionDelayUs,SleepExtraUs;
static BOOLEAN PassiveEnabled;
static PHW_PASSIVE_INITIALIZE_ROUTINE Callback;
static int IsMapped[4];
static HW_INITIALIZATION_DATA Registered;
static unsigned RegisterCalls;
static NTSTATUS RegisterResult;
static PVOID RegisteredObject,RegisteredRegistry,RegisteredContext;
static void stop(void){unsigned old=Irql;Irql=3;
 SCSI_ADAPTER_CONTROL_STATUS status=Control(&Adapter,ScsiStopAdapter,NULL);assert(status==(Adapter.Stop?ScsiAdapterControlUnsuccessful:ScsiAdapterControlSuccess));Irql=old;}
static int mapped_index(PVOID p){if(p==Hci)return 0;if(p==Coherency)return 1;if(p==Lease)return 2;if(p==Dma)return 3;return -1;}
PVOID MmMapIoSpaceEx(PHYSICAL_ADDRESS p,ULONG n,ULONG flags){
 int i;PVOID ptr;assert(Irql==0);MapCalls++;
 if((U64)p.QuadPart==0x13D60000){i=0;ptr=Hci;assert(n==8192&&flags==(PAGE_READWRITE|PAGE_NOCACHE));}
 else if((U64)p.QuadPart==0x13C10000){i=1;ptr=Coherency;assert(n==4096&&flags==(PAGE_READONLY|PAGE_NOCACHE));}
 else if((U64)p.QuadPart==0x93200000){i=2;ptr=Lease;assert(n==8192&&flags==PAGE_READWRITE);}
 else{assert((U64)p.QuadPart==0x93000000);i=3;ptr=Dma;assert(n==NUF_DMA_BYTES&&flags==(PAGE_READWRITE|PAGE_NOCACHE));}
 if(MapFailure==MapCalls)return NULL;
 assert(!IsMapped[i]);IsMapped[i]=1;ActiveMaps++;
 if(StopAt==1&&MapCalls==1){StopAt=0;stop();}
 return ptr;
}
void MmUnmapIoSpace(PVOID p,size_t n){int i=mapped_index(p);assert(Irql==0&&i>=0&&IsMapped[i]);
 assert(n==(i==0||i==2?8192U:i==1?4096U:NUF_DMA_BYTES));IsMapped[i]=0;ActiveMaps--;UnmapCalls++;}
static void put_be(U8 *p,U32 v){p[0]=(U8)(v>>24);p[1]=(U8)(v>>16);p[2]=(U8)(v>>8);p[3]=(U8)v;}
ULONG FakeReadRegister(PULONG p){Reads++;assert(Irql==0||Irql==3);
 if(p==Hci+0x58/4&&PendingUntil&&Now>=PendingUntil){*p=0;PendingUntil=0;}
 if((uintptr_t)p>=(uintptr_t)Coherency&&(uintptr_t)p<(uintptr_t)(Coherency+4096/4)){assert(IsMapped[1]);return *p;}
 assert((uintptr_t)p>=(uintptr_t)Hci&&(uintptr_t)p<(uintptr_t)(Hci+8192/4)&&IsMapped[0]);return *p;}
void FakeWriteRegister(PULONG p,ULONG v){assert((Irql==0||Irql==3)&&IsMapped[0]&&IsMapped[3]);Writes++;
 U32 off=(U32)((U8*)p-(U8*)Hci);assert(off==0x20||off==0x50||off==0x54||off==0x58||off==0x60||off==0x1140);
 if(off==0x20){*p&=~v;return;}*p=v;if(off!=0x58)return;assert(Irql==0);Submits++;
 assert(v==1);
 if(SurpriseAt==Submits){SCSI_PNP_REQUEST_BLOCK pn={0};pn.Length=sizeof(pn);pn.Function=SRB_FUNCTION_PNP;pn.PnPAction=StorSurpriseRemoval;pn.SrbPnPFlags=1;
  unsigned old=Irql;Irql=2;assert(PnpIo(&Adapter,&pn));Irql=old;assert(pn.SrbStatus==SRB_STATUS_BUSY&&Adapter.Removed);return;}
 if(FailSubmit==Submits)return;
 if(StopAt==2){StopAt=0;stop();return;}if(Fault==1||(Fault==3&&Submits==3))return;
 U8 *trd=Dma+4096,*cmd=Dma+12288,*rsp=cmd+1024,*data=Dma+20480;
 assert(cmd[16]==0x25||cmd[16]==0x28||cmd[16]==0x2A||cmd[16]==0x35);LastTag=cmd[3];
 if(CommandFault&&cmd[16]==FaultOpcode){if(CommandFault==1)return;if(CommandFault==2)Dma[0]^=1;}
 trd[8]=0;rsp[0]=0x21;rsp[3]=cmd[3];Hci[0x58/4]=0;Hci[0x20/4]=1;
 if(CommandFault==3&&cmd[16]==FaultOpcode)rsp[3]^=1;
 if(CommandFault==4&&cmd[16]==FaultOpcode)trd[8]=2;
 U32 lba=((U32)cmd[18]<<24)|((U32)cmd[19]<<16)|((U32)cmd[20]<<8)|cmd[21];
 U32 bytes=((U32)cmd[12]<<24)|((U32)cmd[13]<<16)|((U32)cmd[14]<<8)|cmd[15];
 U32 entries=(bytes+4095)/4096,blocks=((U32)cmd[23]<<8)|cmd[24],word=0;
 memcpy(&word,trd+28,4);assert(word==(0x08000000U|(entries?(entries+1)*16:0))&&entries<=16);
 for(U32 n=0;n<entries;n++){
  U32 address,upper,reserved,dbc;U8 *prd=cmd+2048+n*16;
  memcpy(&address,prd,4);memcpy(&upper,prd+4,4);memcpy(&reserved,prd+8,4);memcpy(&dbc,prd+12,4);
  assert(address==0x93000000+20480+n*4096&&!upper&&!reserved&&dbc==4095);
 }
 for(U32 n=entries*16;n<2048;n++)assert(cmd[2048+n]==0);
 if(cmd[16]==0x35){Flushes++;BarrierSeenWrites=DataWrites;assert(!lba&&!bytes&&!blocks);}
 else if(cmd[16]==0x25){assert(bytes==8&&!blocks);put_be(data,LAST);put_be(data+4,4096);}
 else {
  assert(bytes==blocks*4096&&blocks>=1&&blocks<=16);
  if(cmd[16]==0x2A){MediaLba=lba;MediaBlocks=0;}
  for(U32 n=0;n<blocks;n++){
   if(PartialDma&&n==PartialDma){trd[8]=2;break;}
   U32 address;memcpy(&address,cmd+2048+n*16,4);U8 *payload=Dma+(address-0x93000000);
   U32 at=lba+n;
   if(cmd[16]==0x2A){
    assert((at>=NUF_SCOPE_USERDATA_START&&at-NUF_SCOPE_USERDATA_START<NUF_SCOPE_VOLUME_BLOCKS)||
     (at>=NUF_SYSTEM_PARTITION_START&&at-NUF_SYSTEM_PARTITION_START<NUF_SYSTEM_VOLUME_BLOCKS));
    DataWrites++;MediaBlocks++;memcpy(MediaData+n*4096,payload,4096);
    if(at==NUF_SCOPE_USERDATA_START)memcpy(Boot,payload,4096);
    if(at==NUF_SCOPE_USERDATA_START+NUF_SCOPE_VOLUME_BLOCKS-1)memcpy(BackupBoot,payload,4096);
   }else media_read(at,payload);
  }
 }
 if(Fault==2)Dma[0]^=1;
 if(CompletionDelayUs&&cmd[16]==0x28){Hci[0x58/4]=1;PendingUntil=Now+CompletionDelayUs;}
}
void FakeBarrier(void){__atomic_thread_fence(__ATOMIC_SEQ_CST);}
ULONGLONG KeQueryInterruptTimePrecise(ULONGLONG *qpc){assert(Irql==0);*qpc=0;Now+=100;return Now*10;}
NTSTATUS KeDelayExecutionThread(int mode,BOOLEAN alertable,LARGE_INTEGER *interval){assert(Irql==0&&mode==KernelMode&&!alertable&&interval->QuadPart<0&&interval->QuadPart>=-10000);Now+=(U64)(-interval->QuadPart)/10+SleepExtraUs;return 0;}
void StorPortStallExecution(ULONG us){assert(Irql==0&&us&&us<=NUF_READ_POLL_STEP_US&&us<1000);Now+=us;}
BOOLEAN StorPortEnablePassiveInitialization(PVOID p,PHW_PASSIVE_INITIALIZE_ROUTINE callback){
 assert(p==&Adapter&&Irql==3);EnableCalls++;if(PassiveEnabled)Callback=callback;return PassiveEnabled;}
void StorPortNotification(int kind,PVOID extension,PVOID request){assert(extension==&Adapter);(void)request;
 assert(kind==RequestComplete);Notifications++;
 SCSI_REQUEST_BLOCK *s=request;assert(s);
 CompletionSeenWrites=DataWrites;CompletionSeenFlushes=Flushes;
 if(s->SrbStatus!=SRB_STATUS_BUSY)assert(!Adapter.Busy);
 if(ReenterSrb){PSCSI_REQUEST_BLOCK next=ReenterSrb;ReenterSrb=NULL;unsigned old=Irql;submit(next);Irql=old;}
}
NTSTATUS StorPortInitialize(PVOID object,PVOID registry,HW_INITIALIZATION_DATA *init,PVOID hwcontext){
 assert(init);Registered=*init;RegisterCalls++;
 RegisteredObject=object;RegisteredRegistry=registry;RegisteredContext=hwcontext;
 return RegisterResult;}
/* Explicit test oracle for the documented physical registration contract.
 * Rejection here is NOT a claim about a particular Windows Storport binary. */
static int registration_contract(const HW_INITIALIZATION_DATA *h){
 return h->HwInitializationDataSize==sizeof(*h)&&h->AdapterInterfaceType==InterfaceTypeUndefined&&
  h->DeviceExtensionSize==sizeof(NUF_ADAPTER)&&h->HwFindAdapter==FindAdapter&&h->HwBuildIo==BuildIo&&h->SrbExtensionSize==sizeof(NUF_REQUEST)&&
  h->HwInitialize==Initialize&&h->HwStartIo==StartIo&&h->HwInterrupt==Interrupt&&
  h->HwResetBus==ResetBus&&h->HwAdapterControl==Control&&h->NumberOfAccessRanges==4&&
  h->MapBuffers==STOR_MAP_ALL_BUFFERS_INCLUDING_READ_WRITE&&h->NeedPhysicalAddresses==TRUE&&
  h->TaggedQueuing==TRUE&&h->AutoRequestSense==TRUE&&h->MultipleRequestPerLu==TRUE&&
  h->FeatureSupport==(STOR_FEATURE_SET_ADAPTER_INTERFACE_TYPE|STOR_FEATURE_ADAPTER_NOT_REQUIRE_IO_PORT)&&
  h->SrbTypeFlags==SRB_TYPE_FLAG_SCSI_REQUEST_BLOCK&&h->AddressTypeFlags==ADDRESS_TYPE_FLAG_BTL8;
}
static void setup(void){
 memset(&Adapter,0,sizeof(Adapter));memset(&Config,0,sizeof(Config));memset(Ranges,0,sizeof(Ranges));
 memset(Lease,0,sizeof(Lease));memset(Dma,0,sizeof(Dma));memset(Hci,0,sizeof(Hci));memset(Coherency,0,sizeof(Coherency));memset(IsMapped,0,sizeof(IsMapped));
 Irql=MapCalls=UnmapCalls=ActiveMaps=MapFailure=Reads=Writes=Submits=EnableCalls=StopAt=Fault=Notifications=HeaderFault=0;
 FailSubmit=SurpriseAt=PartialDma=0;ReenterSrb=NULL;
 MediaFault=DataWrites=Flushes=Readbacks=CommandFault=FaultOpcode=0;
 BarrierSeenWrites=CompletionSeenWrites=CompletionSeenFlushes=0;Now=PendingUntil=0;CompletionDelayUs=SleepExtraUs=0;PassiveEnabled=TRUE;Callback=NULL;
 WorkerInitStatus=WorkerQueueStatus=WorkerFreeStatus=0;WorkerAllocated=WorkerQueued=WorkerFreed=WorkerLive=LastTag=WorkerBusyRejects=WorkerDeferredFrees=0;memset(Workers,0,sizeof(Workers));
 memset(&Registered,0,sizeof(Registered));RegisterCalls=0;RegisterResult=STATUS_SUCCESS;
 RegisteredObject=RegisteredRegistry=RegisteredContext=NULL;
 U64 bases[4]={0x13D60000,0x13C10000,0x93200000,0x93000000};U32 bytes[4]={8192,4096,8192,NUF_DMA_BYTES};
 for(U32 i=0;i<4;i++){Ranges[i].RangeStart.QuadPart=(LONGLONG)bases[i];Ranges[i].RangeLength=bytes[i];Ranges[i].RangeInMemory=1;}
 Config.AccessRanges=&Ranges;Config.NumberOfAccessRanges=4;
 N976N_UFS_HANDOFF *h=(N976N_UFS_HANDOFF*)Lease;
 h->Magic=N976N_UFS_HANDOFF_MAGIC;h->Version=2;h->Bytes=336;h->ImmutableBytes=320;h->ProducerStage=3;
 h->ProducerChecks=0x7F;h->Flags=7;h->PowerRaw=0x11;h->Guard=N976N_UFS_HANDOFF_GUARD;h->BootCounter=1;h->CounterHz=26000000;
 h->LeaseBase=bases[2];h->LeaseBytes=8192;h->DmaBase=bases[3];h->DmaBytes=NUF_DMA_BYTES;h->FirmwareDmaBase=0x93100000;h->FirmwareDmaBytes=NUF_FIRMWARE_DMA_BYTES;
 h->HciBase=bases[0];h->HciBytes=8192;h->VendorOffset=0x1100;h->CoherencyBase=bases[1];h->CoherencyOffset=0x700;h->CoherencyBytes=4096;
 h->BaselineOffset=4096;h->BaselineBytes=4096;h->LastLba=LAST;h->BlockBytes=4096;
 h->HciCap=0x1303FF1F;h->HciVersion=0x300;h->Hce=1;h->Hcs=0x10F;h->TrlBase=0x93101000;
 h->TxPrdt=h->RxPrdt=12;h->Reorder=10;h->Nexus=~0U;h->Axi=0x18000003;h->Coherency=0x11;
 Lease[4096+510]=0x55;Lease[4096+511]=0xAA;Lease[4096+446+4]=0xEE;
 le32(Lease+4096+446+8,1);le32(Lease+4096+446+12,LAST);media(0);
 memcpy(Lease+4088,&h->Guard,8);h->BaselineCrc32=NufCrc32(Lease+4096,4096);h->Crc32=NufLeaseCrc(h);
 Hci[0]=h->HciCap;Hci[2]=h->HciVersion;Hci[0x34/4]=1;Hci[0x30/4]=0x10F;Hci[0x50/4]=h->TrlBase;
 Hci[0x1100/4]=Hci[0x1104/4]=12;Hci[0x1160/4]=10;Hci[0x1140/4]=~0U;Hci[0x116c/4]=h->Axi;Coherency[0x700/4]=0x11;
}
static void find(void){BOOLEAN again=TRUE;assert(FindAdapter(&Adapter,NULL,NULL,NULL,&Config,&again)==SP_RETURN_FOUND&&!again);}
static BOOLEAN initialize(void){Irql=3;BOOLEAN result=Initialize(&Adapter);Irql=0;return result;}
static BOOLEAN passive(void){assert(Callback);Irql=0;BOOLEAN result=Callback(&Adapter);assert(ActiveMaps==(result?4:0));return result;}
static NUF_REPORT report(void){_Alignas(8) U8 bytes[sizeof(SRB_IO_CONTROL)+sizeof(NUF_REPORT)];NUF_REPORT out;
 SRB_IO_CONTROL *c=(void*)bytes;memset(bytes,0,sizeof(bytes));c->HeaderLength=sizeof(*c);memcpy(c->Signature,"N976UFS",8);c->Length=sizeof(out);c->ControlCode=NUF_CONTROL;
 SCSI_REQUEST_BLOCK s={0};s.Function=SRB_FUNCTION_IO_CONTROL;s.DataBuffer=bytes;s.DataTransferLength=sizeof(bytes);
 Irql=2;assert(StartIo(&Adapter,&s)&&s.SrbStatus==SRB_STATUS_SUCCESS);Irql=0;memcpy(&out,bytes+sizeof(*c),sizeof(out));return out;
}
static void pass(const char *name){puts(name);}
static void ready(void){setup();find();assert(initialize());assert(passive());assert(Adapter.Report.SessionState==1&&Adapter.Started==2&&!Adapter.Stop&&Adapter.Scope.Ready);}
static void read_srb(SCSI_REQUEST_BLOCK *s,NUF_REQUEST *q,U8 *data,U32 lba){
 memset(s,0,sizeof(*s));memset(q,0,sizeof(*q));s->Function=SRB_FUNCTION_EXECUTE_SCSI;s->CdbLength=10;s->Cdb[0]=0x28;
 put_be(s->Cdb+2,lba);s->Cdb[8]=1;s->DataBuffer=data;s->DataTransferLength=4096;s->SrbFlags=SRB_FLAGS_DATA_IN;s->SrbExtension=q;
}
static void submit(SCSI_REQUEST_BLOCK *s){Irql=2;assert(BuildIo(&Adapter,s));assert(StartIo(&Adapter,s));Irql=0;}
static U8 Buffer[65536];

static void write_srb(SCSI_REQUEST_BLOCK *s,NUF_REQUEST *q,U8 *data,U32 lba,U32 sixteen,U32 fua){
 read_srb(s,q,data,lba);s->SrbFlags=SRB_FLAGS_DATA_OUT;s->CdbLength=sixteen?16:10;memset(s->Cdb,0,16);
 s->Cdb[0]=sixteen?0x8A:0x2A;s->Cdb[1]=fua?8:0;put_be(s->Cdb+(sixteen?6:2),lba);s->Cdb[sixteen?13:8]=1;
}
static NUF_SCOPE_REPORT scope_query(void){_Alignas(8) U8 bytes[384]={0};SRB_IO_CONTROL *c=(void*)bytes;
 NUF_SCOPE_REPORT *r=(void*)(bytes+32);c->HeaderLength=28;c->Length=356;c->ControlCode=NUF_SCOPE_CONTROL;memcpy(c->Signature,"N976UFS",8);
 r->Magic=NUF_SCOPE_MAGIC;r->Version=3;r->Bytes=352;SCSI_REQUEST_BLOCK s={0};s.Function=SRB_FUNCTION_IO_CONTROL;
 s.DataBuffer=bytes;s.DataTransferLength=sizeof(bytes);Irql=2;assert(StartIo(&Adapter,&s)&&s.SrbStatus==SRB_STATUS_SUCCESS);Irql=0;return *r;
}

static void pnp(SCSI_PNP_REQUEST_BLOCK *p,U32 action,int adapter){
 memset(p,0xAB,sizeof(*p));p->Length=sizeof(*p);p->Function=SRB_FUNCTION_PNP;
 p->PathId=p->TargetId=p->Lun=0;p->PnPAction=action;p->SrbPnPFlags=adapter?1:0;
 /* All ignored transfer fields deliberately poisoned. */
 Irql=2;assert(BuildIo(&Adapter,(void*)p));assert(StartIo(&Adapter,(void*)p));Irql=0;
}
static void remove_clean(void){SCSI_PNP_REQUEST_BLOCK p;pnp(&p,StorRemoveDevice,1);
 assert(p.SrbStatus==SRB_STATUS_PENDING);run_worker();
 assert(p.SrbStatus==SRB_STATUS_SUCCESS&&!ActiveMaps&&!WorkerLive&&!Adapter.Claimed&&
   ((N976N_UFS_HANDOFF*)Lease)->ClaimState==2);
}
static void read_blocks(SCSI_REQUEST_BLOCK *s,NUF_REQUEST *q,U8 *data,U32 lba,U32 count){
 read_srb(s,q,data,lba);s->Cdb[7]=(U8)(count>>8);s->Cdb[8]=(U8)count;s->DataTransferLength=count*4096;
}
#ifdef NUF_EXPECT_LEGACY_BUSY
int main(void){SCSI_REQUEST_BLOCK first,next;NUF_REQUEST q1,q2;static U8 nextbuf[4096];
 ready();read_srb(&first,&q1,Buffer,0);read_srb(&next,&q2,nextbuf,1);
 submit(&first);ReenterSrb=&next;run_worker();
 assert(first.SrbStatus==SRB_STATUS_SUCCESS&&next.ScsiStatus==2);
 assert(Adapter.Report.RuntimeRequests==1&&Adapter.Report.RuntimeCompleted==1&&Adapter.CompletedBlocks==1);
 assert(Adapter.Stop&&Adapter.Report.SessionState==3&&Adapter.Report.WorkerStatus==STOR_STATUS_BUSY);
 assert(Adapter.Scope.FirstReason==NufScopeWorker&&WorkerBusyRejects==1&&WorkerQueued==1);
 puts("preserved_rework1_reproduces_running_worker_busy_after_lba0_completion");return 0;
}
#else
int main(void){SCSI_REQUEST_BLOCK s;NUF_REQUEST q;NUF_SCOPE_REPORT r;SCSI_PNP_REQUEST_BLOCK pn;
 setup();assert(DriverEntry((void*)1,(void*)2)==STATUS_SUCCESS&&RegisterCalls==1&&registration_contract(&Registered));
 assert(DriverEntry(NULL,(void*)2)==STATUS_NOT_SUPPORTED&&RegisterCalls==1);
 BOOLEAN again=1;assert(FindAdapter(&Adapter,NULL,NULL,"dump=1",&Config,&again)==SP_RETURN_ERROR&&!again&&!MapCalls);
 pass("physical_registration_and_unsupported_dump_refusal");
 find();assert(Config.MaximumTransferLength==65536&&Config.NumberOfPhysicalBreaks>=16&&Config.CachesData&&Config.MaxNumberOfIO==1&&Config.Dma32BitAddresses&&!Config.Dma64BitAddresses);
 assert(!Interrupt(&Adapter)&&!Reads&&!Writes&&!MapCalls);
 pass("64k_os_span_single_low_dma_slot_polled_no_os_buffer_dma");
 ready();r=scope_query();assert(r.Ready&&r.ReadChecks==7&&r.GptChecks==255&&r.TargetMatches==1);
 assert(Adapter.Report.CapacityChecked&&Adapter.Report.ReadChecked&&Adapter.Report.Compared&&!Adapter.Report.Retired);
 assert(Adapter.Engine.SessionActive&&NufRequestRetired(&Adapter.Engine)&&Adapter.Claimed&&ActiveMaps==4&&WorkerLive==1);
 assert(((N976N_UFS_HANDOFF*)Lease)->ClaimState==1);
 pass("fresh_gpt_ntfs_admission_and_one_owned_persistent_session");
 unsigned before=Submits;assert(passive()&&Submits==before&&MapCalls==4&&WorkerAllocated==1);
 NUF_REPORT original=report();assert(original.CapacityChecked&&original.SessionState==1);
 pass("duplicate_initialization_and_queries_do_not_reprobe");
 for(U32 f=1;f<=13;f++){setup();media(f);find();assert(initialize());assert(!passive());assert(!Adapter.Scope.Ready&&!ActiveMaps&&!WorkerLive&&!DataWrites);}
 for(U32 f=1;f<=2;f++){setup();HeaderFault=f;find();assert(initialize());assert(!passive());assert(!Adapter.Scope.Ready&&!ActiveMaps&&!DataWrites);}
 pass("gpt_identity_crc_geometry_overlap_ntfs_primary_backup_refusals");
 setup();Boot[0]^=1;Boot[100]^=2;Boot[4095]^=3;BackupBoot[100]^=4;BackupBoot[80]^=5;
 find();assert(initialize()&&passive()&&Adapter.Scope.Ready);
 pass("ntfs_mutable_boot_code_checksum_tail_accept_without_weakening_bpb_identity");
 for(U32 off=3;off<80;off++){setup();Boot[off]^=1;find();assert(initialize()&&!passive()&&!Adapter.Scope.Ready&&!DataWrites);}
 pass("every_ntfs_identity_geometry_bpb_byte_remains_pinned");

 ready();r=scope_query();assert(r.SystemChecks==7&&r.SystemMatches==1&&r.SystemPartitionIndex==1);
 assert(r.SystemPartitionStart==0x17A00&&r.SystemPartitionBlocks==0x182400&&r.SystemWriteStart==0x17A00&&r.SystemWriteBlocks==0x40000&&r.FatSerial==0x1234ABCD);
 assert(Adapter.Engine.Config.SystemWriteFirst==0x17A00&&Adapter.Engine.Config.SystemWriteBlocks==0x40000);
 pass("actual_system_esp_identity_and_one_gib_fat_prefix_admitted_with_userdata");
 for(U32 f=0;f<8;f++){
  setup();NUF_GPT_ENTRY *p=(void*)Table;
  if(f==0)p[0].PartitionTypeGUID=p[1].PartitionTypeGUID;
  if(f==1)p[0].UniquePartitionGUID.Data1^=1;
  if(f==2)p[0].StartingLBA++;if(f==3)p[0].EndingLBA--;
  if(f==4)p[0].Attributes=1;if(f==5)p[0].PartitionName[0]='S';
  if(f==6){p[2]=p[0];p[2].StartingLBA=0x100;p[2].EndingLBA=0x110;p[2].UniquePartitionGUID.Data1^=1;}
  if(f==7)memset(p,0,sizeof(*p));
  memcpy(BackupTable,Table,sizeof(Table));find();assert(initialize()&&!passive());
  assert(!Adapter.Scope.Ready&&!Adapter.Engine.Config.WriteEnabled&&!Adapter.Engine.Config.SystemWriteBlocks&&!ActiveMaps&&!DataWrites);
 }pass("system_old_basic_type_guid_range_attributes_name_missing_duplicate_refused");
 const U32 critical[]={11,12,13,14,16,17,19,21,22,28,32,36,40,42,44,48,50,66,67,510,511};
 for(U32 copy=0;copy<2;copy++)for(U32 n=0;n<sizeof(critical)/sizeof(*critical);n++){
  setup();(copy?SystemBackup:SystemBoot)[critical[n]]^=1;find();assert(initialize()&&!passive());
  assert(Adapter.Scope.FirstReason==(copy?NufScopeSystemBackup:NufScopeSystemBoot));
  assert(!Adapter.Engine.Config.WriteEnabled&&!Adapter.Engine.Config.WriteBlocks&&!Adapter.Engine.Config.SystemWriteBlocks&&!DataWrites&&!ActiveMaps);
 }pass("system_primary_backup_critical_bpb_geometry_identity_and_signatures_fail_closed");
 setup();SystemBoot[0]^=1;SystemBoot[65]^=1;SystemBoot[71]^=1;SystemBoot[100]^=1;SystemBoot[4095]^=1;
 SystemBackup[65]^=2;SystemBackup[71]^=2;SystemBackup[100]^=2;
 find();assert(initialize()&&passive()&&Adapter.Scope.Ready&&Adapter.Scope.SystemChecks==7&&!DataWrites);
 pass("system_semantic_bpb_accepts_distinct_boot_code_labels_reserved_flags_without_media_seal");
 for(U32 f=1;f<=4;f++){setup();MapFailure=f;find();assert(initialize());assert(!passive());assert(!ActiveMaps&&!Submits&&!WorkerLive);}
 setup();Lease[4096+3]^=1;find();assert(initialize()&&!passive()&&!Submits&&!ActiveMaps);
 setup();((N976N_UFS_HANDOFF*)Lease)->ProducerStage=1;find();assert(initialize()&&!passive()&&!Submits&&!ActiveMaps);
 pass("partial_mapping_and_invalid_lease_cleanup_before_publication");
 setup();find();PassiveEnabled=FALSE;assert(!initialize()&&Adapter.Stop&&!ActiveMaps&&!Submits);
 setup();find();WorkerInitStatus=STOR_STATUS_INSUFFICIENT_RESOURCES;assert(initialize()&&!passive());assert(!ActiveMaps&&!WorkerLive&&!Adapter.Claimed);
 pass("passive_registration_or_worker_allocation_failure_no_published_disk");
 ready();U64 initialized=Adapter.Engine.DmaInitBytes;unsigned maps=MapCalls,alloc=WorkerAllocated;
 for(U32 n=0;n<200;n++){read_srb(&s,&q,Buffer,0x222300+n);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&s.DataTransferLength==4096);}
 assert(MapCalls==maps&&UnmapCalls==0&&WorkerAllocated==alloc+200&&WorkerFreed==200&&ActiveMaps==4&&WorkerLive==1);
 assert(Adapter.Engine.DmaInitBytes==initialized&&Adapter.Report.RuntimeCompleted==200&&Adapter.Report.RuntimeBytes==200*4096ULL);
 pass("200_reads_keep_mapping_dma_list_with_one_worker_per_os_request");
 read_blocks(&s,&q,Buffer,0x222500,16);before=Submits;submit(&s);run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&s.DataTransferLength==65536&&Submits==before+1);
 assert(Adapter.Report.RuntimeCompleted==201&&Adapter.Report.RuntimeBytes==216*4096ULL);
 for(U32 n=0;n<65536;n++)assert(Buffer[n]==0x6C);
 pass("64k_read_one_worker_one_bounded_physical_request_exact_bytes");
 ready();read_blocks(&s,&q,Buffer,1,5);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Report.ViewApplied>=2);
 U32 headerSize=0;memcpy(&headerSize,Buffer+12,4);assert(headerSize==92);
 U64 end=0;memcpy(&end,Buffer+4096+128+40,8);assert(end==0x12221FF);
 assert(!DataWrites&&!Flushes);
 pass("multi_block_gpt_header_and_array_cpu_views_applied_per_block");
 assert(!memcmp(Buffer+4096,Table,128));
 read_srb(&s,&q,Buffer,LAST-4);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!memcmp(Buffer,BackupTable,128));
 pass("primary_backup_gpt_views_preserve_actual_system_esp_type_guid_and_full_partition_extent");
 ready();read_srb(&s,&q,Buffer,LAST);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Report.ViewHeader[1].ReturnedSize==92);
 assert(Adapter.Report.ViewHeader[1].ArrayCrc==NufCrc32(BackupTable,16384));
 pass("backup_gpt_raw_and_returned_crc_evidence_distinct");
 ready();Table[400]^=1;read_srb(&s,&q,Buffer,2);submit(&s);run_worker();assert(s.ScsiStatus==2&&Adapter.Stop&&!DataWrites);
 ready();Adapter.ScopeWork.View.TargetIndex=~0U;read_srb(&s,&q,Buffer,2);submit(&s);run_worker();assert(s.ScsiStatus==2&&Adapter.Stop&&!DataWrites);
 pass("raw_metadata_drift_invalid_cpu_view_never_falls_back_to_success");
 for(U32 which=0;which<3;which++){ready();if(which==0)Lease[4096+3]^=1;if(which==1)Lease[4000]^=1;if(which==2)Lease[40]^=1;
  before=Submits;read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.ScsiStatus==2&&Submits==before&&Adapter.Stop);}
 pass("immutable_snapshot_detects_baseline_padding_and_descriptor_drift_without_crc_recompute");
 ready();Dma[4095]^=1;before=Submits;read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();
 assert(s.ScsiStatus==2&&Adapter.Stop&&Submits==before&&Adapter.IoReport.Quarantined);
 pass("between_requests_guard_corruption_detected_before_reset_or_doorbell");
 ready();read_blocks(&s,&q,Buffer,0x222300,16);PartialDma=4;submit(&s);run_worker();
 assert(s.ScsiStatus==2&&!s.DataTransferLength&&Adapter.PartialBytes==0&&Adapter.Report.RuntimeCompleted==0&&Adapter.Report.RuntimeBytes==0);
 pass("partial_multiblock_read_failure_never_claims_full_srb_success");
 ready();SCSI_REQUEST_BLOCK next;NUF_REQUEST nextq;static U8 nextbuf[4096];
 read_srb(&next,&nextq,nextbuf,1);read_srb(&s,&q,Buffer,0);submit(&s);PVOID firstWorker=q.Worker;ReenterSrb=&next;run_worker();
 assert(next.SrbStatus==SRB_STATUS_PENDING&&WorkerAllocated==3&&nextq.Worker!=firstWorker&&!q.Worker);
 assert(!WorkerBusyRejects&&WorkerDeferredFrees==1&&WorkerFreed==1&&WorkerLive==2);
 run_worker();assert(next.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Report.RuntimeCompleted==2&&Adapter.Report.ViewSeenMask==1);
 assert(!nextq.Worker&&WorkerDeferredFrees==2&&WorkerFreed==2&&WorkerLive==1&&!Adapter.Stop);
 pass("completion_reentrancy_uses_distinct_worker_until_deferred_free_returns");
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);SurpriseAt=Submits+1;run_worker();
 assert(s.ScsiStatus==2&&Adapter.Removed&&Adapter.Stop);unsigned removedReads=Reads,removedWrites=Writes;
 pnp(&pn,StorRemoveDevice,1);run_worker();assert(!ActiveMaps&&!WorkerLive&&Reads==removedReads&&Writes==removedWrites);
 pass("busy_surprise_removal_latches_mmio_block_before_deferred_resource_release");
 ready();memset(Buffer,0x42,sizeof(Buffer));write_srb(&s,&q,Buffer,0x222210,0,0);submit(&s);run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&DataWrites==1&&!Flushes&&!Readbacks&&r.Magic==NUF_SCOPE_MAGIC);
 assert(Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain&&Adapter.Scope.Writes==1&&Adapter.Scope.Readbacks==0);
 write_srb(&s,&q,Buffer,0x222211,1,1);submit(&s);run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Scope.FuaWrites==1&&Flushes==1&&!Readbacks);
 assert(BarrierSeenWrites==2&&CompletionSeenFlushes==1&&!Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain);
 pass("write10_cached_completion_and_write16_fua_real_barrier_without_readback");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);s.Cdb[8]=16;s.DataTransferLength=65536;
 before=Submits;submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&s.DataTransferLength==65536&&DataWrites==16&&!Flushes&&!Readbacks);
 assert(Submits-before==1&&CompletionSeenWrites==16&&!CompletionSeenFlushes&&Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain);
 pass("64k_ordinary_write_one_guarded_command_no_flush_or_readback");
 ready();write_srb(&s,&q,Buffer,0x222300,1,1);s.Cdb[13]=16;s.DataTransferLength=65536;
 before=Submits;submit(&s);run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&s.DataTransferLength==65536&&Submits-before==2);
 assert(DataWrites==16&&Flushes==1&&!Readbacks&&BarrierSeenWrites==16&&CompletionSeenWrites==16&&CompletionSeenFlushes==1);
 assert(Adapter.Scope.FuaWrites==16&&!Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain);
 pass("64k_fua_write_single_final_flush_after_all_blocks_before_completion");
 for(U32 fua=0;fua<2;fua++){
  ready();write_srb(&s,&q,Buffer,0x579F0,1,fua);s.Cdb[13]=16;s.DataTransferLength=65536;
  before=Submits;submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&s.DataTransferLength==65536&&Submits-before==1+fua);
  assert(DataWrites==16&&Flushes==fua&&!Readbacks&&Adapter.Scope.SystemWrites==16&&Adapter.Scope.SystemWriteBytes==65536);
  assert(Adapter.Scope.Writes==16&&!Adapter.Scope.WriteUncertain&&Adapter.Scope.CacheDirty==!fua&&Adapter.Scope.FuaWrites==16*fua);
 }pass("system_final_64k_span_cached_and_fua_completion_uses_same_guarded_write_barrier_contract");
 for(U32 endpoint=0;endpoint<2;endpoint++){
  ready();write_srb(&s,&q,Buffer,endpoint?0x579FF:0x17A00,0,0);submit(&s);run_worker();
  assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.Scope.SystemWrites==1&&Adapter.Scope.SystemWriteBytes==4096);
 }pass("system_fat_prefix_first_and_last_sector_writable_with_subset_accounting");
 for(U32 start=0;start<3;start++){
  ready();before=Submits;write_srb(&s,&q,Buffer,(U32[]){0x179FF,0x579F1,0x57A00}[start],0,0);s.Cdb[8]=16;s.DataTransferLength=65536;
  submit(&s);assert(s.ScsiStatus==2&&Submits==before&&!DataWrites);
  assert(!NufScopeContains(&Adapter.Scope,(U32[]){0x179FF,0x579F1,0x57A00}[start],65536));
 }pass("system_whole_srb_cross_prefix_start_end_and_physical_partition_tail_denied_before_write");
 ready();write_srb(&s,&q,Buffer,0x17B00,0,0);s.Cdb[8]=16;s.DataTransferLength=65536;
 submit(&s);PartialDma=3;run_worker();assert(s.ScsiStatus==2&&!s.DataTransferLength&&DataWrites==3&&Adapter.Scope.SystemWrites==0&&Adapter.Engine.Quarantined);
 assert(Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&Adapter.Stop&&!Adapter.Scope.Ready);
 before=Submits;write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);assert(s.ScsiStatus==2&&Submits==before);
 pass("system_partial_write_uncertainty_disables_both_extents_without_retry_or_false_restore");
 ready();write_srb(&s,&q,Buffer,0x17B00,1,1);FaultOpcode=0x35;CommandFault=1;submit(&s);run_worker();
 assert(s.ScsiStatus==2&&!s.DataTransferLength&&Adapter.Scope.SystemWrites==1&&!Adapter.Scope.FuaWrites&&!Adapter.Scope.Flushes);
 assert(Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&Adapter.Stop&&!Adapter.Scope.Ready);
 pass("system_fua_failed_flush_keeps_dirty_uncertainty_and_never_claims_persistence");
 ready();write_srb(&s,&q,Buffer,0x17B00,0,0);submit(&s);run_worker();assert(Adapter.Scope.CacheDirty);
 pnp(&pn,StorRemoveDevice,1);run_worker();assert(pn.SrbStatus==SRB_STATUS_SUCCESS&&Flushes==1&&!Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain&&!ActiveMaps);
 pass("system_dirty_normal_removal_flushes_before_owned_session_retirement");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);s.Cdb[8]=16;s.DataTransferLength=65536;
 submit(&s);PartialDma=3;run_worker();
 assert(s.ScsiStatus==2&&!s.DataTransferLength&&DataWrites==3&&Adapter.Scope.Writes==0&&Adapter.Scope.WriteBytes==0&&Adapter.Engine.Quarantined);
 assert(!Flushes&&!Readbacks&&Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&Adapter.Stop&&!Adapter.Scope.Ready);
 before=Submits;write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);assert(Submits==before&&s.ScsiStatus==2);
 pass("partial_dma_failed_command_has_zero_confirmed_blocks_no_success_or_retry");
 U32 denied[]={0,1,0x179FF,0x57A00,0x57B00,0x2221FF,0x1222200,LAST};
 for(U32 i=0;i<sizeof(denied)/sizeof(*denied);i++){ready();before=Submits;write_srb(&s,&q,Buffer,denied[i],0,0);submit(&s);assert(s.ScsiStatus==2&&Submits==before&&!DataWrites);}
 ready();before=Submits;write_srb(&s,&q,Buffer,0x12221FF,0,0);s.Cdb[8]=2;s.DataTransferLength=8192;
 submit(&s);assert(s.ScsiStatus==2&&Submits==before&&!DataWrites);
 pass("whole_write_span_fence_prevents_partial_out_of_range_write");
 for(U32 i=0;i<2;i++){ready();write_srb(&s,&q,Buffer,i?0x12221FF:0x222200,0,0);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&DataWrites==1);}
 ready();assert(NufScopeContains(&Adapter.Scope,0x12221F0,65536)&&!NufScopeContains(&Adapter.Scope,0x12221F1,65536));
 assert(!NufScopeWrite(&Adapter.Engine,&Adapter.Scope,&Adapter.ScopeWork,0x222300,Buffer,69632)&&!DataWrites);
 pass("ntfs_endpoints_full_span_and_bounded_multiblock_physical_contract");
 ready();for(U32 n=0;n<270;n++){write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS);}
 assert(Adapter.Scope.Writes==270&&!Adapter.Stop&&WorkerAllocated==271&&WorkerFreed==270&&WorkerLive==1);
 pass("tag_wrap_reuses_only_acknowledged_retired_slot_without_session_budget");
 ready();for(U32 fn=0;fn<4;fn++){
  write_srb(&s,&q,Buffer,0x222300+fn,0,0);submit(&s);run_worker();assert(Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain);
  memset(&s,0,sizeof(s));memset(&q,0,sizeof(q));s.SrbExtension=&q;
  if(fn<2){s.Function=SRB_FUNCTION_EXECUTE_SCSI;s.CdbLength=fn?16:10;s.Cdb[0]=fn?0x91:0x35;}
  else{s.Function=fn==2?SRB_FUNCTION_FLUSH:SRB_FUNCTION_SHUTDOWN;s.SrbFlags=s.DataTransferLength=~0U;}
  submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Stop&&Adapter.Scope.Ready&&!Adapter.Scope.CacheDirty);
  assert(BarrierSeenWrites==fn+1&&CompletionSeenFlushes==fn+1);
 }
 assert(Flushes==4);read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS);
 pass("sync10_sync16_flush_shutdown_drain_prior_cached_writes_and_later_io_valid");
 for(U32 f=1;f<=4;f++){ready();FaultOpcode=0x2A;CommandFault=f;
  write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();assert(s.ScsiStatus==2&&!Adapter.Scope.Ready&&!Adapter.Scope.Writes&&Adapter.Stop&&Adapter.Scope.WriteUncertain);
  before=Submits;submit(&s);assert(Submits==before);}
 pass("write_timeout_guard_tag_ocs_faults_terminal_no_retry_or_readback");
 for(U32 f=1;f<=4;f++){ready();FaultOpcode=0x35;CommandFault=f;
  write_srb(&s,&q,Buffer,0x222300,0,1);s.Cdb[8]=16;s.DataTransferLength=65536;submit(&s);run_worker();
  assert(s.ScsiStatus==2&&!s.DataTransferLength&&DataWrites==16&&Adapter.Scope.Writes==16&&!Adapter.Scope.FuaWrites);
  assert(!Adapter.Scope.Flushes&&!Readbacks&&Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&Adapter.Stop&&!Adapter.Scope.Ready);
  before=Submits;write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);assert(Submits==before&&s.ScsiStatus==2);
 }
 pass("fua_final_flush_fault_never_claims_fua_persistence_or_srb_success");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();
 memset(&s,0,sizeof(s));memset(&q,0,sizeof(q));s.Function=SRB_FUNCTION_FLUSH;s.SrbExtension=&q;
 FaultOpcode=0x35;CommandFault=1;submit(&s);run_worker();
 assert(s.ScsiStatus==2&&Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&Adapter.Stop&&!Adapter.Scope.Flushes);
 pass("explicit_flush_failure_preserves_dirty_uncertainty_and_fails_closed");
 ready();memset(&s,0,sizeof(s));memset(&q,0,sizeof(q));s.Function=SRB_FUNCTION_FLUSH;s.SrbExtension=&q;
 submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Flushes==1&&!Adapter.Scope.CacheDirty);
 pass("explicit_flush_reaches_hardware_even_when_software_cache_is_clean");
 ready();Fault=1;read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.ScsiStatus==2&&Adapter.Stop&&Adapter.IoReport.Quarantined&&Adapter.Report.RuntimeCompleted==0);
 pass("read_timeout_no_completed_bytes_and_quarantined_ownership");
 ready();WorkerQueueStatus=STOR_STATUS_BUSY;before=Submits;write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);
 assert(!s.ScsiStatus&&s.SrbStatus==SRB_STATUS_BUSY&&Submits==before&&!Adapter.Stop&&Adapter.Scope.Ready&&ActiveMaps==4);
 pass("queue_failure_no_hidden_write_retry_or_async_mapping_release");
 ready();WorkerInitStatus=STOR_STATUS_INSUFFICIENT_RESOURCES;before=Submits;
 read_srb(&s,&q,Buffer,0);submit(&s);
 assert(!s.ScsiStatus&&s.SrbStatus==SRB_STATUS_BUSY&&!Adapter.Stop&&Adapter.Scope.Ready&&!q.Worker&&Submits==before&&WorkerLive==1&&!WorkerQueued);
 pass("io_worker_allocation_failure_completes_without_hardware_or_leaked_request_worker");
 ready();read_srb(&s,&q,Buffer,0);s.Cdb[1]=0xFF;before=Submits;submit(&s);
 assert(s.ScsiStatus==2&&!q.Worker&&Submits==before&&WorkerFreed==0&&WorkerLive==1&&!Adapter.Stop);
 read_srb(&s,&q,Buffer,0);Adapter.Busy=1;submit(&s);Adapter.Busy=0;
 assert(s.SrbStatus==SRB_STATUS_BUSY&&!q.Worker&&WorkerFreed==0&&WorkerLive==1&&!Adapter.Stop);
 pass("invalid_and_busy_srb_allocate_no_worker_before_completion");
 /* Same SRB StartIo retry, deliberately without a second BuildIo. */
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;run_worker();
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Stop&&Adapter.Scope.Ready&&!q.Worker);
 pass("same_srb_busy_resubmit_without_buildio_recreates_worker_safely");
 ready();read_srb(&s,&q,Buffer,0);WorkerInitStatus=STOR_STATUS_INSUFFICIENT_RESOURCES;submit(&s);
 assert(s.SrbStatus==SRB_STATUS_BUSY&&!Adapter.Stop);WorkerInitStatus=STOR_STATUS_SUCCESS;
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Stop);
 pass("temporary_worker_shortage_recovers_without_adapter_stop_or_hardware_retry");
 ready();read_srb(&s,&q,Buffer,0);WorkerQueueStatus=STOR_STATUS_BUSY;submit(&s);
 assert(s.SrbStatus==SRB_STATUS_BUSY&&!q.Worker&&!Adapter.Stop);WorkerQueueStatus=STOR_STATUS_SUCCESS;
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Stop);
 pass("unqueued_worker_busy_resubmission_has_fresh_worker_and_no_dma_replay");

 ready();read_srb(&s,&q,Buffer,0);submit(&s);WorkerFreeStatus=STOR_STATUS_INVALID_PARAMETER;run_worker();
 assert(s.ScsiStatus==2&&!s.DataTransferLength&&!q.Worker&&Adapter.OrphanWorker&&Adapter.Stop&&WorkerLive==2);
 assert(Adapter.Scope.FirstReason==NufScopeWorker&&Adapter.Report.SessionState==3);
 pass("executing_io_worker_release_failure_is_terminal_and_never_full_success");
 ready();stop();assert(Adapter.PowerStopped&&!Adapter.Stop&&ActiveMaps==4&&WorkerLive==1&&Adapter.Claimed&&!Adapter.Engine.SessionActive);
 before=Submits;read_srb(&s,&q,Buffer,0x222300);submit(&s);assert(s.ScsiStatus==2&&Submits==before);
 Irql=3;assert(Control(&Adapter,ScsiRestartAdapter,NULL)==ScsiAdapterControlSuccess);Irql=0;
 assert(!Adapter.PowerStopped&&Adapter.Engine.SessionActive);read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&MapCalls==4&&WorkerAllocated==2&&WorkerFreed==1&&WorkerLive==1);
 pass("dirql_stop_restart_no_clock_wait_map_free_or_new_worker");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();before=Submits;
 stop();assert(Adapter.Stop&&Adapter.PowerStopped&&Adapter.Scope.CacheDirty&&Submits==before&&!Flushes&&Adapter.Engine.SessionActive);
 pass("dirty_dirql_stop_refuses_clean_retirement_without_attempting_passive_flush");
 ready();unsigned noticeReads=Reads,noticeWrites=Writes,noticeQueues=WorkerQueued;initialized=Adapter.Engine.DmaInitBytes;
 pnp(&pn,StorStopDevice,1);
 assert(pn.SrbStatus==SRB_STATUS_SUCCESS&&Reads==noticeReads&&Writes==noticeWrites&&WorkerQueued==noticeQueues);
 assert(!Adapter.Stop&&!Adapter.PowerStopped&&Adapter.Scope.Ready&&ActiveMaps==4&&WorkerLive==1&&Adapter.Claimed&&Adapter.Engine.SessionActive);
 /* The port's final FLUSH remains legal after the stop notification. */
 memset(&s,0,sizeof(s));memset(&q,0,sizeof(q));s.Function=SRB_FUNCTION_FLUSH;s.SrbExtension=&q;
 submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&Flushes==1);
 stop();noticeReads=Reads;noticeWrites=Writes;U64 noticeTime=Now;
 stop();assert(Reads==noticeReads&&Writes==noticeWrites&&Now==noticeTime&&!Adapter.Stop&&Adapter.Engine.Stopped);
 pnp(&pn,StorStartDevice,1);assert(pn.SrbStatus==SRB_STATUS_SUCCESS&&Adapter.PowerStopped&&!Adapter.Engine.SessionActive);
 read_srb(&s,&q,Buffer,0x222300);before=Submits;submit(&s);assert(s.ScsiStatus==2&&Submits==before);
 Irql=3;assert(Control(&Adapter,ScsiRestartAdapter,NULL)==ScsiAdapterControlSuccess);Irql=0;
 pnp(&pn,StorStartDevice,1);assert(pn.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.PowerStopped&&Adapter.Engine.SessionActive);
 read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS);
 assert(MapCalls==4&&!UnmapCalls&&WorkerAllocated==3&&WorkerFreed==2&&WorkerLive==1&&Adapter.Engine.DmaInitBytes==initialized&&((N976N_UFS_HANDOFF*)Lease)->ClaimState==1);
 pass("pnp_stop_notice_preserves_final_flush_then_control_stop_start_reuses_retained_session");
 ready();stop();assert(initialize()&&!Adapter.PowerStopped&&Adapter.Engine.SessionActive&&ActiveMaps==4&&WorkerAllocated==1);
 noticeReads=Reads;noticeWrites=Writes;noticeTime=Now;assert(initialize());
 Irql=3;assert(Control(&Adapter,ScsiRestartAdapter,NULL)==ScsiAdapterControlSuccess);Irql=0;
 assert(Reads==noticeReads&&Writes==noticeWrites&&Now==noticeTime&&EnableCalls==1);
 pass("same_resource_hw_initialize_restarts_clean_stop_and_active_restart_is_idempotent");
 ready();stop();Lease[4000]^=1;noticeReads=Reads;noticeWrites=Writes;
 Irql=3;assert(Control(&Adapter,ScsiStopAdapter,NULL)==ScsiAdapterControlUnsuccessful);Irql=0;
 assert(Adapter.Stop&&Adapter.Report.RuntimeQuarantined&&Reads==noticeReads&&Writes==noticeWrites);
 pnp(&pn,StorStartDevice,1);assert(pn.SrbStatus==SRB_STATUS_NO_DEVICE&&!initialize()&&Adapter.PowerStopped);
 ready();remove_clean();pnp(&pn,StorStartDevice,1);assert(pn.SrbStatus==SRB_STATUS_NO_DEVICE&&!initialize()&&!ActiveMaps&&!WorkerLive);
 setup();find();WorkerInitStatus=STOR_STATUS_INSUFFICIENT_RESOURCES;assert(initialize()&&!passive());assert(!initialize());
 pass("invalid_retained_or_removed_or_failed_instance_never_claims_start_or_duplicate_stop_success");
 ready();stop();Dma[0]^=1;Irql=3;assert(Control(&Adapter,ScsiRestartAdapter,NULL)==ScsiAdapterControlUnsuccessful);Irql=0;assert(Adapter.Stop&&Adapter.Report.RuntimeQuarantined);
 pass("corrupted_stopped_session_cannot_restart_or_reinitialize_away_evidence");
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);stop();before=Submits;run_worker();assert(s.ScsiStatus==2&&Submits==before&&Adapter.Stop);
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);StopAt=2;run_worker();assert(s.ScsiStatus==2&&Adapter.Stop);
 pass("unexpected_stop_before_or_during_active_request_never_claims_clean_retirement");
 ready();before=Submits;pnp(&pn,StorRemoveDevice,0);assert(pn.SrbStatus==SRB_STATUS_SUCCESS&&ActiveMaps==4&&WorkerLive==1&&Submits==before);
 assert(pn.DataTransferLength==0xABABABAB&&pn.PnPSubFunction==0xAB&&pn.Reserved==0xABABABAB);
 pass("lun_pnp_does_not_release_adapter_or_overwrite_ignored_fields");
 ready();remove_clean();assert(UnmapCalls==4&&WorkerFreed==1);
 pass("adapter_remove_passive_retirement_before_unmap_worker_free_completion");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();assert(Adapter.Scope.CacheDirty);
 remove_clean();assert(Flushes==1&&BarrierSeenWrites==1&&!Adapter.Scope.CacheDirty&&!Adapter.Scope.WriteUncertain);
 pass("normal_remove_flushes_cached_writes_before_session_retirement");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();
 FaultOpcode=0x35;CommandFault=1;pnp(&pn,StorRemoveDevice,1);run_worker();
 assert(pn.SrbStatus==SRB_STATUS_ERROR&&!ActiveMaps&&Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain&&((N976N_UFS_HANDOFF*)Lease)->ClaimState==3);
 pass("normal_remove_flush_failure_cannot_claim_clean_ownership_release");
 ready();stop();remove_clean();
 pass("adapter_remove_after_power_stop_releases_retained_resources");
 ready();unsigned reads=Reads,writes=Writes;pnp(&pn,StorSurpriseRemoval,1);run_worker();
 assert(pn.SrbStatus==SRB_STATUS_ERROR&&Reads==reads&&Writes==writes&&!ActiveMaps&&!WorkerLive&&((N976N_UFS_HANDOFF*)Lease)->ClaimState==3);
 pass("surprise_remove_never_touches_mmio_quarantines_reserved_dma");
 ready();write_srb(&s,&q,Buffer,0x222300,0,0);submit(&s);run_worker();reads=Reads;writes=Writes;
 pnp(&pn,StorSurpriseRemoval,1);run_worker();
 assert(pn.SrbStatus==SRB_STATUS_ERROR&&Reads==reads&&Writes==writes&&Adapter.Scope.CacheDirty&&Adapter.Scope.WriteUncertain);
 pass("surprise_remove_cached_writes_keeps_uncertainty_without_new_mmio");
 ready();pnp(&pn,StorRemoveDevice,1);WorkerFreeStatus=STOR_STATUS_INVALID_PARAMETER;run_worker();
 assert(pn.SrbStatus==SRB_STATUS_ERROR&&Adapter.OrphanWorker&&!ActiveMaps);
 pass("worker_release_failure_not_reported_as_success");
 ready();NUF_CONFIG cfg=Adapter.Engine.Config;
 assert(NufWriteRangeAllowed(&cfg,0x222200,4096)&&NufWriteRangeAllowed(&cfg,0x222200,8192));
 cfg.WriteBlocks++;assert(!NufWriteRangeAllowed(&cfg,0x222200,4096));
 cfg=Adapter.Engine.Config;assert(NufWriteRangeAllowed(&cfg,0x17A00,4096)&&NufWriteRangeAllowed(&cfg,0x579FF,4096));
 assert(!NufWriteRangeAllowed(&cfg,0x179FF,4096)&&!NufWriteRangeAllowed(&cfg,0x57A00,4096)&&!NufWriteRangeAllowed(&cfg,0x199DFF,4096));
 cfg.SystemWriteBlocks++;assert(!NufWriteRangeAllowed(&cfg,0x17A00,4096)&&!NufWriteRangeAllowed(&cfg,0x222200,4096));
 assert(sizeof(NUF_REPORT)==720&&sizeof(NUF_SCOPE_REPORT)==352);
 r=scope_query();assert(r.Version==3&&r.Bytes==352&&r.CompletionPolicy==1&&!r.Readbacks&&!r.CacheDirty);
 _Alignas(8) U8 oldPacket[384]={0};SRB_IO_CONTROL *oldControl=(void*)oldPacket;
 oldControl->HeaderLength=28;oldControl->Length=356;oldControl->ControlCode=NUF_SCOPE_CONTROL;memcpy(oldControl->Signature,"N976UFS",8);
 NUF_SCOPE_REPORT *oldReport=(void*)(oldPacket+32);oldReport->Magic=NUF_SCOPE_MAGIC;oldReport->Version=1;oldReport->Bytes=352;
 memset(&s,0,sizeof(s));s.Function=SRB_FUNCTION_IO_CONTROL;s.DataBuffer=oldPacket;s.DataTransferLength=sizeof(oldPacket);
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;assert(s.SrbStatus==SRB_STATUS_INVALID_REQUEST&&oldReport->Version==1);
 oldControl->Length=252;oldReport->Bytes=248;s.DataTransferLength=280;Irql=2;assert(StartIo(&Adapter,&s));Irql=0;
 assert(s.SrbStatus==SRB_STATUS_INVALID_REQUEST&&oldReport->Version==1);
 oldControl->Length=260;oldReport->Version=2;oldReport->Bytes=256;s.DataTransferLength=288;
 Irql=2;assert(StartIo(&Adapter,&s));Irql=0;assert(s.SrbStatus==SRB_STATUS_INVALID_REQUEST&&oldReport->Version==2);
 pass("independent_dual_physical_write_fences_and_scope_v3_report_reject_v1_v2");
 ready();unsigned lazyAlloc=WorkerAllocated;
 read_srb(&s,&q,Buffer,0x222300);s.Cdb[8]=0;s.DataTransferLength=0;
 Irql=2;assert(BuildIo(&Adapter,&s));assert(!q.Worker&&WorkerAllocated==lazyAlloc);assert(StartIo(&Adapter,&s));Irql=0;
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&WorkerAllocated==lazyAlloc);
 read_srb(&s,&q,Buffer,0x222300);s.Cdb[1]=0xFF;submit(&s);
 assert(s.ScsiStatus==2&&WorkerAllocated==lazyAlloc);
 read_srb(&s,&q,Buffer,0x222300);Adapter.Busy=1;submit(&s);Adapter.Busy=0;
 assert(s.SrbStatus==SRB_STATUS_BUSY&&WorkerAllocated==lazyAlloc);
 pass("lazy_worker_allocation_only_after_valid_nonempty_idle_request_admission");
 ready();
 for(unsigned i=0;i<3;i++){
  read_srb(&s,&q,Buffer,0x222300);
  submit(&s);PerfTick+=100;run_worker();
  assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Engine.PerfClock&&!Adapter.Engine.ControlGuard32&&!Adapter.Engine.ControlWaitLegacy);
 }
 NUF_PERF_BIN *fast=&Adapter.Perf.Bin[PerfRead4K],*control=&Adapter.Perf.Bin[PerfRead4KControl];
 assert(Adapter.Perf.Frequency==1000000&&Adapter.Perf.QueueAttempts[PerfRead4K]==3);
 assert(Adapter.Perf.Version==8&&Adapter.Perf.WriteWindowUs==1000&&Adapter.Perf.FlushWindowUs==1000&&Adapter.Perf.GuardPolicy==NUF_RUNTIME_GUARD_POLICY&&Adapter.Perf.RangeVersion==2&&Adapter.Perf.ReadWindowUs==1000&&Adapter.Perf.LegacyWindowUs==100&&Adapter.Perf.PollStepUs==10);
 assert(fast->Samples==1&&control->Samples==0&&fast->QueueTicks==120);
 assert(fast->GuardBytes&&fast->GuardLoads&&!control->GuardBytes&&!control->GuardLoads);
 assert(fast->WaitSamples==1&&control->WaitSamples==0&&fast->DoneBeforeSleep==1&&control->DoneBeforeSleep==0);
 assert(fast->DeviceTicks==10&&fast->PrepareTicks&&fast->FinishTicks&&fast->GuardTicks);
 assert(fast->QueueTicks+fast->PrepareTicks+fast->DeviceTicks+fast->FinishTicks==fast->MaxTotalTicks);
 assert(!fast->BetweenTicks&&!fast->FailedSamples&&!fast->RejectedSamples);
 unsigned issued=Submits;U64 fastLoads=fast->GuardLoads;
 for(unsigned i=3;i<66;i++){
  read_srb(&s,&q,Buffer,0x222300);submit(&s);
  assert(q.Sample==(i==65));
  if(q.Sample)assert(q.Bin==PerfRead4K);
  run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS);
 }
 assert(Submits==issued+63&&control->GuardLoads==0&&fast->GuardLoads==2*fastLoads+(NUF_RUNTIME_GUARD_POLICY==NUF_GUARD_CYCLIC?512:0));
 assert(Adapter.Engine.GuardPolicy==NUF_RUNTIME_GUARD_POLICY);
 if(NUF_RUNTIME_GUARD_POLICY==NUF_GUARD_FULL)pass("perf3_4k_sampling_one_in_65_full_guard_coverage_no_extra_transfers");
 else {assert(Adapter.Engine.GuardSweepSteps==66&&Adapter.Engine.GuardCursor==2);
  pass("prod1_4k_sampling_one_in_65_cyclic_guard_policy_no_extra_transfers");}
 ready();
 for(unsigned i=0;i<66;i++){
  read_srb(&s,&q,Buffer,0x222300);s.Cdb[8]=16;s.DataTransferLength=65536;submit(&s);
  assert(q.Sample==(i==0||i==65));
  if(q.Sample)assert(q.Bin==PerfReadLarge);
  run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS&&!Adapter.Engine.ControlWaitLegacy);
 }
 fast=&Adapter.Perf.Bin[PerfReadLarge];control=&Adapter.Perf.Bin[PerfReadLargeControl];
 assert(fast->Samples==2&&control->Samples==0&&fast->Bytes==131072&&control->Bytes==0);
 assert(fast->WaitSamples==2&&control->WaitSamples==0&&fast->GuardLoads&&!control->GuardLoads);
 pass("perf3_large_sampling_one_in_65_reserved_controls_zero");
 ready();CompletionDelayUs=500;SleepExtraUs=5000;
 for(U32 i=0;i<2;i++){
  read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();assert(s.SrbStatus==SRB_STATUS_SUCCESS);
 }
 fast=&Adapter.Perf.Bin[PerfRead4K];control=&Adapter.Perf.Bin[PerfRead4KControl];
 assert(fast->Samples==1&&!control->Samples&&fast->DoneBeforeSleep==1&&!fast->SleepCalls&&fast->StallCalls);
 assert(!Adapter.Engine.WaitSleeps&&!Adapter.Engine.ControlWaitLegacy);
 assert(!fast->RejectedSamples&&!control->RejectedSamples&&!fast->FailedSamples&&!control->FailedSamples);
 pass("all_runtime_reads_use_new_window_without_legacy_oversleep_control");
 ready();write_srb(&s,&q,Buffer,0x222300,0,1);submit(&s);run_worker();
 NUF_PERF_BIN *fua=&Adapter.Perf.Bin[PerfFua4K];
 assert(fua->Samples==1&&fua->Bytes==4096&&fua->DeviceTicks==20&&fua->BetweenTicks&&Flushes==1&&fua->WaitSamples==2);
 assert(Adapter.Engine.PerfWait[0].WindowUs==1000&&Adapter.Engine.PerfWait[1].WindowUs==1000);
 assert(fua->MaxTotalTicks==fua->QueueTicks+fua->PrepareTicks+fua->DeviceTicks+fua->BetweenTicks+fua->FinishTicks);
 memset(&s,0,sizeof(s));memset(&q,0,sizeof(q));s.Function=SRB_FUNCTION_FLUSH;s.SrbExtension=&q;
 submit(&s);run_worker();
 NUF_PERF_BIN *flush=&Adapter.Perf.Bin[PerfFlush];
 assert(flush->Samples==1&&!flush->BetweenTicks&&flush->DeviceTicks==10&&!flush->Bytes&&Flushes==2&&flush->WaitSamples==1);
 pass("fua_and_standalone_flush_record_actual_command_intervals");
 ready();fast=&Adapter.Perf.Bin[PerfRead4K];RejectPerfClock=1;read_srb(&s,&q,Buffer,0x222300);submit(&s);run_worker();RejectPerfClock=0;
 assert(s.SrbStatus==SRB_STATUS_SUCCESS&&fast->RejectedSamples==1&&!fast->Samples&&!Adapter.Engine.PerfClock);
 ready();read_srb(&s,&q,Buffer,0x222300);submit(&s);Dma[0]^=1;run_worker();
 assert(s.ScsiStatus==2&&fast->FailedSamples==1&&!fast->Samples&&Adapter.Stop&&!Adapter.Engine.PerfClock);
 pass("invalid_performance_clock_is_diagnostic_only_and_failed_storage_is_never_a_latency_sample");

 return 0;
}

#endif /* NUF_EXPECT_LEGACY_BUSY */
