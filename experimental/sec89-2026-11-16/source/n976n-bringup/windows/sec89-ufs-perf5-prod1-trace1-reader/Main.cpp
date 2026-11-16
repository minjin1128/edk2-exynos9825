// SPDX-License-Identifier: BSD-2-Clause-Patent
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <setupapi.h>
#include <winioctl.h>
#include <ntddscsi.h>
#include <cstdio>
#include <cstring>
#include <cwchar>
#include <string>
#include <vector>
#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <initializer_list>
#include "N976nUfsTrace.h"
static const GUID StoragePort={0x2accfe60,0xc130,0x11d2,{0xb0,0x82,0x00,0xa0,0xc9,0x1e,0xfb,0x8b}};
static const char *Kinds[]={"READ4K","READlarge","WRITE4K","WRITElarge","FUA4K","FUAlarge","FLUSH"};
static_assert(sizeof(SRB_IO_CONTROL)==28,"wire header");
static_assert(sizeof(NUF_TRACE_SNAPSHOT)==27160&&sizeof(NUF_TRACE_RECORD)==200,"TRACE1 ABI");
struct Handle{HANDLE h=INVALID_HANDLE_VALUE;explicit Handle(HANDLE x):h(x){}~Handle(){if(h!=INVALID_HANDLE_VALUE&&h)CloseHandle(h);}Handle(const Handle&)=delete;};
static void Need(bool yes,const char *why){if(!yes)throw std::runtime_error(why);}
static bool MultiHas(const wchar_t *p,size_t count,const wchar_t *wanted){
 size_t at=0;bool found=false;
 while(at<count&&p[at]){size_t end=at;while(end<count&&p[end])end++;if(end==count)return false;
  if(!_wcsicmp(p+at,wanted))found=true;at=end+1;}
 if(at>=count)return false;for(;at<count;at++)if(p[at])return false;return found;
}
static std::wstring Discover(){
 HDEVINFO set=SetupDiGetClassDevsW(&StoragePort,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
 Need(set!=INVALID_HANDLE_VALUE,"StoragePort enumeration failed");std::wstring path;unsigned matches=0;bool complete=false;
 try{for(DWORD i=0;i<128;i++){
  SP_DEVICE_INTERFACE_DATA face={};face.cbSize=sizeof(face);
  if(!SetupDiEnumDeviceInterfaces(set,nullptr,&StoragePort,i,&face)){Need(GetLastError()==ERROR_NO_MORE_ITEMS,"Incomplete enumeration");complete=true;break;}
  DWORD bytes=0;SetupDiGetDeviceInterfaceDetailW(set,&face,nullptr,0,&bytes,nullptr);
  Need(bytes>=sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)&&bytes<=16384,"Invalid interface length");
  std::vector<unsigned char> buffer(bytes);auto detail=reinterpret_cast<PSP_DEVICE_INTERFACE_DETAIL_DATA_W>(buffer.data());detail->cbSize=sizeof(*detail);
  SP_DEVINFO_DATA dev={};dev.cbSize=sizeof(dev);
  Need(SetupDiGetDeviceInterfaceDetailW(set,&face,detail,bytes,nullptr,&dev)!=FALSE,"Interface detail failed");
  wchar_t ids[4096]={},service[128]={};DWORD type=0,n=0;
  if(!SetupDiGetDeviceRegistryPropertyW(set,&dev,SPDRP_HARDWAREID,&type,reinterpret_cast<PBYTE>(ids),sizeof(ids),&n))continue;
  if(type!=REG_MULTI_SZ||n>sizeof(ids)||n%sizeof(wchar_t)||!MultiHas(ids,n/sizeof(wchar_t),L"ACPI\\NNUF0078"))continue;
  Need(SetupDiGetDeviceRegistryPropertyW(set,&dev,SPDRP_SERVICE,&type,reinterpret_cast<PBYTE>(service),sizeof(service),&n)!=FALSE,"UFS service unavailable");
  Need(type==REG_SZ&&n==sizeof(L"N976nUfs")&&n<=sizeof(service)&&service[n/2-1]==0&&!_wcsicmp(service,L"N976nUfs"),"Unexpected UFS service");
  Need(wmemchr(detail->DevicePath,0,(bytes - offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W,DevicePath))/2)!=nullptr,"Unterminated path");
  path=detail->DevicePath;matches++;
 }}catch(...){SetupDiDestroyDeviceInfoList(set);throw;}
 SetupDiDestroyDeviceInfoList(set);Need(complete&&matches==1,"Expected one ACPI NNUF0078 / N976nUfs StoragePort");return path;
}
static bool Sum(std::initializer_list<NUF_T64> values,NUF_T64&total){total=0;for(auto n:values){if(n>~NUF_T64(0)-total)return false;total+=n;}return true;}
static bool Valid(const NUF_TRACE_SNAPSHOT&s){
 if(!NufTraceHeaderValid(&s)||s.RecordCount!=(s.Published<NUF_TRACE_CAPACITY?s.Published:NUF_TRACE_CAPACITY)||s.NextRecord!=s.Published%NUF_TRACE_CAPACITY)return false;NUF_T64 attempts=0,selected=0;
 for(unsigned k=0;k<NUF_TRACE_BINS;k++){
  const auto &b=s.Bin[k];if(!Sum({attempts,b.Attempts},attempts)||!Sum({selected,b.Selected},selected))return false;NUF_T64 total=0;
  if(!Sum({b.Valid,b.Failed,b.Invalid},total)||b.Selected!=total||b.Selected>b.Attempts)return false;
  if(!Sum({b.QueueTicks,b.PrepareTicks,b.DeviceTicks,b.BetweenTicks,b.FinishTicks},total)||b.TotalTicks!=total)return false;
  if(!Sum({b.GuardPreTicks,b.GuardPostTicks,b.ReadCopyTicks,b.WriteCopyTicks,b.DeviceTicks},total)||total>b.TotalTicks)return false;
 }
 if(attempts!=s.Attempts||selected!=s.Selected)return false;
 NUF_T64 previous=0;
 for(unsigned i=0;i<s.RecordCount;i++){
  const auto&r=s.Record[(s.NextRecord+NUF_TRACE_CAPACITY-s.RecordCount+i)%NUF_TRACE_CAPACITY];
  if(!r.Sequence||r.Sequence<=previous||r.Sequence>s.Attempts||r.Kind>=NUF_TRACE_BINS||r.Commands>2||r.Flags&~15U||r.Reserved[0]||r.Reserved[1])return false;
  previous=r.Sequence;
  if(!(r.Flags&7U)||!!(r.Flags&NUF_TRACE_TWO_COMMANDS)!=(r.Commands==2))return false;
  if(r.Flags&NUF_TRACE_VALID_TIMING){
   if(r.Flags&(NUF_TRACE_TIMING_INVALID|NUF_TRACE_STORAGE_FAILED)||!s.Frequency||!r.T0||r.Worker<r.T0||r.Commands!=((r.Kind==4||r.Kind==5)?2U:1U))return false;
   NUF_T64 last=r.Worker;for(unsigned j=0;j<r.Commands;j++){if(r.T1[j]<last||r.T2[j]<r.T1[j])return false;last=r.T2[j];}
   if(r.T3<last)return false;
  }
 }
 return true;
}
static NUF_TRACE_SNAPSHOT Query(HANDLE h){
 alignas(8) unsigned char packet[NUF_TRACE_WIRE_OFFSET+sizeof(NUF_TRACE_SNAPSHOT)]={};
 auto c=reinterpret_cast<SRB_IO_CONTROL*>(packet);c->HeaderLength=28;c->Timeout=2;c->ControlCode=NUF_TRACE_CONTROL;
 c->Length=sizeof(NUF_TRACE_SNAPSHOT)+4;c->ReturnCode=0xDEADBEEF;memcpy(c->Signature,"N976UFS",8);
 auto result=reinterpret_cast<NUF_TRACE_SNAPSHOT*>(packet+32);result->Magic=NUF_TRACE_MAGIC;result->Version=NUF_TRACE_VERSION;
 result->Bytes=sizeof(*result);result->Driver=NUF_TRACE_DRIVER;
 OVERLAPPED ov={};Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));Need(event.h!=nullptr,"Event creation failed");ov.hEvent=event.h;
 DWORD bytes=0;BOOL ok=DeviceIoControl(h,IOCTL_SCSI_MINIPORT,packet,sizeof(packet),packet,sizeof(packet),&bytes,&ov);
 if(!ok&&GetLastError()==ERROR_IO_PENDING){
  if(WaitForSingleObject(event.h,1500)!=WAIT_OBJECT_0){
   CancelIoEx(h,&ov);
   if(WaitForSingleObject(event.h,1500)!=WAIT_OBJECT_0){fputs("STOP: query cancellation not retired; exiting reader.\n",stderr);fflush(stderr);ExitProcess(ERROR_TIMEOUT);}
   (void)GetOverlappedResult(h,&ov,&bytes,FALSE);throw std::runtime_error("Query timed out; no retry");
  }
  ok=GetOverlappedResult(h,&ov,&bytes,FALSE);
 }
 Need(ok!=FALSE,"UFS snapshot query failed (BUSY/disconnected/wrong driver); no automatic retry");
 Need(bytes==sizeof(packet)&&c->HeaderLength==28&&c->Length==sizeof(*result)+4&&c->ControlCode==NUF_TRACE_CONTROL&&
      !memcmp(c->Signature,"N976UFS",8)&&!c->ReturnCode&&!memcmp(packet+28,"\0\0\0\0",4)&&Valid(*result),"Invalid/incomplete TRACE1 response");
 return *result;
}
static void FileIo(HANDLE f,void *data,DWORD size,bool writing){
 OVERLAPPED ov={};Handle event(CreateEventW(nullptr,TRUE,FALSE,nullptr));Need(event.h!=nullptr,"File event creation failed");ov.hEvent=event.h;
 DWORD n=0;BOOL ok=writing?WriteFile(f,data,size,&n,&ov):ReadFile(f,data,size,&n,&ov);
 if(!ok&&GetLastError()==ERROR_IO_PENDING){
  if(WaitForSingleObject(event.h,5000)!=WAIT_OBJECT_0){
   CancelIoEx(f,&ov);
   if(WaitForSingleObject(event.h,1500)!=WAIT_OBJECT_0){fputs("STOP: file I/O retirement unconfirmed; preserve outputs.\n",stderr);fflush(stderr);ExitProcess(ERROR_TIMEOUT);}
   (void)GetOverlappedResult(f,&ov,&n,FALSE);throw std::runtime_error("File I/O timeout; preserve partial output");
  }
  ok=GetOverlappedResult(f,&ov,&n,FALSE);
 }
 Need(ok&&n==size,"File I/O failed/partial; preserve output");
}
static NUF_TRACE_SNAPSHOT Read(const wchar_t *path){
 Handle f(CreateFileW(path,GENERIC_READ,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OVERLAPPED,nullptr));Need(f.h!=INVALID_HANDLE_VALUE,"Cannot open snapshot");
 BY_HANDLE_FILE_INFORMATION info={};Need(GetFileInformationByHandle(f.h,&info)&&!(info.dwFileAttributes&(FILE_ATTRIBUTE_REPARSE_POINT|FILE_ATTRIBUTE_DIRECTORY))&&
  !info.nFileSizeHigh&&info.nFileSizeLow==sizeof(NUF_TRACE_SNAPSHOT),"Invalid snapshot file size/type");
 NUF_TRACE_SNAPSHOT s={};FileIo(f.h,&s,sizeof(s),false);Need(Valid(s),"Invalid TRACE1 snapshot");return s;
}
static void Write(const std::wstring&path,const void *data,DWORD size){
 Handle f(CreateFileW(path.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_ATTRIBUTE_NORMAL|FILE_FLAG_OPEN_REPARSE_POINT|FILE_FLAG_OVERLAPPED|FILE_FLAG_WRITE_THROUGH,nullptr));Need(f.h!=INVALID_HANDLE_VALUE,"Output already exists or cannot be created");
 FileIo(f.h,const_cast<void*>(data),size,true);
}
static void Enter(){
 DWORD mode=0;Need(GetConsoleMode(GetStdHandle(STD_INPUT_HANDLE),&mode)&&GetConsoleMode(GetStdHandle(STD_OUTPUT_HANDLE),&mode),"Session requires interactive console input/output");
 wchar_t line[4]={};DWORD n=0;Need(ReadConsoleW(GetStdHandle(STD_INPUT_HANDLE),line,4,&n,nullptr)&&n==2&&line[0]==L'\r'&&line[1]==L'\n',"Expected empty ENTER; EOF/text refused");
}
static bool Comparable(const NUF_TRACE_SNAPSHOT&a,const NUF_TRACE_SNAPSHOT&b){
 if(!Valid(a)||!Valid(b)||!a.InstanceQpc||!a.InstanceSystemTime||!a.Frequency||a.Frequency!=b.Frequency||
    a.InstanceQpc!=b.InstanceQpc||a.InstanceSystemTime!=b.InstanceSystemTime||b.Generation<a.Generation||
    b.Attempts<a.Attempts||b.Selected<a.Selected||b.Published<a.Published||
    b.GuardBytes<a.GuardBytes||b.GuardLoads<a.GuardLoads||b.ResetBytes<a.ResetBytes||b.SweepSteps<a.SweepSteps||
    b.WaitSleeps<a.WaitSleeps||b.WaitTimeouts<a.WaitTimeouts||b.InvalidTimings<a.InvalidTimings)return false;
 for(unsigned k=0;k<NUF_TRACE_BINS;k++){
  NUF_T64 x[sizeof(NUF_TRACE_BIN)/8],y[sizeof(NUF_TRACE_BIN)/8];memcpy(x,&a.Bin[k],sizeof(x));memcpy(y,&b.Bin[k],sizeof(y));
  for(unsigned j=0;j<sizeof(NUF_TRACE_BIN)/8;j++)if(y[j]<x[j])return false;
 }
 return true;
}
static std::string Summary(const NUF_TRACE_SNAPSHOT&b,const NUF_TRACE_SNAPSHOT*a=nullptr){
 if(a)Need(Comparable(*a,b),"NOT COMPARABLE: instance/frequency/generation/counters differ");
 std::ostringstream o;o<<std::fixed<<std::setprecision(6)<<"N976N PROD1 TRACE1 .89.2.6 / sample period 65\n";
 o<<(a?"INTERVAL (two RAM snapshots)":"CUMULATIVE")<<" / recorded="<<b.Published<<" retained="<<b.RecordCount<<" overwritten="<<b.Overwritten<<"\n";
 o<<"Times below are sampled means in ms; not p99 or hardware-only latency.\n";
 o<<"kind attempts selected valid failed invalid total queue prepare observed-device between finish guard-pre guard-post read-copy write-copy\n";
 for(unsigned k=0;k<NUF_TRACE_BINS;k++){
  NUF_TRACE_BIN d=b.Bin[k];if(a){NUF_T64 x[sizeof(d)/8],y[sizeof(d)/8];memcpy(x,&d,sizeof(d));memcpy(y,&a->Bin[k],sizeof(d));
   for(unsigned j=0;j<sizeof(d)/8;j++)x[j]-=y[j];memcpy(&d,x,sizeof(d));}
  o<<Kinds[k]<<" "<<d.Attempts<<" "<<d.Selected<<" "<<d.Valid<<" "<<d.Failed<<" "<<d.Invalid;
  NUF_T64 times[]={d.TotalTicks,d.QueueTicks,d.PrepareTicks,d.DeviceTicks,d.BetweenTicks,d.FinishTicks,d.GuardPreTicks,d.GuardPostTicks,d.ReadCopyTicks,d.WriteCopyTicks};
  for(auto t:times){if(d.Valid&&b.Frequency)o<<" "<<static_cast<double>(t)*1000.0/static_cast<double>(b.Frequency)/static_cast<double>(d.Valid);else o<<" NA";}o<<"\n";
 }
 o<<"Guard/copy are subsets of phases: do not add them again.\n";
 o<<"Observed-device includes polling, sleep and scheduling; Windows before StartIo/after notification is excluded.\n";
 o<<"Whole wait sleeps="<<(b.WaitSleeps-(a?a->WaitSleeps:0))<<" timeouts="<<(b.WaitTimeouts-(a?a->WaitTimeouts:0))<<"\n";
 return o.str();
}
int wmain(int argc,wchar_t**argv){
 try{
  if(argc==3&&!_wcsicmp(argv[1],L"show")){auto s=Read(argv[2]);fputs(Summary(s).c_str(),stdout);return 0;}
  if(argc==4&&!_wcsicmp(argv[1],L"diff")){auto a=Read(argv[2]),b=Read(argv[3]);fputs(Summary(b,&a).c_str(),stdout);return 0;}
  Need(argc==3&&(!_wcsicmp(argv[1],L"capture")||!_wcsicmp(argv[1],L"session")),"Usage: N976nUfsTrace.exe session NEW-DIR | capture NEW.bin | show FILE.bin | diff BEFORE.bin AFTER.bin");
  auto path=Discover();Handle h(CreateFileW(path.c_str(),GENERIC_READ|GENERIC_WRITE,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));
  Need(h.h!=INVALID_HANDLE_VALUE,"Cannot open UFS adapter; use Administrator console");
  if(!_wcsicmp(argv[1],L"capture")){auto s=Query(h.h);Write(argv[2],&s,sizeof(s));fputs(Summary(s).c_str(),stdout);return 0;}
  // Create the directory before BEFORE; no reader file writes occur inside the interval.
  Need(CreateDirectoryW(argv[2],nullptr)!=FALSE,"Session directory must be new");
  fputs("Press ENTER for BEFORE, then run the read benchmark.\n",stdout);Enter();
  auto before=Query(h.h);fputs("BEFORE kept in RAM. Run benchmark; press ENTER after it finishes.\n",stdout);
  NUF_TRACE_SNAPSHOT after={};std::wstring dir=argv[2];
  try{Enter();after=Query(h.h);}catch(...){Write(dir+L"\\before.bin",&before,sizeof(before));throw;}
  Write(dir+L"\\before.bin",&before,sizeof(before));Write(dir+L"\\after.bin",&after,sizeof(after));auto summary=Summary(after,&before);
  Write(dir+L"\\result.txt",summary.data(),static_cast<DWORD>(summary.size()));fputs(summary.c_str(),stdout);return 0;
 }catch(const std::exception&e){fprintf(stderr,"STOP: %s\n",e.what());return 2;}
}
