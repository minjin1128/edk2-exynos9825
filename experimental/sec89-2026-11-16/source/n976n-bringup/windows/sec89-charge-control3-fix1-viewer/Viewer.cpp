// SPDX-License-Identifier: MIT
// Read-only cached diagnostics. No charge command, source refresh or raw MMIO.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <setupapi.h>
#include <shellapi.h>
#include <winioctl.h>
#include <initguid.h>
#include <batclass.h>
#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cstddef>
#include "DiagProtocol.h"
static_assert(sizeof(NCD_QUERY)==40 && sizeof(NCD_REPORT)==848 && offsetof(NCD_REPORT,LastQuery)==360,"Diagnostic ABI");
static SRWLOCK Lock=SRWLOCK_INIT;
static NCD_REPORT Last={};
static DWORD Error=ERROR_NOT_READY;
static ULONGLONG Received=0;
static HWND Window;
static HANDLE Stop;
static const wchar_t* State(unsigned n){static const wchar_t* a[]={L"IDLE",L"CONFIGURING",L"MANAGED",L"MODE4 CONFIRMED",L"REFUSED",L"QUARANTINED"};return n<6?a[n]:L"UNKNOWN";}
static const wchar_t* Reason(unsigned n){static const wchar_t* a[]={L"none",L"argument",L"owner",L"stale",L"source",L"temperature",L"evidence",L"baseline",L"cancelled",L"I/O",L"readback",L"timed trial ended",L"reentrant",L"uncertain",L"full - reconnect required",L"3h safety limit"};return n<16?a[n]:L"unknown";}
static bool Valid(const NCD_REPORT&r){return r.Magic==NCD_MAGIC&&r.Version==NCD_VERSION&&r.Bytes==sizeof(r)&&r.Driver==NCD_DRIVER;}
static std::wstring Age(uint64_t now,uint64_t at){return !at||now<at?L"unknown":std::to_wstring((now-at)/10000)+L"ms";}
static std::wstring AgeMs(uint64_t now,uint64_t at){return !at||now<at?L"?":std::to_wstring(now-at);}
static std::wstring Limit(unsigned n){return n?std::to_wstring(n):L"?";}
static const wchar_t* Phase(unsigned n){static const wchar_t* a[]={L"none",L"rearm",L"start",L"kick1",L"CC",L"kick2",L"enable",L"service",L"stop",L"input"};return n<10?a[n]:L"?";}
static bool Fresh(uint64_t now,uint64_t at,uint64_t limit){return at&&now>=at&&now-at<limit;}
static std::wstring Text(const NCD_REPORT&r,DWORD error,ULONGLONG received,ULONGLONG now){
 std::wostringstream s;s<<L"N976N SEC89 CONTROL3 FIX1 / .606\n\n";
 if(error||!Valid(r)){s<<L"Waiting for exact battery driver / error 0x"<<std::hex<<error<<L"\n\nNo charging result has been established.\nThe viewer never starts or stops charging.\n";return s.str();}
 bool hostFresh=received&&now>=received&&now-received<3000;
 uint64_t elapsed=received&&now>=received?now-received:UINT64_MAX;
 uint64_t effectiveNow=elapsed<=(UINT64_MAX-r.Query100ns)/10000?r.Query100ns+elapsed*10000:0;
 s<<L"Report #"<<r.Sequence<<L" / "<<(hostFresh&&r.WorkerLive&&Fresh(effectiveNow,r.Published100ns,30000000)?L"worker recently published":L"STALE or worker stopped")<<L" / age "<<Age(effectiveNow,r.Published100ns)<<L"\n";
 s<<L"Stage/status/point "<<r.Stage<<L"/0x"<<std::hex<<r.Status<<std::dec<<L"/"<<r.Point<<L" / stop "<<r.StopRequested<<L" / samples/failures "<<r.Samples<<L"/"<<r.Failures<<L" / generation "<<r.Generation<<L"\n";
 s<<L"Control"<<(r.WorkerLive?L"":L" (last, frozen)")<<L": "<<State(r.ControlState)<<L" / "<<Reason(r.Reason)<<L" ("<<r.Reason<<L")\n";
 s<<L"Managed starts: "<<r.ManagedStarts<<L" / start calls "<<r.StartCalls<<L" / attempt "<<r.Attempt<<L"\n";
 s<<L"Policy continuous / attachment "<<r.Attachment<<L" / detaches "<<r.Detaches<<L" / signal "<<r.ConnectionSignal<<L" / fault "<<r.ConnectionFault<<L"\n";
 s<<L"Hold"<<(r.WorkerLive?L"":L" (last, frozen)")<<L": "<<Reason(r.HoldReason)<<L" / active age "<<AgeMs(r.Query100ns/10000,r.StartedMs)<<L"ms / safety 10800000ms\n";
 s<<L"Managed at "<<r.ManagedAtMs<<L"ms / stop at "<<r.StoppedMs<<L"ms (since boot)\n";
 s<<L"Stop readback MODE4: "<<r.Mode4Confirmed<<L" / uncertain "<<r.Uncertain<<L" / quarantine "<<r.Quarantined<<L"\n";
 s<<L"ICL setup"<<(r.WorkerLive?L"":L" (last, frozen)")<<L" "<<r.InputConfigured<<L" / writes "<<r.InputWrites<<L" / fallback100 "<<r.InputFallbackConfirmed<<L" / outstanding "<<r.InputTouched<<L"\n";
 s<<L"ICL before/after 0x"<<std::hex<<r.InputBefore<<L"/"<<r.InputAfter<<std::dec<<L" / at "<<r.InputAtMs<<L"ms / epoch "<<r.InputSourceEpoch<<L"\n";
 s<<L"Evidence/missing 0x"<<std::hex<<r.PreflightEvidence<<L"/"<<r.PreflightMissing<<std::dec<<L"\n";
 s<<L"Last preflight: "<<Reason(r.Preflight)<<L" ("<<r.Preflight<<L") / first reason "<<r.FirstReason<<L"\n\n";
 s<<L"QUARANTINE FIRST: site "<<r.QuarantineSite<<L" / at "<<r.QuarantineAt100ns/10000<<L"ms / sample "<<r.QuarantineBus.SampleId<<L" / reason 0x"<<std::hex<<r.QuarantineBus.Reason<<std::dec<<L"\n";
 s<<L"Quarantine RX/request "<<r.QuarantineBus.Received<<L"/"<<r.QuarantineBus.Requested<<L" / wait "<<r.QuarantineBus.FirstWaitUs<<L"us / exit "<<r.QuarantineBus.FirstWaitExit<<L"\n";
 s<<L"Earlier BUS FIRST: sample "<<r.FirstBus.SampleId<<L" / reason 0x"<<std::hex<<r.FirstBus.Reason<<std::dec<<L"\n";
 s<<L"FIRST (frozen): "<<Phase(r.FirstPhase)<<L" / site "<<r.FirstSite<<L" / reason "<<r.FirstControlReason<<L" / snapshot "<<r.FirstSnapshotIssue<<L" / thermal "<<r.FirstThermalReason<<L"\n";
 s<<L"Age sample/source/temp ms "<<AgeMs(r.FirstNowMs,r.FirstSampleMs)<<L"/"<<AgeMs(r.FirstNowMs,r.FirstSourceMs)<<L"/"<<AgeMs(r.FirstNowMs,r.FirstThermalMs)<<L" / limit "<<Limit(r.FirstMaxAgeMs)<<L"\n";
 s<<L"Kick age/limit "<<AgeMs(r.FirstNowMs,r.FirstKickMs)<<L"/"<<Limit(r.FirstServiceMs)<<L"ms / evidence 0x"<<std::hex<<r.FirstEvidence<<std::dec<<L"\n";
 s<<L"Start snapshots/time "<<r.StartSnapshotCalls<<L"/"<<r.StartElapsedMs<<L"ms / snapshot max "<<r.SnapshotMaxMs<<L"ms\n\n";
 bool power=hostFresh&&r.WorkerLive&&r.PowerValidMask==0x7FFFF&&r.PowerDecoded&&r.PowerReadStatus==0&&Fresh(effectiveNow,r.PowerAt100ns,20000000);
 s<<L"Last successful raw: "<<(power?L"recent":L"STALE / unavailable")<<L" / age "<<Age(effectiveNow,r.PowerAt100ns)<<L"\n";
 if(r.PowerDecoded)s<<L"MODE "<<r.Mode<<L" / DETAIL "<<r.Detail<<L" / WDT enabled "<<r.WdtEnabled<<L" expired "<<r.WdtExpired<<L"\n";else s<<L"MODE / DETAIL / WDT: UNKNOWN (decode invalid)\n";
 s<<L"Latest read status 0x"<<std::hex<<r.PowerReadStatus<<std::dec<<L" / raw mask 0x"<<std::hex<<r.PowerValidMask<<std::dec<<L"\n";
 if(r.PowerDecoded)s<<L"Configured CC "<<r.ConfiguredMa<<L"mA / input limit "<<r.InputMa<<L"mA (not measured current)\n";else s<<L"Configured CC / input limit: UNKNOWN\n";
 if(r.PowerDecoded)s<<L"Input Rp / PS_RDY / AutoIbus: "<<r.RpCode<<L" / "<<r.PsReady<<L" / "<<unsigned(r.PowerRaw[1]>>7)<<L" (last raw)\n";else s<<L"Input Rp / PS_RDY / AutoIbus: UNKNOWN\n";
 bool gauge=hostFresh&&r.WorkerLive&&(r.GaugeValidMask&8)&&Fresh(effectiveNow,r.GaugeStart100ns,150000000);
 s<<L"Battery current: ";if(gauge)s<<r.CurrentMa<<L"mA (+ into battery)";else s<<L"UNKNOWN / stale";
 s<<L" / age "<<Age(effectiveNow,r.GaugeStart100ns)<<L"\n";
 s<<L"SOC ";if(hostFresh&&r.WorkerLive&&(r.GaugeValidMask&2)&&Fresh(effectiveNow,r.GaugeStart100ns,150000000))s<<r.SocPermille/10<<L"."<<r.SocPermille%10<<L"%";else s<<L"UNKNOWN";
 s<<L" / voltage ";if(hostFresh&&r.WorkerLive&&(r.GaugeValidMask&4)&&Fresh(effectiveNow,r.GaugeStart100ns,150000000))s<<r.VoltageMv<<L"mV";else s<<L"UNKNOWN";s<<L"\n\n";
 const NCD_QUERY&q=r.LastQuery;
 s<<L"QueryStatus callback (viewer included) #"<<q.Count<<L" / age "<<Age(effectiveNow,q.At100ns)<<L"\n";
 s<<L"NTSTATUS 0x"<<std::hex<<q.Status<<L" / power flags 0x"<<q.PowerState<<std::dec<<L"\n";
 if(q.Count&&q.Status==0)s<<L"ONLINE "<<!!(q.PowerState&BATTERY_POWER_ON_LINE)<<L" / CHARGING "<<!!(q.PowerState&BATTERY_CHARGING)<<L" / DISCHARGING "<<!!(q.PowerState&BATTERY_DISCHARGING)<<L"\n";
 else s<<L"No successful Windows status recorded.\n";
 s<<L"\nInput900 / CC600mA / supervised continuous, 3h safety cap.\nFull/fault stops this attachment. Unplug >=2s before reconnect.\nNo PD increase. Hardware watchdog fail-off not qualified.\nFrozen FIRST is separate from current sequential observations.";
 return s.str();
}
static bool Io(HANDLE h,DWORD code,void*in,DWORD inBytes,void*out,DWORD outBytes,DWORD&error){
 OVERLAPPED ov={};ov.hEvent=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!ov.hEvent){error=GetLastError();return false;}
 DWORD n=0;BOOL ok=DeviceIoControl(h,code,in,inBytes,out,outBytes,&n,&ov);error=ok?0:GetLastError();
 if(!ok&&error==ERROR_IO_PENDING){
  HANDLE waits[]={Stop,ov.hEvent};DWORD w=WaitForMultipleObjects(2,waits,FALSE,1500);
  if(w!=WAIT_OBJECT_0+1){CancelIoEx(h,&ov);if(WaitForSingleObject(ov.hEvent,1500)!=WAIT_OBJECT_0)ExitProcess(ERROR_TIMEOUT);error=w==WAIT_OBJECT_0?ERROR_OPERATION_ABORTED:ERROR_TIMEOUT;(void)GetOverlappedResult(h,&ov,&n,FALSE);CloseHandle(ov.hEvent);return false;}
  ok=GetOverlappedResult(h,&ov,&n,FALSE);error=ok?0:GetLastError();
 }
 CloseHandle(ov.hEvent);if(ok&&n!=outBytes){error=ERROR_INVALID_DATA;return false;}return ok!=FALSE;
}
static HANDLE OpenBattery(DWORD&error){
 HDEVINFO set=SetupDiGetClassDevsW(&GUID_DEVICE_BATTERY,nullptr,nullptr,DIGCF_PRESENT|DIGCF_DEVICEINTERFACE);
 if(set==INVALID_HANDLE_VALUE){error=GetLastError();return INVALID_HANDLE_VALUE;}
 std::wstring path;unsigned matches=0;error=ERROR_NOT_FOUND;
 for(DWORD i=0;i<32;i++){
  SP_DEVICE_INTERFACE_DATA face={};face.cbSize=sizeof(face);
  if(!SetupDiEnumDeviceInterfaces(set,nullptr,&GUID_DEVICE_BATTERY,i,&face)){if(GetLastError()!=ERROR_NO_MORE_ITEMS)error=GetLastError();break;}
  DWORD size=0;SetupDiGetDeviceInterfaceDetailW(set,&face,nullptr,0,&size,nullptr);
  if(size<sizeof(SP_DEVICE_INTERFACE_DETAIL_DATA_W)||size>16384)continue;
  std::vector<unsigned char> buf(size);auto detail=(PSP_DEVICE_INTERFACE_DETAIL_DATA_W)buf.data();detail->cbSize=sizeof(*detail);
  SP_DEVINFO_DATA dev={};dev.cbSize=sizeof(dev);
  if(!SetupDiGetDeviceInterfaceDetailW(set,&face,detail,size,nullptr,&dev))continue;
  wchar_t instance[512]={};
  if(!SetupDiGetDeviceInstanceIdW(set,&dev,instance,512,nullptr)||_wcsicmp(instance,L"ACPI\\NNBT0089\\0"))continue;
  if(!wmemchr(detail->DevicePath,0,(size-offsetof(SP_DEVICE_INTERFACE_DETAIL_DATA_W,DevicePath))/sizeof(wchar_t)))continue;
  path=detail->DevicePath;matches++;
 }
 SetupDiDestroyDeviceInfoList(set);
 if(matches!=1){error=matches?ERROR_DUP_NAME:ERROR_NOT_FOUND;return INVALID_HANDLE_VALUE;}
 HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr);
 error=h==INVALID_HANDLE_VALUE?GetLastError():0;return h;
}
static DWORD WINAPI Poll(void*){
 HANDLE device=INVALID_HANDLE_VALUE;
 while(WaitForSingleObject(Stop,0)!=WAIT_OBJECT_0){
  DWORD error=0;if(device==INVALID_HANDLE_VALUE)device=OpenBattery(error);
  NCD_REPORT r={};
  if(device!=INVALID_HANDLE_VALUE){
   // Invoke the normal BatteryClass query too, so its returned flags are visible.
   ULONG wait=0,tag=0;BATTERY_WAIT_STATUS w={};BATTERY_STATUS b={};DWORD ignored=0;
   if(Io(device,IOCTL_BATTERY_QUERY_TAG,&wait,sizeof(wait),&tag,sizeof(tag),ignored)&&tag){w.BatteryTag=tag;(void)Io(device,IOCTL_BATTERY_QUERY_STATUS,&w,sizeof(w),&b,sizeof(b),ignored);}
   if(!Io(device,NCD_IOCTL,nullptr,0,&r,sizeof(r),error)||!Valid(r)){if(!error)error=ERROR_REVISION_MISMATCH;CloseHandle(device);device=INVALID_HANDLE_VALUE;}
  }
  AcquireSRWLockExclusive(&Lock);Last=r;Error=error;Received=GetTickCount64();ReleaseSRWLockExclusive(&Lock);
  PostMessageW(Window,WM_APP,0,0);if(WaitForSingleObject(Stop,1000)==WAIT_OBJECT_0)break;
 }
 if(device!=INVALID_HANDLE_VALUE)CloseHandle(device);return 0;
}
static LRESULT CALLBACK Proc(HWND w,UINT m,WPARAM a,LPARAM b){
 if(m==WM_APP||m==WM_TIMER){InvalidateRect(w,nullptr,FALSE);return 0;}
 if(m==WM_PAINT){PAINTSTRUCT ps;HDC dc=BeginPaint(w,&ps);RECT rc;GetClientRect(w,&rc);FillRect(dc,&rc,(HBRUSH)GetStockObject(BLACK_BRUSH));
  NCD_REPORT r;DWORD e;ULONGLONG t;AcquireSRWLockShared(&Lock);r=Last;e=Error;t=Received;ReleaseSRWLockShared(&Lock);
  auto text=Text(r,e,t,GetTickCount64());int fontSize=std::clamp((int)(rc.right-rc.left)/64,12,32);HFONT font=CreateFontW(-fontSize,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,FIXED_PITCH,L"Consolas");
  auto old=SelectObject(dc,font);SetTextColor(dc,RGB(220,245,240));SetBkMode(dc,TRANSPARENT);InflateRect(&rc,-24,-24);DrawTextW(dc,text.c_str(),(int)text.size(),&rc,DT_LEFT|DT_TOP|DT_WORDBREAK|DT_NOPREFIX);SelectObject(dc,old);DeleteObject(font);EndPaint(w,&ps);return 0;}
 if(m==WM_DESTROY){KillTimer(w,1);SetEvent(Stop);PostQuitMessage(0);return 0;}
 return DefWindowProcW(w,m,a,b);
}
static int SelfTest(){NCD_REPORT r={};r.Magic=NCD_MAGIC;r.Version=NCD_VERSION;r.Bytes=sizeof(r);r.Driver=606;
 if(Limit(0)!=L"?"||Limit(1000)!=L"1000"||!Valid(r)||Fresh(10,20,20)||Fresh(10,0,20)||Fresh(20,10,10)||!Fresh(19,10,10))return 1;
 r.Driver=601;if(Valid(r))return 2;r.Driver=606;r.Sequence=4;r.WorkerLive=1;r.PowerValidMask=0x7FFFF;r.PowerAt100ns=10000000;r.Query100ns=20000000;r.GaugeStart100ns=10000000;r.GaugeValidMask=8;r.CurrentMa=-123;
 auto t=Text(r,0,100,100);if(t.find(L"Input Rp / PS_RDY / AutoIbus: UNKNOWN")==std::wstring::npos||t.find(L"MODE / DETAIL / WDT: UNKNOWN")==std::wstring::npos||t.find(L"SOC UNKNOWN")==std::wstring::npos||t.find(L"-123mA")==std::wstring::npos||t.find(L"Managed starts: 0")==std::wstring::npos)return 3;
 t=Text(r,0,100,6000);if(t.find(L"STALE or worker stopped")==std::wstring::npos)return 4;
 r.Query100ns=300000000;t=Text(r,0,100,100);if(t.find(L"UNKNOWN / stale")==std::wstring::npos)return 4;return 0;}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int){
 int argc=0;auto argv=CommandLineToArgvW(GetCommandLineW(),&argc);if(!argv)return 5;
 bool test=argc==2&&wcscmp(argv[1],L"--selftest")==0;bool normal=argc==1;LocalFree(argv);
 if(test)return SelfTest();if(!normal)return 6;
 HANDLE mutex=CreateMutexW(nullptr,FALSE,L"Local\\N976nChargeDiag606");if(!mutex||GetLastError()==ERROR_ALREADY_EXISTS)return 0;
 SetProcessDPIAware();Stop=CreateEventW(nullptr,TRUE,FALSE,nullptr);if(!Stop)return 1;
 WNDCLASSW wc={};wc.lpfnWndProc=Proc;wc.hInstance=instance;wc.lpszClassName=L"N976nChargeDiag606";wc.hCursor=LoadCursor(nullptr,IDC_ARROW);RegisterClassW(&wc);
 RECT work;SystemParametersInfoW(SPI_GETWORKAREA,0,&work,0);Window=CreateWindowW(wc.lpszClassName,L"N976N charging observation .606",WS_OVERLAPPEDWINDOW,work.left+16,work.top+64,std::max(600L,work.right-work.left-32),std::max(600L,work.bottom-work.top-96),nullptr,nullptr,instance,nullptr);
 if(!Window)return 2;if(!SetTimer(Window,1,1000,nullptr))return 7;ShowWindow(Window,SW_SHOW);HANDLE thread=CreateThread(nullptr,0,Poll,nullptr,0,nullptr);if(!thread)return 3;
 MSG msg;while(GetMessageW(&msg,nullptr,0,0)>0){TranslateMessage(&msg);DispatchMessageW(&msg);}
 SetEvent(Stop);if(WaitForSingleObject(thread,4000)!=WAIT_OBJECT_0)ExitProcess(ERROR_TIMEOUT);
 CloseHandle(thread);CloseHandle(Stop);CloseHandle(mutex);return 0;
}
