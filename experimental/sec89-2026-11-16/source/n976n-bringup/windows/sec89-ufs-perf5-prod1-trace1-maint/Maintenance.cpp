#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <winioctl.h>
#include <wincrypt.h>
#include <bcrypt.h>
#include <objbase.h>
#ifdef N976N_MAINTENANCE_SELFTEST
#include <shellapi.h>
#endif
#include <algorithm>
#include <atomic>
#include <cstdio>
#include <cwchar>
#include <cwctype>
#include <memory>
#include <sstream>
#include <vector>
#include "MaintenanceContract.h"
#include "PackagePins.h"
#include "PayloadPins.h"
#include <sddl.h>
#include <aclapi.h>
#include "WindowsCommandLine.h"
#include "DosAliasContract.h"
#include "MenuContract.h"

using namespace maintenance;
using Bytes=std::vector<unsigned char>;
// Fixed PROD1 -> TRACE1 profile. Both directions use the preserved 88KiB return.
static const wchar_t* CandidateDirectory(){return L"candidate";}
static const wchar_t* CandidatePass(){return L"PASS - TRACE1 .89.2.6 and reader installed. Use preserved PERF4-return TAR (88KiB).";}
static HWND gWindow=nullptr,gText=nullptr,gHeadline=nullptr;
static std::atomic<bool> gBusy{false},gUncertain{false};
static std::wstring gStage=L"Ready",gExeDir,gLog;
struct Failure {std::wstring message;DWORD code;};
static void Need(bool ok,const std::wstring&m,DWORD e=ERROR_INVALID_DATA){if(!ok)throw Failure{m,e};}
static void Win(bool ok,const std::wstring&m){if(!ok)throw Failure{m,GetLastError()};}
static void Reg(LSTATUS s,const std::wstring&m){if(s!=ERROR_SUCCESS)throw Failure{m,(DWORD)s};}
struct Handle {
    HANDLE h=INVALID_HANDLE_VALUE;Handle()=default;explicit Handle(HANDLE v):h(v){}
    ~Handle(){if(h!=INVALID_HANDLE_VALUE&&h!=nullptr)CloseHandle(h);}Handle(const Handle&)=delete;Handle&operator=(const Handle&)=delete;
    HANDLE release(){HANDLE x=h;h=INVALID_HANDLE_VALUE;return x;}
};
struct Key {HKEY h=nullptr;~Key(){if(h)RegCloseKey(h);}Key()=default;Key(const Key&)=delete;Key&operator=(const Key&)=delete;};
static std::wstring W(const std::u16string&s){static_assert(sizeof(wchar_t)==2,"Windows UTF16");return std::wstring(s.begin(),s.end());}
static std::u16string U(const std::wstring&s){return std::u16string(s.begin(),s.end());}
static std::wstring Hex(DWORD n){wchar_t b[16];swprintf_s(b,L"%08lX",n);return b;}
static void Log(const std::wstring&s){
    if(gWindow){auto p=new std::wstring(s+L"\r\n");if(!PostMessageW(gWindow,WM_APP+1,0,(LPARAM)p))delete p;}
    if(!gLog.empty()){Handle h(CreateFileW(gLog.c_str(),FILE_APPEND_DATA,FILE_SHARE_READ,nullptr,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,nullptr));if(h.h!=INVALID_HANDLE_VALUE){DWORD n=0;std::wstring line=s+L"\r\n";WriteFile(h.h,line.data(),(DWORD)(line.size()*2),&n,nullptr);}}
}
static void Stage(const std::wstring&s){gStage=s;Log(s);}
static std::wstring Unique(){GUID id;Win(SUCCEEDED(CoCreateGuid(&id)),L"Create unique session");wchar_t b[48];StringFromGUID2(id,b,48);std::wstring s(b);s.erase(std::remove_if(s.begin(),s.end(),[](wchar_t c){return c==L'{'||c==L'}'||c==L'-';}),s.end());return s;}
static std::wstring Join(const std::wstring&a,const std::wstring&b){return a+(a.empty()||a.back()==L'\\'?L"":L"\\")+b;}
static bool Exists(const std::wstring&p){return GetFileAttributesW(p.c_str())!=INVALID_FILE_ATTRIBUTES;}
static void NoReparse(HANDLE h){FILE_ATTRIBUTE_TAG_INFO info={};Win(GetFileInformationByHandleEx(h,FileAttributeTagInfo,&info,sizeof(info)),L"Inspect opened file");Need(!(info.FileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),L"Reparse-point file refused");}
// Keep a timed-out buffer and handle alive if cancellation cannot be confirmed.
struct PendingIo {OVERLAPPED ov={};Handle event;Bytes data;PendingIo(size_t n):event(CreateEventW(nullptr,TRUE,FALSE,nullptr)),data(n){Win(event.h!=nullptr,L"I/O event");ov.hEvent=event.h;}};
static DWORD Retire(HANDLE h,PendingIo* op,BOOL started,DWORD immediate){
    if(started)return immediate;DWORD error=GetLastError();if(error!=ERROR_IO_PENDING)throw Failure{L"Issue I/O",error};
    DWORD wait=WaitForSingleObject(op->event.h,30000),n=0;
    if(wait==WAIT_OBJECT_0){Win(GetOverlappedResult(h,&op->ov,&n,FALSE),L"Complete I/O");return n;}
    CancelIoEx(h,&op->ov);
    if(WaitForSingleObject(op->event.h,5000)!=WAIT_OBJECT_0){gUncertain=true;throw Failure{L"I/O retirement unconfirmed; no further writes or restart",ERROR_TIMEOUT};}
    GetOverlappedResult(h,&op->ov,&n,FALSE);throw Failure{L"I/O timed out and was retired",ERROR_TIMEOUT};
}
static DWORD Ioctl(HANDLE h,DWORD code,void*out,DWORD size){
    auto op=std::make_unique<PendingIo>(size);DWORD n=0;BOOL ok=DeviceIoControl(h,code,nullptr,0,op->data.data(),size,&n,&op->ov);
    try{n=Retire(h,op.get(),ok,n);}catch(...){if(gUncertain)op.release();throw;}Need(n<=size,L"IOCTL output bound");std::memcpy(out,op->data.data(),n);return n;
}
static Bytes ReadFileBounded(const std::wstring&p,uint64_t maximum){
    Handle h(CreateFileW(p.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open "+p);NoReparse(h.h);
    LARGE_INTEGER size;Win(GetFileSizeEx(h.h,&size),L"File size");Need(size.QuadPart>=0&&(uint64_t)size.QuadPart<=maximum,L"File size limit: "+p);Bytes result((size_t)size.QuadPart);
    for(size_t at=0;at<result.size();){DWORD count=(DWORD)std::min<size_t>(256*1024,result.size()-at);auto op=std::make_unique<PendingIo>(count);op->ov.Offset=(DWORD)at;op->ov.OffsetHigh=(DWORD)((uint64_t)at>>32);DWORD n=0;BOOL ok=ReadFile(h.h,op->data.data(),count,&n,&op->ov);
        try{n=Retire(h.h,op.get(),ok,n);}catch(...){if(gUncertain){op.release();h.release();}throw;}Need(n==count,L"Short file read");std::memcpy(result.data()+at,op->data.data(),count);at+=count;}
    LARGE_INTEGER after;Win(GetFileSizeEx(h.h,&after),L"Final file size");Need(after.QuadPart==size.QuadPart,L"File changed while reading");return result;
}
static Bytes Sha(const Bytes&b){BCRYPT_ALG_HANDLE a=nullptr;BCRYPT_HASH_HANDLE h=nullptr;Need(BCryptOpenAlgorithmProvider(&a,BCRYPT_SHA256_ALGORITHM,nullptr,0)>=0,L"SHA256 provider");
    try{Need(BCryptCreateHash(a,&h,nullptr,0,nullptr,0,0)>=0,L"SHA256 hash");Need(b.size()<=MAXDWORD,L"SHA256 input size");Need(BCryptHashData(h,(PUCHAR)b.data(),(ULONG)b.size(),0)>=0,L"SHA256 data");Bytes out(32);Need(BCryptFinishHash(h,out.data(),32,0)>=0,L"SHA256 finish");BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0);return out;}catch(...){if(h)BCryptDestroyHash(h);BCryptCloseAlgorithmProvider(a,0);throw;}}
static std::string HexBytes(const Bytes&b){const char*t="0123456789abcdef";std::string s;for(auto c:b){s+=t[c>>4];s+=t[c&15];}return s;}
static std::string FileHash(const std::wstring&p){return HexBytes(Sha(ReadFileBounded(p,2*1024*1024)));}
static void Packages(){for(const auto&which:{std::make_pair(L"baseline",kBaseline),std::make_pair(L"candidate",kDiagnostic)})for(int i=0;i<4;i++){Bytes b=ReadFileBounded(Join(Join(gExeDir,which.first),which.second[i].name),2*1024*1024);Need(b.size()==which.second[i].bytes&&HexBytes(Sha(b))==which.second[i].sha256,L"Package size/hash mismatch");}}
struct FlushWork {HANDLE file=INVALID_HANDLE_VALUE;BOOL ok=FALSE;DWORD error=0;};
static DWORD WINAPI FlushWorker(void*context){auto*w=(FlushWork*)context;w->ok=FlushFileBuffers(w->file);w->error=w->ok?0:GetLastError();CloseHandle(w->file);w->file=INVALID_HANDLE_VALUE;return 0;}
static void TimedFlush(HANDLE file){auto work=std::make_unique<FlushWork>();Win(DuplicateHandle(GetCurrentProcess(),file,GetCurrentProcess(),&work->file,0,FALSE,DUPLICATE_SAME_ACCESS),L"Own flush handle");Handle thread(CreateThread(nullptr,0,FlushWorker,work.get(),0,nullptr));if(!thread.h){DWORD error=GetLastError();CloseHandle(work->file);throw Failure{L"Start bounded flush",error};}
    DWORD wait=WaitForSingleObject(thread.h,30000);if(wait!=WAIT_OBJECT_0){CancelSynchronousIo(thread.h);if(WaitForSingleObject(thread.h,5000)!=WAIT_OBJECT_0){gUncertain=true;work.release();thread.release();throw Failure{L"Flush retirement unconfirmed; no more writes",ERROR_TIMEOUT};}throw Failure{L"Flush timed out and retired",ERROR_TIMEOUT};}Need(work->ok!=FALSE,L"Flush backup",work->error);}
static void WriteNew(const std::wstring&p,const Bytes&b){
    Handle h(CreateFileW(p.c_str(),GENERIC_WRITE,0,nullptr,CREATE_NEW,FILE_FLAG_OVERLAPPED|FILE_FLAG_WRITE_THROUGH|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Create bounded backup");
    auto op=std::make_unique<PendingIo>(b.size());op->data=b;DWORD n=0;BOOL ok=WriteFile(h.h,op->data.data(),(DWORD)b.size(),&n,&op->ov);
    try{n=Retire(h.h,op.get(),ok,n);}catch(...){if(gUncertain){op.release();h.release();}throw;}Need(n==b.size(),L"Short backup write");TimedFlush(h.h);
}
static void Save(const std::wstring&dir,const Backup&s){Log(L"BEGIN save rollback state; phase "+std::to_wstring((uint32_t)s.phase));Need(!gUncertain,L"Uncertain operation blocks new writes");Bytes b=Encode(s),hash=Sha(b);b.insert(b.end(),hash.begin(),hash.end());std::wstring temp=Join(dir,L"state-"+Unique()+L".tmp");WriteNew(temp,b);Log(L"DONE state write/flush; BEGIN commit rename");Win(MoveFileExW(temp.c_str(),Join(dir,L"state.bin").c_str(),MOVEFILE_REPLACE_EXISTING|MOVEFILE_WRITE_THROUGH),L"Commit recovery state");Log(L"DONE commit rename; BEGIN state readback");Need(ReadFileBounded(Join(dir,L"state.bin"),4*1024*1024)==b,L"Recovery state readback");Log(L"DONE save rollback state");}
static Backup Load(const std::wstring&dir){Bytes b=ReadFileBounded(Join(dir,L"state.bin"),4*1024*1024);Need(b.size()>=32,L"Backup digest missing");Bytes hash(b.end()-32,b.end());b.resize(b.size()-32);Need(Sha(b)==hash,L"Backup digest mismatch");return Decode(b);}
static void Privilege(const wchar_t*name){Handle token;Win(OpenProcessToken(GetCurrentProcess(),TOKEN_ADJUST_PRIVILEGES|TOKEN_QUERY,&token.h),L"Open token");TOKEN_PRIVILEGES p={};p.PrivilegeCount=1;Win(LookupPrivilegeValueW(nullptr,name,&p.Privileges[0].Luid),L"Find privilege");p.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;SetLastError(0);Win(AdjustTokenPrivileges(token.h,FALSE,&p,0,nullptr,nullptr),L"Enable privilege");Need(GetLastError()!=ERROR_NOT_ALL_ASSIGNED,L"Required offline hive privilege missing");}
struct Hives {
    std::wstring sysName,softName;HKEY sys=nullptr,soft=nullptr;bool sysLoaded=false,softLoaded=false;
    Hives(const std::wstring&system,const std::wstring&software=L""){
        Privilege(SE_BACKUP_NAME);Privilege(SE_RESTORE_NAME);std::wstring id=Unique();sysName=L"SEC89U_System_"+id;softName=L"SEC89U_Software_"+id;
        try{Log(L"BEGIN load SYSTEM: "+system);Reg(RegLoadKeyW(HKEY_LOCAL_MACHINE,sysName.c_str(),system.c_str()),L"Load offline SYSTEM");sysLoaded=true;Log(L"DONE load SYSTEM");Reg(RegOpenKeyExW(HKEY_LOCAL_MACHINE,sysName.c_str(),0,KEY_READ|KEY_WRITE,&sys),L"Open offline SYSTEM");
            if(!software.empty()){Log(L"BEGIN load SOFTWARE: "+software);Reg(RegLoadKeyW(HKEY_LOCAL_MACHINE,softName.c_str(),software.c_str()),L"Load offline SOFTWARE");softLoaded=true;Log(L"DONE load SOFTWARE");Reg(RegOpenKeyExW(HKEY_LOCAL_MACHINE,softName.c_str(),0,KEY_READ|KEY_WRITE,&soft),L"Open offline SOFTWARE");}}
        catch(...){close(false);throw;}}
    void close(bool throwing=true){if(sys){RegCloseKey(sys);sys=nullptr;}if(soft){RegCloseKey(soft);soft=nullptr;}LSTATUS a=ERROR_SUCCESS,b=ERROR_SUCCESS;if(softLoaded){Log(L"BEGIN unload SOFTWARE");a=RegUnLoadKeyW(HKEY_LOCAL_MACHINE,softName.c_str());if(a==ERROR_SUCCESS){softLoaded=false;Log(L"DONE unload SOFTWARE");}}if(sysLoaded){Log(L"BEGIN unload SYSTEM");b=RegUnLoadKeyW(HKEY_LOCAL_MACHINE,sysName.c_str());if(b==ERROR_SUCCESS){sysLoaded=false;Log(L"DONE unload SYSTEM");}}if(a||b){gUncertain=true;if(throwing)throw Failure{L"Offline hive unload failed; no further writes",(DWORD)(a?a:b)};}}
    ~Hives(){close(false);}Hives(const Hives&)=delete;
};
static RawValue Value(HKEY parent,const std::wstring&path,const std::wstring&name){Key key;Reg(RegOpenKeyExW(parent,path.c_str(),0,KEY_QUERY_VALUE,&key.h),L"Open registry "+path);RawValue r;DWORD size=0,nativeType=0;LSTATUS e=RegQueryValueExW(key.h,name.c_str(),nullptr,&nativeType,nullptr,&size);if(e==ERROR_FILE_NOT_FOUND)return r;Reg(e,L"Query registry value");r.type=nativeType;Need(size<=65536,L"Registry value limit");r.present=true;r.bytes.resize(size);DWORD type=nativeType,actual=size;Reg(RegQueryValueExW(key.h,name.c_str(),nullptr,&type,r.bytes.data(),&actual),L"Read registry value");Need(actual==size&&type==nativeType,L"Registry value changed during read");return r;}
static DWORD Dword(const RawValue&r){Need(r.present&&r.type==REG_DWORD&&r.bytes.size()==4,L"DWORD policy expected");DWORD n;std::memcpy(&n,r.bytes.data(),4);return n;}
static std::wstring String(const RawValue&r){Need(r.present&&(r.type==REG_SZ||r.type==REG_EXPAND_SZ)&&r.bytes.size()>=2&&!(r.bytes.size()%2),L"Registry string expected");std::wstring s((const wchar_t*)r.bytes.data(),r.bytes.size()/2);Need(!s.empty()&&!s.back(),L"Registry string termination");s.pop_back();Need(s.find(L'\0')==std::wstring::npos,L"Embedded string NUL");return s;}
static std::vector<std::wstring> Sets(HKEY sys){std::vector<std::wstring>out;for(DWORD i=0;;i++){wchar_t name[256];DWORD n=256;LSTATUS e=RegEnumKeyExW(sys,i,name,&n,nullptr,nullptr,nullptr,nullptr);if(e==ERROR_NO_MORE_ITEMS)break;Reg(e,L"Enumerate control sets");std::wstring s(name,n);if(s.rfind(L"ControlSet",0)==0){Need(s.size()==13&&std::all_of(s.begin()+10,s.end(),[](wchar_t c){return c>=L'0'&&c<=L'9';})&&s!=L"ControlSet000",L"Unsupported ControlSet");out.push_back(s);}}
    Need(!out.empty()&&out.size()<=8,L"Actual ControlSets required");for(const auto&name:{L"Current",L"Default",L"LastKnownGood",L"Failed"}){DWORD n=Dword(Value(sys,L"Select",name));if(!n){Need(std::wcscmp(name,L"Current")&&std::wcscmp(name,L"Default"),L"Missing selected control set");continue;}wchar_t s[32];swprintf_s(s,L"ControlSet%03lu",n);Need(n<=999&&std::find(out.begin(),out.end(),s)!=out.end(),L"Select points outside actual control sets");}std::sort(out.begin(),out.end());return out;}
struct Target {std::wstring volume,root;DWORD disk=0;std::wstring serviceRoot;};
#ifdef N976N_MAINTENANCE_SELFTEST
struct FixtureConfig {bool active=false;std::wstring volume;DWORD disk=0;uint64_t offset=0,bytes=0;} gFixture;
static Target AdmitFixture(const std::wstring&,DWORD,uint64_t,uint64_t);
#endif
static void CriticalPaths(const Target&t){
    const wchar_t*paths[]={L"Windows",L"Windows\\System32",L"Windows\\System32\\config",L"Windows\\INF",L"Windows\\System32\\DriverStore",L"Windows\\System32\\DriverStore\\FileRepository",L"Windows\\System32\\config\\SYSTEM",L"Windows\\System32\\config\\SOFTWARE"};
    std::vector<std::wstring>checks;for(const auto*p:paths)checks.emplace_back(p);for(const auto*base:{L"SYSTEM",L"SOFTWARE"})for(const auto*suffix:{L".LOG1",L".LOG2"}){std::wstring p=L"Windows\\System32\\config\\"+std::wstring(base)+suffix;if(Exists(Join(t.root,p)))checks.push_back(p);}
    for(const auto&p:checks){Handle h(CreateFileW(Join(t.root,p).c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open critical image path");NoReparse(h.h);wchar_t final[32768];DWORD n=GetFinalPathNameByHandleW(h.h,final,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);Need(n&&n<32768&&n>=t.volume.size()&&!_wcsnicmp(final,t.volume.c_str(),t.volume.size()),L"Critical image path escapes admitted volume");}
}
static std::wstring SystemDirectory(){wchar_t p[MAX_PATH];UINT n=GetWindowsDirectoryW(p,MAX_PATH);Need(n&&n<MAX_PATH,L"Windows directory");return p;}
static void RequirePE(){Key key;Reg(RegOpenKeyExW(HKEY_LOCAL_MACHINE,L"SYSTEM\\CurrentControlSet\\Control\\MiniNT",0,KEY_QUERY_VALUE,&key.h),L"Maintenance helper requires WinPE; installed Windows refused");Need(SystemDirectory().size()>2,L"PE path");}
// The admitted canonical volume GUID is used for files and offline hives.
// DISM requires a standard DOS path; direct GUID is not accepted.
// Use only an unclaimed temporary DOS alias; no WIM reparse or MountMgr operation.
// Volume GUID names are discovered at runtime; candidate disk identity stays pinned.
static bool EqualPath(const std::wstring&a,const std::wstring&b){return !_wcsicmp(a.c_str(),b.c_str());}
static std::wstring CanonicalVolume(const std::wstring&root){
    wchar_t name[MAX_PATH]={};Win(GetVolumeNameForVolumeMountPointW(root.c_str(),name,MAX_PATH),L"Resolve volume binding: "+root);
    std::wstring v=name;Need(v.rfind(L"\\\\?\\Volume{",0)==0&&v.size()==49&&v.substr(47)==L"}\\",L"Volume GUID name expected");return v;
}
static std::wstring VolumeDevice(const std::wstring&root){
    Handle h(CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open volume root identity");
    wchar_t name[32768];DWORD n=GetFinalPathNameByHandleW(h.h,name,32768,FILE_NAME_NORMALIZED|VOLUME_NAME_NT);Need(n&&n<32768,L"Resolve volume device identity",GetLastError());std::wstring v(name,n);while(!v.empty()&&v.back()==L'\\')v.pop_back();Need(v.rfind(L"\\Device\\",0)==0,L"NT volume device expected");return v;
}
static std::wstring SystemVolumeDevice(){wchar_t root[MAX_PATH];Win(GetVolumePathNameW(SystemDirectory().c_str(),root,MAX_PATH),L"Resolve running Windows volume root");return VolumeDevice(root);}
// Production and owned native fixtures share all captured identity fields and checks.
static void IdentitySize(DWORD actual,DWORD expected,const wchar_t*field){
    if(actual<expected)Log(std::wstring(L"IDENTITY ")+field+L" response bytes expected >= "+std::to_wstring(expected)+L" actual "+std::to_wstring(actual));
    Need(actual>=expected,std::wstring(field)+L" identity response truncated");
}
static Target InspectTarget(HANDLE h,const std::wstring&v,const NTFS_VOLUME_DATA_BUFFER&ntfs,const std::wstring&osDevice){
    VOLUME_DISK_EXTENTS ext={};IdentitySize(Ioctl(h,IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS,&ext,sizeof(ext)),sizeof(ext),L"extent");
    PARTITION_INFORMATION_EX part={};IdentitySize(Ioctl(h,IOCTL_DISK_GET_PARTITION_INFO_EX,&part,sizeof(part)),sizeof(part),L"partition");
    Identity id;id.serial=(uint64_t)ntfs.VolumeSerialNumber.QuadPart;id.start=(uint64_t)part.StartingOffset.QuadPart;
    id.partitionBytes=(uint64_t)part.PartitionLength.QuadPart;id.sectors=(uint64_t)ntfs.NumberSectors.QuadPart;
    id.sectorBytes=ntfs.BytesPerSector;id.clusterBytes=ntfs.BytesPerCluster;id.extents=ext.NumberOfDiskExtents;
    id.extentStart=(uint64_t)ext.Extents[0].StartingOffset.QuadPart;id.extentBytes=(uint64_t)ext.Extents[0].ExtentLength.QuadPart;
    id.totalClusters=(uint64_t)ntfs.TotalClusters.QuadPart;id.mftStart=(uint64_t)ntfs.MftStartLcn.QuadPart;
    id.ntfs=true;id.gpt=part.PartitionStyle==PARTITION_STYLE_GPT;id.systemVolume=EqualPath(VolumeDevice(v),osDevice);
    if(id.gpt)std::memcpy(id.guid,&part.Gpt.PartitionId,16);
    try{Bytes marker=ReadFileBounded(Join(v,L"SEC85.ID"),sizeof(kMarker));id.marker=marker.size()==sizeof(kMarker)-1&&!std::memcmp(marker.data(),kMarker,sizeof(kMarker)-1);}
    catch(const Failure&e){Log(L"IDENTITY SEC85 marker read failed / "+Hex(e.code)+L" / "+e.message);throw;}
    auto differences=IdentityMismatches(id);
    for(const auto&d:differences){std::wostringstream line;line<<L"IDENTITY "<<d.field<<L" expected 0x"<<std::hex<<std::uppercase<<d.expected<<L" actual 0x"<<d.actual;Log(line.str());}
    Need(differences.empty(),differences.empty()?L"SEC85 identity":L"SEC85 identity mismatch: "+differences.front().field);
    Need(Exists(Join(v,L"Windows\\System32\\ntoskrnl.exe")),L"Installed Windows image absent");
    Target candidate{v,v,ext.Extents[0].DiskNumber,{}};CriticalPaths(candidate);
    Log(L"IDENTITY PASS: exact GUID/serial/marker; partition and extent 64GiB; NTFS 4Kn");return candidate;
}
static Target FindTarget(){
#ifdef N976N_MAINTENANCE_SELFTEST
    if(gFixture.active){Packages();return AdmitFixture(gFixture.volume,gFixture.disk,gFixture.offset,gFixture.bytes);}
#endif
    RequirePE();Packages();std::wstring peDevice=SystemVolumeDevice();std::vector<Target>matches;wchar_t volume[MAX_PATH];HANDLE find=FindFirstVolumeW(volume,MAX_PATH);Win(find!=INVALID_HANDLE_VALUE,L"Enumerate volumes");
    try{unsigned seen=0;do{Need(++seen<=256,L"Volume enumeration bound");std::wstring listed=volume;if(listed.empty()||listed.back()!=L'\\')continue;std::wstring dev=listed.substr(0,listed.size()-1);
        Handle h(CreateFileW(dev.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));if(h.h==INVALID_HANDLE_VALUE)continue;
        try{wchar_t fs[32]={};if(!GetVolumeInformationByHandleW(h.h,nullptr,0,nullptr,nullptr,nullptr,fs,32)||_wcsicmp(fs,L"NTFS"))continue;
            NTFS_VOLUME_DATA_BUFFER ntfs={};IdentitySize(Ioctl(h.h,FSCTL_GET_NTFS_VOLUME_DATA,&ntfs,sizeof(ntfs)),sizeof(ntfs),L"NTFS");
            if((uint64_t)ntfs.VolumeSerialNumber.QuadPart!=kSerial)continue;
            std::wstring v=CanonicalVolume(listed);matches.push_back(InspectTarget(h.h,v,ntfs,peDevice));
        }catch(const Failure&e){if(gUncertain){h.release();throw;}Log(L"Volume refused: "+e.message+L" / "+Hex(e.code));}
    }while(FindNextVolumeW(find,volume,MAX_PATH));Need(GetLastError()==ERROR_NO_MORE_FILES,L"Volume enumeration incomplete",GetLastError());FindVolumeClose(find);find=INVALID_HANDLE_VALUE;}catch(...){if(find!=INVALID_HANDLE_VALUE)FindVolumeClose(find);throw;}
    Need(matches.size()==1,L"Exactly one admitted SEC85 USERDATA volume required");return matches[0];
}
static void VerifyVolumeRoot(const Target&t){Need(EqualPath(t.root,t.volume)&&EqualPath(CanonicalVolume(t.root),t.volume),L"Canonical servicing volume changed");Need(!EqualPath(VolumeDevice(t.root),SystemVolumeDevice()),L"Running Windows volume cannot be serviced");}
static std::wstring ResolvedVolumeGuid(const std::wstring&root){Handle h(CreateFileW(root.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open DOS alias root identity");wchar_t name[MAX_PATH];DWORD n=GetFinalPathNameByHandleW(h.h,name,MAX_PATH,FILE_NAME_NORMALIZED|VOLUME_NAME_GUID);Need(n&&n<MAX_PATH,L"Resolve DOS alias volume GUID",GetLastError());std::wstring out(name,n);while(!out.empty()&&out.back()==L'\\')out.pop_back();return out+L"\\";}
static bool QueryAlias(const std::wstring&alias,std::u16string&raw){Need(alias.size()==2&&alias[0]>=L'A'&&alias[0]<=L'Z'&&alias[1]==L':',L"Single A-Z DOS alias required");wchar_t names[32768]={};DWORD n=QueryDosDeviceW(alias.c_str(),names,32768),error=n?ERROR_SUCCESS:GetLastError();if(!n){Need(error==ERROR_FILE_NOT_FOUND,L"DOS alias query failed; occupancy unknown",error);raw.clear();return false;}Need(n<=32768,L"DOS alias result bound");raw=U(std::wstring(names,n));return true;}
static bool AliasAbsent(const std::wstring&alias){DWORD drives=GetLogicalDrives(),error=drives?ERROR_SUCCESS:GetLastError();Need(drives!=0,L"Read occupied drive-letter bitmap",error);std::u16string raw;bool mapped=QueryAlias(alias,raw);return !mapped&&!(drives&(1UL<<(alias[0]-L'A')));}
static void ExactAlias(const std::wstring&alias,const std::wstring&target){std::u16string raw;Need(QueryAlias(alias,raw)&&SingleDosTarget(raw,U(target)),L"Owned DOS alias no longer has one exact NT target");}
static void VerifyServiceRoot(const Target&t){VerifyVolumeRoot(t);Need(t.serviceRoot.size()==3&&t.serviceRoot[2]==L'\\',L"Verified DOS alias root required");std::wstring target=VolumeDevice(t.volume);ExactAlias(t.serviceRoot.substr(0,2),target);Need(EqualPath(VolumeDevice(t.serviceRoot),target)&&EqualPath(ResolvedVolumeGuid(t.serviceRoot),t.volume),L"DOS alias resolved identity differs from admitted volume");}
static void SameTarget(const Target&a){Log(L"BEGIN target recheck");Target b=FindTarget();Need(EqualPath(a.volume,b.volume)&&a.disk==b.disk,L"Target changed; no writes allowed");VerifyVolumeRoot(a);if(!a.serviceRoot.empty())VerifyServiceRoot(a);Log(L"DONE target recheck");}
// DefineDosDevice is GLOBAL under LocalSystem, not private to this process.
// Only a previously unclaimed name is created, and only its exact mapping removed.
struct DosAliasLease {
    std::wstring volume,target,alias,root;bool created=false;
    DosAliasLease()=default;DosAliasLease(const DosAliasLease&)=delete;
    void acquire(Target&t){Need(!created&&!gUncertain,L"Invalid DOS alias acquisition");VerifyVolumeRoot(t);volume=t.volume;target=VolumeDevice(volume);
        for(char16_t letter:kAliasOrder){if(!letter)break;std::wstring candidate(1,(wchar_t)letter);candidate+=L":";if(!AliasAbsent(candidate))continue;if(!AliasAbsent(candidate))continue;alias=candidate;root=alias+L"\\";
            BOOL ok=DefineDosDeviceW(DDD_RAW_TARGET_PATH|DDD_NO_BROADCAST_SYSTEM,alias.c_str(),target.c_str());DWORD error=ok?ERROR_SUCCESS:GetLastError();Need(ok!=FALSE,L"Create unclaimed temporary DOS alias",error);created=true;t.serviceRoot=root;VerifyServiceRoot(t);Log(L"Owned temporary DOS alias "+alias+L" -> "+target+L" (global under LocalSystem; no MountMgr/reparse changes).");return;}
        throw Failure{L"No unclaimed A-Z DOS alias; existing mappings are preserved",ERROR_NO_MORE_ITEMS};
    }
    void close(bool throwing=true){if(!created)return;if(gUncertain){Log(L"Owned DOS alias retained: retirement unresolved: "+alias);return;}
        try{ExactAlias(alias,target);Need(EqualPath(VolumeDevice(root),target)&&EqualPath(ResolvedVolumeGuid(root),volume),L"Owned DOS alias resolved target changed");BOOL ok=DefineDosDeviceW(DDD_RAW_TARGET_PATH|DDD_REMOVE_DEFINITION|DDD_EXACT_MATCH_ON_REMOVE|DDD_NO_BROADCAST_SYSTEM,alias.c_str(),target.c_str());DWORD error=ok?ERROR_SUCCESS:GetLastError();Need(ok!=FALSE,L"Remove exact owned DOS alias",error);created=false;Need(AliasAbsent(alias),L"DOS alias still occupied after exact removal; no further removal attempted");Log(L"Removed exact owned DOS alias "+alias);}
        catch(const Failure&e){gUncertain=true;Log(L"DOS alias cleanup STOP: "+e.message+L" / "+Hex(e.code));if(throwing)throw;}
    }
    ~DosAliasLease(){close(false);}
};
static std::wstring SelectedFile(const Target&t,const std::wstring&image,const wchar_t*leaf=L"N976nUfs.sys"){
    std::wstring p=image;if(p.rfind(L"\\SystemRoot\\",0)==0)p=L"Windows\\"+p.substr(12);else if(p.rfind(L"System32\\",0)==0)p=L"Windows\\"+p;
    Need(p.rfind(L"Windows\\System32\\",0)==0&&p.find(L"..") ==std::wstring::npos&&p.find(L':')==std::wstring::npos&&p.find(L'/')==std::wstring::npos,L"Unsupported offline service ImagePath");Need(p.size()>=wcslen(leaf)&&!_wcsicmp(p.substr(p.size()-wcslen(leaf)).c_str(),leaf),L"Selected service is not N976nUfs.sys");
    std::wstring at=t.root;size_t from=0;while(from<p.size()){size_t end=p.find(L'\\',from);std::wstring part=p.substr(from,end==std::wstring::npos?p.size()-from:end-from);at=Join(at,part);DWORD attrs=GetFileAttributesW(at.c_str());Need(attrs!=INVALID_FILE_ATTRIBUTES&&!(attrs&FILE_ATTRIBUTE_REPARSE_POINT),L"Selected driver path missing or redirected");if(end==std::wstring::npos)break;from=end+1;}return at;
}
static std::string SelectedHash(HKEY sys,const Target&t){std::string common;for(const auto&s:Sets(sys)){std::wstring image=String(Value(sys,s+L"\\Services\\N976nUfs",L"ImagePath"));auto hash=FileHash(SelectedFile(t,image));Log(L"SELECTED "+s+L" "+image+L" SHA256="+std::wstring(hash.begin(),hash.end()));Need(hash==kBaseline[1].sha256||hash==kDiagnostic[1].sha256,L"Unknown selected UFS driver");if(common.empty())common=hash;else if(common!=hash)common="mixed-known";}return common;}
static void Selected(HKEY sys,const Target&t,const char*expected){Need(SelectedHash(sys,t)==expected,L"Offline service-selected SYS hash differs");}
static std::wstring Oem(const Target&t,const char*hash,bool required){WIN32_FIND_DATAW data={};HANDLE f=FindFirstFileW(Join(t.root,L"Windows\\INF\\oem*.inf").c_str(),&data);if(f==INVALID_HANDLE_VALUE){Need(!required&&GetLastError()==ERROR_FILE_NOT_FOUND,L"Enumerate OEM drivers");return L"";}std::vector<std::wstring>matches;unsigned count=0;
    try{do{Need(++count<=4096,L"OEM INF count bound");if(data.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY)continue;Need(!(data.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),L"Reparse OEM INF refused");if(FileHash(Join(t.root,L"Windows\\INF\\"+std::wstring(data.cFileName)))==hash)matches.emplace_back(data.cFileName);}while(FindNextFileW(f,&data));Need(GetLastError()==ERROR_NO_MORE_FILES,L"OEM enumeration incomplete");FindClose(f);f=INVALID_HANDLE_VALUE;}catch(...){if(f!=INVALID_HANDLE_VALUE)FindClose(f);throw;}
    Need(matches.size()<=1&&(!required||matches.size()==1),L"OEM INF identity absent or ambiguous");return matches.empty()?L"":matches[0];
}
static void SafeOem(const std::wstring&s){Need(s.size()>=8&&s.size()<=32&&s.rfind(L"oem",0)==0&&s.substr(s.size()-4)==L".inf"&&std::all_of(s.begin()+3,s.end()-4,[](wchar_t c){return c>=L'0'&&c<=L'9';}),L"Unsafe OEM INF name");}
struct Certificate {PCCERT_CONTEXT context=nullptr;explicit Certificate(const Bytes&data){context=CertCreateCertificateContext(X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,data.data(),(DWORD)data.size());Win(context!=nullptr,L"Decode diagnostic certificate");}~Certificate(){if(context)CertFreeCertificateContext(context);}};
struct CertRef {PCCERT_CONTEXT context=nullptr;~CertRef(){if(context)CertFreeCertificateContext(context);}};
static bool CertificateAction(HKEY soft,int storeIndex,const Bytes&bytes,int action){
    const wchar_t*storeName=storeIndex?L"TrustedPublisher":L"ROOT";Key key;std::wstring path=L"Microsoft\\SystemCertificates\\"+std::wstring(storeName);Reg(RegOpenKeyExW(soft,path.c_str(),0,KEY_READ|KEY_WRITE,&key.h),L"Open offline certificate store");
    HCERTSTORE store=CertOpenStore(CERT_STORE_PROV_REG,0,0,CERT_STORE_OPEN_EXISTING_FLAG,key.h);Win(store!=nullptr,L"Open offline registry-backed store");Certificate cert(bytes);bool found=false;
    try{{CertRef prior;prior.context=CertFindCertificateInStore(store,X509_ASN_ENCODING|PKCS_7_ASN_ENCODING,0,CERT_FIND_EXISTING,cert.context,nullptr);if(!prior.context)Need(GetLastError()==(DWORD)CRYPT_E_NOT_FOUND,L"Certificate absence query failed",GetLastError());if(prior.context){found=true;Need(prior.context->cbCertEncoded==bytes.size()&&!std::memcmp(prior.context->pbCertEncoded,bytes.data(),bytes.size()),L"Certificate identity mismatch");if(action<0){PCCERT_CONTEXT deleting=prior.context;prior.context=nullptr;Win(CertDeleteCertificateFromStore(deleting),L"Remove newly added offline certificate");}}
        if(action>0&&!found){CertRef added;Win(CertAddCertificateContextToStore(store,cert.context,CERT_STORE_ADD_NEW,&added.context),L"Add offline diagnostic certificate");Need(added.context&&added.context->cbCertEncoded==bytes.size()&&!std::memcmp(added.context->pbCertEncoded,bytes.data(),bytes.size()),L"Offline certificate readback");}}
        Win(CertCloseStore(store,0),L"Close offline certificate store");store=nullptr;if(action){Reg(RegFlushKey(key.h),L"Flush offline certificate store");Need(CertificateAction(soft,storeIndex,bytes,0)==(action>0),L"Certificate persisted-store readback");}return found;
    }catch(...){if(store)CertCloseStore(store,0);throw;}
}
static DWORD Dism(const Target&t,const std::wstring&operation,const std::wstring&argument,const std::wstring&label){
    Need(!gUncertain,L"Uncertain servicing blocks actions");VerifyServiceRoot(t);std::wstring exe=Join(SystemDirectory(),L"System32\\dism.exe");Need(Exists(exe),L"Native DISM absent");std::wstring log=Join(gExeDir,L"dism-"+label+L"-"+Unique()+L".log");
    std::vector<std::u16string>args={U(exe),u"/English",u"/NoRestart",U(L"/Image:"+t.serviceRoot),U(operation),U(L"/Driver:"+argument)};if(operation==L"/Add-Driver")args.push_back(u"/ForceUnsigned");args.push_back(U(L"/ScratchDir:"+Join(gExeDir,L"scratch")));args.push_back(U(L"/LogPath:"+log));std::wstring command=W(WindowsCommandLine(args));
    Log(L"Native servicing root: "+t.serviceRoot+L" -> "+t.volume+L" (exact owned temporary DOS alias).");
    CreateDirectoryW(Join(gExeDir,L"scratch").c_str(),nullptr);Handle job(CreateJobObjectW(nullptr,nullptr));Win(job.h!=nullptr,L"Create servicing job");JOBOBJECT_EXTENDED_LIMIT_INFORMATION limit={};limit.BasicLimitInformation.LimitFlags=JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;Win(SetInformationJobObject(job.h,JobObjectExtendedLimitInformation,&limit,sizeof(limit)),L"Bound servicing process tree");
    STARTUPINFOW si={sizeof(si)};PROCESS_INFORMATION pi={};Win(CreateProcessW(exe.c_str(),&command[0],nullptr,nullptr,FALSE,CREATE_SUSPENDED|CREATE_NO_WINDOW,nullptr,gExeDir.c_str(),&si,&pi),L"Start native offline DISM");Handle process(pi.hProcess),thread(pi.hThread);
    if(!AssignProcessToJobObject(job.h,process.h)){DWORD error=GetLastError();BOOL stopped=TerminateProcess(process.h,ERROR_CANCELLED);if(!stopped||WaitForSingleObject(process.h,5000)!=WAIT_OBJECT_0){gUncertain=true;process.release();thread.release();}throw Failure{L"Could not own DISM process tree",error};}
    if(ResumeThread(thread.h)==(DWORD)-1){DWORD error=GetLastError();TerminateJobObject(job.h,error);if(WaitForSingleObject(process.h,5000)!=WAIT_OBJECT_0){gUncertain=true;process.release();thread.release();job.release();}throw Failure{L"Could not resume DISM process",error};}
    struct Retirement {bool confirmed=false;~Retirement(){if(!confirmed)gUncertain=true;}} retirement;
    Log(L"Native DISM running; log "+log);DWORD wait=WaitForSingleObject(process.h,15*60*1000);
    if(wait!=WAIT_OBJECT_0){TerminateJobObject(job.h,ERROR_TIMEOUT);WaitForSingleObject(process.h,5000);gUncertain=true;throw Failure{L"DISM timed out; completion unknown. Stop here, keep recovery record and PE logs.",ERROR_TIMEOUT};}
    DWORD exitCode=0;Win(GetExitCodeProcess(process.h,&exitCode),L"DISM exit status");ULONGLONG deadline=GetTickCount64()+30000;JOBOBJECT_BASIC_ACCOUNTING_INFORMATION accounting={};
    for(;;){Win(QueryInformationJobObject(job.h,JobObjectBasicAccountingInformation,&accounting,sizeof(accounting),nullptr),L"DISM process-tree retirement");if(!accounting.ActiveProcesses)break;if(GetTickCount64()>=deadline){TerminateJobObject(job.h,ERROR_TIMEOUT);gUncertain=true;throw Failure{L"DISM child retirement unconfirmed; stop here",ERROR_TIMEOUT};}Sleep(100);}
    retirement.confirmed=true;Log(L"DISM returned "+Hex(exitCode));return exitCode;
}

// Only the boot-start UFS package is serviced. Other settings are observed.
static const wchar_t* kServiceFields[]={L"ImagePath",L"Start",L"Type",L"ErrorControl",L"Group",L"DependOnService",L"DisplayName"};
static std::wstring Config(const Target&t,const wchar_t*name){return Join(t.root,L"Windows\\System32\\config\\"+std::wstring(name));}
static void RecordValue(Bytes&out,const RawValue&v){Put32(out,v.present?1:0);Put32(out,v.type);Put32(out,(uint32_t)v.bytes.size());out.insert(out.end(),v.bytes.begin(),v.bytes.end());}
static RawValue OptionalValue(HKEY root,const std::wstring&path,const wchar_t*name){Key key;LSTATUS e=RegOpenKeyExW(root,path.c_str(),0,KEY_READ,&key.h);if(e==ERROR_FILE_NOT_FOUND)return {};Reg(e,L"Open protected key");return Value(root,path,name);}
static bool ExistsExact(const std::wstring& path);
static Bytes Protected(const Target&t,HKEY sys,HKEY soft){
    Bytes out;
    for(const auto&s:Sets(sys)){
        PutString(out,U(s));
        for(const wchar_t*service:{L"N976nY771Touch",L"N976nBattery"}){
            const auto path=s+L"\\Services\\"+service;
            PutString(out,U(service));
            for(const wchar_t*n:kServiceFields)RecordValue(out,OptionalValue(sys,path,n));
            auto image=OptionalValue(sys,path,L"ImagePath");
            if(image.present){auto hash=FileHash(SelectedFile(t,String(image),(std::wstring(service)+L".sys").c_str()));PutString(out,std::u16string(hash.begin(),hash.end()));}
        }
        for(const auto&p:std::vector<std::pair<std::wstring,const wchar_t*>>{
            {L"\\Control\\Session Manager\\Memory Management",L"PagingFiles"},
            {L"\\Control\\Power",L"HibernateEnabled"},{L"\\Control\\Power",L"HibernateEnabledDefault"},
            {L"\\Control\\Session Manager\\Power",L"HiberbootEnabled"},
            {L"\\Control\\CrashControl",L"CrashDumpEnabled"},{L"\\Control\\CrashControl",L"AutoReboot"}})
            RecordValue(out,OptionalValue(sys,s+p.first,p.second));
    }
    for(const wchar_t*n:{L"SystemSetupInProgress",L"OOBEInProgress",L"SetupPhase",L"SetupType",L"CmdLine"})RecordValue(out,OptionalValue(sys,L"Setup",n));
    RecordValue(out,OptionalValue(soft,L"Microsoft\\Windows\\CurrentVersion\\OOBE",L"EventTimeoutShellReady"));
    for(const wchar_t*n:{L"N976nChargeDiag602",L"N976nChargeDiag603",L"N976nChargeDiag604",L"N976nChargeDiag605",L"N976nChargeDiag606"})
        RecordValue(out,OptionalValue(soft,L"Microsoft\\Windows\\CurrentVersion\\Run",n));
    // Preserve the installed .606 viewer independently from its startup value.
    const auto viewer=Join(t.root,L"Windows\\System32\\N976nChargeDiag606.exe");
    const bool viewerPresent=ExistsExact(viewer);Put32(out,viewerPresent?1U:0U);
    if(viewerPresent){auto hash=FileHash(viewer);PutString(out,std::u16string(hash.begin(),hash.end()));}
    return out;
}
static std::wstring PackageRepository(const Target&t,const PackagePin*pins){
    WIN32_FIND_DATAW d={};std::wstring base=Join(t.root,L"Windows\\System32\\DriverStore\\FileRepository");
    HANDLE f=FindFirstFileW(Join(base,L"n976nufs.inf_arm64_*").c_str(),&d);Win(f!=INVALID_HANDLE_VALUE,L"Find UFS DriverStore");
    std::vector<std::wstring> matches;unsigned count=0;
    try{do{Need(++count<=128,L"UFS repository count bound");if(!(d.dwFileAttributes&FILE_ATTRIBUTE_DIRECTORY))continue;Need(!(d.dwFileAttributes&FILE_ATTRIBUTE_REPARSE_POINT),L"Repository reparse refused");std::wstring dir=Join(base,d.cFileName);
        if(FileHash(Join(dir,pins[0].name))!=pins[0].sha256)continue;
        for(int i=1;i<3;++i)Need(FileHash(Join(dir,pins[i].name))==pins[i].sha256,L"Staged SYS/CAT hash mismatch");matches.push_back(dir);
    }while(FindNextFileW(f,&d));Need(GetLastError()==ERROR_NO_MORE_FILES,L"Repository enumeration incomplete");FindClose(f);f=INVALID_HANDLE_VALUE;}catch(...){if(f!=INVALID_HANDLE_VALUE)FindClose(f);throw;}
    Need(matches.size()==1,L"Exactly one matching UFS repository required");return matches[0];
}
static std::wstring Recovery(const Target&t){return Join(t.root,L"N976nUfsPerf5Prod1Trace1-Recovery");}
static void RecoveryPath(const std::wstring&dir){Handle h(CreateFileW(dir.c_str(),FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open owned recovery path");NoReparse(h.h);}

static Bytes Sealed(const Bytes& plain) {
    Bytes data=plain;
    auto digest=Sha(plain);
    data.insert(data.end(),digest.begin(),digest.end());
    return data;
}
static Bytes ReadSealed(const std::wstring& path) {
    Bytes data=ReadFileBounded(path,4*1024*1024);
    Need(data.size()>=32,L"Truncated evidence");
    Bytes plain(data.begin(),data.end()-32);
    Need(Sealed(plain)==data,L"Evidence digest mismatch: "+path);
    return plain;
}
static bool ExistsExact(const std::wstring& path) {
    if(GetFileAttributesW(path.c_str())!=INVALID_FILE_ATTRIBUTES)return true;
    DWORD e=GetLastError();
    Need(e==ERROR_FILE_NOT_FOUND||e==ERROR_PATH_NOT_FOUND,L"Cannot determine path presence: "+path,e);
    return false;
}
static void SavePhase(const std::wstring& dir,Backup& b,Phase phase) {
    b.phase=phase;
    Save(dir,b);
}
static void PackageState(const Target& t,const PackagePin* pins,const PackagePin* absent) {
    Need(!Oem(t,pins[0].sha256,true).empty(),L"Expected OEM absent");
    SafeOem(Oem(t,pins[0].sha256,true));
    Need(Oem(t,absent[0].sha256,false).empty(),L"Unexpected other OEM");
    for(const auto* other:{kBaseline,kDiagnostic,kOldMq1,kOldFix1})if(other!=pins)Need(Oem(t,other[0].sha256,false).empty(),L"Unexpected third-profile OEM");
    PackageRepository(t,pins);
}
static void NeitherPackage(const Target& t) {
    Need(Oem(t,kBaseline[0].sha256,false).empty()&&Oem(t,kDiagnostic[0].sha256,false).empty()&&Oem(t,kOldMq1[0].sha256,false).empty()&&Oem(t,kOldFix1[0].sha256,false).empty(),
         L"Unexpected package after completed removal");
}
static void BootBinding(const Target& t,Hives& h,const PackagePin* pins) {
    const auto package=PackageRepository(t,pins);
    Selected(h.sys,t,pins[1].sha256);
    for(const auto& s:Sets(h.sys)){
        auto path=s+L"\\Services\\N976nUfs";
        Need(Dword(Value(h.sys,path,L"Start"))==0 && Dword(Value(h.sys,path,L"Type"))==1 &&
             Dword(Value(h.sys,path,L"ErrorControl"))==1 && String(Value(h.sys,path,L"Group"))==L"SCSI Miniport",
             L"Boot service start, type, ErrorControl or group differs");
        Need(EqualPath(SelectedFile(t,String(Value(h.sys,path,L"ImagePath"))),Join(package,pins[1].name)),
             L"Service must select exact verified DriverStore package");
    }
}
static void Trust(Hives& h,const PackagePin* pins,int action,const bool* original=nullptr) {
    const auto bytes=ReadFileBounded(Join(Join(gExeDir,pins==kBaseline?L"baseline":CandidateDirectory()),pins[3].name),65536);
    for(int i=0;i<2;++i){
        int op=action;
        if(op<0&&original&&original[i])op=0;
        CertificateAction(h.soft,i,bytes,op);
        bool expected=action<0?original[i]:true;
        Need(CertificateAction(h.soft,i,bytes,0)==expected,L"Offline certificate presence differs");
    }
}
static void OriginalTrust(Hives& h,const Backup& b) {
    Trust(h,kBaseline,0);
    const auto bytes=ReadFileBounded(Join(Join(gExeDir,CandidateDirectory()),kDiagnostic[3].name),65536);
    for(int i=0;i<2;++i)Need(CertificateAction(h.soft,i,bytes,0)==b.certificatePresent[i],L"Original candidate trust differs");
}
static void VerifyOriginalService(Hives& h,const Backup& b) {
    auto sets=Sets(h.sys);
    Need(sets.size()==b.sets.size(),L"ControlSet inventory changed");
    for(size_t i=0;i<sets.size();++i){
        const auto& cs=b.sets[i];
        Need(U(sets[i])==cs.name,L"ControlSet identity changed");
        const auto path=sets[i]+L"\\Services\\N976nUfs";
        for(int n=0;n<7;++n){
            Need(OptionalValue(h.sys,path,kServiceFields[n])==cs.values[n],
                 L"Original UFS service differs: "+sets[i]+L" / "+kServiceFields[n]);
        }
    }
}
static void CheckProtection(const Target&t,const std::wstring& dir,Hives& h,bool rollback) {
    const auto file=Join(dir,rollback?L"protected-rollback.bin":L"protected-install.bin");
    Need(Protected(t,h.sys,h.soft)==ReadSealed(file),L"Touch, battery, viewer, power or Setup changed during servicing");
}
static void NewProtection(const std::wstring& dir,const std::wstring& filename,const Bytes& values) {
    const auto path=Join(dir,filename);
    if(ExistsExact(path)){
        Need(ReadSealed(path)==values,L"Existing evidence belongs to a different operation");
        return;
    }
    const auto tmp=Join(dir,L"snapshot-"+Unique()+L".tmp");
    WriteNew(tmp,Sealed(values));
    Win(MoveFileExW(tmp.c_str(),path.c_str(),MOVEFILE_WRITE_THROUGH),L"Publish original evidence");
    Need(ReadSealed(path)==values,L"Original evidence readback");
}
static void BindRecord(const std::wstring& dir,const Backup& b,const PackagePin* candidate=kDiagnostic) {
    Need(b.formatVersion==2&&b.diagnosticInfHash==U(std::wstring(candidate[0].sha256,candidate[0].sha256+64)),
         L"Unexpected candidate identity in recovery record");
    SafeOem(W(b.originalOem));
    auto baseline=b;
    baseline.phase=Phase::Prepared;
    baseline.diagnosticOem.clear();
    Need(Encode(baseline)==ReadSealed(Join(dir,L"original-state.bin")),L"Original recovery record differs");
    if(!b.diagnosticOem.empty())SafeOem(W(b.diagnosticOem));
    Need(b.phase!=Phase::DismPending,L"Prior DISM retirement or outcome unknown. Keep maintenance PE; preserve receipt for recovery.");
}
// Old completed journals are evidence; never rewrite or use their OEM as current.
static void PriorJournalsIdle(const Target& t){
 for(const auto& prior:{std::make_pair(L"N976nUfsPerf5Prod1-Recovery",kBaseline),
      std::make_pair(L"N976nUfsPerf5Mq1-Recovery",kOldMq1),
      std::make_pair(L"N976nUfsPerf5Mq1Fix1-Recovery",kOldFix1),
      std::make_pair(L"N976nUfsMq1ToProd1-Recovery",kBaseline)}){
  const auto dir=Join(t.root,prior.first);if(!ExistsExact(dir))continue;
  RecoveryPath(dir);const auto b=Load(dir);BindRecord(dir,b,prior.second);
  Need(b.phase==Phase::Installed||b.phase==Phase::Restored,L"Prior recovery unfinished; preserve and resume its own operation");
 }
}
static Backup Prepare(const Target& t,const std::wstring& dir) {
    PackageState(t,kBaseline,kDiagnostic);
    Backup b;
    b.originalOem=U(Oem(t,kBaseline[0].sha256,true));
    b.diagnosticInfHash=U(std::wstring(kDiagnostic[0].sha256,kDiagnostic[0].sha256+64));
    Bytes protectedBefore;
    {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
     BootBinding(t,h,kBaseline);
     Trust(h,kBaseline,0);
     const auto candidate=ReadFileBounded(Join(Join(gExeDir,CandidateDirectory()),kDiagnostic[3].name),65536);
     for(int i=0;i<2;++i)b.certificatePresent[i]=CertificateAction(h.soft,i,candidate,0);
     for(const auto& s:Sets(h.sys)){
         auto path=s+L"\\Services\\N976nUfs";
         ControlBackup cs;cs.name=U(s);cs.imagePath=U(String(Value(h.sys,path,L"ImagePath")));
         for(int n=0;n<7;++n)cs.values[n]=OptionalValue(h.sys,path,kServiceFields[n]);
         b.sets.push_back(cs);
     }
     protectedBefore=Protected(t,h.sys,h.soft);h.close();}
    // Publish a complete record before changing any service, trust or OEM package.
    SameTarget(t);
    auto tmp=dir+L"-new-"+Unique();
    Win(CreateDirectoryW(tmp.c_str(),nullptr),L"Create private recovery evidence");
    RecoveryPath(tmp);
    NewProtection(tmp,L"original-state.bin",Encode(b));
    NewProtection(tmp,L"protected-install.bin",protectedBefore);
    Save(tmp,b);
    Win(MoveFileExW(tmp.c_str(),dir.c_str(),MOVEFILE_WRITE_THROUGH),L"Publish complete recovery record");
    BindRecord(dir,Load(dir));
    return b;
}
static void Service(const Target& t,const std::wstring& dir,Backup& b,const wchar_t* command,
                    const std::wstring& arg,Phase after,const wchar_t* label) {
    SameTarget(t);
    SavePhase(dir,b,Phase::DismPending);
    DWORD rc=Dism(t,command,arg,label);
    Need(rc==ERROR_SUCCESS||rc==ERROR_SUCCESS_REBOOT_REQUIRED,L"DISM returned failure. Keep maintenance PE; original files and pending receipt retained.",rc);
    SavePhase(dir,b,after);
}
static void VerifyBound(const Target& t,const Backup& b,bool installed) {
    const auto pins=installed?kDiagnostic:kBaseline;
    PackageState(t,pins,installed?kBaseline:kDiagnostic);
    Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
    BootBinding(t,h,pins);
    Trust(h,kBaseline,0);
    if(installed){
        Trust(h,kDiagnostic,0);
        Need(U(Oem(t,kDiagnostic[0].sha256,true))==b.diagnosticOem,L"Candidate OEM identity changed");
    }else{
        VerifyOriginalService(h,b);
        OriginalTrust(h,b);
    }
    h.close();
}
#ifdef N976N_MAINTENANCE_SELFTEST
static Phase gSimulatePowerCutAfter=Phase::DismPending;
static void Checkpoint(const Backup& b){
    if(b.phase==gSimulatePowerCutAfter)throw Failure{L"Fixture: stop after durable known phase",ERROR_OPERATION_ABORTED};
}
#else
static void Checkpoint(const Backup&){}
#endif
static constexpr wchar_t kReaderFolder[]=L"N976nUfsTrace1";
static constexpr char kReaderComplete[]="N976N PROD1 TRACE1 COMPLETE\r\n";
static void NewOwnedDirectory(const std::wstring&path,bool results){
    // New tool files are Users RX; only new results are Users Modify. No parent ACL changes.
    const wchar_t*acl=results?L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1301bf;;;BU)":L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)";
    PSECURITY_DESCRIPTOR sd=nullptr;Win(ConvertStringSecurityDescriptorToSecurityDescriptorW(acl,SDDL_REVISION_1,&sd,nullptr)!=FALSE,L"Owned directory ACL");
    SECURITY_ATTRIBUTES sa={sizeof(sa),sd,FALSE};BOOL ok=CreateDirectoryW(path.c_str(),&sa);DWORD error=GetLastError();LocalFree(sd);Need(ok!=FALSE,L"Create new owned directory",error);
}
static Handle* LockDirectory(const std::wstring&path){
    auto h=std::make_unique<Handle>(CreateFileW(path.c_str(),FILE_LIST_DIRECTORY|FILE_READ_ATTRIBUTES,FILE_SHARE_READ,nullptr,OPEN_EXISTING,FILE_FLAG_BACKUP_SEMANTICS|FILE_FLAG_OPEN_REPARSE_POINT,nullptr));
    Win(h->h!=INVALID_HANDLE_VALUE,L"Lock owned directory identity");NoReparse(h->h);return h.release();
}
static void CheckUsersAcl(const std::wstring&path,bool writable,bool directory=true){
 PSECURITY_DESCRIPTOR sd=nullptr;PACL acl=nullptr;PSID owner=nullptr;
 Need(GetNamedSecurityInfoW(path.c_str(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|OWNER_SECURITY_INFORMATION,&owner,nullptr,&acl,nullptr,&sd)==ERROR_SUCCESS,L"Read owned security");
 try{
  SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;Win(GetSecurityDescriptorControl(sd,&control,&revision),L"Read ACL control");
  Need(!directory||(control&SE_DACL_PROTECTED),L"Directory parent ACL inheritance excluded");
  BYTE users[SECURITY_MAX_SID_SIZE],system[SECURITY_MAX_SID_SIZE],admins[SECURITY_MAX_SID_SIZE];DWORD n=sizeof(users);
  Win(CreateWellKnownSid(WinBuiltinUsersSid,nullptr,users,&n),L"Users SID");n=sizeof(system);
  Win(CreateWellKnownSid(WinLocalSystemSid,nullptr,system,&n),L"System SID");n=sizeof(admins);
  Win(CreateWellKnownSid(WinBuiltinAdministratorsSid,nullptr,admins,&n),L"Admins SID");
  Need(owner&&(EqualSid(owner,system)||EqualSid(owner,admins)),L"Trusted tool owner required");
  Need(acl&&acl->AceCount==3,L"Exact owned ACL required");unsigned seen=0;
  for(DWORD i=0;i<3;i++){
   void*raw=nullptr;Win(GetAce(acl,i,&raw),L"Read owned ACE");auto ace=(ACCESS_ALLOWED_ACE*)raw;
   Need(ace->Header.AceType==ACCESS_ALLOWED_ACE_TYPE&&!(ace->Header.AceFlags&INHERIT_ONLY_ACE),L"Exact allowed ACE required");
   PSID sid=&ace->SidStart;unsigned bit=EqualSid(sid,system)?1:EqualSid(sid,admins)?2:EqualSid(sid,users)?4:0;
   Need(bit&&!(seen&bit),L"Unexpected or duplicate tool principal");seen|=bit;
   Need(ace->Mask==(bit==4?(writable?0x1301bfU:0x1200a9U):FILE_ALL_ACCESS),L"Exact tool RX / results Modify rights");
  }
  Need(seen==7,L"Owned ACL principals missing");LocalFree(sd);
 }catch(...){LocalFree(sd);throw;}
}
static void ReaderSource(){
 for(const auto&p:kPayload){auto b=ReadFileBounded(Join(Join(gExeDir,L"payload"),p.name),2*1024*1024);
  Need(b.size()==p.bytes&&HexBytes(Sha(b))==p.sha256,L"Reader payload size/hash differs");}
}
static void ReaderVerify(const Target&t){
 const auto dest=Join(t.root,kReaderFolder);std::unique_ptr<Handle> lock(LockDirectory(dest));CheckUsersAcl(dest,false);
 for(const auto&p:kPayload){CheckUsersAcl(Join(dest,p.name),false,false);auto b=ReadFileBounded(Join(dest,p.name),2*1024*1024);
  Need(b.size()==p.bytes&&HexBytes(Sha(b))==p.sha256,L"Installed reader partial or changed; preserve it");}
 std::unique_ptr<Handle> results(LockDirectory(Join(dest,L"results")));CheckUsersAcl(Join(dest,L"results"),true);
 CheckUsersAcl(Join(dest,L"install-complete.txt"),false,false);
 Need(ReadFileBounded(Join(dest,L"install-complete.txt"),128)==Bytes(kReaderComplete,kReaderComplete+sizeof(kReaderComplete)-1),L"Reader completion marker missing");
}
static void ReaderPreflight(const Target&t){ReaderSource();if(ExistsExact(Join(t.root,kReaderFolder)))ReaderVerify(t);}
#ifdef N976N_MAINTENANCE_SELFTEST
static bool gReaderFail=false;
#endif
static void ReaderDeploy(const Target&t){
#ifdef N976N_MAINTENANCE_SELFTEST
 if(gReaderFail){
  const auto partial=Join(t.root,kReaderFolder);NewOwnedDirectory(partial,false);
  WriteNew(Join(partial,L"install-started.txt"),Bytes{1,2,3});
  throw Failure{L"Fixture reader copy failed after Installed",ERROR_OPERATION_ABORTED};
 }
#endif
 ReaderSource();SameTarget(t);const auto dest=Join(t.root,kReaderFolder);
 if(ExistsExact(dest)){ReaderVerify(t);return;}
 NewOwnedDirectory(dest,false);std::unique_ptr<Handle> lock(LockDirectory(dest));
 const char pending[]="TRACE1 INCOMPLETE - preserve on failure\r\n";WriteNew(Join(dest,L"install-started.txt"),Bytes(pending,pending+sizeof(pending)-1));
 for(const auto&p:kPayload){auto b=ReadFileBounded(Join(Join(gExeDir,L"payload"),p.name),2*1024*1024);
  Need(b.size()==p.bytes&&HexBytes(Sha(b))==p.sha256,L"Reader source changed");WriteNew(Join(dest,p.name),b);
  Need(ReadFileBounded(Join(dest,p.name),2*1024*1024)==b,L"Reader readback differs");}
 NewOwnedDirectory(Join(dest,L"results"),true);
 WriteNew(Join(dest,L"install-complete.txt"),Bytes(kReaderComplete,kReaderComplete+sizeof(kReaderComplete)-1));lock.reset();ReaderVerify(t);
}
static void InstallUfs(){
    Stage(L"1/5 - verify offline 4Kn USERDATA and exact PROD1/TRACE1 packages");
    Target t=FindTarget();PriorJournalsIdle(t);ReaderPreflight(t);DosAliasLease alias;alias.acquire(t);
    const auto dir=Recovery(t);Backup b;
    if(ExistsExact(dir)){
        RecoveryPath(dir);b=Load(dir);BindRecord(dir,b);
        if(b.phase==Phase::Installed){
            VerifyBound(t,b,true);ReaderDeploy(t);alias.close();Stage(CandidatePass());return;
        }
        Need(b.phase==Phase::Prepared||b.phase==Phase::Trusted||b.phase==Phase::RemovedOriginal||
             b.phase==Phase::Staged,L"Install refuses rollback or restored state; keep recovery record");
    }else b=Prepare(t,dir);
    {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
     CheckProtection(t,dir,h,false);Trust(h,kBaseline,0);h.close();}
    if(b.phase==Phase::Prepared){
        Stage(L"2/5 - add selected package trust to offline Windows");
        PackageState(t,kBaseline,kDiagnostic);
        Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
        BootBinding(t,h,kBaseline);VerifyOriginalService(h,b);Trust(h,kDiagnostic,1);h.close();
        SavePhase(dir,b,Phase::Trusted);Checkpoint(b);
    }
    if(b.phase==Phase::Trusted){
        Stage(L"3/5 - remove exact PROD1 OEM from offline Windows");
        PackageState(t,kBaseline,kDiagnostic);
        {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));BootBinding(t,h,kBaseline);Trust(h,kDiagnostic,0);h.close();}
        const auto oem=Oem(t,kBaseline[0].sha256,true);
        Need(b.originalOem==U(oem),L"Original OEM identity changed");
        Service(t,dir,b,L"/Remove-Driver",oem,Phase::RemovedOriginal,L"remove-prod1");Checkpoint(b);
    }
    if(b.phase==Phase::RemovedOriginal){
        Stage(L"4/5 - install selected native boot-critical package");
        NeitherPackage(t);
        Service(t,dir,b,L"/Add-Driver",Join(Join(gExeDir,CandidateDirectory()),L"N976nUfs.inf"),Phase::Staged,L"add-selected");Checkpoint(b);
    }
    Need(b.phase==Phase::Staged,L"Unexpected install step");
    Stage(L"5/5 - check selected boot service, repository, trust and protected settings");
    b.diagnosticOem=U(Oem(t,kDiagnostic[0].sha256,true));
    VerifyBound(t,b,true);
    {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));CheckProtection(t,dir,h,false);h.close();}
    SavePhase(dir,b,Phase::Installed);ReaderDeploy(t);alias.close();Stage(CandidatePass());
}
static void RestoreUfs(){
    Stage(L"Rollback - verify recovery receipt and exact offline USERDATA");
    Target t=FindTarget();PriorJournalsIdle(t);DosAliasLease alias;alias.acquire(t);
    const auto dir=Recovery(t);RecoveryPath(dir);
    Backup b=Load(dir);BindRecord(dir,b);
    if(b.phase==Phase::Restored){
        VerifyBound(t,b,false);alias.close();Stage(L"PASS - PROD1 .89.2.5 restored. Use preserved PERF4-return TAR (88KiB).");return;
    }
    const bool starting=b.phase==Phase::Installed||b.phase==Phase::Staged||b.phase==Phase::Trusted||
                        b.phase==Phase::RemovedOriginal||b.phase==Phase::Prepared;
    if(starting){
        Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
        if(b.phase!=Phase::Installed)CheckProtection(t,dir,h,false);
        if(b.phase==Phase::Installed||b.phase==Phase::Staged){
            PackageState(t,kDiagnostic,kBaseline);BootBinding(t,h,kDiagnostic);
            Trust(h,kDiagnostic,0);auto oem=Oem(t,kDiagnostic[0].sha256,true);
            Need(b.diagnosticOem.empty()||b.diagnosticOem==U(oem),L"Installed OEM changed");b.diagnosticOem=U(oem);
        }else if(b.phase==Phase::RemovedOriginal)NeitherPackage(t);
        else{PackageState(t,kBaseline,kDiagnostic);BootBinding(t,h,kBaseline);VerifyOriginalService(h,b);}
        Trust(h,kBaseline,0);
        // Windows may legitimately change OOBE/power settings between the two boots.
        NewProtection(dir,L"protected-rollback.bin",Protected(t,h.sys,h.soft));h.close();
        SavePhase(dir,b,(b.phase==Phase::Installed||b.phase==Phase::Staged)?Phase::Restoring:
                    (b.phase==Phase::RemovedOriginal?Phase::RestoreRemoved:Phase::RestoreStaged));
    }
    {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));CheckProtection(t,dir,h,true);Trust(h,kBaseline,0);h.close();}
    if(b.phase==Phase::Restoring){
        Stage(L"Rollback - remove exact selected candidate OEM from offline Windows");
        PackageState(t,kDiagnostic,kBaseline);
        const auto oem=Oem(t,kDiagnostic[0].sha256,true);Need(b.diagnosticOem==U(oem),L"Restore OEM identity differs");
        Service(t,dir,b,L"/Remove-Driver",oem,Phase::RestoreRemoved,L"remove-selected");Checkpoint(b);
    }
    if(b.phase==Phase::RestoreRemoved){
        Stage(L"Rollback - restore signed PROD1 boot driver");NeitherPackage(t);
        Service(t,dir,b,L"/Add-Driver",Join(gExeDir,L"baseline\\N976nUfs.inf"),Phase::RestoreStaged,L"restore-prod1");Checkpoint(b);
    }
    Need(b.phase==Phase::RestoreStaged,L"Unexpected restore step");
    {Hives h(Config(t,L"SYSTEM"),Config(t,L"SOFTWARE"));
     BootBinding(t,h,kBaseline);VerifyOriginalService(h,b);CheckProtection(t,dir,h,true);
     Trust(h,kDiagnostic,-1,b.certificatePresent);h.close();}
    VerifyBound(t,b,false);SavePhase(dir,b,Phase::Restored);alias.close();
    Stage(L"PASS - PROD1 .89.2.5 restored. Use preserved PERF4-return TAR (88KiB). No automatic reboot.");
}
#ifdef N976N_MAINTENANCE_SELFTEST
static uint64_t Decimal(const wchar_t*s){Need(s&&*s,L"Decimal fixture argument required");uint64_t n=0;for(;*s;++s){Need(*s>=L'0'&&*s<=L'9'&&n<=(UINT64_MAX-(uint64_t)(*s-L'0'))/10,L"Invalid decimal fixture argument");n=n*10+(uint64_t)(*s-L'0');}return n;}
static void FixtureBus(DWORD disk){
    std::wstring path=L"\\\\.\\PhysicalDrive"+std::to_wstring(disk);Handle h(CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open fixture physical disk read-only");
    struct Query {STORAGE_PROPERTY_QUERY input={};PendingIo output;Query():output(4096){input.PropertyId=StorageDeviceProperty;input.QueryType=PropertyStandardQuery;}};
    auto query=std::make_unique<Query>();DWORD n=0;BOOL ok=DeviceIoControl(h.h,IOCTL_STORAGE_QUERY_PROPERTY,&query->input,sizeof(query->input),query->output.data.data(),4096,&n,&query->output.ov);
    try{n=Retire(h.h,&query->output,ok,n);}catch(...){if(gUncertain){query.release();h.release();}throw;}
    Need(n>=sizeof(STORAGE_DEVICE_DESCRIPTOR),L"Fixture disk descriptor bound");const auto*d=(const STORAGE_DEVICE_DESCRIPTOR*)query->output.data.data();Need(d->BusType==BusTypeFileBackedVirtual,L"Fixture must be an explicitly supplied file-backed virtual disk");
}
static Target AdmitFixture(const std::wstring&input,DWORD disk,uint64_t offset,uint64_t bytes){
    std::wstring v=CanonicalVolume(input);Need(EqualPath(v,input),L"Fixture GUID must be canonical");Need(!EqualPath(VolumeDevice(v),SystemVolumeDevice()),L"Running Windows volume cannot be a test fixture");FixtureBus(disk);
    Handle h(CreateFileW(v.substr(0,v.size()-1).c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE,nullptr,OPEN_EXISTING,FILE_FLAG_OVERLAPPED,nullptr));Win(h.h!=INVALID_HANDLE_VALUE,L"Open fixture volume read-only");
    try{wchar_t fs[32]={};Win(GetVolumeInformationByHandleW(h.h,nullptr,0,nullptr,nullptr,nullptr,fs,32),L"Fixture filesystem");Need(!_wcsicmp(fs,L"NTFS"),L"Fixture NTFS required");
        NTFS_VOLUME_DATA_BUFFER ntfs={};IdentitySize(Ioctl(h.h,FSCTL_GET_NTFS_VOLUME_DATA,&ntfs,sizeof(ntfs)),sizeof(ntfs),L"NTFS");
        auto t=InspectTarget(h.h,v,ntfs,SystemVolumeDevice());
        Need(t.disk==disk&&offset==kStart&&bytes==kPartitionBytes,L"Fixture exact supplied disk/offset/64GiB range");
        VerifyVolumeRoot(t);return t;
    }catch(...){if(gUncertain)h.release();throw;}
}
static Bytes AliasSnapshot(){Bytes out;DWORD drives=GetLogicalDrives();Win(drives!=0,L"Fixture DOS-drive bitmap");Put32(out,drives);for(wchar_t letter=L'A';letter<=L'Z';++letter){std::wstring alias(1,letter);alias+=L":";std::u16string raw;bool found=QueryAlias(alias,raw);Put32(out,found?1:0);Put32(out,(uint32_t)raw.size());for(char16_t c:raw){out.push_back((unsigned char)c);out.push_back((unsigned char)(c>>8));}}return out;}

static void TestReaderAclRefusals(const Target&t){
 const auto root=Join(t.root,kReaderFolder);
 for(const auto&item:{std::make_pair(root,L"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200e9;;;BU)"),
                     std::make_pair(Join(root,kPayload[0].name),L"D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200ab;;;BU)")}){
  PSECURITY_DESCRIPTOR before=nullptr,bad=nullptr;PACL original=nullptr,changed=nullptr;BOOL present=FALSE,defaulted=FALSE;
  Need(GetNamedSecurityInfoW(item.first.c_str(),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION,nullptr,nullptr,&original,nullptr,&before)==ERROR_SUCCESS,L"Fixture save ACL");
  SECURITY_DESCRIPTOR_CONTROL control=0;DWORD revision=0;Win(GetSecurityDescriptorControl(before,&control,&revision),L"Fixture ACL control");
  Win(ConvertStringSecurityDescriptorToSecurityDescriptorW(item.second,SDDL_REVISION_1,&bad,nullptr),L"Fixture altered ACL");
  Win(GetSecurityDescriptorDacl(bad,&present,&changed,&defaulted)&&present,L"Fixture changed DACL");
  Need(SetNamedSecurityInfoW(const_cast<wchar_t*>(item.first.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|PROTECTED_DACL_SECURITY_INFORMATION,nullptr,nullptr,changed,nullptr)==ERROR_SUCCESS,L"Fixture apply altered ACL");
  bool refused=false;try{ReaderVerify(t);}catch(const Failure&){refused=true;}
  Need(SetNamedSecurityInfoW(const_cast<wchar_t*>(item.first.c_str()),SE_FILE_OBJECT,DACL_SECURITY_INFORMATION|((control&SE_DACL_PROTECTED)?PROTECTED_DACL_SECURITY_INFORMATION:UNPROTECTED_DACL_SECURITY_INFORMATION),nullptr,nullptr,original,nullptr)==ERROR_SUCCESS,L"Fixture restore owned ACL");
  LocalFree(before);LocalFree(bad);Need(refused,L"Users file-write/root-delete-child rights must be refused");ReaderVerify(t);
 }
}
static void TestPriorJournals(const Target&t){
 const auto dir=Join(t.root,L"N976nUfsPerf5Mq1-Recovery");Need(!ExistsExact(dir),L"Fresh prior-journal fixture required");
 auto b=Load(Join(t.root,L"N976nUfsPerf5Prod1-Recovery"));
 b.diagnosticInfHash=U(std::wstring(kOldMq1[0].sha256,kOldMq1[0].sha256+64));
 b.phase=Phase::Prepared;b.diagnosticOem.clear();
 Win(CreateDirectoryW(dir.c_str(),nullptr),L"Owned test journal");NewProtection(dir,L"original-state.bin",Encode(b));
 SavePhase(dir,b,Phase::Installed);PriorJournalsIdle(t);
 auto reject=[&](){bool refused=false;try{PriorJournalsIdle(t);}catch(const Failure&){refused=true;}Need(refused,L"Prior unfinished/corrupt journal must stop");};
 SavePhase(dir,b,Phase::Trusted);reject();SavePhase(dir,b,Phase::DismPending);reject();
 b.diagnosticInfHash=std::u16string(64,u'0');SavePhase(dir,b,Phase::Installed);reject();
 // Delete only this synthetic journal, on the explicitly admitted disposable child.
 Win(DeleteFileW(Join(dir,L"state.bin").c_str()),L"Remove test state");
 Win(DeleteFileW(Join(dir,L"original-state.bin").c_str()),L"Remove test original");Win(RemoveDirectoryW(dir.c_str()),L"Remove test journal");
 PriorJournalsIdle(t);
}
int wmain(int argc,wchar_t**argv){try{
    if(argc==1){
        for(unsigned action=1;action<=2;action++){MenuState m;unsigned got=0;auto cb=[](MenuAction a,void* p){*(unsigned*)p=(unsigned)a;};Need(!DispatchMenu(m,5,cb,&got)&&!got,L"Invalid menu action rejected");Need(DispatchMenu(m,action,cb,&got)&&got==action,L"Exact fixed menu dispatch");for(unsigned again=1;again<=2;again++)Need(!DispatchMenu(m,again,cb,&got)&&got==action,L"One operation per boot");}
        Identity id;id.serial=kSerial;id.start=kStart;id.partitionBytes=id.extentBytes=kPartitionBytes;id.extentStart=kStart;id.totalClusters=kImageSectors;id.mftStart=3;id.sectors=kBpbSectors;id.sectorBytes=4096;id.clusterBytes=4096;id.extents=1;id.ntfs=id.gpt=id.marker=true;std::memcpy(id.guid,kPartitionGuid,16);Need(Admit(id),L"valid identity");
        id.systemVolume=true;Need(!Admit(id),L"live Windows rejected");id.systemVolume=false;id.start++;Need(!Admit(id),L"wrong extent rejected");id.start--;id.guid[0]^=1;Need(!Admit(id),L"wrong GUID rejected");id.guid[0]^=1;id.marker=false;Need(!Admit(id),L"wrong marker rejected");
        for(DWORD size:{(DWORD)sizeof(NTFS_VOLUME_DATA_BUFFER),(DWORD)sizeof(VOLUME_DISK_EXTENTS),(DWORD)sizeof(PARTITION_INFORMATION_EX)}){
            bool shortRefused=false;try{IdentitySize(size-1,size,L"selftest");}catch(const Failure&){shortRefused=true;}
            Need(shortRefused,L"Truncated native identity responses refused");IdentitySize(size,size,L"selftest");
        }
        Backup b;b.diagnosticInfHash=std::u16string(64,u'a');ControlBackup cs;cs.name=u"ControlSet001";cs.imagePath=u"System32\\x";cs.values[0]={true,1,{0,1,0,0xff}};b.sets.push_back(cs);auto wire=Encode(b);Need(Encode(Decode(wire))==wire,L"original raw record codec");wire.push_back(0);bool refused=false;try{Decode(wire);}catch(const std::exception&){refused=true;}Need(refused,L"record trailing data rejected");
        refused=false;try{RequirePE();}catch(const Failure&){refused=true;}Need(refused,L"production must refuse non-PE build VM");
        std::puts("PASS identity, live-OS guard, raw state codec, corrupt receipt rejection. No servicing.");return 0;
    }
    Need(argc==10&&!wcscmp(argv[3],L"--disk")&&!wcscmp(argv[5],L"--offset")&&!wcscmp(argv[7],L"--bytes"),L"exact test-only fixture arguments required");
    const std::wstring mode=argv[1];
    Need(mode==L"--fixture"||mode==L"--fixture-install"||mode==L"--fixture-rollback",L"Unknown fixture action");
    auto disk=Decimal(argv[4]);Need(disk<=MAXDWORD,L"Disk number bound");
    gFixture={true,argv[2],(DWORD)disk,Decimal(argv[6]),Decimal(argv[8])};
    gExeDir=argv[9];gLog=Join(gExeDir,L"ufs-workflow.log");
    wchar_t systemPath[MAX_PATH];Win(GetVolumePathNameW(gExeDir.c_str(),systemPath,MAX_PATH),L"Fixture package root");
    Need(EqualPath(VolumeDevice(systemPath),SystemVolumeDevice()),L"Fixture packaged inputs must be on VM system disk");
    auto t=AdmitFixture(gFixture.volume,gFixture.disk,gFixture.offset,gFixture.bytes);
    const auto aliases=AliasSnapshot();
    if(mode==L"--fixture-install"){InstallUfs();TestReaderAclRefusals(t);}
    else if(mode==L"--fixture-rollback")RestoreUfs();
    else{
        auto dir=Recovery(t);Need(!ExistsExact(dir),L"Isolated failure fixture requires fresh child");
        TestPriorJournals(t);
        const auto payload=Join(Join(gExeDir,L"payload"),kPayload[0].name),hidden=payload+L".fixture-hidden";
        Win(MoveFileW(payload.c_str(),hidden.c_str()),L"Inject missing reader source");
        bool preflight=false;try{InstallUfs();}catch(const Failure&){preflight=true;}
        Win(MoveFileW(hidden.c_str(),payload.c_str()),L"Restore fixture reader source");
        Need(preflight&&!ExistsExact(dir),L"Reader preflight failed before servicing/journal");
        auto interrupted=[&](void(*operation)(),Phase after){
            gSimulatePowerCutAfter=after;bool caught=false;
            try{operation();}catch(const Failure& e){caught=e.code==ERROR_OPERATION_ABORTED;}
            gSimulatePowerCutAfter=Phase::DismPending;
            Need(caught&&!gUncertain&&Load(dir).phase==after,L"Expected durable interruption missing");
        };
        interrupted(InstallUfs,Phase::RemovedOriginal);
        NeitherPackage(t);auto saved=Load(dir);
        SavePhase(dir,saved,Phase::DismPending);
        bool refusedInstall=false,refusedRestore=false;
        try{InstallUfs();}catch(const Failure&){refusedInstall=true;}
        try{RestoreUfs();}catch(const Failure&){refusedRestore=true;}
        Need(refusedInstall&&refusedRestore&&Load(dir).phase==Phase::DismPending,L"Unknown DISM outcome must stop");
        NeitherPackage(t);
        // Restore only the test's injected journal flag on this explicitly admitted VHD.
        SavePhase(dir,saved,Phase::RemovedOriginal);
        gReaderFail=true;bool readerFailed=false;try{InstallUfs();}catch(const Failure&e){readerFailed=e.code==ERROR_OPERATION_ABORTED;}
        gReaderFail=false;Need(readerFailed&&Load(dir).phase==Phase::Installed,L"Reader failure must leave Installed driver journal");
        bool partialRefused=false;try{InstallUfs();}catch(const Failure&){partialRefused=true;}
        Need(partialRefused&&Load(dir).phase==Phase::Installed,L"Partial reader must not give install PASS");
        // Restore remains independent of unavailable reader payload/partial deployment.

        Win(MoveFileW(payload.c_str(),hidden.c_str()),L"Inject missing reader source during rollback");
        interrupted(RestoreUfs,Phase::RestoreRemoved);
        NeitherPackage(t);RestoreUfs();
        Need(Load(dir).phase==Phase::Restored,L"Known rollback checkpoint not resumed");
        Win(MoveFileW(hidden.c_str(),payload.c_str()),L"Restore fixture source after rollback");
        std::puts("PASS known install/rollback checkpoints resumed; uncertain DISM install and rollback both refused");
    }
    Need(!gUncertain&&AliasSnapshot()==aliases,L"Uncertain operation or DOS alias leak");
    std::puts("PASS native UFS maintenance fixture; exact alias cleanup; no live driver load");return 0;
}catch(const Failure&e){std::fwprintf(stderr,L"STOP %ls / %08lX\n",e.message.c_str(),e.code);return gUncertain?2:1;}catch(const std::exception&e){std::fprintf(stderr,"STOP %s\n",e.what());return gUncertain?2:1;}}
#else
static MenuState gMenu;
static HWND gInstall=nullptr,gRollback=nullptr;
static DWORD WINAPI Worker(void* selected){try{
    // action.txt is inside the sealed PE WIM; no external path/command discovery.
    auto action=ReadFileBounded(Join(gExeDir,L"action.txt"),32);std::string mode(action.begin(),action.end());
    Need(mode=="menu\n",L"Exact sealed SEC89 menu required");
    const auto actionId=static_cast<MenuAction>(reinterpret_cast<uintptr_t>(selected));
    Need(actionId>=MenuAction::Install&&actionId<=MenuAction::Rollback,L"Explicit menu action required");
    RequirePE();
    Handle lease(CreateMutexW(nullptr,FALSE,L"Global\\N976nUfsPerf5Maintenance"));
    DWORD mutexError=GetLastError();Win(lease.h!=nullptr,L"Open maintenance mutex");
    Need(mutexError!=ERROR_ALREADY_EXISTS,L"Another UFS maintenance session exists");
    if(actionId==MenuAction::Install)InstallUfs();else RestoreUfs();
}catch(const Failure&e){Stage(L"STOP - "+gStage+L" / "+e.message+L" / "+Hex(e.code));if(gUncertain)Log(L"Retirement unknown: keep PE running. No retry, reboot or further writes.");}
catch(const std::exception&e){std::string m=e.what();Stage(L"STOP - "+std::wstring(m.begin(),m.end()));}
    gBusy=false;return 0;
}
static void StartMenuWorker(MenuAction action,void*) {
    EnableWindow(gInstall,FALSE);EnableWindow(gRollback,FALSE);gBusy=true;
    Stage(L"Selected operation - verify packages and recovery records; preserve touch and battery");
    Handle worker(CreateThread(nullptr,0,Worker,reinterpret_cast<void*>(static_cast<uintptr_t>(action)),0,nullptr));
    if(!worker.h){gBusy=false;Stage(L"STOP - cannot start worker. No automatic retry.");}
}
static LRESULT CALLBACK WindowProc(HWND w,UINT m,WPARAM wp,LPARAM lp){
    if(m==WM_CREATE){gWindow=w;RECT r;GetClientRect(w,&r);int margin=std::max<int>(35,r.right/16),top=std::max<int>(90,r.bottom/16);
        int line=std::max<int>(23,r.right/42),head=4*line,button=3*line,gap=line;
        HFONT font=CreateFontW(-line,0,0,0,FW_NORMAL,FALSE,FALSE,FALSE,DEFAULT_CHARSET,OUT_DEFAULT_PRECIS,CLIP_DEFAULT_PRECIS,DEFAULT_QUALITY,DEFAULT_PITCH,L"Segoe UI");
        gHeadline=CreateWindowW(L"STATIC",L"SEC89 UFS PROD1 TRACE1\r\nKeep current touch and battery. One operation per boot.\r\nInstall trace + reader, or restore PROD1. No automatic reboot.",WS_CHILD|WS_VISIBLE,margin,top,r.right-2*margin,head,w,nullptr,nullptr,nullptr);SendMessageW(gHeadline,WM_SETFONT,(WPARAM)font,TRUE);
        int width=(r.right-2*margin-gap)/2,y=top+head+gap;
        gInstall=CreateWindowW(L"BUTTON",L"INSTALL PROD1 TRACE1",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,margin,y,width,button,w,(HMENU)1,nullptr,nullptr);
        gRollback=CreateWindowW(L"BUTTON",L"RESTORE PROD1",WS_CHILD|WS_VISIBLE|WS_TABSTOP|BS_PUSHBUTTON,margin+width+gap,y,width,button,w,(HMENU)2,nullptr,nullptr);
        SendMessageW(gInstall,WM_SETFONT,(WPARAM)font,TRUE);SendMessageW(gRollback,WM_SETFONT,(WPARAM)font,TRUE);
        y+=button+gap;
        gText=CreateWindowExW(WS_EX_CLIENTEDGE,L"EDIT",L"Waiting for your selection. No offline installation has started.\r\n",WS_CHILD|WS_VISIBLE|ES_MULTILINE|ES_READONLY|ES_AUTOVSCROLL|WS_VSCROLL,margin,y,r.right-2*margin,r.bottom-y-margin,w,nullptr,nullptr,nullptr);SendMessageW(gText,WM_SETFONT,(WPARAM)font,TRUE);SendMessageW(gText,EM_SETLIMITTEXT,256*1024,0);return 0;}
    if(m==WM_COMMAND && HIWORD(wp)==BN_CLICKED &&
       ((LOWORD(wp)==1 && (HWND)lp==gInstall)||(LOWORD(wp)==2 && (HWND)lp==gRollback))){
        DispatchMenu(gMenu,LOWORD(wp),StartMenuWorker,nullptr);return 0;}
    if(m==WM_APP+1){std::unique_ptr<std::wstring>s((std::wstring*)lp);SendMessageW(gText,EM_SETSEL,(WPARAM)-1,(LPARAM)-1);SendMessageW(gText,EM_REPLACESEL,FALSE,(LPARAM)s->c_str());if(s->rfind(L"PASS",0)==0||s->rfind(L"STOP",0)==0)SetWindowTextW(gHeadline,s->c_str());return 0;}
    if(m==WM_CLOSE)return 0; // Preserve PASS/STOP and any uncertain operation.
    return DefWindowProcW(w,m,wp,lp);
}
int WINAPI wWinMain(HINSTANCE instance,HINSTANCE,PWSTR,int){SetProcessDPIAware();wchar_t file[32768];DWORD n=GetModuleFileNameW(nullptr,file,32768);if(!n||n>=32768)return 1;gExeDir=std::wstring(file,n);gExeDir.resize(gExeDir.find_last_of(L'\\'));gLog=Join(gExeDir,L"ufs-maintenance-"+Unique()+L".log");
    WNDCLASSW wc={};wc.hInstance=instance;wc.lpfnWndProc=WindowProc;wc.lpszClassName=L"SEC89UfsPerf5Prod1Trace1Maintenance";wc.hbrBackground=(HBRUSH)(COLOR_WINDOW+1);if(!RegisterClassW(&wc))return 1;
    HWND w=CreateWindowW(wc.lpszClassName,L"N976N SEC89 UFS PROD1 TRACE1",WS_POPUP|WS_VISIBLE,0,0,GetSystemMetrics(SM_CXSCREEN),GetSystemMetrics(SM_CYSCREEN),nullptr,nullptr,instance,nullptr);if(!w)return 1;UpdateWindow(w);MSG m;while(GetMessageW(&m,nullptr,0,0)>0){TranslateMessage(&m);DispatchMessageW(&m);}return (int)m.wParam;
}
#endif
