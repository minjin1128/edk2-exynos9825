#pragma once
#include <cstdint>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

namespace maintenance {
constexpr uint64_t kSerial=0x9AD6604DD6602C27ULL;
constexpr uint64_t kStart=0x222200ULL*4096;
// PERF5 exposes only the NTFS-backed 64GiB view; raw GPT length is not an alternative.
constexpr uint64_t kRawPartitionBytes=0x3972800ULL*4096;
constexpr uint64_t kPartitionBytes=0x1000000ULL*4096;
constexpr uint64_t kImageSectors=0x1000000ULL;
constexpr uint64_t kBpbSectors=0xFFFFFFULL;
constexpr char kMarker[]="N976N SEC85 FullWindows native4Kn\nimage_bytes=68719476736\npartition_start_lba=2236928\n";
constexpr unsigned char kPartitionGuid[16]={0x41,0x4e,0x44,0x52,0x4f,0x49,0x44,0x20,0x75,0x73,0x65,0x72,0x64,0x61,0x74,0x61};
struct Identity {
    uint64_t serial=0,start=0,partitionBytes=0,sectors=0,extentStart=0,extentBytes=0;
    uint64_t totalClusters=0,mftStart=0;
    uint32_t sectorBytes=0,clusterBytes=0,extents=0;
    unsigned char guid[16]={};
    bool ntfs=false,gpt=false,systemVolume=false,marker=false;
};
struct IdentityMismatch {std::wstring field;uint64_t expected,actual;};
inline std::vector<IdentityMismatch> IdentityMismatches(const Identity& x) {
    std::vector<IdentityMismatch> out;
    auto exact=[&](const wchar_t* field,uint64_t expected,uint64_t actual){if(expected!=actual)out.push_back({field,expected,actual});};
    exact(L"NTFS",1,x.ntfs);exact(L"GPT",1,x.gpt);exact(L"running OS volume",0,x.systemVolume);
    exact(L"SEC85 marker content",1,x.marker);exact(L"extent count",1,x.extents);
    exact(L"NTFS serial",kSerial,x.serial);exact(L"partition start",kStart,x.start);
    exact(L"partition bytes (64GiB view)",kPartitionBytes,x.partitionBytes);
    exact(L"extent start",kStart,x.extentStart);exact(L"extent bytes (64GiB view)",kPartitionBytes,x.extentBytes);
    exact(L"sector bytes",4096,x.sectorBytes);exact(L"cluster bytes",4096,x.clusterBytes);
    if(x.sectors!=kBpbSectors&&x.sectors!=kImageSectors)out.push_back({L"NTFS sectors (0xFFFFFF or 0x1000000)",kImageSectors,x.sectors});
    for(unsigned n=0;n<16;n++)if(x.guid[n]!=kPartitionGuid[n])out.push_back({L"partition GUID byte["+std::to_wstring(n)+L"]",kPartitionGuid[n],x.guid[n]});
    if(!x.totalClusters||x.totalClusters>kImageSectors)out.push_back({L"total clusters (1..0x1000000)",kImageSectors,x.totalClusters});
    if(x.mftStart>=x.totalClusters)out.push_back({L"MFT LCN (less than total clusters)",x.totalClusters,x.mftStart});
    return out;
}
inline bool Admit(const Identity& x) {return IdentityMismatches(x).empty();}
struct RawValue { bool present=false;uint32_t type=0;std::vector<unsigned char> bytes; };
inline bool operator==(const RawValue&a,const RawValue&b){return a.present==b.present&&a.type==b.type&&a.bytes==b.bytes;}
enum class Phase:uint32_t {Prepared=1,Trusted=2,DismPending=3,Staged=4,Installed=5,Restoring=6,Restored=7,RemovedOriginal=8,RestoreRemoved=9,RestoreStaged=10};
struct ControlBackup {std::u16string name,imagePath;RawValue values[7];};
struct Backup {
    uint32_t formatVersion=2;std::u16string diagnosticInfHash;
    Phase phase=Phase::Prepared;std::u16string originalOem,diagnosticOem;
    bool certificatePresent[2]={false,false};std::vector<ControlBackup> sets;
};
inline void Put32(std::vector<unsigned char>&b,uint32_t n){for(int i=0;i<4;i++)b.push_back((unsigned char)(n>>(8*i)));}
inline uint32_t Get32(const std::vector<unsigned char>&b,size_t& p){if(p>b.size()||b.size()-p<4)throw std::runtime_error("truncated backup");uint32_t n=0;for(int i=0;i<4;i++)n|=uint32_t(b[p++])<<(8*i);return n;}
inline void PutString(std::vector<unsigned char>&b,const std::u16string&s){if(s.size()>1024)throw std::runtime_error("backup string too long");Put32(b,(uint32_t)s.size());for(char16_t c:s){b.push_back((unsigned char)c);b.push_back((unsigned char)(c>>8));}}
inline std::u16string GetString(const std::vector<unsigned char>&b,size_t&p){uint32_t n=Get32(b,p);if(n>1024||n>(b.size()-p)/2)throw std::runtime_error("invalid backup string");std::u16string s;for(uint32_t i=0;i<n;i++){char16_t c=b[p]|(uint16_t(b[p+1])<<8);p+=2;if(!c)throw std::runtime_error("embedded NUL");s.push_back(c);}return s;}
inline std::vector<unsigned char> Encode(const Backup&s){
    std::vector<unsigned char>b;Put32(b,0x38384655);if(s.formatVersion!=1&&s.formatVersion!=2)throw std::runtime_error("unsupported backup version");Put32(b,s.formatVersion);Put32(b,(uint32_t)s.phase);
    if(s.formatVersion==2){if(s.diagnosticInfHash.size()!=64||s.diagnosticInfHash.find_first_not_of(u"0123456789abcdef")!=std::u16string::npos)throw std::runtime_error("diagnostic INF identity required");PutString(b,s.diagnosticInfHash);}else if(!s.diagnosticInfHash.empty())throw std::runtime_error("legacy backup cannot change diagnostic identity");
    PutString(b,s.originalOem);PutString(b,s.diagnosticOem);for(bool v:s.certificatePresent)Put32(b,v?1:0);
    if(s.sets.empty()||s.sets.size()>8)throw std::runtime_error("invalid control set count");Put32(b,(uint32_t)s.sets.size());
    for(const auto&cs:s.sets){PutString(b,cs.name);PutString(b,cs.imagePath);if(s.formatVersion==1&&(cs.values[6].present||cs.values[6].type||!cs.values[6].bytes.empty()))throw std::runtime_error("legacy backup has unexpected seventh value");for(size_t index=0;index<(s.formatVersion==1?6u:7u);++index){const auto&v=cs.values[index];if(v.bytes.size()>65536||(!v.present&&(!v.bytes.empty()||v.type)))throw std::runtime_error("invalid raw value");Put32(b,v.present?1:0);Put32(b,v.type);Put32(b,(uint32_t)v.bytes.size());b.insert(b.end(),v.bytes.begin(),v.bytes.end());}}
    return b;
}
inline Backup Decode(const std::vector<unsigned char>&b){
    if(b.size()>4*1024*1024)throw std::runtime_error("backup too large");size_t p=0;Backup s;
    if(Get32(b,p)!=0x38384655)throw std::runtime_error("wrong backup magic");s.formatVersion=Get32(b,p);if(s.formatVersion!=1&&s.formatVersion!=2)throw std::runtime_error("wrong backup version");uint32_t phase=Get32(b,p);if(phase<1||phase>10)throw std::runtime_error("invalid backup phase");s.phase=(Phase)phase;
    if(s.formatVersion==2){s.diagnosticInfHash=GetString(b,p);if(s.diagnosticInfHash.size()!=64||s.diagnosticInfHash.find_first_not_of(u"0123456789abcdef")!=std::u16string::npos)throw std::runtime_error("invalid diagnostic INF identity");}
    s.originalOem=GetString(b,p);s.diagnosticOem=GetString(b,p);for(bool&v:s.certificatePresent){uint32_t n=Get32(b,p);if(n>1)throw std::runtime_error("invalid cert state");v=n!=0;}
    uint32_t count=Get32(b,p);if(!count||count>8)throw std::runtime_error("invalid control set count");
    for(uint32_t i=0;i<count;i++){ControlBackup cs;cs.name=GetString(b,p);cs.imagePath=GetString(b,p);for(size_t index=0;index<(s.formatVersion==1?6u:7u);++index){auto&v=cs.values[index];uint32_t present=Get32(b,p);v.type=Get32(b,p);uint32_t n=Get32(b,p);if(present>1||n>65536||n>b.size()-p||(!present&&(n||v.type)))throw std::runtime_error("invalid raw value");v.present=present!=0;v.bytes.assign(b.begin()+p,b.begin()+p+n);p+=n;}s.sets.push_back(cs);}
    if(p!=b.size())throw std::runtime_error("trailing backup data");return s;
}
}
