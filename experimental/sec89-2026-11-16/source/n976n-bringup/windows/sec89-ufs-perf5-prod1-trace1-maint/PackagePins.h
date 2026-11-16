#pragma once
#include <cstdint>
struct PackagePin {const wchar_t* name; uint64_t bytes; const char* sha256;};
static const PackagePin kBaseline[4]={
    {L"N976nUfs.inf",1008,"ef66aa0cd734953b9df29902c844c3c9611a4a2b22c9203f229ff53f09dd9869"},
    {L"N976nUfs.sys",73056,"c190a93fe988c815f0e00a20d644dd31328805da8761ab6a56e1a9fae886ad7f"},
    {L"n976nufs.cat",2860,"9e2bdc6df0df55be4646f57342360e76a5b7d110f1f68a9ac8c5cf1fec242d78"},
    {L"N976nUfsTest.cer",1091,"b50d12a0d7b878d4776b6ad9276072e04064ebefd70767975c727dd51ec2f714"},
};
static const PackagePin kDiagnostic[4]={
    {L"N976nUfs.inf",1008,"afa7f4611588662430bb6a464fc2e96f77cac274336cc230b0c38e4a8abcc6dc"},
    {L"N976nUfs.sys",76656,"1fa3456c508ee3357760f6da023322e602bb6ba1534801323a8934da435afa93"},
    {L"n976nufs.cat",2881,"12aaeae7bde8ea0fba3748d84e885f35bd499e226f414e1656fe97cdfff174b9"},
    {L"N976nUfsTest.cer",1105,"eb6a30583e0f3bb8069acd488de9b07f54994c1a53ae4f03695dddaf8385fcea"},
};
static const PackagePin kOldMq1[4]={
    {L"N976nUfs.inf",1004,"ab3668b86d5755619527ea98a095aac7e3241702870d010e4d9803dee7fbddbb"},
    {L"N976nUfs.sys",82776,"cce4c99f2d9953b531715821d3f5837bf7b3d7a0ebf8e61dc8d3c4b04ba7f3a4"},
    {L"n976nufs.cat",2854,"50ce58c4a2039f95e3e4080f5938e8fe783d0e5a1113715d24bb98c4effe39b0"},
    {L"N976nUfsTest.cer",1087,"31e24cfb6973b567ca5f031545fad2ea85c19cb4ca784446be475992f06cdef3"},
};
static const PackagePin kOldFix1[4]={
    {L"N976nUfs.inf",1014,"21a42d59d0d9ebc49f3ca465f098d8d56abd56fe5931d281876cc80b1c1ba694"},
    {L"N976nUfs.sys",83328,"0c2d6999052dd3162f159b003aac5ba26f304a04f716241df77a9e24903f5e1d"},
    {L"n976nufs.cat",2890,"dfb5557e521992900ee12768e6c4e529f5f9a4ced42f2eb25633c612a5db9cc7"},
    {L"N976nUfsTest.cer",1111,"c386fdc278596c16da8cbe19329c5402e07f28935e572a1c9cd3cb13bda003f9"},
};
