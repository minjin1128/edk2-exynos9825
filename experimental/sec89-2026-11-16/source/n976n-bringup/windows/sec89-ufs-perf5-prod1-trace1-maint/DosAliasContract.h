#pragma once
#include <string>
namespace maintenance {
// Every letter is considered, including A/B that WinPE commonly leaves unused.
constexpr char16_t kAliasOrder[]=u"ABZYXWVUTSRQPONMLKJIHGFEDC";
inline char16_t FoldDos(char16_t c){return c>=u'A'&&c<=u'Z'?(char16_t)(c+(u'a'-u'A')):c;}
inline bool SingleDosTarget(const std::u16string&raw,const std::u16string&expected){
    if(expected.empty()||expected.find(u'\0')!=std::u16string::npos||raw.size()<expected.size()+1)return false;
    for(size_t i=0;i<expected.size();++i)if(FoldDos(raw[i])!=FoldDos(expected[i]))return false;
    for(size_t i=expected.size();i<raw.size();++i)if(raw[i])return false;return true;
}
}
