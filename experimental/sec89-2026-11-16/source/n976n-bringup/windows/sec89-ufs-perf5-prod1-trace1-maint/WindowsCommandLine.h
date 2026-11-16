#pragma once
#include <stdexcept>
#include <string>
#include <vector>

namespace maintenance {
// Quote one argv element for CreateProcessW/MS C startup. Backslashes before a
// quote, including the closing quote, must be doubled; no shell is involved.
inline std::u16string QuoteWindowsArgument(const std::u16string&arg){
    if(arg.find(u'\0')!=std::u16string::npos)throw std::runtime_error("argument contains NUL");
    std::u16string out(1,u'"');size_t slash=0;
    for(char16_t c:arg){if(c==u'\\'){++slash;continue;}out.append(c==u'"'?slash*2+1:slash,u'\\');out+=c;slash=0;}
    out.append(slash*2,u'\\');out+=u'"';return out;
}
inline std::u16string WindowsCommandLine(const std::vector<std::u16string>&args){
    if(args.empty()||args[0].empty())throw std::runtime_error("executable argument missing");
    std::u16string command;for(const auto&arg:args){if(!command.empty())command+=u' ';command+=QuoteWindowsArgument(arg);if(command.size()>=32767)throw std::runtime_error("command line too long");}return command;
}
}
