#define LOG_MODULE PacketLogModuleSyslogLayer

#include "SyslogLayer.h"
#include "EthLayer.h"
#include <string.h>
#include "EndianPortable.h"
#include <sstream>

namespace pcpp
{

std::string SyslogLayer::toString() const
{
    std::stringstream stream;
    stream << "Syslog Layer";
    return stream.str();
}

} // namespace pcpp
