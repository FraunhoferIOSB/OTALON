#define LOG_MODULE PacketLogModuleSsdpLayer

#include "SsdpLayer.h"
#include <sstream>

namespace pcpp
{

std::string SsdpLayer::toString() const
{
    std::stringstream stream;
    stream << "SSDP Layer";
    return stream.str();
}

} // namespace pcpp
