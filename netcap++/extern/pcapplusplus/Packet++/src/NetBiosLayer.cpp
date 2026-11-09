#define LOG_MODULE PacketLogModuleNetBiosLayer

#include "NetBiosLayer.h"
#include <sstream>

namespace pcpp
{

std::string NetBiosLayer::toString() const
{
    std::stringstream stream;
    stream << "NetBIOS Layer";
    return stream.str();
}

} // namespace pcpp
