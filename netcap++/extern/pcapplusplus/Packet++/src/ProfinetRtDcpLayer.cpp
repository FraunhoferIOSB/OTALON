#define LOG_MODULE PacketLogModuleProfinetRtDcpLayer

#include "ProfinetRtDcpLayer.h"
#include <sstream>

namespace pcpp
{

std::string ProfinetRtDcpLayer::toString() const
{
    std::stringstream stream;
    stream << "Profinet RT DCP Layer";
    return stream.str();
}

} // namespace pcpp
