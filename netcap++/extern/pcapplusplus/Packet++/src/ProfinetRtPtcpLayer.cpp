#define LOG_MODULE PacketLogModuleProfinetRtPtcpLayer

#include "ProfinetRtPtcpLayer.h"
#include <sstream>

namespace pcpp
{

std::string ProfinetRtPtcpLayer::toString() const
{
    std::stringstream stream;
    stream << "Profinet RT PTCP Layer";
    return stream.str();
}

} // namespace pcpp
