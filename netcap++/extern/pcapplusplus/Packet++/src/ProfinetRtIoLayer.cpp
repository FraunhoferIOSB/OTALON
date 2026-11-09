#define LOG_MODULE PacketLogModuleProfinetRtIoLayer

#include "ProfinetRtIoLayer.h"
#include <sstream>

namespace pcpp
{

std::string ProfinetRtIoLayer::toString() const
{
    std::stringstream stream;
    stream << "Profinet RT IO Layer";
    return stream.str();
}

} // namespace pcpp
