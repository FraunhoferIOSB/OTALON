#define LOG_MODULE PacketLogModuleLldpLayer

#include "LldpLayer.h"
#include "EthLayer.h"
#include <string.h>
#include "EndianPortable.h"
#include <sstream>

namespace pcpp
{

std::string LldpLayer::toString() const
{
    std::stringstream stream;
    stream << "LLDP Layer";
    return stream.str();
}

} // namespace pcpp
