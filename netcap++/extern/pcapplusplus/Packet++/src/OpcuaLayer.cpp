#define LOG_MODULE PacketLogModuleOpcuaLayer

#include "OpcuaLayer.h"
#include <sstream>

namespace pcpp
{

std::string OpcuaLayer::toString() const
{
    std::stringstream stream;
    stream << "OPC-UA Layer";
    return stream.str();
}

bool OpcuaLayer::isDataValid(const uint8_t *data, size_t dataSize) {
    if (dataSize < sizeof(opcua_header)) {
        return false;
    }

    opcua_header* opcuaHdr = (opcua_header*) data;

    if (opcuaHdr->message_size == dataSize) { 
        return true;
    }
    return false;
}

} // namespace pcpp
