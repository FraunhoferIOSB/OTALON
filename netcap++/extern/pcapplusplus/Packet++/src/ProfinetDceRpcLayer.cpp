#define LOG_MODULE PacketLogModuleProfinetDceRpcLayer

#include "ProfinetDceRpcLayer.h"
#include <string.h>
#include <sstream>
#include "EndianPortable.h"

namespace pcpp
{

std::string ProfinetDceRpcLayer::toString() const
{
    std::stringstream stream;
    stream << "Profinet DCE RPC Layer";
    return stream.str();
}

bool ProfinetDceRpcLayer::isProfinetDceRpcPort(uint16_t port){
    return (port == 34962 || port == 34963 || port == 34964);
}

bool ProfinetDceRpcLayer::isDataValid(uint8_t * data, size_t data_len){
    if (data_len < sizeof(profinetdcerpchdr)){
        return false;
    }

    struct profinetdcerpchdr* hdr_ptr = reinterpret_cast<struct profinetdcerpchdr*>(data);
    
    if (hdr_ptr->rPCVersion != 4) { return false; }
    if (hdr_ptr->rPCPacketType > 0x0A){ return false; }
    if (hdr_ptr->rPCFlags2 > 0x03){ return false; }
    if (hdr_ptr->rPCDRep[1] >0x03){ return false; }
    if (hdr_ptr->rPCDRep[2] != 0){ return false; }


    uint32_t rPCObjectUUID_Data1 = static_cast<uint32_t>(0x0000A0DE);
    uint16_t rPCObjectUUID_Data2 = static_cast<uint16_t>(0x976C);
    uint16_t rPCObjectUUID_Data3 = static_cast<uint16_t>(0xD111);
    uint32_t rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min = static_cast<uint32_t>(0x0100A0DE);
    uint32_t rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max = static_cast<uint32_t>(0x0500A0DE);
    uint16_t rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2 = static_cast<uint16_t>(0x976C);
    uint16_t rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3 = static_cast<uint16_t>(0xD111);
    uint32_t rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1 =static_cast<uint32_t>(0x0883AFE1);
    uint16_t rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2 =static_cast<uint16_t>(0x1F5D);
    uint16_t rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3 =static_cast<uint16_t>(0xC911);

    if (hdr_ptr->rPCDRep[0] & 0xF0) {
        rPCObjectUUID_Data1 = htobe32(rPCObjectUUID_Data1);
        rPCObjectUUID_Data2 = htobe16(rPCObjectUUID_Data2);
        rPCObjectUUID_Data3 = htobe16(rPCObjectUUID_Data3);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min = htobe32(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max = htobe32(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2 = htobe16(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3 = htobe16(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1 = htobe32(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2 = htobe16(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3 = htobe16(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3);
    }
    else {
        rPCObjectUUID_Data1 = htole32(rPCObjectUUID_Data1);
        rPCObjectUUID_Data2 = htole16(rPCObjectUUID_Data2);
        rPCObjectUUID_Data3 = htole16(rPCObjectUUID_Data3);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min = htole32(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max = htole32(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2 = htole16(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2);
        rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3 = htole16(rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1 = htole32(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2 = htole16(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2);
        rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3 = htole16(rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3);
    }

    if (!(hdr_ptr->rPCObjectUUID.data1 == rPCObjectUUID_Data1
        && hdr_ptr->rPCObjectUUID.data2 == rPCObjectUUID_Data2
        && hdr_ptr->rPCObjectUUID.data3 == rPCObjectUUID_Data3
        && hdr_ptr->rPCObjectUUID.data4[0] == static_cast<uint8_t>(0x82)
        && hdr_ptr->rPCObjectUUID.data4[1] == static_cast<uint8_t>(0x71))) {
        return false;
    }

    if (!(((hdr_ptr->rPCInterfaceUUID.data1 >= rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_min && hdr_ptr->rPCInterfaceUUID.data1 <= rPCInterfaceUUID_UUID_IO_DeviceInterface_Data1_max)
            && hdr_ptr->rPCInterfaceUUID.data2 == rPCInterfaceUUID_UUID_IO_DeviceInterface_Data2
            && hdr_ptr->rPCInterfaceUUID.data3 == rPCInterfaceUUID_UUID_IO_DeviceInterface_Data3
            && hdr_ptr->rPCInterfaceUUID.data4[0] == static_cast<uint8_t>(0x82)
            && hdr_ptr->rPCInterfaceUUID.data4[1] == static_cast<uint8_t>(0x71)
            && hdr_ptr->rPCInterfaceUUID.data4[2] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[3] == static_cast<uint8_t>(0xA0)
            && hdr_ptr->rPCInterfaceUUID.data4[4] == static_cast<uint8_t>(0x24)
            && hdr_ptr->rPCInterfaceUUID.data4[5] == static_cast<uint8_t>(0x42)
            && hdr_ptr->rPCInterfaceUUID.data4[6] == static_cast<uint8_t>(0xDF)
            && hdr_ptr->rPCInterfaceUUID.data4[7] == static_cast<uint8_t>(0x7D))
        || (hdr_ptr->rPCInterfaceUUID.data1 == rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data1
            && hdr_ptr->rPCInterfaceUUID.data2 == rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data2
            && hdr_ptr->rPCInterfaceUUID.data3 == rPCInterfaceUUID_UUID_IO_ParameterServerInterface_Data3
            && hdr_ptr->rPCInterfaceUUID.data4[0] == static_cast<uint8_t>(0x91)
            && hdr_ptr->rPCInterfaceUUID.data4[1] == static_cast<uint8_t>(0xA4)
            && hdr_ptr->rPCInterfaceUUID.data4[2] == static_cast<uint8_t>(0x08)
            && hdr_ptr->rPCInterfaceUUID.data4[3] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[4] == static_cast<uint8_t>(0x2B)
            && hdr_ptr->rPCInterfaceUUID.data4[5] == static_cast<uint8_t>(0x14)
            && hdr_ptr->rPCInterfaceUUID.data4[6] == static_cast<uint8_t>(0xA0)
            && hdr_ptr->rPCInterfaceUUID.data4[7] == static_cast<uint8_t>(0xFA))
        || (hdr_ptr->rPCInterfaceUUID.data1 == static_cast<uint32_t>(0x00000000)
            && hdr_ptr->rPCInterfaceUUID.data2 == static_cast<uint16_t>(0x0000)
            && hdr_ptr->rPCInterfaceUUID.data3 == static_cast<uint16_t>(0x0000)
            && hdr_ptr->rPCInterfaceUUID.data4[0] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[1] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[2] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[3] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[4] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[5] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[6] == static_cast<uint8_t>(0x00)
            && hdr_ptr->rPCInterfaceUUID.data4[7] == static_cast<uint8_t>(0x00))
        )) {
        return false;
    }
    
    return true;
}
} // namespace pcpp
