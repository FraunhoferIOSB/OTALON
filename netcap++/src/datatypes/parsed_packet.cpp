#include "network-capture/datatypes/parsed_packet.hpp"

#include <sstream>

std::string
ParsedPacket::to_string() const
{
    std::stringstream ss;
    ss << "UCI: {" << uci.to_string() << "} ";
    ss << "Timestamp in ms: " << timestamp.count() << " ";
    ss << "Size: " << size;
    return ss.str();
}

bool
operator<(const ParsedPacket& lhv, const ParsedPacket& rhv)
{
    return false;
}