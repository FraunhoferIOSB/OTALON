#include "network-capture/datatypes/uci.hpp"

#include "network-capture/datatypes/protocol.hpp"

#include <sstream>
using namespace std;

static std::string
protocol_list_to_string(const Protocol* list, size_t size)
{
    bool is_first = true;
    std::string protocol_string;
    for (int i = 0; i < size; i++) {
        if (list[i] == Protocol::GenericPayload ||
            list[i] == Protocol::PacketTrailer) {
            continue;
        }
        std::string protocol_representation = protocol_to_string(list[i]);
        if (is_first) {
            protocol_string += protocol_representation;
            is_first = false;
        } else {
            protocol_string += ":" + protocol_representation;
        }
    }
    return protocol_string;
}

std::string
UCI::to_string() const
{
    std::stringstream ss;
    ss << "SourceMac: " << source_mac.to_string() << " ";
    ss << "DestinationMac: " << destination_mac.to_string() << " ";

    if (has_vlan_id) {
        ss << "VLAN ID: " << vlan_id << " ";
    }
    if (has_ip) {
        ss << "IP-Type: " << (ip_type == IpType::IPv4 ? "IPv4" : "IPv6") << " ";
        ss << "SourceIP: " << source_ip.to_string() << " ";
        ss << "DestinationIP: " << destination_ip.to_string() << " ";
        ss << "SourcePort: " << source_port << " ";
        ss << "DestinationPort: " << destination_port << " ";
    }

    ss << "Protocols:"
       << protocol_list_to_string(protocol_list.protocols, protocol_list.count);
    return ss.str();
}

std::string
UCI::as_uri() const
{
    char delimiter = '/';
    std::stringstream ss;
    ss << source_mac.to_string() << delimiter;
    ss << destination_mac.to_string() << delimiter;

    if (has_vlan_id) {
        ss << vlan_id << delimiter;
    } else {
        ss << delimiter;
    }

    if (has_ip) {
        ss << (ip_type == IpType::IPv4 ? "IPv4" : "IPv6") << delimiter;
        ss << source_ip.to_string() << delimiter;
        ss << destination_ip.to_string() << delimiter;
        ss << source_port << delimiter;
        ss << destination_port << delimiter;
    } else {
        ss << delimiter << delimiter << delimiter << delimiter << delimiter;
    }

    ss << protocol_list_to_string(protocol_list.protocols, protocol_list.count);
    return ss.str();
}