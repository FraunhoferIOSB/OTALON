#include "network-capture/importer/base_importer.hpp"

#include "network-capture/datatypes/ip.hpp"
#include "network-capture/datatypes/parsed_packet.hpp"
#include "network-capture/datatypes/protocol.hpp"
#include "network-capture/datatypes/uci.hpp"
#include "network-capture/importer/importer_utils.hpp"

#include <EthLayer.h>
#include <EthDot3Layer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <MacAddress.h>
#include <Packet.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <VlanLayer.h>

std::optional<ParsedPacket>
PcapPlusPlusBaseImporter::parse_packet(pcpp::Packet const& packet)
{
    if (!packet.isPacketOfType(pcpp::Ethernet) && !packet.isPacketOfType(pcpp::EthernetDot3)) {
        return {};
    }
    ParsedPacket ret;

    timespec pkg_time = packet.getRawPacket()->getPacketTimeStamp();
    std::chrono::seconds ts_seconds{ pkg_time.tv_sec };
    std::chrono::nanoseconds ts_nseconds{ pkg_time.tv_nsec };
    ret.timestamp =
      std::chrono::duration_cast<std::chrono::milliseconds>(ts_seconds) +
      std::chrono::duration_cast<std::chrono::milliseconds>(ts_nseconds);

    ret.size = packet.getRawPacket()->getRawDataLen();

    auto layer = packet.getFirstLayer();
    do {
        if (ret.uci.protocol_list.count >= (UCI::MAX_PROTOCOL_ENTRIES - 1)) {
            break;
        }
        ret.uci.protocol_list.protocols[ret.uci.protocol_list.count] =
          convert_protocol_type(layer->getProtocol());
        ret.uci.protocol_list.count++;

        if (layer->getProtocol() == pcpp::Ethernet) {
            ret.uci.source_mac.set_mac(
              static_cast<pcpp::EthLayer*>(layer)->getSourceMac().getRawData());
            ret.uci.destination_mac.set_mac(
              static_cast<pcpp::EthLayer*>(layer)->getDestMac().getRawData());
        } else if (layer->getProtocol() == pcpp::EthernetDot3){
           ret.uci.source_mac.set_mac(
              static_cast<pcpp::EthDot3Layer*>(layer)->getSourceMac().getRawData());
            ret.uci.destination_mac.set_mac(
              static_cast<pcpp::EthDot3Layer*>(layer)->getDestMac().getRawData());
        } else if (layer->getProtocol() == pcpp::VLAN) {
            ret.uci.has_vlan_id = true;

            uint16_t vlan = static_cast<pcpp::VlanLayer*>(layer)->getVlanID();
            ret.uci.vlan_id = vlan;
        } else if (layer->getProtocol() == pcpp::IPv4) {
            ret.uci.has_ip = true;
            ret.uci.ip_type = IpType::IPv4;
            ret.uci.source_ip.set_ip_v4(static_cast<pcpp::IPv4Layer*>(layer)
                                          ->getSrcIPv4Address()
                                          .toBytes());
            ret.uci.destination_ip.set_ip_v4(
              static_cast<pcpp::IPv4Layer*>(layer)
                ->getDstIPv4Address()
                .toBytes());
        } else if (layer->getProtocol() == pcpp::IPv6) {
            ret.uci.has_ip = true;
            ret.uci.ip_type = IpType::IPv6;
            ret.uci.source_ip.set_ip_v6(static_cast<pcpp::IPv6Layer*>(layer)
                                          ->getSrcIPv6Address()
                                          .toBytes());
            ret.uci.destination_ip.set_ip_v6(
              static_cast<pcpp::IPv6Layer*>(layer)
                ->getDstIPv6Address()
                .toBytes());
        }

        else if (layer->getProtocol() == pcpp::TCP) {
            ret.uci.source_port =
              static_cast<pcpp::TcpLayer*>(layer)->getSrcPort();
            ret.uci.destination_port =
              static_cast<pcpp::TcpLayer*>(layer)->getDstPort();
        } else if (layer->getProtocol() == pcpp::UDP) {
            ret.uci.source_port =
              static_cast<pcpp::UdpLayer*>(layer)->getSrcPort();
            ret.uci.destination_port =
              static_cast<pcpp::UdpLayer*>(layer)->getDstPort();
        }
    } while ((layer = layer->getNextLayer()) != nullptr);

    return ret;
}

const uint64_t
PcapPlusPlusBaseImporter::get_captured_bytes()
{
    return this->captured_bytes;
}

const bool
PcapPlusPlusBaseImporter::get_stopped()
{
    return this->stopped;
}
