#include "network-capture/importer/live_importer.hpp"

#include "network-capture/datatypes/parsed_packet.hpp"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <MacAddress.h>
#include <Packet.h>
#include <PcapLiveDeviceList.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <VlanLayer.h>

using namespace std;

PcapPlusPlusLiveImporter::PcapPlusPlusLiveImporter(
  ThreadSaveQueue<ParsedPacket>& data_destination,
  std::string path)
  : PcapPlusPlusBaseImporter(data_destination)
{
    this->reader =
      pcpp::PcapLiveDeviceList::getInstance().getPcapLiveDeviceByIpOrName(path);

    if (this->reader == nullptr || !this->reader->open()) {
        throw runtime_error("Could not open live reader");
    }
}

void
PcapPlusPlusLiveImporter::on_packet_arrives(pcpp::RawPacket* raw_packet,
                                            pcpp::PcapLiveDevice* device,
                                            void* on_packet_arrives_user_cookie)
{

    pcpp::Packet packet(raw_packet);

    std::optional<ParsedPacket> parsed_packet = parse_packet(packet);

    if (parsed_packet.has_value()) {
        this->captured_bytes += parsed_packet.value().size;
        this->data_destination.push(parsed_packet.value());
    }
}
void
PcapPlusPlusLiveImporter::process()
{
    auto f = [&](pcpp::RawPacket* raw_packet,
                 pcpp::PcapLiveDevice* device,
                 void* on_packet_arrives_user_cookie) {
        this->on_packet_arrives(
          raw_packet, device, on_packet_arrives_user_cookie);
    };
    reader->startCapture(f, NULL);

    std::unique_lock<std::mutex> lk(mu);
    cv.wait(lk);
    lk.unlock();

    reader->stopCapture();
    this->stopped = true;
}

void
PcapPlusPlusLiveImporter::stop()
{
    cv.notify_all();
}
