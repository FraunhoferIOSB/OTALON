#include "network-capture/importer/pcap_importer.hpp"

#include "network-capture/datatypes/parsed_packet.hpp"

#include <EthLayer.h>
#include <IPv4Layer.h>
#include <IPv6Layer.h>
#include <MacAddress.h>
#include <Packet.h>
#include <TcpLayer.h>
#include <UdpLayer.h>
#include <VlanLayer.h>
#include <stdexcept>

using namespace std;

static bool
is_pcap_ng(string path)
{
    ifstream infile(path, ios::in | ios::binary);
    int count = 0;

    while (!infile.eof() && count < 4) {
        char input = '\0';
        input = infile.get();
        if (count == 0 && input != 0x0a) {
            return false;
        } else if (count == 1 && input != 0x0d) {
            return false;
        } else if (count == 2 && input != 0x0d) {
            return false;
        } else if (count == 3 && input != 0x0a) {
            return false;
        }
        count++;
    }

    if (count < 3) {
        return false;
    }
    return true;
}

PcapPlusPlusPcapImporter::PcapPlusPlusPcapImporter(
  ThreadSaveQueue<ParsedPacket>& data_destination,
  std::string path)
  : PcapPlusPlusBaseImporter(data_destination)
  , reader{ path }
{
    if (!reader.open()) {
        throw std::runtime_error("Could not open file");
    }
    /* The captured bytes count is increased according to the size of the
     * initial header of the pcap or pcap-ng file format */

    if (is_pcap_ng(path)) {
        this->captured_bytes = 28;
        this->header_size = 32;
    } else {
        this->captured_bytes = 24;
        this->header_size = 16;
    }
}

void
PcapPlusPlusPcapImporter::process()
{
    while (true) {
        pcpp::RawPacket rawPacket;

        if (!this->reader.getNextPacket(rawPacket)) {
            this->stopped = true;
            return;
        }

        this->captured_bytes += rawPacket.getRawDataLen() + this->header_size;

        pcpp::Packet packet(&rawPacket);

        std::optional<ParsedPacket> parsed_packet = parse_packet(packet);

        if (parsed_packet.has_value()) {
            /* Additional 16 bytes is added because of the pcap record header,
             * which is not part of the read packet */
            this->data_destination.push(parsed_packet.value());
        }
    }
}
