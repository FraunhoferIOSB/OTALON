#include "network-capture/runner/network_uci_capture.hpp"
#include <ostream>

#include "network-capture/importer/live_importer.hpp"
#include "network-capture/importer/pcap_importer.hpp"

#include <memory>
using namespace std;

NetworkUciCapture::NetworkUciCapture(std::string location, CaptureType type)
{
    switch (type) {
        case CaptureType::PCAP: {
            auto ptr = make_shared<PcapPlusPlusPcapImporter>(tsq_pp, location);
            packet_reader_thread =
              thread(&PcapPlusPlusPcapImporter::process, ptr);
            packet_reader = static_pointer_cast<PcapPlusPlusBaseImporter>(ptr);
        } break;
        case CaptureType::LIVE: {
            auto ptr = make_shared<PcapPlusPlusLiveImporter>(tsq_pp, location);
            packet_reader_thread =
              thread(&PcapPlusPlusLiveImporter::process, ptr);
            packet_reader = static_pointer_cast<PcapPlusPlusBaseImporter>(ptr);
        } break;
    }
}

void
NetworkUciCapture::process()
{
    packet_reader_thread.join();
    tsq_pp.stop();
}

const uint64_t
NetworkUciCapture::get_captured_packet_count()
{
    return this->packet_reader->get_captured_bytes();
}

NetworkUciCapture::~NetworkUciCapture()
{
    if (this->runner.joinable()) {
        this->runner.join();
    }
}

ThreadSaveQueue<ParsedPacket>*
NetworkUciCapture::capture()
{
    runner = thread(&NetworkUciCapture::process, this);
    return &this->tsq_pp;
}
