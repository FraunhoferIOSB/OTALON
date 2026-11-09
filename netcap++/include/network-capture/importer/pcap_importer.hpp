#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/parsed_packet.hpp"
#include "network-capture/importer/base_importer.hpp"

#include <PcapFileDevice.h>
#include <cstdint>
#include <string>

/**
 * @brief Pcap implementation of the pcap plus plus base importer.
 *
 * Imports packets from a PCAP file.
 */
class PcapPlusPlusPcapImporter : public PcapPlusPlusBaseImporter
{
  protected:
    pcpp::PcapFileReaderDevice reader;
    uint16_t header_size = 0;

  public:
    /**
     * @brief Construct a new pcap plus plus pcap importer object
     *
     * @param data_destination Destination of the captured packet information.
     * @param reader Reader for the pcap file.
     */
    PcapPlusPlusPcapImporter(ThreadSaveQueue<ParsedPacket>& data_destination,
                             std::string path);
    void process();
    PcapPlusPlusPcapImporter(const PcapPlusPlusPcapImporter&) = delete;
    ~PcapPlusPlusPcapImporter() = default;
};
