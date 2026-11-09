#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/parsed_packet.hpp"
#include "network-capture/importer/base_importer.hpp"

#include <PcapLiveDevice.h>
#include <RawPacket.h>
#include <string>
#include <condition_variable>
#include <mutex>

/**
 * @brief Live interface implementation of the pcap plus plus base importer.
 *
 * Captures data from a live interface.
 */
class PcapPlusPlusLiveImporter : public PcapPlusPlusBaseImporter
{
  protected:
    std::mutex mu;
    std::condition_variable cv;
    pcpp::PcapLiveDevice* reader { nullptr };
    void on_packet_arrives(pcpp::RawPacket* packet,
                           pcpp::PcapLiveDevice* device,
                           void* on_packet_arrives_user_cookie);

  public:
    /**
     * @brief Construct a new pcap plus plus live importer object
     *
     * @param data_destination Destination of the captured packet information.
     * @param reader Reader for the live interface.
     */
    PcapPlusPlusLiveImporter(ThreadSaveQueue<ParsedPacket>& data_destination,
                             std::string path);
    void process();

    /**
     * @brief Stop the running process.
     *
     * Will stop the live capturing.
     */
    void stop();
};
