#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/parsed_packet.hpp"

#include "Packet.h"
#include <optional>
#include <cstdint>

/**
 * @brief Base class for pcap plus plus based packet importer.
 *
 * The class provide an implementation for packet parsing for all derived
 * pcap plus plus based importers.
 */
class PcapPlusPlusBaseImporter
{
  protected:
    bool stopped = false;
    uint64_t captured_bytes = 0;

    ThreadSaveQueue<ParsedPacket>& data_destination;

  public:
    PcapPlusPlusBaseImporter(ThreadSaveQueue<ParsedPacket>& data_destination)
      : data_destination{ data_destination }
    {
    }
    virtual ~PcapPlusPlusBaseImporter() {}

    static std::optional<ParsedPacket> parse_packet(pcpp::Packet const& packet);

    /**
     * @brief Get count of how many bytes were captured.
     *
     * @return const uint64_t Count of captured bytes.
     */
    const uint64_t get_captured_bytes();

    /**
     * @brief Get stopped state.
     *
     * Get information about the running state of the object.
     *
     * @return true The process has been stopped.
     * @return false The process is running.
     */
    const bool get_stopped();

    /**
     * @brief Abstract processing function.
     *
     * Implements the continuous process of the object. Will continue to run
     * unless the data source signals it will no longer provide data.
     */
    virtual void process() = 0;
};
