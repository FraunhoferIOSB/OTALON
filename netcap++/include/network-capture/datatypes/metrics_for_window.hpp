#pragma once

#include "network-capture/datatypes/uci.hpp"
#include "network-capture/datatypes/unique_windowed_packets.hpp"
#include <cstdint>
#include <chrono>
#include <cstdint>
#include <string>

/**
 * @brief Generated metrics for a single window.
 *
 */
class MetricsForWindow
{
  protected:
    UCI uci;
    std::chrono::milliseconds record_start;

    uint32_t total_packet_count;
    uint32_t total_volume;
    float mean_packet_size;
    uint16_t min_packet_size;
    uint16_t max_packet_size;
    float sd_packet_size;
    float mean_packet_inter_arrival_time;
    std::chrono::milliseconds min_packet_inter_arrival_time;
    std::chrono::milliseconds max_packet_inter_arrival_time;
    float sd_packet_inter_arrival_time;

  public:
    /**
     * @brief Construct a new MetricsForWindow object
     *
     * @param window Existing windowed packet list.
     */
    MetricsForWindow(const UniqueWindowedPackets& window);

    const UCI& get_uci();
    const int64_t get_record_start();
    const uint32_t& get_total_packet_count();
    const uint32_t& get_total_volume();
    const float& get_mean_packet_size();
    const uint16_t& get_min_packet_size();
    const uint16_t& get_max_packet_size();
    const float& get_sd_packet_size();
    const float& get_mean_packet_inter_arrival_time();
    const int64_t get_min_packet_inter_arrival_time();
    const int64_t get_max_packet_inter_arrival_time();
    const float& get_sd_packet_inter_arrival_time();

    /**
     * @brief Generate a string representation.
     *
     * @return std::string String representation.
     */
    std::string to_string() const;
};
