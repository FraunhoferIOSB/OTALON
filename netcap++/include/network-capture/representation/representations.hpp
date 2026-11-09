#pragma once

#include <string>

/**
 * @brief String representation of metrics.
 */
struct StringifyMetricsForWindow
{
    std::string uci;
    std::string record_start;

    std::string total_packet_count;
    std::string total_volume;
    std::string mean_packet_size;
    std::string min_packet_size;
    std::string max_packet_size;
    std::string sd_packet_size;
    std::string mean_packet_inter_arrival_time;
    std::string min_packet_inter_arrival_time;
    std::string max_packet_inter_arrival_time;
    std::string sd_packet_inter_arrival_time;
};
