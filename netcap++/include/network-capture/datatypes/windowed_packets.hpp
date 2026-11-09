#pragma once

#include "network-capture/datatypes/parsed_packet.hpp"

#include <chrono>
#include <string>
#include <vector>

/**
 * @brief A list of parsed packets grouped by their arrival time.
 *
 * Packets are collected in specific time windows and their UCI.
 */
struct WindowedPackets
{
    std::vector<ParsedPacket> data{};
    std::chrono::milliseconds record_start{ 0 };

    std::string to_string() const;

    WindowedPackets(std::vector<ParsedPacket>& data,
                    std::chrono::milliseconds& record_start);
};
