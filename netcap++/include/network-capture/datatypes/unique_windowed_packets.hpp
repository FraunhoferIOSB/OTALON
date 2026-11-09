#pragma once

#include "network-capture/datatypes/parsed_packet.hpp"
#include "network-capture/datatypes/uci.hpp"

#include <string>
#include <vector>
#include <chrono>

struct UniqueWindowedPackets
{
    UCI uci{};
    std::vector<ParsedPacket> data{};
    std::chrono::milliseconds record_start{ 0 };

    std::string to_string() const;

    UniqueWindowedPackets(const UCI& uci,
                          std::vector<ParsedPacket>& data,
                          std::chrono::milliseconds& record_start);
};