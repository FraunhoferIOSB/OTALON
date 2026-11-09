#pragma once

#include "network-capture/datatypes/uci.hpp"

#include <chrono>
#include <cstdint>
#include <string>
#include <cstdint>

/**
 * @brief Information about a collected packet.
 *
 * Contains a unique identifier for the connection the packet belongs, as well
 * as additional meta information like the packet size and the arrival time.
 */
struct ParsedPacket
{
    UCI uci{};
    std::chrono::milliseconds timestamp{ 0 };
    uint16_t size{ 0 };

    std::string to_string() const;
    ParsedPacket() = default;
    ParsedPacket(const ParsedPacket& other)
    {
        this->uci = other.uci;
        this->timestamp = other.timestamp;
        this->size = other.size;
    }

    friend bool operator<(const ParsedPacket& lhv, const ParsedPacket& rhv);
};