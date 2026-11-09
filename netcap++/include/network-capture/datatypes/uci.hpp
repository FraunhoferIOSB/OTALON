#pragma once

#include "network-capture/datatypes/ip.hpp"
#include "network-capture/datatypes/mac.hpp"
#include "network-capture/datatypes/protocol.hpp"

#include <cstdint>
#include <cstring>
#include <string>
#include <cstdint>

/**
 * @brief An identifier for a connection.
 *
 * An Unique Connection Identifier (UCI) is a identifier for a single connection
 * of ethernet based traffic. It contains source and destination MAC addresses
 * as well as IP and port data to distinguish an unique connection.
 */
struct UCI
{
    static const size_t MAX_PROTOCOL_ENTRIES = 10;
    MAC source_mac{};
    MAC destination_mac{};
    struct
    {
        uint16_t count{ 0 };
        Protocol protocols[MAX_PROTOCOL_ENTRIES];
    } protocol_list;

    bool has_vlan_id{ false };
    uint16_t vlan_id{ 0 };

    bool has_ip{ false };
    IpType ip_type{ IpType::IPv4 };
    IP source_ip{};
    IP destination_ip{};
    uint16_t source_port{ 0 };
    uint16_t destination_port{ 0 };

    /**
     * @brief Generate a string representation of the UCI object.
     *
     * @return std::string String representation of the UCI.
     */
    std::string to_string() const;

    /**
     * @brief Generates a URI style string representation of the UCI object.
     *
     * @return std::string String representation of the UCI.
     */
    std::string as_uri() const;

    bool operator==(const UCI& rhs) const
    {

        if (this->has_vlan_id != rhs.has_vlan_id)
            return false;

        if (this->has_ip || rhs.has_ip) {
            if (this->ip_type != rhs.ip_type)
                return false;
            if (this->source_ip != rhs.source_ip)
                return false;
            if (this->destination_ip != rhs.destination_ip)
                return false;
            if (this->source_port != rhs.source_port)
                return false;
            if (this->destination_port != rhs.destination_port)
                return false;
        }

        if (this->source_mac != rhs.source_mac)
            return false;
        if (this->destination_mac != rhs.destination_mac)
            return false;
        if (this->protocol_list.count != rhs.protocol_list.count)
            return false;
        if (std::memcmp(this->protocol_list.protocols,
                        rhs.protocol_list.protocols,
                        protocol_list.count) != 0)
            return false;

        return true;
    }
};

template<>
struct std::hash<UCI>
{
    std::size_t operator()(const UCI& f) const
    {
        return std::hash<std::string>()(f.to_string());
    }
};