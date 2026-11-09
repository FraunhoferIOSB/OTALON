#include "network-capture/datatypes/windowed_packets.hpp"

#include <sstream>

WindowedPackets::WindowedPackets(std::vector<ParsedPacket>& data,
                                 std::chrono::milliseconds& record_start)
{
    this->record_start = record_start;
    this->data = {};

    for (size_t i = 0; i < data.size(); i++) {
        this->data.push_back({ data[i] });
    }
}

std::string
WindowedPackets::to_string() const
{
    std::stringstream ss;
    ss << "Window start: " << record_start.count() << " ";
    ss << "Data: {";
    for (const auto& packet : data) {
        ss << packet.to_string();
    }
    ss << "}";

    return ss.str();
}