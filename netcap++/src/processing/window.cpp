#include <ostream>
#include "network-capture/processing/window.hpp"

#include <chrono>
#include <unordered_map>

void
WindowSeparator::process()
{
    std::vector<ParsedPacket> buffer;
    std::chrono::milliseconds start{ 0 };

    while (true) {
        try {
            auto parsed_packet = data_source.wait_and_pop();
            if (start == std::chrono::milliseconds{ 0 }) {
                start = parsed_packet.timestamp;
            }

            if ((start + intervall) < parsed_packet.timestamp) {
                if (buffer.size()) {
                    data_destination.push({ buffer, start });
                    buffer.clear();
                }
                start = start + intervall;
            }
            buffer.push_back(parsed_packet);
        } catch (const std::exception) {
            data_destination.push({ buffer, start });
            return;
        }
    }
}