#include <ostream>
#include "network-capture/processing/unique_window.hpp"

#include "network-capture/processing/window.hpp"

#include <chrono>
#include <unordered_map>

void
UniqueWindowSeparator::process()
{

    while (true) {
        try {
            std::unordered_map<UCI, std::vector<ParsedPacket>> buffer;
            auto window = data_source.wait_and_pop();

            for (const auto& parsed_packet : window.data) {

                buffer[parsed_packet.uci].push_back(parsed_packet);
            }
            for (auto& [uci, data] : buffer) {
                data_destination.push({ uci, data, window.record_start });
            }
            buffer.clear();
        } catch (const std::exception) {
            return;
        }
    }
}