#pragma once
#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/windowed_packets.hpp"

#include <chrono>

/**
 * @brief Separator of captured packets into windows.
 *
 * Packets should be grouped into windows. A window is first a specific time
 * slot and second an unique identifer for the connection. This class provides
 * functionality to group the packets by time and by their unique identifier.
 */
class WindowSeparator
{
  protected:
    ThreadSaveQueue<ParsedPacket>& data_source;
    ThreadSaveQueue<WindowedPackets>& data_destination;

    std::chrono::milliseconds intervall;

  public:
    /**
     * @brief Construct a new window separator object
     *
     * @param data_source Source of packet data.
     * @param data_destination Destination of the generated windows.
     * @param intervall Window intervall.
     */
    WindowSeparator(ThreadSaveQueue<ParsedPacket>& data_source,
                    ThreadSaveQueue<WindowedPackets>& data_destination,
                    unsigned int intervall)
      : data_source{ data_source }
      , data_destination{ data_destination }
      , intervall{ intervall } {};
    void process();
};
