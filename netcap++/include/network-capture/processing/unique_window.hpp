#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/unique_windowed_packets.hpp"
#include "network-capture/datatypes/windowed_packets.hpp"

/**
 * @brief Create unique windows from windows.
 *
 * Time windows contain connections with different unique identifiers. This
 * class provide fonctionality to extract these unique windows.
 */
class UniqueWindowSeparator
{
  protected:
    ThreadSaveQueue<WindowedPackets>& data_source;
    ThreadSaveQueue<UniqueWindowedPackets>& data_destination;

  public:
    /**
     * @brief Construct a new unique window separator object
     *
     * @param data_source Data source of windowed packets.
     * @param data_destination Data destination of unique windowed packets.
     */
    UniqueWindowSeparator(
      ThreadSaveQueue<WindowedPackets>& data_source,
      ThreadSaveQueue<UniqueWindowedPackets>& data_destination)
      : data_source{ data_source }
      , data_destination{ data_destination } {};
    void process();
};
