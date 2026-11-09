#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/metrics_for_window.hpp"

/**
 * @brief Generator for metrics over a window.
 *
 * For every window specific metrics must be generated. This includes
 * information like the total packet size, the inter arrival time and the packet
 * count.
 */
class MetricGenerator
{
  protected:
    ThreadSaveQueue<UniqueWindowedPackets>& data_source;
    ThreadSaveQueue<MetricsForWindow>& data_destination;

  public:
    /**
     * @brief Construct a new metric generator object
     *
     * @param data_source Source of the window data.
     * @param data_destination Destination of the generated metrics.
     */
    MetricGenerator(ThreadSaveQueue<UniqueWindowedPackets>& data_source,
                    ThreadSaveQueue<MetricsForWindow>& data_destination)
      : data_source{ data_source }
      , data_destination{ data_destination }
    {
    }
    void process();
};
