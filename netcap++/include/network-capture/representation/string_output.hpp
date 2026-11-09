#pragma once

#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/metrics_for_window.hpp"
#include "network-capture/representation/representations.hpp"

/**
 * @brief Generate string representation of metrics.
 */
class MetricStringReprsentationConverter
{
  protected:
    ThreadSaveQueue<MetricsForWindow>& data_source;
    ThreadSaveQueue<StringifyMetricsForWindow>& data_destination;

  public:
    /**
     * @brief Construct a new metric string reprsentation converter object
     *
     * @param data_source Source of the metrics data.
     * @param data_destination Destination of the string representations.
     */
    MetricStringReprsentationConverter(
      ThreadSaveQueue<MetricsForWindow>& data_source,
      ThreadSaveQueue<StringifyMetricsForWindow>& data_destination)
      : data_source{ data_source }
      , data_destination{ data_destination }
    {
    }
    void process();
};
