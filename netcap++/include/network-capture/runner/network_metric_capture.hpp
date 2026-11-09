#pragma once

#include "network-capture/datatypes/metrics_for_window.hpp"
#include "network-capture/datatypes/windowed_packets.hpp"
#include "network-capture/runner/network_uci_capture.hpp"

class NetworkMetricsCapture : public NetworkUciCapture
{
  protected:
    ThreadSaveQueue<WindowedPackets> tsq_wp;
    ThreadSaveQueue<UniqueWindowedPackets> tsq_uwp;
    ThreadSaveQueue<MetricsForWindow> tsq_mfw;
    std::thread window_separator_thread;
    std::vector<std::thread> unique_window_separator_threads;
    std::vector<std::thread> metric_generator_threads;
    void process();

  public:
    NetworkMetricsCapture(std::string location,
                          CaptureType type,
                          unsigned int window_duration);
    ~NetworkMetricsCapture();
    ThreadSaveQueue<MetricsForWindow>* capture();
};
