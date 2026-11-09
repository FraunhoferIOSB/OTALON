#include "network-capture/runner/network_metric_capture.hpp"
#include <ostream>

#include "network-capture/processing/metrics.hpp"
#include "network-capture/processing/unique_window.hpp"
#include "network-capture/processing/window.hpp"

using namespace std;

NetworkMetricsCapture::NetworkMetricsCapture(std::string location,
                                             CaptureType type,
                                             unsigned int window_duration)
  : NetworkUciCapture(location, type)
{
    window_separator_thread =
      thread(&WindowSeparator::process,
             WindowSeparator(tsq_pp, tsq_wp, window_duration));

    for (uint32_t i = 0; i < thread::hardware_concurrency(); i++) {
        unique_window_separator_threads.emplace_back(
          &UniqueWindowSeparator::process,
          UniqueWindowSeparator(tsq_wp, tsq_uwp));
        metric_generator_threads.emplace_back(
          &MetricGenerator::process, MetricGenerator(tsq_uwp, tsq_mfw));
    }
}

NetworkMetricsCapture::~NetworkMetricsCapture()
{
    if (this->runner.joinable()) {
        this->runner.join();
    }
}

void
NetworkMetricsCapture::process()
{
    NetworkUciCapture::process();
    window_separator_thread.join();
    tsq_wp.stop();
    for (auto& t : unique_window_separator_threads) {
        t.join();
    }
    tsq_uwp.stop();
    for (auto& t : metric_generator_threads) {
        t.join();
    }
    tsq_mfw.stop();
}

ThreadSaveQueue<MetricsForWindow>*
NetworkMetricsCapture::capture()
{
    runner = thread(&NetworkMetricsCapture::process, this);
    return &this->tsq_mfw;
}
