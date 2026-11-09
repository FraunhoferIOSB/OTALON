#pragma once
#include "network-capture/exporter/csv_exporter.hpp"
#include "network-capture/runner/network_metric_capture.hpp"
#include "network-capture/visualization/cli_progress.hpp"
class NetworkCsvCapture : public NetworkMetricsCapture
{
  protected:
    ThreadSaveQueue<StringifyMetricsForWindow> tsq_smfw;
    std::vector<std::thread> metric_converter_threads;
    std::thread exporter_thread;
    std::thread cli_progress_thread;
    std::shared_ptr<CsvExporter> exporter{};
    std::shared_ptr<CliProgress> cli_progress;

    void process();

  public:
    NetworkCsvCapture(std::string location,
                      CaptureType type,
                      unsigned int window_duration,
                      std::string destination,
                      bool show_progress,
                      uintmax_t max_size);
    ~NetworkCsvCapture();
    void capture();
};
