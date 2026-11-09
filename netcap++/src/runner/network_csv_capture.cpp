#include "network-capture/runner/network_csv_capture.hpp"
#include <ostream>

#include "network-capture/representation/string_output.hpp"

using namespace std;
NetworkCsvCapture::NetworkCsvCapture(std::string location,
                                     CaptureType type,
                                     unsigned int window_duration,
                                     std::string destination,
                                     bool show_progress,
                                     uintmax_t max_size)
  : NetworkMetricsCapture(location, type, window_duration)
{
    std::optional<uint64_t> file_size;
    if (max_size > 0) {
        file_size.emplace(max_size);
    }
    exporter = make_shared<CsvExporter>(tsq_smfw, destination, ';');
    exporter_thread = thread(&CsvExporter::process, exporter);
    cli_progress = make_shared<CliProgress>(
      packet_reader.get(), chrono::seconds{ 2 }, file_size);
    cli_progress_thread = thread(&CliProgress::process, cli_progress);
    for (uint32_t i = 0; i < thread::hardware_concurrency(); i++) {
        metric_converter_threads.emplace_back(
          &MetricStringReprsentationConverter::process,
          MetricStringReprsentationConverter(tsq_mfw, tsq_smfw));
    }
}

void
NetworkCsvCapture::process()
{
    NetworkMetricsCapture::process();
    cli_progress_thread.join();
    for (auto& t : metric_converter_threads) {
        t.join();
    }
    tsq_smfw.stop();
    exporter_thread.join();
}

NetworkCsvCapture::~NetworkCsvCapture()
{
    if (this->runner.joinable()) {
        this->runner.join();
    }
}

void
NetworkCsvCapture::capture()
{
    runner = thread(&NetworkCsvCapture::process, this);
}
