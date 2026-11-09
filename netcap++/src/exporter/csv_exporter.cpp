#include "network-capture/exporter/csv_exporter.hpp"

#include <iostream>

CsvExporter::CsvExporter(
  ThreadSaveQueue<StringifyMetricsForWindow>& data_source,
  const std::string& filepath,
  char delimiter)
  : data_source{ data_source }
  , delimiter{ delimiter }
{
    this->file.open(filepath, std::ios::trunc);
}

void
CsvExporter::process()
{
    size_t count{ 0 };

    file << "Index" << delimiter;
    file << "UCI" << delimiter;
    file << "WindowStart" << delimiter;
    file << "TotalPacketCount" << delimiter;
    file << "TotalVolume" << delimiter;
    file << "MeanPacketSize" << delimiter;
    file << "MinPacketSize" << delimiter;
    file << "MaxPacketSize" << delimiter;
    file << "StandardDeviationSize" << delimiter;
    file << "MeanPacketInterArrivaltime" << delimiter;
    file << "MinPacketInterArrivaltime" << delimiter;
    file << "MaxPacketInterArrivaltime" << delimiter;
    file << "StandardDeviationPacketInterArrivaltime" << std::endl;

    while (true) {
        try {
            auto data = data_source.wait_and_pop();

            file << count++ << delimiter;
            file << data.uci << delimiter;
            file << data.record_start << delimiter;
            file << data.total_packet_count << delimiter;
            file << data.total_volume << delimiter;
            file << data.mean_packet_size << delimiter;
            file << data.min_packet_size << delimiter;
            file << data.max_packet_size << delimiter;
            file << data.sd_packet_size << delimiter;
            file << data.mean_packet_inter_arrival_time << delimiter;
            file << data.min_packet_inter_arrival_time << delimiter;
            file << data.max_packet_inter_arrival_time << delimiter;
            file << data.sd_packet_inter_arrival_time << std::endl;
        } catch (const std::exception&) {
            return;
        }
    }
}

CsvExporter::~CsvExporter()
{
    file.close();
}
