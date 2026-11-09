#include "network-capture/datatypes/metrics_for_window.hpp"

#include "helper.hpp"

#include <algorithm>
#include <sstream>

std::string
MetricsForWindow::to_string() const
{
    std::stringstream ss;
    ss << "UCI: {" << uci.to_string() << "} ";
    ss << "Window start: " << record_start.count() << " ";
    ss << "TotalPacketCount: " << total_packet_count << " ";
    ss << "TotalVolume: " << total_volume << " ";
    ss << "MeanPacketSize: " << mean_packet_size << " ";
    ss << "MinPacketSize: " << min_packet_size << " ";
    ss << "MaxPacketSize: " << max_packet_size << " ";
    ss << "StandardDeviationSize: " << sd_packet_size << " ";
    ss << "MeanPacketInterArrivaltime: " << mean_packet_inter_arrival_time
       << " ";
    ss << "MinPacketInterArrivaltime: " << min_packet_inter_arrival_time.count()
       << " ";
    ss << "MaxPacketInterArrivaltime: " << max_packet_inter_arrival_time.count()
       << " ";
    ss << "StandardDeviationPacketInterArrivaltime: "
       << sd_packet_inter_arrival_time;

    return ss.str();
}

MetricsForWindow::MetricsForWindow(const UniqueWindowedPackets& window)
{

    auto cmp_packet_size = [](const ParsedPacket& lhs,
                              const ParsedPacket& rhs) {
        return lhs.size < rhs.size;
    };
    this->uci = window.uci;
    this->record_start = window.record_start;
    this->total_packet_count = static_cast<uint32_t>(window.data.size());

    std::vector<uint32_t> packet_sizes;
    std::transform(window.data.begin(),
                   window.data.end(),
                   std::back_inserter(packet_sizes),
                   [](const ParsedPacket& p) { return p.size; });
    this->total_volume = std::reduce(packet_sizes.begin(), packet_sizes.end());
    this->min_packet_size =
      std::min_element(window.data.begin(), window.data.end(), cmp_packet_size)
        ->size;
    this->max_packet_size =
      std::max_element(window.data.begin(), window.data.end(), cmp_packet_size)
        ->size;
    this->mean_packet_size = mean(packet_sizes.begin(), packet_sizes.end());
    this->sd_packet_size =
      standard_deviation(packet_sizes.begin(), packet_sizes.end());

    std::vector<std::chrono::milliseconds> timestamps;
    std::transform(window.data.begin(),
                   window.data.end(),
                   std::back_inserter(timestamps),
                   [](const ParsedPacket& p) { return p.timestamp; });
    std::sort(timestamps.begin(), timestamps.end());
    std::vector<uint64_t> inter_arrival_time;
    for (size_t i = 1; i < timestamps.size(); i++) {
        inter_arrival_time.push_back(
          (timestamps[i] - timestamps[i - 1]).count());
    }
    if (inter_arrival_time.size() > 0) {
        this->min_packet_inter_arrival_time =
          std::chrono::milliseconds(*(std::min_element(
            inter_arrival_time.begin(), inter_arrival_time.end())));
        this->max_packet_inter_arrival_time =
          std::chrono::milliseconds(*(std::max_element(
            inter_arrival_time.begin(), inter_arrival_time.end())));
        this->mean_packet_inter_arrival_time =
          mean(inter_arrival_time.begin(), inter_arrival_time.end());
        this->sd_packet_inter_arrival_time = standard_deviation(
          inter_arrival_time.begin(), inter_arrival_time.end());
    } else {
        this->min_packet_inter_arrival_time = std::chrono::milliseconds{};
        this->max_packet_inter_arrival_time = std::chrono::milliseconds{};
        this->mean_packet_inter_arrival_time = 0, 0;
        this->sd_packet_inter_arrival_time = 0, 0;
    }
}
const UCI&
MetricsForWindow::get_uci()
{
    return this->uci;
}
const int64_t
MetricsForWindow::get_record_start()
{
    return this->record_start.count();
}
const uint32_t&
MetricsForWindow::get_total_packet_count()
{
    return this->total_packet_count;
}
const uint32_t&
MetricsForWindow::get_total_volume()
{
    return this->total_volume;
}
const float&
MetricsForWindow::get_mean_packet_size()
{
    return this->mean_packet_size;
}
const uint16_t&
MetricsForWindow::get_min_packet_size()
{
    return this->min_packet_size;
}
const uint16_t&
MetricsForWindow::get_max_packet_size()
{
    return this->max_packet_size;
}
const float&
MetricsForWindow::get_sd_packet_size()
{
    return this->sd_packet_size;
}
const float&
MetricsForWindow::get_mean_packet_inter_arrival_time()
{
    return this->mean_packet_inter_arrival_time;
}
const int64_t
MetricsForWindow::get_min_packet_inter_arrival_time()
{
    return this->min_packet_inter_arrival_time.count();
}
const int64_t
MetricsForWindow::get_max_packet_inter_arrival_time()
{
    return this->max_packet_inter_arrival_time.count();
}
const float&
MetricsForWindow::get_sd_packet_inter_arrival_time()
{
    return this->sd_packet_inter_arrival_time;
}