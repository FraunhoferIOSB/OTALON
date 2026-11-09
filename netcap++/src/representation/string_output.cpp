#include <ostream>
#include "network-capture/representation/string_output.hpp"

using namespace std;

void
MetricStringReprsentationConverter::process()
{
    while (true) {
        try {
            MetricsForWindow metric = data_source.wait_and_pop();
            StringifyMetricsForWindow string_representation;
            string_representation.uci = metric.get_uci().as_uri();
            string_representation.record_start =
              to_string(metric.get_record_start());
            string_representation.total_packet_count =
              to_string(metric.get_total_packet_count());
            string_representation.total_volume =
              to_string(metric.get_total_volume());
            string_representation.mean_packet_size =
              to_string(metric.get_mean_packet_size());
            string_representation.min_packet_size =
              to_string(metric.get_min_packet_size());
            string_representation.max_packet_size =
              to_string(metric.get_max_packet_size());
            string_representation.sd_packet_size =
              to_string(metric.get_sd_packet_size());
            string_representation.mean_packet_inter_arrival_time =
              to_string(metric.get_mean_packet_inter_arrival_time());
            string_representation.min_packet_inter_arrival_time =
              to_string(metric.get_min_packet_inter_arrival_time());
            string_representation.max_packet_inter_arrival_time =
              to_string(metric.get_max_packet_inter_arrival_time());
            string_representation.sd_packet_inter_arrival_time =
              to_string(metric.get_sd_packet_inter_arrival_time());

            data_destination.push(string_representation);
        } catch (const std::exception&) {
            return;
        }
    }
}
