#include <ostream>
#include "network-capture/processing/metrics.hpp"

void
MetricGenerator::process()
{

    while (true) {
        try {
            auto window = data_source.wait_and_pop();

            MetricsForWindow metrics(window);

            data_destination.push(metrics);
        } catch (const std::exception&) {
            return;
        }
    }
}
