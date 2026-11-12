#include <pybind11/pybind11.h>
#include "py_network_session.hpp"
//#include <pybind11/stl.h>
#include "network-capture/datatypes/uci.hpp"
#include "network-capture/runner/capture_type.hpp"
#include "network-capture/runner/network_metric_capture.hpp"

#include <string>
#include <unordered_map>

namespace py = pybind11;
using namespace pybind11::literals;

class NetworkCapture
{
  protected:
    NetworkMetricsCapture nmc;
    ThreadSaveQueue<MetricsForWindow>* tsq;

  public:
    NetworkCapture(std::string location,
                   CaptureType type,
                   unsigned int window_duration)
      : nmc{ location, type, window_duration }
    {
        tsq = nmc.capture();
    }
    py::dict get_next()
    {
        MetricsForWindow m = tsq->wait_and_pop();
        return py::dict(
          "uci"_a = m.get_uci().as_uri(),
          "time"_a = m.get_record_start(),
          "packet_count"_a = m.get_total_packet_count(),
          "total_volume"_a = m.get_total_volume(),
          "mean_packet_size"_a = m.get_mean_packet_size(),
          "min_packet_size"_a = m.get_min_packet_size(),
          "max_packet_size"_a = m.get_max_packet_size(),
          "std_packet_size"_a = m.get_sd_packet_size(),
          "mean_interarrival_time"_a =
            m.get_mean_packet_inter_arrival_time(),
          "min_interarrival_time"_a = m.get_min_packet_inter_arrival_time(),
          "max_interarrival_time"_a = m.get_max_packet_inter_arrival_time(),
          "std_interarrival_time"_a =
            m.get_sd_packet_inter_arrival_time());
    }
    void stop() { tsq->stop(); }
};

PYBIND11_MODULE(_core, m, py::mod_gil_not_used())
{
    register_session(m);
    py::enum_<CaptureType>(m, "CaptureType")
      .value("PCAP", CaptureType::PCAP)
      .value("LIVE", CaptureType::LIVE);
    py::class_<NetworkCapture>(m, "NetworkCapture")
      .def(py::init<std::string, CaptureType, unsigned int>())
      .def("get_next", &NetworkCapture::get_next)
      .def("stop", &NetworkCapture::stop);
}