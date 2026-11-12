#pragma once
#include <pybind11/pybind11.h>
#include <pybind11/stl.h>
#include "network-capture/importer/base_importer.hpp"
#include "network-capture/datatypes/metrics_for_window.hpp"
#include <map>
#include <vector>
#include <stdexcept>

namespace py = pybind11;

// Synchronous bounded packet seam. Classic-file framing/custody belongs to the
// Python receiver; protocol parsing and all packet metrics remain native.
class NetworkCaptureSession {
    struct Raw {
        std::string bytes;
        int64_t sec;
        int64_t ns;
        ParsedPacket parsed;
    };
    uint64_t interval_, max_packets_, max_bytes_;
    int64_t start_ = 0;
    uint64_t sequence_ = 0, bytes_ = 0;
    bool finished_ = false;
    std::vector<Raw> pending_;

    static Raw parse(std::string bytes, int64_t sec, int64_t ns) {
        if (bytes.size() < 14 || bytes.size() > 262144 || sec < 0 || ns < 0 || ns >= 1000000000)
            throw std::invalid_argument("invalid Ethernet packet or timestamp");
        timespec ts{static_cast<time_t>(sec),static_cast<long>(ns)};
        pcpp::RawPacket raw(reinterpret_cast<const uint8_t*>(bytes.data()), static_cast<int>(bytes.size()), ts, false);
        pcpp::Packet packet(&raw);
        auto parsed = PcapPlusPlusBaseImporter::parse_packet(packet);
        if (!parsed) throw std::invalid_argument("unsupported packet");
        return Raw{std::move(bytes),sec,ns,*parsed};
    }
    py::dict seal() {
        std::map<std::string,std::vector<ParsedPacket>> groups;
        for (auto &r:pending_) groups[r.parsed.uci.as_uri()].push_back(r.parsed);
        py::list records;
        auto stamp = std::chrono::milliseconds(start_);
        for (auto &entry:groups) {
            UniqueWindowedPackets w(entry.second.front().uci,entry.second,stamp);
            MetricsForWindow m(w);
            py::dict d;
            d["uci"]=m.get_uci().as_uri();d["time"]=m.get_record_start();
            d["packet_count"]=m.get_total_packet_count();d["total_volume"]=m.get_total_volume();
            d["mean_packet_size"]=m.get_mean_packet_size();d["min_packet_size"]=m.get_min_packet_size();
            d["max_packet_size"]=m.get_max_packet_size();d["std_packet_size"]=m.get_sd_packet_size();
            d["mean_interarrival_time"]=m.get_mean_packet_inter_arrival_time();
            d["min_interarrival_time"]=m.get_min_packet_inter_arrival_time();
            d["max_interarrival_time"]=m.get_max_packet_inter_arrival_time();
            d["std_interarrival_time"]=m.get_sd_packet_inter_arrival_time();records.append(d);
        }
        py::dict result;result["window_sequence"]=sequence_++;result["record_start_ms"]=start_;
        result["metrics"]=records;pending_.clear();bytes_=0;return result;
    }
public:
    NetworkCaptureSession(uint64_t interval,uint64_t max_packets,uint64_t max_bytes)
      :interval_(interval),max_packets_(max_packets),max_bytes_(max_bytes) {
        if (!interval || interval>3600000 || !max_packets || !max_bytes)
            throw std::invalid_argument("invalid session limits");
    }
    py::object push_packet(py::bytes data,int64_t sec,int64_t ns) {
        if (finished_) throw std::invalid_argument("stream is closed");
        auto r=parse(static_cast<std::string>(data),sec,ns);
        auto time=r.parsed.timestamp.count();
        if (sequence_ && time<start_) throw std::invalid_argument("timestamp crosses sealed window");
        auto next_start=start_==0?time:start_;
        bool emit=next_start+static_cast<int64_t>(interval_)<time && !pending_.empty();
        if (r.bytes.size()>max_bytes_ || (!emit && (pending_.size()>=max_packets_ || bytes_+r.bytes.size()>max_bytes_)))
            throw std::invalid_argument("active window resource limit");
        start_=next_start;
        py::object result=py::none();
        if (emit) {result=seal();start_+=interval_;}
        bytes_+=r.bytes.size();pending_.push_back(std::move(r));return result;
    }
    py::dict export_state() const {
        py::dict d;d["version"]=1;d["interval_ms"]=interval_;d["start_ms"]=start_;
        d["sequence"]=sequence_;d["finished"]=finished_;py::list raw;
        for(auto &r:pending_) raw.append(py::make_tuple(py::bytes(r.bytes),r.sec,r.ns));
        d["pending"]=raw;return d;
    }
    void restore_state(py::dict d) {
        if (py::cast<int>(d["version"])!=1 || py::cast<uint64_t>(d["interval_ms"])!=interval_)
            throw std::invalid_argument("state version or configuration mismatch");
        auto start=py::cast<int64_t>(d["start_ms"]);auto sequence=py::cast<uint64_t>(d["sequence"]);
        auto finished=py::cast<bool>(d["finished"]);std::vector<Raw> pending;uint64_t size=0;
        for(auto item:py::cast<py::list>(d["pending"])) {
            auto tuple=py::cast<py::tuple>(item);
            auto r=parse(py::cast<std::string>(tuple[0]),py::cast<int64_t>(tuple[1]),py::cast<int64_t>(tuple[2]));
            size+=r.bytes.size();pending.push_back(std::move(r));
            if(size>max_bytes_ || pending.size()>max_packets_) throw std::invalid_argument("state exceeds limits");
        }
        if(start<0 || (finished && !pending.empty())) throw std::invalid_argument("invalid state");
        start_=start;sequence_=sequence;finished_=finished;pending_=std::move(pending);bytes_=size;
    }
    py::object finish_stream() {
        if(finished_) return py::none();finished_=true;
        if(pending_.empty()) return py::none();return seal();
    }
};

inline void register_session(py::module_ &m) {
    py::class_<NetworkCaptureSession>(m,"NetworkCaptureSession")
      .def(py::init<uint64_t,uint64_t,uint64_t>())
      .def("push_packet",&NetworkCaptureSession::push_packet)
      .def("export_state",&NetworkCaptureSession::export_state)
      .def("restore_state",&NetworkCaptureSession::restore_state)
      .def("finish_stream",&NetworkCaptureSession::finish_stream);
}
