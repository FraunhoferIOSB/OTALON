#pragma once
#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/datatypes/parsed_packet.hpp"
#include "network-capture/importer/base_importer.hpp"
#include "network-capture/runner/capture_type.hpp"

#include <thread>

class NetworkUciCapture
{
  protected:
    ThreadSaveQueue<ParsedPacket> tsq_pp;
    std::shared_ptr<PcapPlusPlusBaseImporter> packet_reader{};
    std::thread packet_reader_thread;
    std::thread runner;
    void process();

  public:
    NetworkUciCapture(std::string location, CaptureType type);
    ~NetworkUciCapture();
    ThreadSaveQueue<ParsedPacket>* capture();
    const uint64_t get_captured_packet_count();
};
