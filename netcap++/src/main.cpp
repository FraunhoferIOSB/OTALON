#include "network-capture/runner/network_csv_capture.hpp"

#include <boost/program_options/options_description.hpp>
#include <boost/program_options/parsers.hpp>
#include <boost/program_options/variables_map.hpp>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>

using namespace std;
namespace po = boost::program_options;
int
main(int argc, char** argv)
{
    uintmax_t file_size = 0;
    optional<string> location;
    optional<string> destination;
    optional<CaptureType> type;

    po::options_description desc("Allowed options");
    desc.add_options()("help", "produce help message")(
      "input-file", po::value<string>(), "read packets from pcap file")(
      "input-iface", po::value<string>(), "name of the interface to read from")(
      "output-file", po::value<string>(), "write metrics as csv to file")(
      "window-duration",
      po::value<unsigned int>()->default_value(1000),
      "duration of a window in milliseconds");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("help")) {
        cout << desc << endl;
        return 1;
    }

    if (vm.count("input-file")) {
        location = vm["input-file"].as<string>();
        file_size = filesystem::file_size(location.value());
        type = CaptureType::PCAP;

    } else if (vm.count("input-iface")) {
        location = vm["input-iface"].as<string>();
            type = CaptureType::LIVE;
            cout << "LIVE" << endl;
    } else {
        cerr << "Must specify input-file or input-iface options" << endl;
        return 1;
    }

    if (vm.count("output-file")) {
        destination = vm["output-file"].as<string>();
    } else {
        cerr << "Not output option was specified";
        return 1;
    }

    unsigned int intervall(vm["window-duration"].as<unsigned int>());

    NetworkCsvCapture nc(location.value(),
                         type.value(),
                         intervall,
                         destination.value(),
                         true,
                         file_size);

    nc.capture();

    return 0;
}
