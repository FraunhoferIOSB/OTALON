add_library("${PROJECT_NAME}_lib" SHARED)
target_include_directories("${PROJECT_NAME}_lib" PUBLIC "${PROJECT_SOURCE_DIR}/include")

target_sources("${PROJECT_NAME}_lib"
    PUBLIC
    "${CMAKE_SOURCE_DIR}/include/network-capture/base/thread_save_queue.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/ip.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/mac.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/metrics_for_window.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/parsed_packet.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/protocol.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/uci.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/unique_windowed_packets.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/datatypes/windowed_packets.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/exporter/csv_exporter.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/importer/base_importer.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/importer/importer_utils.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/importer/live_importer.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/importer/pcap_importer.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/processing/metrics.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/processing/unique_window.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/processing/window.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/representation/representations.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/representation/string_output.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/runner/capture_type.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/runner/network_csv_capture.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/runner/network_metric_capture.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/runner/network_uci_capture.hpp"
    "${CMAKE_SOURCE_DIR}/include/network-capture/visualization/cli_progress.hpp"
)


target_sources("${PROJECT_NAME}_lib"
    PRIVATE
    "processing/metrics.cpp"
    "datatypes/helper.hpp"
    "datatypes/mac.cpp"
    "datatypes/ip.cpp"
    "datatypes/protocol.cpp"
    "datatypes/uci.cpp"
    "datatypes/parsed_packet.cpp"
    "datatypes/windowed_packets.cpp"
    "datatypes/unique_windowed_packets.cpp"
    "datatypes/metrics_for_window.cpp"
    "exporter/csv_exporter.cpp"
    "importer/base_importer.cpp"
    "importer/pcap_importer.cpp"
    "importer/live_importer.cpp"
    "importer/importer_utils.cpp"
    "processing/metrics.cpp"
    "processing/unique_window.cpp"
    "processing/window.cpp"
    "representation/string_output.cpp"
    "visualization/cli_progress.cpp"
    "runner/network_csv_capture.cpp"
    "runner/network_metric_capture.cpp"
    "runner/network_uci_capture.cpp"
)

target_link_libraries("${PROJECT_NAME}_lib" Packet++ Pcap++ Common++)

add_executable("${PROJECT_NAME}")
target_sources("${PROJECT_NAME}" 
    PRIVATE
    "main.cpp"
)
target_link_libraries("${PROJECT_NAME}" "${PROJECT_NAME}_lib" Boost::program_options)

install(TARGETS "${PROJECT_NAME}" "${PROJECT_NAME}_lib")
