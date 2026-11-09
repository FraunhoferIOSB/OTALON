#pragma once
#include "network-capture/base/thread_save_queue.hpp"
#include "network-capture/representation/representations.hpp"

#include <fstream>
#include <string>

/**
 * @brief Exporter for the CSV format.
 *
 * Consumes string converted metrics to output them into a file formated as CSV.
 */
class CsvExporter
{
  protected:
    ThreadSaveQueue<StringifyMetricsForWindow>& data_source;
    std::ofstream file;
    char delimiter;

  public:
    /**
     * @brief Construct a new Csv Exporter object
     *
     * @param data_source Source of data.
     * @param filepath Path to the file to write to.
     * @param delimiter Used delimiter for the separate entries.
     */
    CsvExporter(ThreadSaveQueue<StringifyMetricsForWindow>& data_source,
                const std::string& filepath,
                char delimiter);
    ~CsvExporter();

    /**
     * @brief Function to implement the process.
     *
     */
    void process();
};
