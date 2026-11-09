#pragma once

#include "network-capture/importer/base_importer.hpp"

#include <optional>
#include <chrono>

/**
 * @brief Visualizator of the packet capturing process.
 *
 * Visualizes the process of packet capturing based on the amount of captured
 * bytes. Provides a text based output in a fixed intervall displaying the
 * amount of captured bytes. If a file size is specified it will be added to the
 * output.
 */
class CliProgress
{
  protected:
    PcapPlusPlusBaseImporter* importer{ nullptr };
    std::chrono::seconds update_intervall{ 0 };
    std::optional<uint64_t> file_size{};

  public:
    /**
     * @brief Construct a new cli progress object
     *
     * @param importer Importer to provide progress for.
     * @param update_intervall Intervall of the status output.
     * @param file_size Optional file size.
     */
    CliProgress(PcapPlusPlusBaseImporter* importer,
                std::chrono::seconds update_intervall,
                std::optional<uint64_t> file_size)
      : importer{ importer }
      , update_intervall{ update_intervall }
      , file_size{ file_size } {};

    void process();
};
