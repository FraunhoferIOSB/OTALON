#pragma once

#include <algorithm>
#include <cmath>
#include <iterator>
#include <numeric>
#include <vector>

/**
 * @brief Calculate mean of iterable.
 *
 * @tparam Iterator
 * @param begin Beginning iterator.
 * @param end Ending iteratro.
 * @return float Calculated mean.
 */
template<typename Iterator>
float
mean(Iterator begin, Iterator end)
{

    auto size = std::distance(begin, end);
    if (size == 0) {
        return 0.0;
    }
    auto sum = std::reduce(begin, end);
    float mean = static_cast<float>(sum) / static_cast<float>(size);
    return mean;
}

/**
 * @brief Calculate standard deviation of iterable.
 *
 * @tparam Iterator
 * @param begin Beginning iterator.
 * @param end Ending iterator.
 * @return float Calculated standard deviation.
 */
template<typename Iterator>
float
standard_deviation(Iterator begin, Iterator end)
{
    auto size = std::distance(begin, end);
    if (size == 0) {
        return 0.0;
    }
    float mean_v = mean(begin, end);

    std::vector<float> distance;
    std::transform(
      begin, end, std::back_inserter(distance), [&](const auto& v) {
          return static_cast<float>(
            std::pow(static_cast<float>(v) - mean_v, 2));
      });

    float std = std::sqrt(std::reduce(distance.begin(), distance.end()) /
                          static_cast<float>(size));
    return std;
}