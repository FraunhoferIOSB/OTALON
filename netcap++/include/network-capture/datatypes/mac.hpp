#pragma once
#include <cstdint>
#include <string>
#include <cstdint>

/**
 * @brief A MAC address representation.
 *
 * Contains a single entry of a MAC address.
 */
class MAC
{
  protected:
    uint8_t mac[6] = { 0 };

  public:
    /**
     * @brief Construct a new MAC object.
     */
    MAC() = default;

    /**
     * @brief Construct a new MAC object
     *
     * @param buff Pointer to a MAC location. Requires the location to have at
     * least a size of 6 bytes.
     */
    MAC(const uint8_t* buff);

    MAC& operator=(const MAC& other);
    bool operator==(const MAC& other) const;
    bool operator!=(const MAC& other) const { return !(*this == other); };

    /**
     * @brief Generate a string representation of the MAC address.
     *
     * @return std::string String representation of the MAC with a form simmilar
     * to 00:00:00:00:00:00.
     */
    std::string to_string() const;

    /**
     * @brief Set the MAC address.
     *
     * @param buff Pointer to a MAC location. Requires the location to have at
     * least a size of 6 bytes.
     */
    void set_mac(const uint8_t* buff);

    /**
     * @brief Get ptr to the MAC address
     *
     */
    const uint8_t* get_mac() const;
};