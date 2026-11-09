#pragma once
#include <cstdint>
#include <string>
#include <cstdint>

/**
 * @brief An IP type representation.
 *
 * Allows to distinguish between IPv4 and IPv6 addresses.
 */
enum class IpType
{
    IPv4,
    IPv6,
    Undefined
};

/**
 * @brief A IP address representation.
 *
 * Holds a single IPv4 or IPv6 address.
 */
class IP
{
  protected:
    IpType type{ IpType::Undefined };
    union
    {
        uint8_t ipv4[4];
        uint8_t ipv6[16];
    } ip;

  public:
    /**
     * @brief Construct a new IP object
     */
    IP();

    /**
     * @brief Construct a new IP object
     *
     * @param buff Pointer to an IP location. Requires the location to have at
     * least a size of 4 bytes for an IPv4 address and at least 16 bytes for a
     * IPv6 address.
     * @param type Type of the IP address.
     */
    IP(const uint8_t* buff, IpType type);

    IP& operator=(const IP& other);
    bool operator==(const IP& other) const;
    bool operator!=(const IP& other) const { return !(*this == other); };

    /**
     * @brief Get a string representation of the IP.
     *
     * @return std::string Typical string representation of an IP address.
     */
    std::string to_string() const;

    /**
     * @brief Set the ip to an IPv4 address.
     *
     * @param buff Pointer to an IP location. Requires the location to have at
     * least a size of 4 bytes.
     */
    void set_ip_v4(const uint8_t* buff);

    /**
     * @brief Set the ip to an IPv6 address.
     *
     * @param buff Pointer to an IP location. Requires the location to have at
     * least a size of 16 bytes.
     */
    void set_ip_v6(const uint8_t* buff);

    /**
     * @brief Get the type of the IP address
     *
     * @return IpType Type of the IP address. Returns Undefined if not assigned
     * yet.
     */
    const IpType& get_type() const noexcept;

    /**
     * @brief Get IPv4 address
     *
     * @throw std::runtime_error If IP address is not IPv4
     *
     * @return const uint8_t* Retrurns ptr to IP address
     */
    const uint8_t* get_ip_v4() const;

    /**
     * @brief Get IPv6 address
     *
     * @throw std::runtime_error If IP address is not IPv6
     *
     * @return const uint8_t* Retrurns ptr to IP address
     */
    const uint8_t* get_ip_v6() const;
};