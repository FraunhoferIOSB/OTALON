#include "network-capture/datatypes/ip.hpp"

#include <cstring>
#include <stdexcept>
#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif
using namespace std;

IP::IP()
{
    this->type = IpType::Undefined;
    memset(this->ip.ipv6, 0, sizeof(this->ip));
}

IP::IP(const uint8_t* buff, IpType type)
{
    this->type = type;

    if (type == IpType::IPv4) {
        memcpy(&this->ip.ipv4, buff, sizeof(this->ip.ipv4));
    } else {
        memcpy(&this->ip.ipv6, buff, sizeof(this->ip.ipv6));
    }
}

IP&
IP::operator=(const IP& other)
{
    this->type = other.type;
    memcpy(&this->ip, &other.ip, sizeof(this->ip));
    return *this;
}

bool
IP::operator==(const IP& other) const
{
    if (this->type != other.type) {
        return false;
    }
    int cmp = -1;
    if (this->type == IpType::IPv4) {
        cmp = memcmp(&this->ip.ipv4, &other.ip.ipv4, sizeof(this->ip.ipv4));
    } else {
        cmp = memcmp(&this->ip.ipv6, &other.ip.ipv6, sizeof(this->ip.ipv6));
    }
    return cmp == 0;
}

std::string
IP::to_string() const
{
    char buff[40];

    if (this->type == IpType::IPv4) {
        inet_ntop(AF_INET, &this->ip.ipv4, buff, sizeof(buff));
    } else if (this->type == IpType::IPv6) {
        inet_ntop(AF_INET6, &this->ip.ipv6, buff, sizeof(buff));
    } else {
        strncpy(buff, "Unknown AF", sizeof(buff));
    }
    buff[sizeof(buff) - 1] = '\0';
    return { buff };
}

void
IP::set_ip_v4(const uint8_t* buff)
{
    this->type = IpType::IPv4;

    memcpy(&this->ip.ipv4, buff, sizeof(this->ip.ipv4));
}

void
IP::set_ip_v6(const uint8_t* buff)
{
    this->type = IpType::IPv6;

    memcpy(&this->ip.ipv6, buff, sizeof(this->ip.ipv6));
}

const IpType&
IP::get_type() const noexcept
{
    return this->type;
}

const uint8_t*
IP::get_ip_v4() const
{
    if (!(this->type == IpType::IPv4)) {
        throw std::runtime_error("IP address is no IPv4 address");
    }
    return this->ip.ipv4;
}

const uint8_t*
IP::get_ip_v6() const
{
    if (!(this->type == IpType::IPv6)) {
        throw std::runtime_error("IP address is no IPv6 address");
    }
    return this->ip.ipv6;
}
